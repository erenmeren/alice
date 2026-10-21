// Package dnsapi is the DNS-01 solver for DNS services Alice reaches through their own API (R57): Cloudflare,
// Azure DNS and Amazon Route 53 implement Provider in the packages below this one, and Solver turns any Provider into
// a solver.Solver. The administrator's DNS hook (package dns01) is the other DNS-01 solver; both apply the same name
// rules (solver.NormalizeDomain, solver.Suffixes) before anything is sent.
//
// # What a provider does
//
// A provider finds the zone that holds a record name (the longest zone name of the account that is the name or a
// suffix of it: "_acme-challenge.www.example.com" goes to "www.example.com" before "example.com"), adds one TXT value
// at the name while keeping every other value there (a wildcard and its base name share the record name with two
// values, solver package comment), removes only the value it is given, and reports when a change it made is live on
// every authoritative server (Route 53's INSYNC; the others are live at once). Every call is idempotent: adding a
// value that is there, or removing one that is gone, succeeds.
//
// # What the solver adds
//
// The allow-list (an empty list refuses every name, before any call), the zone lookup once per zone and order, the
// wait for the provider's change (bounded by the poll time), then the fixed propagation wait, and a bounded
// clean-up that still runs after the order's context ended. A CNAME at _acme-challenge (delegation to another zone)
// is not followed: the record is published in the zone that holds the name itself (R57; the hook can follow one).
//
// # Errors and secrets
//
// Every failure is an *acme.Error with a closed reason (acme.ReasonDNSZoneNotFound, acme.ReasonDNSAuthFailed,
// acme.ReasonDNSProviderError, acme.ReasonNotIssuedInTime, acme.ReasonNameNotAllowed): its text holds the reason,
// the name and the provider's HTTP status, never a credential, a header, a URL or any part of the provider's answer.
// Credentials are secrets.Plaintext values (redacted in every print and log form) and the HTTP client never follows
// a redirect, never uses a proxy from the environment, reaches the provider's fixed hosts only and connects through
// the address rule of netaddr.
package dnsapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/platform/clock"
)

// Kinds of DNS provider (the acme_hooks.kind values of 00030 besides "webhook").
const (
	KindCloudflare = "cloudflare"
	KindAzureDNS   = "azure_dns"
	KindRoute53    = "route53"
)

// Limits and defaults of a Solver. The propagation wait and the poll time have the hook's bounds (dns01), so one
// validation in the inventory serves both.
const (
	DefaultPropagationWait = 10 * time.Second
	MaxPropagationWait     = 120 * time.Second
	DefaultPollTimeout     = 60 * time.Second
	MaxPollTimeout         = 100 * time.Second
	DefaultPollInterval    = 2 * time.Second
	MinPollInterval        = 500 * time.Millisecond
	MaxPollInterval        = 30 * time.Second
	DefaultTTL             = 60
	MinTTL                 = 30
	MaxTTL                 = 86400
	// CleanupTimeout bounds one CleanUp (its own context: it runs after the order's ended).
	CleanupTimeout = 30 * time.Second
	// MaxPolls caps the change polls of one Present.
	MaxPolls = 100
)

// Configuration errors (fixed texts).
var (
	ErrProvider = errors.New("dnsapi: no DNS provider")
	ErrWait     = errors.New("dnsapi: a wait setting is out of range")
	ErrTTL      = errors.New("dnsapi: the TTL is out of range")
	ErrSuffix   = errors.New("dnsapi: an allowed suffix is not a DNS suffix")
)

// Zone is a DNS zone the provider's credentials manage.
type Zone struct {
	// Name is the zone's name in lower case, without a trailing dot ("example.com").
	Name string
	// ID is the provider's handle of the zone (a Cloudflare zone ID, a Route 53 hosted zone ID, an Azure zone name).
	ID string
}

// Provider is one DNS service's API. The fqdn arguments are lower case, without a trailing dot, and always below or
// equal to the zone's name; value is printable ASCII (solver.PrintableValue).
type Provider interface {
	// Kind is one of the Kind constants.
	Kind() string
	// FindZone returns the zone that holds fqdn: the longest zone name of the account that equals fqdn or is a suffix
	// of it on a label boundary (Longest). acme.DNSZoneNotFound when there is none.
	FindZone(ctx context.Context, fqdn string) (Zone, error)
	// AddTXT adds value to the TXT records at fqdn with ttl, keeping every other value there. It returns the handle
	// of a change ChangeDone polls, or "" when the record is live on the provider's servers at once.
	AddTXT(ctx context.Context, z Zone, fqdn, value string, ttl int) (change string, err error)
	// RemoveTXT removes value (only that value) from the TXT records at fqdn; a value that is not there is success.
	RemoveTXT(ctx context.Context, z Zone, fqdn, value string) error
	// ChangeDone reports whether the change AddTXT returned is live on every authoritative server.
	ChangeDone(ctx context.Context, change string) (bool, error)
}

// Config configures a Solver.
type Config struct {
	Provider Provider
	// AllowedSuffixes limits the names the provider is asked about (solver.Suffixes); empty refuses everything.
	AllowedSuffixes []string
	// PropagationWait is how long to wait after the record is live on the provider's servers, for the copies the CA
	// may ask (secondaries, caches). 0 means DefaultPropagationWait, a negative value no wait, at most
	// MaxPropagationWait.
	PropagationWait time.Duration
	// PollTimeout bounds the wait for the provider's change (0 = DefaultPollTimeout, at most MaxPollTimeout).
	PollTimeout time.Duration
	// PollInterval is the pause between two change polls (0 = DefaultPollInterval).
	PollInterval time.Duration
	// TTL is the record TTL (0 = DefaultTTL, MinTTL..MaxTTL; Cloudflare raises a lower one to its minimum itself).
	TTL int
}

// Solver implements solver.Solver over a Provider.
type Solver struct {
	p        Provider
	suffixes solver.Suffixes
	wait     time.Duration
	pollMax  time.Duration
	pollStep time.Duration
	ttl      int

	mu    sync.Mutex
	zones map[string]Zone // fqdn -> zone, for this solver's order

	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

var _ solver.Solver = (*Solver)(nil)

// New validates the configuration and builds the solver. It makes no network call.
func New(cfg Config) (*Solver, error) {
	if cfg.Provider == nil {
		return nil, ErrProvider
	}
	s := &Solver{p: cfg.Provider, wait: cfg.PropagationWait, pollMax: cfg.PollTimeout, pollStep: cfg.PollInterval, ttl: cfg.TTL,
		zones: map[string]Zone{}, now: clock.Real{}.Now, sleep: sleepCtx}
	switch {
	case s.wait == 0:
		s.wait = DefaultPropagationWait
	case s.wait < 0:
		s.wait = 0
	}
	if s.pollMax == 0 {
		s.pollMax = DefaultPollTimeout
	}
	if s.pollStep == 0 {
		s.pollStep = DefaultPollInterval
	}
	if s.wait > MaxPropagationWait || s.pollMax < 0 || s.pollMax > MaxPollTimeout || s.pollStep < MinPollInterval || s.pollStep > MaxPollInterval {
		return nil, ErrWait
	}
	if s.ttl == 0 {
		s.ttl = DefaultTTL
	}
	if s.ttl < MinTTL || s.ttl > MaxTTL {
		return nil, ErrTTL
	}
	var err error
	if s.suffixes, err = solver.ParseSuffixes(cfg.AllowedSuffixes); err != nil {
		return nil, ErrSuffix
	}
	return s, nil
}

// String names the provider's kind only.
func (s *Solver) String() string { return "dnsapi.Solver{kind: " + s.p.Kind() + "}" }

// GoString is String.
func (s *Solver) GoString() string { return s.String() }

// Format keeps every verb on String.
func (s *Solver) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// Kind is the provider's kind.
func (s *Solver) Kind() string { return s.p.Kind() }

// Types implements solver.Solver.
func (*Solver) Types() []string { return []string{solver.DNS01} }

// Present publishes the TXT value and returns once the provider reports it live and the propagation wait is over.
// A cancelled or expired ctx returns ctx.Err().
func (s *Solver) Present(ctx context.Context, ch solver.Challenge) error {
	d, fqdn, err := s.prepare(ch)
	if err != nil {
		return err
	}
	z, err := s.zone(ctx, d, fqdn)
	if err != nil {
		return err
	}
	change, err := s.p.AddTXT(ctx, z, fqdn, ch.DNSValue, s.ttl)
	if err != nil {
		return s.callError(ctx, err, d)
	}
	if change != "" {
		if err := s.awaitChange(ctx, change, d); err != nil {
			return err
		}
	}
	return s.sleepFor(ctx, s.wait)
}

// CleanUp removes the TXT value (and only that value), under its own bounded context.
func (s *Solver) CleanUp(ctx context.Context, ch solver.Challenge) error {
	d, fqdn, err := s.prepare(ch)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), CleanupTimeout)
	defer cancel()
	z, err := s.zone(cctx, d, fqdn)
	if err != nil {
		return err
	}
	if err := s.p.RemoveTXT(cctx, z, fqdn, ch.DNSValue); err != nil {
		return s.callError(cctx, err, d)
	}
	return nil
}

func (s *Solver) awaitChange(ctx context.Context, change, d string) error {
	deadline := s.now().Add(s.pollMax)
	for poll := 1; ; poll++ {
		done, err := s.p.ChangeDone(ctx, change)
		if err != nil {
			return s.callError(ctx, err, d)
		}
		if done {
			return nil
		}
		if poll >= MaxPolls || !s.now().Before(deadline) {
			return &acme.Error{Reason: acme.ReasonNotIssuedInTime, Identifier: d}
		}
		if err := s.sleepFor(ctx, s.pollStep); err != nil {
			return err
		}
	}
}

// zone finds (once per name) the zone that holds fqdn.
func (s *Solver) zone(ctx context.Context, d, fqdn string) (Zone, error) {
	s.mu.Lock()
	z, ok := s.zones[fqdn]
	s.mu.Unlock()
	if ok {
		return z, nil
	}
	z, err := s.p.FindZone(ctx, fqdn)
	if err != nil {
		return Zone{}, s.callError(ctx, err, d)
	}
	if !InZone(fqdn, z.Name) || z.ID == "" {
		// A provider must never hand back a zone that does not hold the name.
		return Zone{}, acme.DNSZoneNotFound(d)
	}
	s.mu.Lock()
	s.zones[fqdn] = z
	s.mu.Unlock()
	return z, nil
}

// callError keeps a provider's *acme.Error (with the name set), reports a dead context as itself and turns anything
// else into a fixed acme.ReasonDNSProviderError: a provider's own error text never leaves the solver.
func (s *Solver) callError(ctx context.Context, err error, d string) error {
	if ce := ctx.Err(); ce != nil {
		return ce
	}
	var ae *acme.Error
	if errors.As(err, &ae) {
		if ae.Identifier == "" {
			c := *ae
			c.Identifier = d
			return &c
		}
		return ae
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return acme.DNSProviderError(d, 0, true)
	}
	return acme.DNSProviderError(d, 0, false)
}

// prepare checks the challenge and the allow-list, before any network call.
func (s *Solver) prepare(ch solver.Challenge) (domain, fqdn string, err error) {
	if ch.Type != solver.DNS01 || !solver.PrintableValue(ch.DNSValue) {
		return "", "", &acme.Error{Reason: acme.ReasonDNSProviderError, Identifier: safeID(ch.Domain)}
	}
	d, ok := solver.NormalizeDomain(ch.Domain)
	if !ok || !s.suffixes.Allows(d) {
		return "", "", &acme.Error{Reason: acme.ReasonNameNotAllowed, Identifier: safeID(ch.Domain)}
	}
	fqdn = solver.ChallengeLabel + d
	if ch.DNSName != "" && !strings.EqualFold(strings.TrimSuffix(ch.DNSName, "."), fqdn) {
		return "", "", &acme.Error{Reason: acme.ReasonDNSProviderError, Identifier: d}
	}
	return d, fqdn, nil
}

func safeID(domain string) string {
	if d, ok := solver.NormalizeDomain(domain); ok {
		return d
	}
	return ""
}

func (s *Solver) sleepFor(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	return s.sleep(ctx, d)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
