// Package dns01 is the DNS-01 solver: it publishes the TXT value of a challenge by calling an administrator's
// DNS hook over https, and removes it again. It is the only code that speaks the hook protocol.
//
// # The wire contract of Alice's DNS hook (public; the fake CA's /hook receiver implements the same)
//
//	POST <hook URL>
//	Authorization: Bearer <secret>
//	X-Alice-Signature: <lowercase hex of HMAC-SHA256(secret, exact request body)>
//	Content-Type: application/json
//	User-Agent: alice-acme/1
//
//	{"action":"present"|"cleanup","fqdn":"_acme-challenge.example.com","value":"<TXT value>","ttl":60}
//
// The secret is one value used both as the bearer token and as the HMAC key, and Alice always sends both headers:
// there is no mode to choose, the hook checks whichever it prefers (or both). The body is exactly the four
// fields in that order, with no whitespace. The fqdn is "_acme-challenge." + the validated domain, lower case,
// without a trailing dot and without the "*." of a wildcard: a wildcard and its base name share one fqdn and
// the hook must keep both values side by side. "cleanup" removes only the TXT record with that value, never
// every record of the name. Both actions are idempotent: repeating one is harmless.
//
// Answers: 200 or 204 means done; any other status (redirects included, they are never followed) is a refusal.
// An answer body is optional and capped at 4 KiB. A JSON object {"ready":true|false} tells Alice whether the
// record is already visible to the CA: true means validate now, false means "ask again" and Alice repeats the
// same present request every poll interval until the hook says true or the poll time runs out. Any other body
// (or none) means the record is assumed visible after the configured propagation wait. The hook's answer text
// is never copied into an error, a log or an audit row.
//
// Alice only calls the hook for names below the configured allowed suffixes; an empty list refuses every name.
package dns01

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/transport"
	"alice/internal/platform/clock"
	"alice/internal/secrets"
)

// Limits and defaults.
const (
	DefaultPropagationWait = 5 * time.Second
	MaxPropagationWait     = 120 * time.Second
	DefaultPollTimeout     = 60 * time.Second
	// MaxPollTimeout stays below the ACME client's per-call deadline (acme.DefaultCallTimeout, 2 min), under which
	// Present runs: a longer poll could never finish.
	MaxPollTimeout = 100 * time.Second
	// MaxPresentAttempts caps the present requests of one Present (the first plus the polls).
	MaxPresentAttempts  = 100
	DefaultPollInterval = 2 * time.Second
	MinPollInterval     = 500 * time.Millisecond
	MaxPollInterval     = 30 * time.Second
	DefaultTTL          = 60
	// MaxReplyBytes is how much of a hook answer is read.
	MaxReplyBytes = 4 << 10
	// UserAgent is sent with every hook call.
	UserAgent = "alice-acme/1"

	cleanupTimeout = 30 * time.Second
	maxValueBytes  = 512
	labelPrefix    = "_acme-challenge."
)

// Configuration errors (fixed text: never the URL or the secret).
var (
	ErrURL         = errors.New("dns01: the hook URL must be an https URL without credentials or fragment")
	ErrSecret      = errors.New("dns01: the hook secret is empty or has control or non-ASCII characters")
	ErrCABundle    = errors.New("dns01: the CA bundle has no usable certificate")
	ErrWait        = errors.New("dns01: a wait setting is out of range")
	ErrSuffix      = errors.New("dns01: an allowed suffix is not a DNS suffix")
	ErrTTL         = errors.New("dns01: the TTL is out of range")
	errBadChalenge = errors.New("dns01: not a DNS-01 challenge Alice can publish")
)

// Config configures a Solver.
type Config struct {
	// URL is the hook endpoint: https, with a host, without userinfo or fragment. A query is allowed and is
	// never printed.
	URL string
	// Secret is the bearer token and HMAC key (the same value for both).
	Secret secrets.Plaintext
	// CABundlePEM adds CAs to the system roots for the hook's certificate.
	CABundlePEM string
	// BaseRoots replaces the system roots when set (the e2e build's trust of its fake CA; nil in a release build).
	BaseRoots *x509.CertPool
	// PropagationWait is how long to wait after a present that did not report readiness. 0 means the default
	// (5 s); a negative value means no wait; the maximum is 120 s.
	PropagationWait time.Duration
	// PollTimeout bounds the polling of a hook that reports ready=false. 0 means the default (60 s), maximum 5 min.
	PollTimeout time.Duration
	// PollInterval is the pause between two polls. 0 means the default (2 s); 10 ms to 30 s.
	PollInterval time.Duration
	// TTL is the record TTL sent to the hook. 0 means 60; at most 86400.
	TTL int
	// AllowedSuffixes limits the domains the hook is asked about. "example.com" admits example.com and every
	// name below it; ".example.com" admits only the names below it. Empty refuses everything.
	AllowedSuffixes []string
}

// String shows the host only: no path, query, secret or bundle.
func (c Config) String() string {
	return "dns01.Config{URL: " + hostOf(c.URL) + ", Secret: redacted}"
}

// GoString is String.
func (c Config) GoString() string { return c.String() }

// Format keeps every verb on String.
func (c Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "invalid"
	}
	return u.Host
}

// Solver implements solver.Solver for DNS-01 through the hook.
type Solver struct {
	url      string
	host     string
	key      secrets.Plaintext // copy of the secret; redacts itself
	client   *http.Client
	wait     time.Duration
	pollMax  time.Duration
	pollStep time.Duration
	ttl      int
	suffixes []string // normalized: leading "." for subdomain-only entries

	// Test seams (unexported: the dialer is never replaceable from outside the transport).
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

var _ solver.Solver = (*Solver)(nil)

// New validates the configuration and builds the solver. It makes no network call.
func New(cfg Config) (*Solver, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, ErrURL
	}
	key := cfg.Secret.Bytes()
	if len(key) == 0 || !validSecret(key) {
		return nil, ErrSecret
	}
	s := &Solver{url: u.String(), host: u.Host, key: secrets.NewPlaintext(append([]byte(nil), key...)),
		wait: cfg.PropagationWait, pollMax: cfg.PollTimeout, pollStep: cfg.PollInterval, ttl: cfg.TTL,
		now: clock.Real{}.Now, sleep: sleepCtx}
	switch {
	case s.wait == 0:
		s.wait = DefaultPropagationWait
	case s.wait < 0:
		s.wait = 0
	}
	if s.wait > MaxPropagationWait {
		return nil, ErrWait
	}
	if s.pollMax == 0 {
		s.pollMax = DefaultPollTimeout
	}
	if s.pollStep == 0 {
		s.pollStep = DefaultPollInterval
	}
	if s.pollMax < 0 || s.pollMax > MaxPollTimeout || s.pollStep < MinPollInterval || s.pollStep > MaxPollInterval {
		return nil, ErrWait
	}
	if s.ttl == 0 {
		s.ttl = DefaultTTL
	}
	if s.ttl < 0 || s.ttl > 86400 {
		return nil, ErrTTL
	}
	for _, raw := range cfg.AllowedSuffixes {
		n, ok := normSuffix(raw)
		if !ok {
			return nil, ErrSuffix
		}
		s.suffixes = append(s.suffixes, n)
	}
	if s.client, err = transport.NewWithRoots(cfg.CABundlePEM, cfg.BaseRoots); err != nil {
		return nil, ErrCABundle
	}
	return s, nil
}

// String shows the host only.
// validSecret admits printable ASCII only: the value is an HTTP header value and an HMAC key.
func validSecret(k []byte) bool {
	for _, c := range k {
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func (s Solver) String() string { return "dns01.Solver{host: " + s.host + ", secret: redacted}" }

// GoString is String.
func (s Solver) GoString() string { return s.String() }

// Format keeps every verb on String.
func (s Solver) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// Types implements solver.Solver.
func (*Solver) Types() []string { return []string{solver.DNS01} }

// Present publishes the TXT value. It returns an *acme.Error: acme.ReasonNameNotAllowed (nothing was sent),
// acme.ReasonHookRefused (the hook refused, failed or could not be reached) or acme.ReasonNotIssuedInTime
// (the hook never reported ready in time); a cancelled or expired ctx returns ctx.Err().
func (s *Solver) Present(ctx context.Context, ch solver.Challenge) error {
	fqdn, err := s.prepare(ch)
	if err != nil {
		return err
	}
	body, sig, err := s.body("present", fqdn, ch.DNSValue)
	if err != nil {
		return err
	}
	deadline := s.now().Add(s.pollMax)
	for attempt := 1; ; attempt++ {
		reply, err := s.post(ctx, body, sig, ch.Domain)
		if err != nil {
			return err
		}
		ready, known := parseHookReply(reply)
		if known && ready {
			return nil
		}
		if !known {
			return s.sleepFor(ctx, s.wait) // no readiness information (also after an earlier ready=false)
		}
		if attempt >= MaxPresentAttempts || !s.now().Before(deadline) {
			return &acme.Error{Reason: acme.ReasonNotIssuedInTime, Identifier: ch.Domain}
		}
		if err := s.sleepFor(ctx, s.pollStep); err != nil {
			return err
		}
	}
}

// CleanUp removes the TXT value (and only that value). It uses its own bounded context, so it still runs after
// the order's context was cancelled, and returns the hook's error for the caller to record.
func (s *Solver) CleanUp(ctx context.Context, ch solver.Challenge) error {
	fqdn, err := s.prepare(ch)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	body, sig, err := s.body("cleanup", fqdn, ch.DNSValue)
	if err != nil {
		return err
	}
	_, err = s.post(cctx, body, sig, ch.Domain)
	return err
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

func refused(domain string) error {
	return &acme.Error{Reason: acme.ReasonHookRefused, Identifier: domain}
}

// prepare checks the challenge and the allow-list, before any network call, and returns the fqdn.
func (s *Solver) prepare(ch solver.Challenge) (string, error) {
	if ch.Type != solver.DNS01 || ch.DNSValue == "" || len(ch.DNSValue) > maxValueBytes || !printable(ch.DNSValue) {
		return "", refused(ch.Domain)
	}
	d, ok := normDomain(ch.Domain)
	if !ok || !s.allowed(d) {
		return "", &acme.Error{Reason: acme.ReasonNameNotAllowed, Identifier: safeID(ch.Domain)}
	}
	fqdn := labelPrefix + d
	if ch.DNSName != "" && !strings.EqualFold(strings.TrimSuffix(ch.DNSName, "."), fqdn) {
		return "", refused(d)
	}
	return fqdn, nil
}

func safeID(domain string) string {
	if d, ok := normDomain(domain); ok {
		return d
	}
	return ""
}

func printable(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// hookRequest has the fixed field order of the wire contract.
type hookRequest struct {
	Action string `json:"action"`
	FQDN   string `json:"fqdn"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
}

func (s *Solver) body(action, fqdn, value string) (body []byte, sig string, err error) {
	body, err = json.Marshal(hookRequest{Action: action, FQDN: fqdn, Value: value, TTL: s.ttl})
	if err != nil {
		return nil, "", errBadChalenge
	}
	m := hmac.New(sha256.New, s.key.Bytes())
	m.Write(body)
	return body, hex.EncodeToString(m.Sum(nil)), nil
}

// post sends one request and returns the capped answer body of a 200 or 204.
func (s *Solver) post(ctx context.Context, body []byte, sig, domain string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return nil, refused(domain)
	}
	req.Header.Set("Authorization", "Bearer "+string(s.key.Bytes()))
	req.Header.Set("X-Alice-Signature", sig)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	res, err := s.client.Do(req)
	if err != nil {
		// The error is a *url.Error carrying the URL; drop it. A dead context is reported as itself.
		if ce := ctx.Err(); ce != nil {
			return nil, ce
		}
		// An untrusted certificate is a setting (the hook's CA bundle); any other failure to get an answer (refused
		// connection, timeout, DNS) is an outage the renewal planner retries (acme.FailureClass).
		return nil, acme.HookError(domain, 0, !untrusted(err))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, MaxReplyBytes))
		// The status only (a 5xx or 429 is an outage, another 4xx a setting); never the answer's text.
		return nil, acme.HookError(domain, res.StatusCode, false)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxReplyBytes+1))
	if err != nil || len(b) > MaxReplyBytes {
		return nil, nil // an unreadable or oversize answer carries no readiness information
	}
	return b, nil
}

// untrusted reports a TLS verification failure in err's chain.
func untrusted(err error) bool {
	var (
		ua  x509.UnknownAuthorityError
		he  x509.HostnameError
		ci  x509.CertificateInvalidError
		cve *tls.CertificateVerificationError
	)
	return errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) || errors.As(err, &cve)
}

// parseHookReply reads the optional {"ready":bool} of a hook answer. known is false for anything else (no body,
// not JSON, not an object, no boolean "ready").
func parseHookReply(b []byte) (ready, known bool) {
	if len(b) == 0 || len(b) > MaxReplyBytes {
		return false, false
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal(b, &v); err != nil {
		return false, false
	}
	switch string(bytes.TrimSpace(v["ready"])) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// normDomain lower-cases a challenge domain, strips "*." and a trailing dot and checks its characters.
func normDomain(d string) (string, bool) {
	d = strings.TrimSuffix(strings.TrimPrefix(asciiLower(d), "*."), ".")
	if d == "" || len(d) > 253-len(labelPrefix) {
		return "", false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	return d, true
}

// normSuffix keeps a leading dot (subdomains only) and validates the rest.
func normSuffix(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	dot := strings.HasPrefix(raw, ".")
	d, ok := normDomain(strings.TrimPrefix(raw, "."))
	if !ok || strings.HasPrefix(raw, "*") || strings.HasSuffix(raw, ".") {
		return "", false
	}
	if dot {
		return "." + d, true
	}
	return d, true
}

func (s *Solver) allowed(d string) bool {
	for _, sf := range s.suffixes {
		if strings.HasPrefix(sf, ".") {
			if strings.HasSuffix(d, sf) {
				return true
			}
		} else if d == sf || strings.HasSuffix(d, "."+sf) {
			return true
		}
	}
	return false
}

// asciiLower lower-cases ASCII letters only (DNS names are case-insensitive in ASCII, and nothing else is valid here).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
