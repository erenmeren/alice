// Package dnssolver builds the DNS-01 solver of one DNS publisher (an acme_hooks row, R57): the administrator's
// hook (package dns01) or one of the built-in DNS providers (package dnsapi and its provider packages). It is the
// one place that maps a publisher's kind to its solver; the inventory fills a Config from the stored row and the
// ACME jobs call New.
package dnssolver

import (
	"errors"
	"fmt"
	"io"
	"time"

	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dns01"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/acme/solver/dnsapi/azuredns"
	"alice/internal/acme/solver/dnsapi/cloudflare"
	"alice/internal/acme/solver/dnsapi/route53"
)

// Kinds of DNS publisher (acme_hooks.kind).
const (
	KindWebhook    = "webhook"
	KindCloudflare = dnsapi.KindCloudflare
	KindAzureDNS   = dnsapi.KindAzureDNS
	KindRoute53    = dnsapi.KindRoute53
)

// Kinds lists every kind, the hook first.
func Kinds() []string { return []string{KindWebhook, KindCloudflare, KindAzureDNS, KindRoute53} }

// ErrKind is a Config of no known kind.
var ErrKind = errors.New("dnssolver: not a DNS publisher kind Alice knows")

// Config is one publisher's solver configuration. Hook is used for KindWebhook (its own waits and suffixes); the
// provider configs for their kind, with the common fields below. It carries opened secrets: Zero clears them, and
// every print form names the kind only.
type Config struct {
	Kind       string
	Hook       dns01.Config
	Cloudflare cloudflare.Config
	AzureDNS   azuredns.Config
	Route53    route53.Config

	// The common settings of a provider kind (dnsapi.Config).
	AllowedSuffixes []string
	PropagationWait time.Duration // 0 = dnsapi's default, negative = none
	PollTimeout     time.Duration
	TTL             int
}

// String names the kind only.
func (c Config) String() string { return "dnssolver.Config{kind: " + c.Kind + ", secrets: redacted}" }

// GoString is String.
func (c Config) GoString() string { return c.String() }

// Format keeps every verb on String.
func (c Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// Zero clears every opened secret of the configuration in place.
func (c Config) Zero() {
	c.Hook.Secret.Zero()
	c.Cloudflare.APIToken.Zero()
	c.AzureDNS.ClientSecret.Zero()
	c.AzureDNS.PrivateKeyDER.Zero()
	c.Route53.SecretAccessKey.Zero()
}

// New builds the solver. It makes no network call; an invalid configuration returns the error of the package that
// refused it (fixed texts, no secret).
func New(c Config) (solver.Solver, error) {
	var (
		p   dnsapi.Provider
		err error
	)
	switch c.Kind {
	case KindWebhook:
		s, err := dns01.New(c.Hook)
		if err != nil {
			return nil, err // never a typed nil in the interface
		}
		return s, nil
	case KindCloudflare:
		p, err = cloudflare.New(c.Cloudflare)
	case KindAzureDNS:
		p, err = azuredns.New(c.AzureDNS)
	case KindRoute53:
		p, err = route53.New(c.Route53)
	default:
		return nil, ErrKind
	}
	if err != nil {
		return nil, err
	}
	s, err := dnsapi.New(dnsapi.Config{Provider: p, AllowedSuffixes: c.AllowedSuffixes, PropagationWait: c.PropagationWait,
		PollTimeout: c.PollTimeout, TTL: c.TTL})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Close clears the credentials a solver New built still holds (a provider's copy; the hook solver keeps its secret for
// its lifetime like before and has nothing to clear here). It is safe on any solver.
func Close(s solver.Solver) {
	if z, ok := s.(interface{ Zero() }); ok {
		z.Zero()
	}
}

// WithCleanupNames returns c with the allow-list replaced by names (the cleanup of a record Alice published: removing
// it needs no allow-list, R57 as A12).
func (c Config) WithCleanupNames(names ...string) Config {
	c.Hook.AllowedSuffixes = names
	c.AllowedSuffixes = names
	return c
}
