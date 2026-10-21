// Package tlspin checks the server identity of an API target (R59 G2; a BIG-IP's management interface, a Kubernetes
// API server, later a WinRM listener) the way linuxssh checks an SSH host key: either the identity Alice pinned (the
// SubjectPublicKeyInfo of the certificate the server presents, host_keys key type tls-spki, confirmed by an
// Administrator) or, instead, a CA bundle in the target's configuration (a verified chain for the server name, no pin).
//
// In pin mode the presented identity is compared with the pinned one, never with any CA: a server without a pinned
// identity, or presenting another one, fails the handshake before a request is sent, and the sighting is recorded
// through providers.HostKeyStore (observed, or a change that blocks the target), so the existing confirm flow and the
// host_key_changed status apply unchanged. Background work never pins anything.
package tlspin

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"alice/internal/providers"
)

// Error codes, the same as an SSH host key's: the inventory and the UI treat both as the target's server identity.
const (
	CodeUnconfirmed = "target.host_key_unconfirmed"
	CodeChanged     = "target.host_key_changed"
)

// ErrIdentityRefused is the handshake's error when the presented identity is not the pinned one (or nothing is pinned).
// Refusal turns it into the provider error.
var ErrIdentityRefused = errors.New("tlspin: the server identity is not the pinned one")

// ErrNoCertificates: a CA bundle with no certificate Alice can read.
var ErrNoCertificates = errors.New("tlspin: the CA bundle holds no certificate")

// DefaultObserveTimeout bounds the recording of a sighting (as linuxssh's handshake budget bounds its own).
const DefaultObserveTimeout = 10 * time.Second

// Options configure one Verifier.
type Options struct {
	Target     uuid.UUID
	ServerName string // SNI, and the name a CA-verified certificate must carry
	// CABundlePEM, when set, selects CA mode: the chain must verify against these roots only (never the system's) for
	// ServerName; nothing is pinned or recorded.
	CABundlePEM []byte
	// Store is the pin and the sightings (pin mode; required then).
	Store          providers.HostKeyStore
	ObserveTimeout time.Duration // 0 = DefaultObserveTimeout
}

// Verifier is the identity check of the connections to one target. Build one per session (New reads the pin once).
type Verifier struct {
	opts   Options
	roots  *x509.CertPool
	pinned *providers.HostKey

	mu        sync.Mutex
	presented *providers.HostKey // the last refused identity
}

// New reads the pinned identity (pin mode) or the CA bundle (CA mode). A pin of another key type (an SSH key) is an
// error: the target was not set up as an API target.
func New(ctx context.Context, o Options) (*Verifier, error) {
	v := &Verifier{opts: o}
	if len(o.CABundlePEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(o.CABundlePEM) {
			return nil, providers.NewError("internal.unexpected", false, ErrNoCertificates, nil)
		}
		v.roots = pool
		return v, nil
	}
	if o.Store == nil {
		return nil, providers.NewError("internal.unexpected", false, errors.New("tlspin: no host key store"), nil)
	}
	k, err := o.Store.Pinned(ctx, o.Target)
	switch {
	case errors.Is(err, providers.ErrNoPinnedKey):
	case err != nil:
		if ctx.Err() != nil {
			return nil, providers.NewError("internal.unexpected", true, ctx.Err(), nil)
		}
		return nil, providers.NewError("internal.unexpected", true, err, nil)
	case k.Type != providers.HostKeyTypeTLSSPKI:
		return nil, providers.NewError("internal.unexpected", false, errors.New("tlspin: the pinned key is not a TLS identity"), nil)
	default:
		v.pinned = &k
	}
	return v, nil
}

// PinMode reports whether the identity is pinned (rather than verified against a CA bundle).
func (v *Verifier) PinMode() bool { return v.roots == nil }

// TLSConfig is the client configuration of one connection: TLS 1.2 or later, SNI ServerName, and the identity check.
func (v *Verifier) TLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: v.opts.ServerName}
	if v.roots != nil {
		cfg.RootCAs = v.roots
		return cfg
	}
	// The chain is not what is trusted here: the pinned SubjectPublicKeyInfo is (a self-signed management certificate is
	// the common case). VerifyConnection runs for every handshake, resumed ones included.
	cfg.InsecureSkipVerify = true //nolint:gosec // G402: the identity is checked against the pin in VerifyConnection
	cfg.VerifyConnection = v.verify
	return cfg
}

func (v *Verifier) verify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return ErrIdentityRefused
	}
	got := providers.TLSIdentity(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if v.pinned != nil && subtle.ConstantTimeCompare(got.PublicKey, v.pinned.PublicKey) == 1 {
		return nil
	}
	v.mu.Lock()
	v.presented = &got
	v.mu.Unlock()
	return ErrIdentityRefused
}

// Refusal turns a failed connection into the target's identity error, after recording the sighting: the presented
// identity as observed (nothing pinned: CodeUnconfirmed with its fingerprint) or as a change (another one pinned:
// CodeChanged with both fingerprints; the store blocks the target). It returns nil when err is not an identity refusal
// (the caller maps it as a network or protocol error), and an internal.unexpected error when the sighting could not be
// recorded (a later connection records it again).
func (v *Verifier) Refusal(ctx context.Context, err error) error {
	if err == nil || !errors.Is(err, ErrIdentityRefused) {
		return nil
	}
	v.mu.Lock()
	presented := v.presented
	v.mu.Unlock()
	if presented == nil {
		return providers.NewError("internal.unexpected", false, errors.New("tlspin: the server presented no certificate"), nil)
	}
	if oerr := v.observe(ctx, *presented); oerr != nil {
		return providers.NewError("internal.unexpected", true, oerr, nil)
	}
	if v.pinned == nil {
		return providers.NewError(CodeUnconfirmed, false, nil, map[string]string{"fingerprint": presented.Fingerprint})
	}
	return providers.NewError(CodeChanged, false, nil,
		map[string]string{"old_fingerprint": v.pinned.Fingerprint, "new_fingerprint": presented.Fingerprint})
}

// observe records the sighting within the budget; the store runs in its own goroutine so one that ignores its context
// cannot hang the caller.
func (v *Verifier) observe(ctx context.Context, k providers.HostKey) error {
	d := v.opts.ObserveTimeout
	if d <= 0 {
		d = DefaultObserveTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	res := make(chan error, 1)
	go func() { res <- v.opts.Store.Observed(ctx, v.opts.Target, k, v.pinned != nil) }()
	select {
	case err := <-res:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
