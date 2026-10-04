package azurekv

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// idSource is a providers.AzureCredentialSource for tests: it hands out id and counts releases.
type idSource struct {
	id       providers.AzureIdentity
	err      error
	released atomic.Int32
}

func (s *idSource) AzureIdentity(context.Context) (providers.AzureIdentity, func(), error) {
	if s.err != nil {
		return providers.AzureIdentity{}, nil, s.err
	}
	return s.id, func() { s.released.Add(1) }, nil
}

// SSHSigner makes idSource a providers.CredentialSource; an Azure provider never calls it.
func (s *idSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, nil, errors.New("not an SSH credential")
}

// sshSource is a credential source that is not an Azure one.
type sshSource struct{}

func (sshSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, nil, errors.New("not used")
}

func secretIdentity(s *fakekv.Server) providers.AzureIdentity {
	return providers.AzureIdentity{Auth: providers.AzureAuthClientSecret, TenantID: s.TenantID(), ClientID: s.ClientID(),
		ClientSecret: providers.NewSecret([]byte(s.Secret()))}
}

// testProvider is a provider whose requests reach the fake: the dial is mapped, the URL and the TLS
// name stay the real vault's.
func testProvider(s *fakekv.Server) *Provider {
	return New(Options{
		RootCAs:  func() (*x509.CertPool, error) { return s.CAPool(), nil },
		dialAddr: s.DialAddr,
		jitter:   func(d time.Duration) time.Duration { return d },
	})
}

func nopLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func nearNow() *clock.Fake { return clock.NewFake(time.Now()) }

func target() providers.TargetRef {
	return providers.TargetRef{ID: uuid.New(), Kind: providers.KindAzureKV, Config: providers.TargetConfig{"vault_url": "https://" + testVaultHost}}
}

func openSession(t testing.TB, p *Provider, src providers.CredentialSource, clk clock.Clock) *session {
	t.Helper()
	sess, err := p.Open(context.Background(), target(), src, providers.Env{Clock: clk})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	return sess.(*session)
}

func rsaSP(t testing.TB) pki.Leaf {
	t.Helper()
	ca := pki.NewCA("SP", pki.RSA2048, time.Now())
	return ca.Issue(pki.Opts{CommonName: "alice-sp", KeyType: pki.RSA2048}, time.Now())
}
