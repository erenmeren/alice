package nginx

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/webserver"
	"alice/internal/testutil/pki"
)

// trustFor is the policy of the fixture's leaf with roots (the CA's own root when known).
func (e *env) trustFor(known bool) *providers.TrustPolicy {
	roots := x509.NewCertPool()
	if known {
		roots.AddCert(e.ca.Root)
	}
	p := providers.TrustPolicyFor([]*x509.Certificate{e.leaf.Cert, e.ca.Intermediate}, roots, providers.TrustStoreSystem, e.now)
	return &p
}

// R51: a verification with a trust policy checks every served chain with crypto/x509 and reports the level it proved.
func TestVerifyChecksTheServedChainsTrust(t *testing.T) {
	e := newEnv(t)
	fp := pki.Fingerprint(e.leaf.Cert)
	s := e.open(t)

	vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: fp, ChainLength: 2, Trust: e.trustFor(true)})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, "remote", vr.Mode)
	assert.Equal(t, providers.LevelTrusted, vr.Level)
	assert.Equal(t, providers.Trust{Status: providers.TrustTrusted, Store: providers.TrustStoreSystem, Enforced: true}, vr.Trust)

	// Without a trust policy nothing but the leaf and the chain length is compared: level served.
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: fp, ChainLength: 2})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, providers.LevelServed, vr.Level)
	assert.Equal(t, providers.Trust{}, vr.Trust)

	// The anchor is unknown (a private CA Alice has no root of): a warning, the verification passes at level served.
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: fp, ChainLength: 2, Trust: e.trustFor(false)})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, providers.LevelServed, vr.Level)
	assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 443,
		Store: providers.TrustStoreSystem}, vr.Trust)

	// The skipped verification proves only the installation.
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: fp, Trust: e.trustFor(true),
		Verify: providers.VerifyOptions{Skip: true}})
	require.NoError(t, err)
	assert.Equal(t, providers.VerifyResult{OK: true, Mode: "skipped", Level: providers.LevelInstalled}, vr)
}

// R51: a known anchor makes a chain that does not verify a failed verification (deployment.verify_untrusted with the
// precise reason), measured again like any other mismatch before it is believed.
func TestVerifyFailsAnUntrustedChainWhenTheAnchorIsKnown(t *testing.T) {
	e := newEnv(t)
	fp := pki.Fingerprint(e.leaf.Cert)
	policy := e.trustFor(true)
	policy.Roots = x509.NewCertPool() // the chain no longer leads to a root of the store
	vr, err := e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: fp, ChainLength: 2, Trust: policy})
	require.NoError(t, err)
	assert.False(t, vr.OK)
	assert.Equal(t, "deployment.verify_untrusted", vr.Reason)
	assert.Equal(t, providers.VerifyFailureTrust, vr.Failure)
	assert.Equal(t, map[string]string{"port": "443", "trust_error": providers.TrustErrUnknownAuthority}, vr.Params)
	assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 443,
		Store: providers.TrustStoreSystem, Enforced: true}, vr.Trust)
	assert.Equal(t, providers.LevelNone, vr.Level)
	assert.Len(t, e.prober.probes(), 5, "measured again on every attempt")

	// A name the leaf does not cover (the endpoint is checked with the configured name) is a warning even with a known
	// anchor: the name is the server configuration's, which a rollback would not mend.
	e = newEnv(t)
	fp = pki.Fingerprint(e.leaf.Cert)
	vr, err = e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: fp, ChainLength: 2,
		Trust: e.trustFor(true), Verify: providers.VerifyOptions{SNI: "shop.example.test"}})
	require.NoError(t, err)
	assert.True(t, vr.OK, "%+v", vr)
	assert.Equal(t, providers.LevelServed, vr.Level)
	assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrNameMismatch, Port: 443,
		Store: providers.TrustStoreSystem, Enforced: true}, vr.Trust)

	// The same leaf on port 8443 from a file that holds the leaf only (a missing intermediate), or the leaf and another
	// CA's intermediate (a wrong one).
	other := pki.NewCA("Other", pki.ECDSA256, e.now)
	for want, fileOf := range map[string]func(e *env) []byte{
		providers.TrustErrIncompleteChain:   func(e *env) []byte { return e.leaf.CertPEM },
		providers.TrustErrWrongIntermediate: func(e *env) []byte { return append(append([]byte(nil), e.leaf.CertPEM...), other.IntermediatePEM...) },
	} {
		e := newEnv(t)
		fp := pki.Fingerprint(e.leaf.Cert)
		file := fileOf(e)
		e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"www.example.test"}, Port: 8443, CertPath: "/etc/nginx/ssl/b.crt", KeyPath: "/etc/nginx/ssl/b.key"},
			file, e.leaf.KeyPEM)
		loc := providers.CertLocation{Servers: []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Port: 8443}}}}}
		vr, err := e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: loc, Fingerprint: fp, Trust: e.trustFor(true)})
		require.NoError(t, err)
		assert.Equal(t, "deployment.verify_untrusted", vr.Reason, want)
		assert.Equal(t, map[string]string{"port": "8443", "trust_error": want}, vr.Params)
	}
}

// R51: the in-target check (tls-probe) answers the chain from protocol 11; an older helper's answer has none, so the
// trust is not checked (level served, status unchecked) and never fails the verification.
func TestVerifyChecksTrustFromTheServerProbe(t *testing.T) {
	e := newEnv(t)
	e.prober.set(true, false)
	fp := pki.Fingerprint(e.leaf.Cert)
	vr, err := e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: fp, ChainLength: 2, Trust: e.trustFor(true)})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, "local", vr.Mode)
	assert.Equal(t, providers.LevelTrusted, vr.Level)

	e = newEnv(t)
	e.prober.set(true, false)
	e.emu.SetProtocol(10)
	fp = pki.Fingerprint(e.leaf.Cert)
	policy := e.trustFor(true)
	policy.Roots = x509.NewCertPool()
	vr, err = e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: fp, ChainLength: 2, Trust: policy})
	require.NoError(t, err)
	assert.True(t, vr.OK, "nothing to check is no failure")
	assert.Equal(t, providers.LevelServed, vr.Level)
	assert.Equal(t, providers.TrustUnchecked, vr.Trust.Status)
	assert.Empty(t, vr.Trust.Error)
}

// R51: a network failure (no handshake on any attempt) is told apart from a certificate that is not the expected one.
func TestVerifyTellsANetworkFailureFromAWrongCertificate(t *testing.T) {
	e := newEnv(t)
	fp := pki.Fingerprint(e.leaf.Cert)
	s := e.open(t)
	vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: strings.Repeat("a", 64), PreviousFingerprint: fp})
	require.NoError(t, err)
	assert.Equal(t, "deployment.verify_failed", vr.Reason)
	assert.Equal(t, providers.VerifyFailureCertificate, vr.Failure)

	e.prober.set(true, false)
	e.emu.LocalProbeFails(true)
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: fp})
	require.NoError(t, err)
	assert.Equal(t, "deployment.verify_unreachable", vr.Reason)
	assert.Equal(t, providers.VerifyFailureNetwork, vr.Failure)
}

// R51: one connection timeout of Alice's own probe is measured again in the next attempt (it does not hand the endpoint
// to the server-side probe for good, which cannot reach a listen on the target's public address); a refused connection
// still does.
func TestVerifyMeasuresAgainAfterAProbeTimeout(t *testing.T) {
	e := newEnv(t)
	e.emu.LocalProbeFails(true)
	flaky := &timeoutProber{emuProber: e.prober, timeouts: 1}
	e.prov.prober = flaky
	vr, err := e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert)})
	require.NoError(t, err)
	assert.True(t, vr.OK, "%+v", vr)
	assert.Equal(t, "remote", vr.Mode)
	assert.Equal(t, 2, flaky.n, "the second attempt reached the website")

	e = newEnv(t)
	e.emu.LocalProbeFails(true)
	e.prober.set(true, false)
	vr, err = e.open(t).VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert)})
	require.NoError(t, err)
	assert.Equal(t, providers.VerifyFailureNetwork, vr.Failure)
	assert.Len(t, e.prober.probes(), 1, "a refused connection is not tried again from Alice")
}

// timeoutProber times out (ErrProbeUnreachable wrapping a timeout) for the first timeouts probes.
type timeoutProber struct {
	*emuProber
	timeouts, n int
}

func (p *timeoutProber) Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error) {
	p.n++
	if p.n <= p.timeouts {
		return Probe{}, fmt.Errorf("%w: %w", ErrProbeUnreachable, os.ErrDeadlineExceeded)
	}
	return p.emuProber.Probe(ctx, host, port, sni, keyType)
}

// The chain bound of a probe answer is the provider's (helperproto says a test compares them).
func TestProbeChainBoundsMatchTheProvider(t *testing.T) {
	assert.Equal(t, webserver.MaxChainCerts, helperproto.MaxProbeChainCerts)
}
