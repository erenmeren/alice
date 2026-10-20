package nginx

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

// paramsOf is the params of the first step logged as entry ("name:status").
func (l *steps) paramsOf(entry string) map[string]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, n := range l.names {
		if n == entry {
			return l.params[i]
		}
	}
	return nil
}

// R51: the deployment's verification checks the trust of the served chain and the outcome carries what it found.
func TestDeployRecordsTheTrustOfTheServedChain(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	req := e.req(t, nw)
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Root)
	p := providers.TrustPolicyFor([]*x509.Certificate{nw.Cert, e.ca.Intermediate}, roots, providers.TrustStoreACME, e.now)
	req.Trust = &p
	log := &steps{}
	out, err := e.open(t).DeployCertificate(context.Background(), req, log)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, providers.Trust{Status: providers.TrustTrusted, Store: providers.TrustStoreACME, Enforced: true}, out.Trust)
	assert.Equal(t, map[string]string{"mode": "remote", "trust": providers.TrustTrusted}, log.paramsOf("verify:ok"))
}

// R51: with a known anchor, a served chain that does not verify fails the deployment and starts the rollback (and its
// R48 guard) like any failed verification; the reason names the precise fault.
func TestDeployRollsBackAnUntrustedChain(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	req := e.req(t, nw)
	req.Trust = &providers.TrustPolicy{Roots: x509.NewCertPool(), Expected: []*x509.Certificate{nw.Cert, e.ca.Intermediate},
		Store: providers.TrustStoreSystem, Enforce: true}
	log := &steps{}
	out, err := e.open(t).DeployCertificate(context.Background(), req, log)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result)
	assert.Equal(t, providers.StepNameVerify, out.FailedStep)
	assert.Equal(t, "deployment.verify_untrusted", out.Reason)
	assert.Equal(t, map[string]string{"port": "443", "trust_error": providers.TrustErrUnknownAuthority}, out.Params)
	assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 443,
		Store: providers.TrustStoreSystem, Enforced: true}, out.Trust)
	assert.Equal(t, map[string]string{"port": "443", "reason": "deployment.verify_untrusted", "trust_error": providers.TrustErrUnknownAuthority},
		log.paramsOf("verify:failed"))
	assert.Equal(t, pki.Fingerprint(e.leaf.Cert), e.emu.Served(443, "www.example.test"), "the previous certificate is back")
	require.NoError(t, out.Validate())

	// Not enforced (the anchor is unknown): the deployment commits with the warning.
	e = newEnv(t)
	nw = e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	req = e.req(t, nw)
	req.Trust = &providers.TrustPolicy{Roots: x509.NewCertPool(), Expected: []*x509.Certificate{nw.Cert, e.ca.Intermediate}, Store: providers.TrustStoreSystem}
	out, err = e.open(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 443,
		Store: providers.TrustStoreSystem}, out.Trust)
}
