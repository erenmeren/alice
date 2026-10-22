package windows

import (
	"context"
	"testing"
	"time"

	"alice/internal/providers"
	"alice/internal/providers/providertest"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

// Spec §6.5 item 5: the shared conformance suite over real SSH sessions against the emulated host,
// with the four capabilities W2 advertises; the private key must never appear in any result or error.
func TestWindowsConformance(t *testing.T) {
	e := newEnv(t)
	want := providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverCerts, providers.CapDeployCertificate,
		providers.CapVerifyDeployment)
	providertest.CheckProvider(t, e.prov)
	providertest.CheckSession(t, providertest.SessionHarness{
		Capabilities: e.prov.Capabilities(),
		Open: func(ctx context.Context) (providers.Session, error) {
			return e.prov.Open(ctx, e.ref, e.cred, providers.Env{})
		},
		Secrets: e.cred.secrets(t),
	})
	providertest.CheckUnsupported(t, e.open(t), want)

	// A session without the deployment capabilities answers ErrUnsupported for each of them.
	s, ok := e.open(t).(*session)
	if !ok {
		t.Fatal("not a Windows session")
	}
	s.caps = providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverCerts)
	providertest.CheckUnsupported(t, s, s.caps)
}

// R59 G7 / Review Focus 3: the deployment contract of a location that is not a file, each case on a
// fresh emulated host whose IIS binding names the current certificate; the helper checks the guard on
// the server (a forbidden rollback restores nothing), the traits are {on_target, self-restores}.
func TestWindowsLocationTargetContract(t *testing.T) {
	now := time.Now()
	ca := pki.NewCA("Contract", pki.ECDSA256, now)
	cur := ca.Issue(pki.Opts{CommonName: wHost, SANs: []string{wHost}}, now)
	next := ca.Issue(pki.Opts{CommonName: wHost, SANs: []string{wHost}}, now)
	var prov *Provider
	fresh := func(ctx context.Context) (providers.Session, error) {
		m := wintest.NewModel()
		m.AddIntermediate(ca.IntermediatePEM)
		sha1 := m.AddCertificate("My", cur.CertPEM, cur.KeyPEM, wintest.CertOptions{})
		m.AddBinding(winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: wHost, Port: 443, AppID: winproto.AppIDIIS,
			CertSHA1: sha1, Store: "My"})
		e := newEnvWith(t, m)
		prov = e.prov
		return e.prov.Open(ctx, e.ref, e.cred, providers.Env{})
	}
	if _, err := fresh(context.Background()); err != nil { // the provider's traits
		t.Fatal(err)
	}
	providertest.CheckLocationTarget(t, providertest.LocationTargetHarness{
		Traits: providers.TraitsOf(prov),
		Fresh:  fresh,
		Location: providers.CertLocation{Kind: providers.LocationWinSSLBinding,
			Locator:  providers.Locator{"type": winproto.BindingHostnamePort, "host": wHost, "port": 443, "app_id": winproto.AppIDIIS},
			CertPath: "http.sys/hostnameport/" + wHost + ":443", Supported: true,
			Details: map[string]any{"store": "My", "cert_sha1": sha1Hex(cur.Cert.Raw), "application": "iis"}},
		ExpectCertSHA256: derSHA256(cur.Cert.Raw),
		Current:          providertest.Chain{CertificatePEM: cur.FullchainPEM, PrivateKeyPEM: cur.KeyPEM},
		Next:             providertest.Chain{CertificatePEM: next.FullchainPEM, PrivateKeyPEM: next.KeyPEM},
	})
	if got := providers.TraitsOf(prov); got != (providers.RollbackTraits{Backup: providers.BackupOnTarget, SelfRestores: true}) {
		t.Errorf("traits %+v", got)
	}
}
