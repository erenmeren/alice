package azuredns_test

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/acme/solver/dnsapi/azuredns"
	"alice/internal/secrets"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// world is one fake Azure (Entra ID, IMDS, Resource Manager) and a provider signed in to it.
type world struct {
	s   *fakekv.Server
	cfg azuredns.Config
	p   *azuredns.Provider
}

func defaultZones(o *fakekv.Options) {
	if o.DNSZones == nil && o.DNSPrivateZones == nil {
		o.DNSZones = []string{"example.test"}
	}
}

// secretWorld signs in with the application's client secret.
func secretWorld(t *testing.T, o fakekv.Options, mut ...func(*azuredns.Config)) *world {
	t.Helper()
	defaultZones(&o)
	s := fakekv.Start(t, o)
	cfg := baseConfig(s)
	cfg.Auth = azuredns.AuthClientSecret
	cfg.TenantID, cfg.ClientID = s.TenantID(), s.ClientID()
	cfg.ClientSecret = secrets.NewPlaintext([]byte(s.Secret()))
	return finish(t, s, cfg, mut)
}

// spLeaf is an RSA certificate credential of the application.
func spLeaf(t testing.TB) (pki.Leaf, []byte) {
	t.Helper()
	ca := pki.NewCA("SP", pki.RSA2048, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "alice-sp", KeyType: pki.RSA2048}, time.Now())
	der, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
	require.NoError(t, err)
	return leaf, der
}

// certWorld signs in with a registered certificate.
func certWorld(t *testing.T, o fakekv.Options, mut ...func(*azuredns.Config)) (*world, []byte) {
	t.Helper()
	leaf, der := spLeaf(t)
	o.ClientCert = leaf.Cert
	defaultZones(&o)
	s := fakekv.Start(t, o)
	cfg := baseConfig(s)
	cfg.Auth = azuredns.AuthCertificate
	cfg.TenantID, cfg.ClientID = s.TenantID(), s.ClientID()
	cfg.CertificateDER = leaf.Cert.Raw
	cfg.PrivateKeyDER = secrets.NewPlaintext(append([]byte(nil), der...))
	return finish(t, s, cfg, mut), der
}

// miWorld signs in as a user-assigned managed identity with a fresh client ID (MSAL caches managed-identity tokens
// process-wide by client ID).
func miWorld(t *testing.T, o fakekv.Options, mut ...func(*azuredns.Config)) *world {
	t.Helper()
	o.ManagedIdentity = true
	o.MIClientID = fakekv.UniqueClientID()
	defaultZones(&o)
	s := fakekv.Start(t, o)
	cfg := baseConfig(s)
	cfg.Auth = azuredns.AuthManagedIdentity
	cfg.ClientID = o.MIClientID
	return finish(t, s, cfg, mut)
}

func baseConfig(s *fakekv.Server) azuredns.Config {
	cfg := azuredns.Config{SubscriptionID: s.DNSSubscriptionID(), ResourceGroup: s.DNSResourceGroup(), BaseRoots: s.CAPool()}
	return azuredns.WithMapAddr(cfg, s.DialAddr)
}

func finish(t *testing.T, s *fakekv.Server, cfg azuredns.Config, mut []func(*azuredns.Config)) *world {
	t.Helper()
	for _, m := range mut {
		m(&cfg)
	}
	p, err := azuredns.New(cfg)
	require.NoError(t, err)
	return &world{s: s, cfg: cfg, p: p}
}

// solverOf is the generic DNS-01 solver over the world's provider, for names below example.test and apex.test.
func (w *world) solverOf(t *testing.T) *dnsapi.Solver {
	t.Helper()
	sv, err := dnsapi.New(dnsapi.Config{Provider: w.p, AllowedSuffixes: []string{"example.test", "apex.test"}, PropagationWait: -1})
	require.NoError(t, err)
	return sv
}

func chal(domain, value string) solver.Challenge {
	d := strings.TrimPrefix(domain, "*.")
	return solver.Challenge{Type: solver.DNS01, Domain: d, Wildcard: strings.HasPrefix(domain, "*."), Token: "tok",
		DNSName: "_acme-challenge." + d, DNSValue: value}
}

func ctx5(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func errorOf(t *testing.T, err error) *acme.Error {
	t.Helper()
	require.Error(t, err)
	var ae *acme.Error
	require.ErrorAs(t, err, &ae)
	return ae
}

// managementRequests are the logged requests to the Resource Manager.
func managementRequests(s *fakekv.Server) []fakekv.Request {
	var out []fakekv.Request
	for _, r := range s.Requests() {
		if r.Host == azuredns.ManagementHost {
			out = append(out, r)
		}
	}
	return out
}
