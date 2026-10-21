package dnssolver

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dns01"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/acme/solver/dnsapi/azuredns"
	"alice/internal/acme/solver/dnsapi/cloudflare"
	"alice/internal/acme/solver/dnsapi/route53"
	"alice/internal/secrets"
)

const (
	tokenText = "a-cloudflare-token-for-tests-only-0123"
	keyText   = "a-route53-secret-for-tests-only-0123"
	hookText  = "a-hook-secret-for-tests-only-0123"
)

func configs() map[string]Config {
	return map[string]Config{
		KindWebhook: {Kind: KindWebhook, Hook: dns01.Config{URL: "https://dns.example.test/hook", Secret: secrets.NewPlaintext([]byte(hookText)),
			AllowedSuffixes: []string{"example.test"}}},
		KindCloudflare: {Kind: KindCloudflare, Cloudflare: cloudflare.Config{APIToken: secrets.NewPlaintext([]byte(tokenText))},
			AllowedSuffixes: []string{"example.test"}, PropagationWait: -1, PollTimeout: 30 * time.Second},
		KindAzureDNS: {Kind: KindAzureDNS, AzureDNS: azuredns.Config{Auth: azuredns.AuthManagedIdentity,
			SubscriptionID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ResourceGroup: "dns"}, AllowedSuffixes: []string{"example.test"}},
		KindRoute53: {Kind: KindRoute53, Route53: route53.Config{AccessKeyID: "TESTACCESSKEYID0001", SecretAccessKey: secrets.NewPlaintext([]byte(keyText))},
			AllowedSuffixes: []string{"example.test"}},
	}
}

func TestNewBuildsTheSolverOfEachKind(t *testing.T) {
	assert.Equal(t, []string{"webhook", "cloudflare", "azure_dns", "route53"}, Kinds())
	for kind, cfg := range configs() {
		s, err := New(cfg)
		require.NoError(t, err, kind)
		assert.Equal(t, []string{solver.DNS01}, s.Types(), kind)
		if kind == KindWebhook {
			assert.IsType(t, &dns01.Solver{}, s)
		} else {
			ds, ok := s.(*dnsapi.Solver)
			require.True(t, ok, kind)
			assert.Equal(t, kind, ds.Kind())
		}
		Close(s) // a provider's copy is cleared; the hook's solver has none
	}
}

func TestNewRefusesABadConfiguration(t *testing.T) {
	_, err := New(Config{Kind: "bind"})
	assert.ErrorIs(t, err, ErrKind)
	bad := configs()
	cases := map[string]Config{}
	h := bad[KindWebhook]
	h.Hook.URL = "http://dns.example.test"
	cases["hook"] = h
	c := bad[KindCloudflare]
	c.Cloudflare.APIToken = secrets.NewPlaintext([]byte("short"))
	cases["cloudflare"] = c
	a := bad[KindAzureDNS]
	a.AzureDNS.SubscriptionID = "x"
	cases["azure"] = a
	r := bad[KindRoute53]
	r.Route53.AccessKeyID = "lower"
	cases["route53"] = r
	w := bad[KindCloudflare]
	w.PropagationWait = 10 * time.Minute
	cases["wait"] = w
	for name, cfg := range cases {
		s, err := New(cfg)
		require.Error(t, err, name)
		assert.Nil(t, s, "%s: never a typed nil in the interface", name)
	}
}

func TestZeroAndPrinting(t *testing.T) {
	cfg := configs()[KindCloudflare]
	r := configs()[KindRoute53]
	cfg.Route53 = r.Route53
	cfg.Hook = configs()[KindWebhook].Hook
	cfg.AzureDNS.ClientSecret = secrets.NewPlaintext([]byte("azure-secret"))
	cfg.AzureDNS.PrivateKeyDER = secrets.NewPlaintext([]byte("azure-key"))
	for _, f := range []string{fmt.Sprint(cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg), cfg.GoString()} {
		assert.Equal(t, "dnssolver.Config{kind: cloudflare, secrets: redacted}", f)
		for _, s := range []string{tokenText, keyText, hookText, "azure-secret", "azure-key"} {
			assert.NotContains(t, f, s)
		}
	}
	cfg.Zero()
	for _, b := range [][]byte{cfg.Cloudflare.APIToken.Bytes(), cfg.Route53.SecretAccessKey.Bytes(), cfg.Hook.Secret.Bytes(),
		cfg.AzureDNS.ClientSecret.Bytes(), cfg.AzureDNS.PrivateKeyDER.Bytes()} {
		assert.Equal(t, make([]byte, len(b)), b)
	}
}

func TestWithCleanupNames(t *testing.T) {
	cfg := configs()[KindWebhook].WithCleanupNames("www.example.test")
	assert.Equal(t, []string{"www.example.test"}, cfg.Hook.AllowedSuffixes)
	assert.Equal(t, []string{"www.example.test"}, cfg.AllowedSuffixes)
	Close(nil) // nothing to clear
}
