package azuredns_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/acme/solver/dnsapi/azuredns"
	"alice/internal/secrets"
	"alice/internal/testutil/fakekv"
)

// ---- sign-in ----

func TestEverySignInMethodPublishesAndRemoves(t *testing.T) {
	cases := map[string]func(t *testing.T) *world{
		"client secret":    func(t *testing.T) *world { return secretWorld(t, fakekv.Options{}) },
		"certificate":      func(t *testing.T) *world { w, _ := certWorld(t, fakekv.Options{}); return w },
		"managed identity": func(t *testing.T) *world { return miWorld(t, fakekv.Options{}) },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			w := mk(t)
			assert.Empty(t, w.s.Requests(), "New makes no network call")
			sv := w.solverOf(t)
			require.NoError(t, sv.Present(ctx5(t), chal("www.example.test", "v1")))
			assert.Equal(t, []string{"v1"}, w.s.DNSRecords()["_acme-challenge.www.example.test"])
			assert.Equal(t, dnsapi.DefaultTTL, w.s.DNSRecordTTL("_acme-challenge.www.example.test"))
			require.NoError(t, sv.CleanUp(ctx5(t), chal("www.example.test", "v1")))
			assert.Empty(t, w.s.DNSRecords())
			mr := managementRequests(w.s)
			require.NotEmpty(t, mr)
			for _, r := range mr {
				assert.True(t, r.HadAuth, "%s %s carried the token", r.Method, r.Path)
				assert.Equal(t, []string{"api-version"}, r.Query)
			}
		})
	}
}

func TestTokenIsAskedOnceAndForTheResourceManager(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	sv := w.solverOf(t)
	require.NoError(t, sv.Present(ctx5(t), chal("a.example.test", "v")))
	require.NoError(t, sv.Present(ctx5(t), chal("b.example.test", "v")))
	tokens := 0
	for _, r := range w.s.Requests() {
		if r.Host == "login.microsoftonline.com" && strings.HasSuffix(r.Path, "/token") {
			tokens++
			assert.Equal(t, "/"+w.s.TenantID()+"/oauth2/v2.0/token", r.Path, "the configured tenant only")
		}
	}
	assert.Equal(t, 1, tokens, "the credential caches the token")
}

func TestWrongClientSecretIsAuthFailed(t *testing.T) {
	w := secretWorld(t, fakekv.Options{}, func(c *azuredns.Config) {
		c.ClientSecret = secrets.NewPlaintext([]byte(fakekv.NewClientSecret()))
	})
	e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, acme.ReasonDNSAuthFailed, e.Reason)
	assert.Equal(t, "example.test", e.Identifier)
	assert.Equal(t, http.StatusUnauthorized, e.Status)
	assert.Equal(t, acme.ClassPermanent, acme.FailureClass(e))
	assert.Empty(t, managementRequests(w.s), "no DNS call without a token")
}

func TestUnknownTenantAndUnknownCertificateAreAuthFailed(t *testing.T) {
	w := secretWorld(t, fakekv.Options{}, func(c *azuredns.Config) { c.TenantID = fakekv.UniqueClientID() })
	assert.Equal(t, acme.ReasonDNSAuthFailed, acme.ReasonOf(w.solverOf(t).Present(ctx5(t), chal("example.test", "v"))))

	wc, _ := certWorld(t, fakekv.Options{}, func(c *azuredns.Config) {
		other, der := spLeaf(t)
		c.CertificateDER, c.PrivateKeyDER = other.Cert.Raw, secrets.NewPlaintext(der)
	})
	assert.Equal(t, acme.ReasonDNSAuthFailed, acme.ReasonOf(wc.solverOf(t).Present(ctx5(t), chal("example.test", "v"))))
}

func TestManagedIdentityThatIsNotAssignedIsAuthFailed(t *testing.T) {
	w := miWorld(t, fakekv.Options{}, func(c *azuredns.Config) { c.ClientID = fakekv.UniqueClientID() })
	e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, acme.ReasonDNSAuthFailed, e.Reason)
	assert.Equal(t, acme.ClassPermanent, acme.FailureClass(e))
}

func TestEntraOutageIsTransient(t *testing.T) {
	for name, f := range map[string]fakekv.Fault{
		"503":   {Status: http.StatusServiceUnavailable},
		"429":   {Status: http.StatusTooManyRequests},
		"reset": {Reset: true},
		"drop":  {Drop: true},
	} {
		t.Run(name, func(t *testing.T) {
			w := secretWorld(t, fakekv.Options{})
			w.s.FailAll("/"+w.s.TenantID()+"/", f)
			e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
			assert.Equal(t, acme.ClassTransient, acme.FailureClass(e), "%v", e)
			assert.Equal(t, acme.ReasonDNSProviderError, e.Reason)
		})
	}
}

func TestIMDSOutageIsTransient(t *testing.T) {
	w := miWorld(t, fakekv.Options{})
	w.s.FailAll("/metadata/", fakekv.Fault{Reset: true})
	e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, acme.ClassTransient, acme.FailureClass(e))
}

func TestRefusedEnvironmentSendsNothing(t *testing.T) {
	for _, name := range []string{"AZURE_REGIONAL_AUTHORITY_NAME", "MSAL_FORCE_REGION", "AZURE_SDK_GO_LOGGING"} {
		t.Run(name, func(t *testing.T) {
			w := secretWorld(t, fakekv.Options{})
			t.Setenv(name, "westeurope")
			e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
			assert.Equal(t, acme.ReasonDNSAuthFailed, e.Reason)
			assert.Zero(t, e.Status)
			assert.Empty(t, w.s.Requests(), "the guard refused before any request")
		})
	}
}

func TestZeroDropsTheCredential(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	w.p.Zero()
	assert.Equal(t, acme.ReasonDNSAuthFailed, acme.ReasonOf(w.solverOf(t).Present(ctx5(t), chal("example.test", "v"))))
	assert.Empty(t, w.s.Requests())
}

// ---- the record set ----

func TestWildcardAndBaseShareTheRecordSet(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	sv := w.solverOf(t)
	wild, base := chal("*.example.test", "wild-value"), chal("example.test", "base-value")
	require.NoError(t, sv.Present(ctx5(t), wild))
	require.NoError(t, sv.Present(ctx5(t), base))
	require.NoError(t, sv.Present(ctx5(t), base), "idempotent")
	assert.Equal(t, []string{"wild-value", "base-value"}, w.s.DNSRecords()["_acme-challenge.example.test"])
	require.NoError(t, sv.CleanUp(ctx5(t), wild))
	assert.Equal(t, []string{"base-value"}, w.s.DNSRecords()["_acme-challenge.example.test"], "only the exact value is removed")
	require.NoError(t, sv.CleanUp(ctx5(t), wild), "removing a value that is gone succeeds")
	require.NoError(t, sv.CleanUp(ctx5(t), base))
	assert.Empty(t, w.s.DNSRecords(), "the last value deletes the record set")
	require.NoError(t, sv.CleanUp(ctx5(t), base), "removing from a record set that is gone succeeds")
	var deletes int
	for _, r := range managementRequests(w.s) {
		if r.Method == http.MethodDelete {
			deletes++
		}
	}
	assert.Equal(t, 1, deletes)
}

func TestOtherValuesMetadataAndTTLAreKept(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	w.s.SetDNSTXT("example.test", "_acme-challenge", 3600, "theirs")
	sv := w.solverOf(t)
	require.NoError(t, sv.Present(ctx5(t), chal("example.test", "ours")))
	assert.Equal(t, []string{"theirs", "ours"}, w.s.DNSRecords()["_acme-challenge.example.test"])
	assert.Equal(t, dnsapi.DefaultTTL, w.s.DNSRecordTTL("_acme-challenge.example.test"), "an add sets the solver's TTL")
	assert.Equal(t, map[string]string{"owner": "someone-else"}, w.s.DNSRecordMetadata("_acme-challenge.example.test"))
	w.s.SetDNSTXT("example.test", "_acme-challenge", 3600, "theirs", "ours")
	require.NoError(t, sv.CleanUp(ctx5(t), chal("example.test", "ours")))
	assert.Equal(t, []string{"theirs"}, w.s.DNSRecords()["_acme-challenge.example.test"])
	assert.Equal(t, 3600, w.s.DNSRecordTTL("_acme-challenge.example.test"), "a removal keeps the TTL")
	assert.Equal(t, map[string]string{"owner": "someone-else"}, w.s.DNSRecordMetadata("_acme-challenge.example.test"))
}

func TestApexOfAChallengeZone(t *testing.T) {
	w := secretWorld(t, fakekv.Options{DNSZones: []string{"apex.test", "_acme-challenge.apex.test"}})
	sv := w.solverOf(t)
	require.NoError(t, sv.Present(ctx5(t), chal("apex.test", "v")))
	assert.Equal(t, []string{"v"}, w.s.DNSRecords()["_acme-challenge.apex.test"])
	var paths []string
	for _, r := range managementRequests(w.s) {
		paths = append(paths, r.Path)
	}
	assert.Contains(t, paths, w.s.DNSRecordPath("_acme-challenge.apex.test", "@"))
	require.NoError(t, sv.CleanUp(ctx5(t), chal("apex.test", "v")))
	assert.Empty(t, w.s.DNSRecords())
}

func TestLongestZoneAndPrivateZoneSkipped(t *testing.T) {
	w := secretWorld(t, fakekv.Options{DNSZones: []string{"example.test", "www.example.test"}, DNSPrivateZones: []string{"deep.www.example.test"}})
	sv := w.solverOf(t)
	require.NoError(t, sv.Present(ctx5(t), chal("deep.www.example.test", "v")))
	assert.Equal(t, []string{"v"}, w.s.DNSRecords()["_acme-challenge.deep.www.example.test"])
	var paths []string
	for _, r := range managementRequests(w.s) {
		paths = append(paths, r.Path)
	}
	assert.Contains(t, paths, w.s.DNSRecordPath("www.example.test", "_acme-challenge.deep"))
}

func TestZoneListingIsPaged(t *testing.T) {
	zones := []string{"a.test", "b.test", "c.test", "example.test"}
	w := secretWorld(t, fakekv.Options{DNSZones: zones, DNSPageSize: 1})
	require.NoError(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
	lists := 0
	for _, r := range managementRequests(w.s) {
		if r.Path == w.s.DNSZonesPath() {
			lists++
		}
	}
	assert.Equal(t, 4, lists)
}

func TestTooManyPagesFail(t *testing.T) {
	var zones []string
	for i := range azuredns.MaxZonePages + 1 {
		zones = append(zones, fmt.Sprintf("z%d.test", i))
	}
	w := secretWorld(t, fakekv.Options{DNSZones: append(zones, "example.test"), DNSPageSize: 1})
	e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, acme.ReasonDNSProviderError, e.Reason)
	assert.Equal(t, acme.ClassPermanent, acme.FailureClass(e))
	assert.Len(t, managementRequests(w.s), azuredns.MaxZonePages)
}

func TestNextLinkElsewhereIsRefused(t *testing.T) {
	w := secretWorld(t, fakekv.Options{ExtraHosts: []string{"evil.test"}})
	for _, link := range []string{
		"https://evil.test" + w.s.DNSZonesPath() + "?api-version=2018-05-01",
		"http://management.azure.com" + w.s.DNSZonesPath() + "?api-version=2018-05-01",
		"https://management.azure.com:8443" + w.s.DNSZonesPath(),
		"https://user@management.azure.com" + w.s.DNSZonesPath(),
		"https://management.azure.com/subscriptions/" + w.s.DNSSubscriptionID() + "/providers/Microsoft.Network/dnsZones",
		"https://management.azure.com" + w.s.DNSZonesPath() + "#frag",
		"::not a url",
	} {
		w.s.FailNext(w.s.DNSZonesPath(), fakekv.Fault{NextLink: link})
		sv := w.solverOf(t)
		e := errorOf(t, sv.Present(ctx5(t), chal("example.test", "v")))
		assert.Equal(t, acme.ReasonDNSProviderError, e.Reason, link)
	}
	for _, r := range w.s.Requests() {
		assert.NotEqual(t, "evil.test", r.Host)
	}
	assert.Len(t, managementRequests(w.s), 7, "one listing each, no link followed")
	assert.Empty(t, w.s.DNSRecords())
}

func TestNextLinkOnTheSameListingIsFollowedInAnyCase(t *testing.T) {
	w := secretWorld(t, fakekv.Options{DNSZones: []string{"a.test", "example.test"}, DNSPageSize: 1})
	link := "https://Management.Azure.com" + strings.Replace(w.s.DNSZonesPath(), "dnsZones", "dnszones", 1) + "?api-version=2018-05-01&$skipToken=1"
	w.s.FailNext(w.s.DNSZonesPath(), fakekv.Fault{NextLink: link})
	require.NoError(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
}

func TestZoneNotFound(t *testing.T) {
	cases := map[string]func(*azuredns.Config){
		"no zone holds the name": nil,
		"resource group missing": func(c *azuredns.Config) { c.ResourceGroup = "missing-rg" },
		"subscription missing":   func(c *azuredns.Config) { c.SubscriptionID = fakekv.UniqueClientID() },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			var muts []func(*azuredns.Config)
			if mut != nil {
				muts = append(muts, mut)
			}
			w := secretWorld(t, fakekv.Options{DNSZones: []string{"other.test"}}, muts...)
			e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
			assert.Equal(t, acme.ReasonDNSZoneNotFound, e.Reason)
			assert.Equal(t, "example.test", e.Identifier)
		})
	}
}

func TestPrivateOnlyZoneIsNotFound(t *testing.T) {
	w := secretWorld(t, fakekv.Options{DNSPrivateZones: []string{"example.test"}})
	assert.Equal(t, acme.ReasonDNSZoneNotFound, acme.ReasonOf(w.solverOf(t).Present(ctx5(t), chal("example.test", "v"))))
}

func TestZoneGoneBetweenListingAndWrite(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	p := w.p
	z := dnsapi.Zone{Name: "gone.test", ID: "gone.test"}
	_, err := p.AddTXT(ctx5(t), z, "_acme-challenge.gone.test", "v", 60)
	assert.Equal(t, acme.ReasonDNSZoneNotFound, acme.ReasonOf(err))
	require.NoError(t, p.RemoveTXT(ctx5(t), z, "_acme-challenge.gone.test", "v"))
}

func TestPreconditionFailedIsRetried(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	path := w.s.DNSRecordPath("example.test", "_acme-challenge")
	w.s.FailNext(path, fakekv.Fault{})                                      // the GET passes
	w.s.FailNext(path, fakekv.Fault{Status: http.StatusPreconditionFailed}) // the PUT meets a concurrent change
	sv := w.solverOf(t)
	require.NoError(t, sv.Present(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, []string{"v"}, w.s.DNSRecords()["_acme-challenge.example.test"])

	w.s.SetDNSTXT("example.test", "_acme-challenge", 60, "v", "other")
	w.s.FailNext(path, fakekv.Fault{})
	w.s.FailNext(path, fakekv.Fault{Status: http.StatusPreconditionFailed}) // the PUT of the rest
	require.NoError(t, sv.CleanUp(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, []string{"other"}, w.s.DNSRecords()["_acme-challenge.example.test"])

	w.s.FailNext(path, fakekv.Fault{})
	w.s.FailNext(path, fakekv.Fault{Status: http.StatusPreconditionFailed}) // the DELETE of the last value
	require.NoError(t, sv.CleanUp(ctx5(t), chal("example.test", "other")))
	assert.Empty(t, w.s.DNSRecords())
}

func TestPreconditionFailedForeverGivesUp(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	path := w.s.DNSRecordPath("example.test", "_acme-challenge")
	queue := func() {
		for range azuredns.MaxPreconditionRetries + 1 {
			w.s.FailNext(path, fakekv.Fault{})
			w.s.FailNext(path, fakekv.Fault{Status: http.StatusPreconditionFailed})
		}
	}
	queue()
	e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, acme.ReasonDNSProviderError, e.Reason)
	assert.Equal(t, http.StatusPreconditionFailed, e.Status)
	assert.Equal(t, acme.ClassTransient, acme.FailureClass(e), "another writer is expected to finish")

	w.s.SetDNSTXT("example.test", "_acme-challenge", 60, "v")
	queue()
	e = errorOf(t, w.solverOf(t).CleanUp(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, http.StatusPreconditionFailed, e.Status)
}

func TestWritesDeniedAreAuthFailed(t *testing.T) {
	w := secretWorld(t, fakekv.Options{DNSReadOnly: true})
	e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, acme.ReasonDNSAuthFailed, e.Reason)
	assert.Equal(t, http.StatusForbidden, e.Status)

	w.s.SetDNSTXT("example.test", "_acme-challenge", 60, "v")
	e = errorOf(t, w.solverOf(t).CleanUp(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, acme.ReasonDNSAuthFailed, e.Reason)
	w.s.SetDNSTXT("example.test", "_acme-challenge", 60, "v", "x")
	e = errorOf(t, w.solverOf(t).CleanUp(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, acme.ReasonDNSAuthFailed, e.Reason)
	w.s.SetDNSReadOnly(false)
	require.NoError(t, w.solverOf(t).CleanUp(ctx5(t), chal("example.test", "v")))
}

// ---- failures of the Resource Manager ----

func TestFailuresAreClassified(t *testing.T) {
	big := `{"value":[],"pad":"` + strings.Repeat("x", dnsapi.MaxResponseBytes) + `"}`
	cases := []struct {
		name   string
		fault  fakekv.Fault
		reason string
		class  string
		status int
	}{
		{"throttled", fakekv.Fault{Status: http.StatusTooManyRequests, RetryAfter: "7"}, acme.ReasonDNSProviderError, acme.ClassTransient, 429},
		{"server error", fakekv.Fault{Status: http.StatusInternalServerError}, acme.ReasonDNSProviderError, acme.ClassTransient, 500},
		{"reset", fakekv.Fault{Reset: true}, acme.ReasonDNSProviderError, acme.ClassTransient, 0},
		{"dropped", fakekv.Fault{Drop: true}, acme.ReasonDNSProviderError, acme.ClassTransient, 200},
		{"bad request", fakekv.Fault{Status: http.StatusBadRequest}, acme.ReasonDNSProviderError, acme.ClassPermanent, 400},
		{"unauthorized", fakekv.Fault{Status: http.StatusUnauthorized}, acme.ReasonDNSAuthFailed, acme.ClassPermanent, 401},
		{"forbidden", fakekv.Fault{Status: http.StatusForbidden}, acme.ReasonDNSAuthFailed, acme.ClassPermanent, 403},
		{"redirect", fakekv.Fault{Status: http.StatusFound, Location: "https://evil.test/"}, acme.ReasonDNSProviderError, acme.ClassPermanent, 302},
		{"malformed", fakekv.Fault{Body: "{not json"}, acme.ReasonDNSProviderError, acme.ClassPermanent, 200},
		{"no value", fakekv.Fault{Body: `{"nextLink":""}`}, acme.ReasonDNSProviderError, acme.ClassPermanent, 200},
		{"oversized", fakekv.Fault{Body: big}, acme.ReasonDNSProviderError, acme.ClassPermanent, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := secretWorld(t, fakekv.Options{})
			w.s.FailNext(w.s.DNSZonesPath(), c.fault)
			e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
			assert.Equal(t, c.reason, e.Reason)
			assert.Equal(t, c.class, acme.FailureClass(e))
			assert.Equal(t, c.status, e.Status)
			assert.Equal(t, "example.test", e.Identifier)
		})
	}
}

func TestRecordSetFailures(t *testing.T) {
	cases := []struct {
		name   string
		faults []fakekv.Fault
		status int
		class  string
	}{
		{"read 500", []fakekv.Fault{{Status: 500}}, 500, acme.ClassTransient},
		{"read malformed", []fakekv.Fault{{Status: 200, Body: "{}"}}, 200, acme.ClassPermanent},
		{"read without etag", []fakekv.Fault{{Status: 200, Body: `{"properties":{"TXTRecords":[]}}`}}, 200, acme.ClassPermanent},
		{"write 400", []fakekv.Fault{{}, {Status: 400}}, 400, acme.ClassPermanent},
		{"write 503", []fakekv.Fault{{}, {Status: 503}}, 503, acme.ClassTransient},
		{"write answer malformed", []fakekv.Fault{{}, {Status: 201, Body: "[]"}}, 201, acme.ClassPermanent},
		{"write reset", []fakekv.Fault{{}, {Reset: true}}, 0, acme.ClassTransient},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := secretWorld(t, fakekv.Options{})
			for _, f := range c.faults {
				w.s.FailNext(w.s.DNSRecordPath("example.test", "_acme-challenge"), f)
			}
			e := errorOf(t, w.solverOf(t).Present(ctx5(t), chal("example.test", "v")))
			assert.Equal(t, c.status, e.Status)
			assert.Equal(t, c.class, acme.FailureClass(e))
		})
	}
}

func TestRemovalFailures(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	path := w.s.DNSRecordPath("example.test", "_acme-challenge")
	sv := w.solverOf(t)
	w.s.SetDNSTXT("example.test", "_acme-challenge", 60, "v")
	w.s.FailNext(path, fakekv.Fault{})
	w.s.FailNext(path, fakekv.Fault{Status: http.StatusBadRequest})
	assert.Equal(t, 400, errorOf(t, sv.CleanUp(ctx5(t), chal("example.test", "v"))).Status, "the delete")
	w.s.FailNext(path, fakekv.Fault{})
	w.s.FailNext(path, fakekv.Fault{Reset: true})
	assert.Equal(t, acme.ClassTransient, acme.FailureClass(sv.CleanUp(ctx5(t), chal("example.test", "v"))))
	w.s.FailNext(path, fakekv.Fault{Status: http.StatusBadGateway})
	assert.Equal(t, 502, errorOf(t, sv.CleanUp(ctx5(t), chal("example.test", "v"))).Status, "the read")
	w.s.FailNext(path, fakekv.Fault{})
	w.s.FailNext(path, fakekv.Fault{Status: http.StatusNotFound})
	require.NoError(t, sv.CleanUp(ctx5(t), chal("example.test", "v")), "a delete that finds nothing succeeded")

	w.s.SetDNSTXT("example.test", "_acme-challenge", 0, "v", "x")
	w.s.FailNext(path, fakekv.Fault{})
	w.s.FailNext(path, fakekv.Fault{Status: http.StatusNotFound})
	require.NoError(t, sv.CleanUp(ctx5(t), chal("example.test", "v")), "a zone that went away holds no value")
	w.s.FailNext(path, fakekv.Fault{})
	w.s.FailNext(path, fakekv.Fault{Status: http.StatusConflict})
	assert.Equal(t, 409, errorOf(t, sv.CleanUp(ctx5(t), chal("example.test", "v"))).Status)
	require.NoError(t, sv.CleanUp(ctx5(t), chal("example.test", "v")))
	assert.Equal(t, []string{"x"}, w.s.DNSRecords()["_acme-challenge.example.test"])
	assert.Equal(t, dnsapi.DefaultTTL, w.s.DNSRecordTTL("_acme-challenge.example.test"), "a set without a TTL gets the default")
}

func TestCancelledContextIsItself(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, w.solverOf(t).Present(ctx, chal("example.test", "v")), context.Canceled)
	_, err := w.p.FindZone(ctx, "_acme-challenge.example.test")
	assert.ErrorIs(t, err, context.Canceled)
}

func TestKindAndChangeDone(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	assert.Equal(t, dnsapi.KindAzureDNS, w.p.Kind())
	done, err := w.p.ChangeDone(context.Background(), "")
	require.NoError(t, err)
	assert.True(t, done)
	change, err := w.p.AddTXT(ctx5(t), dnsapi.Zone{Name: "example.test", ID: "example.test"}, "_acme-challenge.example.test", "v", 120)
	require.NoError(t, err)
	assert.Empty(t, change, "live at once")
	assert.Equal(t, 120, w.s.DNSRecordTTL("_acme-challenge.example.test"))
}
