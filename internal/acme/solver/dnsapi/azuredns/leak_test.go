package azuredns_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver/dnsapi/azuredns"
	"alice/internal/testutil/fakekv"
)

const canary = "CANARY-azuredns-7f3a"

// printed is every print form of the values.
func printed(vs ...any) string {
	var out string
	for _, v := range vs {
		out += fmt.Sprintf("%v|%+v|%#v|%s|%q|%x\n", v, v, v, v, v, v)
	}
	return out
}

func armBody(code string) string {
	b, _ := json.Marshal(map[string]any{"error": map[string]any{"code": code, "message": canary + " https://management.azure.com/x Bearer abc"}})
	return string(b)
}

func TestNoSecretKeyTokenOrAnswerTextLeaks(t *testing.T) {
	w, keyDER := certWorld(t, fakekv.Options{})
	sw := secretWorld(t, fakekv.Options{})
	secret := sw.s.Secret()
	keyNeedles := []string{string(keyDER), hex.EncodeToString(keyDER), base64.StdEncoding.EncodeToString(keyDER)}

	var errs []error
	for _, x := range []*world{w, sw} {
		sv := x.solverOf(t)
		require.NoError(t, sv.Present(ctx5(t), chal("example.test", "v")))
		token := x.s.LastAccessToken()
		require.NotEmpty(t, token)

		// Every kind of failure, with the canary in Azure's answer.
		zones, rec := x.s.DNSZonesPath(), x.s.DNSRecordPath("example.test", "_acme-challenge")
		for _, f := range []fakekv.Fault{
			{Status: http.StatusForbidden, Body: armBody("AuthorizationFailed")},
			{Status: http.StatusBadRequest, Body: armBody("BadRequest")},
			{Status: http.StatusInternalServerError, Body: armBody("InternalServerError")},
			{Status: http.StatusTooManyRequests, Body: armBody("TooManyRequests")},
			{Body: `{"value":[{"name":"` + canary + `"}], "nextLink":"https://evil.test/` + canary + `"}`},
		} {
			x.s.FailNext(zones, f)
			errs = append(errs, x.solverOf(t).Present(ctx5(t), chal("x.example.test", "v")))
		}
		x.s.FailNext(rec, fakekv.Fault{})
		x.s.FailNext(rec, fakekv.Fault{Status: http.StatusConflict, Body: armBody("Conflict")})
		errs = append(errs, sv.Present(ctx5(t), chal("example.test", "v2")))

		out := printed(x.cfg, x.p, sv)
		for _, e := range errs {
			out += printed(e, e.Error())
		}
		out += printed(x.s.Requests())
		assert.NotContains(t, out, token, "the access token")
		assert.NotContains(t, out, secret, "the client secret")
		for _, k := range keyNeedles {
			assert.NotContains(t, out, k, "the private key")
		}
		assert.NotContains(t, out, canary, "Azure's answer text")
		assert.NotContains(t, out, "Bearer")
		assert.NotContains(t, out, "https://")
	}
	for _, e := range errs {
		var ae *acme.Error
		assert.ErrorAs(t, e, &ae)
	}
}

func TestEntraAnswerTextNeverReachesAnError(t *testing.T) {
	w := secretWorld(t, fakekv.Options{}, func(c *azuredns.Config) {})
	body, _ := json.Marshal(map[string]any{"error": "invalid_client", "error_description": "AADSTS7000215: " + canary,
		"error_codes": []int{7000215}, "error_uri": "https://login.microsoftonline.com/error?code=" + canary})
	tokenPath := "/" + w.s.TenantID() + "/oauth2/v2.0/token"
	for _, status := range []int{http.StatusUnauthorized, http.StatusBadRequest, http.StatusServiceUnavailable} {
		w.s.FailNext(tokenPath, fakekv.Fault{Status: status, Body: string(body)})
		err := w.solverOf(t).Present(ctx5(t), chal("example.test", "v"))
		e := errorOf(t, err)
		assert.Equal(t, status, e.Status)
		out := printed(err, err.Error())
		assert.NotContains(t, out, canary)
		assert.NotContains(t, out, "AADSTS")
		assert.NotContains(t, out, w.s.Secret())
		assert.NotContains(t, out, w.s.TenantID(), "not even the token endpoint's URL")
	}
}

func TestConfigAndProviderPrintIdentifiersOnly(t *testing.T) {
	w := secretWorld(t, fakekv.Options{})
	want := "{auth: client_secret, tenant: " + w.s.TenantID() + ", client: " + w.s.ClientID() + ", subscription: " +
		w.s.DNSSubscriptionID() + ", resource_group: " + w.s.DNSResourceGroup() + "}"
	assert.Equal(t, "azuredns.Config"+want, w.cfg.String())
	assert.Equal(t, "azuredns.Config"+want, fmt.Sprintf("%#v", w.cfg))
	assert.Equal(t, "azuredns.Provider"+want, w.p.String())
	assert.Equal(t, "azuredns.Provider"+want, w.p.GoString())
	assert.Equal(t, "azuredns.Provider"+want, fmt.Sprintf("%+v", w.p))
	assert.Equal(t, "dnsapi.Solver{kind: azure_dns}", fmt.Sprint(w.solverOf(t)))
	assert.NotContains(t, printed(w.cfg, &w.cfg, w.p), w.s.Secret())
}
