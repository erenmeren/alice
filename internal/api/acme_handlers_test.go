package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/rbac"
)

var (
	acmeProvID = uuid.MustParse("0193a000-0000-7000-8000-000000000001")
	acmeAcctID = uuid.MustParse("0193a000-0000-7000-8000-000000000002")
	acmeHookID = uuid.MustParse("0193a000-0000-7000-8000-000000000003")
	acmeCertID = uuid.MustParse("0193a000-0000-7000-8000-000000000004")
	acmeLocID  = uuid.MustParse("0193a000-0000-7000-8000-000000000005")
	acmeLeafID = uuid.MustParse("0193a000-0000-7000-8000-000000000006")
	acmeOrdID  = uuid.MustParse("0193a000-0000-7000-8000-000000000007")
	acmeAt     = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
)

// acmeHMAC is a base64url EAB HMAC key (32 bytes); acmeHookSecret a hook secret. Neither may ever be answered.
const (
	acmeHMAC       = "c2VjcmV0LWhtYWMta2V5LW9mLXRoaXJ0eS10d28tYnl0ZXM"
	acmeHookSecret = "hook-secret-0123456789-abcdef"
)

// acmeDeps is the API with a fake ACME service. Its handler starts every request with fresh limiters and denial
// windows (each request is judged alone; TestACMEActionRoutesAreRateLimited tests the limits).
func acmeDeps(t *testing.T) (http.Handler, *fakeACME, Deps) {
	t.Helper()
	d := testDeps(t, nil)
	f := &fakeACME{}
	d.ACME = f
	srv := New(d)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.ResetLimits()
		srv.Handler().ServeHTTP(w, r)
	}), f, d
}

func sampleACMEProvider() inventory.ACMEProvider {
	acct := acmeAcctID
	return inventory.ACMEProvider{ID: acmeProvID, Name: "Internal CA", DirectoryURL: "https://ca.example.com/acme/directory", Preset: "custom",
		EABKID: "kid-1", EABConfigured: true, AllowedSuffixes: []string{"example.com"}, ActiveAccountID: &acct, CreatedAt: acmeAt, UpdatedAt: acmeAt}
}

func sampleACMEHook() inventory.ACMEHook {
	return inventory.ACMEHook{ID: acmeHookID, Name: "Internal DNS", URL: "https://dns.example.com/hook", SecretConfigured: true,
		AllowedSuffixes: []string{"example.com"}, PropagationWaitSeconds: 5, PollTimeoutSeconds: 60, CreatedAt: acmeAt, UpdatedAt: acmeAt}
}

func sampleACMECert() inventory.ACMECertificate {
	hook, leaf := acmeHookID, acmeLeafID
	start, end := acmeAt.Add(40*24*time.Hour), acmeAt.Add(42*24*time.Hour)
	return inventory.ACMECertificate{ID: acmeCertID, ProviderID: acmeProvID, AccountID: acmeAcctID, Names: []string{"www.example.com"},
		KeyType: "ecdsa_p256", Challenge: inventory.ACMEChallengeDNS01, HookID: &hook, RenewBeforeDays: 30, AutoRenew: true, AutoDeploy: true,
		State: inventory.ACMEStateActive, CurrentCertificateID: &leaf, LastErrorCode: "acme.ca_rate_limited", Bindings: 1,
		Current: &inventory.ACMECurrentCertificate{ID: leaf, Fingerprint: strings.Repeat("ab", 32), NotBefore: acmeAt, NotAfter: acmeAt.Add(90 * 24 * time.Hour),
			ChainComplete: true},
		ARIWindowStart: &start, ARIWindowEnd: &end, DeployHeldReason: inventory.ACMEHoldLicense, CreatedAt: acmeAt, UpdatedAt: acmeAt}
}

func sampleACMEBinding(auto bool) inventory.ACMEBinding {
	at := acmeAt
	return inventory.ACMEBinding{ACMECertificateID: acmeCertID, LocationID: acmeLocID, TargetID: targetID, TargetName: "web-01",
		CertPath: "/etc/ssl/www.pem", AutoDeploy: auto, State: inventory.ACMEBindingAttention, AttentionAt: &at, AttentionCode: "nginx.config_invalid",
		CreatedAt: acmeAt}
}

func sampleACMEOrder(kind string) inventory.ACMEOrder {
	return inventory.ACMEOrder{ID: acmeOrdID, ACMECertificateID: acmeCertID, Kind: kind, State: inventory.ACMEOrderRunning, StartedAt: acmeAt,
		Trigger: "manual"}
}

func errorField(t *testing.T, rec *httptest.ResponseRecorder) (code, reason string, details []any) {
	t.Helper()
	e := jsonObj(t, rec)["error"].(map[string]any)
	details, _ = e["details"].([]any)
	return e["code"].(string), e["reason"].(string), details
}

func detailFields(details []any) []string {
	var out []string
	for _, d := range details {
		out = append(out, d.(map[string]any)["field"].(string))
	}
	return out
}

func TestACMEProviderHandlers(t *testing.T) {
	h, f, _ := acmeDeps(t)
	var got inventory.ACMEProviderInput
	var hmacSeen string
	f.CreateACMEProviderFn = func(_ context.Context, a inventory.Actor, in inventory.ACMEProviderInput) (inventory.ACMEProvider, error) {
		got = in
		if in.EAB != nil {
			hmacSeen = string(in.EAB.HMAC.Bytes())
			in.EAB.HMAC.Zero()
		}
		assert.Equal(t, rbac.Admin, a.Role)
		return sampleACMEProvider(), nil
	}
	body := `{"name":"Internal CA","directory_url":"https://ca.example.com/acme/directory","preset":"custom","ca_bundle_pem":"",` +
		`"eab_kid":"kid-1","eab_hmac":"` + acmeHMAC + `","allowed_suffixes":["example.com"]}`
	rec := call(h, http.MethodPost, "/api/v1/acme/providers", "admin-stepup", body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, "/api/v1/acme/providers/"+acmeProvID.String(), rec.Header().Get("Location"))
	assert.Equal(t, "Internal CA", got.Name)
	assert.Equal(t, []string{"example.com"}, got.AllowedSuffixes)
	require.NotNil(t, got.EAB)
	assert.Equal(t, "kid-1", got.EAB.KID)
	assert.Equal(t, acmeHMAC, hmacSeen)
	assert.NotContains(t, rec.Body.String(), acmeHMAC, "the HMAC key is write-only")
	p := jsonObj(t, rec)
	assert.Equal(t, true, p["eab_configured"])
	assert.NotContains(t, p, "eab_hmac")

	// Boundary validation: nothing reaches the inventory.
	f.CreateACMEProviderFn = func(context.Context, inventory.Actor, inventory.ACMEProviderInput) (inventory.ACMEProvider, error) {
		t.Fatal("an invalid request reached the inventory")
		return inventory.ACMEProvider{}, nil
	}
	for _, tc := range []struct{ name, body, field string }{
		{"http directory", `{"name":"x","directory_url":"http://ca.example.com/dir"}`, "directory_url"},
		{"userinfo", `{"name":"x","directory_url":"https://u:p@ca.example.com/dir"}`, "directory_url"},
		{"no directory", `{"name":"x"}`, "directory_url"},
		{"no name", `{"directory_url":"https://ca.example.com/dir"}`, "name"},
		{"long name", `{"name":"` + strings.Repeat("n", 101) + `","directory_url":"https://ca.example.com/dir"}`, "name"},
		{"long url", `{"name":"x","directory_url":"https://ca.example.com/` + strings.Repeat("d", 2048) + `"}`, "directory_url"},
		{"preset", `{"name":"x","directory_url":"https://ca.example.com/dir","preset":"acme-inc"}`, "preset"},
		{"kid alone", `{"name":"x","directory_url":"https://ca.example.com/dir","eab_kid":"k"}`, "eab_hmac"},
		{"hmac alone", `{"name":"x","directory_url":"https://ca.example.com/dir","eab_hmac":"` + acmeHMAC + `"}`, "eab_kid"},
		{"hmac not base64url", `{"name":"x","directory_url":"https://ca.example.com/dir","eab_kid":"k","eab_hmac":"***"}`, "eab_hmac"},
		{"bundle", `{"name":"x","directory_url":"https://ca.example.com/dir","ca_bundle_pem":"` + strings.Repeat("b", 65*1024) + `"}`, "ca_bundle_pem"},
		{"suffixes", `{"name":"x","directory_url":"https://ca.example.com/dir","allowed_suffixes":[` + strings.Repeat(`"a.example",`, 100) + `"b"]}`,
			"allowed_suffixes"},
	} {
		rec := call(h, http.MethodPost, "/api/v1/acme/providers", "admin-stepup", tc.body)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, tc.name)
		_, _, details := errorField(t, rec)
		assert.Contains(t, detailFields(details), tc.field, tc.name)
	}
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/acme/providers", "admin-stepup",
		`{"name":"x","directory_url":"https://ca.example.com/dir","extra":1}`).Code, "unknown fields are refused")
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/acme/providers", "admin-stepup",
		`{"name":"x","Name":"y","directory_url":"https://ca.example.com/dir"}`).Code, "a case variant of a key is refused")
	assert.Equal(t, http.StatusRequestEntityTooLarge, call(h, http.MethodPost, "/api/v1/acme/providers", "admin-stepup",
		`{"name":"`+strings.Repeat("x", 130<<10)+`"}`).Code)

	// One provider with its accounts.
	f.GetACMEProviderFn = func(context.Context, uuid.UUID) (inventory.ACMEProvider, error) { return sampleACMEProvider(), nil }
	f.ListACMEAccountsFn = func(_ context.Context, id uuid.UUID) ([]inventory.ACMEAccount, error) {
		assert.Equal(t, acmeProvID, id)
		return []inventory.ACMEAccount{{ID: acmeAcctID, ProviderID: acmeProvID, ContactEmail: "ops@example.com", State: "active",
			TermsURL: "https://ca.example.com/tos", CreatedAt: acmeAt, UpdatedAt: acmeAt}}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/acme/providers/"+acmeProvID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	accounts := jsonObj(t, rec)["accounts"].([]any)
	require.Len(t, accounts, 1)
	assert.Equal(t, "https://ca.example.com/tos", accounts[0].(map[string]any)["tos_url"])
	f.ListACMEProvidersFn = func(context.Context) ([]inventory.ACMEProvider, error) {
		return []inventory.ACMEProvider{sampleACMEProvider()}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/acme/providers", "alice_read_auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Len(t, jsonObj(t, rec)["items"], 1)
	assert.NotContains(t, jsonObj(t, rec)["items"].([]any)[0], "accounts", "the list carries no accounts")

	// Patch: absent fields stay, flags reach the inventory.
	var patch inventory.ACMEProviderPatch
	f.UpdateACMEProviderFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, p inventory.ACMEProviderPatch) (inventory.ACMEProvider, error) {
		patch = p
		return sampleACMEProvider(), nil
	}
	rec = call(h, http.MethodPatch, "/api/v1/acme/providers/"+acmeProvID.String(), "admin-stepup",
		`{"directory_url":"https://ca2.example.com/dir","confirm_directory_change":true,"remove_eab":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, patch.DirectoryURL)
	assert.Equal(t, "https://ca2.example.com/dir", *patch.DirectoryURL)
	assert.Nil(t, patch.Name)
	assert.True(t, patch.ConfirmDirectoryChange)
	assert.True(t, patch.RemoveEAB)
	assert.Nil(t, patch.EAB)

	// Refusals map to their codes.
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{inventory.ErrACMEProviderInUse, 409, "ALC-ACM-0012"}, {inventory.ErrACMEDirectoryChange, 409, "ALC-ACM-0022"},
		{inventory.ErrACMENameTaken, 409, "ALC-ACM-0020"}, {inventory.ErrACMERolloverPending, 409, "ALC-ACM-0024"},
		{inventory.ErrNotFound, 404, "ALC-SYS-0001"},
	} {
		f.DeleteACMEProviderFn = func(context.Context, inventory.Actor, uuid.UUID) error { return tc.err }
		rec := call(h, http.MethodDelete, "/api/v1/acme/providers/"+acmeProvID.String(), "admin-stepup", "")
		assert.Equal(t, tc.status, rec.Code, tc.code)
		code, _, _ := errorField(t, rec)
		assert.Equal(t, tc.code, code)
	}
	f.DeleteACMEProviderFn = func(context.Context, inventory.Actor, uuid.UUID) error { return nil }
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, "/api/v1/acme/providers/"+acmeProvID.String(), "admin-stepup", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/acme/providers/not-a-uuid", "auditor", "").Code)
}

func TestACMEAccountHandlers(t *testing.T) {
	h, f, _ := acmeDeps(t)
	var contact string
	var tos bool
	var terms string
	f.RegisterACMEAccountFn = func(_ context.Context, _ inventory.Actor, id uuid.UUID, c string, accepted bool, shown string) (inventory.ACMEAccount, error) {
		terms = shown
		assert.Equal(t, acmeProvID, id)
		contact, tos = c, accepted
		return inventory.ACMEAccount{ID: acmeAcctID, ProviderID: acmeProvID, ContactEmail: c, State: "active", CreatedAt: acmeAt, UpdatedAt: acmeAt}, nil
	}
	path := "/api/v1/acme/providers/" + acmeProvID.String() + "/account"
	rec := call(h, http.MethodPost, path, "admin-stepup", `{"contact_email":"mailto:ops@example.com","tos_accepted":true}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, "mailto:ops@example.com", contact)
	assert.True(t, tos)
	assert.Empty(t, terms)
	rec = call(h, http.MethodPost, path, "admin-stepup", `{"tos_accepted":true,"accepted_terms_url":"https://ca.example.com/terms"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, "https://ca.example.com/terms", terms, "the terms shown reach the inventory, which binds the registration to them")
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPost, path, "admin-stepup",
		`{"accepted_terms_url":"https://ca.example.com/`+strings.Repeat("t", 2048)+`"}`).Code)
	require.Equal(t, http.StatusCreated, call(h, http.MethodPost, path, "admin-stepup", "").Code, "the body is optional")
	assert.False(t, tos)
	for _, bad := range []string{`{"contact_email":"tel:+90555"}`, `{"contact_email":"` + strings.Repeat("a", 250) + `@example.com"}`} {
		rec := call(h, http.MethodPost, path, "admin-stepup", bad)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, bad)
		_, _, details := errorField(t, rec)
		assert.Equal(t, []string{"contact_email"}, detailFields(details))
	}

	// CA failures: closed ALC-ACM codes, the CA's Retry-After, the lock answer.
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
		after  string
	}{
		{"terms", &inventory.ACMEError{Reason: "acme.terms_not_accepted"}, 422, "ALC-ACM-0003", ""},
		{"rate limited", &inventory.ACMEError{Reason: "acme.ca_rate_limited", RetryAfter: 90*time.Second + time.Millisecond}, 503, "ALC-ACM-0005", "91"},
		{"rate limited without a time", &inventory.ACMEError{Reason: "acme.ca_rate_limited"}, 503, "ALC-ACM-0005", "60"},
		{"unknown reason", &inventory.ACMEError{Reason: "ssh.auth_failed"}, 502, "ALC-ACM-0002", ""},
		{"busy", inventory.ErrACMEProviderBusy, 409, "ALC-ACM-0024", "2"},
		{"exists", inventory.ErrACMEAccountExists, 409, "ALC-ACM-0021", ""},
		{"locked", license.ErrLocked, 403, "ALC-LIC-0001", ""},
		{"rejected", &inventory.ACMEError{Reason: "acme.account_rejected"}, 422, "ALC-ACM-0004", ""},
	} {
		f.RegisterACMEAccountFn = func(context.Context, inventory.Actor, uuid.UUID, string, bool, string) (inventory.ACMEAccount, error) {
			return inventory.ACMEAccount{}, tc.err
		}
		rec := call(h, http.MethodPost, path, "admin-stepup", `{"tos_accepted":true}`)
		assert.Equal(t, tc.status, rec.Code, tc.name)
		code, _, _ := errorField(t, rec)
		assert.Equal(t, tc.code, code, tc.name)
		assert.Equal(t, tc.after, rec.Header().Get("Retry-After"), tc.name)
	}

	// Rollover, its check and deactivation call their own operation.
	called := map[string]uuid.UUID{}
	acct := func(name string) func(context.Context, inventory.Actor, uuid.UUID) (inventory.ACMEAccount, error) {
		return func(_ context.Context, _ inventory.Actor, id uuid.UUID) (inventory.ACMEAccount, error) {
			called[name] = id
			return inventory.ACMEAccount{ID: id, ProviderID: acmeProvID, State: "active", CreatedAt: acmeAt, UpdatedAt: acmeAt}, nil
		}
	}
	f.RolloverACMEAccountFn, f.RecoverACMERolloverFn, f.DeactivateACMEAccountFn = acct("rollover"), acct("recover"), acct("deactivate")
	for name, p := range map[string]string{"rollover": "/rollover", "recover": "/rollover/recover", "deactivate": "/deactivate"} {
		rec := call(h, http.MethodPost, "/api/v1/acme/accounts/"+acmeAcctID.String()+p, "admin-stepup", "")
		require.Equal(t, http.StatusOK, rec.Code, name)
		assert.Equal(t, acmeAcctID, called[name], name)
	}
	f.RolloverACMEAccountFn = func(context.Context, inventory.Actor, uuid.UUID) (inventory.ACMEAccount, error) {
		return inventory.ACMEAccount{}, &inventory.ACMEError{Reason: "acme.rollover_unsupported"}
	}
	code, _, _ := errorField(t, call(h, http.MethodPost, "/api/v1/acme/accounts/"+acmeAcctID.String()+"/rollover", "admin-stepup", ""))
	assert.Equal(t, "ALC-ACM-0014", code)
}

func TestACMEHookHandlers(t *testing.T) {
	h, f, _ := acmeDeps(t)
	var in inventory.ACMEHookInput
	var secret string
	f.CreateACMEHookFn = func(_ context.Context, _ inventory.Actor, i inventory.ACMEHookInput) (inventory.ACMEHook, error) {
		in, secret = i, string(i.Secret.Bytes())
		return sampleACMEHook(), nil
	}
	body := `{"name":"Internal DNS","url":"https://dns.example.com/hook","secret":"` + acmeHookSecret + `","allowed_suffixes":["example.com"],` +
		`"propagation_wait_seconds":0,"poll_timeout_seconds":30}`
	rec := call(h, http.MethodPost, "/api/v1/acme/hooks", "admin-stepup", body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, acmeHookSecret, secret)
	require.NotNil(t, in.PropagationWaitSeconds)
	assert.Equal(t, 0, *in.PropagationWaitSeconds)
	assert.Equal(t, 30, in.PollTimeoutSeconds)
	assert.NotContains(t, rec.Body.String(), acmeHookSecret)
	assert.Equal(t, true, jsonObj(t, rec)["secret_configured"])
	for _, tc := range []struct{ name, body, field string }{
		{"no secret", `{"name":"x","url":"https://dns.example.com/hook"}`, "secret"},
		{"http hook", `{"name":"x","url":"http://dns.example.com/hook","secret":"` + acmeHookSecret + `"}`, "url"},
		{"long secret", `{"name":"x","url":"https://dns.example.com/hook","secret":"` + strings.Repeat("s", 257) + `"}`, "secret"},
	} {
		rec := call(h, http.MethodPost, "/api/v1/acme/hooks", "admin-stepup", tc.body)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, tc.name)
		_, _, details := errorField(t, rec)
		assert.Contains(t, detailFields(details), tc.field, tc.name)
	}
	var patch inventory.ACMEHookPatch
	f.UpdateACMEHookFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, p inventory.ACMEHookPatch) (inventory.ACMEHook, error) {
		patch = p
		return sampleACMEHook(), nil
	}
	rec = call(h, http.MethodPatch, "/api/v1/acme/hooks/"+acmeHookID.String(), "admin-stepup", `{"name":"DNS 2"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, patch.Secret.Bytes(), "no secret: the stored one stays")
	f.DeleteACMEHookFn = func(context.Context, inventory.Actor, uuid.UUID) error { return inventory.ErrACMEHookInUse }
	code, _, _ := errorField(t, call(h, http.MethodDelete, "/api/v1/acme/hooks/"+acmeHookID.String(), "admin-stepup", ""))
	assert.Equal(t, "ALC-ACM-0019", code)
	f.GetACMEHookFn = func(context.Context, uuid.UUID) (inventory.ACMEHook, error) { return sampleACMEHook(), nil }
	f.ListACMEHooksFn = func(context.Context) ([]inventory.ACMEHook, error) {
		return []inventory.ACMEHook{sampleACMEHook()}, nil
	}
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/acme/hooks/"+acmeHookID.String(), "operator", "").Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/acme/hooks", "auditor", "").Code)
}

func TestACMECertificateHandlers(t *testing.T) {
	h, f, _ := acmeDeps(t)
	var in inventory.ACMECertificateInput
	f.CreateACMECertificateFn = func(_ context.Context, _ inventory.Actor, i inventory.ACMECertificateInput) (inventory.ACMECertificate, error) {
		in = i
		return sampleACMECert(), nil
	}
	body := `{"provider_id":"` + acmeProvID.String() + `","names":["www.example.com","*.example.com"],"challenge":"dns01","hook_id":"` +
		acmeHookID.String() + `","auto_deploy":false}`
	rec := call(h, http.MethodPost, "/api/v1/acme/certificates", "admin-stepup", body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, acmeProvID, in.ProviderID)
	assert.Equal(t, []string{"www.example.com", "*.example.com"}, in.Names)
	require.NotNil(t, in.HookID)
	assert.Nil(t, in.HTTPTargetID)
	assert.Nil(t, in.AutoRenew, "absent: the inventory's default (on)")
	// HTTP-01 is enabled (the helper suites ran, Task 7): the boundary accepts it.
	rec = call(h, http.MethodPost, "/api/v1/acme/certificates", "admin-stepup", `{"provider_id":"`+acmeProvID.String()+
		`","names":["www.example.com"],"challenge":"http01","http_target_id":"`+targetID.String()+`"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.ACMEChallengeHTTP01, in.Challenge)

	many := make([]string, 101)
	for i := range many {
		many[i] = `"n` + strconv.Itoa(i) + `.example.com"`
	}
	for _, tc := range []struct{ name, body, field string }{
		{"no names", `{"provider_id":"` + acmeProvID.String() + `","names":[],"challenge":"dns01"}`, "names"},
		{"101 names", `{"provider_id":"` + acmeProvID.String() + `","names":[` + strings.Join(many, ",") + `],"challenge":"dns01"}`, "names"},
		{"wildcard inside", `{"provider_id":"` + acmeProvID.String() + `","names":["www.*.example.com"],"challenge":"dns01"}`, "names"},
		{"an address", `{"provider_id":"` + acmeProvID.String() + `","names":["192.0.2.1"],"challenge":"dns01"}`, "names"},
		{"bad label", `{"provider_id":"` + acmeProvID.String() + `","names":["-bad.example.com"],"challenge":"dns01"}`, "names"},
		{"challenge", `{"provider_id":"` + acmeProvID.String() + `","names":["www.example.com"],"challenge":"tls-alpn-01"}`, "challenge"},
		{"no challenge", `{"provider_id":"` + acmeProvID.String() + `","names":["www.example.com"]}`, "challenge"},
		{"provider", `{"provider_id":"nope","names":["www.example.com"],"challenge":"dns01"}`, "provider_id"},
		{"no provider", `{"names":["www.example.com"],"challenge":"dns01"}`, "provider_id"},
		{"hook", `{"provider_id":"` + acmeProvID.String() + `","names":["www.example.com"],"challenge":"dns01","hook_id":"x"}`, "hook_id"},
	} {
		rec := call(h, http.MethodPost, "/api/v1/acme/certificates", "admin-stepup", tc.body)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, tc.name+": "+rec.Body.String())
		_, _, details := errorField(t, rec)
		assert.Contains(t, detailFields(details), tc.field, tc.name)
	}
	f.CreateACMECertificateFn = func(context.Context, inventory.Actor, inventory.ACMECertificateInput) (inventory.ACMECertificate, error) {
		return inventory.ACMECertificate{}, inventory.ErrACMENameNotAllowed
	}
	rec = call(h, http.MethodPost, "/api/v1/acme/certificates", "admin-stepup", body)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	code, _, _ := errorField(t, rec)
	assert.Equal(t, "ALC-ACM-0015", code, "a name outside the allow-list")
	f.CreateACMECertificateFn = func(context.Context, inventory.Actor, inventory.ACMECertificateInput) (inventory.ACMECertificate, error) {
		return inventory.ACMECertificate{}, inventory.ErrACMEAccountState
	}
	code, _, _ = errorField(t, call(h, http.MethodPost, "/api/v1/acme/certificates", "admin-stepup", body))
	assert.Equal(t, "ALC-ACM-0023", code, "a provider without an account")

	// The detail: state, marks, current certificate, ARI window, bindings with their attention mark.
	f.GetACMECertificateFn = func(context.Context, uuid.UUID) (inventory.ACMECertificate, error) { return sampleACMECert(), nil }
	f.ListACMEBindingsFn = func(context.Context, uuid.UUID) ([]inventory.ACMEBinding, error) {
		return []inventory.ACMEBinding{sampleACMEBinding(true)}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/acme/certificates/"+acmeCertID.String(), "alice_read_admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	c := jsonObj(t, rec)
	assert.Equal(t, "active", c["state"])
	assert.Equal(t, "license", c["deploy_held_reason"])
	assert.Equal(t, false, c["deploy_stopped"])
	assert.Equal(t, "", c["stopped_reason"])
	assert.Equal(t, "ALC-ACM-0005", c["last_error"].(map[string]any)["code"])
	assert.Equal(t, strings.Repeat("ab", 32), c["current"].(map[string]any)["fingerprint_sha256"])
	assert.Equal(t, "2026-11-22T09:00:00Z", c["ari_window"].(map[string]any)["start"])
	b := c["bindings"].([]any)[0].(map[string]any)
	assert.Equal(t, "attention", b["state"])
	assert.Equal(t, "ALC-NGX-0002", b["attention"].(map[string]any)["code"])

	stopped := sampleACMECert()
	stopped.State, stopped.Current, stopped.ARIWindowStart, stopped.ARIWindowEnd = inventory.ACMEStateStopped, nil, nil, nil
	d := acmeCertificateJSON(stopped, acmeAt)
	assert.Equal(t, acmeStoppedRenewalFailures, d.StoppedReason)
	assert.Nil(t, d.Current)
	assert.Nil(t, d.ARIWindow)
	assert.Nil(t, d.Bindings, "the list carries no bindings")
	assert.Nil(t, d.LastNotice, "the list carries no delivery")
	assert.Equal(t, "", c["last_failure_class"])
	assert.Equal(t, false, c["recovering"])
	assert.NotContains(t, c, "last_notice", "no renewal e-mail yet")

	// The failure class, the recovery after an outage and the delivery of the last renewal e-mail (owner decision
	// 2026-10-20).
	failing := sampleACMECert()
	failing.State, failing.Failures, failing.PermanentFailures, failing.LastFailureClass = inventory.ACMEStateStopped, 7, 1, "transient"
	f.GetACMECertificateFn = func(context.Context, uuid.UUID) (inventory.ACMECertificate, error) { return failing, nil }
	sent := acmeAt.Add(time.Minute)
	f.ACMENoticeDeliveryFn = func(context.Context, uuid.UUID) (*inventory.ACMENoticeDelivery, error) {
		return &inventory.ACMENoticeDelivery{Template: "acme.renewal_expiring_transient", QueuedAt: acmeAt, Recipients: 3, Sent: 1, Pending: 1,
			Failed: 1, SentAt: &sent, LastErrorCode: "smtp.auth"}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/acme/certificates/"+acmeCertID.String(), "alice_read_admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	c = jsonObj(t, rec)
	assert.Equal(t, "transient", c["last_failure_class"])
	assert.Equal(t, float64(1), c["permanent_failures"])
	assert.Equal(t, true, c["recovering"], "stopped after an outage, the certificate still valid")
	n := c["last_notice"].(map[string]any)
	assert.Equal(t, "acme.renewal_expiring_transient", n["template"])
	assert.Equal(t, float64(3), n["recipients"])
	assert.Equal(t, float64(1), n["failed"])
	assert.Equal(t, "smtp.auth", n["last_failure_code"])
	assert.Equal(t, sent.UTC().Format(time.RFC3339), n["sent_at"])
	expired := failing
	cur := *failing.Current
	cur.NotAfter = acmeAt.Add(-time.Hour)
	expired.Current = &cur
	assert.False(t, acmeCertificateJSON(expired, acmeAt).Recovering, "an expired certificate is not recovered by itself")
	odd := failing
	odd.LastFailureClass = "flaky"
	assert.Equal(t, "", acmeCertificateJSON(odd, acmeAt).LastFailureClass)
	f.ACMENoticeDeliveryFn = func(context.Context, uuid.UUID) (*inventory.ACMENoticeDelivery, error) {
		return nil, inventory.ErrNotFound
	}
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/acme/certificates/"+acmeCertID.String(), "alice_read_admin", "").Code)
	f.ACMENoticeDeliveryFn = nil

	// Patch and delete.
	var patch inventory.ACMECertificatePatch
	f.UpdateACMECertificateFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, p inventory.ACMECertificatePatch) (inventory.ACMECertificate, error) {
		patch = p
		return sampleACMECert(), nil
	}
	rec = call(h, http.MethodPatch, "/api/v1/acme/certificates/"+acmeCertID.String(), "admin-stepup", `{"auto_deploy":true,"renew_before_days":20}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, patch.AutoDeploy)
	assert.True(t, *patch.AutoDeploy)
	assert.Equal(t, 20, *patch.RenewBeforeDays)
	assert.Nil(t, patch.Names)
	f.UpdateACMECertificateFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.ACMECertificatePatch) (inventory.ACMECertificate, error) {
		return inventory.ACMECertificate{}, inventory.ErrACMEKeyTypeLocked
	}
	code, _, _ = errorField(t, call(h, http.MethodPatch, "/api/v1/acme/certificates/"+acmeCertID.String(), "admin-stepup", `{"key_type":"rsa_2048"}`))
	assert.Equal(t, "ALC-ACM-0018", code)
	f.DeleteACMECertificateFn = func(context.Context, inventory.Actor, uuid.UUID) error { return inventory.ErrACMEOrderRunning }
	code, _, _ = errorField(t, call(h, http.MethodDelete, "/api/v1/acme/certificates/"+acmeCertID.String(), "admin-stepup", ""))
	assert.Equal(t, "ALC-ACM-0016", code)
}

func TestACMECertificateListPagesAndFilters(t *testing.T) {
	h, f, _ := acmeDeps(t)
	other := uuid.MustParse("0193a000-0000-7000-8000-0000000000ff")
	var all []inventory.ACMECertificate
	for i := range 5 {
		c := sampleACMECert()
		c.ID = uuid.MustParse("0193a000-0000-7000-8000-00000000010" + strconv.Itoa(i))
		c.CreatedAt = acmeAt.Add(time.Duration(i/2) * time.Hour) // two pairs share a creation time: the id decides
		c.Names = []string{"n" + strconv.Itoa(i) + ".example.com"}
		if i == 3 {
			c.State, c.ProviderID = inventory.ACMEStateFailing, other
		}
		all = append(all, c)
	}
	f.ListACMECertificatesFn = func(context.Context) ([]inventory.ACMECertificate, error) { return all, nil }
	page := func(q string) (ids []string, next any) {
		rec := call(h, http.MethodGet, "/api/v1/acme/certificates"+q, "auditor", "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		m := jsonObj(t, rec)
		for _, it := range m["items"].([]any) {
			ids = append(ids, it.(map[string]any)["id"].(string))
		}
		return ids, m["next_cursor"]
	}
	var seen []string
	cursor := ""
	for range 5 {
		ids, next := page("?limit=2" + cursor)
		seen = append(seen, ids...)
		if next == nil {
			break
		}
		cursor = "&cursor=" + next.(string)
	}
	require.Len(t, seen, 5)
	for i, c := range all {
		assert.Equal(t, c.ID.String(), seen[i])
	}
	ids, next := page("?state=failing")
	assert.Equal(t, []string{all[3].ID.String()}, ids)
	assert.Nil(t, next)
	ids, _ = page("?provider_id=" + other.String())
	assert.Equal(t, []string{all[3].ID.String()}, ids)
	ids, _ = page("?q=N4.EXAMPLE")
	assert.Equal(t, []string{all[4].ID.String()}, ids)
	for _, bad := range []string{"?state=done", "?limit=0", "?limit=201", "?cursor=nope", "?cursor=1.x", "?provider_id=x",
		"?cursor=" + strings.Repeat("1", 600)} {
		assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/acme/certificates"+bad, "auditor", "").Code, bad)
	}
}

func TestACMEOrderTestRearmReleaseDeploy(t *testing.T) {
	h, f, _ := acmeDeps(t)
	var kinds []string
	f.RequestOrderFn = func(_ context.Context, a inventory.Actor, id uuid.UUID, kind string) (inventory.ACMEOrder, error) {
		assert.Equal(t, acmeCertID, id)
		kinds = append(kinds, kind)
		return sampleACMEOrder(kind), nil
	}
	rec := call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/order", "operator", "")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.Equal(t, "running", jsonObj(t, rec)["state"])
	rec = call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/test", "alice_operate_operator", "")
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.Equal(t, []string{inventory.ACMEOrderIssue, inventory.ACMEOrderTest}, kinds)
	for _, tc := range []struct {
		err  error
		code string
	}{{inventory.ErrACMEOrderRunning, "ALC-ACM-0016"}, {inventory.ErrACMERolloverPending, "ALC-ACM-0024"}, {inventory.ErrACMEAccountState, "ALC-ACM-0023"}} {
		f.RequestOrderFn = func(context.Context, inventory.Actor, uuid.UUID, string) (inventory.ACMEOrder, error) {
			return inventory.ACMEOrder{}, tc.err
		}
		code, _, _ := errorField(t, call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/order", "admin", ""))
		assert.Equal(t, tc.code, code)
	}

	var limit int
	f.ListACMEOrdersFn = func(_ context.Context, _ uuid.UUID, l int) ([]inventory.ACMEOrder, error) {
		limit = l
		o := sampleACMEOrder(inventory.ACMEOrderIssue)
		o.State, o.ErrorCode = inventory.ACMEOrderFailed, "acme.validation_failed_dns"
		return []inventory.ACMEOrder{o}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/acme/certificates/"+acmeCertID.String()+"/orders?limit=5", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 5, limit)
	assert.Equal(t, "ALC-ACM-0006", jsonObj(t, rec)["items"].([]any)[0].(map[string]any)["error"].(map[string]any)["code"])
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodGet, "/api/v1/acme/certificates/"+acmeCertID.String()+"/orders?limit=101",
		"auditor", "").Code)

	f.ReArmACMEAutoRenewFn = func(context.Context, inventory.Actor, uuid.UUID) (inventory.ACMECertificate, error) {
		return sampleACMECert(), nil
	}
	assert.Equal(t, http.StatusOK, call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/rearm", "admin-stepup", "").Code)
	released := false
	f.ReleaseACMEDeployHoldFn = func(context.Context, inventory.Actor, uuid.UUID) error { released = true; return nil }
	f.GetACMECertificateFn = func(context.Context, uuid.UUID) (inventory.ACMECertificate, error) { return sampleACMECert(), nil }
	assert.Equal(t, http.StatusOK, call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/release-hold", "admin-stepup", "").Code)
	assert.True(t, released)
	f.ReleaseACMEDeployHoldFn = func(context.Context, inventory.Actor, uuid.UUID) error { return inventory.ErrChainUnconfirmed }
	code, _, _ := errorField(t, call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/release-hold", "admin-stepup", ""))
	assert.Equal(t, "ALC-CRT-0011", code)

	var dep inventory.ACMEDeployInput
	f.DeployACMENowFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, in inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, error) {
		dep = in
		return []inventory.RequestedDeployment{{ID: acmeOrdID, JobID: jobID, LocationID: acmeLocID}}, nil
	}
	rec = call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/deploy", "operator",
		`{"location_ids":["`+acmeLocID.String()+`"],"confirm_incomplete_chain":true}`)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.Equal(t, []uuid.UUID{acmeLocID}, dep.LocationIDs)
	assert.True(t, dep.ConfirmIncompleteChain, "passed on; the inventory counts it for an Administrator only")
	require.Equal(t, http.StatusAccepted, call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/deploy", "operator", "").Code)
	assert.Empty(t, dep.LocationIDs, "no body: every bound location")
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/deploy", "operator",
		`{"location_ids":["x"]}`).Code)
	f.DeployACMENowFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, error) {
		return nil, &inventory.LocationRefusalError{LocationID: acmeLocID, Err: inventory.ErrACMELocationNotBound}
	}
	rec = call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/deploy", "operator", "")
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	e := jsonObj(t, rec)["error"].(map[string]any)
	assert.Equal(t, "ALC-ACM-0029", e["code"])
	assert.Equal(t, acmeLocID.String(), e["params"].(map[string]any)["location_id"])
}

// Switching unattended deployment on through a binding is an Administrator's act with a fresh step-up and no token
// (Task 12 ruling I2); binding with it off, keeping it on, switching it off and removing a binding are acme.operate.
func TestACMEBindingAutoDeployNeedsAFreshStepUp(t *testing.T) {
	h, f, d := acmeDeps(t)
	fa := d.Audit.(*fakeAudit)
	existing := []inventory.ACMEBinding{}
	f.ListACMEBindingsFn = func(context.Context, uuid.UUID) ([]inventory.ACMEBinding, error) { return existing, nil }
	var added, stricts []bool
	f.AddACMEBindingFn = func(_ context.Context, _ inventory.Actor, id, loc uuid.UUID, auto, strict bool) (inventory.ACMEBinding, error) {
		assert.Equal(t, acmeCertID, id)
		assert.Equal(t, acmeLocID, loc)
		added, stricts = append(added, auto), append(stricts, strict)
		return sampleACMEBinding(auto), nil
	}
	path := "/api/v1/acme/certificates/" + acmeCertID.String() + "/bindings/" + acmeLocID.String()
	on := `{"auto_deploy":true}`
	for _, tc := range []struct {
		who    string
		status int
		reason string
	}{
		{"admin", http.StatusForbidden, "auth.stepup_required"},
		{"operator", http.StatusForbidden, "auth.forbidden"},
		{"operator-stepup", http.StatusForbidden, "auth.forbidden"},
		{"alice_operate_admin", http.StatusForbidden, "auth.forbidden"},
		{"alice_operate_operator", http.StatusForbidden, "auth.forbidden"},
	} {
		before := fa.Count("authz.denied")
		rec := call(h, http.MethodPut, path, tc.who, on)
		require.Equal(t, tc.status, rec.Code, tc.who)
		_, reason, _ := errorField(t, rec)
		assert.Equal(t, tc.reason, reason, tc.who)
		assert.Equal(t, before+1, fa.Count("authz.denied"), "the refusal is audited: %s", tc.who)
	}
	assert.Empty(t, added, "nothing reached the inventory")
	require.Equal(t, http.StatusOK, call(h, http.MethodPut, path, "admin-stepup", on).Code)
	assert.Equal(t, []bool{true}, added)
	assert.Equal(t, []bool{true}, stricts, "the session's strength reaches the inventory, which decides inside its transaction")

	// An existing binding whose automatic deployment is off is switched on: the same rule.
	existing = []inventory.ACMEBinding{sampleACMEBinding(false)}
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPut, path, "operator", on).Code)
	// Already on: keeping it on, or switching it off, is an Operator's.
	existing = []inventory.ACMEBinding{sampleACMEBinding(true)}
	added = nil
	require.Equal(t, http.StatusOK, call(h, http.MethodPut, path, "operator", on).Code)
	require.Equal(t, http.StatusOK, call(h, http.MethodPut, path, "alice_operate_operator", `{"auto_deploy":false}`).Code)
	require.Equal(t, http.StatusOK, call(h, http.MethodPut, path, "operator", "").Code)
	assert.Equal(t, []bool{true, false, false}, added)
	assert.Equal(t, []bool{true, false, false, false}, stricts, "an Operator's session and a token are never strict")
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPut, path, "operator", `{"auto_deploy":"yes"}`).Code)
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPut, path, "operator", `{"auto":true}`).Code)

	// The inventory's own refusals.
	for _, tc := range []struct {
		err  error
		code string
	}{
		{inventory.ErrACMENotIssued, "ALC-ACM-0027"}, {inventory.ErrACMELocationBound, "ALC-ACM-0028"},
		{inventory.ErrAdminRequired, "ALC-AUTH-0002"}, {license.ErrLocked, "ALC-LIC-0001"},
		{&inventory.KeyTypeMismatchError{Expected: "rsa", Actual: "ecdsa"}, "ALC-CRT-0010"},
	} {
		f.AddACMEBindingFn = func(context.Context, inventory.Actor, uuid.UUID, uuid.UUID, bool, bool) (inventory.ACMEBinding, error) {
			return inventory.ACMEBinding{}, tc.err
		}
		code, _, _ := errorField(t, call(h, http.MethodPut, path, "operator", ""))
		assert.Equal(t, tc.code, code)
	}
	// An unknown certificate is 404 before any step-up is asked.
	f.ListACMEBindingsFn = func(context.Context, uuid.UUID) ([]inventory.ACMEBinding, error) { return nil, inventory.ErrNotFound }
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodPut, path, "admin", on).Code)

	removed := false
	f.RemoveACMEBindingFn = func(context.Context, inventory.Actor, uuid.UUID, uuid.UUID) error { removed = true; return nil }
	require.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, path, "alice_operate_operator", "").Code)
	assert.True(t, removed)
}

// Every acme.manage route refuses an Administrator without a fresh step-up, an Operator and every API token, and the
// handler never runs (the matrix test covers the identities; this names the ACME routes).
func TestACMEManageRoutesNeedAFreshStepUp(t *testing.T) {
	h, f, _ := acmeDeps(t)
	called := false
	f.DeleteACMEProviderFn = func(context.Context, inventory.Actor, uuid.UUID) error { called = true; return nil }
	n := 0
	for _, rt := range newServer(Deps{}).acmeRoutes() {
		if rt.perm != rbac.AcmeManage {
			continue
		}
		n++
		target := pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString())
		for _, who := range []string{"admin", "operator-stepup", "alice_operate_admin", "auditor-stepup"} {
			rec := call(h, rt.method, target, who, "{}")
			require.Equal(t, http.StatusForbidden, rec.Code, "%s %s as %s", rt.method, rt.pattern, who)
			_, reason, _ := errorField(t, rec)
			if who == "admin" {
				assert.Equal(t, "auth.stepup_required", reason, rt.pattern)
			} else {
				assert.Equal(t, "auth.forbidden", reason, rt.pattern)
			}
		}
	}
	assert.Equal(t, 15, n, "providers 3 and the registration, accounts 3, hooks 3, certificates 3, re-arm, release")
	assert.False(t, called)
}

// Auditors and read tokens read every ACME page and change nothing; an Operator cannot define or change certificates.
func TestACMEReadOnlyCallers(t *testing.T) {
	h, f, _ := acmeDeps(t)
	f.ListACMECertificatesFn = func(context.Context) ([]inventory.ACMECertificate, error) { return nil, nil }
	f.RequestOrderFn = func(context.Context, inventory.Actor, uuid.UUID, string) (inventory.ACMEOrder, error) {
		t.Fatal("a read-only caller reached an order")
		return inventory.ACMEOrder{}, nil
	}
	for _, who := range []string{"auditor", "auditor-stepup", "alice_read_auditor", "alice_read_admin"} {
		assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/acme/certificates", who, "").Code, who)
		for _, p := range []string{"/order", "/test", "/deploy"} {
			assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+p, who, "").Code, who+p)
		}
		assert.Equal(t, http.StatusForbidden, call(h, http.MethodPut, "/api/v1/acme/certificates/"+acmeCertID.String()+"/bindings/"+acmeLocID.String(),
			who, "").Code, who)
	}
	for _, who := range []string{"operator", "operator-stepup", "alice_operate_operator"} {
		assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/acme/certificates", who, "{}").Code, who)
		assert.Equal(t, http.StatusForbidden, call(h, http.MethodPatch, "/api/v1/acme/certificates/"+acmeCertID.String(), who,
			`{"auto_deploy":true}`).Code, who)
	}
}

// A5: the routes that contact a CA or start work are limited to 10 a minute per user (session) or token, besides the
// general limit; the 11th answers 429 with Retry-After and reaches no service.
func TestACMEActionRoutesAreRateLimited(t *testing.T) {
	_, f, d := acmeDeps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	calls := 0
	f.RequestOrderFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, kind string) (inventory.ACMEOrder, error) {
		calls++
		return sampleACMEOrder(kind), nil
	}
	f.DeployACMENowFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, error) {
		calls++
		return nil, nil
	}
	f.ReArmACMEAutoRenewFn = func(context.Context, inventory.Actor, uuid.UUID) (inventory.ACMECertificate, error) {
		calls++
		return sampleACMECert(), nil
	}
	base := "/api/v1/acme/certificates/" + acmeCertID.String()
	for _, tc := range []struct{ path, who, other string }{
		{"/order", "operator", "admin"}, {"/order", "alice_operate_operator", "alice_operate_admin"},
		{"/test", "operator", "admin"}, {"/test", "alice_operate_operator", "alice_operate_admin"},
		{"/deploy", "operator", "admin"}, {"/deploy", "alice_operate_operator", "alice_operate_admin"},
		{"/rearm", "admin-stepup", "admin2-stepup"},
	} {
		(&Server{s: s}).ResetLimits()
		calls = 0
		for i := range 10 {
			require.Equal(t, http.StatusAccepted/100, call(h, http.MethodPost, base+tc.path, tc.who, "").Code/100, "%s %s #%d", tc.path, tc.who, i+1)
		}
		rec := call(h, http.MethodPost, base+tc.path, tc.who, "")
		assert.Equal(t, http.StatusTooManyRequests, rec.Code, "%s %s: the 11th", tc.path, tc.who)
		assert.NotEmpty(t, rec.Header().Get("Retry-After"))
		assert.Equal(t, 10, calls, "the refused request reached no service")
		assert.Equal(t, 2, call(h, http.MethodPost, base+tc.path, tc.other, "").Code/100, "%s: %s has its own budget", tc.path, tc.other)
	}
	// The budget is the identity's for every ACME action together: orders and test runs draw on the same ten.
	(&Server{s: s}).ResetLimits()
	for range 5 {
		require.Equal(t, http.StatusAccepted, call(h, http.MethodPost, base+"/order", "operator", "").Code)
		require.Equal(t, http.StatusAccepted, call(h, http.MethodPost, base+"/test", "operator", "").Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, call(h, http.MethodPost, base+"/deploy", "operator", "").Code)
	// Reads and definitions are not in the ACME bucket.
	f.ListACMECertificatesFn = func(context.Context) ([]inventory.ACMECertificate, error) { return nil, nil }
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/acme/certificates", "operator", "").Code)
}

// In lock every ACME change that could reach a CA or a server is refused before the handler (no service call, the
// refusal audited as request.denied_license); removing a binding and deleting a definition still work.
func TestACMEInLock(t *testing.T) {
	h, f, d := acmeDeps(t)
	d.License.(*fakeLicense).set(license.ErrLocked)
	f.RequestOrderFn = func(context.Context, inventory.Actor, uuid.UUID, string) (inventory.ACMEOrder, error) {
		t.Fatal("an order reached the inventory in lock")
		return inventory.ACMEOrder{}, nil
	}
	f.RegisterACMEAccountFn = func(context.Context, inventory.Actor, uuid.UUID, string, bool, string) (inventory.ACMEAccount, error) {
		t.Fatal("a registration reached the inventory in lock")
		return inventory.ACMEAccount{}, nil
	}
	fa := d.Audit.(*fakeAudit)
	for _, tc := range []struct{ method, path, who string }{
		{http.MethodPost, "/api/v1/acme/certificates/" + acmeCertID.String() + "/order", "operator"},
		{http.MethodPost, "/api/v1/acme/certificates/" + acmeCertID.String() + "/test", "alice_operate_operator"},
		{http.MethodPost, "/api/v1/acme/certificates/" + acmeCertID.String() + "/deploy", "operator"},
		{http.MethodPost, "/api/v1/acme/providers/" + acmeProvID.String() + "/account", "admin-stepup"},
		{http.MethodPost, "/api/v1/acme/accounts/" + acmeAcctID.String() + "/rollover", "admin-stepup"},
		{http.MethodPost, "/api/v1/acme/certificates", "admin-stepup"},
		{http.MethodPut, "/api/v1/acme/certificates/" + acmeCertID.String() + "/bindings/" + acmeLocID.String(), "operator"},
	} {
		before := fa.Count("request.denied_license")
		rec := call(h, tc.method, tc.path, tc.who, "")
		require.Equal(t, http.StatusForbidden, rec.Code, tc.path)
		_, reason, _ := errorField(t, rec)
		assert.Equal(t, "license.locked", reason, tc.path)
		assert.Equal(t, before+1, fa.Count("request.denied_license"), tc.path)
	}
	removed, deleted := false, false
	f.RemoveACMEBindingFn = func(context.Context, inventory.Actor, uuid.UUID, uuid.UUID) error { removed = true; return nil }
	f.DeleteACMECertificateFn = func(context.Context, inventory.Actor, uuid.UUID) error { deleted = true; return nil }
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, "/api/v1/acme/certificates/"+acmeCertID.String()+"/bindings/"+acmeLocID.String(),
		"operator", "").Code)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, "/api/v1/acme/certificates/"+acmeCertID.String(), "admin-stepup", "").Code)
	assert.True(t, removed)
	assert.True(t, deleted)
	f.ListACMECertificatesFn = func(context.Context) ([]inventory.ACMECertificate, error) { return nil, nil }
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/acme/certificates", "auditor", "").Code, "reads stay available")
}

// A state-changing ACME request of a browser session needs the CSRF token and the same origin, like every other route.
func TestACMECSRFAndOrigin(t *testing.T) {
	h, f, _ := acmeDeps(t)
	f.RequestOrderFn = func(context.Context, inventory.Actor, uuid.UUID, string) (inventory.ACMEOrder, error) {
		t.Fatal("reached the inventory")
		return inventory.ACMEOrder{}, nil
	}
	path := "/api/v1/acme/certificates/" + acmeCertID.String() + "/order"
	rec := callWith(h, http.MethodPost, path, "operator", "", map[string]string{"X-CSRF-Token": "wrong"})
	require.Equal(t, http.StatusForbidden, rec.Code)
	_, reason, _ := errorField(t, rec)
	assert.Equal(t, "auth.csrf_failed", reason)
	rec = callWith(h, http.MethodPost, path, "operator", "", map[string]string{"Sec-Fetch-Site": "cross-site"})
	require.Equal(t, http.StatusForbidden, rec.Code)
	_, reason, _ = errorField(t, rec)
	assert.Equal(t, "auth.csrf_failed", reason)
}

// The request secrets (EAB HMAC key, hook secret) are zeroed on every path: success, a refusal of the inventory, a
// validation error before the inventory, a body that does not decode.
func TestACMERequestSecretsAreZeroed(t *testing.T) {
	h, f, _ := acmeDeps(t)
	w := watchSecrets(t)
	okProvider := func(context.Context, inventory.Actor, inventory.ACMEProviderInput) (inventory.ACMEProvider, error) {
		return sampleACMEProvider(), nil
	}
	refuseProvider := func(context.Context, inventory.Actor, inventory.ACMEProviderInput) (inventory.ACMEProvider, error) {
		return inventory.ACMEProvider{}, inventory.ErrACMENameTaken
	}
	okHook := func(context.Context, inventory.Actor, inventory.ACMEHookInput) (inventory.ACMEHook, error) {
		return sampleACMEHook(), nil
	}
	f.UpdateACMEProviderFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.ACMEProviderPatch) (inventory.ACMEProvider, error) {
		return sampleACMEProvider(), nil
	}
	f.UpdateACMEHookFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.ACMEHookPatch) (inventory.ACMEHook, error) {
		return inventory.ACMEHook{}, inventory.ErrNotFound
	}
	eab := `"eab_kid":"kid-1","eab_hmac":"` + acmeHMAC + `"`
	prov := `"name":"x","directory_url":"https://ca.example.com/dir",`
	hook := `"name":"x","url":"https://dns.example.com/hook",`
	for _, c := range []struct {
		name, method, path, body string
		set                      func()
		slices                   int
	}{
		{"provider ok", http.MethodPost, "/api/v1/acme/providers", `{` + prov + eab + `}`, func() { f.CreateACMEProviderFn = okProvider }, 1},
		{"provider refused", http.MethodPost, "/api/v1/acme/providers", `{` + prov + eab + `}`, func() { f.CreateACMEProviderFn = refuseProvider }, 1},
		{"provider invalid", http.MethodPost, "/api/v1/acme/providers", `{"name":"x","directory_url":"http://x",` + eab + `}`, func() {}, 1},
		{"provider unknown key", http.MethodPost, "/api/v1/acme/providers", `{` + prov + eab + `,"extra":1}`, func() {}, 0},
		{"provider patch", http.MethodPatch, "/api/v1/acme/providers/" + acmeProvID.String(), `{` + eab + `}`, func() {}, 1},
		{"hook ok", http.MethodPost, "/api/v1/acme/hooks", `{` + hook + `"secret":"` + acmeHookSecret + `"}`, func() { f.CreateACMEHookFn = okHook }, 1},
		{"hook invalid", http.MethodPost, "/api/v1/acme/hooks", `{"name":"x","url":"http://x","secret":"` + acmeHookSecret + `"}`, func() {}, 1},
		{"hook patch refused", http.MethodPatch, "/api/v1/acme/hooks/" + acmeHookID.String(), `{"secret":"` + acmeHookSecret + `"}`, func() {}, 1},
	} {
		c.set()
		rec, body := callObserved(h, c.method, c.path, "admin-stepup", c.body, nil)
		assert.NotEqual(t, http.StatusInternalServerError, rec.Code, c.name)
		assert.NotContains(t, rec.Body.String(), acmeHMAC, c.name)
		assert.NotContains(t, rec.Body.String(), acmeHookSecret, c.name)
		w.requireZeroed(t, c.name, c.slices)
		body.requireZeroed(t, c.name)
	}
}

// No ACME view has a field that could carry a secret: the EAB HMAC key, the account key and the hook secret are
// write-only, the views say only whether one is configured.
func TestACMEViewsHaveNoSecretField(t *testing.T) {
	for _, v := range []any{acmeProviderDTO{}, acmeAccountDTO{}, acmeHookDTO{}, acmeCertificateDTO{}, acmeBindingDTO{}, acmeOrderDTO{},
		acmeCurrentDTO{}} {
		typ := reflect.TypeOf(v)
		for i := range typ.NumField() {
			tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			for _, bad := range []string{"hmac", "secret", "key", "private", "token", "password"} {
				if strings.Contains(tag, bad) && tag != "secret_configured" && tag != "key_type" {
					t.Errorf("%s.%s (%q) looks like a secret", typ.Name(), typ.Field(i).Name, tag)
				}
			}
		}
	}
	b, err := json.Marshal(acmeProviderJSON(sampleACMEProvider()))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"eab_configured":true`)
	b, err = json.Marshal(acmeHookJSON(sampleACMEHook()))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"secret_configured":true`)
}

// Values outside the documented enums are shown as their safe default.
func TestACMEDTOFallbacks(t *testing.T) {
	b := sampleACMEBinding(false)
	b.State = "bogus"
	assert.Equal(t, inventory.ACMEBindingPending, acmeBindingJSON(b).State)
	c := sampleACMECert()
	c.DeployHeldReason = "bogus"
	assert.Empty(t, acmeCertificateJSON(c, acmeAt).DeployHeldReason)
	assert.Nil(t, acmeCertificateJSON(inventory.ACMECertificate{}, acmeAt).LastError)
	assert.Equal(t, []string{}, acmeProviderJSON(inventory.ACMEProvider{}).AllowedSuffixes)
}

// notFoundACME is a fakeACME whose every operation answers inventory.ErrNotFound (an unknown or deleted record).
func notFoundACME() *fakeACME {
	f := &fakeACME{}
	v := reflect.ValueOf(f).Elem()
	errType := reflect.TypeOf((*error)(nil)).Elem()
	for i := range v.NumField() {
		fn := v.Field(i)
		ft := fn.Type()
		fn.Set(reflect.MakeFunc(ft, func([]reflect.Value) []reflect.Value {
			out := make([]reflect.Value, ft.NumOut())
			for j := range out {
				if ft.Out(j) == errType {
					out[j] = reflect.ValueOf(&inventory.ErrNotFound).Elem()
				} else {
					out[j] = reflect.Zero(ft.Out(j))
				}
			}
			return out
		}))
	}
	return f
}

// Every ACME route answers an unknown record with 404 (the service's ErrNotFound, never a 500), and a path id that is
// not a UUID with 404 before any service is asked.
func TestACMERoutesAnswerNotFound(t *testing.T) {
	d := testDeps(t, nil)
	d.ACME = notFoundACME()
	srv := New(d)
	bodies := map[string]string{
		"POST /api/v1/acme/providers":                               `{"name":"x","directory_url":"https://ca.example.com/dir"}`,
		"POST /api/v1/acme/hooks":                                   `{"name":"x","url":"https://dns.example.com/h","secret":"` + acmeHookSecret + `"}`,
		"POST /api/v1/acme/certificates":                            `{"provider_id":"` + acmeProvID.String() + `","names":["www.example.com"],"challenge":"dns01"}`,
		"PUT /api/v1/acme/certificates/{id}/bindings/{location_id}": `{"auto_deploy":true}`,
	}
	who := map[rbac.Permission]string{rbac.AcmeView: "auditor", rbac.AcmeOperate: "operator", rbac.AcmeManage: "admin-stepup",
		rbac.AcmePreview: "admin"}
	for _, rt := range srv.s.acmeRoutes() {
		key := rt.method + " " + rt.pattern
		body, ok := bodies[key]
		if !ok && !safeMethod(rt.method) {
			body = "{}"
		}
		if strings.Contains(rt.pattern, "/{id}/account") || strings.HasSuffix(rt.pattern, "/preview") || strings.HasSuffix(rt.pattern, "/order") || strings.HasSuffix(rt.pattern, "/test") ||
			strings.HasSuffix(rt.pattern, "/rearm") || strings.HasSuffix(rt.pattern, "/release-hold") || strings.Contains(rt.pattern, "/accounts/") {
			body = ""
		}
		srv.ResetLimits()
		rec := call(srv.Handler(), rt.method, pathParamRE.ReplaceAllString(rt.pattern, acmeCertID.String()), who[rt.perm], body)
		if rt.method == http.MethodPost && (rt.pattern == "/api/v1/acme/providers" || rt.pattern == "/api/v1/acme/hooks" ||
			rt.pattern == "/api/v1/acme/certificates") {
			assert.Equal(t, http.StatusNotFound, rec.Code, "%s: %s", key, rec.Body.String())
			continue
		}
		if rt.pattern == "/api/v1/acme/providers" || rt.pattern == "/api/v1/acme/hooks" || rt.pattern == "/api/v1/acme/certificates" {
			assert.Equal(t, http.StatusNotFound, rec.Code, key) // the lists' service failure is answered like any other
			continue
		}
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s: %s", key, rec.Body.String())
		if strings.Contains(rt.pattern, "{") {
			srv.ResetLimits()
			bad := strings.Replace(rt.pattern, "{id}", "not-a-uuid", 1)
			bad = pathParamRE.ReplaceAllString(bad, acmeLocID.String())
			assert.Equal(t, http.StatusNotFound, call(srv.Handler(), rt.method, bad, who[rt.perm], body).Code, key+" with a bad id")
			if strings.Contains(rt.pattern, "{location_id}") {
				bad = strings.Replace(rt.pattern, "{id}", acmeCertID.String(), 1)
				bad = strings.Replace(bad, "{location_id}", "nope", 1)
				assert.Equal(t, http.StatusNotFound, call(srv.Handler(), rt.method, bad, who[rt.perm], body).Code, key+" with a bad location")
			}
		}
	}
	// Boundary rules not met elsewhere: a long allow-list entry, a patch that empties the provider id, an unparsable PATCH.
	h := srv.Handler()
	srv.ResetLimits()
	rec := call(h, http.MethodPost, "/api/v1/acme/hooks", "admin-stepup", `{"name":"x","url":"https://d.example.com/h","secret":"`+acmeHookSecret+
		`","allowed_suffixes":["`+strings.Repeat("a", 254)+`"]}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	rec = call(h, http.MethodPatch, "/api/v1/acme/certificates/"+acmeCertID.String(), "admin-stepup", `{"provider_id":""}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	rec = call(h, http.MethodPost, "/api/v1/acme/certificates", "admin-stepup", `{"provider_id":"`+acmeProvID.String()+`","names":["`+
		strings.Repeat("a", 254)+`"],"challenge":"dns01"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	for _, p := range []string{"/api/v1/acme/providers/" + acmeProvID.String(), "/api/v1/acme/hooks/" + acmeHookID.String(),
		"/api/v1/acme/certificates/" + acmeCertID.String()} {
		assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPatch, p, "admin-stepup", `{"name":`).Code, p)
		field := "name"
		if strings.Contains(p, "/certificates/") {
			field = "key_type"
		}
		assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPatch, p, "admin-stepup", `{"`+field+`":"`+strings.Repeat("n", 101)+`"}`).Code,
			p)
	}
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/acme/providers/"+acmeProvID.String()+"/account", "admin-stepup",
		`{"tos":true}`).Code)
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/deploy", "operator",
		`[]`).Code)
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/acme/certificates", "admin-stepup", `{"names":1}`).Code)
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/acme/hooks", "admin-stepup", `{"secret":1}`).Code)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPatch, "/api/v1/acme/providers/"+acmeProvID.String(), "admin-stepup",
		`{"eab_kid":"`+strings.Repeat("k", 256)+`","eab_hmac":"`+acmeHMAC+`"}`).Code)
	assert.Equal(t, http.StatusUnprocessableEntity, call(h, http.MethodPatch, "/api/v1/acme/providers/"+acmeProvID.String(), "admin-stepup",
		`{"eab_kid":"k","eab_hmac":"`+strings.Repeat("A", 1025)+`"}`).Code)
}

func TestACMEBindingListAndFollowUpReads(t *testing.T) {
	h, f, _ := acmeDeps(t)
	f.ListACMEBindingsFn = func(context.Context, uuid.UUID) ([]inventory.ACMEBinding, error) {
		return []inventory.ACMEBinding{sampleACMEBinding(true)}, nil
	}
	rec := call(h, http.MethodGet, "/api/v1/acme/certificates/"+acmeCertID.String()+"/bindings", "alice_read_auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, true, jsonObj(t, rec)["items"].([]any)[0].(map[string]any)["auto_deploy"])
	// The detail and the release answer a failure of their second read like any other.
	f.GetACMECertificateFn = func(context.Context, uuid.UUID) (inventory.ACMECertificate, error) { return sampleACMECert(), nil }
	f.ListACMEBindingsFn = func(context.Context, uuid.UUID) ([]inventory.ACMEBinding, error) { return nil, inventory.ErrNotFound }
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/acme/certificates/"+acmeCertID.String(), "auditor", "").Code)
	f.ReleaseACMEDeployHoldFn = func(context.Context, inventory.Actor, uuid.UUID) error { return nil }
	f.GetACMECertificateFn = func(context.Context, uuid.UUID) (inventory.ACMECertificate, error) {
		return inventory.ACMECertificate{}, inventory.ErrNotFound
	}
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/release-hold", "admin-stepup", "").Code)
	f.GetACMEProviderFn = func(context.Context, uuid.UUID) (inventory.ACMEProvider, error) { return sampleACMEProvider(), nil }
	f.ListACMEAccountsFn = func(context.Context, uuid.UUID) ([]inventory.ACMEAccount, error) { return nil, inventory.ErrNotFound }
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/acme/providers/"+acmeProvID.String(), "auditor", "").Code)
	f.DeleteACMEHookFn = func(context.Context, inventory.Actor, uuid.UUID) error { return nil }
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodDelete, "/api/v1/acme/hooks/"+acmeHookID.String(), "admin-stepup", "").Code)
}

// Fix round 1 (I1): the handler saw "already on" and asked for no step-up, but the binding was switched off meanwhile;
// the inventory refuses the switch-on inside its transaction (ErrAutoDeployNeedsStepUp) and the caller gets the step-up
// answer (an Administrator) or 403 ALC-AUTH-0002 (a token, which can never step up).
func TestACMEBindingSwitchOnRaceIsAnsweredWithTheStepUp(t *testing.T) {
	h, f, _ := acmeDeps(t)
	f.ListACMEBindingsFn = func(context.Context, uuid.UUID) ([]inventory.ACMEBinding, error) {
		return []inventory.ACMEBinding{sampleACMEBinding(true)}, nil // the handler's read: on
	}
	var strict []bool
	f.AddACMEBindingFn = func(_ context.Context, _ inventory.Actor, _, _ uuid.UUID, _, s bool) (inventory.ACMEBinding, error) {
		strict = append(strict, s)
		if !s {
			return inventory.ACMEBinding{}, inventory.ErrAutoDeployNeedsStepUp // switched off in between
		}
		return sampleACMEBinding(true), nil
	}
	path := "/api/v1/acme/certificates/" + acmeCertID.String() + "/bindings/" + acmeLocID.String()
	rec := call(h, http.MethodPut, path, "admin", `{"auto_deploy":true}`)
	require.Equal(t, http.StatusForbidden, rec.Code)
	code, reason, _ := errorField(t, rec)
	assert.Equal(t, "auth.stepup_required", reason)
	assert.Equal(t, "ALC-AUTH-0003", code)
	rec = call(h, http.MethodPut, path, "alice_operate_admin", `{"auto_deploy":true}`)
	require.Equal(t, http.StatusForbidden, rec.Code)
	code, _, _ = errorField(t, rec)
	assert.Equal(t, "ALC-AUTH-0002", code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodPut, path, "admin-stepup", `{"auto_deploy":true}`).Code)
	assert.Equal(t, []bool{false, false, true}, strict)
}

// Fix round 1 (M1): switching auto_renew on through PATCH re-arms the renewal like /rearm, so the definition's PATCH is in
// the ACME bucket (10 a minute per user).
func TestACMECertificatePatchIsRateLimited(t *testing.T) {
	_, f, d := acmeDeps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	f.UpdateACMECertificateFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.ACMECertificatePatch) (inventory.ACMECertificate, error) {
		return sampleACMECert(), nil
	}
	path := "/api/v1/acme/certificates/" + acmeCertID.String()
	for i := range 10 {
		require.Equal(t, http.StatusOK, call(h, http.MethodPatch, path, "admin-stepup", `{"auto_renew":true}`).Code, "#%d", i+1)
	}
	rec := call(h, http.MethodPatch, path, "admin-stepup", `{"auto_renew":true}`)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
}

// Fix round 1 (M4): read tokens change nothing, whatever the method.
func TestACMEReadTokensChangeNothing(t *testing.T) {
	h, _, _ := acmeDeps(t)
	for _, tok := range []string{"alice_read_admin", "alice_read_auditor"} {
		for _, r := range []struct{ method, path string }{
			{http.MethodPatch, "/api/v1/acme/certificates/" + acmeCertID.String()},
			{http.MethodDelete, "/api/v1/acme/certificates/" + acmeCertID.String()},
			{http.MethodPatch, "/api/v1/acme/providers/" + acmeProvID.String()},
			{http.MethodDelete, "/api/v1/acme/providers/" + acmeProvID.String()},
			{http.MethodPatch, "/api/v1/acme/hooks/" + acmeHookID.String()},
			{http.MethodDelete, "/api/v1/acme/hooks/" + acmeHookID.String()},
			{http.MethodDelete, "/api/v1/acme/certificates/" + acmeCertID.String() + "/bindings/" + acmeLocID.String()},
		} {
			rec := call(h, r.method, r.path, tok, "{}")
			require.Equal(t, http.StatusForbidden, rec.Code, tok+" "+r.method+" "+r.path)
			code, _, _ := errorField(t, rec)
			assert.Equal(t, "ALC-AUTH-0002", code)
		}
	}
}

// Fix round 1 (M2): Deploy now without named websites answers its own codes; their texts name the limit, which must
// stay the inventory's.
func TestACMEDeployNowWithoutNamedWebsites(t *testing.T) {
	h, f, _ := acmeDeps(t)
	assert.Equal(t, 20, inventory.MaxDeployLocations, "locales/common and troubleshooting say 'at most 20'")
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{{inventory.ErrACMENoBindings, 409, "ALC-ACM-0035"}, {inventory.ErrACMETooManyBindings, 422, "ALC-ACM-0036"}} {
		f.DeployACMENowFn = func(context.Context, inventory.Actor, uuid.UUID, inventory.ACMEDeployInput) ([]inventory.RequestedDeployment, error) {
			return nil, tc.err
		}
		rec := call(h, http.MethodPost, "/api/v1/acme/certificates/"+acmeCertID.String()+"/deploy", "operator", "")
		require.Equal(t, tc.status, rec.Code)
		code, _, details := errorField(t, rec)
		assert.Equal(t, tc.code, code)
		assert.Empty(t, details, "no field error on a field the request did not send")
	}
}

// Task 13 fix round 2: the registration form's preview of the CA's directory. An Administrator's browser session
// without a step-up; never an Operator, an Auditor or a token; 10 a minute per user; refused in lock with no call.
func TestACMEProviderPreviewHandler(t *testing.T) {
	h, f, d := acmeDeps(t)
	calls := 0
	f.PreviewACMEProviderFn = func(_ context.Context, id uuid.UUID) (inventory.ACMEProviderPreview, error) {
		calls++
		assert.Equal(t, acmeProvID, id)
		return inventory.ACMEProviderPreview{TermsOfServiceURL: "https://ca.example.com/terms", ExternalAccountRequired: true, KeyChangeSupported: true,
			Website: "https://ca.example.com"}, nil
	}
	path := "/api/v1/acme/providers/" + acmeProvID.String() + "/preview"
	rec := call(h, http.MethodPost, path, "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"terms_of_service_url":"https://ca.example.com/terms","terms_url_unsafe":false,"external_account_required":true,
		"key_change_supported":true,"renewal_info_supported":false,"website":"https://ca.example.com"}`, rec.Body.String())
	for _, who := range []string{"operator", "operator-stepup", "auditor", "alice_operate_admin", "alice_read_admin", "alice_operate_operator"} {
		rec := call(h, http.MethodPost, path, who, "")
		require.Equal(t, http.StatusForbidden, rec.Code, who)
		code, _, _ := errorField(t, rec)
		assert.Equal(t, "ALC-AUTH-0002", code, who)
	}
	assert.Equal(t, 1, calls)
	for _, tc := range []struct {
		err    error
		status int
		code   string
		after  string
	}{
		{&inventory.ACMEError{Reason: "acme.provider_unreachable"}, 502, "ALC-ACM-0001", ""},
		{&inventory.ACMEError{Reason: "acme.directory_invalid"}, 502, "ALC-ACM-0002", ""},
		{&inventory.ACMEError{Reason: "acme.tls_trust_failed"}, 502, "ALC-ACM-0013", ""},
		{&inventory.ACMEError{Reason: "acme.ca_rate_limited", RetryAfter: 30 * time.Second}, 503, "ALC-ACM-0005", "30"},
		{inventory.ErrNotFound, 404, "ALC-SYS-0001", ""},
	} {
		f.PreviewACMEProviderFn = func(context.Context, uuid.UUID) (inventory.ACMEProviderPreview, error) {
			return inventory.ACMEProviderPreview{}, tc.err
		}
		rec := call(h, http.MethodPost, path, "admin", "")
		assert.Equal(t, tc.status, rec.Code, tc.code)
		code, _, _ := errorField(t, rec)
		assert.Equal(t, tc.code, code)
		assert.Equal(t, tc.after, rec.Header().Get("Retry-After"), tc.code)
	}
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodPost, "/api/v1/acme/providers/nope/preview", "admin", "").Code)

	// In lock: refused before the service, audited.
	d.License.(*fakeLicense).set(license.ErrLocked)
	calls = 0
	f.PreviewACMEProviderFn = func(context.Context, uuid.UUID) (inventory.ACMEProviderPreview, error) {
		calls++
		return inventory.ACMEProviderPreview{}, nil
	}
	rec = call(h, http.MethodPost, path, "admin", "")
	require.Equal(t, http.StatusForbidden, rec.Code)
	code, _, _ := errorField(t, rec)
	assert.Equal(t, "ALC-LIC-0001", code)
	assert.Zero(t, calls)
}

// The preview is an ACME action: 10 a minute per user (session); tokens never reach it (no token may preview).
func TestACMEProviderPreviewIsRateLimited(t *testing.T) {
	_, f, d := acmeDeps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	f.PreviewACMEProviderFn = func(context.Context, uuid.UUID) (inventory.ACMEProviderPreview, error) {
		return inventory.ACMEProviderPreview{}, nil
	}
	path := "/api/v1/acme/providers/" + acmeProvID.String() + "/preview"
	for i := range 10 {
		require.Equal(t, http.StatusOK, call(h, http.MethodPost, path, "admin", "").Code, "#%d", i+1)
	}
	rec := call(h, http.MethodPost, path, "admin", "")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusOK, call(h, http.MethodPost, path, "admin2-stepup", "").Code, "another Administrator has their own budget")
	rec = call(h, http.MethodPost, path, "alice_operate_admin", "")
	assert.Equal(t, http.StatusForbidden, rec.Code, "a token is refused by the permission, never by the limit")
}
