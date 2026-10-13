//go:build integration

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakeacme"
)

// ACME over HTTP (plan 2026-10-13 Task 13): the real services, PostgreSQL, the acme.issue job, fakeacme as the
// certificate authority (with its DNS hook) and the emulated Nginx server of the Phase 4 harness.

// acmeWorld is an installed stack with an Administrator, an Operator, one Nginx server serving wwwName and a fake CA
// that requires an external account binding and publishes terms of service.
type acmeWorld struct {
	*nj
	fake *fakeacme.Server
	cred fakeacme.Credentials
}

func newACMEWorld(t *testing.T) *acmeWorld {
	t.Helper()
	n := newNJ(t, wwwSite())
	fake, err := fakeacme.New(fakeacme.Options{Now: n.clock.Now, RequireEAB: true})
	require.NoError(t, err)
	require.NoError(t, fake.Start())
	t.Cleanup(fake.Close)
	return &acmeWorld{nj: n, fake: fake, cred: fake.Credentials()}
}

// providerBody is the provider of the fake: its TLS CA (to reach it) and its issuing root (the chain is complete,
// A3) as the bundle, its EAB credentials and the stack's names as the allow-list.
func (w *acmeWorld) providerBody() map[string]any {
	return map[string]any{"name": "Fake CA", "directory_url": w.fake.DirectoryURL(), "preset": "custom",
		"ca_bundle_pem": string(w.fake.CAPEM()) + string(w.fake.IssuerRootPEM()), "eab_kid": w.cred.EABKID, "eab_hmac": w.cred.EABHMAC,
		"allowed_suffixes": []string{"example.test"}}
}

func (w *acmeWorld) hookBody() map[string]any {
	return map[string]any{"name": "Fake DNS", "url": w.cred.HookURL, "ca_bundle_pem": string(w.fake.CAPEM()), "secret": w.cred.HookSecret,
		"allowed_suffixes": []string{"example.test"}, "propagation_wait_seconds": 0, "poll_timeout_seconds": 5}
}

// setUp adds the provider, registers its account (terms accepted) and adds the hook as the stepped-up Administrator.
func (w *acmeWorld) setUp() (providerID, hookID string) {
	t := w.t
	t.Helper()
	w.stepUp(w.admin, w.adminAcct)
	rec := w.admin.do(http.MethodPost, "/api/v1/acme/providers", w.providerBody())
	requireStatus(t, rec, http.StatusCreated)
	providerID = decodeBody[map[string]any](t, rec)["id"].(string)
	requireStatus(t, w.admin.do(http.MethodPost, "/api/v1/acme/providers/"+providerID+"/account",
		map[string]any{"contact_email": "ops@example.test", "tos_accepted": true}), http.StatusCreated)
	rec = w.admin.do(http.MethodPost, "/api/v1/acme/hooks", w.hookBody())
	requireStatus(t, rec, http.StatusCreated)
	return providerID, decodeBody[map[string]any](t, rec)["id"].(string)
}

func (w *acmeWorld) defineCert(providerID, hookID string, names ...string) *httptest.ResponseRecorder {
	return w.admin.do(http.MethodPost, "/api/v1/acme/certificates", map[string]any{"provider_id": providerID, "names": names,
		"challenge": "dns01", "hook_id": hookID})
}

// waitIssued runs the due jobs until the certificate leaves the issuing state; it returns the certificate's view.
func (w *acmeWorld) waitIssued(c *client, id string) map[string]any {
	t := w.t
	t.Helper()
	for range 20 {
		w.runJobs()
		rec := c.do(http.MethodGet, "/api/v1/acme/certificates/"+id, nil)
		requireStatus(t, rec, http.StatusOK)
		v := decodeBody[map[string]any](t, rec)
		if v["state"] != "issuing" {
			return v
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the order did not end")
	return nil
}

// The whole journey over HTTP: a provider with a private CA bundle and EAB, the account (terms of service), a DNS
// hook, a DNS-01 certificate, an order polled until issued, a binding and Deploy now; the served leaf is the issued
// one. No response, log line, audit row or job payload holds the EAB key or the hook secret.
func TestACMEJourneyOverHTTP(t *testing.T) {
	w := newACMEWorld(t)
	w.stepUp(w.admin, w.adminAcct)
	rec := w.admin.do(http.MethodPost, "/api/v1/acme/providers", w.providerBody())
	requireStatus(t, rec, http.StatusCreated)
	prov := decodeBody[map[string]any](t, rec)
	providerID := prov["id"].(string)
	assert.Equal(t, true, prov["eab_configured"])
	assert.Nil(t, prov["active_account_id"])
	assert.Zero(t, w.fake.Counters()["requests"], "adding a provider contacts nobody")

	// Terms of service: refused until accepted, and nothing is registered.
	rec = w.admin.do(http.MethodPost, "/api/v1/acme/providers/"+providerID+"/account", map[string]any{"contact_email": "ops@example.test"})
	requireStatus(t, rec, http.StatusUnprocessableEntity)
	assert.Equal(t, "ALC-ACM-0003", errCode(rec))
	rec = w.admin.do(http.MethodPost, "/api/v1/acme/providers/"+providerID+"/account",
		map[string]any{"contact_email": "mailto:ops@example.test", "tos_accepted": true})
	requireStatus(t, rec, http.StatusCreated)
	acct := decodeBody[map[string]any](t, rec)
	assert.Equal(t, "active", acct["state"])
	assert.Equal(t, w.cred.TermsURL, acct["tos_url"])
	rec = w.admin.do(http.MethodGet, "/api/v1/acme/providers/"+providerID, nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, acct["id"], decodeBody[map[string]any](t, rec)["active_account_id"])

	rec = w.admin.do(http.MethodPost, "/api/v1/acme/hooks", w.hookBody())
	requireStatus(t, rec, http.StatusCreated)
	hook := decodeBody[map[string]any](t, rec)
	assert.Equal(t, true, hook["secret_configured"])

	// A name outside the allow-list is refused; the certificate inside it is defined.
	rec = w.defineCert(providerID, hook["id"].(string), "www.other.test")
	requireStatus(t, rec, http.StatusUnprocessableEntity)
	assert.Equal(t, "ALC-ACM-0015", errCode(rec))
	rec = w.defineCert(providerID, hook["id"].(string), wwwName)
	requireStatus(t, rec, http.StatusCreated)
	cert := decodeBody[map[string]any](t, rec)
	certID := cert["id"].(string)
	assert.Equal(t, "pending", cert["state"])
	assert.Nil(t, cert["current"])

	// The Operator orders; the job runs it against the fake CA through the DNS hook.
	rec = w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+"/order", nil)
	requireStatus(t, rec, http.StatusAccepted)
	order := decodeBody[map[string]any](t, rec)
	assert.Equal(t, "running", order["state"])
	assert.Equal(t, "issue", order["kind"])
	rec = w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+"/order", nil)
	requireStatus(t, rec, http.StatusConflict)
	assert.Equal(t, "ALC-ACM-0016", errCode(rec), "one order at a time")
	issued := w.waitIssued(w.op, certID)
	require.Equal(t, "active", issued["state"], "%v", issued)
	current := issued["current"].(map[string]any)
	fingerprint := current["fingerprint_sha256"].(string)
	assert.Regexp(t, `^[0-9a-f]{64}$`, fingerprint)
	assert.Equal(t, true, current["chain_complete"], "the provider's bundle completes the private chain (A3)")
	assert.Equal(t, 1, w.fake.Counters()["issued"])
	rec = w.op.do(http.MethodGet, "/api/v1/acme/certificates/"+certID+"/orders", nil)
	requireStatus(t, rec, http.StatusOK)
	orders := decodeBody[map[string][]map[string]any](t, rec)["items"]
	require.Len(t, orders, 1)
	assert.Equal(t, "succeeded", orders[0]["state"])
	assert.Equal(t, current["id"], orders[0]["certificate_id"])

	// The Operator binds the website (automatic deployment off) and deploys now; the issued leaf is served.
	loc := w.locs[wwwCert]
	rec = w.op.do(http.MethodPut, "/api/v1/acme/certificates/"+certID+"/bindings/"+loc, map[string]any{"auto_deploy": false})
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "pending", decodeBody[map[string]any](t, rec)["state"])
	rec = w.op.do(http.MethodPut, "/api/v1/acme/certificates/"+certID+"/bindings/"+loc, map[string]any{"auto_deploy": true})
	requireStatus(t, rec, http.StatusForbidden)
	assert.Equal(t, "ALC-AUTH-0002", errCode(rec), "an Operator never switches unattended deployment on")
	rec = w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+"/deploy", nil)
	requireStatus(t, rec, http.StatusAccepted)
	deps := decodeBody[struct {
		Deployments []deployRef `json:"deployments"`
	}](t, rec).Deployments
	require.Len(t, deps, 1)
	d := w.settle(w.op, deps[0].ID)
	require.Equal(t, "succeeded", d.Status, "%+v", d)
	assert.Equal(t, fingerprint, d.NewFingerprint)
	assert.Equal(t, fingerprint, w.f.served(wwwName), "the website serves the issued certificate")
	rec = w.op.do(http.MethodGet, "/api/v1/acme/certificates/"+certID, nil)
	requireStatus(t, rec, http.StatusOK)
	bindings := decodeBody[map[string]any](t, rec)["bindings"].([]any)
	require.Len(t, bindings, 1)
	assert.Equal(t, "current", bindings[0].(map[string]any)["state"])

	// The Administrator switches unattended deployment on, with a fresh step-up only.
	w.clock.Advance(6 * time.Minute) // the step-up window (5 minutes) has passed
	rec = w.admin.do(http.MethodPut, "/api/v1/acme/certificates/"+certID+"/bindings/"+loc, map[string]any{"auto_deploy": true})
	requireStatus(t, rec, http.StatusForbidden)
	assert.Equal(t, "ALC-AUTH-0003", errCode(rec))
	rec = w.admin.do(http.MethodPost, "/api/v1/acme/hooks", w.hookBody())
	requireStatus(t, rec, http.StatusForbidden)
	assert.Equal(t, "ALC-AUTH-0003", errCode(rec), "every acme.manage route needs the fresh step-up")
	w.stepUp(w.admin, w.adminAcct)
	rec = w.admin.do(http.MethodPut, "/api/v1/acme/certificates/"+certID+"/bindings/"+loc, map[string]any{"auto_deploy": true})
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, true, decodeBody[map[string]any](t, rec)["auto_deploy"])

	// Secrets never leave: not in a response, a log line, an audit row or a job payload.
	secrets := []string{w.cred.EABHMAC, w.cred.HookSecret}
	for _, e := range w.recorded() {
		for _, sec := range secrets {
			assert.NotContains(t, string(e.body), sec, "%s answered a secret", e.key())
			for k, v := range e.header {
				assert.NotContains(t, strings.Join(v, " "), sec, "%s header %s", e.key(), k)
			}
		}
		assert.NotContains(t, string(e.body), "PRIVATE KEY", e.key())
	}
	logs := w.logs.String()
	var audit, payloads string
	require.NoError(t, w.db.Owner.QueryRow(context.Background(), "SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log").Scan(&audit))
	require.NoError(t, w.db.Owner.QueryRow(context.Background(), "SELECT coalesce(string_agg(payload::text, ' '), '') FROM jobs").Scan(&payloads))
	for _, sec := range secrets {
		assert.NotContains(t, logs, sec)
		assert.NotContains(t, audit, sec)
		assert.NotContains(t, payloads, sec)
	}
	assert.Contains(t, audit, `"eab_used": "true"`, "the audit row says a binding was used, not which key")
}

// The refusals of the journey: roles, the licence lock (no CA contact), a busy provider, the CA's rate limit with its
// Retry-After, and Alice's own limit of 10 ACME actions a minute.
func TestACMERefusalsOverHTTP(t *testing.T) {
	w := newACMEWorld(t)
	providerID, hookID := w.setUp()
	rec := w.defineCert(providerID, hookID, wwwName)
	requireStatus(t, rec, http.StatusCreated)
	certID := decodeBody[map[string]any](t, rec)["id"].(string)

	// An Operator cannot define or change certificates, providers or hooks; an Auditor reads and operates nothing.
	for _, r := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/acme/certificates"}, {http.MethodPatch, "/api/v1/acme/certificates/" + certID},
		{http.MethodPost, "/api/v1/acme/providers"}, {http.MethodPost, "/api/v1/acme/hooks"},
		{http.MethodPost, "/api/v1/acme/certificates/" + certID + "/rearm"},
	} {
		rec := w.op.do(r.method, r.path, map[string]any{})
		requireStatus(t, rec, http.StatusForbidden)
		assert.Equal(t, "ALC-AUTH-0002", errCode(rec), r.path)
	}
	auditorAcct := w.createUser(w.admin, w.adminAcct, "aud", "auditor", "auditor-password-2026")
	ac := w.freshClient()
	w.firstSignIn(ac, auditorAcct)
	requireStatus(t, ac.do(http.MethodGet, "/api/v1/acme/certificates/"+certID, nil), http.StatusOK)
	requireStatus(t, ac.do(http.MethodGet, "/api/v1/acme/providers/"+providerID, nil), http.StatusOK)
	for _, p := range []string{"/order", "/test", "/deploy"} {
		requireStatus(t, ac.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+p, nil), http.StatusForbidden)
	}

	// Another account operation holds the provider: the answer is "try again" with a Retry-After.
	conn, err := w.db.Owner.Acquire(context.Background())
	require.NoError(t, err)
	var got bool
	require.NoError(t, conn.QueryRow(context.Background(), "SELECT pg_try_advisory_lock(hashtextextended($1, 0))", "acme.provider."+providerID).Scan(&got))
	require.True(t, got)
	w.stepUp(w.admin, w.adminAcct)
	rec = w.admin.do(http.MethodPost, "/api/v1/acme/providers/"+providerID+"/account", map[string]any{"tos_accepted": true})
	requireStatus(t, rec, http.StatusConflict)
	assert.Equal(t, "ALC-ACM-0024", errCode(rec))
	assert.Equal(t, "2", rec.Header().Get("Retry-After"))
	_, err = conn.Exec(context.Background(), "SELECT pg_advisory_unlock_all()")
	require.NoError(t, err)
	conn.Release()

	// The CA's rate limit reaches the caller with the CA's Retry-After (Task 9 M7): a second provider's registration.
	body := w.providerBody()
	body["name"] = "Fake CA 2"
	rec = w.admin.do(http.MethodPost, "/api/v1/acme/providers", body)
	requireStatus(t, rec, http.StatusCreated)
	second := decodeBody[map[string]any](t, rec)["id"].(string)
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "new-account", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: 2 * time.Minute}))
	rec = w.admin.do(http.MethodPost, "/api/v1/acme/providers/"+second+"/account", map[string]any{"tos_accepted": true})
	requireStatus(t, rec, http.StatusServiceUnavailable)
	assert.Equal(t, "ALC-ACM-0005", errCode(rec))
	assert.Equal(t, "120", rec.Header().Get("Retry-After"))

	// Alice's own limit: 10 ACME actions a minute per user, the 11th is 429 and reaches nothing.
	w.api.ResetLimits()
	for i := range 10 {
		rec := w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+"/test", nil)
		require.Contains(t, []int{http.StatusAccepted, http.StatusConflict}, rec.Code, "test run %d: %s", i+1, rec.Body.String())
	}
	before := w.count("acme_orders")
	rec = w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+certID+"/order", nil)
	requireStatus(t, rec, http.StatusTooManyRequests)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, before, w.count("acme_orders"))
	w.runJobs()

	// In lock: 403 license.locked and the CA is not contacted; removing a binding still works.
	loc := w.locs[wwwCert]
	w.lockNow()
	w.fake.Reset() // counters from zero
	w.stepUp(w.admin, w.adminAcct)
	for _, r := range []struct {
		c            *client
		method, path string
	}{
		{w.op, http.MethodPost, "/api/v1/acme/certificates/" + certID + "/order"},
		{w.op, http.MethodPost, "/api/v1/acme/certificates/" + certID + "/test"},
		{w.op, http.MethodPost, "/api/v1/acme/certificates/" + certID + "/deploy"},
		{w.op, http.MethodPut, "/api/v1/acme/certificates/" + certID + "/bindings/" + loc},
		{w.admin, http.MethodPost, "/api/v1/acme/providers/" + second + "/account"},
		{w.admin, http.MethodPost, "/api/v1/acme/certificates"},
	} {
		w.api.ResetLimits()
		rec := r.c.do(r.method, r.path, map[string]any{})
		requireStatus(t, rec, http.StatusForbidden)
		assert.Equal(t, "ALC-LIC-0001", errCode(rec), r.path)
	}
	assert.Zero(t, w.fake.Counters()["requests"], "no certificate authority is contacted in lock")
	// Removing a binding is not refused by the lock: it reaches the inventory (this location was never bound: 404).
	requireStatus(t, w.op.do(http.MethodDelete, "/api/v1/acme/certificates/"+certID+"/bindings/"+loc, nil), http.StatusNotFound)
	requireStatus(t, w.op.do(http.MethodGet, "/api/v1/acme/certificates/"+certID, nil), http.StatusOK)
	requireStatus(t, w.admin.do(http.MethodDelete, "/api/v1/acme/certificates/"+certID, nil), http.StatusNoContent)
}

// Without an account a certificate cannot be defined; a provider with an account cannot be deleted.
func TestACMEDefinitionsNeedAnAccount(t *testing.T) {
	w := newACMEWorld(t)
	w.stepUp(w.admin, w.adminAcct)
	rec := w.admin.do(http.MethodPost, "/api/v1/acme/providers", w.providerBody())
	requireStatus(t, rec, http.StatusCreated)
	providerID := decodeBody[map[string]any](t, rec)["id"].(string)
	rec = w.admin.do(http.MethodPost, "/api/v1/acme/hooks", w.hookBody())
	requireStatus(t, rec, http.StatusCreated)
	hookID := decodeBody[map[string]any](t, rec)["id"].(string)
	rec = w.defineCert(providerID, hookID, wwwName)
	requireStatus(t, rec, http.StatusConflict)
	assert.Equal(t, "ALC-ACM-0023", errCode(rec), "no account")
	requireStatus(t, w.admin.do(http.MethodPost, "/api/v1/acme/providers/"+providerID+"/account", map[string]any{"tos_accepted": true}),
		http.StatusCreated)
	rec = w.admin.do(http.MethodDelete, "/api/v1/acme/providers/"+providerID, nil)
	requireStatus(t, rec, http.StatusConflict)
	assert.Equal(t, "ALC-ACM-0012", errCode(rec))
}

// acmeRecords makes one ACME provider (with its account at a fake CA), hook and certificate over the API, so every
// ACME GET answers 200 with a real record (TestA06GETRoutesNeverChangeState). It returns them by path prefix.
func acmeRecords(t *testing.T, s *stack, c *client, admin *account) map[string]string {
	t.Helper()
	fake, err := fakeacme.New(fakeacme.Options{Now: s.clock.Now, NoTerms: true})
	require.NoError(t, err)
	require.NoError(t, fake.Start())
	t.Cleanup(fake.Close)
	cred := fake.Credentials()
	s.stepUp(c, admin)
	rec := c.do(http.MethodPost, "/api/v1/acme/providers", map[string]any{"name": "Fake CA", "directory_url": fake.DirectoryURL(),
		"ca_bundle_pem": string(fake.CAPEM()) + string(fake.IssuerRootPEM()), "allowed_suffixes": []string{"example.test"}})
	requireStatus(t, rec, http.StatusCreated)
	provider := decodeBody[map[string]any](t, rec)["id"].(string)
	requireStatus(t, c.do(http.MethodPost, "/api/v1/acme/providers/"+provider+"/account", nil), http.StatusCreated)
	rec = c.do(http.MethodPost, "/api/v1/acme/hooks", map[string]any{"name": "Fake DNS", "url": cred.HookURL, "secret": cred.HookSecret,
		"ca_bundle_pem": string(fake.CAPEM()), "allowed_suffixes": []string{"example.test"}})
	requireStatus(t, rec, http.StatusCreated)
	hook := decodeBody[map[string]any](t, rec)["id"].(string)
	rec = c.do(http.MethodPost, "/api/v1/acme/certificates", map[string]any{"provider_id": provider, "names": []string{"www.example.test"},
		"challenge": "dns01", "hook_id": hook})
	requireStatus(t, rec, http.StatusCreated)
	return map[string]string{"/api/v1/acme/providers/": provider, "/api/v1/acme/hooks/": hook,
		"/api/v1/acme/certificates/": decodeBody[map[string]any](t, rec)["id"].(string)}
}
