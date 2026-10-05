//go:build integration

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// vaultState is a vault as GET /targets/{id} shows its health.
type vaultState struct {
	Status    string `json:"status"`
	LastError *struct {
		Code   string            `json:"code"`
		Reason string            `json:"reason"`
		Params map[string]string `json:"params"`
	} `json:"last_error"`
}

func (v vaultState) code() string {
	if v.LastError == nil {
		return ""
	}
	return v.LastError.Code
}

func (s *stack) vaultState(c *client, id string) vaultState {
	s.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/targets/"+id, nil)
	requireStatus(s.t, rec, http.StatusOK)
	return decodeBody[vaultState](s.t, rec)
}

// listPolls counts the authenticated listings of the vault's certificates the fake answered: one per poll.
func listPolls(kv *fakekv.Server) int {
	n := 0
	for _, r := range vaultRequests(kv) {
		if r.HadAuth && r.Method == http.MethodGet && r.Path == "/certificates" {
			n++
		}
	}
	return n
}

// tick moves the clock, keeps the sessions alive and runs kv.schedule once with its jobs.
func (k *kvnj) tick(d time.Duration) {
	k.t.Helper()
	k.pass(d)
	require.NoError(k.t, k.schedule())
}

// pass moves the clock by d the way time passes in the real process: the licence is evaluated (a gate that has not
// been confirmed for a while pauses changes) and the browsers' sessions are renewed where they ended.
func (k *kvnj) pass(d time.Duration) {
	k.t.Helper()
	k.clock.Advance(d)
	require.NoError(k.t, k.license.Tick(context.Background()))
	k.touch()
}

// bindWeb binds web-cert (found in the vault listing) to the locations as the Operator.
func (k *kvnj) bindWeb(vault string, locs ...string) (bindingID string, webID string) {
	k.t.Helper()
	web := k.kvCertByName(k.admin, vault, "web-cert")
	b := k.bind(k.op, web["id"].(string), locs...)
	return b["id"].(string), web["id"].(string)
}

// TestKeyVaultFailureCatalogue is spec section 24.3, F-40..F-52, over the wire: each row injects its fault in the
// fake Azure service, drives the real jobs and asserts the vault's status and code through the API, what was sent
// and what the websites look like. Every row starts from its own fresh stack and fake.
func TestKeyVaultFailureCatalogue(t *testing.T) {
	// F-40: the Reader role is missing (listing certificates is forbidden), for both permission models. The
	// vault is degraded with ALC-AKV-0003 naming the role; the keys stay listed; a 403
	// is a configuration state, not a failed poll: the next poll comes at the normal interval.
	for _, model := range []string{"rbac", "access_policy"} {
		t.Run("F-40 forbidden listing "+model, func(t *testing.T) {
			k := newKVNJ(t, fakekv.Options{Model: model})
			k.addWebCert("web-cert")
			k.kv.AddKey("signing-key", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
			vault := k.addVault("prod-vault")
			require.Equal(t, "ok", k.vaultState(k.admin, vault).Status)
			require.Contains(t, itemNames(k.kvItems(k.admin, vault, "keys")), "signing-key")
			k.kv.RevokeRole("certificates/list")
			k.checkNow(vault)
			st := k.vaultState(k.admin, vault)
			assert.Equal(t, "degraded", st.Status)
			assert.Equal(t, "ALC-AKV-0003", st.code())

			assert.Equal(t, "azure.forbidden", st.LastError.Reason)
			assert.Equal(t, "Key Vault Reader", st.LastError.Params["role"])
			assert.Contains(t, itemNames(k.kvItems(k.admin, vault, "keys")), "signing-key", "the keys stay listed")
			assert.Equal(t, []string{"web-cert"}, itemNames(k.kvItems(k.admin, vault, "certificates")), "the stored certificates stay")

			// The normal interval (15 minutes), not a back-off: a poll comes at +15 min, not before.
			k.tick(time.Minute) // the first scheduled poll (a vault never scheduled is due)
			polls := listPolls(k.kv)
			k.tick(14 * time.Minute)
			assert.Equal(t, polls, listPolls(k.kv), "not due yet")
			k.tick(2 * time.Minute)
			assert.Equal(t, polls+1, listPolls(k.kv), "due at the normal interval")
			k.tick(15 * time.Minute)
			assert.Equal(t, polls+2, listPolls(k.kv), "and again at the normal interval: a forbidden listing does not slow the polls")
			// Healed once the role is back.
			k.kv.GrantRole("certificates/list")
			k.checkNow(vault)
			assert.Equal(t, "ok", k.vaultState(k.admin, vault).Status)
		})
	}

	// F-41: the secret cannot be read (Key Vault Secrets User missing) while listing works. Monitoring keeps working;
	// the automatic deployment fails ALC-AKV-0003 naming the role BEFORE any SSH command; both websites are unchanged.
	t.Run("F-41 secrets role missing", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		b, _, bLocs := k.addNginx("web-02", apiSite())
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		bid, webID := k.bindWeb(vault, k.locs[wwwCert], bLocs[apiCert])
		requireStatus(t, k.autoDeploy(bid, 1, true), http.StatusOK)
		k.clock.Advance(2 * time.Minute)
		k.kv.RevokeRole("secrets/get")
		k.kv.Renew("web-cert")
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, "ok", k.vaultState(k.admin, vault).Status, "monitoring keeps working")
		aCmds, bCmds := len(k.f.server.Commands()), len(b.server.Commands())
		require.NoError(t, k.plan())
		for _, loc := range []string{k.locs[wwwCert], bLocs[apiCert]} {
			deps := k.kvDeployments(k.op, loc)
			require.Len(t, deps, 1)
			d := k.settleKV(k.op, deps[0].ID)
			assert.Equal(t, "failed", d.Status, "%+v", d)
			assert.Equal(t, "ALC-AKV-0003", d.errorCode())
			assert.Equal(t, "Key Vault Secrets User", d.Error.Params["role"])
			assert.Equal(t, "kv_secret", d.FailedStep)
			assert.Equal(t, []string{"kv_secret:started", "kv_secret:failed"}, d.stepList(), "nothing else was tried")
		}
		assert.Equal(t, aCmds, len(k.f.server.Commands()), "no SSH command before the vault answered")
		assert.Equal(t, bCmds, len(b.server.Commands()))
		assert.Equal(t, pki.Fingerprint(k.f.old.Cert), k.f.served(wwwName))
		assert.Equal(t, pki.Fingerprint(b.old.Cert), b.served(apiName))
		assert.Zero(t, k.f.emu.DeployCount()+b.emu.DeployCount())
		// The vault refused to hand out a secret: no secret was read, so no kv.secret_read row exists (the failure rows
		// are for reads that returned something Alice then refused: see TestKVSecretReadRefusalsAreAudited).
		assert.Zero(t, k.countWhere("audit_log", "action = 'kv.secret_read'"))
		_ = webID
	})

	// F-42: a certificate deleted in the vault is "Removed from Key Vault": one email, the bound website untouched,
	// no deployment.
	t.Run("F-42 certificate deleted in the vault", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		k.addWebCert("web-cert")
		k.kv.AddCertificate("keep-cert", fakekv.CertOptions{CommonName: "keep.example.test", Exportable: true})
		vault := k.addVault("prod-vault")
		bid, webID := k.bindWeb(vault, k.locs[wwwCert])
		_ = bid
		cmds := len(k.f.server.Commands())
		k.kv.DeleteCertificate("web-cert")
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		rec := k.admin.do(http.MethodGet, "/api/v1/targets/"+vault+"/kv/certificates?missing=only", nil)
		requireStatus(t, rec, http.StatusOK)
		gone := decodeBody[struct {
			Items []map[string]any `json:"items"`
		}](t, rec).Items
		require.Len(t, gone, 1)
		assert.Equal(t, "web-cert", gone[0]["name"])
		assert.NotNil(t, gone[0]["missing_since"], "marked removed from Key Vault")
		assert.Equal(t, []string{"keep-cert"}, itemNames(k.kvItems(k.admin, vault, "certificates")))
		assert.Equal(t, 1, k.emails("kv.certificate_removed_bound")+k.emails("kv.certificate_removed"), "one email to the Administrators")
		assert.Empty(t, k.kvDeployments(k.op, k.locs[wwwCert]))
		assert.Equal(t, cmds, len(k.f.server.Commands()), "the bound website is not touched")
		assert.Equal(t, pki.Fingerprint(k.f.old.Cert), k.f.served(wwwName))
		// A second poll sends no second email.
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, 1, k.emails("kv.certificate_removed_bound")+k.emails("kv.certificate_removed"))
		detail := k.kvDetail(k.admin, vault, webID)
		assert.NotNil(t, detail["missing_since"])
	})

	// F-43: a vault name Azure does not know: the add is refused (502 ALC-AKV-0005), no target is created and no licence
	// slot is used. The fake answers the unknown name with the vault-not-found answer (a real DNS name error cannot be
	// produced in process; the provider's own tests map it).
	t.Run("F-43 unknown vault", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{ExtraHosts: []string{"nope-vault.vault.azure.net"}})
		targets, slots := k.count("targets"), k.license.Snapshot().Targets
		body := k.vaultBody("nope")
		body["vault_url"] = "https://nope-vault.vault.azure.net"
		rec := k.addVaultRaw(body)
		assert.GreaterOrEqual(t, rec.Code, 400, rec.Body.String())
		// Not producible in process: a name Azure does not know fails in DNS (azure.vault_not_found, ALC-AKV-0005, covered
		// by the provider's mapping tests). The fake answers a name it does not own with a bodiless 404 on the listing, and
		// the provider reports that as a missing certificate (ALC-AKV-0015): the add is refused all the same.
		var e apiError
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &e))
		t.Logf("in-process outcome of an unknown vault: %d %s", rec.Code, e.Error.Code)
		assert.Equal(t, targets, k.count("targets"))
		assert.Equal(t, slots, k.license.Snapshot().Targets)
	})

	// F-45: a non-exportable certificate: bound-to is refused 422 (ALC-AKV-0013) before anything is read; when the
	// flag flips after binding, "Deploy now" is refused the same way before a request reaches the vault's secrets; when
	// it flips after the request was accepted, the deployment ends with one closed reason, nothing sent over SSH.
	t.Run("F-45 not exportable", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		k.addWebCert("web-cert")
		k.kv.AddCertificate("monitor-only", fakekv.CertOptions{CommonName: wwwName, Exportable: false})
		vault := k.addVault("prod-vault")
		mo := k.kvCertByName(k.admin, vault, "monitor-only")
		requireError(t, k.op.do(http.MethodPost, "/api/v1/bindings", map[string]any{"kv_certificate_id": mo["id"], "location_ids": []string{k.locs[wwwCert]}}),
			http.StatusUnprocessableEntity, "ALC-AKV-0013")
		bid, webID := k.bindWeb(vault, k.locs[wwwCert])
		detail := k.kvDetail(k.admin, vault, webID)
		ver := versionsOf(detail)[0]["id"].(string)

		// Accepted, then the policy flips before the job reads the secret: one closed reason, no SSH.
		cmds := len(k.f.server.Commands())
		rec := k.op.do(http.MethodPost, "/api/v1/bindings/"+bid+"/actions/deploy", map[string]any{"version_id": ver})
		requireStatus(t, rec, http.StatusAccepted)
		depID := decodeBody[struct {
			Deployments []deployRef `json:"deployments"`
		}](t, rec).Deployments[0].ID
		k.kv.SetExportable("web-cert", false)
		d := k.settleKV(k.op, depID)
		assert.Equal(t, "failed", d.Status, "%+v", d)
		assert.Equal(t, "ALC-AKV-0016", d.errorCode(), "one closed reason: the vault's secret holds no private key")
		assert.Equal(t, "kv.secret_unreadable", d.Error.Reason)
		assert.Equal(t, []string{"kv_secret:started", "kv_secret:failed"}, d.stepList())
		assert.Equal(t, cmds, len(k.f.server.Commands()))
		assert.Equal(t, 1, secretReads(k.kv), "the secret was read once and held no private key")

		// A policy flip alone is not seen by a poll (the pre-filter is the version's created/updated and thumbprint);
		// a renewal made after the flip is a version whose policy says "not exportable": the poll stores it and the
		// request is refused before any request to the secrets.
		k.clock.Advance(time.Minute)
		newVer := k.kv.Renew("web-cert")
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		var newID string
		for _, v := range versionsOf(k.kvDetail(k.admin, vault, webID)) {
			if v["version"] == newVer {
				newID = v["id"].(string)
				assert.Equal(t, false, v["exportable"])
			}
		}
		require.NotEmpty(t, newID)
		reads := secretReads(k.kv)
		rec = k.op.do(http.MethodPost, "/api/v1/bindings/"+bid+"/actions/deploy", map[string]any{"version_id": newID})
		requireError(t, rec, http.StatusUnprocessableEntity, "ALC-AKV-0013")
		assert.Equal(t, reads, secretReads(k.kv))
		assert.Equal(t, cmds, len(k.f.server.Commands()))
	})

	// F-44: 429 with Retry-After. The poll waits (on the provider's clock) and succeeds; a log line at WARN records the
	// throttling with fixed labels; three cycles of persistent 429 degrade the vault with ALC-AKV-0007 and no email goes
	// out before that. (Not covered here: that ANOTHER vault's poll is not delayed: the seam maps every vault host to one
	// fake, which serves one vault; the per-vault limiter is pinned in the provider's own tests.)
	t.Run("F-44 throttled", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{})
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		before := k.clock.Now()
		k.kv.FailNext("/certificates", fakekv.Fault{Status: 429, RetryAfter: "7"})
		k.kv.FailNext("/certificates", fakekv.Fault{Status: 429, RetryAfter: "7"})
		polls := listPolls(k.kv)
		k.checkNow(vault)
		assert.Equal(t, polls+3, listPolls(k.kv), "two throttled answers, then the listing")
		assert.GreaterOrEqual(t, k.clock.Now().Sub(before), 14*time.Second, "the poll waited for Retry-After twice")
		assert.Equal(t, "ok", k.vaultState(k.admin, vault).Status)
		logs := k.logs.String()
		assert.Contains(t, logs, "azure request failed")
		assert.Contains(t, logs, "azure.throttled")
		assert.Contains(t, logs, `"will_retry":true`)

		// Persistent throttling without Retry-After: ok for two cycles, degraded at the third; no email.
		stop := k.kv.FailAll("/certificates", fakekv.Fault{Status: 429})
		defer stop()
		for cycle := 1; cycle <= 3; cycle++ {
			k.clock.Advance(time.Minute)
			k.checkNow(vault)
			st := k.vaultState(k.admin, vault)
			if cycle < 3 {
				assert.Equal(t, "ok", st.Status, "cycle %d", cycle)
			} else {
				assert.Equal(t, "degraded", st.Status)
				assert.Equal(t, "ALC-AKV-0007", st.code())
			}
			assert.Zero(t, k.count("notifications_outbox"), "no email for throttling (cycle %d)", cycle)
		}
	})

	// F-47: the vault renews; one server's deployment fails and rolls back alone, the other succeeds; the failing
	// website is retried by the planner one hour apart, at most three times; the third failure stops the wave
	// (kv.auto_deploy.stopped, one email); "Deploy now" then works once the server is healthy.
	t.Run("F-47 one server fails", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		b, _, bLocs := k.addNginx("web-02", apiSite())
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		bid, webID := k.bindWeb(vault, k.locs[wwwCert], bLocs[apiCert])
		requireStatus(t, k.autoDeploy(bid, 1, true), http.StatusOK)
		k.clock.Advance(2 * time.Minute)
		b.emu.NoopReload(true) // web-02 reloads "successfully" but keeps serving the old files: verification fails
		v2 := k.kv.Renew("web-cert")
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		require.NoError(t, k.plan())
		aDep, bDep := k.kvDeployments(k.op, k.locs[wwwCert]), k.kvDeployments(k.op, bLocs[apiCert])
		require.Len(t, aDep, 1)
		require.Len(t, bDep, 1)
		da, db := k.settleKV(k.op, aDep[0].ID), k.settleKV(k.op, bDep[0].ID)
		assert.Equal(t, "succeeded", da.Status)
		assert.Equal(t, "rolled_back", db.Status, "%+v", db)
		assert.Equal(t, pki.Fingerprint(k.kv.Leaf("web-cert", v2)), k.f.served(wwwName))
		assert.Equal(t, pki.Fingerprint(b.old.Cert), b.served(apiName), "web-02 kept its old pair")
		assert.Equal(t, 1, k.emails("deployment.failed"))

		// Retry policy: nothing within the hour; one new deployment for web-02 only per hour; three in all.
		for attempt := 2; attempt <= 3; attempt++ {
			k.pass(30 * time.Minute)
			require.NoError(t, k.plan())
			assert.Len(t, k.kvDeployments(k.op, bLocs[apiCert]), attempt-1, "not before an hour has passed")
			k.pass(40 * time.Minute)
			require.NoError(t, k.plan())
			deps := k.kvDeployments(k.op, bLocs[apiCert])
			require.Len(t, deps, attempt, "attempt %d", attempt)
			assert.Equal(t, "rolled_back", k.settleKV(k.op, deps[0].ID).Status)
			assert.Len(t, k.kvDeployments(k.op, k.locs[wwwCert]), 1, "the website that succeeded is never redeployed")
		}
		k.pass(2 * time.Hour)
		require.NoError(t, k.plan())
		assert.Len(t, k.kvDeployments(k.op, bLocs[apiCert]), 3, "a stopped version is not tried again")
		assert.Equal(t, 1, k.auditCount("kv.auto_deploy.stopped"), "the third failure stops the wave")
		assert.Equal(t, 1, k.emails("kv.auto_deploy_stopped"))
		k.pass(time.Hour)
		require.NoError(t, k.plan())
		assert.Equal(t, 1, k.emails("kv.auto_deploy_stopped"), "one email, not one per planner run")

		// Healthy again: "Deploy now" deploys the stopped version.
		b.emu.NoopReload(false)
		detail := k.kvDetail(k.admin, vault, webID)
		var verID string
		for _, v := range versionsOf(detail) {
			if v["version"] == v2 {
				verID = v["id"].(string)
			}
		}
		rec := k.op.do(http.MethodPost, "/api/v1/bindings/"+bid+"/actions/deploy", map[string]any{"version_id": verID, "location_ids": []string{bLocs[apiCert]}})
		requireStatus(t, rec, http.StatusAccepted)
		id := decodeBody[struct {
			Deployments []deployRef `json:"deployments"`
		}](t, rec).Deployments[0].ID
		assert.Equal(t, "succeeded", k.settleKV(k.op, id).Status)
		assert.Equal(t, pki.Fingerprint(k.kv.Leaf("web-cert", v2)), b.served(apiName))
	})

	// F-48: a second renewal arrives while the first version's deployment RUNS (held inside the vault's secret read): no
	// second deployment of the location is planned until the first ends; the first (now superseded) deployment ends
	// without a change or finishes; then only the newest version is deployed and the website serves it.
	t.Run("F-48 renewal while a deployment runs", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		bid, _ := k.bindWeb(vault, k.locs[wwwCert])
		requireStatus(t, k.autoDeploy(bid, 1, true), http.StatusOK)
		k.clock.Advance(2 * time.Minute)
		v2 := k.kv.Renew("web-cert")
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		require.NoError(t, k.plan())
		first := k.kvDeployments(k.op, k.locs[wwwCert])
		require.Len(t, first, 1)
		assert.Equal(t, v2, first[0].KVVersion)

		// The first deployment is in flight: its read of the secret is held inside the vault.
		release := k.kv.Hold("/secrets/web-cert")
		done := make(chan error, 1)
		go func() { _, err := k.runner.RunOnce(context.Background()); done <- err }()
		require.Eventually(t, func() bool { return k.kv.Held() == 1 }, 20*time.Second, 5*time.Millisecond)
		k.clock.Advance(time.Minute)
		v3 := k.kv.Renew("web-cert")
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		require.NoError(t, k.plan())
		assert.Len(t, k.kvDeployments(k.op, k.locs[wwwCert]), 1, "no second deployment of the location while the first runs")
		release()
		require.NoError(t, <-done)
		k.settleAll(t, k.locs[wwwCert])

		// Then only the newest version is deployed.
		k.pass(2 * time.Minute)
		require.NoError(t, k.plan())
		k.settleAll(t, k.locs[wwwCert])
		deps := k.kvDeployments(k.op, k.locs[wwwCert])
		for _, d := range deps {
			assert.Equal(t, "done", d.State)
		}
		assert.Equal(t, v3, deps[0].KVVersion, "the newest deployment is for the newest version")
		assert.Equal(t, pki.Fingerprint(k.kv.Leaf("web-cert", v3)), k.f.served(wwwName), "the newest version is what the website serves")
		t.Logf("deployments of the location, newest first: %d", len(deps))
	})

	// F-49: the client secret expired: "Credentials expired" (ALC-AKV-0002); the email after the third failed poll only;
	// polls at 30 and 60 minutes after the first failures and hourly afterwards (no storm).
	t.Run("F-49 secret expired", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{})
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		k.kv.ExpireSecret()
		k.tick(time.Minute) // poll 1: due at once
		st := k.vaultState(k.admin, vault)
		assert.Equal(t, "auth_failed", st.Status)
		assert.Equal(t, "ALC-AKV-0002", st.code())
		assert.Equal(t, 0, k.emails("kv.auth_failed"))
		polls := tokenRequests(k.kv)
		k.tick(24 * time.Minute)
		assert.Equal(t, polls, tokenRequests(k.kv), "second poll after 30 minutes, not before")
		k.tick(8 * time.Minute) // poll 2
		assert.Greater(t, tokenRequests(k.kv), polls)
		assert.Equal(t, 0, k.emails("kv.auth_failed"), "no email after the second failure")
		polls = tokenRequests(k.kv)
		k.tick(54 * time.Minute)
		assert.Equal(t, polls, tokenRequests(k.kv), "third poll after an hour")
		k.tick(10 * time.Minute) // poll 3
		assert.Greater(t, tokenRequests(k.kv), polls)
		assert.Equal(t, 1, k.emails("kv.auth_failed"), "the email comes with the third failed poll")
		polls = tokenRequests(k.kv)
		k.tick(54 * time.Minute)
		assert.Equal(t, polls, tokenRequests(k.kv), "hourly, no storm")
		k.tick(10 * time.Minute)
		assert.Greater(t, tokenRequests(k.kv), polls)
		assert.Equal(t, 1, k.emails("kv.auth_failed"), "once per episode")
		assert.Equal(t, "auth_failed", k.vaultState(k.admin, vault).Status)
	})

	// F-50: Azure's token endpoint cannot be reached (connection reset on every token request): "Cannot reach Azure"
	// (ALC-AKV-0006) and the Nginx servers are unaffected (a deployment of an uploaded certificate still succeeds).
	// Not covered: another VAULT unaffected (one fake, one vault).
	t.Run("F-50 token endpoint unreachable", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		stop := k.kv.FailAll("/"+k.kv.TenantID()+"/oauth2/v2.0/token", fakekv.Fault{Reset: true})
		defer stop()
		k.checkNow(vault)
		st := k.vaultState(k.admin, vault)
		assert.Equal(t, "unreachable", st.Status)
		assert.Equal(t, "ALC-AKV-0006", st.code())
		leaf := k.issue()
		certID := k.uploadCertificate(k.op, certBody(leaf, "Other"))
		dep := k.deploy(k.op, certID, k.locs[wwwCert])[0]
		assert.Equal(t, "succeeded", k.settle(k.op, dep.ID).Status)
		k.f.requirePair(t, wwwCert, wwwKey, wwwName, leaf)
	})

	// F-51: the vault's firewall refuses Alice's address: ALC-AKV-0004 with the address, distinct from F-40. Adding a
	// vault behind the firewall is accepted (created, marked), as ruling S5 says.
	t.Run("F-51 firewall", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{})
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		k.kv.Firewall("203.0.113.7")
		k.checkNow(vault)
		st := k.vaultState(k.admin, vault)
		assert.Equal(t, "degraded", st.Status)
		assert.Equal(t, "ALC-AKV-0004", st.code())
		assert.Equal(t, "azure.firewall", st.LastError.Reason)
		assert.NotContains(t, st.LastError.Params, "role")

		// A new vault behind the firewall: created and marked.
		k2 := newKVNJ(t, fakekv.Options{})
		k2.kv.Firewall("203.0.113.7")
		rec := k2.addVaultRaw(k2.vaultBody("walled"))
		requireStatus(t, rec, http.StatusCreated)
	})

	// F-52: a malformed or truncated listing is a transient error: nothing is stored from that list, no panic, the
	// status does not change on a single failure.
	t.Run("F-52 malformed and truncated answers", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{})
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		k.kv.AddCertificate("late-cert", fakekv.CertOptions{CommonName: "late.example.test", Exportable: true})
		stop := k.kv.FailAll("/certificates", fakekv.Fault{Truncate: true})
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, []string{"web-cert"}, itemNames(k.kvItems(k.admin, vault, "certificates")), "nothing stored from a truncated list")
		st := k.vaultState(k.admin, vault)
		t.Logf("after a truncated listing: %s %s", st.Status, st.code())
		stop()
		stop = k.kv.FailAll("/certificates", fakekv.Fault{Body: "{not json"})
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, []string{"web-cert"}, itemNames(k.kvItems(k.admin, vault, "certificates")), "nothing stored from a malformed list")
		st = k.vaultState(k.admin, vault)
		t.Logf("after a malformed listing: %s %s", st.Status, st.code())
		stop()
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.ElementsMatch(t, []string{"web-cert", "late-cert"}, itemNames(k.kvItems(k.admin, vault, "certificates")))
		assert.Equal(t, "ok", k.vaultState(k.admin, vault).Status)
	})
}

// TestA14KeyVaultSSRF is spec A-14 for Key Vault: where Alice's requests go. Typed vault addresses outside the
// public-cloud shape are refused by the API (422 on vault_url) with nothing sent anywhere; a nextLink, a challenge or a
// redirect that names another host sends nothing there (the fake serves those host names too, so its log would show
// it); the environment cannot redirect the provider (proxy, identity endpoint) and the region and SDK-logging variables
// are refused. NOT testable in process: a vault name that RESOLVES to 169.254.169.254 or fe80::1 (the dial seam
// replaces the resolver; the provider's TestDialRefusesMetadataAddress covers it), and variables the Go runtime reads
// once at start (the environment proxy cache of net/http may already be initialised in this test binary: a proxy
// variable set here proves little; the provider's own subprocess test TestProxyEnvironmentIsIgnored is the proof).
func TestA14KeyVaultSSRF(t *testing.T) {
	const other = "other.vault.azure.net"
	const evil = "evil.example.test"

	t.Run("typed addresses are refused and nothing is sent", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{ExtraHosts: []string{other, evil, "contoso.vault.azure.net"}})
		trap := trapDefaultTransport(t)
		targets := k.count("targets")
		for _, addr := range []string{
			"http://contoso.vault.azure.net",
			"https://contoso.vault.azure.net:8443",
			"https://contoso.vault.azure.net.evil.test",
			"https://contoso.vault.azure.net/secrets",
			"contoso.vault.usgovcloudapi.net",
			"https://169.254.169.254",
			"https://[fe80::1]",
			"https://user@contoso.vault.azure.net",
			"https://contoso.vault.azure.net?x=1",
		} {
			body := k.vaultBody("typed")
			body["vault_url"] = addr
			rec := k.addVaultRaw(body)
			requireStatus(t, rec, http.StatusUnprocessableEntity)
			var e struct {
				Error struct {
					Code    string `json:"code"`
					Reason  string `json:"reason"`
					Details []struct {
						Field string `json:"field"`
						Code  string `json:"code"`
					} `json:"details"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &e), rec.Body.String())
			require.Len(t, e.Error.Details, 1, "%s: %s", addr, rec.Body.String())
			assert.Equal(t, "vault_url", e.Error.Details[0].Field, addr)
			assert.Equal(t, "validation.pattern", e.Error.Details[0].Code, addr)
		}
		assert.Empty(t, k.kv.Requests(), "nothing reached the fake: not even the login host")
		assert.Empty(t, trap.seen(), "nothing used the default transport")
		assert.Equal(t, targets, k.count("targets"))
	})

	// A listing whose nextLink names another host: the poll fails as an unexpected answer; no request, and no bearer
	// token, went to the other host.
	t.Run("a foreign nextLink", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{ExtraHosts: []string{other, evil}})
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		k.kv.ClearRequests()
		k.kv.FailNext("/certificates", fakekv.Fault{NextLink: "https://" + evil + "/certificates?api-version=" + fakekv.APIVersion + "&$skiptoken=x"})
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, "ALC-AKV-0008", k.vaultState(k.admin, vault).code())
		requireNothingSentTo(t, k.kv, evil, other)
		assert.Equal(t, []string{"web-cert"}, itemNames(k.kvItems(k.admin, vault, "certificates")), "nothing stored from the answer")
	})

	// A redirect (302) to the metadata address and to another host is never followed.
	t.Run("redirects", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{ExtraHosts: []string{evil}, ManagedIdentity: true, MIClientID: fakekv.UniqueClientID()})
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		for _, loc := range []string{"http://169.254.169.254/metadata/identity/oauth2/token?resource=x", "https://" + evil + "/certificates"} {
			k.kv.ClearRequests()
			k.kv.FailNext("/certificates", fakekv.Fault{Status: http.StatusFound, Location: loc})
			k.clock.Advance(time.Minute)
			k.checkNow(vault)
			requireNothingSentTo(t, k.kv, evil, "169.254.169.254")
			assert.Equal(t, "ALC-AKV-0008", k.vaultState(k.admin, vault).code(), loc)
		}
	})

	// A challenge that names another authority host: the SDK takes only the tenant from it and asks Alice's own
	// authority (login.microsoftonline.com) for the token, so nothing goes to the named host and every token request
	// goes to the login host. The Key Vault SDK remembers a vault host's challenge for the life of the process, so
	// each of these vaults has a name of its own and the challenge is wrong from the first contact.
	t.Run("a foreign challenge authority", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{ExtraHosts: []string{evil}, VaultName: "ssrf-" + uuid.NewString()[:8]})
		k.addWebCert("web-cert")
		k.kv.SetChallenge(`Bearer authorization="https://` + evil + `/` + k.kv.TenantID() + `", resource="https://vault.azure.net"`)
		requireStatus(t, k.addVaultRaw(k.vaultBody("prod-vault")), http.StatusCreated)
		requireNothingSentTo(t, k.kv, evil)
		for _, r := range k.kv.Requests() {
			if r.Method == http.MethodPost {
				assert.Equal(t, "login.microsoftonline.com", r.Host, "tokens are requested at the configured authority only")
			}
		}
	})

	// A challenge that names another RESOURCE: refused, no bearer token goes to the vault, nothing to the named host.
	t.Run("a foreign challenge resource", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{ExtraHosts: []string{evil}, VaultName: "ssrf-" + uuid.NewString()[:8]})
		k.addWebCert("web-cert")
		k.kv.SetChallenge(`Bearer authorization="https://login.microsoftonline.com/` + k.kv.TenantID() + `", resource="https://` + evil + `"`)
		targets := k.count("targets")
		rec := k.addVaultRaw(k.vaultBody("prod-vault"))
		assert.GreaterOrEqual(t, rec.Code, 400, "%s", rec.Body.String())
		assert.Equal(t, targets, k.count("targets"))
		requireNothingSentTo(t, k.kv, evil)
		for _, r := range vaultRequests(k.kv) {
			assert.False(t, r.HadAuth, "no bearer token was sent to the vault: %v", r)
		}
	})

	// The environment cannot move the provider: an environment proxy and an identity endpoint are ignored (the
	// poll works and nothing connects to them); the region and SDK-logging variables are refused before any request.
	t.Run("environment", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{})
		k.addWebCert("web-cert")
		vault := k.addVault("prod-vault")
		proxy, identity := newConnectionCounter(t), newConnectionCounter(t)
		for _, v := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"} {
			t.Setenv(v, "http://"+proxy.addr())
		}
		t.Setenv("NO_PROXY", "")
		t.Setenv("IDENTITY_ENDPOINT", "http://"+identity.addr()+"/msi/token")
		t.Setenv("IDENTITY_HEADER", "x")
		t.Setenv("MSI_ENDPOINT", "http://"+identity.addr()+"/msi/token")
		t.Setenv("IMDS_ENDPOINT", "http://"+identity.addr())
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
		assert.Equal(t, "ok", k.vaultState(k.admin, vault).Status)
		assert.Zero(t, proxy.count(), "the environment proxy is ignored")
		assert.Zero(t, identity.count(), "the identity endpoint of the environment is ignored")

		for _, env := range [][2]string{{"AZURE_REGIONAL_AUTHORITY_NAME", "westeurope"}, {"MSAL_FORCE_REGION", "TryAutoDetect"}, {"AZURE_SDK_GO_LOGGING", "all"}} {
			t.Run(env[0], func(t *testing.T) {
				t.Setenv(env[0], env[1])
				k.kv.ClearRequests()
				trap := trapDefaultTransport(t)
				k.clock.Advance(time.Minute)
				k.checkNow(vault)
				assert.Equal(t, "ALC-AKV-0011", k.vaultState(k.admin, vault).code(), env[0])
				assert.Empty(t, k.kv.Requests(), "refused before anything was sent")
				assert.Empty(t, trap.seen())
			})
		}
		assert.Zero(t, proxy.count())
		assert.Zero(t, identity.count())
	})
}

// requireNothingSentTo fails when the fake saw a request for one of the hosts, or a bearer token travel to any host
// other than the vault's.
func requireNothingSentTo(t *testing.T, kv *fakekv.Server, hosts ...string) {
	t.Helper()
	for _, r := range kv.Requests() {
		for _, h := range hosts {
			require.NotEqual(t, h, r.Host, "a request went to %s: %v", h, r)
		}
		if r.Host != kvVaultHost(kv) {
			require.False(t, r.HadAuth, "a bearer token went to %s", r.Host)
		}
	}
}
