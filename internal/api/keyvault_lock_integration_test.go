//go:build integration

package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// unlock installs a licence as the stepped-up Administrator (the licence that ended the lock).
func (k *kvnj) unlock() {
	k.t.Helper()
	k.stepUp(k.admin, k.adminAcct)
	now := k.clock.Now()
	requireStatus(k.t, k.admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": k.signedLicense("LIC-KV", now, now.AddDate(1, 0, 0), 10)}), http.StatusOK)
}

// deniedRefusals counts the licence refusals the audit log accounts for: the rows of single refusals plus the refusals
// the summary rows of coalesced windows count.
func (s *stack) deniedRefusals() int {
	s.t.Helper()
	var n int
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE details->>'suppressed_count' IS NULL)
+ coalesce(sum((details->>'suppressed_count')::int), 0) FROM audit_log WHERE action = 'request.denied_license'`).Scan(&n))
	return n
}

// vaultRows counts the rows a lock must not change.
func (s *stack) vaultRows() map[string]int {
	out := map[string]int{}
	for _, t := range []string{"targets", "credentials", "kv_certificates", "kv_certificate_versions", "kv_keys", "kv_secrets", "kv_imports", "bindings", "deployments", "certificates"} {
		out[t] = s.count(t)
	}
	return out
}

// TestKeyVaultInLock is L-26 and L-29 for vaults: with the licence locked every operation that reaches Azure or changes
// what Alice manages is refused 403 license.locked and audited; reads work; the two safety actions (automatic
// deployment OFF, deleting a binding) stay allowed; the scheduled work is refused by the gate; nothing reached the fake
// Azure service, no server saw a command and no row was added or deleted.
func TestKeyVaultInLock(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{}, wwwSite())
	k.addWebCert("web-cert")
	vault := k.addVault("prod-vault")
	bid, webID := k.bindWeb(vault, k.locs[wwwCert])
	requireStatus(t, k.autoDeploy(bid, 1, true), http.StatusOK)
	certID := k.uploadCertificate(k.op, certBody(k.issue(), "To import"))
	verID := versionsOf(k.kvDetail(k.admin, vault, webID))[0]["id"].(string)

	k.lockNow()
	k.stepUp(k.admin, k.adminAcct)
	reqs, cmds, rows := len(k.kv.Requests()), len(k.f.server.Commands()), k.vaultRows()
	denied := k.deniedRefusals()

	refused := []struct {
		name, method, path string
		body               any
		opts               []reqOpt
	}{
		{"add vault", http.MethodPost, "/api/v1/key-vaults", k.vaultBody("second"), nil},
		{"replace credentials", http.MethodPut, "/api/v1/targets/" + vault + "/vault-credentials", map[string]any{"auth": "client_secret", "tenant_id": k.kv.TenantID(),
			"client_id": k.kv.ClientID(), "client_secret": k.kv.Secret()}, []reqOpt{ifMatchOf("1")}},
		{"test", http.MethodPost, "/api/v1/targets/" + vault + "/actions/test", nil, nil},
		{"check now", http.MethodPost, "/api/v1/targets/" + vault + "/actions/discover", nil, nil},
		{"change the vault", http.MethodPatch, "/api/v1/targets/" + vault, map[string]any{"poll_interval_minutes": 30}, []reqOpt{ifMatchOf("1")}},
		{"create binding", http.MethodPost, "/api/v1/bindings", map[string]any{"kv_certificate_id": webID, "location_ids": []string{k.locs[wwwCert]}}, nil},
		{"update binding", http.MethodPatch, "/api/v1/bindings/" + bid, map[string]any{"location_ids": []string{k.locs[wwwCert]}}, []reqOpt{ifMatchOf("2")}},
		{"automatic deployment ON", http.MethodPut, "/api/v1/bindings/" + bid + "/auto-deploy", map[string]any{"enabled": true}, []reqOpt{ifMatchOf("2")}},
		{"deploy now", http.MethodPost, "/api/v1/bindings/" + bid + "/actions/deploy", map[string]any{"version_id": verID}, nil},
		{"import", http.MethodPost, "/api/v1/certificates/" + certID + "/actions/import-to-key-vault", map[string]any{"target_id": vault, "name": "x"}, nil},
		{"release a version", http.MethodPost, "/api/v1/targets/" + vault + "/kv/certificates/" + webID + "/versions/" + verID + "/actions/release", nil, nil},
		{"delete the vault", http.MethodDelete, "/api/v1/targets/" + vault, nil, nil},
	}
	for _, r := range refused {
		requireError(t, k.admin.do(r.method, r.path, r.body, r.opts...), http.StatusForbidden, "ALC-LIC-0001")
	}
	k.api.FlushDenials(context.Background())
	// Every refusal is audited: its own row, or counted in the summary row of its window (AUD-06). Switching automatic
	// deployment ON passes the route's gate (OFF must not be blocked) and is refused by the inventory, audited as
	// binding.denied with reason locked.
	assert.Equal(t, denied+len(refused)-1, k.deniedRefusals())
	assert.Equal(t, 1, k.countWhere("audit_log", "action = 'binding.denied' AND details->>'reason' = 'locked'"))

	// The scheduled work is refused by the gate: nothing polls, nothing is planned.
	for _, task := range []string{"kv.schedule", "kv.auto_deploy"} {
		err := k.kvScheduler().RunNow(context.Background(), task)
		assert.True(t, errors.Is(err, license.ErrLocked), "%s: %v", task, err)
	}
	k.runKV()

	// Reads work.
	for _, p := range []string{"/api/v1/targets/" + vault, "/api/v1/targets/" + vault + "/kv/certificates", "/api/v1/targets/" + vault + "/kv/imports",
		"/api/v1/targets/" + vault + "/kv/keys", "/api/v1/bindings/" + bid, "/api/v1/deployments", "/api/v1/certificate-locations", "/api/v1/jobs"} {
		requireStatus(t, k.admin.do(http.MethodGet, p, nil), http.StatusOK)
	}
	assert.Equal(t, reqs, len(k.kv.Requests()), "no request reached Azure")
	assert.Equal(t, cmds, len(k.f.server.Commands()), "no SSH command")
	assert.Equal(t, rows, k.vaultRows(), "no row added or deleted")

	// The safety actions stay allowed: automatic deployment OFF and deleting the binding.
	requireStatus(t, k.admin.do(http.MethodPut, "/api/v1/bindings/"+bid+"/auto-deploy", map[string]any{"enabled": false}, ifMatchOf("2")), http.StatusOK)
	k.stepUp(k.admin, k.adminAcct)
	requireStatus(t, k.op.do(http.MethodDelete, "/api/v1/bindings/"+bid, nil), http.StatusNoContent)
	assert.Equal(t, reqs, len(k.kv.Requests()))
	assert.Equal(t, cmds, len(k.f.server.Commands()))
	assert.Equal(t, rows["bindings"], k.count("bindings"), "the binding row is soft-deleted, not removed")
}

// TestL81KeyVaultDeploymentHeld: an automatic deployment queued before the lock is held (blocked_license, listed among
// the blocked jobs); no SSH command and no vault read happen in lock; a renewed licence alone starts nothing; an
// Administrator's confirmation does, and the deployment then reads the vault and succeeds.
func TestL81KeyVaultDeploymentHeld(t *testing.T) {
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
	dep := k.kvDeployments(k.op, k.locs[wwwCert])
	require.Len(t, dep, 1)

	k.lockNow()
	reqs, cmds := len(k.kv.Requests()), len(k.f.server.Commands())
	k.clock.Advance(2 * time.Second)
	k.runKV()
	d := k.deployment(k.op, dep[0].ID)
	assert.Equal(t, "queued", d.State)
	assert.Equal(t, "blocked_license", d.JobStatus)
	rec := k.admin.do(http.MethodGet, "/api/v1/jobs?status=blocked_license", nil)
	requireStatus(t, rec, http.StatusOK)
	var listed []string
	for _, j := range decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, rec).Items {
		listed = append(listed, j["id"].(string))
	}
	assert.Equal(t, []string{dep[0].JobID}, listed)
	assert.Equal(t, reqs, len(k.kv.Requests()), "the held deployment read nothing from the vault")
	assert.Equal(t, cmds, len(k.f.server.Commands()))

	k.unlock()
	assert.Zero(t, k.runJobs(), "a renewed licence alone starts nothing")
	assert.Equal(t, "blocked_license", k.deployment(k.op, dep[0].ID).JobStatus)
	requireError(t, k.op.do(http.MethodPost, "/api/v1/jobs/"+dep[0].JobID+"/actions/confirm", nil), http.StatusForbidden, "ALC-AUTH-0002")
	requireStatus(t, k.admin.do(http.MethodPost, "/api/v1/jobs/"+dep[0].JobID+"/actions/confirm", nil), http.StatusOK)
	got := k.settleKV(k.op, dep[0].ID)
	assert.Equal(t, "succeeded", got.Status, "%+v", got)
	assert.Equal(t, pki.Fingerprint(k.kv.Leaf("web-cert", v2)), k.f.served(wwwName))
}

// heldVersion builds the state of the lock journey: a vault with a binding (automatic deployment ON), the licence
// locked, the vault renewed while it was locked, the licence renewed and the first poll after it done. The renewed
// version is held (S8: found after the gate reopened, created before it) and the planner left it alone.
func (k *kvnj) heldVersion() (vault, bindingID, certID, versionID, version string) {
	t := k.t
	t.Helper()
	k.addWebCert("web-cert")
	vault = k.addVault("prod-vault")
	bindingID, certID = k.bindWeb(vault, k.locs[wwwCert])
	requireStatus(t, k.autoDeploy(bindingID, 1, true), http.StatusOK)
	k.clock.Advance(2 * time.Minute)
	k.lockNow()
	version = k.kv.Renew("web-cert") // renewed in Azure while Alice is locked: no poll saw it
	k.clock.Advance(time.Minute)
	k.unlock()
	k.clock.Advance(time.Minute)
	k.checkNow(vault)
	for _, v := range versionsOf(k.kvDetail(k.admin, vault, certID)) {
		if v["version"] == version {
			versionID = v["id"].(string)
			require.Equal(t, true, v["held"], "a version found after a lock is held for an Administrator")
			require.Equal(t, "license", v["held_reason"])
		}
	}
	require.NotEmpty(t, versionID)
	require.NoError(t, k.plan())
	require.Empty(t, k.kvDeployments(k.op, k.locs[wwwCert]), "the planner does not deploy a held version")
	return vault, bindingID, certID, versionID, version
}

// TestKeyVaultHeldVersionDeployNow: "Deploy now" of a held version is an Administrator's act with a fresh step-up and
// no API token. An Operator is refused (ALC-AKV-0022), an Administrator whose step-up ended is asked for it
// (ALC-AUTH-0003), an Administrator's API token is refused (ALC-AUTH-0002): each leaves no deployment row, no read of
// the vault's secrets and no SSH command. With a fresh step-up it is accepted and runs.
func TestKeyVaultHeldVersionDeployNow(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{}, wwwSite())
	_, bid, _, verID, version := k.heldVersion()
	assert.Equal(t, 1, k.emails("kv.new_version_held_license"), "one email says the version waits for an Administrator")
	token, _ := createToken(t, k.stack, k.admin, k.adminAcct, "operate", 1)
	api := k.client("198.51.100.77")
	api.bearer = token

	deps, reads, cmds := k.count("deployments"), secretReads(k.kv), len(k.f.server.Commands())
	body := map[string]any{"version_id": verID}
	path := "/api/v1/bindings/" + bid + "/actions/deploy"
	requireError(t, k.op.do(http.MethodPost, path, body), http.StatusForbidden, "ALC-AKV-0022")
	k.pass(6 * time.Minute) // sign-in granted five minutes of step-up: they are over
	requireError(t, k.admin.do(http.MethodPost, path, body), http.StatusForbidden, "ALC-AUTH-0003")
	requireError(t, api.do(http.MethodPost, path, body, withoutHeader("Origin"), withoutHeader("Sec-Fetch-Site")), http.StatusForbidden, "ALC-AUTH-0002")
	assert.Equal(t, deps, k.count("deployments"), "no deployment row")
	assert.Equal(t, reads, secretReads(k.kv), "no read of the vault's secrets")
	assert.Equal(t, cmds, len(k.f.server.Commands()), "no SSH command")

	k.stepUp(k.admin, k.adminAcct)
	rec := k.admin.do(http.MethodPost, path, body)
	requireStatus(t, rec, http.StatusAccepted)
	id := decodeBody[struct {
		Deployments []deployRef `json:"deployments"`
	}](t, rec).Deployments[0].ID
	got := k.settleKV(k.op, id)
	assert.Equal(t, "succeeded", got.Status, "%+v", got)
	assert.Equal(t, pki.Fingerprint(k.kv.Leaf("web-cert", version)), k.f.served(wwwName))
	assert.Equal(t, 1, secretReads(k.kv)-reads)
}

// TestKeyVaultReleasedVersionIsDeployedAndNeverHeldAgain: the Administrator releases the held version; the planner then
// deploys it automatically, and the version is not held again by the following planner runs.
func TestKeyVaultReleasedVersionIsDeployedAndNeverHeldAgain(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{}, wwwSite())
	vault, _, certID, verID, version := k.heldVersion()
	k.stepUp(k.admin, k.adminAcct)
	requireError(t, k.op.do(http.MethodPost, "/api/v1/targets/"+vault+"/kv/certificates/"+certID+"/versions/"+verID+"/actions/release", nil), http.StatusForbidden, "ALC-AUTH-0002")
	requireStatus(t, k.admin.do(http.MethodPost, "/api/v1/targets/"+vault+"/kv/certificates/"+certID+"/versions/"+verID+"/actions/release", nil), http.StatusOK)
	require.NoError(t, k.plan())
	deps := k.kvDeployments(k.op, k.locs[wwwCert])
	require.Len(t, deps, 1, "the released version is deployed automatically")
	assert.Equal(t, version, deps[0].KVVersion)
	assert.Equal(t, "kv_renewal", deps[0].Trigger)
	require.Equal(t, "succeeded", k.settleKV(k.op, deps[0].ID).Status)
	for i := 0; i < 3; i++ {
		k.pass(time.Hour)
		k.checkNow(vault)
		require.NoError(t, k.plan())
	}
	for _, v := range versionsOf(k.kvDetail(k.admin, vault, certID)) {
		if v["version"] == version {
			assert.Equal(t, false, v["held"], "a released version is never held again")
		}
	}
	assert.Len(t, k.kvDeployments(k.op, k.locs[wwwCert]), 1, "and nothing more is deployed")
}

// TestL87KeyVaultPollInFlightAtLock is L-87 over the wire: the licence locks while a poll is held inside the fake
// Azure service. The request finishes, its result is stored (metadata only), and no automatic deployment is created
// from it, neither in lock nor after the licence returns (the version was found in lock: held).
func TestL87KeyVaultPollInFlightAtLock(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{}, wwwSite())
	k.addWebCert("web-cert")
	vault := k.addVault("prod-vault")
	bid, certID := k.bindWeb(vault, k.locs[wwwCert])
	requireStatus(t, k.autoDeploy(bid, 1, true), http.StatusOK)
	k.clock.Advance(2 * time.Minute)
	version := k.kv.Renew("web-cert")
	// Three minutes before the evaluation ends (the provider's poll budget runs on the stack's clock: a jump of weeks
	// while a request is in flight would end the poll as over budget, which is the provider's rule and not L-87).
	k.pass(k.license.Snapshot().Eval.LocksAt.Sub(k.clock.Now()) - 3*time.Minute)

	release := k.kv.Hold("/certificates")
	rec := k.op.do(http.MethodPost, "/api/v1/targets/"+vault+"/actions/discover", nil)
	requireStatus(t, rec, http.StatusAccepted)
	pollJob := decodeBody[map[string]any](t, rec)["job_id"].(string)
	done := make(chan error, 1)
	go func() {
		_, err := k.runner.RunOnce(context.Background())
		done <- err
	}()
	require.Eventually(t, func() bool { return k.kv.Held() == 1 }, 20*time.Second, 5*time.Millisecond, "the poll is inside the fake")
	k.clock.Advance(4 * time.Minute) // the licence locks while the request is in flight
	require.NoError(t, k.license.Tick(context.Background()))
	require.True(t, k.license.Snapshot().Eval.Locked())
	k.signIn(k.admin, k.adminAcct)
	k.signIn(k.op, k.opAcct)
	reqs := len(k.kv.Requests())
	release()
	require.NoError(t, <-done)
	require.GreaterOrEqual(t, len(k.kv.Requests()), reqs)

	assert.Equal(t, "succeeded", k.job(k.admin, pollJob)["status"], "a read-only job in flight finishes in lock")
	// The result was stored: the new version is known; nothing was deployed from it, in lock or after.
	detail := k.kvDetail(k.admin, vault, certID)
	assert.Equal(t, version, detail["current_version"], "the result of the poll in flight is stored")
	assert.Equal(t, "ok", k.vaultState(k.admin, vault).Status)
	assert.Empty(t, k.kvDeployments(k.op, k.locs[wwwCert]))
	err := k.kvScheduler().RunNow(context.Background(), "kv.auto_deploy")
	assert.True(t, errors.Is(err, license.ErrLocked))
	k.unlock()
	k.pass(time.Minute)
	require.NoError(t, k.plan())
	assert.Empty(t, k.kvDeployments(k.op, k.locs[wwwCert]), "the version found in lock waits for an Administrator")
	assert.Zero(t, k.f.emu.DeployCount())
}
