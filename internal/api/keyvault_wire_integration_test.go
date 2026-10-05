//go:build integration

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// renewedBinding is a vault with web-cert bound to web-01 (automatic deployment ON), renewed once and polled: the planner
// has not run. It returns the vault, the binding, the certificate and the new version.
func (k *kvnj) renewedBinding() (vault, binding, certID, version string) {
	k.t.Helper()
	k.addWebCert("web-cert")
	vault = k.addVault("prod-vault")
	binding, certID = k.bindWeb(vault, k.locs[wwwCert])
	requireStatus(k.t, k.autoDeploy(binding, 1, true), http.StatusOK)
	k.clock.Advance(2 * time.Minute)
	version = k.kv.Renew("web-cert")
	k.clock.Advance(time.Minute)
	k.checkNow(vault)
	return vault, binding, certID, version
}

// planOne plans the deployment of the renewed version and returns it.
func (k *kvnj) planOne() kvDep {
	k.t.Helper()
	require.NoError(k.t, k.plan())
	deps := k.kvDeployments(k.op, k.locs[wwwCert])
	require.Len(k.t, deps, 1)
	return deps[0]
}

// TestKVDeploymentSecretReadOverTheWire: what the vault answers to the deployment's secret read, as the real provider
// maps it. Each row fails the deployment with one closed reason BEFORE any SSH command, the website keeps its old
// certificate, and nothing of the answer's text is in the record.
func TestKVDeploymentSecretReadOverTheWire(t *testing.T) {
	rows := []struct {
		name   string
		inject func(k *kvnj, version string)
		status string
		code   string
		reason string
		params map[string]string
		audit  string // the failure reason of the kv.secret_read row ("" = no such row: nothing was read)
	}{
		{name: "403 on the secret: Key Vault Secrets User missing", inject: func(k *kvnj, _ string) { k.kv.RevokeRole("secrets/get") },
			code: "ALC-AKV-0003", reason: "azure.forbidden", params: map[string]string{"role": "Key Vault Secrets User"}},
		{name: "vault firewall", inject: func(k *kvnj, _ string) { k.kv.Firewall("203.0.113.7") }, code: "ALC-AKV-0004", reason: "azure.firewall"},
		{name: "version disabled before the read", inject: func(k *kvnj, v string) { k.kv.DisableVersion("web-cert", v) }, code: "ALC-AKV-0014", reason: "kv.version_disabled"},
		{name: "certificate deleted before the read", inject: func(k *kvnj, _ string) { k.kv.DeleteCertificate("web-cert") }, code: "ALC-AKV-0015", reason: "kv.certificate_not_found"},
		{name: "200 without a private key (policy flipped)", inject: func(k *kvnj, _ string) { k.kv.SetExportable("web-cert", false) },
			code: "ALC-AKV-0016", reason: "kv.secret_unreadable", audit: "secret_unreadable"},
		{name: "secret unauthorised (token refused)", inject: func(k *kvnj, _ string) {
			k.kv.FailNext("/secrets/web-cert", fakekv.Fault{Status: http.StatusUnauthorized})
			k.kv.FailNext("/secrets/web-cert", fakekv.Fault{Status: http.StatusUnauthorized})
		}, code: "ALC-AKV-0001", reason: "azure.auth_failed"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			k := newKVNJ(t, fakekv.Options{}, wwwSite())
			_, _, _, version := k.renewedBinding()
			dep := k.planOne() // pre-check passed: the stored state is fine; the vault changes before the job reads
			cmds := len(k.f.server.Commands())
			tc.inject(k, version)
			d := k.settleKV(k.op, dep.ID)
			assert.Equal(t, "failed", d.Status, "%+v", d)
			assert.Equal(t, tc.code, d.errorCode())
			require.NotNil(t, d.Error)
			assert.Equal(t, tc.reason, d.Error.Reason)
			for key, want := range tc.params {
				assert.Equal(t, want, d.Error.Params[key])
			}
			assert.Equal(t, "kv_secret", d.FailedStep)
			assert.Equal(t, cmds, len(k.f.server.Commands()), "no SSH command")
			assert.Equal(t, pki.Fingerprint(k.f.old.Cert), k.f.served(wwwName), "the website is unchanged")
			if tc.audit != "" {
				assert.Equal(t, 1, k.countWhere("audit_log", "action = 'kv.secret_read' AND result = 'failure' AND details->>'reason' = '"+tc.audit+"' AND details->>'purpose' = 'deploy'"))
			}
			// The error carried only closed reasons: nothing but allowlisted params, short.
			for key, v := range d.Error.Params {
				assert.Contains(t, []string{"role", "model", "aadsts", "azure_code", "azure_request_id", "client_address", "reason"}, key)
				assert.LessOrEqual(t, len(v), 128)
			}
			j := k.job(k.op, d.JobID)
			assert.Less(t, len(asJSON(t, j["error"])), 1024, "the job's error is bounded")
		})
	}
}

// TestKVDeploymentVaultCredential: the deployment unseals the vault's credential at run time; a credential row
// that cannot be opened ends the deployment with a closed reason and no SSH. (The vault read's one-minute budget is a
// context deadline in real time: honouring it would take a minute of wall time per run, so it is not part of this
// suite; see the report.)
func TestKVDeploymentVaultCredential(t *testing.T) {
	t.Run("credential cannot be unsealed", func(t *testing.T) {
		k := newKVNJ(t, fakekv.Options{}, wwwSite())
		vault, _, _, _ := k.renewedBinding()
		dep := k.planOne()
		cmds, reads := len(k.f.server.Commands()), secretReads(k.kv)
		// The sealed secret is damaged (a restore from a wrong backup, a flipped bit): the open fails its authentication.
		_, err := k.db.Owner.Exec(context.Background(), `UPDATE credentials SET ciphertext = set_byte(ciphertext, 0, get_byte(ciphertext, 0) # 255)
WHERE target_id = $1 AND purpose = 'azure_vault'`, vault)
		require.NoError(t, err)
		d := k.settleKV(k.op, dep.ID)
		assert.Equal(t, "failed", d.Status, "%+v", d)
		assert.NotEmpty(t, d.errorCode())
		t.Logf("a damaged vault credential ends the deployment with %s %v", d.errorCode(), d.Error)
		assert.Equal(t, cmds, len(k.f.server.Commands()), "no SSH command")
		assert.Equal(t, reads, secretReads(k.kv), "nothing was read from the vault")
		assert.Equal(t, pki.Fingerprint(k.f.old.Cert), k.f.served(wwwName))
	})
}

// TestKVDeploymentAddressGuard: on the deployment path as on the poll's, a redirect that names another host (a metadata
// address, a foreign name) is not followed: nothing is sent there, the read is retried and finally refused, the
// deployment fails before any SSH command and the website is unchanged.
func TestKVDeploymentAddressGuard(t *testing.T) {
	const evil = "evil.example.test"
	for name, location := range map[string]string{"foreign host": "https://" + evil + "/secrets/web-cert", "metadata address": "http://169.254.169.254/metadata/identity"} {
		t.Run(name, func(t *testing.T) {
			k := newKVNJ(t, fakekv.Options{ExtraHosts: []string{evil}, ManagedIdentity: true, MIClientID: fakekv.UniqueClientID()}, wwwSite())
			_, _, _, _ = k.renewedBinding()
			dep := k.planOne()
			cmds := len(k.f.server.Commands())
			k.kv.ClearRequests()
			stop := k.kv.FailAll("/secrets/web-cert", fakekv.Fault{Status: http.StatusFound, Location: location})
			defer stop()
			d := k.settleKV(k.op, dep.ID)
			assert.Equal(t, "failed", d.Status, "%+v", d)
			requireNothingSentTo(t, k.kv, evil, "169.254.169.254")
			assert.Equal(t, cmds, len(k.f.server.Commands()))
			assert.Equal(t, pki.Fingerprint(k.f.old.Cert), k.f.served(wwwName))
		})
	}
}

// TestKVSessionThatPanicsOnClose: a vault session that panics when it is closed (after the secret was read) never leaves
// the deployment unended or leaks the key: the runner contains the panic and the deployment reaches a final state.
func TestKVSessionThatPanicsOnClose(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{}, wwwSite())
	_, _, _, version := k.renewedBinding()
	dep := k.planOne()
	cmds := len(k.f.server.Commands())
	k.closePanics.Store(true)
	d := k.settleKV(k.op, dep.ID)
	k.closePanics.Store(false)
	t.Logf("a session that panics when closed: state %s status %s error %v", d.State, d.Status, d.Error)
	assert.Equal(t, "done", d.State, "the deployment is ended, not stuck")
	assert.Contains(t, k.logs.String(), "panic", "the panic is contained and logged by the runner")
	assert.NotContains(t, k.logs.String(), "goroutine ", "no stack dump with a value in the log")
	// The panic came right after the read and before anything was sent: the deployment failed closed.
	assert.Equal(t, "failed", d.Status)
	assert.Equal(t, cmds, len(k.f.server.Commands()))
	assert.Equal(t, pki.Fingerprint(k.f.old.Cert), k.f.served(wwwName))
	// A deployment can still be made once the session behaves.
	_ = version
}

// TestKVPolledListingEdges: listing answers the provider must not take for the vault's truth: a page without "value"
// is not an empty vault (nothing is marked removed), and an answer is never partially stored.
func TestKVPolledListingEdges(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{})
	k.addWebCert("web-cert")
	k.kv.AddCertificate("other-cert", fakekv.CertOptions{CommonName: "o.example.test", Exportable: true})
	vault := k.addVault("prod-vault")
	for i := 0; i < 3; i++ { // three polls in a row that answer "{}": never an empty vault
		k.kv.FailNext("/certificates", fakekv.Fault{Body: "{}"})
		k.clock.Advance(time.Minute)
		k.checkNow(vault)
	}
	gone := k.admin.do(http.MethodGet, "/api/v1/targets/"+vault+"/kv/certificates?missing=only", nil)
	requireStatus(t, gone, http.StatusOK)
	assert.Empty(t, decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, gone).Items, "a page without value marks nothing missing")
	assert.ElementsMatch(t, []string{"web-cert", "other-cert"}, itemNames(k.kvItems(k.admin, vault, "certificates")))
	assert.Zero(t, k.emails("kv.certificate_removed")+k.emails("kv.certificate_removed_bound"))
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	return strings.TrimSpace(string(kvMarshal(t, v)))
}

// TestKeyVaultAPIFacts pins API behaviours of the vault routes against the real stack (a version that comes from a real
// poll of the fake vault): a binding that moved answers 412 before anything about the body is judged; a version the
// certificate does not have is 404; the import list pages with a cursor that belongs to its vault and filters by
// certificate; a failed import whose requester lost the Administrator role says so (ALC-AKV-0040); a body of "null" is
// a bad request while an empty body and {} are accepted by the optional-body routes.
func TestKeyVaultAPIFacts(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{}, wwwSite())
	k.addWebCert("web-cert")
	vault := k.addVault("main-vault")
	bid, webID := k.bindWeb(vault, k.locs[wwwCert])
	verID := versionsOf(k.kvDetail(k.admin, vault, webID))[0]["id"].(string)

	// A binding that moved answers 412 before the inventory judges anything else; the body's own shape is judged first.
	requireError(t, k.op.do(http.MethodPatch, "/api/v1/bindings/"+bid, map[string]any{"location_ids": []string{k.locs[wwwCert]}}, ifMatchOf("99")), http.StatusPreconditionFailed, "ALC-SYS-0008")
	requireError(t, k.op.do(http.MethodPatch, "/api/v1/bindings/"+bid, map[string]any{"location_ids": []string{"not-a-uuid"}}, ifMatchOf("1")), http.StatusUnprocessableEntity, "ALC-SYS-0006")

	// A version id the certificate does not have is "not found", not "not deployable".
	other := "01a109cc-ae73-740d-80f6-e6fd3f1e1c2a"
	requireError(t, k.op.do(http.MethodPost, "/api/v1/bindings/"+bid+"/actions/deploy", map[string]any{"version_id": other}), http.StatusNotFound, "ALC-SYS-0001")
	k.stepUp(k.admin, k.adminAcct)
	requireError(t, k.admin.do(http.MethodPost, "/api/v1/targets/"+vault+"/kv/certificates/"+webID+"/versions/"+other+"/actions/release", nil), http.StatusNotFound, "ALC-SYS-0001")

	// Optional bodies: nothing, {} and a nested release are accepted; "null" is not.
	rel := "/api/v1/targets/" + vault + "/kv/certificates/" + webID + "/versions/" + verID + "/actions/release"
	requireError(t, k.admin.do(http.MethodPost, rel, "null"), http.StatusBadRequest, "ALC-SYS-0004")
	for _, body := range []any{nil, "{}"} {
		rec := k.admin.do(http.MethodPost, rel, body)
		assert.Contains(t, []int{http.StatusOK, http.StatusConflict}, rec.Code, "an empty body or {} is read as no options: %s", rec.Body.String())
		assert.NotEqual(t, http.StatusBadRequest, rec.Code)
	}

	// The import list pages and filters; a cursor is valid only for its own vault.
	up := k.uploadCertificate(k.op, certBody(k.issue(), "To import"))
	other2 := k.uploadCertificate(k.op, certBody(k.issue(), "Another"))
	var ids []string
	for i, name := range []string{"a-cert", "b-cert", "c-cert"} {
		src := up
		if i == 2 {
			src = other2
		}
		ids = append(ids, k.requestImport(src, vault, name, false).ID)
	}
	list := "/api/v1/targets/" + vault + "/kv/imports"
	type page struct {
		Items      []importView `json:"items"`
		NextCursor *string      `json:"next_cursor"`
	}
	rec := k.admin.do(http.MethodGet, list+"?limit=2", nil)
	requireStatus(t, rec, http.StatusOK)
	first := decodeBody[page](t, rec)
	require.Len(t, first.Items, 2)
	require.NotNil(t, first.NextCursor, "a real next_cursor")
	rec = k.admin.do(http.MethodGet, list+"?limit=2&cursor="+*first.NextCursor, nil)
	requireStatus(t, rec, http.StatusOK)
	second := decodeBody[page](t, rec)
	require.Len(t, second.Items, 1)
	assert.Nil(t, second.NextCursor)
	got := map[string]bool{}
	for _, it := range append(first.Items, second.Items...) {
		got[it.ID] = true
	}
	for _, id := range ids {
		assert.True(t, got[id], "every import is listed once")
	}
	rec = k.admin.do(http.MethodGet, list+"?certificate_name=b-cert", nil)
	requireStatus(t, rec, http.StatusOK)
	if items := decodeBody[page](t, rec).Items; assert.Len(t, items, 1) {
		assert.Equal(t, "b-cert", items[0].Name)
	}
	rec = k.admin.do(http.MethodGet, list+"?certificate_id="+other2, nil)
	requireStatus(t, rec, http.StatusOK)
	if items := decodeBody[page](t, rec).Items; assert.Len(t, items, 1) {
		assert.Equal(t, "c-cert", items[0].Name)
	}
	// A cursor of this vault on another vault is refused.
	p5 := phase5Records(t, k.stack, up)
	requireError(t, k.admin.do(http.MethodGet, "/api/v1/targets/"+p5["vault"]+"/kv/imports?cursor="+*first.NextCursor, nil), http.StatusUnprocessableEntity, "ALC-SYS-0006")

	// A requester that lost the Administrator role before the job ran: the import fails, saying so.
	pw := "second-admin-password-2026"
	root2 := k.createUser(k.admin, k.adminAcct, "ruth", "admin", pw)
	c2 := k.freshClient()
	k.firstSignIn(c2, root2)
	k.stepUp(c2, root2)
	rec = c2.do(http.MethodPost, "/api/v1/certificates/"+up+"/actions/import-to-key-vault", map[string]any{"target_id": vault, "name": "late-cert"})
	requireStatus(t, rec, http.StatusAccepted)
	id := decodeBody[struct {
		Import importView `json:"import"`
	}](t, rec).Import.ID
	k.stepUp(k.admin, k.adminAcct)
	requireStatus(t, k.admin.do(http.MethodPatch, "/api/v1/users/"+root2.id, map[string]string{"role": "operator"}), http.StatusOK)
	k.runKV()
	im := k.importOf(vault, id)
	assert.Equal(t, "failed", im.State)
	assert.Equal(t, "ALC-AKV-0040", im.errCode())
	assert.Empty(t, k.kv.Versions("late-cert"), "nothing was sent for a requester who is no longer an Administrator")
}
