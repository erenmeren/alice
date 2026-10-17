//go:build integration

package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// TestKeyVaultJourney is the phase's main end-to-end journey over the wire: an Administrator adds a vault, the
// access check is green, the first poll lists the vault's objects, an Operator binds a certificate to two
// websites on two Nginx servers, the Administrator turns automatic deployment on, the vault renews, "Check now"
// finds the version, the planner creates one deployment per website, the jobs run and both websites serve the
// renewed leaf. Every request to "Azure" goes through the real azurekv provider to the in-process fake.
func TestKeyVaultJourney(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{}, wwwSite())
	b, _, bLocs := k.addNginx("web-02", apiSite())
	oldVersion := k.addWebCert("web-cert")
	k.kv.AddCertificate("monitor-only", fakekv.CertOptions{CommonName: "mo.example.test", Exportable: false})
	k.kv.AddKey("signing-key", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
	k.kv.AddSecret("db-password", "text/plain")

	// The Administrator adds the vault (step-up): the answer carries the access check, never the secret.
	k.stepUp(k.admin, k.adminAcct)
	rec := k.admin.do(http.MethodPost, "/api/v1/key-vaults", k.vaultBody("prod-vault"))
	requireStatus(t, rec, http.StatusCreated)
	assert.NotContains(t, rec.Body.String(), k.kv.Secret())
	created := decodeBody[map[string]any](t, rec)
	vault := created["target"].(map[string]any)["id"].(string)
	access := created["access"].(map[string]any)
	assert.Equal(t, k.kv.TenantID(), access["tenant_id"])
	assert.Equal(t, k.kv.ObjectID(), access["object_id"])
	got := map[string]string{}
	for _, c := range access["checks"].([]any) {
		m := c.(map[string]any)
		got[m["name"].(string)] = m["result"].(string)
	}
	assert.Equal(t, map[string]string{"sign_in": "ok", "list_certificates": "ok", "list_keys": "ok", "list_secrets": "ok",
		"read_secret": "not_checked", "import": "not_checked"}, got)

	// The first poll lists what the vault holds.
	k.runKV()
	tv := k.target(k.admin, vault)
	assert.Equal(t, "ok", tv["status"])
	certs := map[string]map[string]any{}
	for _, c := range k.kvItems(k.admin, vault, "certificates") {
		certs[c["name"].(string)] = c
	}
	require.Len(t, certs, 2)
	web, mo := certs["web-cert"], certs["monitor-only"]
	assert.Equal(t, true, web["exportable"])
	assert.Equal(t, "ecdsa", web["key_type"])
	assert.Equal(t, oldVersion, web["current_version"])
	assert.Equal(t, false, mo["exportable"])
	assert.Contains(t, itemNames(k.kvItems(k.admin, vault, "keys")), "signing-key")
	assert.Contains(t, itemNames(k.kvItems(k.admin, vault, "secrets")), "db-password")

	// The poll read no secret value: monitoring needs only the lists and the details.
	assert.Zero(t, secretReads(k.kv))

	// The Operator binds web-cert to the two websites; the monitor-only certificate cannot be bound (F-45).
	requireError(t, k.op.do(http.MethodPost, "/api/v1/bindings", map[string]any{"kv_certificate_id": mo["id"], "location_ids": []string{k.locs[wwwCert]}}),
		http.StatusUnprocessableEntity, "ALC-AKV-0013")
	binding := k.bind(k.op, web["id"].(string), k.locs[wwwCert], bLocs[apiCert])
	bid := binding["id"].(string)
	assert.Equal(t, false, binding["auto_deploy"])
	assert.Zero(t, k.f.emu.DeployCount())

	// Automatic deployment ON (Administrator). Only versions created afterwards are deployed.
	rec = k.autoDeploy(bid, int(binding["version"].(float64)), true)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, true, decodeBody[map[string]any](t, rec)["auto_deploy"])
	k.clock.Advance(2 * time.Minute)

	// Nothing new: the planner creates nothing.
	require.NoError(t, k.plan())
	assert.Empty(t, k.kvDeployments(k.op, k.locs[wwwCert]))

	// Key Vault renews; Check now finds the version; the planner creates one deployment per website.
	newVersion := k.kv.Renew("web-cert")
	k.clock.Advance(time.Minute)
	k.checkNow(vault)
	detail := k.kvDetail(k.admin, vault, web["id"].(string))
	assert.Equal(t, newVersion, detail["current_version"])
	require.Len(t, versionsOf(detail), 2, "the old version stays in the history")
	assert.Equal(t, 0, secretReads(k.kv))
	require.NoError(t, k.plan())
	aDeps, bDeps := k.kvDeployments(k.op, k.locs[wwwCert]), k.kvDeployments(k.op, bLocs[apiCert])
	require.Len(t, aDeps, 1)
	require.Len(t, bDeps, 1)
	for _, d := range []kvDep{aDeps[0], bDeps[0]} {
		assert.Equal(t, "key_vault", d.Source)
		assert.Equal(t, "kv_renewal", d.Trigger)
		assert.Equal(t, newVersion, d.KVVersion)
		assert.Equal(t, "prod-vault", d.VaultName)
		assert.Equal(t, bid, *d.BindingID)
	}
	// A second planner run while those are in flight creates nothing more.
	require.NoError(t, k.plan())
	require.Len(t, k.kvDeployments(k.op, k.locs[wwwCert]), 1)

	da, db := k.settleKV(k.op, aDeps[0].ID), k.settleKV(k.op, bDeps[0].ID)
	require.Equal(t, "succeeded", da.Status, "%+v", da)
	require.Equal(t, "succeeded", db.Status, "%+v", db)
	require.Equal(t, []string{"kv_secret:started", "kv_secret:ok"}, da.stepList()[:2], "the vault is read before anything else: %v", da.stepList())

	// Both websites serve the renewed leaf (the file pair on the server and what the website serves).
	want := k.kv.Leaf("web-cert", newVersion)
	for _, w := range []struct {
		f             *nginxFixture
		cert, key, sn string
	}{{k.f, wwwCert, wwwKey, wwwName}, {b, apiCert, apiKey, apiName}} {
		certPEM, keyPEM := w.f.emu.DumpFile(w.cert), w.f.emu.DumpFile(w.key)
		require.NotEmpty(t, keyPEM)
		assert.Equal(t, pki.Fingerprint(want), w.f.served(w.sn), "the website serves the renewed leaf")
		assert.Equal(t, 2, strings.Count(string(certPEM), "BEGIN CERTIFICATE"), "the installed file holds the leaf and the vault's intermediate")
		assert.Equal(t, 1, w.f.emu.DeployCount())
	}

	// One authenticated secret read per deployment, audited; the private key was never sealed by Alice.
	assert.Equal(t, 2, secretReads(k.kv))
	assert.Equal(t, 2, k.countWhere("audit_log", "action = 'kv.secret_read' AND result = 'success' AND details->>'purpose' = 'deploy'"))
	assert.Zero(t, k.count("managed_private_keys"))

	// The history keeps both versions; the vault's current one is the deployed one; the binding's websites are deployed.
	detail = k.kvDetail(k.admin, vault, web["id"].(string))
	assert.Equal(t, newVersion, detail["current_version"])
	assert.Equal(t, k.leafFingerprint("web-cert", newVersion), pki.Fingerprint(want))
	assert.Empty(t, k.deploymentEmails(), "no deployment email on success")
	rec = k.op.do(http.MethodGet, "/api/v1/bindings/"+bid, nil)
	requireStatus(t, rec, http.StatusOK)
	for _, l := range decodeBody[map[string]any](t, rec)["locations"].([]any) {
		assert.Equal(t, "deployed", l.(map[string]any)["state"])
	}
}

// TestImportJourney: an uploaded certificate goes into the vault under a new name (version 1), under the same name
// without and with the confirmation (version 2, which a binding with automatic deployment then deploys), without the
// Certificates Officer role (nothing created) and with an answer that is lost after the vault processed the request
// (never re-sent; uncertain until a poll sees the version).
func TestImportJourney(t *testing.T) {
	k := newKVNJ(t, fakekv.Options{}, wwwSite())
	k.addWebCert("web-cert")
	vault := k.addVault("prod-vault")
	leaf := k.issue(wwwName, apiName)
	certID := k.uploadCertificate(k.op, certBody(leaf, "To import"))

	// New name: version 1, one authenticated POST, the thumbprint the request announced.
	im := k.requestImport(certID, vault, "imported-cert", false)
	assert.Equal(t, "succeeded", im.State)
	require.Len(t, k.kv.Versions("imported-cert"), 1)
	assert.Equal(t, k.kv.Versions("imported-cert")[0], im.Version)
	assert.Equal(t, 1, importPosts(k.kv))
	assert.Equal(t, pki.Fingerprint(leaf.Cert), pki.Fingerprint(k.kv.Leaf("imported-cert", im.Version)), "the vault holds the uploaded certificate")
	assert.Nil(t, im.Error)
	assert.Equal(t, 1, k.auditCount("kv.import.requested"))

	// The same name without the confirmation is refused before anything is sent; with it a version is added.
	posts := importPosts(k.kv)
	rec := k.importRaw(certID, vault, "imported-cert", false)
	requireError(t, rec, http.StatusConflict, "ALC-AKV-0023")
	assert.Equal(t, posts, importPosts(k.kv))
	assert.Equal(t, 1, k.count("kv_imports"))
	im2 := k.requestImport(certID, vault, "imported-cert", true)
	assert.Equal(t, "succeeded", im2.State)
	assert.True(t, im2.NewVersion)
	require.Len(t, k.kv.Versions("imported-cert"), 2)

	// A binding with automatic deployment on web-cert: importing into web-cert adds version 2 and it is deployed.
	k.checkNow(vault)
	web := k.kvCertByName(k.admin, vault, "web-cert")
	binding := k.bind(k.op, web["id"].(string), k.locs[wwwCert])
	bid := binding["id"].(string)
	requireStatus(t, k.autoDeploy(bid, int(binding["version"].(float64)), true), http.StatusOK)
	k.clock.Advance(2 * time.Minute)
	im3 := k.requestImport(certID, vault, "web-cert", true)
	require.Equal(t, "succeeded", im3.State, "%+v", im3)
	require.Len(t, k.kv.Versions("web-cert"), 2)
	k.clock.Advance(time.Minute)
	k.checkNow(vault)
	require.NoError(t, k.plan())
	deps := k.kvDeployments(k.op, k.locs[wwwCert])
	require.Len(t, deps, 1)
	assert.Equal(t, im3.Version, deps[0].KVVersion)
	require.Equal(t, "succeeded", k.settleKV(k.op, deps[0].ID).Status)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), k.f.served(wwwName), "the imported certificate is what the website serves")

	// Without the Certificates Officer role: rejected as a missing role, nothing created.
	k.kv.RevokeRole("certificates/import")
	versions := len(k.kv.Versions("imported-cert"))
	imF := k.requestImport(certID, vault, "second-cert", false)
	assert.Equal(t, "failed", imF.State)
	assert.Equal(t, "ALC-AKV-0003", imF.errCode())
	assert.Equal(t, "Key Vault Certificates Officer", imF.Error.Params["role"])
	assert.Empty(t, k.kv.Versions("second-cert"))
	assert.Len(t, k.kv.Versions("imported-cert"), versions)
	k.kv.GrantRole("certificates/import")

	// A lost answer: the vault processed the request, the connection was reset. The import is never re-sent.
	k.kv.FailNext("/certificates/lost-cert/import", fakekv.Fault{Reset: true, Apply: true})
	posts = importPosts(k.kv)
	imU := k.requestImport(certID, vault, "lost-cert", false)
	assert.Equal(t, "uncertain", imU.State)
	assert.Equal(t, posts+1, importPosts(k.kv))
	require.Len(t, k.kv.Versions("lost-cert"), 1)
	// The record carries the cause of the uncertainty (the connection was lost), never a rejection.
	assert.Equal(t, "ALC-AKV-0006", imU.errCode())
	// Nothing re-sends it: the job's retry, a rerun and the schedule send nothing more.
	k.clock.Advance(10 * time.Minute)
	k.runKV()
	k.touch()
	k.clock.Advance(20 * time.Minute)
	require.NoError(t, k.schedule())
	k.touch()
	assert.Equal(t, posts+1, importPosts(k.kv))
	// A later poll sees the version with the thumbprint, created after the request: settled.
	k.checkNow(vault)
	imS := k.importOf(vault, imU.ID)
	assert.Equal(t, "succeeded", imS.State)
	assert.Equal(t, k.kv.Versions("lost-cert")[0], imS.Version)
	assert.Equal(t, posts+1, importPosts(k.kv))
}
