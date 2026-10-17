//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

func (h *harness) names(page inventory.KVCertificatePage) []string {
	var out []string
	for _, c := range page.Items {
		out = append(out, c.Name)
	}
	return out
}

func TestListKVCertificates(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	vault := h.vault("prod")
	other := h.vault("other")
	now := h.clock.Now()
	var cs []providers.KVCertificate
	for i, n := range []string{"alpha", "Beta", "gamma", "delta-web", "web-cert"} {
		c := h.kvc(n, h.kvLeaf(n+".example.test"), ver(i+1), now, true)
		exp := now.Add(time.Duration(i+1) * 24 * time.Hour)
		c.Expires = &exp
		cs = append(cs, c)
	}
	h.reconcile(vault, kvResult(cs...))
	h.reconcile(other, kvResult(h.kvc("alpha", h.kvLeaf("o.example.test"), ver(1), now, true)))
	h.clock.Advance(time.Minute)
	h.reconcile(vault, kvResult(cs[0], cs[1], cs[2], cs[4])) // delta-web is gone
	require.NotNil(t, h.certRow(vault, "delta-web").Missing)

	list := func(f inventory.KVFilter) []string {
		page, err := h.svc.ListKVCertificates(h.ctx, vault, f)
		require.NoError(t, err)
		return h.names(page)
	}
	assert.Equal(t, []string{"alpha", "Beta", "gamma", "web-cert"}, list(inventory.KVFilter{}), "by folded name, missing hidden, one vault only")
	assert.Equal(t, []string{"alpha", "Beta", "delta-web", "gamma", "web-cert"}, list(inventory.KVFilter{Missing: inventory.KVMissingInclude}))
	assert.Equal(t, []string{"delta-web"}, list(inventory.KVFilter{Missing: inventory.KVMissingOnly}))
	assert.Equal(t, []string{"web-cert"}, list(inventory.KVFilter{Query: "WEB"}), "case-insensitive substring")
	assert.Equal(t, []string{"delta-web", "web-cert"}, list(inventory.KVFilter{Query: "web", Missing: inventory.KVMissingInclude}))
	assert.Empty(t, list(inventory.KVFilter{Query: "100%"}), "wildcards are escaped")
	before := now.Add(60 * time.Hour) // alpha 24 h, Beta 48 h expire before; gamma 72 h does not
	assert.Equal(t, []string{"alpha", "Beta"}, list(inventory.KVFilter{ExpiresBefore: &before}))

	// Paging by name.
	page, err := h.svc.ListKVCertificates(h.ctx, vault, inventory.KVFilter{Limit: 2})
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "Beta"}, h.names(page))
	require.NotEmpty(t, page.NextCursor)
	page, err = h.svc.ListKVCertificates(h.ctx, vault, inventory.KVFilter{Limit: 2, Cursor: page.NextCursor})
	require.NoError(t, err)
	assert.Equal(t, []string{"gamma", "web-cert"}, h.names(page))
	assert.Empty(t, page.NextCursor)

	// Validation: every problem, closed codes.
	for _, f := range []inventory.KVFilter{{Limit: 201}, {Limit: -1}, {Missing: "x"}, {Cursor: "!!"}, {Cursor: "QWxwaGE"}, {Query: "a\x00"}} {
		_, err := h.svc.ListKVCertificates(h.ctx, vault, f)
		var verrs validate.Errors
		require.ErrorAs(t, err, &verrs)
	}

	// The vault must be a live vault.
	web := h.seedTarget("web", "nginx", "web.example.com")
	_, err = h.svc.ListKVCertificates(h.ctx, web, inventory.KVFilter{})
	require.ErrorIs(t, err, inventory.ErrNotAVault)
	_, err = h.svc.ListKVCertificates(h.ctx, uuid.New(), inventory.KVFilter{})
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, _, err = h.svc.ListKVKeys(h.ctx, web, inventory.KVFilter{})
	require.ErrorIs(t, err, inventory.ErrNotAVault)
	_, _, err = h.svc.ListKVSecrets(h.ctx, web, inventory.KVFilter{})
	require.ErrorIs(t, err, inventory.ErrNotAVault)
}

func TestListKVKeysAndSecrets(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "")
	vault := h.vault("prod")
	now := h.clock.Now()
	res := kvResult()
	for _, n := range []string{"k1", "K2", "signing", "backing"} {
		res.KV.Keys = append(res.KV.Keys, kvKey(n, n == "backing", now, n != "backing"))
	}
	for _, n := range []string{"s1", "S2", "token"} {
		res.KV.Secrets = append(res.KV.Secrets, kvSecret(n, now))
	}
	res.KV.KeysListed, res.KV.SecretsListed = true, true
	h.reconcile(vault, res)

	keys, next, err := h.svc.ListKVKeys(h.ctx, vault, inventory.KVFilter{Limit: 3})
	require.NoError(t, err)
	require.Len(t, keys, 3)
	assert.Equal(t, "backing", keys[0].Name)
	assert.True(t, keys[0].Managed)
	assert.Equal(t, "k1", keys[1].Name)
	assert.Equal(t, "rsa", keys[1].KeyType)
	assert.Equal(t, 2048, keys[1].KeySize)
	require.NotNil(t, keys[1].DetailsUpdatedAt)
	assert.Equal(t, "K2", keys[2].Name)
	require.NotEmpty(t, next)
	keys, next, err = h.svc.ListKVKeys(h.ctx, vault, inventory.KVFilter{Limit: 3, Cursor: next})
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "signing", keys[0].Name)
	assert.Empty(t, next)
	keys, _, err = h.svc.ListKVKeys(h.ctx, vault, inventory.KVFilter{Query: "K"})
	require.NoError(t, err)
	assert.Len(t, keys, 3, "backing, k1 and K2: a folded substring")

	secs, _, err := h.svc.ListKVSecrets(h.ctx, vault, inventory.KVFilter{})
	require.NoError(t, err)
	require.Len(t, secs, 3)
	assert.Equal(t, []string{"s1", "S2", "token"}, []string{secs[0].Name, secs[1].Name, secs[2].Name})
	assert.Equal(t, "text/plain", secs[0].ContentType)

	// A removed secret is hidden unless asked for.
	h.clock.Advance(time.Minute)
	res.KV.Secrets = res.KV.Secrets[:2]
	h.reconcile(vault, res)
	secs, _, err = h.svc.ListKVSecrets(h.ctx, vault, inventory.KVFilter{})
	require.NoError(t, err)
	assert.Len(t, secs, 2)
	secs, _, err = h.svc.ListKVSecrets(h.ctx, vault, inventory.KVFilter{Missing: inventory.KVMissingOnly})
	require.NoError(t, err)
	require.Len(t, secs, 1)
	assert.Equal(t, "token", secs[0].Name)
	require.NotNil(t, secs[0].MissingSince)
	_, _, err = h.svc.ListKVKeys(h.ctx, vault, inventory.KVFilter{Limit: 500})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
}

func TestKVCertificateDetail(t *testing.T) {
	h := newHarness(t, withAzure(), withNginxProvider())
	admin := h.user("ada", rbac.Admin, "")
	vault := h.vault("prod")
	web := nginxTarget(t, h, admin, "web-01")
	t0 := h.clock.Now()
	l1 := h.kvLeaf("www.example.test")
	h.reconcile(vault, kvResult(h.kvc("web-cert", l1, ver(1), t0, true)))
	h.clock.Advance(time.Hour)
	l2 := h.kvLeaf("www.example.test")
	h.reconcile(vault, kvResult(h.kvc("web-cert", l2, ver(2), h.clock.Now(), true, ver(1), ver(0))))
	cert := h.certRow(vault, "web-cert")

	d, err := h.svc.KVCertificate(h.ctx, vault, cert.ID)
	require.NoError(t, err)
	assert.Equal(t, "web-cert", d.Name)
	assert.Equal(t, ver(2), d.CurrentVersion)
	require.Len(t, d.Versions, 3)
	assert.Equal(t, []string{ver(2), ver(1), ver(0)}, []string{d.Versions[0].Version, d.Versions[1].Version, d.Versions[2].Version}, "newest first")
	require.NotNil(t, d.Versions[0].CertificateID)
	assert.Nil(t, d.Versions[2].CertificateID)
	assert.Nil(t, d.Binding)
	assert.False(t, d.Bound)
	assert.Equal(t, inventory.DeployAccessNotChecked, d.DeployAccess)

	// A binding with two locations.
	binding := h.bindCertificate(cert.ID, vault)
	ca := pki.NewCA("Bind", pki.ECDSA256, h.clock.Now())
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key"), ca.Issue(pki.Opts{CommonName: "a.example.test"}, h.clock.Now())),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key"), ca.Issue(pki.Opts{CommonName: "b.example.test"}, h.clock.Now()))}})
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET binding_id = $1 WHERE target_id = $2", binding, web.ID)
	require.NoError(t, err)
	d, err = h.svc.KVCertificate(h.ctx, vault, cert.ID)
	require.NoError(t, err)
	require.NotNil(t, d.Binding)
	assert.Equal(t, binding, d.Binding.ID)
	assert.Equal(t, 2, d.Binding.LocationCount)
	assert.False(t, d.Binding.AutoDeploy)
	assert.True(t, d.Bound)

	// Deploy access: forbidden from the checklist, ok from a checklist row or a successful Key Vault
	// deployment; the most recent evidence wins.
	checks := func(result string) {
		t.Helper()
		rep := providers.ConnectionReport{Azure: &providers.AzureFacts{PermissionModel: "rbac", CheckedAt: h.clock.Now(), Checks: []providers.AzureCheck{
			{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK},
			{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultOK},
			{Name: providers.AzureCheckReadSecret, Result: result, Role: providers.RoleKeyVaultSecretsUser}}}}
		require.NoError(t, h.svc.RecordKVConnection(h.ctx, vault, rep))
	}
	access := func() string {
		d, err := h.svc.KVCertificate(h.ctx, vault, cert.ID)
		require.NoError(t, err)
		return d.DeployAccess
	}
	checks(providers.AzureResultForbidden)
	assert.Equal(t, inventory.DeployAccessForbidden, access())
	checks(providers.AzureResultNotChecked)
	assert.Equal(t, inventory.DeployAccessNotChecked, access())
	checks(providers.AzureResultOK)
	assert.Equal(t, inventory.DeployAccessOK, access())
	h.clock.Advance(time.Hour)
	checks(providers.AzureResultForbidden)
	assert.Equal(t, inventory.DeployAccessForbidden, access())
	h.clock.Advance(time.Hour)
	vs := h.versionRows(cert.ID)
	loc := byPath(t, h, web.ID, false)["/etc/nginx/ssl/a.crt"]
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint, cert_path, key_path,
binding_id, kv_version_id, created_at, finished_at) SELECT $1, certificate_id, $2, $3, 'kv_renewal', 'done', 'succeeded', repeat('a', 64), '/etc/nginx/ssl/a.crt',
'/etc/nginx/ssl/a.key', $4, v.id, $5, $5 FROM kv_certificate_versions v WHERE v.kv_certificate_id = $6 AND v.version = $7`,
		uuid.Must(uuid.NewV7()), loc.ID, web.ID, binding, h.clock.Now(), cert.ID, ver(2))
	require.NoError(t, err)
	require.NotNil(t, vs[ver(2)].CertID)
	assert.Equal(t, inventory.DeployAccessOK, access(), "a later successful deployment from this vault beats an earlier refusal")

	// Held versions are shown as held.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE kv_certificate_versions SET held = true, held_reason = 'incomplete_chain' WHERE kv_certificate_id = $1 AND version = $2", cert.ID, ver(2))
	require.NoError(t, err)
	d, err = h.svc.KVCertificate(h.ctx, vault, cert.ID)
	require.NoError(t, err)
	assert.True(t, d.CurrentHeld)
	assert.Equal(t, "incomplete_chain", d.CurrentHeldReason)
	assert.True(t, d.Versions[0].Held)

	// Unknown ids, another vault's certificate and servers.
	_, err = h.svc.KVCertificate(h.ctx, vault, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
	other := h.vault("other")
	_, err = h.svc.KVCertificate(h.ctx, other, cert.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.KVCertificate(h.ctx, web.ID, cert.ID)
	require.ErrorIs(t, err, inventory.ErrNotAVault)
}
