//go:build integration

package migrations_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

const (
	groundworkDownRefused = "Z1031" // the Down of 00031 refuses while the new targets' data exists
	backupLive            = "Z1032" // the held backup of an unfinished deployment is never deleted
	credentialChange      = "Z1005" // the application cannot move a server's credential
	credentialOwner       = "Z1006" // a target's credential is its own (or the platform key)
)

// insertOwnTarget inserts, in one transaction as pool's role, a credential of purpose and kind that belongs to a new target
// of type typ (the credential's target_id is checked at commit) and returns the target's id.
func insertOwnTarget(t *testing.T, pool *pgxpool.Pool, typ, purpose, kind, host string) (uuid.UUID, error) {
	t.Helper()
	ctx := context.Background()
	cred, target := uuid.New(), uuid.New()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, $2, $3, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), $4)`, cred, purpose, kind, target); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, $2, $3, jsonb_build_object('host', $4::text, 'port', 443), $5, 'ok', now(), now())`, target, host, typ, host, cred); err != nil {
		return uuid.Nil, err
	}
	return target, tx.Commit(ctx)
}

// 00031 (R59, G6 and G3): the Windows, BIG-IP and Kubernetes target types; a BIG-IP and a cluster sign in with a
// credential of their own purpose (as a vault), a Windows server with the platform key; the application may move the
// credential of an API target to its replacement but not of a server.
func TestMigration00031TargetTypesAndCredentials(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	platform := platformCredential(t, d, w)

	bigip, err := insertOwnTarget(t, d.App, "f5_bigip", "f5_device", "f5_password", "bigip.example.test")
	require.NoError(t, err)
	_, err = insertOwnTarget(t, d.App, "kubernetes", "kubernetes_cluster", "k8s_token", "k8s-a.example.test")
	require.NoError(t, err)
	_, err = insertOwnTarget(t, d.App, "kubernetes", "kubernetes_cluster", "k8s_client_cert", "k8s-b.example.test")
	require.NoError(t, err)
	require.NoError(t, exec(t, d.App, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'iis-01', 'windows', '{"host":"10.0.0.7","port":22}', $2, 'pending_host_key', now(), now())`, uuid.New(), platform),
		"a Windows server signs in with the platform key")

	for name, c := range map[string]struct{ typ, purpose, kind string }{
		"a BIG-IP with a cluster credential": {"f5_bigip", "kubernetes_cluster", "k8s_token"},
		"a cluster with a BIG-IP credential": {"kubernetes", "f5_device", "f5_password"},
		"a BIG-IP with a vault credential":   {"f5_bigip", "azure_vault", "azure_sp_secret"},
	} {
		_, err := insertOwnTarget(t, d.App, c.typ, c.purpose, c.kind, "x-"+uuid.NewString()[:8]+".example.test")
		assert.Equal(t, credentialOwner, sqlState(err), name)
	}
	for name, c := range map[string]struct{ purpose, kind string }{
		"a password for a cluster": {"kubernetes_cluster", "f5_password"},
		"a token for a BIG-IP":     {"f5_device", "k8s_token"},
		"an unknown kind":          {"f5_device", "f5_api_key"},
	} {
		_, err := insertOwnTarget(t, d.App, "f5_bigip", c.purpose, c.kind, "y-"+uuid.NewString()[:8]+".example.test")
		assert.Equal(t, checkViolation, sqlState(err), name)
	}
	assert.Equal(t, credentialOwner, sqlState(exec(t, d.App, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'bigip-2', 'f5_bigip', '{"host":"10.0.0.8","port":443}', $2, 'ok', now(), now())`, uuid.New(), platform)),
		"a BIG-IP never signs in with the platform key")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'f5_device', 'f5_password', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, uuid.New())),
		"a BIG-IP credential belongs to its target")

	// A replacement: a new credential row of the BIG-IP that the target moves to.
	next := uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, 'f5_device', 'f5_password', '\x03', decode(repeat('01', 12), 'hex'), '\x04', 1, now(), $2)`, next, bigip))
	require.NoError(t, exec(t, d.App, "UPDATE targets SET credential_id = $2 WHERE id = $1", bigip, next), "an API target's credential moves")
	assert.Equal(t, credentialChange, sqlState(exec(t, d.App, "UPDATE targets SET credential_id = credential_id WHERE type = 'windows'")),
		"a Windows server's credential never moves")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'mainframe', 'zos', '{"host":"10.0.0.9","port":22}', $2, 'ok', now(), now())`, uuid.New(), platform)))
}

// 00031 (R59, G1, G4): a location of a new kind is a locator (unique per target and kind) with its canonical text in
// cert_path and no key path or Unix key facts; a certificate file keeps no locator, no details and no probe address. The
// application updates the details and the probe address, never the locator.
func TestMigration00031LocationKinds(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	cluster, err := insertOwnTarget(t, d.App, "kubernetes", "kubernetes_cluster", "k8s_token", "k8s.example.test")
	require.NoError(t, err)
	row := func(over map[string]any) map[string]any {
		return with(map[string]any{"id": uuid.New(), "target_id": cluster, "kind": "k8s_tls_secret", "cert_path": "shop/shop-tls",
			"locator": `{"namespace":"shop","name":"shop-tls"}`, "details": `{"resource_version":"12"}`, "supported": true,
			"first_seen_at": time.Now(), "last_seen_at": time.Now()}, over)
	}
	secret := uuid.New()
	require.NoError(t, insertRow(t, d.App, "certificate_locations", row(map[string]any{"id": secret, "verify_address": "10.20.0.5"})))
	require.NoError(t, insertRow(t, d.App, "certificate_locations", row(map[string]any{"kind": "f5_clientssl", "cert_path": "/Common/www_clientssl#default",
		"locator": `{"partition":"Common","profile":"/Common/www_clientssl","entry":"default"}`})), "another kind, another identity")
	require.NoError(t, insertRow(t, d.App, "certificate_locations", row(map[string]any{"kind": "win_sslbinding",
		"cert_path": "http.sys/hostnameport/www.example.com:443", "verify_address": "2001:db8::7",
		"locator": `{"type":"hostnameport","host":"www.example.com","port":443,"app_id":"{4dc3e181-e14b-4a21-b022-59fc669b0914}"}`})))

	assert.Equal(t, uniqueViolation, sqlState(insertRow(t, d.App, "certificate_locations", row(map[string]any{"cert_path": "shop/other"}))),
		"one location per locator")
	assert.Equal(t, uniqueViolation, sqlState(insertRow(t, d.App, "certificate_locations",
		row(map[string]any{"locator": `{"namespace":"shop","name":"other"}`}))), "one location per canonical text")
	for name, over := range map[string]map[string]any{
		"no locator":            {"locator": omit},
		"an array locator":      {"locator": `["shop","shop-tls"]`},
		"a large locator":       {"locator": `{"name":"` + strings.Repeat("a", 1100) + `"}`},
		"a key path":            {"key_path": "/etc/ssl/k.key"},
		"a key owner":           {"key_owner": "root"},
		"a key mode":            {"key_mode": "0600"},
		"a resolved path":       {"resolved_cert_path": "/etc/ssl/x.crt"},
		"symlinked":             {"symlinked": true},
		"a string details":      {"details": `"x"`},
		"an unknown kind":       {"kind": "ssh_file"},
		"a bad probe address":   {"verify_address": "10.0.0.5%2"},
		"a probe address space": {"verify_address": "lb internal"},
	} {
		fresh := row(map[string]any{"cert_path": "x/" + uuid.NewString(), "locator": `{"name":"` + uuid.NewString() + `"}`})
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "certificate_locations", with(fresh, over))), name)
	}
	for name, over := range map[string]map[string]any{
		"a file with a locator":       {"locator": `{"path":"/etc/ssl/a.crt"}`},
		"a file with details":         {"details": `{"x":1}`},
		"a file with a probe address": {"verify_address": "10.0.0.5"},
	} {
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "certificate_locations", with(locationRow(w, "/etc/ssl/"+uuid.NewString()+".crt"), over))), name)
	}
	require.NoError(t, insertRow(t, d.App, "certificate_locations", locationRow(w, "/etc/ssl/plain.crt")), "a certificate file inserts as before")

	require.NoError(t, exec(t, d.App, `UPDATE certificate_locations SET details = '{"resource_version":"13"}', verify_address = NULL WHERE id = $1`, secret))
	assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, `UPDATE certificate_locations SET locator = '{"namespace":"shop","name":"x"}' WHERE id = $1`, secret)),
		"the locator is the location's identity")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE certificate_locations SET verify_address = '10.0.0.5' WHERE id = $1", w.loc)),
		"a certificate file takes no probe address in this phase")
}

// 00031 (R59, G1, G5): a deployment records its location's kind (a file's paths keep 00006's rule; another kind records its
// canonical text and no key path); a held backup is written once, read, and deleted only once its deployment is final.
func TestMigration00031DeploymentsAndBackups(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	cluster, err := insertOwnTarget(t, d.App, "kubernetes", "kubernetes_cluster", "k8s_token", "k8s.example.test")
	require.NoError(t, err)
	secret := uuid.New()
	require.NoError(t, insertRow(t, d.App, "certificate_locations", map[string]any{"id": secret, "target_id": cluster, "kind": "k8s_tls_secret",
		"cert_path": "shop/shop-tls", "locator": `{"namespace":"shop","name":"shop-tls"}`, "supported": true, "first_seen_at": time.Now(),
		"last_seen_at": time.Now()}))
	k8s := with(deploymentRow(w), map[string]any{"location_id": secret, "target_id": cluster, "location_kind": "k8s_tls_secret",
		"cert_path": "shop/shop-tls", "key_path": ""})
	require.NoError(t, insertRow(t, d.App, "deployments", k8s))
	require.NoError(t, insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"state": "done", "status": "succeeded",
		"finished_at": time.Now()})), "a file deployment inserts as before (location_kind defaults to server_file)")
	for name, over := range map[string]map[string]any{
		"a file without a key path":         {"key_path": ""},
		"a file with a relative path":       {"cert_path": "etc/www.crt"},
		"a secret with a key path":          {"location_kind": "k8s_tls_secret", "cert_path": "shop/x", "key_path": "/x.key"},
		"a secret without its text":         {"location_kind": "k8s_tls_secret", "cert_path": "", "key_path": ""},
		"an unknown kind":                   {"location_kind": "ssh_file"},
		"a binding text over 1024":          {"location_kind": "win_sslbinding", "cert_path": strings.Repeat("a", 1025), "key_path": ""},
	} {
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployments", with(deploymentRow(w), with(map[string]any{"state": "done",
			"status": "failed", "finished_at": time.Now()}, over)))), name)
	}

	backup := func(dep any, over map[string]any) error {
		return insertRow(t, d.App, "deployment_backups", with(map[string]any{"deployment_id": dep, "location_id": secret, "leaf_sha256": hex64("a"),
			"spki_sha256": hex64("b"), "ciphertext": []byte{1}, "nonce": make([]byte, 12), "wrapped_dek": []byte{2}, "key_version": 1,
			"created_at": time.Now()}, over))
	}
	for name, over := range map[string]map[string]any{
		"a short nonce":   {"nonce": make([]byte, 11)},
		"a bad leaf hash": {"leaf_sha256": "abc"},
		"no key version":  {"key_version": 0},
		"a huge payload":  {"ciphertext": make([]byte, 262145)},
	} {
		assert.Equal(t, checkViolation, sqlState(backup(k8s["id"], over)), name)
	}
	require.NoError(t, backup(k8s["id"], nil))
	assert.Equal(t, uniqueViolation, sqlState(backup(k8s["id"], nil)), "one backup per deployment")
	assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, "UPDATE deployment_backups SET key_version = 2")), "a backup is never rewritten")
	assert.Equal(t, backupLive, sqlState(exec(t, d.App, "DELETE FROM deployment_backups WHERE deployment_id = $1", k8s["id"])),
		"a rollback may still need it")
	require.NoError(t, exec(t, d.App, "UPDATE deployments SET state = 'done', status = 'succeeded', finished_at = now() WHERE id = $1", k8s["id"]))
	require.NoError(t, exec(t, d.App, "DELETE FROM deployment_backups WHERE deployment_id = $1", k8s["id"]), "a final deployment's backup goes")
}

// 00031's Down refuses while a target of a new type (with its credential), a location of a new kind or a held backup
// exists, and otherwise restores the schema before it (a gap at 00030 is another branch's).
func TestMigration00031Down(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	before := pgtest.PreviousVersion(t)
	w := seedWorld(t, d)
	cluster, err := insertOwnTarget(t, d.App, "kubernetes", "kubernetes_cluster", "k8s_token", "k8s.example.test")
	require.NoError(t, err)

	_, err = p.DownTo(ctx, before)
	assert.Equal(t, groundworkDownRefused, sqlState(err), "a cluster exists")
	assert.True(t, hasColumn(t, d, "certificate_locations", "locator"), "nothing changed")
	require.NoError(t, exec(t, d.Owner, "UPDATE targets SET deleted_at = now() WHERE id = $1", cluster))
	_, err = p.DownTo(ctx, before)
	assert.Equal(t, groundworkDownRefused, sqlState(err), "a deleted cluster counts too: targets are never hard-deleted")
	// The owner removes the cluster and its credential in one transaction (the credential's target is checked at commit).
	require.NoError(t, exec(t, d.Owner, fmt.Sprintf("DELETE FROM targets WHERE id = '%s'; DELETE FROM credentials WHERE target_id = '%s'", cluster, cluster)))

	odd := uuid.New()
	require.NoError(t, insertRow(t, d.Owner, "certificate_locations", map[string]any{"id": odd, "target_id": w.target, "kind": "win_sslbinding",
		"cert_path": "http.sys/ipport/0.0.0.0:443", "locator": `{"type":"ipport","ip":"0.0.0.0","port":443}`, "supported": false,
		"unsupported_reason": "unknown", "first_seen_at": time.Now(), "last_seen_at": time.Now()}))
	_, err = p.DownTo(ctx, before)
	assert.Equal(t, groundworkDownRefused, sqlState(err), "a location of a new kind exists")
	require.NoError(t, exec(t, d.Owner, "DELETE FROM certificate_locations WHERE id = $1", odd))

	_, err = p.DownTo(ctx, before)
	require.NoError(t, err)
	assert.False(t, hasColumn(t, d, "certificate_locations", "locator"))
	assert.False(t, hasColumn(t, d, "deployments", "location_kind"))
	assert.False(t, tableExists(t, d, "deployment_backups"))
	assert.Empty(t, grantProblems(t, d))
	require.NoError(t, insertRow(t, d.App, "deployments", deploymentRow(w)), "00006's path rule is back")
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"key_path": "",
		"state": "done", "status": "failed", "finished_at": time.Now()}))))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'iis-01', 'windows', '{"host":"10.0.0.7","port":22}', $2, 'ok', now(), now())`, uuid.New(), platformCredential(t, d, w))))

	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.Empty(t, grantProblems(t, d))
	_, err = insertOwnTarget(t, d.App, "f5_bigip", "f5_device", "f5_password", "bigip.example.test")
	require.NoError(t, err)
}

// platformCredential returns the platform credential of w's server.
func platformCredential(t *testing.T, d *pgtest.DB, w world) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT credential_id FROM targets WHERE id = $1", w.target).Scan(&id))
	return id
}
