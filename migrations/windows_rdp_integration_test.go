//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// rdpDownRefused is the SQLSTATE of 00037's Down while RDP data exists.
const rdpDownRefused = "Z1035"

// rdpLocation is a win_rdp location row of target (W6 Ruling 3: the RDP-Tcp listener, no key path).
func rdpLocation(id, target uuid.UUID) map[string]any {
	return map[string]any{"id": id, "target_id": target, "kind": "win_rdp", "cert_path": "rdp/RDP-Tcp",
		"locator": `{"listener":"RDP-Tcp","port":3389,"type":"rdp"}`, "details": `{"store":"Remote Desktop","self_signed":true}`,
		"supported": true, "first_seen_at": time.Now(), "last_seen_at": time.Now()}
}

// seedRDPWorld is a Windows server (signing in with the platform key) with its win_rdp location.
func seedRDPWorld(t *testing.T, d *pgtest.DB) (w world, win, loc uuid.UUID) {
	t.Helper()
	w, win, loc = seedWorld(t, d), uuid.New(), uuid.New()
	require.NoError(t, exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'iis-01', 'windows', '{"host":"10.0.0.7","port":22}', $2, 'ok', now(), now())`, win, platformCredential(t, d, w)))
	require.NoError(t, insertRow(t, d.App, "certificate_locations", rdpLocation(loc, win)))
	return w, win, loc
}

// 00037 (R69, W6 Ruling 1): the win_rdp location kind and deployment kind.
func TestMigration00037WindowsRDP(t *testing.T) {
	d := pgtest.New(t)
	w, win, loc := seedRDPWorld(t, d)
	require.NoError(t, insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"location_id": loc, "target_id": win,
		"location_kind": "win_rdp", "cert_path": "rdp/RDP-Tcp", "key_path": ""})))
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"location_id": loc,
		"target_id": win, "location_kind": "win_rdp", "cert_path": "rdp/RDP-Tcp", "key_path": `C:\k.key`,
		"state": "done", "status": "failed", "finished_at": time.Now()}))), "an RDP listener has no key path")
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "certificate_locations", with(rdpLocation(uuid.New(), win),
		map[string]any{"kind": "win_rdp_listener", "cert_path": "rdp/RDP-Tcp2"}))), "the kind list stays closed")
}

// 00037's Down refuses while a win_rdp location or deployment exists, each alone (W6-17 of fixes batch 3: the RDP
// deployment's row points at a win_sslbinding location of the same server, which the foreign key allows, so the
// deployment is what remains once the RDP location is gone), and otherwise restores the lists of 00036.
func TestMigration00037Down(t *testing.T) {
	ctx := context.Background()
	d := pgtest.New(t)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	w, win, _ := seedRDPWorld(t, d)
	binding := uuid.New()
	require.NoError(t, insertRow(t, d.App, "certificate_locations", with(rdpLocation(binding, win), map[string]any{"kind": "win_sslbinding",
		"cert_path": "http.sys/ipport/0.0.0.0:443", "locator": `{"ip":"0.0.0.0","port":443,"type":"ipport"}`, "details": `{}`})))
	require.NoError(t, insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"location_id": binding, "target_id": win,
		"location_kind": "win_rdp", "cert_path": "rdp/RDP-Tcp", "key_path": "", "state": "done", "status": "succeeded",
		"finished_at": time.Now()})))

	for _, step := range []struct{ what, cleanup string }{
		{"an RDP location and an RDP deployment exist", "DELETE FROM certificate_locations WHERE kind = 'win_rdp'"},
		{"an RDP deployment alone", "DELETE FROM deployments WHERE location_kind = 'win_rdp'"},
	} {
		_, err = p.DownTo(ctx, 36)
		assert.Equal(t, rdpDownRefused, sqlState(err), "%s: %v", step.what, err)
		require.NoError(t, exec(t, d.Owner, step.cleanup))
	}
	_, err = p.DownTo(ctx, 36)
	require.NoError(t, err)
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "certificate_locations", rdpLocation(uuid.New(), win))), "00036's kinds are back")
	assert.Empty(t, grantProblems(t, d))

	_, err = p.Up(ctx)
	require.NoError(t, err)
	require.NoError(t, insertRow(t, d.App, "certificate_locations", rdpLocation(uuid.New(), win)))
}
