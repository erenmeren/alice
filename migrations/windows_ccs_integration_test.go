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

// ccsDownRefused is the SQLSTATE of 00036's Down while CCS data exists.
const ccsDownRefused = "Z1034"

// ccsWorld is a Windows server (signing in with the platform key) with a win_ccs_file location.
type ccsWorld struct {
	world
	win, file uuid.UUID
}

func seedCCSWorld(t *testing.T, d *pgtest.DB) ccsWorld {
	t.Helper()
	w := ccsWorld{world: seedWorld(t, d), win: uuid.New(), file: uuid.New()}
	require.NoError(t, exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'iis-01', 'windows', '{"host":"10.0.0.7","port":22}', $2, 'ok', now(), now())`, w.win, platformCredential(t, d, w.world)))
	require.NoError(t, insertRow(t, d.App, "certificate_locations", map[string]any{"id": w.file, "target_id": w.win, "kind": "win_ccs_file",
		"cert_path": `C:\CCS\www.example.com.pfx`, "locator": `{"type":"ccs_file","path":"C:\\CCS","host":"www.example.com"}`,
		"details": `{"ccs_path":"C:\\CCS","file_name":"www.example.com.pfx"}`, "supported": true, "first_seen_at": time.Now(),
		"last_seen_at": time.Now()}))
	return w
}

// ccsCredential inserts a credential of purpose and kind for target (nil: none) as pool's role.
func ccsCredential(t *testing.T, d *pgtest.DB, purpose, kind string, target any) error {
	t.Helper()
	return exec(t, d.App, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, $2, $3, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), $4)`, uuid.New(), purpose, kind, target)
}

// 00036 (R68, W5 Ruling 1): the win_ccs_file location kind and deployment kind, and the CCS password of a Windows server
// (purpose win_ccs, kind win_ccs_password, bound to its target).
func TestMigration00036WindowsCCS(t *testing.T) {
	d := pgtest.New(t)
	w := seedCCSWorld(t, d)
	require.NoError(t, insertRow(t, d.App, "deployments", with(deploymentRow(w.world), map[string]any{"location_id": w.file, "target_id": w.win,
		"location_kind": "win_ccs_file", "cert_path": `C:\CCS\www.example.com.pfx`, "key_path": ""})))
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployments", with(deploymentRow(w.world), map[string]any{"location_id": w.file,
		"target_id": w.win, "location_kind": "win_ccs_file", "cert_path": `C:\CCS\www.example.com.pfx`, "key_path": `C:\CCS\k.key`,
		"state": "done", "status": "failed", "finished_at": time.Now()}))), "a CCS file has no key path")

	require.NoError(t, ccsCredential(t, d, "win_ccs", "win_ccs_password", w.win))
	require.NoError(t, ccsCredential(t, d, "win_ccs", "win_ccs_password", w.win), "rows are append-only: a replacement is a new row")
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "win_ccs", "win_ccs_password", nil)), "the password belongs to its server")
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "f5_device", "win_ccs_password", w.win)), "the kind goes with its purpose")
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "win_ccs", "f5_password", w.win)), "the purpose takes its kind only")
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "certificate_locations", map[string]any{"id": uuid.New(), "target_id": w.win,
		"kind": "win_ccs_files", "cert_path": `C:\CCS\x.pfx`, "locator": `{"type":"ccs_file","host":"x"}`, "supported": true,
		"first_seen_at": time.Now(), "last_seen_at": time.Now()})), "the kind list stays closed")
}

// 00036's Down refuses while a win_ccs_file location, deployment or win_ccs credential exists, and otherwise restores the
// lists of 00035.
func TestMigration00036Down(t *testing.T) {
	ctx := context.Background()
	d := pgtest.New(t)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	w := seedCCSWorld(t, d)
	dep := with(deploymentRow(w.world), map[string]any{"location_id": w.file, "target_id": w.win, "location_kind": "win_ccs_file",
		"cert_path": `C:\CCS\www.example.com.pfx`, "key_path": "", "state": "done", "status": "succeeded", "finished_at": time.Now()})
	require.NoError(t, insertRow(t, d.App, "deployments", dep))
	require.NoError(t, ccsCredential(t, d, "win_ccs", "win_ccs_password", w.win))

	for _, step := range []struct{ what, cleanup string }{
		{"a CCS password exists", "DELETE FROM credentials WHERE purpose = 'win_ccs'"},
		{"a CCS deployment exists", "DELETE FROM deployments WHERE location_kind = 'win_ccs_file'"},
		{"a CCS location exists", "DELETE FROM certificate_locations WHERE kind = 'win_ccs_file'"},
	} {
		_, err = p.DownTo(ctx, 35)
		assert.Equal(t, ccsDownRefused, sqlState(err), "%s: %v", step.what, err)
		require.NoError(t, exec(t, d.Owner, step.cleanup))
	}
	_, err = p.DownTo(ctx, 35)
	require.NoError(t, err)
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "win_ccs", "win_ccs_password", w.win)), "00035's purposes are back")
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "certificate_locations", map[string]any{"id": uuid.New(), "target_id": w.win,
		"kind": "win_ccs_file", "cert_path": `C:\CCS\x.pfx`, "locator": `{"type":"ccs_file","host":"x"}`, "supported": true,
		"first_seen_at": time.Now(), "last_seen_at": time.Now()})), "00035's kinds are back")
	assert.Empty(t, grantProblems(t, d))

	_, err = p.Up(ctx)
	require.NoError(t, err)
	require.NoError(t, ccsCredential(t, d, "win_ccs", "win_ccs_password", w.win))
}
