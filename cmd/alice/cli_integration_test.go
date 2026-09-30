//go:build integration

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/logging"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) {
	os.Exit(pgtest.Main(m))
}

var setupCodeRE = regexp.MustCompile(`One-time setup code: [0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{6}\n`)

// cliEnv points the CLI at the test database as the application role.
func cliEnv(t *testing.T, d *pgtest.DB) func(string) string {
	t.Helper()
	return env(map[string]string{"ALICE_DATABASE_URL": d.AppURL, "ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": t.TempDir()})
}

func runCLI(t *testing.T, getenv func(string) string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, getenv, &out, &errOut)
	return code, out.String(), errOut.String()
}

func insertUser(t *testing.T, d *pgtest.DB, username, role string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := d.Owner.Exec(context.Background(),
		`INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
		 VALUES ($1, $2, $3, '$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA', $4, now(), now())`, id, username, username, role)
	require.NoError(t, err)
	return id
}

func TestSetupTokenResetCLI(t *testing.T) {
	d := pgtest.New(t)
	getenv := cliEnv(t, d)

	code, out, errOut := runCLI(t, getenv, "setup-token", "--reset")
	require.Equal(t, 0, code, errOut)
	assert.Regexp(t, setupCodeRE, out)

	code, out2, _ := runCLI(t, getenv, "setup-token", "--reset")
	require.Equal(t, 0, code)
	assert.NotEqual(t, out, out2, "every reset issues a new code")

	insertUser(t, d, "admin", "admin")
	code, _, errOut = runCLI(t, getenv, "setup-token", "--reset")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "administrator already exists")
}

func TestAuditVerifyCLI(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	getenv := cliEnv(t, d)

	svc := audit.NewService(audit.New(clock.Real{}), d.App)
	for _, action := range []string{"test.first", "test.second"} {
		require.NoError(t, svc.Write(ctx, audit.Event{Actor: audit.SystemActor("test"), Action: action, Result: audit.Success}))
	}

	code, out, errOut := runCLI(t, getenv, "audit", "verify")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "The audit log is intact")

	// Tamper as the owner role: the append-only trigger has to be switched off first.
	for _, stmt := range []string{
		`ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete`,
		`UPDATE audit_log SET action = 'test.forged' WHERE seq = 1`,
		`ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete`,
	} {
		_, err := d.Owner.Exec(ctx, stmt)
		require.NoError(t, err)
	}
	code, out, _ = runCLI(t, getenv, "audit", "verify")
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "integrity problem at entry 1")
}

func TestAdminResetMFACLI(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	getenv := cliEnv(t, d)

	id := insertUser(t, d, "bob", "operator")
	_, err := d.Owner.Exec(ctx,
		`INSERT INTO user_mfa (user_id, totp_secret_ct, totp_nonce, totp_wrapped_dek, totp_key_version, enrolled_at, created_at)
		 VALUES ($1, '\x01', '\x02', '\x03', 1, now(), now())`, id)
	require.NoError(t, err)

	code, out, errOut := runCLI(t, getenv, "admin", "reset-mfa", "BOB")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "was removed")

	var left int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM user_mfa WHERE user_id = $1`, id).Scan(&left))
	assert.Equal(t, 0, left)
	var audited int
	require.NoError(t, d.Owner.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'user.mfa_reset' AND actor_type = 'system' AND actor_name = 'cli'`).Scan(&audited))
	assert.Equal(t, 1, audited)

	code, _, errOut = runCLI(t, getenv, "admin", "reset-mfa", "nobody")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, `no user named "nobody"`)
}

func TestAdminUnlockCLI(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	getenv := cliEnv(t, d)

	id := insertUser(t, d, "bob", "admin")
	_, err := d.Owner.Exec(ctx, `UPDATE users SET failed_logins = 10, locked_until = now() + interval '15 minutes' WHERE id = $1`, id)
	require.NoError(t, err)

	code, out, errOut := runCLI(t, getenv, "admin", "unlock", "BOB")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "was unlocked")

	var failed int
	var locked bool
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT failed_logins, locked_until IS NOT NULL FROM users WHERE id = $1`, id).Scan(&failed, &locked))
	assert.Equal(t, 0, failed)
	assert.False(t, locked)
	var audited int
	require.NoError(t, d.Owner.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'user.unlocked' AND actor_type = 'system' AND actor_name = 'cli' AND object_id = $1`,
		id.String()).Scan(&audited))
	assert.Equal(t, 1, audited)

	code, _, errOut = runCLI(t, getenv, "admin", "unlock", "nobody")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, `no user named "nobody"`)
}

func TestLicenseStatusCLI(t *testing.T) {
	d := pgtest.New(t)
	getenv := cliEnv(t, d)
	code, _, errOut := runCLI(t, getenv, "license", "status")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "has not been started on this database yet")

	id := license.NewInstallationID()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO license (id, installation_id, installed_at, state, updated_at)
VALUES (1, $1, now(), 'evaluation', now())`, id)
	require.NoError(t, err)
	code, out, errOut := runCLI(t, getenv, "license", "status")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "Installation ID: "+id)
	assert.Contains(t, out, "State: evaluation")
	assert.Contains(t, out, "at most 5 targets")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM settings WHERE key = 'time.hwm'"), "status changes nothing")
}

func countRows(t *testing.T, d *pgtest.DB, sql string) int {
	t.Helper()
	var n int
	require.NoError(t, d.Owner.QueryRow(context.Background(), sql).Scan(&n))
	return n
}

// serve creates the installation and the time record (settings and the state volume) before
// it listens, and saves the time record again at a graceful shutdown (spec §16.5).
func TestServeStartsLicenseAndSavesTimeRecordAtShutdown(t *testing.T) {
	d := pgtest.New(t)
	stateDir := t.TempDir()
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL":         d.AppURL,
		"ALICE_MIGRATE_DATABASE_URL": d.OwnerURL,
		"ALICE_LISTEN_ADDR":          "127.0.0.1:0",
		"ALICE_HEALTH_ADDR":          "127.0.0.1:0",
		"ALICE_KEYS_DIR":             t.TempDir(),
		"ALICE_STATE_DIR":            stateDir,
	}))
	require.NoError(t, err)
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, logging.New(logs, slog.LevelInfo)) }()
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "alice is ready") },
		30*time.Second, 20*time.Millisecond, "serve did not start: %s", logs.String())

	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM license"), "the installation exists before any request")
	hwmPath := filepath.Join(stateDir, license.HWMFileName)
	fileAtStart, err := os.ReadFile(hwmPath)
	require.NoError(t, err, "the time record is on the state volume")
	settingAtStart := hwmSetting(t, d)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop")
	}
	fileAtStop, err := os.ReadFile(hwmPath)
	require.NoError(t, err)
	assert.NotEqual(t, fileAtStart, fileAtStop, "the file copy was saved again at shutdown")
	assert.NotEqual(t, settingAtStart, hwmSetting(t, d), "the settings copy was saved again at shutdown")
	assert.NotContains(t, logs.String(), "could not save the license time record")
}

func hwmSetting(t *testing.T, d *pgtest.DB) string {
	t.Helper()
	var v string
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT value::text FROM settings WHERE key = $1", license.HWMSettingKey).Scan(&v))
	return v
}
