//go:build integration

package main

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) {
	os.Exit(pgtest.Main(m))
}

var setupCodeRE = regexp.MustCompile(`One-time setup code: [0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{6}\n`)

// cliEnv points the CLI at the test database as the application role.
func cliEnv(t *testing.T, d *pgtest.DB) func(string) string {
	t.Helper()
	return env(map[string]string{"ALICE_DATABASE_URL": d.AppURL, "ALICE_KEYS_DIR": t.TempDir()})
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
