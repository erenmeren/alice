//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/config"
	"alice/internal/platform/logging"
	"alice/internal/testutil/pgtest"
)

// Secret-leak tests for the database passwords (spec §25.2 S-01): the owner
// (migration) and application URLs carry canary passwords through startup,
// failed startup and the operator CLI at DEBUG level. The HTTP surface is
// covered by internal/api's leak suite.

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// dbPasswordCanaries creates an owner (superuser) and an application role
// (member of alice_app) whose passwords are unique canaries, and returns URLs
// for the test database with those credentials.
func dbPasswordCanaries(t *testing.T, d *pgtest.DB) (ownerURL, appURL, ownerPW, appPW string) {
	t.Helper()
	ctx := context.Background()
	suffix := rand.Text()[:10] // quoted with %I below, so the upper-case letters are kept
	ownerPW, appPW = "CANARY-"+rand.Text()+"-db-owner", "CANARY-"+rand.Text()+"-db-app"
	for _, role := range []struct{ name, options, password string }{
		{"leak_owner_" + suffix, "LOGIN SUPERUSER", ownerPW},
		{"leak_app_" + suffix, "LOGIN IN ROLE alice_app", appPW},
	} {
		// DDL takes no bind parameters; PostgreSQL's format() quotes both values.
		var ddl string
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT format('CREATE ROLE %I '||$2||' PASSWORD %L', $1::text, $3::text)`,
			role.name, role.options, role.password).Scan(&ddl))
		_, err := d.Owner.Exec(ctx, ddl)
		require.NoError(t, err)
		// Roles are cluster-wide: drop them (and their grants in this database) when the test ends.
		t.Cleanup(func() {
			var drop string
			require.NoError(t, d.Owner.QueryRow(ctx, `SELECT format('DROP OWNED BY %1$I; DROP ROLE %1$I', $1::text)`, role.name).Scan(&drop))
			_, err := d.Owner.Exec(ctx, drop)
			require.NoError(t, err)
		})
	}
	withUser := func(raw, user, pw string) string {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		u.User = url.UserPassword(user, pw)
		return u.String()
	}
	return withUser(d.OwnerURL, "leak_owner_"+suffix, ownerPW), withUser(d.AppURL, "leak_app_"+suffix, appPW), ownerPW, appPW
}

func assertNoDBPassword(t *testing.T, where, text string, passwords ...string) {
	t.Helper()
	for _, pw := range passwords {
		for _, form := range []string{pw, url.QueryEscape(pw), hex.EncodeToString([]byte(pw))} {
			if strings.Contains(text, form) {
				t.Errorf("a password canary leaked in %s", where)
			}
		}
	}
}

// A full start (migrations on the owner URL, the app pool, services, the SMTP mailer, the
// license service and the scheduler, TLS) and shutdown at DEBUG level log neither database
// password nor the SMTP password.
func TestServeLogsNoDatabasePassword(t *testing.T) {
	d := pgtest.New(t)
	ownerURL, appURL, ownerPW, appPW := dbPasswordCanaries(t, d)
	smtpPW := "CANARY-" + rand.Text() + "-smtp"
	pwFile := filepath.Join(t.TempDir(), "smtp_password")
	require.NoError(t, os.WriteFile(pwFile, []byte(smtpPW+"\n"), 0o600))
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL":         appURL,
		"ALICE_MIGRATE_DATABASE_URL": ownerURL,
		"ALICE_LISTEN_ADDR":          "127.0.0.1:0",
		"ALICE_HEALTH_ADDR":          "127.0.0.1:0",
		"ALICE_KEYS_DIR":             t.TempDir(),
		"ALICE_STATE_DIR":            t.TempDir(),
		"ALICE_LOG_LEVEL":            "debug",
		"ALICE_SMTP_HOST":            "mail.example.invalid",
		"ALICE_SMTP_FROM":            "alice@example.com",
		"ALICE_SMTP_USERNAME":        "alice",
		"ALICE_SMTP_PASSWORD_FILE":   pwFile,
	}))
	require.NoError(t, err)
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, logging.New(logs, slog.LevelDebug)) }()

	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "alice is ready") },
		30*time.Second, 20*time.Millisecond, "serve did not start: %s", logs.String())
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop")
	}
	assert.Contains(t, logs.String(), "starting alice", "the configuration (with both URLs) was logged")
	assert.Contains(t, logs.String(), "mail.example.invalid", "the SMTP configuration was logged")
	assertNoDBPassword(t, "serve logs", logs.String(), ownerPW, appPW, smtpPW)

	// ALICE_SMTP_* were imported once into the mail settings at the start (Phase 7, S-12): the password only as an
	// envelope, the audit row without it.
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM settings WHERE key = 'notify.smtp'"))
	assert.Equal(t, 1, countRows(t, d, "SELECT count(*) FROM audit_log WHERE action = 'settings.smtp_imported'"))
	var sealed, audit string
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT encode(ciphertext, 'escape') FROM setting_secrets
WHERE key = 'notify.smtp.password'`).Scan(&sealed))
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT string_agg(details::text, ' ') FROM audit_log`).Scan(&audit))
	assertNoDBPassword(t, "the stored mail settings", sealed+" "+audit, smtpPW)
}

// The start stops with the error when ALICE_SMTP_PASSWORD_FILE cannot be read, as the Phase 2 mailer did: the import
// runs before anything listens, and the error names the file, not a secret.
func TestServeStopsWhenTheSMTPPasswordFileIsUnreadable(t *testing.T) {
	d := pgtest.New(t)
	missing := filepath.Join(t.TempDir(), "missing")
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL": d.AppURL, "ALICE_MIGRATE_DATABASE_URL": d.OwnerURL,
		"ALICE_LISTEN_ADDR": "127.0.0.1:0", "ALICE_HEALTH_ADDR": "127.0.0.1:0",
		"ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": t.TempDir(),
		"ALICE_SMTP_HOST": "mail.example.invalid", "ALICE_SMTP_FROM": "alice@example.com",
		"ALICE_SMTP_USERNAME": "alice", "ALICE_SMTP_PASSWORD_FILE": missing,
	}))
	require.NoError(t, err)
	logs := &lockedBuffer{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err = serve(ctx, cfg, logging.New(logs, slog.LevelInfo))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SMTP password file")
	assert.NotContains(t, logs.String(), "alice is ready")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM settings WHERE key = 'notify.smtp'"))
}

// Rejected passwords fail startup, migration and every CLI command with an
// error that names neither password.
func TestFailedStartupAndCLINameNoDatabasePassword(t *testing.T) {
	d := pgtest.New(t)
	ownerURL, appURL, ownerPW, appPW := dbPasswordCanaries(t, d)
	wrongOwner := strings.Replace(ownerURL, url.QueryEscape(ownerPW), "CANARY-"+rand.Text()+"-db-wrong-owner", 1)
	wrongApp := strings.Replace(appURL, url.QueryEscape(appPW), "CANARY-"+rand.Text()+"-db-wrong-app", 1)
	require.NotEqual(t, ownerURL, wrongOwner)
	require.NotEqual(t, appURL, wrongApp)
	wrongOwnerPW, _ := mustURL(t, wrongOwner).User.Password()
	wrongAppPW, _ := mustURL(t, wrongApp).User.Password()

	// serve and migrate connect with the owner URL; serve and the operator
	// commands with the application URL. Each command fails when a URL it
	// uses has the wrong password, and its output never names a password.
	commands := [][]string{
		{"serve"}, {"migrate"}, {"setup-token", "--reset"}, {"audit", "verify"}, {"admin", "reset-mfa", "nobody"},
		{"license", "status"},
	}
	for _, tc := range []struct {
		name, owner, app string
		fails            map[string]bool
	}{
		{"wrong owner password", wrongOwner, appURL, map[string]bool{"serve": true, "migrate": true}},
		{"wrong app password", ownerURL, wrongApp, map[string]bool{"serve": true, "setup-token": true, "audit": true, "admin": true, "license": true}},
	} {
		for _, args := range commands {
			t.Run(tc.name+"/"+strings.Join(args, " "), func(t *testing.T) {
				getenv := env(map[string]string{
					"ALICE_DATABASE_URL":         tc.app,
					"ALICE_MIGRATE_DATABASE_URL": tc.owner,
					"ALICE_LISTEN_ADDR":          "127.0.0.1:0",
					"ALICE_HEALTH_ADDR":          "127.0.0.1:0",
					"ALICE_KEYS_DIR":             t.TempDir(),
					"ALICE_STATE_DIR":            t.TempDir(),
					"ALICE_LOG_LEVEL":            "debug",
				})
				code, out, errOut := runCLI(t, getenv, args...)
				if tc.fails[args[0]] {
					require.NotEqual(t, 0, code, "stdout: %s", out)
					require.Contains(t, errOut, "rejected the user name or password", "the failure is the rejected password")
				}
				assertNoDBPassword(t, "output", out+errOut, ownerPW, appPW, wrongOwnerPW, wrongAppPW)
			})
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}
