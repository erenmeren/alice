//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/backup"
	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
	"alice/internal/version"
	"alice/locales"
	"alice/migrations"
)

// cliPassphrase is the recovery passphrase of the CLI test installations.
const cliPassphrase = "kırmızı kedi mavi deniz 2026 CLI"

// testKDF keeps the test's backup key cheap (C7's lower bounds).
var testKDF = secrets.KDFParams{MemoryKiB: 8192, Time: 1, Threads: 1}

// cliInstall is an installation the CLI commands work on: a database with its installation row, a master key, a
// recovery passphrase (backup.key v2 and backup.sender) and its own keys, state and backups directories.
type cliInstall struct {
	t                    *testing.T
	ctx                  context.Context
	d                    *pgtest.DB
	keys, state, backups string
	vars                 map[string]string
	installationID       string
}

func newCLIInstall(t *testing.T) *cliInstall {
	t.Helper()
	i := &cliInstall{t: t, ctx: context.Background(), d: pgtest.New(t), keys: t.TempDir(), state: t.TempDir(), backups: t.TempDir()}
	i.vars = map[string]string{"ALICE_DATABASE_URL": i.d.AppURL, "ALICE_MIGRATE_DATABASE_URL": i.d.OwnerURL,
		"ALICE_KEYS_DIR": i.keys, "ALICE_STATE_DIR": i.state, "ALICE_BACKUP_DIR": i.backups}
	svc := i.services()
	require.NoError(t, svc.license.Start(i.ctx))
	for _, action := range []string{"test.first", "test.second", "test.third"} {
		require.NoError(t, svc.audit.Write(i.ctx, audit.Event{Actor: audit.SystemActor("test"), Action: action, Result: audit.Success}))
	}
	require.NoError(t, svc.license.Shutdown(i.ctx))
	svc.license.Close()
	require.NoError(t, i.d.Owner.QueryRow(i.ctx, "SELECT installation_id FROM license WHERE id = 1").Scan(&i.installationID))
	wrapped, sender, err := secrets.NewBackupKey([]byte(cliPassphrase), testKDF)
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, settings.Set(i.ctx, i.d.App, "backup.key", wrapped, now))
	require.NoError(t, svc.keyring.PutSetting(i.ctx, i.d.App, "backup.sender", secrets.NewPlaintext(sender.Bytes()), now))
	return i
}

func (i *cliInstall) config() config.Config {
	i.t.Helper()
	cfg, err := config.Load(env(i.vars))
	require.NoError(i.t, err)
	return cfg
}

// services wires the services on the installation's app pool (the master key is created on the first call).
func (i *cliInstall) services() *services {
	i.t.Helper()
	catalog, err := i18n.Load(locales.FS)
	require.NoError(i.t, err)
	svc, err := buildServices(i.ctx, i.d.App, i.config(), catalog, clock.Real{}, slog.New(slog.DiscardHandler))
	require.NoError(i.t, err)
	i.t.Cleanup(svc.sshPool.Close)
	return svc
}

// run runs the CLI with the installation's environment and stdin.
func (i *cliInstall) run(stdin string, args ...string) (int, string, string) {
	i.t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, env(i.vars), strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

var backupWrittenRE = regexp.MustCompile(`^Backup written: (/\S+/alice-backup-[0-9A-Z]{8}-[0-9]{8}T[0-9]{6}Z-manual\.alicebak) \([0-9]+\.[0-9] MiB\)\n$`)

// backup makes a manual backup through the CLI and returns its path.
func (i *cliInstall) backup() string {
	i.t.Helper()
	code, out, errOut := i.run("", "backup")
	require.Equal(i.t, 0, code, errOut)
	m := backupWrittenRE.FindStringSubmatch(out)
	require.NotNil(i.t, m, out)
	return m[1]
}

// stop closes the test's pools, as stopping Alice does; reopen opens new ones (the database may have been swapped).
func (i *cliInstall) stop() {
	i.d.Owner.Close()
	i.d.App.Close()
}

func (i *cliInstall) reopen() {
	i.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var err error
	i.d.Owner, err = db.Open(ctx, i.d.OwnerURL)
	require.NoError(i.t, err)
	i.t.Cleanup(i.d.Owner.Close)
	i.d.App, err = db.Open(ctx, i.d.AppURL)
	require.NoError(i.t, err)
	i.t.Cleanup(i.d.App.Close)
}

func (i *cliInstall) count(sql string, args ...any) int {
	i.t.Helper()
	var n int
	require.NoError(i.t, i.d.Owner.QueryRow(i.ctx, sql, args...).Scan(&n))
	return n
}

func TestCLIBackupListVerify(t *testing.T) {
	i := newCLIInstall(t)
	path := i.backup()
	assert.Equal(t, i.backups, filepath.Dir(path))
	assert.True(t, strings.Contains(filepath.Base(path), strings.ReplaceAll(strings.TrimPrefix(i.installationID, "ALICE-"), "-", "")[:8]))
	assert.Equal(t, 1, i.count("SELECT count(*) FROM audit_log WHERE action = 'backup.created' AND actor_name = 'cli'"))

	code, out, errOut := i.run("", "backup", "list")
	require.Equal(t, 0, code, errOut)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	require.Len(t, lines, 2, out)
	assert.Regexp(t, `^NAME +KIND +SIZE +CREATED \(UTC\) +ALICE +CHECK$`, lines[0])
	assert.Regexp(t, `^`+regexp.QuoteMeta(filepath.Base(path))+` +manual +[0-9]+\.[0-9] MiB +[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} +dev +ok$`, lines[1])

	code, out, errOut = i.run("", "backup", "verify", path)
	require.Equal(t, 0, code, errOut)
	assert.Equal(t, "The backup file looks complete (header, size and checksum are correct).\n", out)

	code, out, errOut = i.run(cliPassphrase+"\n", "backup", "verify", path, "--deep", "--passphrase-stdin")
	require.Equal(t, 0, code, errOut)
	host, err := os.Hostname()
	require.NoError(t, err)
	assert.Regexp(t, `^The backup opens with this passphrase and is complete: Backup from [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC, `+
		`Alice dev, host `+regexp.QuoteMeta(host)+`, installation `+i.installationID+`\.\n$`, out)

	code, out, errOut = i.run("not the passphrase\n", "backup", "verify", path, "--deep", "--passphrase-stdin")
	assert.Equal(t, 1, code)
	assert.Empty(t, out)
	assert.Equal(t, "The passphrase is wrong or the file is damaged. Nothing was changed.\n", errOut)

	// A pre-upgrade backup is named after this binary's version; the reason stays in the manifest.
	old := version.Version
	version.Version = "1.0.0"
	t.Cleanup(func() { version.Version = old })
	code, out, errOut = i.run("", "backup", "--reason", "pre-upgrade-1.1.0")
	require.Equal(t, 0, code, errOut)
	assert.Regexp(t, `-pre-upgrade-1\.0\.0\.alicebak \(`, out)

	// No such file; a missing checksum file; a foreign file (shallow and deep); a damaged checksum.
	code, _, errOut = i.run("", "backup", "verify", filepath.Join(i.backups, "gone.alicebak"))
	assert.Equal(t, 1, code)
	assert.Equal(t, "There is no backup file "+filepath.Join(i.backups, "gone.alicebak")+".\n", errOut)
	sum, err := os.ReadFile(path + ".sha256")
	require.NoError(t, err)
	require.NoError(t, os.Remove(path+".sha256"))
	code, _, errOut = i.run("", "backup", "verify", path)
	assert.Equal(t, 1, code)
	assert.Equal(t, "The checksum file "+filepath.Base(path)+".sha256 is missing, so the file can only be checked with the passphrase (--deep).\n", errOut)
	require.NoError(t, os.WriteFile(path+".sha256", sum, 0o600))
	code, _, errOut = i.run(cliPassphrase+"\n", "backup", "verify", filepath.Join(i.backups, "gone.alicebak"), "--deep", "--passphrase-stdin")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "The backup file could not be read:")
	other := filepath.Join(i.backups, "note.alicebak")
	require.NoError(t, os.WriteFile(other, []byte("just some text\n"), 0o600))
	code, _, errOut = i.run("", "backup", "verify", other)
	assert.Equal(t, 1, code)
	assert.Equal(t, "This is not an Alice backup.\n", errOut)
	code, _, errOut = i.run(cliPassphrase+"\n", "backup", "verify", other, "--deep", "--passphrase-stdin")
	assert.Equal(t, 1, code)
	assert.Equal(t, "This is not an Alice backup.\n", errOut)
	code, out, errOut = i.run("", "backup", "list")
	require.Equal(t, 0, code, errOut)
	assert.Regexp(t, `(?m)^note\.alicebak +- +0\.0 MiB +[0-9-]+ [0-9:]+ +- +unreadable header$`, out)
	require.NoError(t, os.WriteFile(path+".sha256", []byte(strings.Repeat("0", 64)+"  "+filepath.Base(path)+"\n"), 0o600))
	code, _, errOut = i.run("", "backup", "verify", path)
	assert.Equal(t, 1, code)
	assert.Equal(t, "The passphrase is wrong or the file is damaged. Nothing was changed.\n", errOut)
}

func TestCLIBackupOutMustStayInTheBackupDir(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"backup", "--out", "/tmp/x.alicebak"}, env(map[string]string{"ALICE_DATABASE_URL": "postgres://alice@127.0.0.1:1/alice"}),
		nil, &out, &errOut)
	assert.Equal(t, 2, code)
	assert.Equal(t, "The backup file must be in /opt/alice/backups (ALICE_BACKUP_DIR).\n", errOut.String())
	assert.Empty(t, out.String())

	i := newCLIInstall(t)
	code, outS, errS := i.run("", "backup", "--out", filepath.Join(i.backups, "before-the-move.alicebak"))
	require.Equal(t, 0, code, errS)
	assert.Contains(t, outS, "Backup written: "+filepath.Join(i.backups, "before-the-move.alicebak")+" (")
	code, _, errS = i.run("", "backup", "--out", filepath.Join(i.backups, "sub", "x.alicebak"))
	assert.Equal(t, 2, code)
	assert.Equal(t, "The backup file must be in "+i.backups+" (ALICE_BACKUP_DIR).\n", errS)
	code, _, _ = i.run("", "backup", "--out", filepath.Join(i.backups, ".hidden.alicebak"))
	assert.Equal(t, 2, code)
}

// restoreCase runs one restore through the CLI after stopping the installation's pools.
func (i *cliInstall) restore(stdin string, args ...string) (int, string, string) {
	i.t.Helper()
	i.stop()
	defer i.reopen()
	return i.run(stdin, append([]string{"restore"}, args...)...)
}

func TestCLIRestoreMessages(t *testing.T) {
	const damaged = "The passphrase is wrong or the file is damaged. Nothing was changed.\n"
	pass := cliPassphrase + "\n"

	t.Run("not a backup", func(t *testing.T) {
		i := newCLIInstall(t)
		text := filepath.Join(i.backups, "notes.alicebak")
		require.NoError(t, os.WriteFile(text, []byte("hello\n"), 0o600))
		code, _, errOut := i.restore(pass, text, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
		assert.Equal(t, 1, code)
		assert.Equal(t, "This is not an Alice backup.\n", errOut)
	})
	t.Run("no owner URL", func(t *testing.T) {
		i := newCLIInstall(t)
		path := i.backup()
		delete(i.vars, "ALICE_MIGRATE_DATABASE_URL")
		code, _, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
		assert.Equal(t, 1, code)
		assert.Equal(t, "ALICE_MIGRATE_DATABASE_URL is not set; a restore needs the database owner role. Nothing was changed.\n", errOut)
	})
	t.Run("not the owner role", func(t *testing.T) {
		i := newCLIInstall(t)
		path := i.backup()
		i.vars["ALICE_MIGRATE_DATABASE_URL"] = i.d.AppURL
		code, _, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
		assert.Equal(t, 1, code)
		assert.Regexp(t, `^The role in ALICE_MIGRATE_DATABASE_URL \(alice_app\) does not own the database \S+; a restore needs the `+
			`database owner role\. Nothing was changed\.\n$`, errOut)
	})
	t.Run("newer", func(t *testing.T) {
		i := newCLIInstall(t)
		old := version.Version
		t.Cleanup(func() { version.Version = old })
		version.Version = "9.9.9"
		path := i.backup()
		version.Version = "1.0.0"
		code, _, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
		assert.Equal(t, 1, code)
		assert.Equal(t, "This backup was created by a newer Alice version (9.9.9). Install Alice 9.9.9 or newer, then restore.\n", errOut)
		// The deep verification, which alicectl restore runs first, gives the same answer before it decrypts anything.
		code, out, errOut := i.run(pass, "backup", "verify", path, "--deep", "--passphrase-stdin")
		assert.Equal(t, 1, code)
		assert.Empty(t, out)
		assert.Equal(t, "This backup was created by a newer Alice version (9.9.9). Install Alice 9.9.9 or newer, then restore.\n", errOut)
	})
	t.Run("damaged", func(t *testing.T) {
		i := newCLIInstall(t)
		path := i.backup()
		code, _, errOut := i.restore("wrong passphrase\n", path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
		assert.Equal(t, 1, code)
		assert.Equal(t, damaged, errOut)
	})
	t.Run("broken audit", func(t *testing.T) {
		i := newCLIInstall(t)
		conn, err := i.d.Owner.Acquire(i.ctx)
		require.NoError(t, err)
		for _, q := range []string{"SET session_replication_role = replica",
			`UPDATE audit_log SET details = '{"changed":"yes"}' WHERE seq = (SELECT min(seq) + 1 FROM audit_log)`, "RESET session_replication_role"} {
			_, err = conn.Exec(i.ctx, q)
			require.NoError(t, err)
		}
		conn.Release()
		var seq int64
		require.NoError(t, i.d.Owner.QueryRow(i.ctx, "SELECT min(seq) + 1 FROM audit_log").Scan(&seq))
		path := i.backup()
		code, _, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
		assert.Equal(t, 1, code)
		assert.Equal(t, fmt.Sprintf("The audit log in this backup is damaged at entry %d. Nothing was changed. To restore it anyway, "+
			"run the command again with --accept-broken-audit-log (the damage stays visible in Alice).\n", seq), errOut)
	})
	t.Run("not confirmed", func(t *testing.T) {
		i := newCLIInstall(t)
		path := i.backup()
		code, out, errOut := i.restore(pass+"restore\n", path, "--passphrase-stdin", "--wait-for-sessions", "0s")
		assert.Equal(t, 1, code)
		assert.Regexp(t, `^Backup from [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC, Alice dev, host \S+, installation `+
			i.installationID+`\.\nType RESTORE to replace all current data: \n$`, out)
		assert.Equal(t, "Restore cancelled. Nothing was changed.\n", errOut)
	})
	t.Run("no safety backup possible", func(t *testing.T) {
		i := newCLIInstall(t)
		path := i.backup()
		_, err := i.d.Owner.Exec(i.ctx, "DELETE FROM settings WHERE key = 'backup.key'")
		require.NoError(t, err)
		code, _, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
		assert.Equal(t, 1, code)
		assert.Equal(t, "This installation has data but no recovery passphrase, so no safety backup can be made first. Nothing was changed. "+
			"To restore anyway, run the command again with --no-safety-backup (the current data is then replaced without a copy).\n", errOut)

		code, out, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s", "--no-safety-backup")
		require.Equal(t, 0, code, errOut)
		assert.Equal(t, "Restore finished. Everyone must sign in again. Users and API tokens are as they were when the backup was made; review them.\n", out)
		assert.Equal(t, 1, i.count(`SELECT count(*) FROM audit_log WHERE action = 'system.restored' AND details->>'no_safety_backup' = 'true'
			AND details->>'safety_backup' = 'none'`))
	})
	t.Run("not enough disk", func(t *testing.T) {
		i := newCLIInstall(t)
		path := i.backup()
		code, _, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s", "--free-bytes", "1")
		assert.Equal(t, 1, code)
		assert.Regexp(t, `^Not enough free disk space for a restore: 0 GB free, [0-9]+ GB needed\.\n$`, errOut)
	})
	t.Run("still connected", func(t *testing.T) {
		i := newCLIInstall(t)
		path := i.backup()
		extra, err := pgxpool.New(i.ctx, i.d.AppURL)
		require.NoError(t, err)
		defer extra.Close()
		require.NoError(t, extra.Ping(i.ctx))
		code, _, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
		assert.Equal(t, 1, code)
		assert.Equal(t, "Alice is still connected to the database. Stop it first.\n", errOut)
	})
	t.Run("done", func(t *testing.T) {
		i := newCLIInstall(t)
		path := i.backup()
		_, err := i.d.Owner.Exec(i.ctx, "INSERT INTO settings (key, value, updated_at) VALUES ('test.after_backup', '1', now())")
		require.NoError(t, err)
		code, out, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s")
		require.Equal(t, 0, code, errOut)
		assert.Regexp(t, `^The replaced data was saved first as alice-backup-\S+-pre-restore\.alicebak\.\n`+
			regexp.QuoteMeta("Restore finished. Everyone must sign in again. Users and API tokens are as they were when the backup was made; review them.")+`\n$`, out)
		assert.Zero(t, i.count("SELECT count(*) FROM settings WHERE key = 'test.after_backup'"), "the backup's data is live")
		assert.Equal(t, 1, i.count("SELECT count(*) FROM audit_log WHERE action = 'system.restored' AND actor_name = 'cli'"))
	})
	t.Run("db-only done", func(t *testing.T) {
		i := newCLIInstall(t)
		path := i.backup()
		code, out, errOut := i.restore(pass, path, "--passphrase-stdin", "--confirm", "RESTORE", "--wait-for-sessions", "0s", "--db-only")
		require.Equal(t, 0, code, errOut)
		assert.True(t, strings.HasSuffix(out, "Database restored from "+filepath.Base(path)+".\n"), out)
	})
}

// The flags reach the restore as the contract says; the default wait is 150 s.
func TestCLIRestoreFlags(t *testing.T) {
	var got []backup.RestoreInput
	old := restoreFunc
	t.Cleanup(func() { restoreFunc = old })
	restoreFunc = func(_ context.Context, _ backup.Config, in backup.RestoreInput) (backup.RestoreResult, error) {
		got = append(got, in)
		return backup.RestoreResult{}, nil
	}
	oldCheck := ownerCheckFunc
	t.Cleanup(func() { ownerCheckFunc = oldCheck })
	var checked []string
	ownerCheckFunc = func(_ context.Context, url string) error { checked = append(checked, url); return nil }
	vars := env(map[string]string{"ALICE_DATABASE_URL": "postgres://alice_app@db/alice", "ALICE_MIGRATE_DATABASE_URL": "postgres://alice_owner@db/alice"})
	var out, errOut bytes.Buffer
	require.Equal(t, 0, run([]string{"restore", "/b/x.alicebak", "--passphrase-stdin", "--confirm", "RESTORE"}, vars,
		strings.NewReader("p\n"), &out, &errOut), errOut.String())
	require.Equal(t, 0, run([]string{"restore", "--passphrase-stdin", "--no-safety-backup", "--db-only", "--accept-broken-audit-log",
		"--free-bytes", "12345", "--wait-for-sessions", "3s", "/b/y.alicebak"}, vars, strings.NewReader("p\n"), &out, &errOut), errOut.String())
	require.Len(t, got, 2)
	assert.Equal(t, []string{"postgres://alice_owner@db/alice", "postgres://alice_owner@db/alice"}, checked, "the owner role is checked first")
	assert.Equal(t, 150*time.Second, got[0].WaitForSessions)
	assert.Nil(t, got[0].Confirm, "--confirm RESTORE skips the prompt")
	assert.False(t, got[0].NoSafetyBackup)
	assert.Equal(t, "postgres://alice_owner@db/alice", got[0].OwnerURL)
	assert.Equal(t, "/b/x.alicebak", got[0].Path)
	assert.Nil(t, got[0].Passphrase, "the passphrase is asked for only after the header check")
	assert.True(t, got[1].NoSafetyBackup)
	assert.True(t, got[1].DBOnly)
	assert.True(t, got[1].AcceptBrokenAudit)
	assert.Equal(t, int64(12345), got[1].FreeBytes)
	assert.Equal(t, 3*time.Second, got[1].WaitForSessions)
	assert.NotNil(t, got[1].Confirm)

	for _, bad := range [][]string{{"restore"}, {"restore", "a", "b"}, {"restore", "f", "--confirm", "yes"}, {"restore", "f", "--free-bytes", "-1"}} {
		errOut.Reset()
		assert.Equal(t, 2, run(bad, vars, strings.NewReader(""), &out, &errOut), bad)
		assert.Contains(t, errOut.String(), "usage: alice restore", bad)
	}
}

func TestCLIPassphraseNeverFromArgsOrEnv(t *testing.T) {
	vars := map[string]string{"ALICE_DATABASE_URL": "postgres://alice_app@db/alice", "ALICE_PASSPHRASE": "from-the-environment"}
	var out, errOut bytes.Buffer
	assert.Equal(t, 2, run([]string{"restore", "/b/x.alicebak", "--passphrase", "x"}, env(vars), strings.NewReader(""), &out, &errOut))
	assert.Contains(t, errOut.String(), "usage: alice restore")

	for _, args := range [][]string{{"restore", "/b/x.alicebak", "--confirm", "RESTORE"}, {"backup", "verify", "/b/x.alicebak", "--deep"}} {
		errOut.Reset()
		assert.Equal(t, 2, run(args, env(vars), strings.NewReader("from-stdin\n"), &out, &errOut), args)
		assert.Equal(t, "A passphrase is needed. Run this command in a terminal, or pass --passphrase-file to alicectl.\n", errOut.String())
	}
	assert.NotContains(t, out.String(), "from-the-environment")
}

func TestCLIMigrateToLatest(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	latest, err := db.LatestVersion(migrations.FS)
	require.NoError(t, err)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, pgtest.PreviousVersion(t))
	require.NoError(t, err)
	code, out, errOut := runCLI(t, env(map[string]string{"ALICE_MIGRATE_DATABASE_URL": d.OwnerURL}), "migrate", "--to-latest")
	require.Equal(t, 0, code, errOut)
	assert.Equal(t, "database is up to date\n", out)
	v, err := db.SchemaVersion(ctx, d.Owner)
	require.NoError(t, err)
	assert.Equal(t, latest, v)
	code, _, errOut = runCLI(t, env(map[string]string{"ALICE_MIGRATE_DATABASE_URL": d.OwnerURL}), "migrate", "--to-oldest")
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "usage: alice migrate")
}

func TestCLIBackupRefusals(t *testing.T) {
	i := newCLIInstall(t)
	conn, err := i.d.Owner.Acquire(i.ctx)
	require.NoError(t, err)
	var locked bool
	require.NoError(t, conn.QueryRow(i.ctx, "SELECT pg_try_advisory_lock(hashtext('alice.backup'))").Scan(&locked))
	require.True(t, locked)
	code, out, errOut := i.run("", "backup")
	assert.Equal(t, 1, code)
	assert.Empty(t, out)
	assert.Equal(t, "Another backup is running. Try again when it has finished.\n", errOut)
	_, err = conn.Exec(i.ctx, "SELECT pg_advisory_unlock(hashtext('alice.backup'))")
	require.NoError(t, err)
	conn.Release()

	_, err = i.d.Owner.Exec(i.ctx, "DELETE FROM settings WHERE key = 'backup.key'")
	require.NoError(t, err)
	code, _, errOut = i.run("", "backup")
	assert.Equal(t, 1, code)
	assert.Equal(t, "Backups start after the recovery passphrase is set. Finish the setup wizard first.\n", errOut)
}
