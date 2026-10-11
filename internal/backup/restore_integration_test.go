//go:build integration

package backup_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/backup"
	"alice/internal/backup/dump"
	"alice/internal/backup/format"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/tlscert"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/pki"
	"alice/migrations"
)

// ---- environment ----------------------------------------------------------------------------------------------------

// newRestoreEnv is newEnv with what a restore verifies: an installation row sealed under the master key, a real time
// record in both stores, and enough incompressible data that the backup spans several chunks.
func newRestoreEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, true)
	var at time.Time
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT installed_at FROM license WHERE id = 1").Scan(&at))
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE license SET installation_seal = $1 WHERE id = 1",
		backup.InstallationSeal(e.keyring, e.installationID, at))
	require.NoError(t, err)
	e.writeTimeRecord(e.keyring, e.clk.Now(), 1)
	bulk := make([]byte, 150<<10)
	_, _ = rand.Read(bulk)
	require.NoError(t, settings.Set(e.ctx, e.db.Owner, "test.bulk", hex.EncodeToString(bulk), e.clk.Now()))
	return e
}

func (e *env) writeTimeRecord(k *secrets.Keyring, at time.Time, seq uint64) {
	e.t.Helper()
	raw, err := license.NewHWMCodec(k).Encode(license.HWMRecord{At: at.UTC().Truncate(time.Second), Seq: seq})
	require.NoError(e.t, err)
	require.NoError(e.t, settings.Set(e.ctx, e.db.Owner, license.HWMSettingKey, json.RawMessage(raw), e.clk.Now()))
	p := filepath.Join(e.stateDir, license.HWMFileName)
	_ = os.Remove(p)
	require.NoError(e.t, os.WriteFile(p, raw, 0o600))
}

// timeRecords decodes both stores of the time record with k.
func (e *env) timeRecords(k *secrets.Keyring) (fromDB, fromFile license.HWMRecord) {
	e.t.Helper()
	codec := license.NewHWMCodec(k)
	var raw json.RawMessage
	found, err := settings.Get(e.ctx, e.db.Owner, license.HWMSettingKey, &raw)
	require.NoError(e.t, err)
	require.True(e.t, found)
	fromDB, err = codec.Decode(raw)
	require.NoError(e.t, err)
	b, err := os.ReadFile(filepath.Join(e.stateDir, license.HWMFileName))
	require.NoError(e.t, err)
	fromFile, err = codec.Decode(b)
	require.NoError(e.t, err)
	return fromDB, fromFile
}

// stop closes the test's pools, as stopping Alice does; start opens new ones.
func (e *env) stop() {
	e.db.Owner.Close()
	e.db.App.Close()
}

func (e *env) start() {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := db.Open(ctx, e.db.OwnerURL)
	require.NoError(e.t, err)
	e.t.Cleanup(owner.Close)
	app, err := db.Open(ctx, e.db.AppURL)
	require.NoError(e.t, err)
	e.t.Cleanup(app.Close)
	e.db.Owner, e.db.App = owner, app
}

// reload loads the (possibly restored) master key and rebuilds the service, as a restart would.
func (e *env) reload() {
	e.t.Helper()
	var err error
	e.keyring, err = secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, e.keysDir, e.clk.Now())
	require.NoError(e.t, err)
	e.cfg.Pool, e.cfg.Keyring = e.db.App, e.keyring
	e.svc = backup.New(e.cfg)
}

func (e *env) input(path string) backup.RestoreInput {
	return backup.RestoreInput{Path: path, Passphrase: []byte(passphrase), OwnerURL: e.db.OwnerURL}
}

// restoreWith runs a restore while the test's pools are closed. The fake clock moves on a minute first, so safety
// backups and previous databases get names of their own.
func (e *env) restoreWith(in backup.RestoreInput) (backup.RestoreResult, error) {
	e.clk.Advance(time.Minute)
	e.stop()
	defer e.start()
	return backup.Restore(e.ctx, e.cfg, in)
}

func (e *env) restore(path string, edit func(*backup.RestoreInput)) (backup.RestoreResult, error) {
	in := e.input(path)
	if edit != nil {
		edit(&in)
	}
	return e.restoreWith(in)
}

// crash is what a crash-point hook panics with: Restore stops there without running its error cleanup, as a killed
// process would.
type crash struct{ point string }

func (e *env) restoreCrashing(path, point string) (crashed bool) {
	e.t.Helper()
	in := e.input(path)
	backup.SetRestoreHook(&in, func(p string) error {
		if p == point {
			panic(crash{p})
		}
		return nil
	})
	defer func() {
		if r := recover(); r != nil {
			c, ok := r.(crash)
			require.True(e.t, ok, "unexpected panic %v", r)
			require.Equal(e.t, point, c.point)
			crashed = true
		}
	}()
	_, err := e.restoreWith(in)
	require.NoError(e.t, err)
	return false
}

// ---- snapshots ------------------------------------------------------------------------------------------------------

type snap struct {
	tables map[string]string // table → md5 of its rows
	files  map[string]string // "keys/…" or "state/…" (recursive) → SHA-256, directories as "dir"
	dbs    []string          // databases whose name starts with the test database's name
}

func dbName(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return strings.TrimPrefix(u.Path, "/")
}

func withDB(t *testing.T, rawURL, name string, user *url.Userinfo) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	u.Path = "/" + name
	if user != nil {
		u.User = user
	}
	return u.String()
}

// superPool is a superuser pool on the server's maintenance database.
func (e *env) superPool() *pgxpool.Pool {
	e.t.Helper()
	p, err := db.Open(e.ctx, withDB(e.t, e.db.OwnerURL, "postgres", nil))
	require.NoError(e.t, err)
	e.t.Cleanup(p.Close)
	return p
}

func tableHashes(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[string]string {
	t.Helper()
	tables, err := dump.Tables(ctx, pool)
	require.NoError(t, err)
	out := map[string]string{}
	for _, tb := range tables {
		q := "SELECT coalesce(md5(string_agg(x::text, E'\\n' ORDER BY x::text)), '') FROM " + //nolint:gosec // G202: a catalog name quoted by pgx
			pgx.Identifier{"public", tb.Name}.Sanitize() + " AS x"
		var h string
		require.NoError(t, pool.QueryRow(ctx, q).Scan(&h))
		out[tb.Name] = h
	}
	return out
}

func fileHashes(t *testing.T, dirs map[string]string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for prefix, dir := range dirs {
		require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			if rel == "." {
				return nil
			}
			if d.IsDir() {
				out[prefix+"/"+rel] = "dir"
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			out[prefix+"/"+rel] = hex.EncodeToString(sum[:])
			return nil
		}))
	}
	return out
}

func (e *env) databases() []string {
	e.t.Helper()
	sp := e.superPool()
	defer sp.Close()
	rows, err := sp.Query(e.ctx, "SELECT datname FROM pg_database WHERE starts_with(datname, $1) ORDER BY 1", dbName(e.t, e.db.OwnerURL))
	require.NoError(e.t, err)
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(e.t, err)
	return names
}

func (e *env) snapshot() snap {
	e.t.Helper()
	return snap{tables: tableHashes(e.t, e.ctx, e.db.Owner),
		files: fileHashes(e.t, map[string]string{"keys": e.keysDir, "state": e.stateDir}), dbs: e.databases()}
}

// requireUnchanged compares two snapshots; tables named in except may differ.
func requireUnchanged(t *testing.T, before, after snap, except ...string) {
	t.Helper()
	for name, h := range before.tables {
		if slices.Contains(except, name) {
			continue
		}
		assert.Equal(t, h, after.tables[name], "table %s changed", name)
	}
	assert.Len(t, after.tables, len(before.tables))
	assert.Equal(t, before.files, after.files, "key or state files changed")
	assert.Equal(t, before.dbs, after.dbs, "databases changed")
}

// restoredExcept are the tables a restore changes on purpose: sessions end, the audit log gains system.restored and
// settings gain backup.restore_id.
var restoredExcept = []string{"audit_log", "settings", "sessions", "setup_sessions", "oidc_login_states"}

// requireRestored checks that the installation is the one of the backup taken at atBackup.
func (e *env) requireRestored(atBackup snap, wantAudit string) {
	e.t.Helper()
	now := e.snapshot()
	for name, h := range atBackup.tables {
		if slices.Contains(restoredExcept, name) {
			continue
		}
		assert.Equal(e.t, h, now.tables[name], "table %s is not the backup's", name)
	}
	assert.Equal(e.t, atBackup.files, now.files, "key and state files are not the backup's")
	assert.Equal(e.t, []string{dbName(e.t, e.db.OwnerURL)}, now.dbs, "no staging or previous database is left")
	for _, tb := range []string{"sessions", "setup_sessions", "oidc_login_states"} {
		assert.Zero(e.t, e.count("SELECT count(*) FROM "+tb), tb)
	}
	var action string
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT action FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&action))
	assert.Equal(e.t, "system.restored", action)
	rep, err := audit.Verify(e.ctx, e.db.Owner)
	require.NoError(e.t, err)
	assert.True(e.t, rep.Intact)
	if wantAudit != "" {
		assert.Equal(e.t, wantAudit, auditRowsBefore(e, rep.HeadSeq))
	}
}

// auditRowsBefore hashes the audit rows before seq.
func auditRowsBefore(e *env, seq int64) string {
	var h string
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx,
		"SELECT coalesce(md5(string_agg(x::text, E'\\n' ORDER BY x.seq)), '') FROM audit_log x WHERE seq < $1", seq).Scan(&h))
	return h
}

func (e *env) auditHash() string {
	var h string
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx,
		"SELECT coalesce(md5(string_agg(x::text, E'\\n' ORDER BY x.seq)), '') FROM audit_log x").Scan(&h))
	return h
}

// mutate changes data and files after a backup, so a restore is visible.
func (e *env) mutate() {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, "DELETE FROM recovery_codes")
	require.NoError(e.t, err)
	require.NoError(e.t, settings.Set(e.ctx, e.db.Owner, "test.changed", "after the backup", e.clk.Now()))
	require.NoError(e.t, os.Remove(filepath.Join(e.keysDir, "tls.crt")))
	require.NoError(e.t, os.Remove(filepath.Join(e.keysDir, "tls.key")))
	_, err = tlscert.EnsureSelfSigned(e.keysDir, []string{"changed.example.test"}, e.clk.Now())
	require.NoError(e.t, err)
}

func (e *env) requireNoStaging() {
	e.t.Helper()
	for _, d := range []string{e.keysDir, e.stateDir} {
		_, err := os.Lstat(filepath.Join(d, ".restore-staging"))
		assert.ErrorIs(e.t, err, os.ErrNotExist, "staging directory in %s", d)
	}
}

// backupWithSnapshot takes the snapshot and then the backup.
func (e *env) backupWithSnapshot() (snap, string, backup.Info) {
	e.t.Helper()
	s := e.snapshot()
	h := e.auditHash()
	return s, h, e.create(backup.KindManual)
}

// ---- tests ----------------------------------------------------------------------------------------------------------

func TestRestoreRoundTrip(t *testing.T) {
	e := newRestoreEnv(t)
	atBackup, auditAtBackup, info := e.backupWithSnapshot()
	e.mutate()
	var logs bytes.Buffer
	e.cfg.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	master, err := os.ReadFile(filepath.Join(e.keysDir, "master.key"))
	require.NoError(t, err)
	res, err := e.restore(info.Path, nil)
	require.NoError(t, err)
	// Canaries: neither the passphrase nor the master key reaches the log.
	assert.NotContains(t, logs.String(), passphrase)
	assert.NotContains(t, logs.String(), strings.TrimSpace(string(master)))
	e.requireRestored(atBackup, auditAtBackup)
	e.requireNoStaging()

	assert.Equal(t, e.installationID, res.Manifest.InstallationID)
	assert.Equal(t, hostname, res.Manifest.Hostname)
	require.NotEmpty(t, res.SafetyBackup)
	assert.True(t, strings.HasSuffix(res.SafetyBackup, "-pre-restore.alicebak"), res.SafetyBackup)
	e.reload()
	v, err := e.svc.Verify(e.ctx, res.SafetyBackup)
	require.NoError(t, err)
	assert.Equal(t, backup.CheckOK, v.Check)
	_, err = e.svc.VerifyDeep(e.ctx, res.SafetyBackup, []byte(passphrase))
	require.NoError(t, err)

	// The settings of the backup are back, plus the restore ID; the change made after the backup is gone.
	var changed string
	found, err := settings.Get(e.ctx, e.db.Owner, "test.changed", &changed)
	require.NoError(t, err)
	assert.False(t, found)
	var id string
	found, err = settings.Get(e.ctx, e.db.Owner, "backup.restore_id", &id)
	require.NoError(t, err)
	require.True(t, found)
	assert.Regexp(t, `^[0-9a-f]{32}$`, id)

	// A backup made after the restore works with the same passphrase.
	e.clk.Advance(time.Hour)
	again := e.create(backup.KindManual)
	_, err = e.svc.VerifyDeep(e.ctx, again.Path, []byte(passphrase))
	require.NoError(t, err)
}

// headerLength returns n of the clear header.
func headerLength(t *testing.T, b []byte) int {
	t.Helper()
	require.Greater(t, len(b), 14)
	return int(binary.BigEndian.Uint32(b[10:14]))
}

// requireNothingChanged is the check of every refused restore: the live installation, its files and its databases
// are as they were, and no safety backup was written.
func (e *env) requireNothingChanged(before snap, backupsBefore []string) {
	e.t.Helper()
	requireUnchanged(e.t, before, e.snapshot())
	e.requireNoStaging()
	assert.Equal(e.t, backupsBefore, e.files(), "no safety backup was written")
}

func TestF80WrongPassphraseChangesNothing(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	before, backups := e.snapshot(), e.files()
	_, err := e.restore(info.Path, func(in *backup.RestoreInput) { in.Passphrase = []byte("not the passphrase at all, sorry") })
	require.ErrorIs(t, err, backup.ErrDamaged)
	e.requireNothingChanged(before, backups)
}

func TestF81FlippedByteChangesNothing(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	orig, err := os.ReadFile(info.Path)
	require.NoError(t, err)
	n := headerLength(t, orig)
	salt := strings.Index(string(orig[14:14+n]), `"salt":"`)
	require.Positive(t, salt)
	require.Greater(t, len(orig), 14+n+2*(format.ChunkSize+16), "the backup spans more than two chunks")
	for name, at := range map[string]int{
		"header":         14 + n - 5,
		"salt":           14 + salt + len(`"salt":"`) + 2,
		"ciphertext":     14 + n + format.ChunkSize/2,
		"chunk-boundary": 14 + n + format.ChunkSize + 16,
	} {
		t.Run(name, func(t *testing.T) {
			b := slices.Clone(orig)
			if name == "salt" {
				b[at] = map[bool]byte{true: 'B', false: 'A'}[b[at] == 'A'] // stays base64
			} else {
				b[at] ^= 0x01
			}
			p := filepath.Join(t.TempDir(), "flipped.alicebak")
			require.NoError(t, os.WriteFile(p, b, 0o600))
			before, backups := e.snapshot(), e.files()
			_, err := e.restore(p, nil)
			require.ErrorIs(t, err, backup.ErrDamaged)
			e.requireNothingChanged(before, backups)
		})
	}
}

func TestF82TruncatedChangesNothing(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	orig, err := os.ReadFile(info.Path)
	require.NoError(t, err)
	n := headerLength(t, orig)
	body := len(orig) - 14 - n
	final := body % (format.ChunkSize + 16)
	require.Positive(t, final)
	for name, size := range map[string]int{
		"inside chunk 1":      14 + n + format.ChunkSize + 16 + 100,
		"final chunk removed": len(orig) - final,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "cut.alicebak")
			require.NoError(t, os.WriteFile(p, orig[:size], 0o600))
			before, backups := e.snapshot(), e.files()
			_, err := e.restore(p, nil)
			require.ErrorIs(t, err, backup.ErrDamaged)
			e.requireNothingChanged(before, backups)
		})
	}
}

func TestF83ForeignAndNewer(t *testing.T) {
	e := newRestoreEnv(t)
	asking := func(asked *bool) func(*backup.RestoreInput) {
		return func(in *backup.RestoreInput) {
			in.Passphrase = nil
			in.AskPassphrase = func() ([]byte, error) { *asked = true; return []byte(passphrase), nil }
		}
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.alicebak")
	require.NoError(t, os.WriteFile(empty, nil, 0o600))
	text := filepath.Join(dir, "notes.alicebak")
	require.NoError(t, os.WriteFile(text, []byte("These are my notes, not a backup.\n"), 0o600))
	for _, p := range []string{empty, text} {
		before, backups := e.snapshot(), e.files()
		asked := false
		_, err := e.restore(p, asking(&asked))
		require.ErrorIs(t, err, format.ErrNotBackup)
		assert.False(t, asked, "the passphrase is not asked for a file that is not a backup")
		e.requireNothingChanged(before, backups)
	}

	// A backup made by Alice 9.0.0, restored by Alice 1.0.0.
	e.cfg.Version = "9.0.0"
	e.reload()
	newer := e.create(backup.KindManual)
	e.cfg.Version = "1.0.0"
	before, backups := e.snapshot(), e.files()
	asked := false
	_, err := e.restore(newer.Path, asking(&asked))
	var en *backup.ErrNewer
	require.ErrorAs(t, err, &en)
	assert.Equal(t, "9.0.0", en.Version)
	assert.False(t, asked, "a newer version is refused before the passphrase")
	e.requireNothingChanged(before, backups)

	// A manifest with a newer schema (a real backup whose manifest frame is re-encoded).
	e.reload()
	latest, err := db.LatestVersion(migrations.FS)
	require.NoError(t, err)
	e.clk.Advance(time.Minute)
	current := e.create(backup.KindManual)
	future := reframe(t, e, current.Path, func(f dump.Frame) *dump.Frame {
		if f.Kind == dump.Manifest {
			var m backup.Manifest
			require.NoError(t, json.Unmarshal(f.Data, &m))
			m.SchemaVersion = latest + 1
			b, err := json.Marshal(m)
			require.NoError(t, err)
			f.Data = b
		}
		return &f
	})
	before, backups = e.snapshot(), e.files()
	_, err = e.restore(future, nil)
	require.ErrorAs(t, err, &en)
	assert.Equal(t, "1.0.0", en.Version)
	e.requireNothingChanged(before, backups)
}

// createDB creates an empty database on the test server and drops it when the test ends.
func (e *env) createDB(name string) string {
	e.t.Helper()
	sp := e.superPool()
	_, err := sp.Exec(e.ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	require.NoError(e.t, err)
	e.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		p, err := db.Open(ctx, withDB(e.t, e.db.OwnerURL, "postgres", nil))
		if err != nil {
			return
		}
		defer p.Close()
		for _, n := range []string{name, name + "_restore"} {
			_, _ = p.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{n}.Sanitize()+" WITH (FORCE)")
		}
	})
	return withDB(e.t, e.db.OwnerURL, name, nil)
}

func uniqueName(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// restoreElsewhere restores path into the database at ownerURL with its own empty keys and state directories; the
// returned env reads that installation.
func (e *env) restoreElsewhere(path, ownerURL string, edit func(*backup.RestoreInput)) (*env, backup.RestoreResult, error) {
	e.t.Helper()
	o := &env{t: e.t, ctx: e.ctx, clk: e.clk, audit: e.audit, dir: e.t.TempDir(), keysDir: e.t.TempDir(), stateDir: e.t.TempDir(),
		db: &pgtest.DB{OwnerURL: ownerURL, AppURL: withDB(e.t, ownerURL, dbName(e.t, ownerURL), url.UserPassword("alice_app", pgtest.AppPassword))}}
	o.cfg = backup.Config{Audit: o.audit, Clock: o.clk, Dir: o.dir, KeysDir: o.keysDir, StateDir: o.stateDir, Version: "1.0.0",
		Hostname: func() (string, error) { return "new-host", nil }}
	backup.SetStatfs(&o.cfg, func(string) (uint64, error) { return 100 << 30, nil })
	in := backup.RestoreInput{Path: path, Passphrase: []byte(passphrase), OwnerURL: ownerURL}
	if edit != nil {
		edit(&in)
	}
	e.clk.Advance(time.Minute)
	res, err := backup.Restore(e.ctx, o.cfg, in)
	o.start()
	return o, res, err
}

func TestF84OlderSchemaMigratesForward(t *testing.T) {
	e := newRestoreEnv(t)
	latest, err := db.LatestVersion(migrations.FS)
	require.NoError(t, err)
	oldURL := e.createDB(uniqueName("f84_"))
	old, err := db.Open(e.ctx, oldURL)
	require.NoError(t, err)
	defer old.Close()
	require.NoError(t, db.MigrateTo(e.ctx, old, migrations.FS, latest-1))

	keysDir, stateDir, dir := t.TempDir(), t.TempDir(), t.TempDir()
	k, err := secrets.LoadOrCreateMasterKey(e.ctx, old, keysDir, e.clk.Now())
	require.NoError(t, err)
	id := license.NewInstallationID()
	at := e.clk.Now().UTC()
	_, err = old.Exec(e.ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at, installation_seal)
VALUES (1, $1, $2, 'evaluation', $2, $3)`, id, at, backup.InstallationSeal(k, id, at))
	require.NoError(t, err)
	require.NoError(t, settings.Set(e.ctx, old, "general.public_url", "https://old.example.test", at))
	log := audit.New(e.clk)
	for i := range 5 {
		require.NoError(t, db.InTx(e.ctx, old, func(tx pgx.Tx) error {
			_, err := log.Append(e.ctx, tx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.older_schema",
				Result: audit.Success, Details: map[string]string{"n": fmt.Sprint(i)}})
			return err
		}))
	}
	wrapped, sender, err := secrets.NewBackupKey([]byte(passphrase), fastKDF)
	require.NoError(t, err)
	cfg := backup.Config{Pool: old, Audit: log, Clock: e.clk, Dir: dir, KeysDir: keysDir, StateDir: stateDir, Version: "1.0.0",
		Hostname: func() (string, error) { return "old-host", nil }, Keyring: k}
	backup.SetStatfs(&cfg, func(string) (uint64, error) { return 100 << 30, nil })
	path := filepath.Join(dir, "older-schema.alicebak")
	require.NoError(t, backup.WriteBackupWith(e.ctx, backup.New(cfg), path, wrapped, sender))
	old.Close()

	target := e.createDB(uniqueName("f84t_"))
	tdb, err := db.Open(e.ctx, target)
	require.NoError(t, err)
	require.NoError(t, db.Migrate(e.ctx, tdb, migrations.FS))
	tdb.Close()

	o, res, err := e.restoreElsewhere(path, target, nil)
	require.NoError(t, err)
	assert.Equal(t, latest-1, res.Manifest.SchemaVersion)
	v, err := db.SchemaVersion(e.ctx, o.db.Owner)
	require.NoError(t, err)
	assert.Equal(t, latest, v)
	var url string
	found, err := settings.Get(e.ctx, o.db.Owner, "general.public_url", &url)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "https://old.example.test", url)
	assert.Equal(t, 5, o.count("SELECT count(*) FROM audit_log WHERE action = 'test.older_schema'"))
	rep, err := audit.Verify(e.ctx, o.db.Owner)
	require.NoError(t, err)
	assert.True(t, rep.Intact)
	_, err = secrets.LoadOrCreateMasterKey(e.ctx, o.db.App, o.keysDir, e.clk.Now())
	require.NoError(t, err, "the restored master key opens the restored key check")
}

func TestRestoreRefusesABrokenChain(t *testing.T) {
	e := newRestoreEnv(t)
	var seq int64
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT min(seq) + 1 FROM audit_log").Scan(&seq))
	conn, err := e.db.Owner.Acquire(e.ctx)
	require.NoError(t, err)
	_, err = conn.Exec(e.ctx, "SET session_replication_role = replica")
	require.NoError(t, err)
	_, err = conn.Exec(e.ctx, `UPDATE audit_log SET details = '{"changed":"yes"}' WHERE seq = $1`, seq)
	require.NoError(t, err)
	_, err = conn.Exec(e.ctx, "RESET session_replication_role")
	require.NoError(t, err)
	conn.Release()
	info := e.create(backup.KindManual)

	before, backups := e.snapshot(), e.files()
	_, err = e.restore(info.Path, nil)
	var ab *backup.ErrAuditBroken
	require.ErrorAs(t, err, &ab)
	assert.Equal(t, seq, ab.Seq)
	e.requireNothingChanged(before, backups)

	_, err = e.restore(info.Path, func(in *backup.RestoreInput) { in.AcceptBrokenAudit = true })
	require.NoError(t, err)
	rows := e.auditRows("system.restored")
	require.Len(t, rows, 1)
	assert.Equal(t, "false", rows[0]["audit_intact"])
	rep, err := audit.Verify(e.ctx, e.db.Owner)
	require.NoError(t, err)
	assert.False(t, rep.Intact, "the damage stays visible")
	assert.Equal(t, seq, rep.FirstBadSeq)
}

// crashPoints are the restore's crash points in order; the database renames happen between "previous" and
// "renamed".
var (
	beforeSwap = []string{"loaded", "verified", "safety-backup", "audited", "staged", "previous"}
	afterSwap  = []string{"renamed", "files"}
)

func TestRestorePointsAreTheProductionOnes(t *testing.T) {
	assert.Equal(t, append(slices.Clone(beforeSwap), afterSwap...), slices.DeleteFunc(slices.Clone(backup.RestorePoints()),
		func(p string) bool { return p == "cleaned" }))
}

func TestRestoreIsAllOrNothing(t *testing.T) {
	for i, point := range beforeSwap {
		afterSafety := i >= slices.Index(beforeSwap, "safety-backup")
		// A failure (an error at that point): Restore cleans up, nothing is changed.
		t.Run("error/"+point, func(t *testing.T) {
			e := newRestoreEnv(t)
			atBackup, auditAtBackup, info := e.backupWithSnapshot()
			e.mutate()
			before, backups := e.snapshot(), e.files()
			in := e.input(info.Path)
			backup.SetRestoreHook(&in, func(p string) error {
				if p == point {
					return errors.New("injected failure")
				}
				return nil
			})
			_, err := e.restoreWith(in)
			require.Error(t, err)
			if afterSafety {
				// The safety backup was written and audited in the live database before the failure.
				requireUnchanged(t, before, e.snapshot(), "audit_log", "settings")
				assert.Len(t, e.files(), len(backups)+2, "the safety backup and its checksum stay")
			} else {
				e.requireNothingChanged(before, backups)
			}
			e.requireNoStaging()
			_, err = e.restore(info.Path, nil)
			require.NoError(t, err)
			e.requireRestored(atBackup, auditAtBackup)
		})
		// A crash at that point: the live installation is in force; the next restore cleans up and succeeds.
		t.Run("crash/"+point, func(t *testing.T) {
			e := newRestoreEnv(t)
			atBackup, auditAtBackup, info := e.backupWithSnapshot()
			e.mutate()
			before := e.snapshot()
			require.True(t, e.restoreCrashing(info.Path, point))
			after := e.snapshot()
			except := []string{}
			if afterSafety {
				except = []string{"audit_log", "settings"}
			}
			for name, h := range before.tables {
				if !slices.Contains(except, name) {
					assert.Equal(t, h, after.tables[name], "table %s", name)
				}
			}
			for p, h := range before.files {
				assert.Equal(t, h, after.files[p], "live file %s", p)
			}
			// Alice starts now (serve runs FinishInterruptedRestore with its pool): the live database does not carry
			// the staging's restore ID, so nothing is applied and the staging is removed (S-1).
			applied, err := backup.FinishInterruptedRestore(e.ctx, e.db.App, e.keysDir, e.stateDir)
			require.NoError(t, err)
			assert.False(t, applied)
			e.requireNoStaging()
			for p, h := range before.files {
				assert.Equal(t, h, e.snapshot().files[p], "live file %s after the start", p)
			}
			// The live database still answers with the live master key: nothing was swapped.
			_, err = secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, e.keysDir, e.clk.Now())
			require.NoError(t, err)
			_, err = e.restore(info.Path, nil)
			require.NoError(t, err)
			e.requireRestored(atBackup, auditAtBackup)
			e.requireNoStaging()
		})
	}
	for _, point := range afterSwap {
		// A crash after the swap point, then the start of Alice (serve runs FinishInterruptedRestore with its pool).
		t.Run("serve/"+point, func(t *testing.T) {
			e := newRestoreEnv(t)
			atBackup, auditAtBackup, info := e.backupWithSnapshot()
			e.mutate()
			require.True(t, e.restoreCrashing(info.Path, point))
			applied, err := backup.FinishInterruptedRestore(e.ctx, e.db.App, e.keysDir, e.stateDir)
			require.NoError(t, err)
			assert.Equal(t, point == "renamed", applied, "the staged files are applied only when they were not yet")
			e.requireNoStaging()
			now := e.snapshot()
			for name, h := range atBackup.tables {
				if !slices.Contains(restoredExcept, name) {
					assert.Equal(t, h, now.tables[name], "table %s", name)
				}
			}
			assert.Equal(t, atBackup.files, now.files)
			assert.NotContains(t, now.dbs, dbName(t, e.db.OwnerURL)+"_restore")
			_, err = secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, e.keysDir, e.clk.Now())
			require.NoError(t, err, "the restored key opens the restored database")
			// The next restore removes the previous database the crash left.
			_, err = e.restore(info.Path, nil)
			require.NoError(t, err)
			e.requireRestored(atBackup, auditAtBackup)
		})
		t.Run("restore/"+point, func(t *testing.T) {
			e := newRestoreEnv(t)
			atBackup, auditAtBackup, info := e.backupWithSnapshot()
			e.mutate()
			require.True(t, e.restoreCrashing(info.Path, point))
			_, err := e.restore(info.Path, nil)
			require.NoError(t, err)
			e.requireRestored(atBackup, auditAtBackup)
			e.requireNoStaging()
		})
	}
}

// stage writes a staging directory as a restore would, with id as its restore ID.
func stage(t *testing.T, dir, id string, files map[string][]byte) {
	t.Helper()
	s := filepath.Join(dir, ".restore-staging")
	require.NoError(t, os.Mkdir(s, 0o700))
	var names []string
	for n, b := range files {
		require.NoError(t, os.WriteFile(filepath.Join(s, n), b, 0o400))
		names = append(names, n)
	}
	slices.Sort(names)
	require.NoError(t, os.WriteFile(filepath.Join(s, "FILES"), []byte(strings.Join(names, "\n")+"\n"), 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(s, "RESTORE_ID"), []byte(id+"\n"), 0o400))
}

func TestFinishIgnoresStaleStaging(t *testing.T) {
	e := newRestoreEnv(t)
	for name, liveID := range map[string]string{"no restore ID": "", "another restore ID": strings.Repeat("ab", 16)} {
		t.Run(name, func(t *testing.T) {
			if liveID != "" {
				require.NoError(t, settings.Set(e.ctx, e.db.Owner, "backup.restore_id", liveID, e.clk.Now()))
			}
			before := e.snapshot()
			stage(t, e.keysDir, strings.Repeat("cd", 16), map[string][]byte{"master.key": []byte("not the live key\n")})
			stage(t, e.stateDir, strings.Repeat("cd", 16), nil)
			applied, err := backup.FinishInterruptedRestore(e.ctx, e.db.App, e.keysDir, e.stateDir)
			require.NoError(t, err)
			assert.False(t, applied)
			e.requireNoStaging()
			requireUnchanged(t, before, e.snapshot())
		})
	}
	t.Run("matching restore ID", func(t *testing.T) {
		id := strings.Repeat("ef", 16)
		require.NoError(t, settings.Set(e.ctx, e.db.Owner, "backup.restore_id", id, e.clk.Now()))
		crt, err := os.ReadFile(filepath.Join(e.keysDir, "tls.crt"))
		require.NoError(t, err)
		stage(t, e.keysDir, id, map[string][]byte{"tls.crt": crt})
		stage(t, e.stateDir, id, nil)
		applied, err := backup.FinishInterruptedRestore(e.ctx, e.db.App, e.keysDir, e.stateDir)
		require.NoError(t, err)
		assert.True(t, applied)
		e.requireNoStaging()
		// Files the restore did not stage are removed: the key no longer matching tls.crt, and the time record of
		// the old master key.
		_, err = os.Stat(filepath.Join(e.keysDir, "tls.key"))
		assert.ErrorIs(t, err, os.ErrNotExist)
		_, err = os.Stat(filepath.Join(e.stateDir, license.HWMFileName))
		assert.ErrorIs(t, err, os.ErrNotExist)
		got, err := os.ReadFile(filepath.Join(e.keysDir, "tls.crt"))
		require.NoError(t, err)
		assert.Equal(t, crt, got)
		_, err = os.Stat(filepath.Join(e.keysDir, "master.key"))
		require.NoError(t, err, "the master key was not staged and not listed, so it would be removed only by a real restore; here it is kept")
	})
	t.Run("nothing staged", func(t *testing.T) {
		applied, err := backup.FinishInterruptedRestore(e.ctx, e.db.App, e.keysDir, e.stateDir)
		require.NoError(t, err)
		assert.False(t, applied)
	})
}

func TestCleanupNeverDropsTheOnlyCopy(t *testing.T) {
	// No <db> and a <db>_restore that never reached the swap (no staging carries its restore ID): an unverified
	// database is never made live, and never dropped (Task 5 review, minor 1). The restore refuses and leaves it.
	t.Run("unverified", func(t *testing.T) {
		e := newRestoreEnv(t)
		info := e.create(backup.KindManual)
		e.mutate()
		live := dbName(t, e.db.OwnerURL)
		before := e.snapshot()
		e.stop()
		e.renameDB(live, live+"_restore")

		_, err := backup.Restore(e.ctx, e.cfg, e.input(info.Path))
		require.ErrorIs(t, err, backup.ErrUnfinishedStaging)
		assert.Contains(t, err.Error(), live+"_restore")
		assert.Equal(t, []string{live + "_restore"}, e.databases(), "the only copy is neither renamed nor dropped")
		e.renameDB(live+"_restore", live)
		e.start()
		requireUnchanged(t, before, e.snapshot())
	})
	// The same with both staging directories of its restore ID (the restore reached "staged"): it is renamed, never
	// dropped, and its files are applied.
	t.Run("staged", func(t *testing.T) {
		e := newRestoreEnv(t)
		info := e.create(backup.KindManual)
		live := dbName(t, e.db.OwnerURL)
		id := strings.Repeat("ab", 16)
		require.NoError(t, settings.Set(e.ctx, e.db.Owner, "backup.restore_id", id, e.clk.Now()))
		crt, err := os.ReadFile(filepath.Join(e.keysDir, "tls.crt"))
		require.NoError(t, err)
		stage(t, e.keysDir, id, map[string][]byte{"tls.crt": crt})
		stage(t, e.stateDir, id, nil)
		e.stop()
		e.renameDB(live, live+"_restore")

		in := e.input(info.Path)
		backup.SetRestoreHook(&in, func(p string) error {
			if p == "cleaned" {
				return errors.New("stop after the cleanup")
			}
			return nil
		})
		_, err = backup.Restore(e.ctx, e.cfg, in)
		require.EqualError(t, err, "stop after the cleanup")
		assert.Equal(t, []string{live}, e.databases())
		e.requireNoStaging()
		_, err = os.Stat(filepath.Join(e.keysDir, "tls.key"))
		assert.ErrorIs(t, err, os.ErrNotExist, "the staged files were applied")
		e.start()
	})
}

func (e *env) renameDB(from, to string) {
	e.t.Helper()
	sp := e.superPool()
	defer sp.Close()
	_, err := sp.Exec(e.ctx, "ALTER DATABASE "+pgx.Identifier{from}.Sanitize()+" RENAME TO "+pgx.Identifier{to}.Sanitize())
	require.NoError(e.t, err)
}

// I-1 (Task 5 review): the COMMIT of the rename transaction reaches the server but its reply is lost. Restore fails,
// but it must not remove the staging of a swap that happened: the restore ID decides, at the next start or restore.
func TestRestoreSurvivesALostCommitReply(t *testing.T) {
	for _, next := range []string{"serve", "restore"} {
		t.Run("committed/"+next, func(t *testing.T) {
			e := newRestoreEnv(t)
			atBackup, auditAtBackup, info := e.backupWithSnapshot()
			e.mutate()
			in := e.input(info.Path)
			backup.SetCommit(&in, func(ctx context.Context, tx pgx.Tx) error {
				if err := tx.Commit(ctx); err != nil {
					return err
				}
				return errors.New("connection reset while reading the reply")
			})
			_, err := e.restoreWith(in)
			require.Error(t, err)
			for _, d := range []string{e.keysDir, e.stateDir} {
				_, err := os.Stat(filepath.Join(d, ".restore-staging", "RESTORE_ID"))
				require.NoError(t, err, "the staging of a swap that may have happened is kept")
			}
			if next == "serve" {
				applied, err := backup.FinishInterruptedRestore(e.ctx, e.db.App, e.keysDir, e.stateDir)
				require.NoError(t, err)
				assert.True(t, applied, "the swap happened, so its staged files are applied")
				_, err = secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, e.keysDir, e.clk.Now())
				require.NoError(t, err, "the restored key opens the restored database")
			}
			_, err = e.restore(info.Path, nil)
			require.NoError(t, err)
			e.requireRestored(atBackup, auditAtBackup)
			e.requireNoStaging()
		})
	}
	t.Run("not committed", func(t *testing.T) {
		e := newRestoreEnv(t)
		atBackup, auditAtBackup, info := e.backupWithSnapshot()
		e.mutate()
		before := e.snapshot()
		in := e.input(info.Path)
		backup.SetCommit(&in, func(ctx context.Context, tx pgx.Tx) error {
			_ = tx.Rollback(ctx)
			return errors.New("connection reset before the commit")
		})
		_, err := e.restoreWith(in)
		require.Error(t, err)
		applied, err := backup.FinishInterruptedRestore(e.ctx, e.db.App, e.keysDir, e.stateDir)
		require.NoError(t, err)
		assert.False(t, applied)
		e.requireNoStaging()
		for p, h := range before.files {
			assert.Equal(t, h, e.snapshot().files[p], "live file %s", p)
		}
		_, err = secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, e.keysDir, e.clk.Now())
		require.NoError(t, err)
		_, err = e.restore(info.Path, nil)
		require.NoError(t, err)
		e.requireRestored(atBackup, auditAtBackup)
	})
}

// I-2 (Task 5 review): a second restore of the same database while one runs fails fast and touches nothing.
func TestConcurrentRestoresAreRefused(t *testing.T) {
	e := newRestoreEnv(t)
	atBackup, auditAtBackup, info := e.backupWithSnapshot()
	e.mutate()
	in := e.input(info.Path)
	var second error
	ran := false
	backup.SetRestoreHook(&in, func(p string) error {
		if p == "previous" {
			ran = true
			_, second = backup.Restore(e.ctx, e.cfg, e.input(info.Path))
		}
		return nil
	})
	_, err := e.restoreWith(in)
	require.NoError(t, err)
	require.True(t, ran)
	require.ErrorIs(t, second, backup.ErrRestoreRunning)
	e.requireRestored(atBackup, auditAtBackup)
	e.requireNoStaging()
}

// I-2 (Task 5 review): when the swap happened but no staged file was applied (the staging vanished), the previous
// database is kept and the restore fails naming it, instead of reporting success.
func TestSwapKeepsThePreviousDatabaseWhenNoFileWasApplied(t *testing.T) {
	e := newRestoreEnv(t)
	_, _, info := e.backupWithSnapshot()
	e.mutate()
	in := e.input(info.Path)
	backup.SetRestoreHook(&in, func(p string) error {
		if p == "previous" {
			require.NoError(t, os.RemoveAll(filepath.Join(e.keysDir, ".restore-staging")))
			require.NoError(t, os.RemoveAll(filepath.Join(e.stateDir, ".restore-staging")))
		}
		return nil
	})
	_, err := e.restoreWith(in)
	require.Error(t, err)
	prefix := dbName(t, e.db.OwnerURL) + "_previous_"
	assert.Contains(t, err.Error(), prefix)
	var kept []string
	for _, n := range e.databases() {
		if strings.HasPrefix(n, prefix) {
			kept = append(kept, n)
		}
	}
	require.Len(t, kept, 1, "the previous database is kept")
	assert.Contains(t, err.Error(), kept[0])
}

// Minor 3 (Task 5 review): the key check is that of the newest key version, not of version 1.
func TestRestoreChecksTheCurrentKeyVersion(t *testing.T) {
	e := newRestoreEnv(t)
	k2 := make([]byte, 32)
	_, _ = rand.Read(k2)
	kr2, err := secrets.NewKeyring(2, k2)
	require.NoError(t, err)
	check, err := kr2.KeyCheck()
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "INSERT INTO master_key_versions (version, key_check, created_at) VALUES (2, $1, $2)", check, e.clk.Now())
	require.NoError(t, err)
	var at time.Time
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT installed_at FROM license WHERE id = 1").Scan(&at))
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE license SET installation_seal = $1 WHERE id = 1", backup.InstallationSeal(kr2, e.installationID, at))
	require.NoError(t, err)
	p := filepath.Join(e.keysDir, "master.key")
	require.NoError(t, os.Remove(p))
	require.NoError(t, os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(k2)+"\n"), 0o400))
	info := e.create(backup.KindManual)

	_, _, err = e.restoreElsewhere(info.Path, e.createDB(uniqueName("rotated_")), nil)
	require.NoError(t, err)
}

func TestRestoreRefusesWhileTheDatabaseIsInUse(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	before, backups := e.snapshot(), e.files()
	e.clk.Advance(time.Minute)
	e.stop()
	conn, err := pgx.Connect(e.ctx, e.db.AppURL)
	require.NoError(t, err)
	_, err = backup.Restore(e.ctx, e.cfg, e.input(info.Path))
	require.ErrorIs(t, err, backup.ErrDatabaseInUse)
	require.NoError(t, conn.Close(e.ctx))
	e.start()
	e.requireNothingChanged(before, backups)
}

func TestRestoreWaitsForALeftoverSession(t *testing.T) {
	e := newRestoreEnv(t)
	atBackup, auditAtBackup, info := e.backupWithSnapshot()
	e.stop()
	conn, err := pgx.Connect(e.ctx, e.db.AppURL)
	require.NoError(t, err)
	go func() {
		time.Sleep(3 * time.Second)
		_ = conn.Close(context.Background())
	}()
	e.start()
	_, err = e.restore(info.Path, func(in *backup.RestoreInput) { in.WaitForSessions = 10 * time.Second })
	require.NoError(t, err)
	e.requireRestored(atBackup, auditAtBackup)
}

func TestRestoreOnAnEmptyServerNeedsOnlyThePassphrase(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	h, err := format.ReadHeader(mustOpen(t, info.Path))
	require.NoError(t, err)
	o, res, err := e.restoreElsewhere(info.Path, e.createDB(uniqueName("empty_")), nil)
	require.NoError(t, err)
	assert.Empty(t, res.SafetyBackup, "an empty server has nothing to back up first")
	rows := o.auditRows("system.restored")
	require.Len(t, rows, 1)
	assert.Equal(t, "none", rows[0]["safety_backup"])
	assert.NotContains(t, rows[0], "previous_audit_seq")

	o.reload2()
	var w secrets.WrappedBackupKey
	found, err := settings.Get(e.ctx, o.db.Owner, "backup.key", &w)
	require.NoError(t, err)
	require.True(t, found)
	_, ok, err := o.keyring.GetSetting(e.ctx, o.db.App, "backup.sender")
	require.NoError(t, err)
	require.True(t, ok)
	e.clk.Advance(time.Hour)
	again := o.create(backup.KindManual)
	_, err = o.svc.VerifyDeep(e.ctx, again.Path, []byte(passphrase))
	require.NoError(t, err)
	h2, err := format.ReadHeader(mustOpen(t, again.Path))
	require.NoError(t, err)
	assert.Equal(t, h.WrappedKey.SenderPublicKey, h2.WrappedKey.SenderPublicKey)
	assert.Equal(t, h.Recipient, h2.Recipient)
}

// reload2 is reload for an env built by restoreElsewhere (no service yet).
func (e *env) reload2() {
	e.t.Helper()
	e.cfg.Audit = e.audit
	backup.SetStatfs(&e.cfg, func(string) (uint64, error) { return 100 << 30, nil })
	e.reload()
}

func mustOpen(t *testing.T, p string) *os.File {
	t.Helper()
	f, err := os.Open(p)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestRestoreKeepsTheNewerTimeRecord(t *testing.T) {
	e := newRestoreEnv(t)
	t0 := e.clk.Now().UTC().Truncate(time.Second)
	info := e.create(backup.KindManual)
	later := t0.Add(10 * 24 * time.Hour)
	e.writeTimeRecord(e.keyring, later, 7)
	_, err := e.restore(info.Path, nil)
	require.NoError(t, err)
	e.reload()
	fromDB, fromFile := e.timeRecords(e.keyring)
	assert.Equal(t, later, fromDB.At)
	assert.Equal(t, later, fromFile.At)
	assert.Greater(t, fromDB.Seq, uint64(7))
	assert.Equal(t, fromDB, fromFile)

	// On an empty host the backup's record is kept.
	o, _, err := e.restoreElsewhere(info.Path, e.createDB(uniqueName("hwm_")), nil)
	require.NoError(t, err)
	o.reload2()
	fromDB, fromFile = o.timeRecords(o.keyring)
	assert.Equal(t, t0, fromDB.At)
	assert.Equal(t, t0, fromFile.At)
	assert.Equal(t, uint64(1), fromDB.Seq)
}

// reframe re-encodes the frames of a real backup, letting edit change each frame (nil drops it) and add frames before
// the end frame.
func reframe(t *testing.T, e *env, path string, edit func(dump.Frame) *dump.Frame, extra ...dump.Frame) string {
	t.Helper()
	frames := payloadFrames(t, path)
	return forge(t, e, func(enc *dump.Encoder) {
		for _, f := range frames {
			if f.Kind == dump.End {
				for _, x := range extra {
					require.NoError(t, enc.Frame(x.Kind, x.Name, x.Data))
				}
			}
			if g := edit(f); g != nil {
				require.NoError(t, enc.Frame(g.Kind, g.Name, g.Data))
			}
		}
	})
}

func keep(f dump.Frame) *dump.Frame { return &f }

func TestRestoreRefusesUnknownFileFrames(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	master, err := os.ReadFile(filepath.Join(e.keysDir, "master.key"))
	require.NoError(t, err)
	parent := filepath.Dir(e.keysDir)
	for name, extra := range map[string]dump.Frame{
		"traversal": {Kind: dump.File, Name: "keys/../../x", Data: []byte("planted")},
		"unknown":   {Kind: dump.File, Name: "keys/other", Data: []byte("planted")},
		"repeated":  {Kind: dump.File, Name: "keys/master.key", Data: master},
	} {
		t.Run(name, func(t *testing.T) {
			p := reframe(t, e, info.Path, keep, extra)
			before, backups := e.snapshot(), e.files()
			_, err := e.restore(p, nil)
			require.ErrorIs(t, err, backup.ErrDamaged)
			e.requireNothingChanged(before, backups)
			for _, d := range []string{parent, filepath.Dir(parent), e.keysDir} {
				for _, n := range []string{"x", "other"} {
					_, err := os.Lstat(filepath.Join(d, n))
					assert.ErrorIs(t, err, os.ErrNotExist, "%s in %s", n, d)
				}
			}
		})
	}
}

func TestRestoreDropsAMismatchedTLSPair(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	other := pki.SelfSigned("other.example.test", pki.ECDSA256, e.clk.Now())
	p := reframe(t, e, info.Path, func(f dump.Frame) *dump.Frame {
		if f.Name == "keys/tls.key" {
			f.Data = other.KeyPEM
		}
		return &f
	})
	res, err := e.restore(p, nil)
	require.NoError(t, err)
	require.NotEmpty(t, res.Warnings)
	assert.Contains(t, strings.Join(res.Warnings, " "), "certificate")
	for _, n := range []string{"tls.crt", "tls.key"} {
		_, err := os.Stat(filepath.Join(e.keysDir, n))
		assert.ErrorIs(t, err, os.ErrNotExist, n)
	}
	_, err = os.Stat(filepath.Join(e.keysDir, "master.key"))
	require.NoError(t, err)
}

func TestRestoreWithoutBackupKeyNeedsTheFlag(t *testing.T) {
	src := newRestoreEnv(t)
	info := src.create(backup.KindManual)
	e := newEnv(t, false) // data, but no recovery passphrase
	before, backups := e.snapshot(), e.files()
	_, err := e.restore(info.Path, nil)
	require.ErrorIs(t, err, backup.ErrNoSafetyBackup)
	e.requireNothingChanged(before, backups)

	res, err := e.restore(info.Path, func(in *backup.RestoreInput) { in.NoSafetyBackup = true })
	require.NoError(t, err)
	assert.Empty(t, res.SafetyBackup)
	rows := e.auditRows("system.restored")
	require.Len(t, rows, 1)
	assert.Equal(t, "none", rows[0]["safety_backup"])
	assert.Equal(t, "true", rows[0]["no_safety_backup"])
}

func TestRestoreCleansUpAfterADatabaseError(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	before, backups := e.snapshot(), e.files()
	in := e.input(info.Path)
	backup.SetLoad(&in, func(ctx context.Context, conn *pgx.Conn, dec *dump.Decoder, first dump.Frame) (dump.Stats, error) {
		st, err := dump.Load(ctx, conn, dec, first)
		if err != nil {
			return st, err
		}
		return st, &pgconn.PgError{Code: "53100", Message: "could not extend file: No space left on device"}
	})
	_, err := e.restoreWith(in)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "53100", pe.Code)
	assert.NotErrorIs(t, err, backup.ErrDamaged)
	e.requireNothingChanged(before, backups)
}

func TestRestoreRefusesWithoutFreeSpace(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	before, backups := e.snapshot(), e.files()
	_, err := e.restore(info.Path, func(in *backup.RestoreInput) { in.FreeBytes = 1 << 20 })
	var ns *backup.ErrNoSpace
	require.ErrorAs(t, err, &ns)
	assert.Equal(t, int64(1<<20), ns.Free)
	assert.Greater(t, ns.Need, int64(1<<30))
	e.requireNothingChanged(before, backups)

	// Enough space: the check passes.
	_, err = e.restore(info.Path, func(in *backup.RestoreInput) { in.FreeBytes = 50 << 30 })
	require.NoError(t, err)
}

func TestRestoreWithANonSuperuserOwner(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	role, live := uniqueName("r_owner_"), uniqueName("r_live_")
	sp := e.superPool()
	for _, stmt := range []string{
		"CREATE ROLE " + role + " LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION PASSWORD 'r-owner-pw'",
		"GRANT SET ON PARAMETER session_replication_role TO " + role,
		"CREATE DATABASE " + live + " OWNER " + role,
	} {
		_, err := sp.Exec(e.ctx, stmt)
		require.NoError(t, err, stmt)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		p, err := db.Open(ctx, withDB(t, e.db.OwnerURL, "postgres", nil))
		if err != nil {
			return
		}
		defer p.Close()
		rows, _ := p.Query(ctx, "SELECT datname FROM pg_database WHERE starts_with(datname, $1)", live)
		names, _ := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, n := range names {
			_, _ = p.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{n}.Sanitize()+" WITH (FORCE)")
		}
		_, _ = p.Exec(ctx, "REVOKE SET ON PARAMETER session_replication_role FROM "+role)
		_, _ = p.Exec(ctx, "DROP ROLE IF EXISTS "+role)
	})
	ownerURL := withDB(t, e.db.OwnerURL, live, url.UserPassword(role, "r-owner-pw"))
	owner, err := db.Open(e.ctx, ownerURL)
	require.NoError(t, err)
	var isSuper bool
	require.NoError(t, owner.QueryRow(e.ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&isSuper))
	require.False(t, isSuper)
	require.NoError(t, db.Migrate(e.ctx, owner, migrations.FS))
	owner.Close()

	o, _, err := e.restoreElsewhere(info.Path, ownerURL, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, o.count("SELECT count(*) FROM audit_log WHERE action = 'system.restored'"))
	var dbOwner string
	require.NoError(t, o.db.Owner.QueryRow(e.ctx,
		"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()").Scan(&dbOwner))
	assert.Equal(t, role, dbOwner)
	rows, err := sp.Query(e.ctx, "SELECT datname FROM pg_database WHERE starts_with(datname, $1) ORDER BY 1", live)
	require.NoError(t, err)
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	assert.Equal(t, []string{live}, names, "the previous database was dropped at the end")
}

func TestDBOnlyKeepsFiles(t *testing.T) {
	e := newRestoreEnv(t)
	atBackup, _, info := e.backupWithSnapshot()
	e.mutate()
	filesBefore := e.snapshot().files
	res, err := e.restore(info.Path, func(in *backup.RestoreInput) { in.DBOnly = true })
	require.NoError(t, err)
	assert.NotEmpty(t, res.SafetyBackup)
	now := e.snapshot()
	assert.Equal(t, filesBefore, now.files, "a database-only restore leaves the key and state files")
	for name, h := range atBackup.tables {
		if !slices.Contains(restoredExcept, name) {
			assert.Equal(t, h, now.tables[name], "table %s", name)
		}
	}
	e.requireNoStaging()
	assert.Equal(t, []string{dbName(t, e.db.OwnerURL)}, now.dbs)

	// A backup of another installation (another master key) is refused: the live keys could not open it.
	other := newRestoreEnv(t).create(backup.KindManual)
	before, backups := e.snapshot(), e.files()
	_, err = e.restore(other.Path, func(in *backup.RestoreInput) { in.DBOnly = true })
	wantNotVerified(t, err)
	e.requireNothingChanged(before, backups)
}

func TestF97RestoreContinuesTheChain(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	var headSeq int64
	var headHash []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&headSeq, &headHash))
	res, err := e.restore(info.Path, nil)
	require.NoError(t, err)

	var action, actor string
	var details map[string]string
	var seq int64
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT seq, action, actor_name, details FROM audit_log ORDER BY seq DESC LIMIT 1").
		Scan(&seq, &action, &actor, &details))
	assert.Equal(t, "system.restored", action)
	assert.Equal(t, "cli", actor)
	assert.Equal(t, res.Manifest.AuditHead.Seq+1, seq, "system.restored follows the backup's head")
	assert.Equal(t, info.Name, details["backup_name"])
	assert.Equal(t, info.CreatedAt.UTC().Format(time.RFC3339), details["backup_created_at"])
	assert.Equal(t, "1.0.0", details["alice_version"])
	assert.Equal(t, fmt.Sprint(res.Manifest.SchemaVersion), details["schema_version"])
	assert.Equal(t, "true", details["audit_intact"])
	assert.Equal(t, fmt.Sprint(headSeq), details["previous_audit_seq"])
	assert.Equal(t, hex.EncodeToString(headHash), details["previous_audit_hash"])
	assert.Equal(t, filepath.Base(res.SafetyBackup), details["safety_backup"])
	assert.True(t, strings.HasSuffix(details["safety_backup"], "-pre-restore.alicebak"))
	assert.NotContains(t, details, "no_safety_backup")

	rep, err := audit.Verify(e.ctx, e.db.Owner)
	require.NoError(t, err)
	assert.True(t, rep.Intact)
	var next audit.Entry
	require.NoError(t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
		next, err = e.audit.Append(e.ctx, tx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.after_restore", Result: audit.Success})
		return err
	}))
	assert.Equal(t, seq+1, next.Seq)
}

func TestRestoreEndsSessions(t *testing.T) {
	e := newRestoreEnv(t)
	require.Positive(t, e.count("SELECT count(*) FROM sessions"), "the backup holds the administrator's session")
	info := e.create(backup.KindManual)
	_, err := e.restore(info.Path, nil)
	require.NoError(t, err)
	assert.Zero(t, e.count("SELECT count(*) FROM sessions"))
	assert.Zero(t, e.count("SELECT count(*) FROM setup_sessions"))
	assert.Zero(t, e.count("SELECT count(*) FROM oidc_login_states"))
}

func TestInstallationSealMatchesTheLicenseModule(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	k, err := secrets.LoadOrCreateMasterKey(ctx, d.App, t.TempDir(), clk.Now())
	require.NoError(t, err)
	lic := license.New(license.Config{Pool: d.App, Keyring: k, Audit: audit.New(clk), Clock: clk, Uptime: clk, Keys: license.NewKeySet()})
	require.NoError(t, lic.Start(ctx))
	defer lic.Close()
	var id string
	var at time.Time
	var seal []byte
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT installation_id, installed_at, installation_seal FROM license WHERE id = 1").Scan(&id, &at, &seal))
	assert.Equal(t, seal, backup.InstallationSeal(k, id, at))
}

// editManifest returns a frame editor that changes the manifest with edit and keeps every other frame.
func editManifest(t *testing.T, edit func(m map[string]any)) func(dump.Frame) *dump.Frame {
	return func(f dump.Frame) *dump.Frame {
		if f.Kind == dump.Manifest {
			var m map[string]any
			require.NoError(t, json.Unmarshal(f.Data, &m))
			edit(m)
			b, err := json.Marshal(m)
			require.NoError(t, err)
			f.Data = b
		}
		return &f
	}
}

// dropFile drops the F frame name and removes it from the manifest's file list.
func dropFile(t *testing.T, name string) func(dump.Frame) *dump.Frame {
	strip := editManifest(t, func(m map[string]any) {
		files := []any{}
		for _, f := range m["files"].([]any) {
			if f != name {
				files = append(files, f)
			}
		}
		m["files"] = files
	})
	return func(f dump.Frame) *dump.Frame {
		switch {
		case f.Kind == dump.File && f.Name == name:
			return nil
		case f.Kind == dump.End:
			var end map[string]int
			require.NoError(t, json.Unmarshal(f.Data, &end))
			end["files"]--
			b, err := json.Marshal(end)
			require.NoError(t, err)
			f.Data = b
		}
		return strip(f)
	}
}

func replaceFile(name string, data []byte) func(dump.Frame) *dump.Frame {
	return func(f dump.Frame) *dump.Frame {
		if f.Kind == dump.File && f.Name == name {
			f.Data = data
		}
		return &f
	}
}

func TestRestoreRefusesUnverifiableData(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	otherKey := []byte(base64.StdEncoding.EncodeToString(other) + "\n")
	for name, c := range map[string]struct {
		edit func(dump.Frame) *dump.Frame
		want func(*testing.T, error)
	}{
		"audit head":         {editManifest(t, func(m map[string]any) { m["audit_head"].(map[string]any)["seq"] = 1 }), wantNotVerified},
		"row counts":         {editManifest(t, func(m map[string]any) { m["tables"].(map[string]any)["users"] = 99 }), wantNotVerified},
		"another master key": {replaceFile("keys/master.key", otherKey), wantNotVerified},
		"no master key":      {dropFile(t, "keys/master.key"), wantNotVerified},
		"invalid master key": {replaceFile("keys/master.key", []byte("not a key\n")), wantNotVerified},
		"manifest not JSON": {func(f dump.Frame) *dump.Frame {
			if f.Kind == dump.Manifest {
				f.Data = []byte("{")
			}
			return &f
		}, wantDamaged},
		"manifest format 0":     {editManifest(t, func(m map[string]any) { m["format"] = 0 }), wantDamaged},
		"newer manifest format": {editManifest(t, func(m map[string]any) { m["format"] = 2 }), wantNewer},
		"files differ":          {editManifest(t, func(m map[string]any) { m["files"] = []any{"keys/master.key"} }), wantDamaged},
	} {
		t.Run(name, func(t *testing.T) {
			p := reframe(t, e, info.Path, c.edit)
			before, backups := e.snapshot(), e.files()
			_, err := e.restore(p, nil)
			c.want(t, err)
			e.requireNothingChanged(before, backups)
		})
	}
	t.Run("installation seal", func(t *testing.T) {
		e := newRestoreEnv(t)
		_, err := e.db.Owner.Exec(e.ctx, "UPDATE license SET installation_seal = decode(repeat('00', 32), 'hex')")
		require.NoError(t, err)
		info := e.create(backup.KindManual)
		before, backups := e.snapshot(), e.files()
		_, err = e.restore(info.Path, nil)
		wantNotVerified(t, err)
		assert.Contains(t, err.Error(), "seal")
		e.requireNothingChanged(before, backups)
	})
}

func wantNotVerified(t *testing.T, err error) {
	t.Helper()
	var nv *backup.ErrNotVerified
	require.ErrorAs(t, err, &nv)
	assert.NotEmpty(t, nv.Reason)
}

func wantDamaged(t *testing.T, err error) { t.Helper(); require.ErrorIs(t, err, backup.ErrDamaged) }

func wantNewer(t *testing.T, err error) {
	t.Helper()
	var en *backup.ErrNewer
	require.ErrorAs(t, err, &en)
}

func TestRestoreKeepsWhatItCanOfDamagedOptionalFiles(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	dbRecord, _ := e.timeRecords(e.keyring)

	// Only the certificate: the pair is incomplete and dropped.
	res, err := e.restore(reframe(t, e, info.Path, dropFile(t, "keys/tls.key")), nil)
	require.NoError(t, err)
	assert.Len(t, res.Warnings, 1)
	_, err = os.Stat(filepath.Join(e.keysDir, "tls.crt"))
	assert.ErrorIs(t, err, os.ErrNotExist)

	// A time record file that does not verify: the database's copy is staged instead.
	res, err = e.restore(reframe(t, e, info.Path, replaceFile("state/hwm.dat", []byte(`{"v":1,"data":"x","mac":"y"}`))), nil)
	require.NoError(t, err)
	require.Len(t, res.Warnings, 1)
	assert.Contains(t, res.Warnings[0], "time record")
	e.reload()
	fromDB, fromFile := e.timeRecords(e.keyring)
	assert.Equal(t, dbRecord, fromDB)
	assert.Equal(t, dbRecord, fromFile)
}

func TestRestoreCancelled(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	before, backups := e.snapshot(), e.files()
	var shown backup.Manifest
	_, err := e.restore(info.Path, func(in *backup.RestoreInput) {
		in.Confirm = func(m backup.Manifest) bool { shown = m; return false }
	})
	require.ErrorIs(t, err, backup.ErrCancelled)
	e.requireNothingChanged(before, backups)
	assert.Equal(t, e.installationID, shown.InstallationID, "the confirmation shows the verified manifest")
	assert.Equal(t, hostname, shown.Hostname)
	assert.Equal(t, info.CreatedAt, shown.CreatedAt)
}

func TestRestoreRefusesBadInput(t *testing.T) {
	e := newRestoreEnv(t)
	info := e.create(backup.KindManual)
	before, backups := e.snapshot(), e.files()
	_, err := e.restore(filepath.Join(t.TempDir(), "missing.alicebak"), nil)
	require.ErrorIs(t, err, backup.ErrNotFound)
	for name, u := range map[string]string{
		"not a URL":        "postgres://%zz",
		"maintenance name": withDB(t, e.db.OwnerURL, "postgres", nil),
		"name too long":    withDB(t, e.db.OwnerURL, strings.Repeat("a", 38), nil),
	} {
		_, err := e.restore(info.Path, func(in *backup.RestoreInput) { in.OwnerURL = u })
		require.Error(t, err, name)
		assert.NotContains(t, err.Error(), "s3cret", "no password in the error")
	}
	_, err = e.restore(info.Path, func(in *backup.RestoreInput) {
		in.Passphrase = nil
		in.AskPassphrase = func() ([]byte, error) { return nil, errors.New("no terminal") }
	})
	require.EqualError(t, err, "no terminal")
	e.requireNothingChanged(before, backups)
}
