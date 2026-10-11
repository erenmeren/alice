//go:build integration

package backup_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/backup"
	"alice/internal/backup/dump"
	"alice/internal/backup/format"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/tlscert"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/pki"
	"alice/locales"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

const (
	passphrase = "a long and safe recovery passphrase for the tests"
	hostname   = "alice-host.example.test"
)

// fastKDF is the cheapest KDF the backup header accepts (format.MinKDFMemoryKiB).
var fastKDF = secrets.KDFParams{MemoryKiB: format.MinKDFMemoryKiB, Time: 1, Threads: 1}

type env struct {
	t                          *testing.T
	ctx                        context.Context
	db                         *pgtest.DB
	clk                        *clock.Fake
	keyring                    *secrets.Keyring
	audit                      *audit.Log
	cfg                        backup.Config
	svc                        *backup.Service
	dir, keysDir, stateDir     string
	installationID, totpSecret string
	setup                      *setup.Service
	auth                       *auth.Service
}

var hwmFixture = []byte("alice-time-record-fixture\x00\x01\x02")

// newEnv builds an installation with an Administrator (with an e-mail address and MFA), the recovery passphrase,
// a master key, a temporary HTTPS certificate, a time record and a license row, and a backup service on it.
func newEnv(t *testing.T, withPassphrase bool) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), db: pgtest.New(t), clk: clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)),
		dir: t.TempDir(), keysDir: t.TempDir(), stateDir: t.TempDir()}
	var err error
	e.keyring, err = secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, e.keysDir, e.clk.Now())
	require.NoError(t, err)
	_, err = tlscert.EnsureSelfSigned(e.keysDir, []string{"alice.example.test"}, e.clk.Now())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(e.stateDir, license.HWMFileName), hwmFixture, 0o600))
	e.audit = audit.New(e.clk)
	e.installationID = license.NewInstallationID()
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at, installation_seal)
VALUES (1, $1, $2, 'evaluation', $2, $3)`, e.installationID, e.clk.Now(), bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)

	h := auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	e.auth = auth.NewService(auth.Config{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clk, Hasher: h, RecoveryHasher: h})
	e.setup = setup.New(setup.Config{Pool: e.db.App, Auth: e.auth, Keyring: e.keyring, Audit: e.audit, Clock: e.clk, Hasher: h, BackupKDF: fastKDF})
	code, err := e.setup.ResetToken(e.ctx)
	require.NoError(t, err)
	meta := auth.Meta{RequestID: "env"}
	token, err := e.setup.StartSession(e.ctx, code, meta)
	require.NoError(t, err)
	enr, err := e.setup.BeginAdminEnrollment(e.ctx, token, setup.AdminInput{Username: "admin", DisplayName: "Ayşe Yılmaz",
		Email: "ayse@example.com", Password: "correct horse battery staple"})
	require.NoError(t, err)
	e.totpSecret = enr.Secret
	totpCode, err := totp.GenerateCode(enr.Secret, e.clk.Now())
	require.NoError(t, err)
	res, err := e.setup.CreateAdmin(e.ctx, token, totpCode, meta)
	require.NoError(t, err)
	if withPassphrase {
		p, err := e.auth.Authenticate(e.ctx, res.Token)
		require.NoError(t, err)
		require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, meta, passphrase, passphrase))
	}
	e.cfg = backup.Config{Pool: e.db.App, Audit: e.audit, Notifier: notify.AdminNotifier{Clock: e.clk}, Clock: e.clk, Dir: e.dir,
		KeysDir: e.keysDir, StateDir: e.stateDir, Version: "1.0.0", Hostname: func() (string, error) { return hostname, nil },
		Keyring: e.keyring}
	backup.SetStatfs(&e.cfg, func(string) (uint64, error) { return 100 << 30, nil })
	e.svc = backup.New(e.cfg)
	return e
}

// rebuild makes a new service from e.cfg (after a hook changed it), as a restart would.
func (e *env) rebuild() { e.svc = backup.New(e.cfg) }

func (e *env) completeSetup() {
	e.t.Helper()
	require.NoError(e.t, settings.Set(e.ctx, e.db.Owner, "setup.completed_at", e.clk.Now().UTC().Format(time.RFC3339), e.clk.Now()))
}

func (e *env) state() backup.State {
	e.t.Helper()
	st, err := e.svc.State(e.ctx)
	require.NoError(e.t, err)
	return st
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, sql, args...).Scan(&n))
	return n
}

func (e *env) auditRows(action string) []map[string]string {
	e.t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, "SELECT details FROM audit_log WHERE action = $1 ORDER BY seq", action)
	require.NoError(e.t, err)
	var out []map[string]string
	for rows.Next() {
		var d map[string]string
		require.NoError(e.t, rows.Scan(&d))
		out = append(out, d)
	}
	require.NoError(e.t, rows.Err())
	return out
}

func (e *env) outbox(template string) int {
	return e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = $1", template)
}

func (e *env) files() []string {
	e.t.Helper()
	entries, err := os.ReadDir(e.dir)
	require.NoError(e.t, err)
	var names []string
	for _, en := range entries {
		names = append(names, en.Name())
	}
	return names
}

func (e *env) create(kind backup.Kind) backup.Info {
	e.t.Helper()
	info, err := e.svc.Create(e.ctx, backup.CreateInput{Kind: kind, Actor: audit.SystemActor("test")})
	require.NoError(e.t, err)
	return info
}

func TestCreateWritesAVerifiedFile(t *testing.T) {
	e := newEnv(t, true)
	var headSeq int64
	var headHash []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&headSeq, &headHash))
	tables, err := dump.Tables(e.ctx, e.db.App)
	require.NoError(t, err)
	counts, err := dump.Counts(e.ctx, e.db.App, tables)
	require.NoError(t, err)

	info, err := e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Reason: "before the firewall change", Actor: audit.SystemActor("cli")})
	require.NoError(t, err)
	want, err := backup.FileName(e.installationID, e.clk.Now(), backup.KindManual)
	require.NoError(t, err)
	assert.Equal(t, want, info.Name)
	assert.Equal(t, filepath.Join(e.dir, want), info.Path)
	assert.Equal(t, backup.KindManual, info.Kind)
	assert.Equal(t, "1.0.0", info.AliceVersion)
	assert.Equal(t, e.clk.Now(), info.CreatedAt)
	assert.Equal(t, "ok", info.Check)
	assert.ElementsMatch(t, []string{want, want + ".sha256"}, e.files(), "no partial file remains")
	for _, name := range e.files() {
		fi, err := os.Stat(filepath.Join(e.dir, name))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), name)
		if name == want {
			assert.Equal(t, fi.Size(), info.Size)
		}
	}
	raw, err := os.ReadFile(info.Path)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	sumFile, err := os.ReadFile(info.Path + ".sha256")
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(sum[:])+"  "+want+"\n", string(sumFile))

	v, err := e.svc.Verify(e.ctx, info.Path)
	require.NoError(t, err)
	assert.Equal(t, "ok", v.Check)

	m, err := e.svc.VerifyDeep(e.ctx, info.Path, []byte(passphrase))
	require.NoError(t, err)
	assert.Equal(t, counts, m.Tables)
	assert.Equal(t, backup.AuditHead{Seq: headSeq, Hash: hex.EncodeToString(headHash)}, m.AuditHead, "the head before backup.created")
	assert.Equal(t, e.installationID, m.InstallationID)
	assert.Equal(t, hostname, m.Hostname)
	assert.Equal(t, []string{"keys/master.key", "keys/tls.crt", "keys/tls.key", "state/hwm.dat"}, m.Files)
	assert.Equal(t, backup.KindManual, m.Kind)
	assert.Equal(t, "before the firewall change", m.Reason)
	assert.Equal(t, "1.0.0", m.AliceVersion)
	assert.Equal(t, 1, m.Format)
	latest, err := db.SchemaVersion(e.ctx, e.db.App)
	require.NoError(t, err)
	assert.Equal(t, latest, m.SchemaVersion)

	files := payloadFiles(t, info.Path)
	for name, path := range map[string]string{"keys/master.key": filepath.Join(e.keysDir, secrets.MasterKeyFile),
		"keys/tls.crt": filepath.Join(e.keysDir, "tls.crt"), "keys/tls.key": filepath.Join(e.keysDir, "tls.key"),
		"state/hwm.dat": filepath.Join(e.stateDir, license.HWMFileName)} {
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, b, files[name], name)
	}

	rows := e.auditRows("backup.created")
	require.Len(t, rows, 1)
	assert.Equal(t, map[string]string{"name": want, "kind": "manual", "size": fmt.Sprint(info.Size), "reason": "before the firewall change"}, rows[0])
	st := e.state()
	assert.Equal(t, e.clk.Now(), st.LastSuccessAt)
	assert.Equal(t, want, st.LastSuccessName)
	assert.True(t, st.LastAutoSuccessAt.IsZero(), "a manual backup is not the daily one")

	_, err = e.svc.VerifyDeep(e.ctx, info.Path, []byte("the wrong passphrase, long enough"))
	require.ErrorIs(t, err, backup.ErrDamaged)
}

// payloadFiles decrypts the backup with the test passphrase and returns its F frames.
func payloadFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, f := range payloadFrames(t, path) {
		if f.Kind == dump.File {
			out[f.Name] = f.Data
		}
	}
	return out
}

func payloadFrames(t *testing.T, path string) []dump.Frame {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	r, _, err := format.Open(bufio.NewReader(f), []byte(passphrase))
	require.NoError(t, err)
	gz, err := gzip.NewReader(r)
	require.NoError(t, err)
	dec := dump.NewDecoder(gz)
	var frames []dump.Frame
	for {
		fr, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		frames = append(frames, fr)
	}
	_, err = io.Copy(io.Discard, r)
	require.NoError(t, err)
	return frames
}

func TestCreateLeavesOutMissingOptionalFiles(t *testing.T) {
	e := newEnv(t, true)
	require.NoError(t, os.Remove(filepath.Join(e.keysDir, "tls.crt")))
	require.NoError(t, os.Remove(filepath.Join(e.keysDir, "tls.key")))
	require.NoError(t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName)))
	info := e.create(backup.KindManual)
	m, err := e.svc.VerifyDeep(e.ctx, info.Path, []byte(passphrase))
	require.NoError(t, err)
	assert.Equal(t, []string{"keys/master.key"}, m.Files)
}

func TestCreateLeavesOutAMismatchedTLSPair(t *testing.T) {
	e := newEnv(t, true)
	other := t.TempDir()
	_, err := tlscert.EnsureSelfSigned(other, []string{"other.example.test"}, e.clk.Now())
	require.NoError(t, err)
	key, err := os.ReadFile(filepath.Join(other, "tls.key"))
	require.NoError(t, err)
	require.NoError(t, os.Chmod(filepath.Join(e.keysDir, "tls.key"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(e.keysDir, "tls.key"), key, 0o600))
	info := e.create(backup.KindManual)
	m, err := e.svc.VerifyDeep(e.ctx, info.Path, []byte(passphrase))
	require.NoError(t, err)
	assert.Equal(t, []string{"keys/master.key", "state/hwm.dat"}, m.Files, "a pair that does not match is left out (S-14)")
}

func TestCreateRefusesOversizedFiles(t *testing.T) {
	e := newEnv(t, true)
	require.NoError(t, os.WriteFile(filepath.Join(e.stateDir, license.HWMFileName), make([]byte, dump.MaxData+1), 0o600))
	_, err := e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
	require.ErrorIs(t, err, backup.ErrWrite)
	assert.Equal(t, "file_too_large", e.state().LastErrorCode)
	assert.Empty(t, e.files())
}

func TestCreateNeedsTheRecoveryPassphrase(t *testing.T) {
	e := newEnv(t, false)
	_, err := e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
	require.ErrorIs(t, err, backup.ErrNotConfigured)
	assert.Empty(t, e.files())
	assert.Equal(t, "not_configured", e.state().LastErrorCode)
}

func TestCreateRefusesV1BackupKey(t *testing.T) {
	cases := map[string]func(e *env){
		"version 1 key": func(e *env) {
			var w secrets.WrappedBackupKey
			_, err := settings.Get(e.ctx, e.db.Owner, "backup.key", &w)
			require.NoError(t, err)
			w.Version = 1
			require.NoError(t, settings.Set(e.ctx, e.db.Owner, "backup.key", w, e.clk.Now()))
		},
		"sender key missing": func(e *env) {
			require.NoError(t, secrets.DeleteSetting(e.ctx, e.db.Owner, "backup.sender"))
		},
		"sender key of another backup key": func(e *env) {
			_, other, err := secrets.NewBackupKey([]byte(passphrase), fastKDF)
			require.NoError(t, err)
			require.NoError(t, e.keyring.PutSetting(e.ctx, e.db.Owner, "backup.sender", secrets.NewPlaintext(other.Bytes()), e.clk.Now()))
		},
		"sender key is not a key": func(e *env) {
			require.NoError(t, e.keyring.PutSetting(e.ctx, e.db.Owner, "backup.sender", secrets.NewPlaintext([]byte("short")), e.clk.Now()))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, true)
			change(e)
			_, err := e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
			require.ErrorIs(t, err, backup.ErrNotConfigured)
			assert.Empty(t, e.files())
			assert.Equal(t, "not_configured", e.state().LastErrorCode)
			assert.Len(t, e.auditRows("backup.failed"), 1)
		})
	}
}

func TestCreateRefusesWhenTheDiskIsNearlyFull(t *testing.T) {
	e := newEnv(t, true)
	first := e.create(backup.KindManual)
	need := uint64(2*first.Size) + 1<<30
	free := need - 1
	opened := 0
	backup.SetStatfs(&e.cfg, func(dir string) (uint64, error) {
		assert.Equal(t, e.dir, dir)
		return free, nil
	})
	backup.SetCreate(&e.cfg, func(path string) (backup.WriteFile, error) {
		opened++
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	})
	e.rebuild()
	e.clk.Advance(time.Minute)
	_, err := e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
	require.ErrorIs(t, err, backup.ErrWrite)
	assert.Zero(t, opened, "no .partial was ever opened")
	assert.Equal(t, "disk_full", e.state().LastErrorCode)
	failed := e.auditRows("backup.failed")
	require.Len(t, failed, 1)
	assert.Equal(t, map[string]string{"kind": "manual", "error_code": "disk_full"}, failed[0])
	fb, err := e.svc.FreeBytes()
	require.NoError(t, err)
	assert.Equal(t, free, fb)

	free = need
	e.clk.Advance(time.Minute)
	e.create(backup.KindManual)
	assert.Equal(t, 2, opened, "the backup and its checksum file")
}

func TestFreeBytesOfTheRealDirectory(t *testing.T) {
	e := newEnv(t, true)
	cfg := e.cfg
	backup.SetStatfs(&cfg, nil)
	fb, err := backup.New(cfg).FreeBytes()
	require.NoError(t, err)
	assert.Positive(t, fb)
	cfg.Dir = filepath.Join(e.dir, "missing")
	_, err = backup.New(cfg).FreeBytes()
	require.Error(t, err)
}

func TestOneBackupAtATime(t *testing.T) {
	e := newEnv(t, true)
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	backup.SetInDump(e.svc, func() {
		once.Do(func() {
			close(held)
			<-release
		})
	})
	done := make(chan error)
	go func() {
		_, err := e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
		done <- err
	}()
	<-held
	other := backup.New(e.cfg) // another process
	_, err := other.Create(e.ctx, backup.CreateInput{Kind: backup.KindAuto, Actor: audit.SystemActor("scheduler")})
	require.ErrorIs(t, err, backup.ErrRunning)
	_, err = e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindAuto, Actor: audit.SystemActor("scheduler")})
	require.ErrorIs(t, err, backup.ErrRunning)
	close(release)
	require.NoError(t, <-done)
	assert.Empty(t, e.auditRows("backup.failed"), "a refused second backup is not a failure")
	e.clk.Advance(time.Minute)
	_, err = other.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
	require.NoError(t, err, "the lock is released")
}

// failingFile fails every write after limit bytes with ENOSPC.
type failingFile struct {
	*os.File
	limit int
}

func (f *failingFile) Write(p []byte) (int, error) {
	if len(p) > f.limit {
		n, _ := f.File.Write(p[:f.limit])
		f.limit = 0
		return n, &os.PathError{Op: "write", Path: f.Name(), Err: syscall.ENOSPC}
	}
	f.limit -= len(p)
	return f.File.Write(p)
}

func snapshotDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, en := range entries {
		b, err := os.ReadFile(filepath.Join(dir, en.Name()))
		require.NoError(t, err)
		out[en.Name()] = b
	}
	return out
}

func TestF70DiskFullLeavesNothing(t *testing.T) {
	e := newEnv(t, true)
	// Enough rows that the payload is larger than 100 KiB.
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO jobs (id, type, class, kind, payload, payload_mac, status, run_at, max_attempts, created_at)
SELECT gen_random_uuid(), 'test.job', 'always', 'system', jsonb_build_object('pad', md5(g::text) || md5((g * 7)::text)), decode(repeat('07', 32), 'hex'),
'queued', now(), 3, now() FROM generate_series(1, 20000) g`)
	require.NoError(t, err)
	e.create(backup.KindManual)
	e.clk.Advance(time.Hour)
	e.create(backup.KindAuto)
	before := snapshotDir(t, e.dir)
	require.Len(t, before, 4)
	failuresBefore := e.state().ConsecutiveFailures

	for _, limit := range []int{0, 100 << 10} {
		backup.SetCreate(&e.cfg, func(path string) (backup.WriteFile, error) {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, err
			}
			return &failingFile{File: f, limit: limit}, nil
		})
		e.rebuild()
		e.clk.Advance(time.Hour)
		_, err = e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
		require.ErrorIs(t, err, backup.ErrWrite)
		assert.Equal(t, before, snapshotDir(t, e.dir), "no file of that name, no .partial, the earlier backups untouched")
		st := e.state()
		assert.Equal(t, "disk_full", st.LastErrorCode)
		failuresBefore++
		assert.Equal(t, failuresBefore, st.ConsecutiveFailures)
	}
	assert.Len(t, e.auditRows("backup.failed"), 2)

	// The checksum file fails: the backup it belongs to is removed too.
	backup.SetCreate(&e.cfg, func(path string) (backup.WriteFile, error) {
		if strings.HasSuffix(path, ".sha256.partial") {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ENOSPC}
		}
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	})
	e.rebuild()
	e.clk.Advance(time.Hour)
	_, err = e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
	require.ErrorIs(t, err, backup.ErrWrite)
	assert.Equal(t, before, snapshotDir(t, e.dir))
}

func TestCreateRefusesAnExistingName(t *testing.T) {
	e := newEnv(t, true)
	in := backup.CreateInput{Kind: backup.KindManual, Out: "before-firewall-change.alicebak", Actor: audit.SystemActor("cli")}
	info, err := e.svc.Create(e.ctx, in)
	require.NoError(t, err)
	assert.Equal(t, "before-firewall-change.alicebak", info.Name)
	before := snapshotDir(t, e.dir)
	_, err = e.svc.Create(e.ctx, in)
	require.ErrorIs(t, err, backup.ErrWrite)
	assert.Equal(t, before, snapshotDir(t, e.dir), "an existing backup is never replaced")

	for _, bad := range []backup.CreateInput{
		{Kind: backup.KindManual, Out: "../escape.alicebak"},
		{Kind: backup.KindManual, Out: ".hidden.alicebak"},
		{Kind: "weekly"},
		{Kind: backup.KindManual, Reason: "two\nlines"},
		{Kind: backup.KindManual, Reason: strings.Repeat("x", 201)},
	} {
		_, err := e.svc.Create(e.ctx, bad)
		require.Error(t, err)
		assert.NotErrorIs(t, err, backup.ErrRunning)
	}
	assert.Equal(t, before, snapshotDir(t, e.dir))
}

func TestF86BackupWhileJobsRun(t *testing.T) {
	e := newEnv(t, true)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				require.NoError(t, db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
					if _, err := tx.Exec(e.ctx, `INSERT INTO jobs (id, type, class, kind, payload, payload_mac, status, run_at, max_attempts, created_at)
VALUES ($1, 'test.job', 'always', 'system', '{}', $2, 'queued', now(), 3, now())`, uuid.New(), bytes.Repeat([]byte{7}, 32)); err != nil {
						return err
					}
					_, err := e.audit.Append(e.ctx, tx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.concurrent", Result: audit.Success})
					return err
				}))
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	info, err := e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
	close(stop)
	wg.Wait()
	require.NoError(t, err)

	m, err := e.svc.VerifyDeep(e.ctx, info.Path, []byte(passphrase))
	require.NoError(t, err)
	rows := map[string]int64{}
	for _, f := range payloadFrames(t, info.Path) {
		if f.Kind == dump.TableEnd {
			var end struct{ Rows int64 }
			require.NoError(t, json.Unmarshal(f.Data, &end))
			rows[f.Name] = end.Rows
		}
	}
	assert.Equal(t, m.Tables, rows)
	assert.Greater(t, int64(e.count("SELECT count(*) FROM jobs")), m.Tables["jobs"], "jobs were inserted after the snapshot")
}

func TestF87NoPlaintextInTheFile(t *testing.T) {
	e := newEnv(t, true)
	ctx := e.ctx
	who := audit.SystemActor("test")
	smtpPassword := "smtp-canary-" + uuid.NewString()
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	ns := notify.NewSettings(notify.SettingsConfig{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clk, Catalog: cat})
	pw := secrets.NewPlaintext([]byte(smtpPassword))
	_, err = ns.SaveSMTP(ctx, who, 0, notify.SMTPInput{Host: "mail.example.com", Port: 587, TLSMode: notify.TLSModeSTARTTLS,
		From: "alice@example.com", Username: "alice", Password: &pw})
	require.NoError(t, err)
	oidcSecret := "oidc-canary-" + uuid.NewString()
	require.NoError(t, e.keyring.PutSetting(ctx, e.db.App, "sso.provider."+uuid.NewString()+".client_secret",
		secrets.NewPlaintext([]byte(oidcSecret)), e.clk.Now()))
	managedKey := uploadCertificate(t, e)

	masterRaw, err := os.ReadFile(filepath.Join(e.keysDir, secrets.MasterKeyFile))
	require.NoError(t, err)
	masterKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(masterRaw)))
	require.NoError(t, err)
	senderPT, ok, err := e.keyring.GetSetting(ctx, e.db.App, "backup.sender")
	require.NoError(t, err)
	require.True(t, ok)
	sender := bytes.Clone(senderPT.Bytes())

	info := e.create(backup.KindManual)
	file, err := os.ReadFile(info.Path)
	require.NoError(t, err)

	canaries := map[string][]byte{
		"totp secret": []byte(e.totpSecret), "smtp password": []byte(smtpPassword), "oidc secret": []byte(oidcSecret),
		"managed private key": managedKey, "master key": masterKey, "passphrase": []byte(passphrase), "sender key": sender,
	}
	for name, c := range canaries {
		for form, b := range map[string][]byte{"raw": c, "base64": []byte(base64.StdEncoding.EncodeToString(c)),
			"base64url": []byte(base64.RawURLEncoding.EncodeToString(c)), "hex": []byte(hex.EncodeToString(c))} {
			assert.False(t, bytes.Contains(file, b), "%s (%s) in the backup file", name, form)
		}
	}
	assert.NotContains(t, string(file), "-----BEGIN")
	_, err = format.ReadHeader(bytes.NewReader(file))
	require.NoError(t, err)
	header := file[:headerLen(t, file)]
	assert.NotContains(t, string(header), e.installationID)
	assert.NotContains(t, string(header), strings.ReplaceAll(strings.TrimPrefix(e.installationID, "ALICE-"), "-", "")[:8])
	assert.NotContains(t, string(header), hostname)
	// The canaries are really in the payload (the test would pass trivially otherwise): the payload has the master
	// key file and the sealed SMTP password row.
	assert.Equal(t, masterRaw, payloadFiles(t, info.Path)["keys/master.key"])
	assert.Equal(t, 1, e.count("SELECT count(*) FROM setting_secrets WHERE key = 'notify.smtp.password'"))
}

func headerLen(t *testing.T, file []byte) int {
	t.Helper()
	require.Greater(t, len(file), 14)
	return 14 + int(uint32(file[10])<<24|uint32(file[11])<<16|uint32(file[12])<<8|uint32(file[13]))
}

func TestF88Retention(t *testing.T) {
	e := newEnv(t, true)
	e.completeSetup()
	manual := e.create(backup.KindManual)
	e.clk.Advance(time.Minute)
	upgrade := e.create("pre-upgrade-1.0.0")
	// 20 days of ticks from the first scheduled instant: 20 automatic backups.
	e.clk.Set(time.Date(2026, 10, 2, 2, 30, 0, 0, time.UTC))
	start := e.clk.Now()
	for e.clk.Now().Before(start.Add(20 * 24 * time.Hour)) {
		require.NoError(t, e.svc.RunScheduled(e.ctx))
		e.clk.Advance(5 * time.Minute)
	}
	list, err := e.svc.List(e.ctx)
	require.NoError(t, err)
	var autos []backup.Info
	names := map[string]bool{}
	for _, i := range list {
		names[i.Name] = true
		if i.Kind == backup.KindAuto {
			autos = append(autos, i)
		}
	}
	require.Len(t, autos, 14, "exactly the 14 newest auto backups remain")
	assert.True(t, names[manual.Name])
	assert.True(t, names[upgrade.Name])
	assert.True(t, slices.IsSortedFunc(list, func(a, b backup.Info) int { return b.CreatedAt.Compare(a.CreatedAt) }), "newest first")
	deleted := e.auditRows("backup.deleted")
	require.Len(t, deleted, 6)
	for _, d := range deleted {
		assert.Equal(t, "1", d["deleted_count"])
		assert.Equal(t, "auto", d["kind"])
		assert.False(t, names[d["name"]])
	}
	for _, i := range list {
		_, err := os.Stat(i.Path + ".sha256")
		assert.NoError(t, err)
	}
	assert.Len(t, e.files(), 2*16, "every deleted backup took its checksum file with it")

	// A failing run deletes nothing.
	before := snapshotDir(t, e.dir)
	backup.SetStatfs(&e.cfg, func(string) (uint64, error) { return 0, nil })
	e.rebuild()
	e.clk.Advance(24 * time.Hour)
	require.Error(t, e.svc.RunScheduled(e.ctx))
	assert.Equal(t, before, snapshotDir(t, e.dir))
	assert.Len(t, e.auditRows("backup.deleted"), 6)
}

func TestPruneKeepsUnverifiedAndOtherKinds(t *testing.T) {
	e := newEnv(t, true)
	var autos []backup.Info
	for range 4 {
		autos = append(autos, e.create(backup.KindAuto))
		e.clk.Advance(time.Hour)
	}
	manual := e.create(backup.KindManual)
	// The oldest auto backup no longer matches its checksum: it is never pruned (R43 row 12).
	require.NoError(t, os.WriteFile(autos[0].Path+".sha256", []byte(strings.Repeat("0", 64)+"  "+autos[0].Name+"\n"), 0o600))
	n, err := e.svc.Prune(e.ctx, 1, audit.SystemActor("test"))
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	for i, a := range autos {
		_, err := os.Stat(a.Path)
		if i == 1 || i == 2 {
			assert.ErrorIs(t, err, os.ErrNotExist)
		} else {
			assert.NoError(t, err)
		}
	}
	_, err = os.Stat(manual.Path)
	assert.NoError(t, err)
	_, err = e.svc.Prune(e.ctx, 0, audit.SystemActor("test"))
	require.Error(t, err, "keep must be at least 1")
}

func TestScheduledBackupRunsOncePerDay(t *testing.T) {
	e := newEnv(t, true)
	e.completeSetup()
	_, err := e.svc.SaveSchedule(e.ctx, audit.SystemActor("test"), 0, backup.Schedule{Time: "02:30", Zone: "Europe/Istanbul", Retention: 14})
	require.NoError(t, err)
	e.clk.Set(time.Date(2026, 10, 9, 23, 30, 0, 0, time.UTC))
	start := e.clk.Now()
	for i := 0; e.clk.Now().Before(start.Add(72 * time.Hour)); i++ {
		if i == 400 {
			e.rebuild() // a restart: the state is in the database
		}
		require.NoError(t, e.svc.RunScheduled(e.ctx))
		e.clk.Advance(5 * time.Minute)
	}
	list, err := e.svc.List(e.ctx)
	require.NoError(t, err)
	require.Len(t, list, 3)
	for _, i := range list {
		assert.Equal(t, backup.KindAuto, i.Kind)
		at := i.CreatedAt.UTC()
		scheduled := time.Date(at.Year(), at.Month(), at.Day(), 23, 30, 0, 0, time.UTC)
		assert.WithinDuration(t, scheduled, at, 5*time.Minute, i.Name)
	}
	assert.Equal(t, list[0].CreatedAt, e.state().LastAutoSuccessAt)
}

func TestRunScheduledWaitsForThePassphrase(t *testing.T) {
	e := newEnv(t, false)
	require.NoError(t, e.svc.RunScheduled(e.ctx))
	assert.Empty(t, e.files())
	assert.Empty(t, e.auditRows("backup.failed"), "nothing to back up to before the wizard's passphrase step")
}

func TestFailureEmailOncePerEpisodeAndAlarmAt48Hours(t *testing.T) {
	e := newEnv(t, true)
	e.completeSetup()
	setupDone := e.clk.Now()
	backup.SetStatfs(&e.cfg, func(string) (uint64, error) { return 0, nil })
	e.rebuild()
	for e.clk.Now().Before(setupDone.Add(49 * time.Hour)) {
		require.Error(t, e.svc.RunScheduled(e.ctx))
		if e.clk.Now().Equal(setupDone) {
			assert.Equal(t, 1, e.outbox("backup.failed"), "queued at the first failure")
		}
		if e.clk.Now().Before(setupDone.Add(backup.AlarmAfter)) {
			assert.Zero(t, e.outbox("backup.alarm"))
		}
		e.clk.Advance(5 * time.Minute)
	}
	assert.Equal(t, 1, e.outbox("backup.failed"))
	assert.Equal(t, 1, e.outbox("backup.alarm"))
	st := e.state()
	assert.True(t, st.Alarm(e.clk.Now()))
	assert.True(t, st.FailureNotified)
	assert.True(t, st.AlarmNotified)
	assert.Greater(t, st.ConsecutiveFailures, 500)
	var params map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT params FROM notifications_outbox WHERE template_key = 'backup.failed'").Scan(&params))
	assert.Equal(t, map[string]string{"time": "2026-10-01 09:00 UTC", "error_code": "disk_full", "dashboard_url": "/"}, params)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT params FROM notifications_outbox WHERE template_key = 'backup.alarm'").Scan(&params))
	assert.Equal(t, map[string]string{"last_success": "never / hiç", "dashboard_url": "/"}, params)

	// A success resets the episode.
	backup.SetStatfs(&e.cfg, func(string) (uint64, error) { return 100 << 30, nil })
	e.rebuild()
	require.NoError(t, e.svc.RunScheduled(e.ctx))
	st = e.state()
	assert.False(t, st.Alarm(e.clk.Now()))
	assert.Zero(t, st.ConsecutiveFailures)
	assert.False(t, st.FailureNotified)
	assert.False(t, st.AlarmNotified)
	assert.Empty(t, st.LastErrorCode)

	// A later failure is a new episode.
	require.NoError(t, settings.Set(e.ctx, e.db.Owner, "general", settings.General{PublicURL: "https://alice.example.com/", RetiredKeyRetentionDays: 30, Version: 1}, e.clk.Now()))
	backup.SetStatfs(&e.cfg, func(string) (uint64, error) { return 0, nil })
	e.rebuild()
	e.clk.Advance(24 * time.Hour)
	require.Error(t, e.svc.RunScheduled(e.ctx))
	require.Error(t, e.svc.RunScheduled(e.ctx))
	assert.Equal(t, 2, e.outbox("backup.failed"))
	assert.Equal(t, 1, e.outbox("backup.alarm"))
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT params FROM notifications_outbox WHERE template_key = 'backup.failed' ORDER BY created_at DESC LIMIT 1").Scan(&params))
	assert.Equal(t, "https://alice.example.com/", params["dashboard_url"])

	// A failed manual backup never e-mails.
	e.clk.Advance(time.Hour)
	_, err := e.svc.Create(e.ctx, backup.CreateInput{Kind: backup.KindManual, Actor: audit.SystemActor("test")})
	require.Error(t, err)
	assert.Equal(t, 2, e.outbox("backup.failed"))
}

func TestAlarmNamesTheLastSuccess(t *testing.T) {
	e := newEnv(t, true)
	e.completeSetup()
	e.create(backup.KindManual)
	backup.SetStatfs(&e.cfg, func(string) (uint64, error) { return 0, nil })
	e.rebuild()
	e.clk.Advance(backup.AlarmAfter)
	require.Error(t, e.svc.RunScheduled(e.ctx))
	var params map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT params FROM notifications_outbox WHERE template_key = 'backup.alarm'").Scan(&params))
	assert.Equal(t, "2026-10-01 09:00 UTC", params["last_success"])
}

func TestVerifyShallow(t *testing.T) {
	e := newEnv(t, true)
	info := e.create(backup.KindManual)
	check := func(path string) string {
		t.Helper()
		v, err := e.svc.Verify(e.ctx, path)
		require.NoError(t, err)
		return v.Check
	}
	assert.Equal(t, "ok", check(info.Path))

	copyTo := func(name string, mutate func([]byte) []byte) string {
		b, err := os.ReadFile(info.Path)
		require.NoError(t, err)
		sum, err := os.ReadFile(info.Path + ".sha256")
		require.NoError(t, err)
		p := filepath.Join(t.TempDir(), name)
		require.NoError(t, os.WriteFile(p, mutate(bytes.Clone(b)), 0o600))
		require.NoError(t, os.WriteFile(p+".sha256", bytes.ReplaceAll(sum, []byte(info.Name), []byte(name)), 0o600))
		return p
	}
	flipped := copyTo("flipped.alicebak", func(b []byte) []byte { b[len(b)-100] ^= 1; return b })
	assert.Equal(t, "checksum mismatch", check(flipped))
	noSum := copyTo("nosum.alicebak", func(b []byte) []byte { return b })
	require.NoError(t, os.Remove(noSum+".sha256"))
	assert.Equal(t, "missing checksum", check(noSum))
	cut := copyTo("cut.alicebak", func(b []byte) []byte { return b[:headerLen(t, b)+10] })
	assert.Equal(t, "unreadable header", check(cut), "the size does not fit the chunk framing")

	text := filepath.Join(t.TempDir(), "x.alicebak")
	require.NoError(t, os.WriteFile(text, []byte("this is a text file, not a backup\n"), 0o600))
	assert.Equal(t, "unreadable header", check(text))

	_, err := e.svc.Verify(e.ctx, filepath.Join(t.TempDir(), "missing.alicebak"))
	require.ErrorIs(t, err, backup.ErrNotFound)

	_, err = e.svc.VerifyDeep(e.ctx, text, []byte(passphrase))
	require.ErrorIs(t, err, format.ErrNotBackup)
	_, err = e.svc.VerifyDeep(e.ctx, flipped, []byte(passphrase))
	require.ErrorIs(t, err, backup.ErrDamaged)
	_, err = e.svc.VerifyDeep(e.ctx, cut, []byte(passphrase))
	require.ErrorIs(t, err, backup.ErrDamaged)
}

func TestListNewestFirst(t *testing.T) {
	e := newEnv(t, true)
	list, err := e.svc.List(e.ctx)
	require.NoError(t, err)
	assert.Empty(t, list)
	var made []backup.Info
	for _, k := range []backup.Kind{backup.KindAuto, backup.KindManual, "pre-upgrade-1.0.1", backup.KindPreRestore} {
		made = append(made, e.create(k))
		e.clk.Advance(time.Hour)
	}
	// Files that are not backups are not listed.
	require.NoError(t, os.WriteFile(filepath.Join(e.dir, "notes.txt"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(e.dir, ".alice-backup-x.alicebak.partial"), []byte("x"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(e.dir, "sub.alicebak"), 0o700))
	list, err = e.svc.List(e.ctx)
	require.NoError(t, err)
	require.Len(t, list, 4)
	for i := range list {
		assert.Equal(t, made[3-i].Name, list[i].Name)
		assert.Equal(t, "ok", list[i].Check)
	}

	f, info, err := e.svc.Open(e.ctx, made[1].Name)
	require.NoError(t, err)
	defer f.Close()
	assert.Equal(t, made[1].Name, info.Name)
	assert.Equal(t, made[1].Size, info.Size)
	for _, bad := range []string{"../x.alicebak", "missing.alicebak", ".alice-backup-x.alicebak.partial", "sub.alicebak", "notes.txt"} {
		_, _, err := e.svc.Open(e.ctx, bad)
		require.ErrorIs(t, err, backup.ErrNotFound, bad)
	}
	require.NoError(t, os.Symlink(made[1].Path, filepath.Join(e.dir, "link.alicebak")))
	_, _, err = e.svc.Open(e.ctx, "link.alicebak")
	require.ErrorIs(t, err, backup.ErrNotFound, "a symbolic link is never followed")
}

func TestScheduleSettings(t *testing.T) {
	e := newEnv(t, true)
	sch, err := e.svc.Schedule(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, backup.Schedule{Time: "02:30", Zone: "UTC", Retention: 14, Version: 0}, sch)

	cfg := e.cfg
	cfg.Zone = mustLoc(t, "Europe/Istanbul")
	sch, err = backup.New(cfg).Schedule(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, "Europe/Istanbul", sch.Zone, "ALICE_TZ is the default zone (R43 row 10)")

	who := audit.SystemActor("test")
	for name, in := range map[string]backup.Schedule{
		"time":           {Time: "2:30", Zone: "UTC", Retention: 14},
		"hour":           {Time: "24:00", Zone: "UTC", Retention: 14},
		"zone":           {Time: "02:30", Zone: "Mars/Olympus", Retention: 14},
		"empty zone":     {Time: "02:30", Zone: "", Retention: 14},
		"local zone":     {Time: "02:30", Zone: "Local", Retention: 14},
		"retention low":  {Time: "02:30", Zone: "UTC", Retention: 6},
		"retention high": {Time: "02:30", Zone: "UTC", Retention: 61},
	} {
		_, err := e.svc.SaveSchedule(e.ctx, who, 0, in)
		require.Error(t, err, name)
		assert.NotErrorIs(t, err, backup.ErrVersion, name)
	}
	assert.Empty(t, e.auditRows("backup.settings_changed"))

	saved, err := e.svc.SaveSchedule(e.ctx, who, 0, backup.Schedule{Time: "03:15", Zone: "Europe/Istanbul", Retention: 7})
	require.NoError(t, err)
	assert.Equal(t, backup.Schedule{Time: "03:15", Zone: "Europe/Istanbul", Retention: 7, Version: 1}, saved)
	got, err := e.svc.Schedule(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, saved, got)
	_, err = e.svc.SaveSchedule(e.ctx, who, 0, backup.Schedule{Time: "04:00", Zone: "UTC", Retention: 60})
	require.ErrorIs(t, err, backup.ErrVersion)
	saved, err = e.svc.SaveSchedule(e.ctx, who, 1, backup.Schedule{Time: "04:00", Zone: "UTC", Retention: 60})
	require.NoError(t, err)
	assert.Equal(t, 2, saved.Version)
	rows := e.auditRows("backup.settings_changed")
	require.Len(t, rows, 2)
	assert.Equal(t, map[string]string{"time": "03:15", "zone": "Europe/Istanbul", "retention": "7"}, rows[0])
}

func TestBackupTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"time": "2026-10-10 23:30 UTC", "error_code": "disk_full", "dashboard_url": "https://alice.example.com/",
		"last_success": "2026-10-08 23:30 UTC"}
	assert.Equal(t, []string{"backup.failed", "backup.alarm"}, backup.Templates())
	subjects := map[string]string{
		"backup.failed/en": "Alice could not make its daily backup", "backup.failed/tr": "Alice günlük yedeğini alamadı",
		"backup.alarm/en": "Alice has had no successful backup for 48 hours", "backup.alarm/tr": "Alice'in 48 saattir başarılı bir yedeği yok",
	}
	for _, tpl := range backup.Templates() {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ayse@example.com", tpl, lang, params)
			assert.Equal(t, subjects[tpl+"/"+lang], m.Subject)
			assert.NotContains(t, m.Subject, "\n")
			assert.NotContains(t, m.Body, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Body, "email.", "%s %s", tpl, lang)
			assert.Contains(t, m.Body, "https://alice.example.com/", "%s %s", tpl, lang)
		}
		assert.Contains(t, s.Render("a@example.com", "backup.failed", "en", params).Body, "disk_full")
		assert.Contains(t, s.Render("a@example.com", "backup.alarm", "tr", params).Body, "2026-10-08 23:30 UTC")
	}
}

// openGate allows every license class: the canary test only needs the upload to store a sealed key.
type openGate struct{}

func (openGate) CheckCanAddTarget(context.Context, pgx.Tx) error { return nil }
func (openGate) Tick(context.Context) error                      { return nil }
func (openGate) Allow(license.Class) error                       { return nil }

// uploadCertificate stores a certificate with its private key through the inventory upload (the key is sealed under
// the master key) and returns the key's PKCS#8 DER bytes as the canary.
func uploadCertificate(t *testing.T, e *env) []byte {
	t.Helper()
	leaf := pki.SelfSigned("canary.example.test", pki.ECDSA256, e.clk.Now())
	inv := inventory.New(inventory.Config{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clk, License: openGate{}})
	_, _, err := inv.UploadCertificate(e.ctx, inventory.Actor{Audit: audit.SystemActor("test"), Role: rbac.Admin},
		inventory.UploadInput{CertificatePEM: string(leaf.CertPEM), PrivateKeyPEM: string(leaf.KeyPEM)})
	require.NoError(t, err)
	require.Equal(t, 1, e.count("SELECT count(*) FROM managed_private_keys"))
	block, _ := pem.Decode(leaf.KeyPEM)
	require.NotNil(t, block)
	return block.Bytes
}

// forge writes a backup file whose payload is the frames frames writes, keyed with this installation's real backup and
// sender keys, so only the payload is wrong.
func forge(t *testing.T, e *env, frames func(enc *dump.Encoder)) string {
	t.Helper()
	var w secrets.WrappedBackupKey
	_, err := settings.Get(e.ctx, e.db.Owner, "backup.key", &w)
	require.NoError(t, err)
	pt, ok, err := e.keyring.GetSetting(e.ctx, e.db.App, "backup.sender")
	require.NoError(t, err)
	require.True(t, ok)
	sender, err := ecdh.X25519().NewPrivateKey(pt.Bytes())
	require.NoError(t, err)
	var buf bytes.Buffer
	fw, err := format.NewWriter(&buf, w, sender, format.Meta{AliceVersion: "1.0.0", CreatedAt: e.clk.Now(), Kind: "manual"})
	require.NoError(t, err)
	gz := gzip.NewWriter(fw)
	enc := dump.NewEncoder(gz)
	frames(enc)
	require.NoError(t, enc.Flush())
	require.NoError(t, gz.Close())
	require.NoError(t, fw.Close())
	p := filepath.Join(t.TempDir(), "forged.alicebak")
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o600))
	return p
}

func TestVerifyDeepRefusesAPayloadThatDisagreesWithItsManifest(t *testing.T) {
	e := newEnv(t, true)
	manifest := func(enc *dump.Encoder, tables map[string]int64, files []string) {
		require.NoError(t, enc.JSON(dump.Manifest, "manifest.json", backup.Manifest{Format: 1, Tables: tables, Files: files}))
	}
	table := func(enc *dump.Encoder, name string, rows int) {
		require.NoError(t, enc.JSON(dump.TableStart, name, dump.Table{Name: name, Columns: []string{"a"}}))
		require.NoError(t, enc.JSON(dump.TableEnd, name, map[string]int{"rows": rows}))
	}
	tail := func(enc *dump.Encoder, files []string, end any) {
		require.NoError(t, enc.JSON(dump.Sequences, "sequences.json", map[string]any{}))
		for _, f := range files {
			require.NoError(t, enc.Frame(dump.File, f, []byte("x")))
		}
		require.NoError(t, enc.JSON(dump.End, "end", end))
	}
	good := func(enc *dump.Encoder) {
		manifest(enc, map[string]int64{"a": 1}, []string{"keys/master.key"})
		table(enc, "a", 1)
		tail(enc, []string{"keys/master.key"}, map[string]int{"tables": 1, "files": 1})
	}
	m, err := e.svc.VerifyDeep(e.ctx, forge(t, e, good), []byte(passphrase))
	require.NoError(t, err, "control: the forged file is valid")
	assert.Equal(t, map[string]int64{"a": 1}, m.Tables)

	for name, frames := range map[string]func(*dump.Encoder){
		"row count": func(enc *dump.Encoder) {
			manifest(enc, map[string]int64{"a": 2}, []string{"keys/master.key"})
			table(enc, "a", 1)
			tail(enc, []string{"keys/master.key"}, map[string]int{"tables": 1, "files": 1})
		},
		"missing table": func(enc *dump.Encoder) {
			manifest(enc, map[string]int64{"a": 1, "b": 0}, nil)
			table(enc, "a", 1)
			tail(enc, nil, map[string]int{"tables": 1, "files": 0})
		},
		"unknown file": func(enc *dump.Encoder) {
			manifest(enc, map[string]int64{"a": 1}, []string{"../etc/passwd"})
			table(enc, "a", 1)
			tail(enc, []string{"../etc/passwd"}, map[string]int{"tables": 1, "files": 1})
		},
		"repeated file": func(enc *dump.Encoder) {
			manifest(enc, map[string]int64{"a": 1}, []string{"keys/master.key", "keys/master.key"})
			table(enc, "a", 1)
			tail(enc, []string{"keys/master.key", "keys/master.key"}, map[string]int{"tables": 1, "files": 2})
		},
		"files differ": func(enc *dump.Encoder) {
			manifest(enc, map[string]int64{"a": 1}, []string{"keys/master.key", "state/hwm.dat"})
			table(enc, "a", 1)
			tail(enc, []string{"keys/master.key"}, map[string]int{"tables": 1, "files": 1})
		},
		"end frame counts": func(enc *dump.Encoder) {
			manifest(enc, map[string]int64{"a": 1}, nil)
			table(enc, "a", 1)
			tail(enc, nil, map[string]int{"tables": 2, "files": 0})
		},
		"end frame not JSON": func(enc *dump.Encoder) {
			manifest(enc, map[string]int64{"a": 1}, nil)
			table(enc, "a", 1)
			tail(enc, nil, "x")
		},
		"end of table not JSON": func(enc *dump.Encoder) {
			manifest(enc, map[string]int64{"a": 1}, nil)
			require.NoError(t, enc.JSON(dump.TableStart, "a", dump.Table{Name: "a"}))
			require.NoError(t, enc.Frame(dump.TableEnd, "a", []byte("{")))
			tail(enc, nil, map[string]int{"tables": 1, "files": 0})
		},
		"manifest not JSON": func(enc *dump.Encoder) {
			require.NoError(t, enc.Frame(dump.Manifest, "manifest.json", []byte("not json")))
			tail(enc, nil, map[string]int{"tables": 0, "files": 0})
		},
		"no frames": func(*dump.Encoder) {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.svc.VerifyDeep(e.ctx, forge(t, e, frames), []byte(passphrase))
			require.ErrorIs(t, err, backup.ErrDamaged)
		})
	}
	_, err = e.svc.VerifyDeep(e.ctx, filepath.Join(t.TempDir(), "missing.alicebak"), []byte(passphrase))
	require.ErrorIs(t, err, backup.ErrNotFound)
}
