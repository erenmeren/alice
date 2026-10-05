//go:build integration

package sshkeys_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/fake"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/sshkeys"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) {
	// The job types sshkey.add and rotation.location are registered by the job handlers (Task 10);
	// until they exist the tests register them here with the classes C1 gives them.
	for _, jt := range []jobs.Type{{Name: sshkeys.JobDeploy, Class: license.ClassChange}, {Name: sshkeys.JobRotationLocation, Class: license.ClassAlways}} {
		if !slices.ContainsFunc(jobs.Types(), func(t jobs.Type) bool { return t.Name == jt.Name }) {
			jobs.Register(jt.Name, jt.Class)
		}
	}
	os.Exit(pgtest.Main(m))
}

var start = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// lockGate is the license service with a switch that puts it in lock. Unlike deployjobs' harness it
// does not ask the real service: these tests move the clock by months, after which the service would
// say the license was not checked recently.
type lockGate struct {
	*license.Service
	locked atomic.Bool
}

func (g *lockGate) Allow(c license.Class) error {
	if g.locked.Load() && c != license.ClassAlways {
		return license.ErrLocked
	}
	return nil
}

func (g *lockGate) lock()   { g.locked.Store(true) }
func (g *lockGate) unlock() { g.locked.Store(false) }

// recordingNotifier records every NotifyAdmins call (template and params) and queues the email in
// the outbox as production does (next), so a test can see the outbox rows and their delivery.
type recordingNotifier struct {
	mu    sync.Mutex
	calls []notice
	next  notify.AdminNotifier
}

type notice struct {
	template string
	params   map[string]string
}

func (r *recordingNotifier) NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	if err := r.next.NotifyAdmins(ctx, tx, template, params); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, notice{template: template, params: params})
	return nil
}

// syncBuffer is a log sink safe for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	t        *testing.T
	ctx      context.Context
	db       *pgtest.DB
	clock    *clock.Fake
	keyring  *secrets.Keyring
	audit    *audit.Log
	lic      *license.Service
	gate     *lockGate
	queue    *jobs.Queue
	inv      *inventory.Service
	notifier *recordingNotifier
	logs     *syncBuffer
	svc      *sshkeys.Service
	admin    inventory.Actor
	operator inventory.Actor
	n        int // names of helper targets
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), db: pgtest.New(t), clock: clock.NewFake(start), logs: &syncBuffer{}}
	e.notifier = &recordingNotifier{next: notify.AdminNotifier{Clock: e.clock}}
	var err error
	e.keyring, err = secrets.LoadOrCreateMasterKey(e.ctx, e.db.App, t.TempDir(), e.clock.Now())
	require.NoError(t, err)
	e.audit = audit.New(e.clock)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	e.lic = license.New(license.Config{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clock, Uptime: e.clock,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), Targets: inventory.Counter{}, Notifier: notify.AdminNotifier{Clock: e.clock},
		Log: quiet})
	require.NoError(t, e.lic.Start(e.ctx))
	e.gate = &lockGate{Service: e.lic}
	e.queue = jobs.NewQueue(jobs.QueueConfig{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clock, Gate: e.gate})
	reg := providers.NewRegistry()
	reg.Register(fake.New(providers.KindLinuxSSH))
	reg.Freeze()
	e.inv = inventory.New(inventory.Config{Pool: e.db.App, Keyring: e.keyring, Audit: e.audit, Clock: e.clock, License: e.gate,
		Registry: reg, Jobs: e.queue, Notifier: notify.AdminNotifier{Clock: e.clock}, Log: quiet})
	_, err = e.inv.EnsurePlatformKey(e.ctx)
	require.NoError(t, err)
	e.svc = e.newService(e.keyring)
	e.admin = e.user("ada", rbac.Admin)
	e.operator = e.user("oscar", rbac.Operator)
	return e
}

// newService builds the module on the environment with a keyring (another master key: a
// decryption failure).
func (e *env) newService(k *secrets.Keyring) *sshkeys.Service {
	return sshkeys.New(sshkeys.Config{Pool: e.db.App, Keyring: k, Audit: e.audit, Clock: e.clock, License: e.gate, Inventory: e.inv,
		Jobs: e.queue, Notifier: e.notifier, Log: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
}

func (e *env) user(name string, role rbac.Role) inventory.Actor {
	e.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'x', $5, $6, $6)`, id, name, name+"@example.com", name, string(role), e.clock.Now())
	require.NoError(e.t, err)
	return inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: name, RequestID: uuid.NewString()}, UserID: id, Role: role}
}

func (e *env) generate(label string) sshkeys.ManagedKey {
	e.t.Helper()
	k, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: label})
	require.NoError(e.t, err)
	return k
}

// generateUnlocked generates a key while the gate is unlocked and locks it again.
func (e *env) generateUnlocked(label string) uuid.UUID {
	e.t.Helper()
	e.gate.unlock()
	defer e.gate.lock()
	return e.generate(label).ID
}

// keyFiles are the candidate key files every helper server reports: the connection account
// alice-svc is one of the users, as the real helper lists it.
var keyFiles = []providers.UserKeyFiles{
	{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}},
	{OSUser: "root", Files: []string{"/root/.ssh/authorized_keys"}},
	{OSUser: "alice-svc", Files: []string{"/home/alice-svc/.ssh/authorized_keys"}},
}

// server adds a confirmed ok Linux target whose last scan read sshd and found keyFiles.
func (e *env) server(name string) uuid.UUID {
	e.t.Helper()
	return e.serverWith(name, keyFiles)
}

func (e *env) serverWith(name string, files []providers.UserKeyFiles) uuid.UUID {
	e.t.Helper()
	pk, err := e.inv.PlatformKey(e.ctx)
	require.NoError(e.t, err)
	facts, err := json.Marshal(inventory.Facts{SSHD: &providers.SSHDSummary{Read: true, PubkeyAuthentication: "yes", PermitRootLogin: "prohibit-password",
		AuthorizedKeysFile: []string{".ssh/authorized_keys"}, AuthorizedKeysCommand: "none"}, KeyFiles: files})
	require.NoError(e.t, err)
	id := uuid.Must(uuid.NewV7())
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, facts, created_at, updated_at)
VALUES ($1, $2, 'linux', jsonb_build_object('host', $3::text, 'port', 22, 'username', 'alice-svc'), $4, 'ok', $5, $6, $6)`,
		id, name, name+".example.com", pk.ID, facts, e.clock.Now())
	require.NoError(e.t, err)
	return id
}

func (e *env) setTargetStatus(id uuid.UUID, status string) {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET status = $2 WHERE id = $1", id, status)
	require.NoError(e.t, err)
}

// discover stores a scan of a new helper server that found one key line, and returns the key's id.
func (e *env) discover(user, file, publicKey, fingerprint string) (keyID, targetID uuid.UUID) {
	e.t.Helper()
	e.n++
	targetID = e.server("scan-" + strconv.Itoa(e.n))
	_, err := e.inv.Reconcile(e.ctx, targetID, providers.DiscoveryResult{
		SSHKeys: []providers.DiscoveredSSHKey{{OSUser: user, FilePath: file, LineNo: 1, PublicKey: publicKey, Fingerprint: fingerprint,
			KeyType: strings.Fields(publicKey)[0], Bits: 256, Comment: "found"}},
		SSHD: providers.SSHDSummary{Read: true, PubkeyAuthentication: "yes"}, ReadFiles: []string{file}, KeyFiles: keyFiles})
	require.NoError(e.t, err)
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM ssh_keys WHERE fingerprint_sha256 = $1", fingerprint).Scan(&keyID))
	return keyID, targetID
}

// discoveredKey is a key found on a server: Alice holds no private key for it.
func (e *env) discoveredKey() uuid.UUID {
	e.t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(e.t, err)
	sp, err := ssh.NewPublicKey(pub)
	require.NoError(e.t, err)
	id, _ := e.discover("deploy", "/home/deploy/.ssh/authorized_keys", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))),
		ssh.FingerprintSHA256(sp))
	return id
}

// platformKeyRow is the ssh_keys row of Alice's own key, as a scan that found it records it.
func (e *env) platformKeyRow() uuid.UUID {
	e.t.Helper()
	pk, err := e.inv.EnsurePlatformKey(e.ctx)
	require.NoError(e.t, err)
	id, _ := e.discover("alice-svc", "/home/alice-svc/.ssh/authorized_keys", pk.PublicKey, pk.Fingerprint)
	var platform bool
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT is_platform_key FROM ssh_keys WHERE id = $1", id).Scan(&platform))
	require.True(e.t, platform)
	return id
}

// liveLocation records a location of the key on a new server as a scan finds it.
func (e *env) liveLocation(k sshkeys.ManagedKey) uuid.UUID {
	e.t.Helper()
	_, target := e.discover("deploy", "/home/deploy/.ssh/authorized_keys", k.PublicKey, k.Fingerprint)
	return target
}

func (e *env) retire(id uuid.UUID) { e.retireAt(id, e.clock.Now()) }

func (e *env) retireAt(id uuid.UUID, at time.Time) {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", id, at)
	require.NoError(e.t, err)
}

// destroy retires the key (when it is not) and destroys its private key as DestroyRetiredKeys
// does (owner pool, no checks but the database's: only a retired key's private key is destroyed).
func (e *env) destroy(id uuid.UUID) {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE ssh_keys SET retired_at = coalesce(retired_at, $2) WHERE id = $1", id, e.clock.Now())
	require.NoError(e.t, err)
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE managed_private_keys SET destroyed_at = $2, ciphertext = NULL, nonce = NULL, wrapped_dek = NULL,
    key_version = NULL WHERE id = (SELECT private_key_id FROM ssh_keys WHERE id = $1)`, id, e.clock.Now())
	require.NoError(e.t, err)
}

func (e *env) envelope(privateKeyID uuid.UUID) secrets.Envelope {
	e.t.Helper()
	var env secrets.Envelope
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT ciphertext, nonce, wrapped_dek, key_version FROM managed_private_keys WHERE id = $1",
		privateKeyID).Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion))
	return env
}

func (e *env) wrappedDEK(privateKeyID uuid.UUID) []byte { return e.envelope(privateKeyID).WrappedDEK }

type job struct {
	Type     string
	TargetID uuid.UUID
	Status   jobs.Status
	Payload  map[string]string
}

func (e *env) job(id uuid.UUID) job {
	e.t.Helper()
	v, err := e.queue.Get(e.ctx, id)
	require.NoError(e.t, err)
	j := job{Type: v.Type, TargetID: v.TargetID, Status: v.Status}
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT payload FROM jobs WHERE id = $1", id).Scan(&j.Payload))
	return j
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, sql, args...).Scan(&n))
	return n
}

func (e *env) audits(action string) int {
	return e.count("SELECT count(*) FROM audit_log WHERE action = $1", action)
}

// lastAuditDetail is one details value of the newest audit row of the action ("" when none).
func (e *env) lastAuditDetail(action, key string) string {
	e.t.Helper()
	var v *string
	err := e.db.Owner.QueryRow(e.ctx, "SELECT details->>$2 FROM audit_log WHERE action = $1 ORDER BY seq DESC LIMIT 1", action, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && v == nil) {
		return ""
	}
	require.NoError(e.t, err)
	return *v
}

// dumpTable is every row of the table as text (owner pool). The name comes from the test's own
// list and is quoted.
func (e *env) dumpTable(name string) string {
	e.t.Helper()
	rows, err := e.db.Owner.Query(e.ctx, "SELECT t::text FROM "+pgx.Identifier{name}.Sanitize()+" t")
	require.NoError(e.t, err)
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var s string
		require.NoError(e.t, rows.Scan(&s))
		b.WriteString(s)
		b.WriteByte('\n')
	}
	require.NoError(e.t, rows.Err())
	return b.String()
}

// leakTables are the tables a private key, a passphrase or a seed must never reach in clear.
var leakTables = []string{"managed_private_keys", "ssh_keys", "ssh_key_locations", "audit_log", "jobs", "notifications_outbox", "targets"}

// keyBodyLines are the base64 lines between the PEM markers of an OpenSSH file, each at least 20
// characters: canaries of the private key.
func keyBodyLines(pem string) []string {
	var out []string
	for _, l := range strings.Split(pem, "\n") {
		l = strings.TrimSpace(l)
		if len(l) >= 20 && !strings.HasPrefix(l, "-----") {
			out = append(out, l)
		}
	}
	return out
}
