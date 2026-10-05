//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/i18n"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/logging"
	"alice/locales"
)

// The Phase 6 harness of the API integration suite (Task 14): the real sshkeys service, the real job handlers of
// sshkeyjobs on the stack's runner, the rotation's periodic tasks on a real jobs.Scheduler, the outbox drained by the
// real notify.Sender into a recording "SMTP server", and Linux servers emulated by linuxsshtest whose test logins are
// decided by the emulated authorized_keys files (SetLoginCheck(emu.AcceptsLogin)).

// tickClock is the Phase 6 services' clock: the stack's fake clock, which moves one millisecond on every read while
// ticking is on, as a real clock does between two reads (a frozen clock once hid a comparison of two clock reads in the
// notice lookup; preflight ruling "Tests of scheduled starts use an ADVANCING clock").
type tickClock struct {
	*clock.Fake
	on atomic.Bool
}

func (c *tickClock) Now() time.Time {
	if c.on.Load() {
		c.Advance(time.Millisecond)
	}
	return c.Fake.Now()
}

// mailbox stands for the SMTP server: every message the sender delivered, rendered as the recipient reads it.
type mailbox struct {
	mu   sync.Mutex
	msgs []notify.Message
	down bool
}

func (m *mailbox) Send(_ context.Context, msg notify.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return errors.New("mailbox: connection refused")
	}
	m.msgs = append(m.msgs, msg)
	return nil
}

func (m *mailbox) setDown(down bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.down = down
}

func (m *mailbox) messages() []notify.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]notify.Message(nil), m.msgs...)
}

// deliverMail drains the outbox the way the notify.send job does in production (notify.Sender with an SMTP mailer)
// and returns how many emails it handled.
func (s *stack) deliverMail() int {
	s.t.Helper()
	catalog, err := i18n.Load(locales.FS)
	require.NoError(s.t, err)
	sender := notify.Sender{Pool: s.db.App, Mailer: s.mailbox, Catalog: catalog, Clock: s.tick, Log: logging.New(s.logs, slog.LevelDebug)}
	n, err := sender.Drain(context.Background())
	require.NoError(s.t, err)
	return n
}

// rotationTasks are the Phase 6 periodic tasks as cmd/alice schedules them, on a real scheduler (its licence gate).
func (s *stack) rotationTasks() *jobs.Scheduler {
	return jobs.NewScheduler(s.tick, s.license, logging.New(s.logs, slog.LevelDebug),
		jobs.Task{Type: jobs.RotationPlan, Every: time.Minute, Run: func(ctx context.Context) error {
			_, err := s.sshKeys.PlanDue(ctx)
			return err
		}},
		jobs.Task{Type: jobs.RotationSweep, Every: time.Minute, Run: func(ctx context.Context) error {
			_, err := s.sshKeys.Sweep(ctx)
			return err
		}},
		jobs.Task{Type: jobs.SSHKeyDestroyRetired, Every: time.Hour, Run: func(ctx context.Context) error {
			_, err := s.sshKeys.DestroyRetiredKeys(ctx)
			return err
		}},
	)
}

// keyEnv is an installed Alice with one Linux server (web-01: users root, deploy and the connection account
// alice-svc, discovered) whose test logins are decided by its authorized_keys files, an Administrator with an email
// address (so the rotation emails are queued), the rotation tasks and the mailbox.
type keyEnv struct {
	*stack
	admin     *client
	adminAcct *account
	f         *sshFixture
	targetID  string
	tasks     *jobs.Scheduler
	clients   map[*client]*account // browsers signed in again after a long clock step
}

func newKeyEnv(t *testing.T) *keyEnv {
	t.Helper()
	s, admin, adminAcct := installed(t)
	e := &keyEnv{stack: s, admin: admin, adminAcct: adminAcct, clients: map[*client]*account{admin: adminAcct}}
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)
	e.f, e.targetID = e.addKeyServer("web-01")
	e.tasks = s.rotationTasks()
	return e
}

// addKeyServer adds, pins and discovers one more emulated Linux server whose logins follow its files.
func (e *keyEnv) addKeyServer(name string) (*sshFixture, string) {
	e.t.Helper()
	f := e.sshFixture()
	f.server.SetLoginCheck(f.emu.AcceptsLogin)
	id, _ := e.addServer(e.admin, name, f)
	e.pinServer(e.admin, id)
	return f, id
}

// signedIn registers a browser that advance signs in again after a long clock step.
func (e *keyEnv) signedIn(c *client, a *account) { e.clients[c] = a }

// advance moves the clock and evaluates the licence, as the hourly license.evaluate task does (without an evaluation
// for 3 hours every change is refused, AUD-02); after a step longer than a session's idle time every registered
// browser signs in again.
func (e *keyEnv) advance(d time.Duration) {
	e.t.Helper()
	e.clock.Advance(d)
	require.NoError(e.t, e.license.Tick(context.Background()))
	if d >= 25*time.Minute {
		for c, a := range e.clients {
			e.signIn(c, a)
		}
	}
}

// drain runs due jobs until none is due (a bounded wait: at most 200 runs).
func (e *keyEnv) drain() int {
	e.t.Helper()
	for n := 0; n < 200; n++ {
		ran, err := e.runner.RunOnce(context.Background())
		require.NoError(e.t, err)
		if !ran {
			return n
		}
	}
	e.t.Fatal("jobs did not settle after 200 runs")
	return 0
}

// task runs one periodic task now through the scheduler (its licence gate first); it returns the gate's refusal.
func (e *keyEnv) task(name string) error {
	e.t.Helper()
	err := e.tasks.RunNow(context.Background(), name)
	if err != nil && !errors.Is(err, license.ErrLocked) && !errors.Is(err, license.ErrUnverified) && !errors.Is(err, license.ErrLockDue) {
		require.NoError(e.t, err, name)
	}
	return err
}

// sweep runs the rotation tasks (plan, sweep) and then the jobs they queued, n times.
func (e *keyEnv) sweep(n int) {
	e.t.Helper()
	for i := 0; i < n; i++ {
		_ = e.task(jobs.RotationPlan.Name)
		_ = e.task(jobs.RotationSweep.Name)
		e.drain()
	}
}

// file is the emulated server's file as it is now.
func (f *sshFixture) file(path string) string {
	b, _ := f.emu.File(path)
	return string(b)
}

// keyLine is a generated key as the API shows it.
type keyLine struct {
	id, fingerprint, publicKey string
	pub                        ssh.PublicKey
}

// blob is "type base64" of the key (what an authorized_keys line holds whatever its options and comment).
func (k keyLine) blob() string {
	f := strings.Fields(k.publicKey)
	return f[0] + " " + f[1]
}

// generate creates a key through the API (POST /ssh-keys/generate) and returns it.
func (e *keyEnv) generate(c *client, label, keyType string) keyLine {
	e.t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/ssh-keys/generate", map[string]string{"label": label, "key_type": keyType})
	requireStatus(e.t, rec, http.StatusCreated)
	body := decodeBody[map[string]any](e.t, rec)
	k := keyLine{id: body["id"].(string), fingerprint: body["fingerprint"].(string), publicKey: body["public_key"].(string)}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.publicKey))
	require.NoError(e.t, err)
	k.pub = pub
	require.Equal(e.t, k.fingerprint, ssh.FingerprintSHA256(pub))
	return k
}

// deploy asks for a deploy (202) and returns the job id.
func (e *keyEnv) deploy(c *client, keyID, targetID, user, file string) string {
	e.t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/ssh-keys/"+keyID+"/actions/deploy", map[string]any{"target_id": targetID, "os_user": user, "file_path": file})
	requireStatus(e.t, rec, http.StatusAccepted)
	return decodeBody[map[string]string](e.t, rec)["job_id"]
}

// deployed deploys a key to deploy's file on web-01, runs the job and requires it verified.
func (e *keyEnv) deployed(k keyLine) {
	e.t.Helper()
	job := e.deploy(e.admin, k.id, e.targetID, "deploy", deployKeysPath)
	e.drain()
	got := e.job(e.admin, job)
	require.Equal(e.t, "succeeded", got["status"], "%v", got)
	require.Equal(e.t, "verified", got["result"].(map[string]any)["result"], "%v", got)
}

// createPolicy creates a policy (201) and returns its id and ETag.
func (e *keyEnv) createPolicy(c *client, keyID string, overlapDays int) (string, string) {
	e.t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/rotation/policies", map[string]any{"ssh_key_id": keyID, "name": "rotate " + keyID[:8],
		"interval_days": 90, "overlap_days": overlapDays})
	requireStatus(e.t, rec, http.StatusCreated)
	return decodeBody[map[string]any](e.t, rec)["id"].(string), rec.Header().Get("ETag")
}

// previewDoc is POST …/preview's answer.
type previewDoc struct {
	PolicyID    string           `json:"policy_id"`
	SSHKeyID    string           `json:"ssh_key_id"`
	PlanDigest  string           `json:"plan_digest"`
	ChangeCount int              `json:"change_count"`
	SkipCount   int              `json:"skip_count"`
	Emailed     bool             `json:"emailed"`
	Actions     []map[string]any `json:"actions"`
}

func (e *keyEnv) preview(c *client, policyID string) previewDoc {
	e.t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/preview", nil)
	requireStatus(e.t, rec, http.StatusOK)
	return decodeBody[previewDoc](e.t, rec)
}

// runNow starts the policy's rotation with digest as the stepped-up Administrator and returns the run id.
func (e *keyEnv) runNow(policyID, digest string) string {
	e.t.Helper()
	e.stepUp(e.admin, e.adminAcct)
	rec := e.admin.do(http.MethodPost, "/api/v1/rotation/policies/"+policyID+"/actions/run", map[string]string{"plan_digest": digest})
	requireStatus(e.t, rec, http.StatusAccepted)
	return decodeBody[map[string]string](e.t, rec)["rotation_id"]
}

// runDoc is GET /rotation/runs/{id}.
type runDoc struct {
	ID             string           `json:"id"`
	Status         string           `json:"status"`
	PausedLicense  bool             `json:"paused_license"`
	Result         map[string]any   `json:"result"`
	PlanDigest     string           `json:"plan_digest"`
	ActionsAllowed []string         `json:"actions_allowed"`
	NoticeState    map[string]any   `json:"notice_state"`
	NewSSHKeyID    *string          `json:"new_ssh_key_id"`
	NewFingerprint string           `json:"new_fingerprint"`
	OldFingerprint string           `json:"old_fingerprint"`
	DecisionDueAt  *time.Time       `json:"decision_due_at"`
	OverlapUntil   *time.Time       `json:"overlap_until"`
	Locations      []map[string]any `json:"locations"`
	Steps          []map[string]any `json:"steps"`
}

func (e *keyEnv) run(c *client, id string) runDoc {
	e.t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/rotation/runs/"+id, nil)
	requireStatus(e.t, rec, http.StatusOK)
	return decodeBody[runDoc](e.t, rec)
}

// rotateOnce runs a whole rotation of k with a 1-day overlap (preview, Run now, add and verify, overlap, removal) and
// returns the run id and the new key's id.
func (e *keyEnv) rotateOnce(k keyLine) (string, string) {
	e.t.Helper()
	policyID, _ := e.createPolicy(e.admin, k.id, 1)
	p := e.preview(e.admin, policyID)
	runID := e.runNow(policyID, p.PlanDigest)
	e.drain()
	require.Equal(e.t, "overlap", e.run(e.admin, runID).Status)
	e.advance(24*time.Hour + time.Minute)
	e.sweep(3)
	r := e.run(e.admin, runID)
	require.Equal(e.t, "completed", r.Status, "%+v", r)
	return runID, *r.NewSSHKeyID
}

// auditRows are the audit rows of action, oldest first, as (details, result).
func (s *stack) auditRows(action string) []map[string]string {
	s.t.Helper()
	rows, err := s.db.Owner.Query(context.Background(), `SELECT details::text, result FROM audit_log WHERE action = $1 ORDER BY seq`, action)
	require.NoError(s.t, err)
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var raw, result string
		require.NoError(s.t, rows.Scan(&raw, &result))
		d := map[string]string{}
		require.NoError(s.t, json.Unmarshal([]byte(raw), &d))
		d["_result"] = result
		out = append(out, d)
	}
	require.NoError(s.t, rows.Err())
	return out
}

// helperWrites are the authkeys-write command lines the server received.
func (f *sshFixture) helperWrites() []string {
	var out []string
	for _, c := range f.server.Commands() {
		if strings.Contains(c, " authkeys-write ") {
			out = append(out, c)
		}
	}
	return out
}

// pub parses a fixture key's public key.
func (k fixtureKey) pub() ssh.PublicKey {
	p, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.line))
	if err != nil {
		panic(err)
	}
	return p
}
