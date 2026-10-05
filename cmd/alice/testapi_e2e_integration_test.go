//go:build integration && e2e

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/config"
	"alice/internal/platform/logging"
	"alice/internal/rbac"
	"alice/internal/testutil/pgtest"
	"alice/locales"
)

// e2eStack is the serve wiring the /test endpoints need, on a real database.
type e2eStack struct {
	t        *testing.T
	d        *pgtest.DB
	stateDir string
	svc      *services
	runner   *jobs.Runner
	sched    *jobs.Scheduler
	h        http.Handler
}

func newE2EStack(t *testing.T) *e2eStack {
	t.Helper()
	t.Cleanup(e2eClock.Reset)
	t.Cleanup(e2eMailbox.reset)
	d := pgtest.New(t)
	stateDir := t.TempDir()
	cfg, err := config.Load(env(map[string]string{
		"ALICE_DATABASE_URL": d.AppURL, "ALICE_MIGRATE_DATABASE_URL": d.OwnerURL,
		"ALICE_KEYS_DIR": t.TempDir(), "ALICE_STATE_DIR": stateDir,
	}))
	require.NoError(t, err)
	ctx := context.Background()
	log := logging.New(&lockedBuffer{}, slog.LevelInfo)
	svc, err := buildServices(ctx, d.App, cfg, newClock(), log)
	require.NoError(t, err)
	require.NoError(t, svc.license.Start(ctx))
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	sender, err := buildSender(d.App, cfg, catalog, newClock(), log)
	require.NoError(t, err)
	_, err = svc.inventory.EnsurePlatformKey(ctx)
	require.NoError(t, err)
	t.Cleanup(svc.sshPool.Close)
	sched := buildScheduler(svc, sender, newClock(), log)
	runner := buildRunner(d.App, svc, newClock(), log)
	return &e2eStack{t: t, d: d, stateDir: stateDir, svc: svc, runner: runner, sched: sched, h: testHandler(testDeps{
		OwnerURL: d.OwnerURL, Setup: svc.setup, License: svc.license, Scheduler: sched, Sender: sender,
		StateDir: stateDir, Log: log, ResetLimits: func() {}, Inventory: svc.inventory, Runner: runner,
	})}
}

func (s *e2eStack) post(path, body string) *httptest.ResponseRecorder {
	s.t.Helper()
	return postTest(s.t, s.h, path, body)
}

func (s *e2eStack) mail() []map[string]string {
	s.t.Helper()
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/mail", nil))
	var body struct{ Messages []map[string]string }
	require.NoError(s.t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Messages
}

func (s *e2eStack) count(sql string) int { return countRows(s.t, s.d, sql) }

// After a clock move the evaluation and the email sender run at once: no hourly wait.
func TestE2EClockMoveEvaluatesAndSendsEmailAtOnce(t *testing.T) {
	s := newE2EStack(t)
	id := insertUser(t, s.d, "admin", "admin")
	_, err := s.d.Owner.Exec(context.Background(), `UPDATE users SET email = 'admin@example.com' WHERE id = $1`, id)
	require.NoError(t, err)
	require.Empty(t, s.mail())

	require.Equal(t, http.StatusOK, s.post("/test/clock", `{"advance_seconds":`+"2073600"+`}`).Code) // 24 days: warning due
	assert.Equal(t, 1, s.count("SELECT count(*) FROM license_history WHERE event = 'notice'"), "evaluated at once")
	msgs := s.mail()
	require.Len(t, msgs, 1, "sent at once")
	assert.Equal(t, "admin@example.com", msgs[0]["to"])

	// A forward move of 3 more days is another threshold; moving back sends nothing.
	require.Equal(t, http.StatusOK, s.post("/test/clock", `{"advance_seconds":-172800}`).Code)
	assert.Len(t, s.mail(), 1)
}

// Task 7 carry-in and Task 16 ruling: after the reset there is a fresh installation, no
// license files, no time record file and no mail.
func TestE2EResetStartsAFreshInstallation(t *testing.T) {
	s := newE2EStack(t)
	ctx := context.Background()
	oldID := s.svc.license.Snapshot().InstallationID
	rec := s.post("/test/license", `{}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var lic struct{ License string }
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &lic))
	_, err := s.svc.license.Install(ctx, []byte(lic.License), audit.SystemActor("test"), uuid.Nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, s.post("/test/clock", `{"advance_seconds":86400}`).Code)
	require.Equal(t, 1, s.count("SELECT count(*) FROM license_files"))
	require.NoError(t, e2eMailbox.Send(ctx, notify.Message{To: "old@example.com", Subject: "old", Body: "old"}))

	require.Equal(t, http.StatusNoContent, s.post("/test/reset", ``).Code)

	snap := s.svc.license.Snapshot()
	assert.True(t, snap.Ready)
	assert.NotEqual(t, oldID, snap.InstallationID, "a new installation ID")
	// AUD-18: a properly new, sealed installation with a fresh evaluation, not a removed one; the
	// platform key (whose audit event marks a started installation) is created after the start.
	assert.False(t, snap.InstallationTampered)
	assert.Equal(t, license.PhaseEvaluation, snap.Eval.Phase)
	assert.Equal(t, 30, snap.Eval.DaysLeft)
	assert.Zero(t, s.count("SELECT count(*) FROM audit_log WHERE action = 'license.installation_tampered'"))
	assert.Equal(t, 1, s.count("SELECT count(*) FROM audit_log WHERE action = 'platform_key.created'"))
	require.Equal(t, http.StatusNoContent, s.post("/test/reset", ``).Code, "a second reset")
	assert.Equal(t, license.PhaseEvaluation, s.svc.license.Snapshot().Eval.Phase)
	assert.Zero(t, s.count("SELECT count(*) FROM audit_log WHERE action = 'license.installation_tampered'"))
	snap = s.svc.license.Snapshot()
	assert.Equal(t, 1, s.count("SELECT count(*) FROM license"), "the installation row exists again")
	assert.Zero(t, s.count("SELECT count(*) FROM license_files"))
	assert.Empty(t, s.mail())
	assert.WithinDuration(t, time.Now(), e2eClock.Now(), time.Minute, "the demo clock is reset")
	raw, err := os.ReadFile(filepath.Join(s.stateDir, license.HWMFileName))
	require.NoError(t, err, "the time record was written again by the restart")
	assert.NotEmpty(t, raw)
	assert.True(t, strings.HasPrefix(snap.InstallationID, "ALICE-"), "installation id format: %s", snap.InstallationID)
}

// The reset empties the Phase 3 tables and creates a new platform key at once, so the next
// test can prepare its SSH target with the key the wizard shows.
func TestE2EResetCreatesANewPlatformKey(t *testing.T) {
	s := newE2EStack(t)
	ctx := context.Background()
	before, err := s.svc.inventory.PlatformKey(ctx)
	require.NoError(t, err)

	require.Equal(t, http.StatusNoContent, s.post("/test/reset", ``).Code)

	after, err := s.svc.inventory.PlatformKey(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, before.Fingerprint, after.Fingerprint, "a new key for the new installation")
	assert.Equal(t, 1, s.count("SELECT count(*) FROM credentials"))
	assert.Equal(t, 1, s.count("SELECT count(*) FROM audit_log WHERE action = 'platform_key.created'"))
	assert.Zero(t, s.count("SELECT count(*) FROM targets"))
}

// Carry 5: /test/license/tamper makes the "License data was changed outside Alice" banner reachable.
func TestE2ELicenseTamperShowsTheBanner(t *testing.T) {
	s := newE2EStack(t)
	ctx := context.Background()
	assert.Equal(t, http.StatusConflict, s.post("/test/license/tamper", ``).Code, "no stored file yet")

	rec := s.post("/test/license", `{}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var lic struct{ License string }
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &lic))
	_, err := s.svc.license.Install(ctx, []byte(lic.License), audit.SystemActor("test"), uuid.Nil)
	require.NoError(t, err)
	require.False(t, s.svc.license.Snapshot().Tampered)

	rec = s.post("/test/license/tamper", ``)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"tampered_seq":1}`, rec.Body.String())

	snap := s.svc.license.Snapshot()
	assert.True(t, snap.Tampered, "the evaluation ran at once")
	var kinds []string
	for _, b := range snap.Banners(true) {
		kinds = append(kinds, b.Kind)
	}
	assert.Contains(t, kinds, "tampered")
	assert.Equal(t, 1, s.count("SELECT count(*) FROM audit_log WHERE action = 'license.tampered'"))
}

// /test/jobs/drain runs due jobs at once: a connection test to an address that does not
// resolve ends as dead (a retryable failure on its only attempt) with ssh.unreachable, and a
// second drain finds nothing.
func TestE2EJobsDrainRunsDueJobs(t *testing.T) {
	s := newE2EStack(t)
	ctx := context.Background()
	admin := insertUser(t, s.d, "admin", "admin")
	_, jobID, err := s.svc.inventory.CreateTarget(ctx,
		inventory.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: admin, Name: "admin"}, UserID: admin, Role: rbac.Admin},
		inventory.NewTarget{Name: "nowhere", Type: "linux", Host: "nowhere.invalid"})
	require.NoError(t, err)

	rec := s.post("/test/jobs/drain", ``)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"ran":1}`, rec.Body.String())
	v, err := s.svc.queue.Get(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, jobs.StatusDead, v.Status)
	assert.Equal(t, "ssh.unreachable", v.LastErrorCode)

	assert.JSONEq(t, `{"ran":0}`, s.post("/test/jobs/drain", ``).Body.String())
}

// The runner serve builds runs the Phase 4 jobs (a runner claims only the types it has handlers
// for: RunOnce reports true) and the scheduler runs the deployment recovery sweep. A job for a
// deployment that does not exist ends failed with system.not_found.
func TestWiringRunsDeployJobs(t *testing.T) {
	s := newE2EStack(t)
	ctx := context.Background()
	for _, typ := range []jobs.Type{jobs.CertificateDeployRecover, jobs.CertificateDeploy} {
		id, _, err := s.svc.queue.Enqueue(ctx, jobs.Spec{Type: typ, Kind: jobs.KindSystem,
			Payload: map[string]string{"deployment_id": uuid.NewString()}})
		require.NoError(t, err, typ.Name)
		ran, err := s.runner.RunOnce(ctx)
		require.NoError(t, err, typ.Name)
		require.True(t, ran, "the built runner claims %s", typ.Name)
		v, err := s.svc.queue.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, jobs.StatusFailed, v.Status, typ.Name)
		assert.Equal(t, "system.not_found", v.LastErrorCode, typ.Name)
	}
	require.NoError(t, s.sched.RunNow(ctx, jobs.DeploymentRecoverySweep.Name), "the sweep is a task of the built scheduler")
	require.NoError(t, checkWiring(s.svc.registry, s.runner, s.sched))
}

// POST /test/scheduler/run runs one periodic task at once: the deployment recovery sweep (and any
// other scheduled task) is drivable from Playwright without waiting for its minute.
func TestE2ESchedulerRunEndpoint(t *testing.T) {
	s := newE2EStack(t)
	rec := s.post("/test/scheduler/run", `{"task":"deployment.recovery_sweep"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"task":"deployment.recovery_sweep"}`, rec.Body.String())
	assert.Equal(t, http.StatusNotFound, s.post("/test/scheduler/run", `{"task":"nope"}`).Code)
	assert.Equal(t, http.StatusBadRequest, s.post("/test/scheduler/run", `{}`).Code)
	assert.Equal(t, http.StatusBadRequest, s.post("/test/scheduler/run", `{"task":"deployment.recovery_sweep","x":1}`).Code)
}

// Every table of the schema is emptied by the reset except the two it keeps (the master key versions: the
// key file on the volume stays, and the migration bookkeeping). A table added by a migration and missing
// from resetSQL (the Key Vault tables once were) makes the reset fail on a foreign key, or leave rows of
// the previous test behind.
func TestE2EResetCoversEveryTable(t *testing.T) {
	s := newE2EStack(t)
	rows, err := s.d.Owner.Query(context.Background(), "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
	require.NoError(t, err)
	defer rows.Close()
	var kept []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		if !regexp.MustCompile(`(?m)(^|[\s,])` + regexp.QuoteMeta(name) + `([\s,]|$)`).MatchString(resetSQL) {
			kept = append(kept, name)
		}
	}
	require.NoError(t, rows.Err())
	require.Len(t, kept, 2, "only two tables are kept: %v", kept)
	assert.Contains(t, kept, "master_key_versions")
}

// overlapFx is a rotation of one location seeded through the legal path of the schema (as the migration
// tests do): a target, a generated old key on it, its policy, and a run created with the policy's overlap.
type overlapFx struct {
	s                   *e2eStack
	target, policy, run uuid.UUID
	oldKey, newKey, loc uuid.UUID
	oldLoc              uuid.UUID
	t0                  time.Time
}

func (f *overlapFx) exec(sql string, args ...any) error {
	_, err := f.s.d.App.Exec(context.Background(), sql, args...)
	return err
}

func (f *overlapFx) must(sql string, args ...any) {
	f.s.t.Helper()
	require.NoError(f.s.t, f.exec(sql, args...))
}

// seedKey inserts a generated key (managed, with a private key row holding no real key material).
func (f *overlapFx) seedKey(fp string, from *uuid.UUID) uuid.UUID {
	f.s.t.Helper()
	pk, key := uuid.New(), uuid.New()
	f.must(`INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'ssh_key', 'ed25519', 256, repeat('a', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2)`, pk, f.t0)
	f.must(`INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, managed, private_key_id, rotated_from, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 256, 'ssh-ed25519 AAAA', true, $3, $4, $5, $5)`, key, fp, pk, from, f.t0)
	return key
}

func (f *overlapFx) keyLocation(key uuid.UUID) uuid.UUID {
	f.s.t.Helper()
	id := uuid.New()
	f.must(`INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, 'deploy', '/home/deploy/.ssh/authorized_keys', 1, $4, $4)`, id, key, f.target, f.t0)
	return id
}

func newOverlapFx(t *testing.T) *overlapFx {
	t.Helper()
	s := newE2EStack(t)
	f := &overlapFx{s: s, t0: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	ctx := context.Background()
	require.NoError(t, s.d.App.QueryRow(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
SELECT gen_random_uuid(), 'web-01', 'linux', jsonb_build_object('host', 'web-01.example.test', 'port', 22, 'username', 'alice-svc'), id,
       'pending_host_key', now(), now() FROM credentials WHERE purpose = 'platform_ssh' RETURNING id`).Scan(&f.target))
	f.oldKey = f.seedKey("SHA256:"+strings.Repeat("O", 43), nil)
	f.oldLoc = f.keyLocation(f.oldKey)
	f.policy = uuid.New()
	f.must(`INSERT INTO rotation_policies (id, ssh_key_id, name, interval_days, created_at, updated_at) VALUES ($1, $2, 'p', 90, $3, $3)`,
		f.policy, f.oldKey, f.t0)
	return f
}

// createRun inserts the run as the planner does: its overlap is the policy's at that moment.
func (f *overlapFx) createRun() {
	f.s.t.Helper()
	f.run = uuid.New()
	f.must(`INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type, overlap_minutes, planned_for,
    notified_at, created_at, updated_at)
SELECT $1, p.id, p.ssh_key_id, 'manual', 'dry_run_notified', '{}', repeat('0', 64), 'ed25519', p.overlap_minutes, $3, $3, $3, $3
FROM rotation_policies p WHERE p.id = $2`, f.run, f.policy, f.t0)
	f.loc = uuid.New()
	f.must(`INSERT INTO rotation_locations (id, rotation_id, n, old_location_id, target_id, os_user, file_path, state, updated_at)
VALUES ($1, $2, 1, $3, $4, 'deploy', '/home/deploy/.ssh/authorized_keys', 'planned', $5)`, f.loc, f.run, f.oldLoc, f.target, f.t0)
}

func (f *overlapFx) locSet(set string, args ...any) error {
	return f.exec("UPDATE rotation_locations SET "+set+" WHERE id = $1", append([]any{f.loc}, args...)...)
}

func pgState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func pgConstraint(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.ConstraintName
	}
	return ""
}

// POST /test/rotation/overlap writes the policy's overlap (and its version) on the real schema; a deleted
// or unknown policy is 404 and keeps its value.
func TestRotationOverlapEndpointSetsThePolicy(t *testing.T) {
	f := newOverlapFx(t)
	rec := f.s.post("/test/rotation/overlap", `{"policy_id":"`+f.policy.String()+`","minutes":1}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"overlap_minutes":1}`, rec.Body.String())
	assert.Equal(t, 1, f.s.count("SELECT overlap_minutes FROM rotation_policies WHERE id = '"+f.policy.String()+"'"))
	assert.Equal(t, 2, f.s.count("SELECT version FROM rotation_policies WHERE id = '"+f.policy.String()+"'"), "an edit with the old ETag is refused")

	// The overlap of a run is the policy's when the run was created; the endpoint never touches a run.
	f.createRun()
	require.Equal(t, http.StatusOK, f.s.post("/test/rotation/overlap", `{"policy_id":"`+f.policy.String()+`","minutes":30}`).Code)
	assert.Equal(t, 1, f.s.count("SELECT overlap_minutes FROM rotations WHERE id = '"+f.run.String()+"'"))

	assert.Equal(t, http.StatusNotFound, f.s.post("/test/rotation/overlap", `{"policy_id":"`+uuid.NewString()+`","minutes":1}`).Code)
	f.must("UPDATE rotations SET status = 'cancelled', finished_at = $2 WHERE id = $1", f.run, f.t0)
	f.must("UPDATE rotation_policies SET deleted_at = $2 WHERE id = $1", f.policy, f.t0)
	assert.Equal(t, http.StatusNotFound, f.s.post("/test/rotation/overlap", `{"policy_id":"`+f.policy.String()+`","minutes":5}`).Code)
	assert.Equal(t, 30, f.s.count("SELECT overlap_minutes FROM rotation_policies WHERE id = '"+f.policy.String()+"'"))
}

// A zero overlap shortens the wait and nothing else: with the policy's overlap set to 0 through the test
// endpoint, the run goes from the verification straight to removing_old, and the database still refuses
// to send the old key's removal without a login with the new key strictly after the verification and at
// most 15 minutes before the send (the old-key rule holds whatever the endpoint wrote).
func TestZeroOverlapStillNeedsTheRecheck(t *testing.T) {
	f := newOverlapFx(t)
	require.Equal(t, http.StatusOK, f.s.post("/test/rotation/overlap", `{"policy_id":"`+f.policy.String()+`","minutes":0}`).Code)
	f.createRun()
	assert.Equal(t, 0, f.s.count("SELECT overlap_minutes FROM rotations WHERE id = '"+f.run.String()+"'"))

	f.newKey = f.seedKey("SHA256:"+strings.Repeat("N", 43), &f.oldKey)
	f.must("UPDATE rotations SET status = 'adding_new', new_ssh_key_id = $2, started_at = $3 WHERE id = $1", f.run, f.newKey, f.t0)
	require.NoError(t, f.locSet("state = 'adding', add_op_id = gen_random_uuid(), add_sent_at = $2", f.t0))
	newLoc := f.keyLocation(f.newKey)
	require.NoError(t, f.locSet("state = 'added', added_line_no = 2, new_location_id = $2", newLoc))
	require.NoError(t, f.locSet("state = 'verified', verified_at = $2", f.t0))
	f.must("UPDATE rotations SET status = 'overlap', verified_at = $2, overlap_until = $2 WHERE id = $1", f.run, f.t0)
	f.must("UPDATE rotations SET status = 'removing_old', removal_allowed = true WHERE id = $1", f.run)

	op, sent := uuid.New(), f.t0.Add(time.Minute)
	assert.Equal(t, "Z1011", pgState(f.locSet(`state = 'removing', remove_op_id = $2, remove_verified_at = verified_at, remove_sent_at = $3`, op, sent)),
		"no re-check: the verification is not the login a removal relies on")
	assert.Equal(t, "Z1011", pgState(f.locSet(`state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`, op, sent)),
		"no re-check at all")
	require.NoError(t, f.locSet("reverified_at = $2", f.t0.Add(time.Minute)))
	assert.Equal(t, "rotation_locations_removal_fresh", pgConstraint(f.locSet(`state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`,
		op, f.t0.Add(17*time.Minute))), "a re-check older than 15 minutes is not fresh")
	require.NoError(t, f.locSet(`state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`, op, f.t0.Add(2*time.Minute)),
		"a fresh re-check allows the removal")
}
