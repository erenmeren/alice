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

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/config"
	"alice/internal/platform/logging"
	"alice/internal/rbac"
	"alice/internal/reports"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
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
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	svc, err := buildServices(ctx, d.App, cfg, catalog, newClock(), log)
	require.NoError(t, err)
	require.NoError(t, svc.license.Start(ctx))
	sender := buildSender(d.App, svc, catalog, newClock(), log)
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

// overlapFx is the rotation fixture on the e2e stack's database.
type overlapFx struct {
	*rotFixture
	s *e2eStack
}

func newOverlapFx(t *testing.T) *overlapFx {
	t.Helper()
	s := newE2EStack(t)
	return &overlapFx{rotFixture: newRotFixture(t, s.d, time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC), false), s: s}
}

func (f *rotFixture) locSet(set string, args ...any) error {
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

	f.start()
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
	assert.Equal(t, "rotation_locations_times", pgConstraint(f.locSet("reverified_at = $2", f.t0)),
		"a re-check is strictly later than the verification: the first verification is not enough")
	assert.Equal(t, "rotation_locations_times", pgConstraint(f.locSet(`state = 'removing', reverified_at = verified_at, remove_op_id = $2, remove_verified_at = verified_at, remove_sent_at = $3`,
		op, sent)), "nor in the statement that sends the removal")
	require.NoError(t, f.locSet("reverified_at = $2", f.t0.Add(time.Minute)))
	assert.Equal(t, "Z1011", pgState(f.locSet(`state = 'removing', remove_op_id = $2, remove_verified_at = verified_at, remove_sent_at = $3`,
		op, f.t0.Add(2*time.Minute))), "with a re-check on record, a removal sent on the first verification is refused")
	assert.Equal(t, "rotation_locations_removal_fresh", pgConstraint(f.locSet(`state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`,
		op, f.t0.Add(17*time.Minute))), "a re-check older than 15 minutes is not fresh")
	require.NoError(t, f.locSet(`state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at, remove_sent_at = $3`, op, f.t0.Add(2*time.Minute)),
		"a fresh re-check allows the removal")
}

// B8 (pre-flight ruling) and C17: the answer of POST /test/seed/dashboard is what the wired dashboard, its expiring
// list and the certificate page really show for the seeded rows, so the journeys assert true numbers. The certificate
// counts are the dashboard's cumulative windows (Task 9: every certificate row with the list's predicates, expired ones
// included), so each equals the rows its link opens; spare.seed.test is on no server, so it is counted by the windows
// but neither monitored nor listed as expiring.
func TestSeedDashboardMatchesTheDashboard(t *testing.T) {
	s := newE2EStack(t)
	ctx := context.Background()
	rec := s.post("/test/seed/dashboard", `{}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var got seed.DashboardAnswer
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, map[string]int{"monitored": 8, "expired": 1, "within_7": 4, "within_30": 7, "within_60": 8}, got.Certificates)
	assert.Equal(t, map[string]int{"total": 3, "ok": 2, "host_key_changed": 1}, got.Targets)
	assert.Equal(t, map[string]int{"failed_7d": 1}, got.Deployments)
	assert.Equal(t, []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test", "mail.seed.test", "intra.seed.test"},
		got.Expiring30)
	require.NotNil(t, got.ServerFilter)
	assert.Equal(t, "seed-web-1", got.ServerFilter.Target)
	assert.Equal(t, []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test"}, got.ServerFilter.Expiry30)

	sum, err := s.svc.reports.Summary(ctx, reports.Viewer{Role: rbac.Operator})
	require.NoError(t, err)
	assert.Equal(t, alerts.Counts{Monitored: got.Certificates["monitored"], Expired: got.Certificates["expired"],
		Within7: got.Certificates["within_7"], Within30: got.Certificates["within_30"], Within60: got.Certificates["within_60"]},
		sum.Certificates)
	assert.Equal(t, got.Deployments["failed_7d"], sum.Deployments.Failed7d)
	assert.Equal(t, got.Targets["total"], sum.Targets.Total)
	for _, st := range []string{"ok", "host_key_changed"} {
		assert.Equal(t, got.Targets[st], sum.Targets.ByStatus[st], st)
	}

	items, err := s.svc.reports.Expiring(ctx, 30, 200)
	require.NoError(t, err)
	var expiring []string
	for _, it := range items {
		expiring = append(expiring, it.Name)
	}
	assert.Equal(t, got.Expiring30, expiring)

	// Each count is the number of rows its link opens on the certificate page.
	for window, key := range map[string]string{"expired": "expired", "7": "within_7", "30": "within_30", "60": "within_60"} {
		page, err := s.svc.inventory.ListCertificates(ctx, inventory.CertificateFilter{Expiry: window, Limit: 200})
		require.NoError(t, err)
		assert.Len(t, page.Items, got.Certificates[key], "expiry=%s", window)
	}
	var target uuid.UUID
	require.NoError(t, s.d.Owner.QueryRow(ctx, `SELECT id FROM targets WHERE name = $1`, got.ServerFilter.Target).Scan(&target))
	page, err := s.svc.inventory.ListCertificates(ctx, inventory.CertificateFilter{TargetID: target, Expiry: "30", Limit: 200})
	require.NoError(t, err)
	var onServer []string
	for _, c := range page.Items {
		onServer = append(onServer, c.SubjectCN)
	}
	assert.Equal(t, got.ServerFilter.Expiry30, onServer)

	// The seed is one data set per installation: a second call fails (the target names are taken) without database text.
	rec = s.post("/test/seed/dashboard", `{}`)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "duplicate")
}
