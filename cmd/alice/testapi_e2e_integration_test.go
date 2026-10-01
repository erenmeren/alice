//go:build integration && e2e

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
	return &e2eStack{t: t, d: d, stateDir: stateDir, svc: svc, h: testHandler(testDeps{
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
