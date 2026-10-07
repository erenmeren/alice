//go:build integration

package reports_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/settings"
	"alice/internal/rbac"
	"alice/internal/reports"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var t0 = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

type lic struct{ eval license.Evaluation }

func (l lic) Snapshot() license.Snapshot { return license.Snapshot{Eval: l.eval} }

type delivery struct{ d notify.Delivery }

func (x delivery) Delivery(context.Context) (notify.Delivery, error) { return x.d, nil }

type world struct {
	svc            *reports.Service
	d              *pgtest.DB
	web1, web2, hk uuid.UUID
}

// seedPolicy inserts a generated key and an enabled rotation policy named label that runs next at next.
func seedPolicy(t *testing.T, d *pgtest.DB, label string, next time.Time) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	key, pol, pk := uuid.New(), uuid.New(), uuid.New()
	_, err := d.Owner.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'ed25519', 256, $2, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, pk, seed.Hex(pk.String()))
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, managed, private_key_id, label,
first_seen_at, created_at) VALUES ($1::uuid, 'SHA256:' || substr(repeat(md5($1::uuid::text), 2), 1, 43), 'ssh-ed25519', 256,
'ssh-ed25519 AAAA', true, $2, $3, now(), now())`, key, pk, label)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `INSERT INTO rotation_policies (id, ssh_key_id, name, enabled, interval_days, next_run_at, created_at, updated_at)
VALUES ($1, $2, $3, true, 30, $4, now(), now())`, pol, key, label, next)
	require.NoError(t, err)
	return pol
}

// newWorld seeds C17's data set (the e2e seed endpoint's) at t0.
func newWorld(t *testing.T, failing bool) world {
	t.Helper()
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	must := func(id uuid.UUID, err error) uuid.UUID { require.NoError(t, err); return id }
	web1 := must(seed.Target(ctx, d.Owner, "seed-web-1", "linux", "ok", nil))
	web2 := must(seed.Target(ctx, d.Owner, "seed-web-2", "linux", "ok", nil))
	hk := must(seed.Target(ctx, d.Owner, "seed-web-3", "linux", "host_key_changed", nil))
	at := func(dd time.Duration) time.Time { return t0.Add(dd) }
	must(seed.Certificate(ctx, d.Owner, "www.seed.test", at(7*day-time.Hour), []uuid.UUID{web1}, "www.seed.test"))
	api := must(seed.Certificate(ctx, d.Owner, "api.seed.test", at(5*day), []uuid.UUID{web1}))
	must(seed.Certificate(ctx, d.Owner, "old.seed.test", at(-2*day), []uuid.UUID{web1}))
	must(seed.Certificate(ctx, d.Owner, "shop.seed.test", at(20*day), []uuid.UUID{web1}))
	must(seed.Certificate(ctx, d.Owner, "mail.seed.test", at(25*day), []uuid.UUID{web2}))
	must(seed.Certificate(ctx, d.Owner, "docs.seed.test", at(45*day), []uuid.UUID{web2}))
	must(seed.Certificate(ctx, d.Owner, "blog.seed.test", at(200*day), []uuid.UUID{web2}))
	must(seed.Certificate(ctx, d.Owner, "intra.seed.test", at(29*day), []uuid.UUID{hk}))
	must(seed.Certificate(ctx, d.Owner, "spare.seed.test", at(3*day), nil))
	must(seed.Deployment(ctx, d.Owner, api, web1, "failed", "ngx.reload_failed", at(-day)))
	must(seed.Deployment(ctx, d.Owner, api, web1, "failed", "ngx.reload_failed", at(-8*day))) // outside the window
	must(seed.Deployment(ctx, d.Owner, api, web1, "rolled_back", "ngx.reload_failed", at(-2*day)))
	seedPolicy(t, d, "soon", at(3*day))
	seedPolicy(t, d, "later", at(20*day)) // outside RotationWindow
	_, err := d.Owner.Exec(ctx, `INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type,
overlap_minutes, planned_for, notified_at, created_at, updated_at)
SELECT $1, p.id, p.ssh_key_id, 'manual', 'dry_run_notified', '{}', repeat('a', 64), 'ed25519', 0, $2, $2, $2, $2
FROM rotation_policies p WHERE p.name = 'soon'`, uuid.New(), t0)
	require.NoError(t, err)
	al := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: lic{}})
	del := notify.Delivery{}
	if failing {
		del = notify.Delivery{ConsecutiveFailures: 3, LastFailureCode: "smtp.connect"}
	}
	ends := t0.Add(40 * day)
	svc := reports.New(reports.Config{Pool: d.App, Clock: clk, Audit: audit.New(clk), Alerts: al, Delivery: delivery{del},
		License: lic{license.Evaluation{Phase: license.PhaseActive, EndsAt: ends, DaysLeft: 40}}})
	return world{svc: svc, d: d, web1: web1, web2: web2, hk: hk}
}

// §26.9 "dashboard API tests with seeded data (exact counts)"; exit "the dashboard numbers match the database".
func TestSummaryCountsMatchTheDatabase(t *testing.T) {
	w := newWorld(t, false)
	s, err := w.svc.Summary(context.Background(), reports.Viewer{Role: rbac.Admin})
	require.NoError(t, err)
	// Cumulative windows with the list filter's semantics: each count equals the rows its dashboard link opens.
	assert.Equal(t, alerts.Counts{Monitored: 8, Expired: 1, Within7: 3, Within30: 6, Within60: 7}, s.Certificates)
	assert.Equal(t, 3, s.Targets.Total)
	assert.Equal(t, 2, s.Targets.ByStatus["ok"])
	assert.Equal(t, 1, s.Targets.ByStatus["host_key_changed"])
	assert.Equal(t, 0, s.Targets.ByStatus["unreachable"], "every known status is present")
	assert.Equal(t, 2, s.Deployments.Failed7d, "the failed one and the rolled back one; the 8-day-old one is outside the window")
	require.Len(t, s.Deployments.Recent, 2)
	assert.Equal(t, "failed", s.Deployments.Recent[0].Status)
	assert.Equal(t, "rolled_back", s.Deployments.Recent[1].Status)
	require.Len(t, s.Rotation.Upcoming, 1, "the policy due in 20 days is outside RotationWindow")
	assert.Equal(t, "soon", s.Rotation.Upcoming[0].KeyLabel)
	assert.Equal(t, t0.Add(3*day), s.Rotation.Upcoming[0].NextRunAt)
	assert.Equal(t, 1, s.Rotation.Running)
	assert.Equal(t, 0, s.Rotation.NeedsAttention)
	assert.Equal(t, "api.seed.test", s.Deployments.Recent[0].CertificateName)
	assert.Equal(t, "seed-web-1", s.Deployments.Recent[0].TargetName)
	assert.Equal(t, "ngx.reload_failed", s.Deployments.Recent[0].ErrorCode)
	assert.Equal(t, string(license.PhaseActive), s.License.Phase)
	require.NotNil(t, s.License.DaysLeft)
	assert.Equal(t, 40, *s.License.DaysLeft)
	require.NotNil(t, s.Notifications)
	assert.False(t, s.Notifications.Failing())
	// The database agrees, counted independently.
	var failed int
	require.NoError(t, w.d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM deployments
WHERE status IN ('failed', 'rolled_back', 'rollback_failed', 'needs_attention') AND coalesce(finished_at, created_at) >= $1`,
		t0.Add(-7*day)).Scan(&failed))
	assert.Equal(t, failed, s.Deployments.Failed7d)
	var monitored int
	require.NoError(t, w.d.Owner.QueryRow(context.Background(), `SELECT count(DISTINCT c.id) FROM certificates c
JOIN certificate_locations l ON l.certificate_id = c.id AND l.missing_since IS NULL`).Scan(&monitored))
	assert.Equal(t, monitored, s.Certificates.Monitored)
}

// Review Focus 5, R42 row 13: Operators see neither the audit head, nor the delivery state, nor license details.
func TestSummaryIsRoleFiltered(t *testing.T) {
	w := newWorld(t, true)
	ctx := context.Background()
	op, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Operator})
	require.NoError(t, err)
	assert.Nil(t, op.Notifications)
	assert.Nil(t, op.Audit)
	assert.Empty(t, op.License.Phase)
	assert.Nil(t, op.License.EndsAt)
	aud, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Auditor})
	require.NoError(t, err)
	assert.Nil(t, aud.Notifications)
	assert.Equal(t, string(license.PhaseActive), aud.License.Phase)
	adm, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Admin})
	require.NoError(t, err)
	require.NotNil(t, adm.Notifications)
	assert.True(t, adm.Notifications.Failing())
}

func TestSummaryAuditHead(t *testing.T) {
	w := newWorld(t, false)
	ctx := context.Background()
	s, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Auditor})
	require.NoError(t, err)
	assert.Nil(t, s.Audit, "no verification yet")
	clk := clock.NewFake(t0)
	asvc := audit.NewService(audit.New(clk), w.d.App)
	require.NoError(t, asvc.Write(ctx, audit.Event{Actor: audit.SystemActor("t"), Action: "test.one", Result: audit.Success}))
	rep, err := asvc.Verify(ctx, audit.SystemActor("scheduler"))
	require.NoError(t, err)
	require.NoError(t, settings.Set(ctx, w.d.App, "jobs.audit_verify", jobs.AuditVerifyState{LastIntactAt: t0}, t0))
	s, err = w.svc.Summary(ctx, reports.Viewer{Role: rbac.Auditor})
	require.NoError(t, err)
	require.NotNil(t, s.Audit)
	assert.Equal(t, rep.HeadSeq, s.Audit.HeadSeq)
	assert.True(t, s.Audit.Intact)
	require.NoError(t, settings.Set(ctx, w.d.App, "jobs.audit_verify",
		jobs.AuditVerifyState{LastIntactAt: t0, LastBrokenAt: t0.Add(time.Hour), AlertedBadSeq: 1, AlertedProblem: "hash_mismatch"}, t0))
	s, err = w.svc.Summary(ctx, reports.Viewer{Role: rbac.Admin})
	require.NoError(t, err)
	assert.False(t, s.Audit.Intact)
}

func TestExpiringListIsSoonestFirst(t *testing.T) {
	w := newWorld(t, false)
	items, err := w.svc.Expiring(context.Background(), 30, 50)
	require.NoError(t, err)
	var names []string
	for _, it := range items {
		names = append(names, it.Name)
	}
	assert.Equal(t, []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test", "mail.seed.test", "intra.seed.test"}, names)
	assert.Equal(t, []string{"www.seed.test"}, items[2].Websites)
	_, err = w.svc.Expiring(context.Background(), 0, 50)
	assert.Error(t, err)
	_, err = w.svc.Expiring(context.Background(), 30, 201)
	assert.Error(t, err)
}

func TestAttentionConditions(t *testing.T) {
	w := newWorld(t, true)
	ctx := context.Background()
	require.NoError(t, seed.SetStatus(ctx, w.d.Owner, w.web2, "auth_failed"))
	require.NoError(t, settings.Set(ctx, w.d.App, "jobs.audit_verify",
		jobs.AuditVerifyState{LastIntactAt: t0, LastBrokenAt: t0.Add(time.Hour), AlertedBadSeq: 1, AlertedProblem: "hash_mismatch"}, t0))
	kinds := func(v reports.Viewer) []string { // distinct kinds: two failed deployments are two conditions
		cs, err := w.svc.Attention(ctx, v)
		require.NoError(t, err)
		seen := map[string]bool{}
		var out []string
		for _, c := range cs {
			if !seen[c.Kind] {
				seen[c.Kind] = true
				out = append(out, c.Kind)
			}
		}
		return out
	}
	assert.ElementsMatch(t, []string{"host_key_changed", "auth_failed", "deployment_failed", "audit_broken", "notifications_failing"},
		kinds(reports.Viewer{Role: rbac.Admin}))
	assert.ElementsMatch(t, []string{"host_key_changed", "auth_failed", "deployment_failed", "audit_broken"},
		kinds(reports.Viewer{Role: rbac.Auditor}))
	assert.ElementsMatch(t, []string{"host_key_changed", "auth_failed", "deployment_failed"}, kinds(reports.Viewer{Role: rbac.Operator}))
	s, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Admin})
	require.NoError(t, err)
	assert.Equal(t, 6, s.Attention, "host key, auth, two failed deployments, audit and notifications")
}

// A count equals the rows its dashboard link opens: the boundaries are strict, as the inventory's windows are.
func TestSummaryWindowBoundariesAreStrict(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	web := func() uuid.UUID {
		id, err := seed.Target(ctx, d.Owner, "b-web", "linux", "ok", nil)
		require.NoError(t, err)
		return id
	}()
	for _, c := range []struct {
		cn string
		at time.Duration
	}{{"at-now", 0}, {"at-7", 7 * day}, {"at-30", 30 * day}, {"at-60", 60 * day}, {"in-60", 60*day - time.Second}} {
		_, err := seed.Certificate(ctx, d.Owner, c.cn, t0.Add(c.at), []uuid.UUID{web})
		require.NoError(t, err)
	}
	al := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: lic{}})
	svc := reports.New(reports.Config{Pool: d.App, Clock: clk, Audit: audit.New(clk), Alerts: al, Delivery: delivery{}, License: lic{}})
	s, err := svc.Summary(ctx, reports.Viewer{Role: rbac.Operator})
	require.NoError(t, err)
	assert.Equal(t, alerts.Counts{Monitored: 5, Expired: 0, Within7: 1, Within30: 2, Within60: 4}, s.Certificates)
}

// The Key Vault line is cumulative too.
func TestSummaryKeyVaultLineIsCumulative(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	past, soon := t0.Add(-day), t0.Add(10*day)
	vault, err := seed.Target(ctx, d.Owner, "kv-1", "azure_key_vault", "ok", &past)
	require.NoError(t, err)
	_, _, err = seed.KeyVault(ctx, d.Owner, vault, "kvcert", soon, nil, "kvkey", soon)
	require.NoError(t, err)
	al := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: lic{}})
	svc := reports.New(reports.Config{Pool: d.App, Clock: clk, Audit: audit.New(clk), Alerts: al, Delivery: delivery{}, License: lic{}})
	s, err := svc.Summary(ctx, reports.Viewer{Role: rbac.Operator})
	require.NoError(t, err)
	assert.Equal(t, 1, s.Certificates.KVExpired)
	assert.Equal(t, 3, s.Certificates.KVWithin30, "the expired client secret, the certificate and the key due in 10 days")
}
