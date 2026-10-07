//go:build integration

package alerts_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/settings"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var t0 = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

type queued struct {
	template string
	params   map[string]string
}

// recorder is the Notifier: it records what the scan queued (the outbox itself is notify's, tested there).
type recorder struct {
	mu       sync.Mutex
	got      []queued
	fail     error
	failName string // fail only the notice of this item name
}

func (r *recorder) NotifyAdmins(_ context.Context, _ pgx.Tx, template string, params map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil || (r.failName != "" && params["name"] == r.failName) {
		return errors.New("queue failed")
	}
	r.got = append(r.got, queued{template, params})
	return nil
}

func (r *recorder) templates() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, q := range r.got {
		out = append(out, q.template)
	}
	return out
}

type lic struct{ locked bool }

func (l lic) Snapshot() license.Snapshot {
	s := license.Snapshot{}
	if l.locked {
		s.Eval.Phase = license.PhaseLocked
	} else {
		s.Eval.Phase = license.PhaseActive
	}
	return s
}

func newService(t *testing.T, d *pgtest.DB, clk clock.Clock, l lic, r *recorder) *alerts.Service {
	t.Helper()
	return alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: l, Notifier: r})
}

func ledger(t *testing.T, d *pgtest.DB) map[string]int {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), `SELECT kind || ':' || threshold_days::text, count(*) FROM alerts GROUP BY 1`)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		require.NoError(t, rows.Scan(&k, &n))
		out[k] = n
	}
	return out
}

// Review Focus 2, §26.9 "no duplicates": hourly scans over 70 days queue each threshold once and the expiry once.
func TestScanIsExactlyOncePerThreshold(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	seedCert(t, d, "www.example.com", t0.Add(65*day), []uuid.UUID{web}, "www.example.com", "example.com")
	for clk.Now().Before(t0.Add(70 * day)) {
		_, err := s.Scan(context.Background())
		require.NoError(t, err)
		clk.Advance(time.Hour)
	}
	assert.Equal(t, []string{"alert.certificate_expiring", "alert.certificate_expiring", "alert.certificate_expiring",
		"alert.certificate_expiring", "alert.certificate_expiring", "alert.certificate_expired"}, r.templates())
	assert.Equal(t, map[string]int{"certificate_expiry:60": 1, "certificate_expiry:30": 1, "certificate_expiry:14": 1,
		"certificate_expiry:7": 1, "certificate_expiry:1": 1, "certificate_expiry:0": 1}, ledger(t, d))
	first := r.got[0].params
	assert.Equal(t, "www.example.com", first["name"])
	assert.Equal(t, "60", first["days"])
	assert.Equal(t, "2026-12-11 09:00 UTC", first["expires_at"])
	assert.Equal(t, "example.com, www.example.com", first["websites"])
	assert.Equal(t, "web-01", first["servers"])
	assert.NotContains(t, first, "license_note")
}

// §26.9 "catch-up after downtime": Alice down from 31 to 13 days before expiry sends 14 only.
func TestDowntimeCatchUp(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	seedCert(t, d, "www.example.com", t0.Add(40*day), []uuid.UUID{web}, "www.example.com")
	_, err := s.Scan(context.Background()) // 40 days left: the 60-day notice
	require.NoError(t, err)
	clk.Set(t0.Add(27 * day)) // 13 days left after the downtime
	_, err = s.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"certificate_expiry:60": 1, "certificate_expiry:14": 1}, ledger(t, d))
}

// Review Focus 2: two processes scanning at once queue every notice once.
func TestConcurrentScansQueueOnce(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	web := seedTarget(t, d, "web-01", "nginx", nil)
	for i := 0; i < 15; i++ {
		seedCert(t, d, "site-"+string(rune('a'+i))+".example.com", t0.Add(5*day), []uuid.UUID{web})
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := newService(t, d, clk, lic{}, r).Scan(context.Background())
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Len(t, r.templates(), 15)
	assert.Equal(t, map[string]int{"certificate_expiry:7": 15}, ledger(t, d))
}

// A renewal (a new expiry instant) starts a new series; a certificate no longer in use is not monitored.
func TestRenewalStartsANewSeriesAndReplacedIsNotMonitored(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	old := seedCert(t, d, "www.example.com", t0.Add(5*day), []uuid.UUID{web}, "www.example.com")
	_, err := s.Scan(context.Background())
	require.NoError(t, err)
	renewed := seedCert(t, d, "www.example.com", t0.Add(50*day), nil)
	moveLocations(t, d, old, renewed) // the renewal was deployed on the server
	clk.Advance(10 * day)             // the old one has expired, but it is not in use any more
	_, err = s.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"certificate_expiry:7": 1, "certificate_expiry:60": 1}, ledger(t, d),
		"no expired notice for the replaced certificate; the renewed one starts at 60")
}

// R42 row 4: a Key Vault certificate whose current version is the certificate in use on a server alerts once (as the
// certificate); keys and client secrets are scanned too.
func TestKVKindsAreScanned(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	secretExp := t0.Add(20 * day)
	vault := seedTarget(t, d, "prod-vault", "azure_key_vault", &secretExp)
	deployed := seedCert(t, d, "shop.example.com", t0.Add(10*day), []uuid.UUID{web}, "shop.example.com")
	seedKV(t, d, vault, "shop-cert", t0.Add(10*day), &deployed, "signing-key", t0.Add(3*day))
	seedKV(t, d, vault, "other-cert", t0.Add(25*day), nil, "old-key", t0.Add(-1*day))
	_, err := s.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"certificate_expiry:14": 1, "kv_certificate_expiry:30": 1, "kv_key_expiry:7": 1,
		"kv_key_expiry:0": 1, "kv_credential_expiry:30": 1}, ledger(t, d))
	byTpl := map[string]map[string]string{}
	for _, q := range r.got {
		byTpl[q.template+":"+q.params["name"]+q.params["vault"]] = q.params
	}
	assert.Contains(t, byTpl, "alert.kv_key_expired:old-keyprod-vault")
	assert.Contains(t, byTpl, "alert.kv_credential_expiring:prod-vaultprod-vault")
	before, n := ledger(t, d), len(r.got)
	clk.Advance(time.Hour)
	_, err = s.Scan(context.Background())
	require.NoError(t, err)
	assert.Len(t, r.got, n, "no kind resends on the next tick")
	assert.Equal(t, before, ledger(t, d))
	// The tail of the test follows.
	assert.NotContains(t, byTpl, "alert.kv_certificate_expiring:shop-certprod-vault", "deployed: the certificate notice covers it")
}

// Review Focus 2: at most 20 emails per kind and scan; the rest are recorded and summarised in one email.
func TestEmailCapAndSummary(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	for i := 0; i < 25; i++ {
		seedCert(t, d, "s"+uuid.NewString()[:8]+".example.com", t0.Add(time.Duration(i+1)*time.Hour), []uuid.UUID{web})
	}
	res, err := s.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 20, res.Queued[alerts.KindCertificate])
	assert.Equal(t, 5, res.Suppressed[alerts.KindCertificate])
	tpls := r.templates()
	require.Len(t, tpls, 21)
	assert.Equal(t, "alert.more", tpls[20])
	assert.Equal(t, "5", r.got[20].params["count"])
	var emailed, silent int
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		`SELECT count(*) FILTER (WHERE emailed), count(*) FILTER (WHERE NOT emailed) FROM alerts`).Scan(&emailed, &silent))
	assert.Equal(t, [2]int{20, 5}, [2]int{emailed, silent})
	_, err = s.Scan(context.Background())
	require.NoError(t, err)
	assert.Len(t, r.templates(), 21, "suppressed notices are recorded: never sent later")
}

// L-28: in lock, expiry emails continue with the license note and the license page.
func TestL28LockNote(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{locked: true}, r)
	require.NoError(t, settings.Set(context.Background(), d.App, settings.GeneralKey,
		settings.General{PublicURL: "https://alice.example.com", RetiredKeyRetentionDays: 30, Version: 1}, t0))
	web := seedTarget(t, d, "web-01", "nginx", nil)
	vault := seedTarget(t, d, "prod-vault", "azure_key_vault", nil)
	seedCert(t, d, "www.example.com", t0.Add(5*day), []uuid.UUID{web}, "www.example.com")
	seedCert(t, d, "old.example.com", t0.Add(-day), []uuid.UUID{web}, "old.example.com")
	seedKV(t, d, vault, "kv-cert", t0.Add(5*day), nil, "kv-key", t0.Add(90*day))
	_, err := s.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, r.got, 3)
	for _, q := range r.got {
		assert.Equal(t, "https://alice.example.com/license", q.params["license_url"], q.template)
		if q.template == "alert.kv_certificate_expiring" {
			assert.Equal(t, "kv", q.params["license_note"])
		} else {
			assert.Equal(t, "true", q.params["license_note"], q.template)
		}
	}
	var locked bool
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT bool_and(license_locked) FROM alerts`).Scan(&locked))
	assert.True(t, locked)
}

// L-18: without SMTP the notice is recorded and its emails are skipped as skipped_no_smtp, with no error.
func TestL18NoSMTP(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	_, err := d.Owner.Exec(ctx, `INSERT INTO users (id, username, display_name, email, password_hash, role, locale, created_at, updated_at)
VALUES (gen_random_uuid(), 'ada', 'Ada', 'ada@example.com', '$argon2id$x', 'admin', 'tr', now(), now())`)
	require.NoError(t, err)
	s := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: lic{}, Notifier: notify.AdminNotifier{Clock: clk}})
	web := seedTarget(t, d, "web-01", "nginx", nil)
	seedCert(t, d, "www.example.com", t0.Add(6*day), []uuid.UUID{web}, "www.example.com")
	_, err = s.Scan(ctx)
	require.NoError(t, err)
	sender := &notify.Sender{Pool: d.App, Clock: clk} // no Mailer, no Source: SMTP is not configured
	n, err := sender.Drain(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	var status, tpl, locale string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT status, template_key, locale FROM notifications_outbox`).Scan(&status, &tpl, &locale))
	assert.Equal(t, [3]string{"skipped_no_smtp", "alert.certificate_expiring", "tr"}, [3]string{status, tpl, locale})
	assert.Equal(t, map[string]int{"certificate_expiry:7": 1}, ledger(t, d), "the dashboard still has the notice")
}

func TestThresholdSettings(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	s := newService(t, d, clk, lic{}, &recorder{})
	ctx := context.Background()
	got, err := s.Thresholds(ctx)
	require.NoError(t, err)
	assert.Equal(t, alerts.ThresholdSettings{Days: []int{60, 30, 14, 7, 1}}, got)
	got, err = s.SaveThresholds(ctx, audit.SystemActor("test"), 0, []int{3, 90, 21})
	require.NoError(t, err)
	assert.Equal(t, alerts.ThresholdSettings{Days: []int{90, 21, 3}, Version: 1}, got)
	_, err = s.SaveThresholds(ctx, audit.SystemActor("test"), 0, []int{5})
	assert.ErrorIs(t, err, notify.ErrVersion)
	for _, bad := range [][]int{nil, {0}, {366}, {5, 5}, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}} {
		_, err := s.SaveThresholds(ctx, audit.SystemActor("test"), 1, bad)
		assert.Error(t, err, "%v", bad)
	}
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'settings.thresholds_changed'`).Scan(&n))
	assert.Equal(t, 1, n)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	seedCert(t, d, "far.example.com", t0.Add(80*day), []uuid.UUID{web})
	r := &recorder{}
	s2 := newService(t, d, clk, lic{}, r)
	_, err = s2.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"certificate_expiry:90": 1}, ledger(t, d), "the saved thresholds [90 21 3] drive the scan")
}

// The dashboard's counts come from the same definition (R42 rows 4 and 14).
func TestCountsAndItems(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	s := newService(t, d, clk, lic{}, &recorder{})
	web := seedTarget(t, d, "web-01", "nginx", nil)
	for cn, left := range map[string]time.Duration{"a": -day, "b": 3 * day, "c": 7 * day, "d": 8 * day, "e": 30 * day,
		"f": 45 * day, "g": 200 * day} {
		seedCert(t, d, cn+".example.com", t0.Add(left), []uuid.UUID{web})
	}
	seedCert(t, d, "spare.example.com", t0.Add(2*day), nil) // on no server: not monitored
	c, err := s.Counts(context.Background())
	require.NoError(t, err)
	assert.Equal(t, alerts.Counts{Monitored: 7, Expired: 1, Within7: 2, Within30: 2, Within60: 1}, c)
	items, err := s.Items(context.Background(), []alerts.Kind{alerts.KindCertificate}, t0.Add(30*day), 3)
	require.NoError(t, err)
	require.Len(t, items, 3)
	assert.Equal(t, []string{"a.example.com", "b.example.com", "c.example.com"}, []string{items[0].Name, items[1].Name, items[2].Name})
}

func seedTarget(t *testing.T, d *pgtest.DB, name, typ string, secretExpires *time.Time) uuid.UUID {
	t.Helper()
	id, err := seed.Target(context.Background(), d.Owner, name, typ, "ok", secretExpires)
	require.NoError(t, err)
	return id
}

func seedCert(t *testing.T, d *pgtest.DB, cn string, notAfter time.Time, targets []uuid.UUID, websites ...string) uuid.UUID {
	t.Helper()
	id, err := seed.Certificate(context.Background(), d.Owner, cn, notAfter, targets, websites...)
	require.NoError(t, err)
	return id
}

func moveLocations(t *testing.T, d *pgtest.DB, from, to uuid.UUID) {
	t.Helper()
	require.NoError(t, seed.MoveLocations(context.Background(), d.Owner, from, to))
}

func seedKV(t *testing.T, d *pgtest.DB, vault uuid.UUID, certName string, certExpires time.Time, linkCert *uuid.UUID,
	keyName string, keyExpires time.Time) {
	t.Helper()
	_, _, err := seed.KeyVault(context.Background(), d.Owner, vault, certName, certExpires, linkCert, keyName, keyExpires)
	require.NoError(t, err)
}

// Task 1 carry: the levels sent for an old expiry instant never block a renewed one (the series is per instant).
func TestRenewedInstantStartsAFreshSeries(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	vault := seedTarget(t, d, "prod-vault", "azure_key_vault", nil)
	kvCert, _, err := seed.KeyVault(ctx, d.Owner, vault, "shop-cert", t0.Add(5*day), nil, "k", t0.Add(900*day))
	require.NoError(t, err)
	_, err = s.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"kv_certificate_expiry:7": 1}, ledger(t, d))
	// The certificate is renewed in place: the same object, a new expiry instant, again within 7 days.
	_, err = d.Owner.Exec(ctx, `UPDATE kv_certificates SET expires = $2 WHERE id = $1`, kvCert, t0.Add(6*day))
	require.NoError(t, err)
	_, err = s.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, r.templates(), 2, "the old instant's level-7 row does not block the new instant")
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE object_id = $1`, kvCert).Scan(&n))
	assert.Equal(t, 2, n)
	_, err = s.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, r.templates(), 2, "and it is sent once")
}

// Task 1 carry: an item first seen already expired gets exactly one Expired notice.
func TestFirstSeenExpiredGetsOneExpiredNotice(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	seedCert(t, d, "gone.example.com", t0.Add(-30*day), []uuid.UUID{web}, "gone.example.com")
	for range 3 {
		_, err := s.Scan(ctx)
		require.NoError(t, err)
		clk.Advance(day)
	}
	assert.Equal(t, []string{"alert.certificate_expired"}, r.templates())
	assert.Equal(t, map[string]int{"certificate_expiry:0": 1}, ledger(t, d))
	assert.NotContains(t, r.got[0].params, "days")
}

// S-3: a 400-rune name is cut to 300 runes in the ledger, never a CHECK failure that silences the others.
func TestS3LongNameIsTruncated(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	for i := range 9 {
		seedCert(t, d, "ok-"+string(rune('a'+i))+".example.com", t0.Add(time.Duration(i+1)*time.Hour), []uuid.UUID{web})
	}
	seedCert(t, d, strings.Repeat("é", 400), t0.Add(30*time.Minute), []uuid.UUID{web})
	res, err := s.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, 10, res.Queued[alerts.KindCertificate])
	assert.Zero(t, res.Failed)
	var longest int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT max(char_length(subject)) FROM alerts`).Scan(&longest))
	assert.Equal(t, 300, longest)
	for _, q := range r.got {
		assert.LessOrEqual(t, len([]rune(q.params["name"])), 300)
	}
}

// S-3: one item whose notice cannot be queued is logged and skipped; the other nine are queued, and the failed one is
// retried by the next scan (its ledger row was rolled back with the failed queueing).
func TestS3OneFailingItemDoesNotStopTheRest(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	r := &recorder{failName: "bad.example.com"}
	var logs bytes.Buffer
	s := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: lic{}, Notifier: r,
		Log: slog.New(slog.NewTextHandler(&logs, nil))})
	web := seedTarget(t, d, "web-01", "nginx", nil)
	seedCert(t, d, "bad.example.com", t0.Add(time.Hour), []uuid.UUID{web})
	for i := range 9 {
		seedCert(t, d, "ok-"+string(rune('a'+i))+".example.com", t0.Add(time.Duration(i+2)*time.Hour), []uuid.UUID{web})
	}
	res, err := s.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, 9, res.Queued[alerts.KindCertificate])
	assert.Equal(t, 1, res.Failed)
	assert.Equal(t, 1, strings.Count(logs.String(), "could not be recorded"))
	assert.NotContains(t, logs.String(), "bad.example.com", "the subject is not logged")
	assert.Equal(t, map[string]int{"certificate_expiry:1": 9}, ledger(t, d))
	r.failName = ""
	res, err = s.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Queued[alerts.KindCertificate], "the failed item is retried")
}

func TestItemsListsAreCappedAndMarked(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	var targets []uuid.UUID
	var names []string
	for i := range 12 {
		targets = append(targets, seedTarget(t, d, "srv-"+string(rune('a'+i)), "nginx", nil))
		names = append(names, "site-"+string(rune('a'+i))+".example.com")
	}
	seedCert(t, d, "many.example.com", t0.Add(day), targets, names...)
	empty := seedTarget(t, d, "lone", "nginx", nil)
	seedCert(t, d, "", t0.Add(2*day), []uuid.UUID{empty})
	items, err := s.Items(ctx, alerts.Kinds(), t0.Add(10*day), 0)
	require.NoError(t, err)
	require.Len(t, items, 2)
	assert.Len(t, items[0].Websites, 10)
	assert.Len(t, items[0].Servers, 10)
	assert.Len(t, items[0].TargetIDs, 12)
	assert.Len(t, items[1].Name, 16, "no CN, no label: the fingerprint's first 16 characters")
	_, err = s.Scan(ctx)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(r.got[0].params["websites"], ", …"))
	assert.Equal(t, "-", r.got[1].params["websites"])
}

// Contexts: a cancelled context is an error, not a skipped item.
func TestScanFailsOnACancelledContext(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	s := newService(t, d, clk, lic{}, &recorder{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Scan(ctx)
	assert.Error(t, err)
	_, err = s.Counts(ctx)
	assert.Error(t, err)
	_, err = s.Items(ctx, alerts.Kinds(), t0, 0)
	assert.Error(t, err)
}
