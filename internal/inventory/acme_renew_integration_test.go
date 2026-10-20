//go:build integration

package inventory_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/acme/renew"
	"alice/internal/acme/solver"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/rbac"
	"alice/internal/testutil/fakeacme"
	"alice/locales"
)

const day = 24 * time.Hour

// renewWorld is a certWorld whose service mails the Administrators (one English, one Turkish).
type renewWorld struct {
	*certWorld
}

func newRenewWorld(t *testing.T) *renewWorld {
	t.Helper()
	cw := newCertWorld(t)
	cw.svc = inventory.New(inventory.Config{Pool: cw.db.App, Keyring: cw.keyring, Audit: cw.audit, Clock: cw.clock, License: cw.lic,
		Registry: cw.reg, Jobs: cw.jobs, Notifier: notify.AdminNotifier{Clock: cw.clock},
		Log: slog.New(slog.NewTextHandler(cw.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	ayse := cw.user("ayse", rbac.Admin, "ayse@example.test")
	_, err := cw.db.Owner.Exec(cw.ctx, "UPDATE users SET locale = 'tr' WHERE id = $1", ayse.UserID)
	require.NoError(t, err)
	cw.installLicense("LIC-RENEW", 5, 3650) // the tests move the clock months ahead: past the evaluation
	return &renewWorld{certWorld: cw}
}

// otherProcess is a second planner on the same database (another Alice process).
func (w *renewWorld) otherProcess() *inventory.Service {
	return inventory.New(inventory.Config{Pool: w.db.App, Keyring: w.keyring, Audit: w.audit, Clock: w.clock, License: w.lic,
		Registry: w.reg, Jobs: w.jobs, Notifier: notify.AdminNotifier{Clock: w.clock}})
}

// issued defines a DNS-01 certificate and issues it from the fake CA as a person's order would (the job's steps).
func (w *renewWorld) issued(names ...string) inventory.ACMECertificate {
	w.t.Helper()
	c := w.create(w.dnsInput(names...))
	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(w.t, err)
	w.complete(o.ID)
	return w.get(c.ID)
}

// complete runs an order's CA conversation and stores the certificate (what acme.issue does).
func (w *renewWorld) complete(order uuid.UUID) {
	w.t.Helper()
	work, err := w.svc.ACMEOrderWork(w.ctx, order)
	require.NoError(w.t, err)
	client, err := w.svc.ACMEOrderClient(w.ctx, order)
	require.NoError(w.t, err)
	signer, err := w.svc.NewACMEOrderKey(w.ctx, order)
	require.NoError(w.t, err)
	csr, err := keygen.NewCSR(signer, work.Names)
	require.NoError(w.t, err)
	sol := solver.NewMemory(solver.DNS01)
	sol.AfterPresent = func(_ context.Context, ch solver.Challenge) error { w.fake.DNSSet(ch.DNSName, ch.DNSValue); return nil }
	sol.AfterCleanUp = func(_ context.Context, ch solver.Challenge) error {
		w.fake.DNSClear(ch.DNSName, ch.DNSValue)
		return nil
	}
	chain, err := client.Order(w.ctx, work.Names, csr, sol)
	require.NoError(w.t, err)
	_, err = w.svc.FinishACMEOrder(w.ctx, order, chain)
	require.NoError(w.t, err)
}

// setClock and advance move the clock and evaluate the licence again (an evaluation older than its maximum age
// pauses changes).
func (w *renewWorld) setClock(t time.Time) {
	w.t.Helper()
	w.clock.Set(t)
	require.NoError(w.t, w.harness.lic.Tick(w.ctx))
}

func (w *renewWorld) advance(d time.Duration) { w.setClock(w.clock.Now().Add(d)) }

func (w *renewWorld) get(id uuid.UUID) inventory.ACMECertificate {
	w.t.Helper()
	c, err := w.svc.GetACMECertificate(w.ctx, id)
	require.NoError(w.t, err)
	return c
}

func (w *renewWorld) plan() inventory.ACMERenewRun {
	w.t.Helper()
	run, err := w.svc.PlanACMERenewals(w.ctx)
	require.NoError(w.t, err)
	return run
}

// renewals are the running renewal orders of the certificate.
func (w *renewWorld) renewals(id uuid.UUID) int {
	return w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1 AND trigger = 'renewal'", id)
}

// running is the certificate's running order (it must have one).
func (w *renewWorld) running(id uuid.UUID) uuid.UUID {
	w.t.Helper()
	c := w.get(id)
	require.NotNil(w.t, c.RunningOrderID)
	return *c.RunningOrderID
}

// notAfter is the end of the certificate's current certificate.
func (w *renewWorld) notAfter(c inventory.ACMECertificate) time.Time {
	w.t.Helper()
	require.NotNil(w.t, c.CurrentCertificateID)
	var na time.Time
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT not_after FROM certificates WHERE id = $1", *c.CurrentCertificateID).Scan(&na))
	return na.UTC()
}

type outboxMail struct {
	Template, Locale string
	Params           map[string]string
}

func (w *renewWorld) outbox(template string) []outboxMail {
	w.t.Helper()
	rows, err := w.db.Owner.Query(w.ctx, "SELECT template_key, locale, params FROM notifications_outbox WHERE template_key = $1 ORDER BY locale", template)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []outboxMail
	for rows.Next() {
		var m outboxMail
		var raw []byte
		require.NoError(w.t, rows.Scan(&m.Template, &m.Locale, &raw))
		require.NoError(w.t, json.Unmarshal(raw, &m.Params))
		out = append(out, m)
	}
	require.NoError(w.t, rows.Err())
	return out
}

// snapshot is every row the planner could write (ACME tables, audit, outbox, jobs requested).
func (w *renewWorld) snapshot() string {
	w.t.Helper()
	var s string
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, `SELECT concat_ws('|',
    (SELECT string_agg(to_jsonb(c)::text, ',' ORDER BY c.id) FROM acme_certificates c),
    (SELECT string_agg(to_jsonb(o)::text, ',' ORDER BY o.id) FROM acme_orders o),
    (SELECT count(*) FROM audit_log), (SELECT count(*) FROM notifications_outbox))`).Scan(&s))
	return fmt.Sprintf("%s|%d", s, len(w.jobs.requests()))
}

// A certificate nearing its end is renewed by the planner (system actor, trigger renewal, a system job), and only then.
func TestACMEPlannerRenewsADueCertificate(t *testing.T) {
	w := newRenewWorld(t)
	c := w.issued("due.example.test")
	assert.Nil(t, c.NextAttemptAt, "NULL next_attempt_at with a current certificate: the planner computes from not_after")
	na := w.notAfter(c)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off")) // the local rule alone

	assert.Equal(t, inventory.ACMERenewRun{}, w.plan(), "15 minutes after the issuing order nothing is planned")
	w.advance(renew.MinSpacing)
	run := w.plan()
	assert.Equal(t, inventory.ACMERenewRun{ARIChecked: 1}, run, "not due yet: only the renewal information is asked for")
	assert.Zero(t, w.renewals(c.ID))

	w.setClock(na.Add(-30*day - time.Minute))
	assert.Zero(t, w.plan().Started, "a minute before the 30-day window")
	w.setClock(na.Add(-30 * day))
	before := len(w.jobs.requests())
	run = w.plan()
	assert.Equal(t, 1, run.Started)
	require.Equal(t, 1, w.renewals(c.ID))
	reqs := w.jobs.requests()[before:]
	require.Len(t, reqs, 1)
	assert.Equal(t, inventory.JobACMERenew, reqs[0].Type, "the planner's order is continuity work (owner decision 2026-10-20)")
	assert.Equal(t, "system", reqs[0].Kind)
	assert.Equal(t, "acme.issue:"+c.ID.String(), reqs[0].DedupeKey)
	d := w.auditDetails("acme.order.started")
	require.Len(t, d, 2)
	assert.Equal(t, "renewal", d[1]["trigger"])
	var actor string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT actor_name FROM audit_log WHERE action = 'acme.order.started' ORDER BY seq DESC LIMIT 1").
		Scan(&actor))
	assert.Equal(t, "jobs", actor)
	o, err := w.svc.GetACMEOrder(w.ctx, w.running(c.ID))
	require.NoError(t, err)
	assert.Nil(t, o.RequestedBy)
	assert.Equal(t, inventory.ACMETriggerRenewal, o.Trigger)
	assert.Equal(t, inventory.ACMEStateIssuing, w.get(c.ID).State)

	assert.Zero(t, w.plan().Started, "an order runs")
	old := *c.CurrentCertificateID
	w.complete(o.ID)
	r := w.get(c.ID)
	assert.NotEqual(t, old, *r.CurrentCertificateID, "the new certificate is current")
	assert.Equal(t, 1, w.count("SELECT count(*) FROM certificates WHERE id = $1", old), "the old certificate is kept")
	assert.Equal(t, inventory.ACMEStateActive, r.State)
	assert.Zero(t, w.plan().Started, "renewed: not due")
}

// The planner skips what is not its to renew: automatic renewal off (a restored clone too), stopped, deleted, never
// issued, an order running.
func TestACMEPlannerSkips(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	off := w.issued("off.example.test")
	clone := w.issued("clone.example.test")
	stopped := w.issued("stopped.example.test")
	deleted := w.issued("deleted.example.test")
	running := w.issued("running.example.test")
	never := w.create(w.dnsInput("never.example.test"))
	due := w.issued("due.example.test")

	_, err := w.svc.UpdateACMECertificate(w.ctx, w.admin, off.ID, inventory.ACMECertificatePatch{AutoRenew: ptr(false)})
	require.NoError(t, err)
	// A restored clone: the restore switches automatic renewal off (A11, backup.restore).
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET auto_renew = false WHERE id = $1", clone.ID)
	require.NoError(t, err)
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET state = 'stopped', failures = 5 WHERE id = $1", stopped.ID)
	require.NoError(t, err)
	require.NoError(t, w.svc.DeleteACMECertificate(w.ctx, w.admin, deleted.ID))
	_, err = w.svc.RequestOrder(w.ctx, w.operator, running.ID, inventory.ACMEOrderTest)
	require.NoError(t, err)

	w.setClock(w.notAfter(due).Add(-day))
	run := w.plan()
	assert.Equal(t, 1, run.Started)
	assert.Equal(t, 1, w.renewals(due.ID))
	for _, id := range []uuid.UUID{off.ID, clone.ID, stopped.ID, deleted.ID, running.ID, never.ID} {
		assert.Zero(t, w.renewals(id))
	}
	assert.Equal(t, inventory.ACMEStatePending, w.get(never.ID).State, "the first order is a person's")
}

// In lock the planner contacts no CA and writes nothing; the order a due certificate needs starts once the licence
// allows changes again, with no failure counted.
func TestACMEPlannerInLockDoesNothing(t *testing.T) {
	w := newRenewWorld(t)
	c := w.issued("lock.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	w.lic.locked.Store(true)
	before, requests := w.snapshot(), w.requests()
	for range 3 {
		assert.Equal(t, inventory.ACMERenewRun{}, w.plan())
	}
	assert.Equal(t, requests, w.requests(), "no CA contact, no renewal information")
	assert.Equal(t, before, w.snapshot(), "no row written")
	w.lic.locked.Store(false)
	assert.Equal(t, 1, w.plan().Started)
	assert.Zero(t, w.get(c.ID).Failures)
}

// In the continuity window of a lock (owner decision 2026-10-20) the planner still renews an issued certificate: the
// order is an acme.renew job (ClassContinuity) holding the acme.issue dedupe key, while a person's order is refused.
// Once the window has ended the planner does nothing, as in lock before.
func TestACMEPlannerRenewsInTheContinuityWindow(t *testing.T) {
	w := newRenewWorld(t)
	c := w.issued("window.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	w.lic.locked.Store(true)
	w.lic.window.Store(true)
	_, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.ErrorIs(t, err, license.ErrLocked, "Renew now is a person's change")
	before := len(w.jobs.requests())
	assert.Equal(t, 1, w.plan().Started)
	reqs := w.jobs.requests()[before:]
	require.Len(t, reqs, 1)
	assert.Equal(t, inventory.JobACMERenew, reqs[0].Type)
	assert.Equal(t, w.running(c.ID).String(), reqs[0].Payload["order_id"])
	assert.Equal(t, "acme.issue:"+c.ID.String(), reqs[0].DedupeKey, "one order per certificate across both job types")

	w.complete(w.running(c.ID)) // the renewed certificate is due again later
	w.setClock(w.notAfter(w.get(c.ID)).Add(-day))
	w.lic.window.Store(false)
	snap := w.snapshot()
	assert.Equal(t, inventory.ACMERenewRun{}, w.plan(), "after the window the planner does nothing")
	assert.Equal(t, snap, w.snapshot())
}

// A lock that ends an order (license.locked) is neutral: no failure, no backoff; the planner orders again after the
// spacing.
func TestACMELockedOrderIsNeutral(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("neutral.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	require.Equal(t, 1, w.plan().Started)
	require.NoError(t, w.svc.FailACMEOrder(w.ctx, w.running(c.ID), inventory.ACMELicenseLocked, time.Hour))
	r := w.get(c.ID)
	assert.Zero(t, r.Failures)
	assert.Nil(t, r.NextAttemptAt)
	assert.Equal(t, inventory.ACMEStateActive, r.State)
	assert.Equal(t, "", r.LastErrorCode)
	assert.Zero(t, w.plan().Started, "15 minutes between two orders")
	w.advance(renew.MinSpacing)
	assert.Equal(t, 1, w.plan().Started)
}

// Five failures in a row: the backoff 1 h, 2 h, 4 h, 8 h; one e-mail at the third (both languages), the stop at the
// fifth (state stopped, audit, one e-mail); stopped certificates are skipped; a person's successful order resets it all.
func TestACMEFailureSequence(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("fail.example.test", "www.fail.example.test")
	na := w.notAfter(c)
	w.setClock(na.Add(-20 * day))
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	sender := &notify.Sender{Catalog: cat}
	for n := 1; n <= 5; n++ {
		require.Equal(t, 1, w.plan().Started, "failure %d: due again", n)
		now := w.clock.Now().UTC()
		require.NoError(t, w.svc.FailACMEOrder(w.ctx, w.running(c.ID), acme.ReasonValidationFailedDNS, 0))
		r := w.get(c.ID)
		assert.Equal(t, n, r.Failures)
		assert.Equal(t, n, r.PermanentFailures, "a failed validation known only by its code needs a person")
		assert.Equal(t, renew.ClassPermanent, r.LastFailureClass)
		assert.Equal(t, acme.ReasonValidationFailedDNS, r.LastErrorCode)
		if n < 5 {
			assert.Equal(t, inventory.ACMEStateFailing, r.State)
			require.NotNil(t, r.NextAttemptAt)
			assert.Equal(t, now.Add(renew.Backoff(n)), *r.NextAttemptAt, "failure %d", n)
			w.setClock(r.NextAttemptAt.Add(-time.Second))
			assert.Zero(t, w.plan().Started, "failure %d: waits its backoff", n)
			w.setClock(*r.NextAttemptAt)
		}
		mails := w.outbox(inventory.TemplateACMERenewalFailed)
		if n < 3 {
			assert.Empty(t, mails, "failure %d", n)
			continue
		}
		require.Len(t, mails, 2, "failure %d: one e-mail per Administrator, once", n)
		assert.Equal(t, []string{"en", "tr"}, []string{mails[0].Locale, mails[1].Locale})
		assert.Equal(t, map[string]string{"name": "fail.example.test", "names": "fail.example.test, www.fail.example.test", "count": "3",
			"error_reason": acme.ReasonValidationFailedDNS, "expires_at": na.Format("2006-01-02 15:04 UTC"), "acme_certificate_id": c.ID.String()},
			mails[0].Params)
		for _, m := range mails {
			msg := sender.Render("x@example.test", m.Template, m.Locale, m.Params)
			assert.Contains(t, msg.Subject, "fail.example.test")
			assert.Contains(t, msg.Body, cat.T(m.Locale, "errors.acme.validation_failed_dns.title", nil))
			assert.Contains(t, msg.Body, na.Format("2006-01-02 15:04 UTC"))
			assert.NotContains(t, msg.Body, acme.ReasonValidationFailedDNS)
		}
	}
	r := w.get(c.ID)
	assert.Equal(t, inventory.ACMEStateStopped, r.State)
	d := w.auditDetails("acme.auto_renew.stopped")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"acme_certificate_id": c.ID.String(), "names": "fail.example.test,www.fail.example.test",
		"failed_count": "5", "error_code": acme.ReasonValidationFailedDNS}, d[0])
	stops := w.outbox(inventory.TemplateACMEAutoRenewStopped)
	require.Len(t, stops, 2)
	assert.Equal(t, "5", stops[1].Params["count"])
	w.advance(2 * day)
	assert.Equal(t, inventory.ACMERenewRun{}, w.plan(), "stopped: skipped")

	// A person's order that fails again keeps it stopped and sends nothing more.
	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, acme.ReasonHookRefused, 0))
	assert.Equal(t, inventory.ACMEStateStopped, w.get(c.ID).State)
	assert.Len(t, w.outbox(inventory.TemplateACMEAutoRenewStopped), 2)
	assert.Len(t, w.outbox(inventory.TemplateACMERenewalFailed), 2)
	assert.Equal(t, 1, w.audits("acme.auto_renew.stopped"))

	// Recovery: a successful order resets the failures, the state and the notice mark.
	o, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	w.complete(o.ID)
	r = w.get(c.ID)
	assert.Equal(t, inventory.ACMEStateActive, r.State)
	assert.Zero(t, r.Failures)
	assert.Zero(t, r.PermanentFailures)
	assert.Empty(t, r.LastFailureClass)
	assert.Nil(t, r.NextAttemptAt)
	assert.Zero(t, w.count("SELECT count(*) FROM acme_certificates WHERE id = $1 AND failure_notified_at IS NOT NULL", c.ID))
}

// A certificate that never stopped but reached five permanent failures with renewal switched off is stopped by the
// planner when renewal is switched on again (the backstop of the stop rule), once.
func TestACMEPlannerStopsAtFiveFailures(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("backstop.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	_, err := w.db.Owner.Exec(w.ctx, `UPDATE acme_certificates SET failures = 6, permanent_failures = 5, last_failure_class = 'permanent',
    state = 'failing', last_error_code = 'acme.hook_refused' WHERE id = $1`, c.ID)
	require.NoError(t, err)
	run := w.plan()
	assert.Equal(t, inventory.ACMERenewRun{Stopped: 1, Warned: 1}, run, "a day left: the expiry reminder goes too")
	assert.Equal(t, inventory.ACMEStateStopped, w.get(c.ID).State)
	assert.Equal(t, "acme.hook_refused", w.auditDetails("acme.auto_renew.stopped")[0]["error_code"])
	assert.Len(t, w.outbox(inventory.TemplateACMEAutoRenewStopped), 2)
	assert.Equal(t, inventory.ACMERenewRun{}, w.plan())
	assert.Equal(t, 1, w.audits("acme.auto_renew.stopped"))
}

// The CA's rate limit: ca_not_before is its Retry-After (longer than the backoff), and no other certificate of that
// provider is ordered while it lasts; the wave bounds every run to five orders.
func TestACMERateLimitAndWave(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	certs := make([]inventory.ACMECertificate, 8)
	for i := range certs {
		certs[i] = w.issued(fmt.Sprintf("c%d.example.test", i))
	}
	w.setClock(w.notAfter(certs[0]).Add(-29 * day)) // due, before the middle of the window (the hold applies)

	run := w.plan()
	assert.Equal(t, inventory.ACMERenewWave, run.Started, "five orders per run")
	started := 0
	for _, c := range certs {
		started += w.renewals(c.ID)
	}
	assert.Equal(t, 5, started)

	// One order fails with the CA's rate limit (Retry-After 3 h); the other four end without counting.
	var limited inventory.ACMECertificate
	n := 0
	for _, c := range certs {
		cur := w.get(c.ID)
		if cur.RunningOrderID == nil {
			continue
		}
		if n == 0 {
			limited = cur
			require.NoError(t, w.svc.FailACMEOrder(w.ctx, *cur.RunningOrderID, acme.ReasonCARateLimited, 3*time.Hour))
		} else {
			require.NoError(t, w.svc.AbandonACMEOrder(w.ctx, *cur.RunningOrderID, "job.lease_expired"))
		}
		n++
	}
	r := w.get(limited.ID)
	assert.Equal(t, w.clock.Now().UTC().Add(time.Hour), *r.NextAttemptAt, "Alice's own backoff")
	assert.Equal(t, w.clock.Now().UTC().Add(3*time.Hour), *r.CANotBefore, "the CA's wait, kept apart (R47)")
	w.advance(time.Hour)
	assert.Equal(t, inventory.ACMERenewRun{}, w.plan(), "the provider is rate limited: no storm")
	w.advance(2 * time.Hour)
	run = w.plan()
	assert.Equal(t, 5, run.Started, "after the wait, five again")
}

// ARI: a window earlier than the local rule pulls the renewal forward; a later one is ignored; the answer is cached
// (Retry-After 6 h) and cleared by the next issuance.
func TestACMEARIPullsARenewalEarlier(t *testing.T) {
	w := newRenewWorld(t)
	c := w.issued("ari.example.test")
	na := w.notAfter(c)
	w.setClock(na.Add(-60 * day)) // 30 days before the local rule
	// A window already open and over by now: the random time in it (R50) is in the past, so the renewal starts at once.
	require.NoError(t, w.fake.SetARIWindow(na.Add(-62*day), na.Add(-61*day)))
	aris := w.fake.Counters()["ari"]
	run := w.plan()
	assert.Equal(t, inventory.ACMERenewRun{Started: 1, ARIChecked: 1}, run, "the CA asks for an early renewal")
	assert.Equal(t, aris+1, w.fake.Counters()["ari"])
	var start, end, checked, next time.Time
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, `SELECT ari_window_start, ari_window_end, ari_checked_at, ari_next_check_at FROM acme_certificates
WHERE id = $1`, c.ID).Scan(&start, &end, &checked, &next))
	assert.Equal(t, na.Add(-62*day), start.UTC())
	assert.Equal(t, na.Add(-61*day), end.UTC())
	assert.Equal(t, w.clock.Now().UTC(), checked.UTC())
	assert.Equal(t, w.clock.Now().UTC().Add(6*time.Hour), next.UTC(), "the CA's Retry-After")
	view, err := w.svc.GetACMECertificate(w.ctx, c.ID)
	require.NoError(t, err)
	require.NotNil(t, view.ARIWindowStart)
	require.NotNil(t, view.ARIWindowEnd)
	assert.Equal(t, start.UTC(), *view.ARIWindowStart, "the view shows the cached window")
	assert.Equal(t, end.UTC(), *view.ARIWindowEnd)

	w.complete(w.running(c.ID))
	assert.Zero(t, w.count("SELECT count(*) FROM acme_certificates WHERE id = $1 AND ari_checked_at IS NOT NULL", c.ID), "cleared on issuance")

}

// A window later than the local rule never holds back a certificate that is due by the rule.
func TestACMEARILaterWindowIsIgnored(t *testing.T) {
	w := newRenewWorld(t)
	late := w.issued("late.example.test")
	na := w.notAfter(late)
	require.NoError(t, w.fake.SetARIWindow(na.Add(-day), na))
	w.setClock(na.Add(-60 * day))
	run := w.plan()
	assert.Equal(t, inventory.ACMERenewRun{ARIChecked: 1}, run, "not due by the rule, and the window is later")
	w.setClock(na.Add(-30 * day))
	aris := w.fake.Counters()["ari"]
	assert.Equal(t, 1, w.plan().Started, "due by the local rule although the window is later")
	assert.Equal(t, aris, w.fake.Counters()["ari"], "a due certificate needs no window")
}

// ARI failing (an error, a garbled answer, a CA without renewal information) is never a failure and never blocks the
// renewal: the local rule decides; the lookup waits its recheck time.
func TestACMEARIFailureFallsBackToTheLocalRule(t *testing.T) {
	w := newRenewWorld(t)
	c := w.issued("arifail.example.test")
	na := w.notAfter(c)
	w.setClock(na.Add(-45 * day))
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "ari", Kind: fakeacme.FaultServerInternal}))
	run := w.plan()
	assert.Equal(t, inventory.ACMERenewRun{ARIChecked: 1}, run)
	r := w.get(c.ID)
	assert.Zero(t, r.Failures)
	assert.Nil(t, r.NextAttemptAt)
	assert.Equal(t, "", r.LastErrorCode)
	assert.Equal(t, inventory.ACMERenewRun{}, w.plan(), "the lookup waits its recheck time")
	assert.Contains(t, w.logs.String(), "the local rule decides")

	w.fake.ClearFaults()
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "ari", Kind: fakeacme.FaultGiant}))
	w.advance(6 * time.Hour)
	assert.Equal(t, inventory.ACMERenewRun{ARIChecked: 1}, w.plan(), "a garbled answer: the same")
	w.fake.ClearFaults()
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	w.advance(6 * time.Hour)
	assert.Equal(t, inventory.ACMERenewRun{ARIChecked: 1}, w.plan(), "no renewal information at all")
	assert.Zero(t, w.count("SELECT count(*) FROM acme_certificates WHERE id = $1 AND ari_window_start IS NOT NULL", c.ID))

	w.setClock(na.Add(-30 * day))
	assert.Equal(t, 1, w.plan().Started, "the local rule renews it")
	assert.Zero(t, w.get(c.ID).Failures)
}

// Two planners at once (two processes): one order per certificate (row lock with SKIP LOCKED, the unique index).
func TestACMETwoPlannersOneOrderPerCertificate(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	var certs []inventory.ACMECertificate
	for i := range 4 {
		certs = append(certs, w.issued(fmt.Sprintf("r%d.example.test", i)))
	}
	w.setClock(w.notAfter(certs[0]).Add(-day))
	planners := []*inventory.Service{w.svc, w.otherProcess(), w.otherProcess(), w.otherProcess()}
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for _, p := range planners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3 {
				run, err := p.PlanACMERenewals(w.ctx)
				assert.NoError(t, err)
				mu.Lock()
				total += run.Started
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 4, total)
	for _, c := range certs {
		assert.Equal(t, 1, w.renewals(c.ID), c.Names[0])
	}
}

// A provider without an active account: the renewal cannot start; that counts as a failure (backoff, e-mails), never
// as a silent skip every minute.
func TestACMEPlannerCountsAMissingAccount(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("noaccount.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	_, err := w.db.Owner.Exec(w.ctx, "UPDATE acme_accounts SET state = 'deactivated' WHERE provider_id = $1", w.provider.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMERenewRun{Failed: 1}, w.plan())
	r := w.get(c.ID)
	assert.Equal(t, 1, r.Failures)
	assert.Equal(t, "acme.account_state", r.LastErrorCode)
	assert.Equal(t, w.clock.Now().UTC().Add(time.Hour), *r.NextAttemptAt)
	assert.Zero(t, w.renewals(c.ID))
	assert.Equal(t, inventory.ACMERenewRun{Warned: 1}, w.plan(), "the backoff paces it (a day left: the expiry reminder goes)")
}

// A next_attempt_at beyond the 24-hour cap (the clock moved back) is repaired instead of waited for.
func TestACMEPlannerRepairsASkewedNextAttempt(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("skew.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	far := w.clock.Now().Add(400 * day)
	_, err := w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET failures = 1, state = 'failing', next_attempt_at = $2 WHERE id = $1", c.ID, far)
	require.NoError(t, err)
	assert.Zero(t, w.plan().Started)
	assert.Equal(t, w.clock.Now().UTC().Add(renew.MaxBackoff), *w.get(c.ID).NextAttemptAt)
	w.advance(renew.MaxBackoff)
	assert.Equal(t, 1, w.plan().Started)
}

// A certificate another transaction holds is skipped until the next run (SKIP LOCKED), not waited for.
func TestACMEPlannerSkipsALockedCertificate(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("held.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	tx, err := w.db.App.Begin(w.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(w.ctx) }() // a planner that waits is released when the test fails
	_, err = tx.Exec(w.ctx, "SELECT 1 FROM acme_certificates WHERE id = $1 FOR UPDATE", c.ID)
	require.NoError(t, err)
	done := make(chan inventory.ACMERenewRun, 1)
	go func() {
		run, _ := w.svc.PlanACMERenewals(w.ctx)
		done <- run
	}()
	select {
	case run := <-done:
		assert.Zero(t, run.Started)
	case <-time.After(10 * time.Second):
		t.Fatal("the planner waited for the row")
	}
	require.NoError(t, tx.Rollback(w.ctx))
	assert.Equal(t, 1, w.plan().Started)
}

// The candidates come most urgent first.
func TestACMEPlannerOrdersByUrgency(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	var ids []uuid.UUID
	for i := range 7 {
		c := w.issued(fmt.Sprintf("u%d.example.test", i))
		ids = append(ids, c.ID)
		w.advance(time.Hour)
	}
	w.advance(80 * day)
	require.Equal(t, 5, w.plan().Started)
	var got []string
	for i, id := range ids {
		if w.renewals(id) == 1 {
			got = append(got, fmt.Sprint(i))
		}
	}
	sort.Strings(got)
	assert.Equal(t, []string{"0", "1", "2", "3", "4"}, got, "the five that end first")
}

// The world changes between the candidates' read and a certificate's transaction: a deleted certificate, a person's
// order, or a licence that locked is planned for nothing (no error, no order, no CA contact).
func TestACMEPlannerRereadsUnderTheLock(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	gone := w.issued("gone.example.test")
	busy := w.issued("busy.example.test")
	locked := w.issued("locked.example.test")
	w.setClock(w.notAfter(gone).Add(-day))
	t.Cleanup(func() { inventory.SetACMERenewHook(nil) })
	inventory.SetACMERenewHook(func(id uuid.UUID) {
		switch id {
		case gone.ID:
			require.NoError(t, w.svc.DeleteACMECertificate(w.ctx, w.admin, id))
		case busy.ID:
			_, err := w.svc.RequestOrder(w.ctx, w.operator, id, inventory.ACMEOrderIssue)
			require.NoError(t, err)
		case locked.ID:
			w.lic.locked.Store(true)
		}
	})
	requests := w.requests()
	run := w.plan()
	assert.Zero(t, run.Started)
	assert.Zero(t, w.renewals(gone.ID)+w.renewals(busy.ID)+w.renewals(locked.ID))
	assert.Equal(t, requests, w.requests())
	inventory.SetACMERenewHook(nil)
	w.lic.locked.Store(false)
	assert.Equal(t, 1, w.plan().Started, "the locked one, once the licence allows changes")
}

// A cancelled run stops between certificates and says so.
func TestACMEPlannerStopsOnACancelledContext(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("cancel.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	ctx, cancel := context.WithCancel(w.ctx)
	t.Cleanup(func() { inventory.SetACMERenewHook(nil) })
	inventory.SetACMERenewHook(func(uuid.UUID) { cancel() })
	_, err := w.svc.PlanACMERenewals(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, w.renewals(c.ID))
}

// Fix round 1, I1: one certificate the CA limits for days (its own names: Retry-After a day, again and again) holds the
// provider's other certificates for at most 24 hours of its series; a 6-day certificate of the same provider is
// renewed in time.
func TestACMERateLimitedNeighbourDoesNotStarveAShortCertificate(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	limited := w.issued("limited.example.test")
	w.advance(85 * day) // limited is due (60 days) and keeps being limited by the CA
	require.NoError(t, w.fake.SetLeafLifetime(6*day))
	short := w.issued("short.example.test")
	shortDue, shortEnd := w.shortWindow(short)
	w.advance(12 * time.Hour) // the neighbour's daily retries do not line up with the short certificate's renewal time
	renewedAt := time.Time{}
	limits := 0
	for range 5 * 24 {
		w.advance(time.Hour)
		w.plan()
		if l := w.get(limited.ID); l.RunningOrderID != nil {
			require.NoError(t, w.svc.FailACMEOrder(w.ctx, *l.RunningOrderID, acme.ReasonCARateLimited, 24*time.Hour))
			limits++
		}
		if s := w.get(short.ID); s.RunningOrderID != nil && renewedAt.IsZero() {
			w.complete(*s.RunningOrderID)
			renewedAt = w.clock.Now()
		}
	}
	assert.GreaterOrEqual(t, limits, 4, "the CA limited the neighbour again and again")
	require.False(t, renewedAt.IsZero(), "the 6-day certificate was renewed")
	assert.True(t, renewedAt.Before(shortEnd), "before it expired")
	assert.LessOrEqual(t, renewedAt.Sub(shortDue), time.Hour, "at its renewal time, not at the neighbour's next retry")
	var since time.Time
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT rate_limited_since FROM acme_certificates WHERE id = $1", limited.ID).Scan(&since))
	assert.True(t, since.Before(w.clock.Now().Add(-4*day)), "the series began at the first limit and is kept")
}

// shortWindow is the renewal time and the end of the certificate's current certificate.
func (w *renewWorld) shortWindow(c inventory.ACMECertificate) (time.Time, time.Time) {
	w.t.Helper()
	na := w.notAfter(c)
	var nb time.Time
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT not_before FROM certificates WHERE id = $1", *c.CurrentCertificateID).Scan(&nb))
	return renew.RenewAt(nb, na, c.RenewBeforeDays), na
}

// The hold lasts at most 24 hours of a series, and never holds a certificate past the middle of its renewal window.
func TestACMERateLimitHoldBounds(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	limited := w.issued("limited.example.test")
	other := w.issued("other.example.test")
	due, end := w.shortWindow(other)
	w.setClock(due)
	// The CA limits the neighbour again now (Retry-After 24 h, the cap); its series began 23 hours ago.
	limit := func(since time.Time) {
		t.Helper()
		_, err := w.db.Owner.Exec(w.ctx, `UPDATE acme_certificates SET failures = 2, state = 'failing', last_error_code = 'acme.ca_rate_limited',
    last_attempt_at = $3, next_attempt_at = $4, rate_limited_since = $2 WHERE id = $1`, limited.ID, since, w.clock.Now(), w.clock.Now().Add(24*time.Hour))
		require.NoError(t, err)
	}
	limit(w.clock.Now().Add(-23 * time.Hour))
	assert.Equal(t, inventory.ACMERenewRun{}, w.plan(), "held: the series began 23 hours ago")
	w.advance(59 * time.Minute)
	assert.Equal(t, inventory.ACMERenewRun{}, w.plan(), "still held")
	w.advance(time.Minute)
	assert.Equal(t, 1, w.plan().Started, "24 hours after the series began the hold ends, though the CA's wait does not")
	require.NoError(t, w.svc.AbandonACMEOrder(w.ctx, w.running(other.ID), "job.lease_expired"))

	// A fresh series again: a certificate past the middle of its window is renewed regardless.
	w.setClock(due.Add(end.Sub(due) / 2))
	limit(w.clock.Now())
	assert.Equal(t, 1, w.plan().Started, "past the middle of its window: never held")
}

// Fix round 1, I2: a CA that answers with a window before the current certificate began (here 2001) causes no renewal
// loop: only the local rule applies; a window of year 1 is refused as garbled (no failure either).
func TestACMEARIWindowInThePastIsIgnored(t *testing.T) {
	w := newRenewWorld(t)
	c := w.issued("past.example.test")
	require.NoError(t, w.fake.SetARIWindow(time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2001, 1, 2, 0, 0, 0, 0, time.UTC)))
	for range 4 * 8 { // four days in 3-hour steps
		w.advance(3 * time.Hour)
		w.plan()
	}
	assert.Zero(t, w.renewals(c.ID), "no renewal loop")
	var start time.Time
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT ari_window_start FROM acme_certificates WHERE id = $1", c.ID).Scan(&start))
	assert.Equal(t, 2001, start.Year(), "the answer was stored, and ignored")

	require.NoError(t, w.fake.SetARIWindow(time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1, 1, 2, 0, 0, 0, 0, time.UTC)))
	w.advance(7 * time.Hour)
	run := w.plan()
	assert.Equal(t, inventory.ACMERenewRun{ARIChecked: 1}, run, "year 1 is refused: no order")
	assert.Zero(t, w.get(c.ID).Failures)

	w.setClock(w.notAfter(c).Add(-30 * day))
	assert.Equal(t, 1, w.plan().Started, "the local rule")
}

// Minor 1: many certificates fell due during a lock; the first run after the lock starts exactly five orders.
func TestACMEReopenedLicenceStartsOneWave(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	var certs []inventory.ACMECertificate
	for i := range 9 {
		certs = append(certs, w.issued(fmt.Sprintf("herd%d.example.test", i)))
	}
	w.lic.locked.Store(true)
	w.setClock(w.notAfter(certs[0]).Add(-day))
	assert.Equal(t, inventory.ACMERenewRun{}, w.plan())
	w.lic.locked.Store(false)
	assert.Equal(t, inventory.ACMERenewRun{Started: 5}, w.plan(), "exactly one wave")
	n := 0
	for _, c := range certs {
		n += w.renewals(c.ID)
	}
	assert.Equal(t, 5, n)
}

// Minor 2: an Administrator re-arms a stopped certificate; switching automatic renewal on after failures made while it
// was off starts afresh (no immediate stop).
func TestACMEReArm(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("rearm.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	_, err := w.db.Owner.Exec(w.ctx, `UPDATE acme_certificates SET state = 'stopped', failures = 5, failure_notified_at = now(),
    next_attempt_at = $2, rate_limited_since = now(), last_error_code = 'acme.hook_refused' WHERE id = $1`, c.ID, w.clock.Now().Add(5*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMERenewRun{Warned: 1}, w.plan(), "stopped (a day left: the expiry reminder goes)")
	orders := w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1", c.ID)
	r, err := w.svc.ReArmACMEAutoRenew(w.ctx, w.admin, c.ID)
	require.NoError(t, err)
	// Check again and resume (owner decision 2026-10-20): re-armed, and an order of the person started at once.
	assert.Equal(t, inventory.ACMEStateIssuing, r.State, "an order runs")
	require.NotNil(t, r.RunningOrderID)
	o, err := w.svc.GetACMEOrder(w.ctx, *r.RunningOrderID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMETriggerManual, o.Trigger)
	assert.Equal(t, inventory.ACMEOrderIssue, o.Kind)
	assert.Equal(t, orders+1, w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1", c.ID))
	assert.Equal(t, inventory.JobACMEIssue, w.jobs.requests()[len(w.jobs.requests())-1].Type, "a person's order is a change, not continuity work")
	assert.Zero(t, r.Failures)
	assert.Zero(t, r.PermanentFailures)
	assert.Empty(t, r.LastFailureClass)
	assert.Nil(t, r.NextAttemptAt)
	assert.True(t, r.AutoRenew)
	assert.Equal(t, "acme.hook_refused", r.LastErrorCode, "the last reason stays for the record")
	assert.Zero(t, w.count(`SELECT count(*) FROM acme_certificates WHERE id = $1 AND (failure_notified_at IS NOT NULL OR rate_limited_since IS NOT NULL)`, c.ID))
	d := w.auditDetails("acme.auto_renew.rearmed")
	require.Len(t, d, 1)
	assert.Equal(t, map[string]string{"acme_certificate_id": c.ID.String(), "names": "rearm.example.test", "previous_state": "stopped",
		"previous_failures": "5"}, d[0])
	started := w.auditDetails("acme.order.started")
	assert.Equal(t, "manual", started[len(started)-1]["trigger"])
	assert.Zero(t, w.plan().Started, "the order of the person runs")
	_, err = w.svc.ReArmACMEAutoRenew(w.ctx, w.admin, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	r, err = w.svc.ReArmACMEAutoRenew(w.ctx, w.admin, c.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEStateIssuing, r.State, "an order runs")
	assert.Equal(t, orders+1, w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1", c.ID), "no second order")
	w.complete(*r.RunningOrderID)
	assert.Equal(t, inventory.ACMEStateActive, w.get(c.ID).State)

	// Automatic renewal off, five failed orders of a person, then switched on: no stop, it is renewed.
	off := w.issued("off.example.test")
	_, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, off.ID, inventory.ACMECertificatePatch{AutoRenew: ptr(false)})
	require.NoError(t, err)
	for range 5 {
		o, err := w.svc.RequestOrder(w.ctx, w.operator, off.ID, inventory.ACMEOrderIssue)
		require.NoError(t, err)
		require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, acme.ReasonHookRefused, 0))
	}
	got := w.get(off.ID)
	assert.Equal(t, 5, got.Failures)
	assert.Equal(t, inventory.ACMEStateFailing, got.State, "off: never stopped")
	assert.Empty(t, w.outbox(inventory.TemplateACMEAutoRenewStopped))
	got, err = w.svc.UpdateACMECertificate(w.ctx, w.admin, off.ID, inventory.ACMECertificatePatch{AutoRenew: ptr(true)})
	require.NoError(t, err)
	assert.Zero(t, got.Failures)
	assert.Equal(t, inventory.ACMEStateActive, got.State)
	assert.Equal(t, 3, w.audits("acme.auto_renew.rearmed"), "switching on wrote a re-arm row too")
	w.setClock(w.notAfter(off).Add(-day))
	run := w.plan()
	assert.Equal(t, 1, w.renewals(off.ID), "renewed, not stopped")
	assert.Zero(t, run.Stopped)
}

// Minor 4: certificates skipped run after run (a key change that does not settle) do not hide a renewable one behind
// them: the run reads further pages.
func TestACMESkippedCandidatesDoNotStarveOthers(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	p2 := w.registryWorld.provider("Second CA", false)
	w.register(p2)
	hook := w.hook.ID
	stuck, err := w.svc.CreateACMECertificate(w.ctx, w.admin, inventory.ACMECertificateInput{ProviderID: p2.ID, Names: []string{"stuck.example.test"},
		Challenge: inventory.ACMEChallengeDNS01, HookID: &hook})
	require.NoError(t, err)
	o, err := w.svc.RequestOrder(w.ctx, w.operator, stuck.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	w.complete(o.ID)
	stuck = w.get(stuck.ID)
	// 59 more definitions of the second provider holding the same certificate: 60 candidates, all more urgent.
	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, state,
    current_certificate_id, created_at, updated_at)
SELECT gen_random_uuid(), provider_id, account_id, names, key_type, challenge, hook_id, 'active', current_certificate_id, created_at, updated_at
FROM acme_certificates, generate_series(1, 59) WHERE id = $1`, stuck.ID)
	require.NoError(t, err)
	w.advance(time.Hour)
	fine := w.issued("fine.example.test")
	// The second provider's key change never settles: every one of its certificates is skipped.
	_, err = w.db.Owner.Exec(w.ctx, `INSERT INTO acme_accounts (id, provider_id, key_ct, key_nonce, key_wrapped_dek, key_version, state,
    pending_since, created_at, updated_at) VALUES (gen_random_uuid(), $1, '\x01', decode(repeat('00', 12), 'hex'), '\x01', 1, 'pending_rollover',
    now(), now(), now())`, p2.ID)
	require.NoError(t, err)
	w.setClock(w.notAfter(fine).Add(-day))
	run := w.plan()
	assert.Equal(t, 1, run.Started)
	assert.Equal(t, 1, w.renewals(fine.ID), "found behind 60 skipped candidates")
	assert.Zero(t, w.count("SELECT count(*) FROM acme_orders WHERE trigger = 'renewal' AND acme_certificate_id <> $1", fine.ID))
}

// Minor 3: the spacing reads the newest order that is not in the future (a clock that moved back), as the candidates do.
func TestACMESpacingIgnoresAFutureOrder(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("future.example.test")
	w.setClock(w.notAfter(c).Add(-day))
	t.Cleanup(func() { inventory.SetACMERenewHook(nil) })
	inventory.SetACMERenewHook(func(id uuid.UUID) {
		// After the candidates were read: an order of ten minutes ago, and one "in two days" from before a clock change.
		for _, at := range []time.Time{w.clock.Now().Add(-10 * time.Minute), w.clock.Now().Add(2 * day)} {
			_, err := w.db.Owner.Exec(w.ctx, `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, finished_at, error_code)
VALUES (gen_random_uuid(), $1, 'issue', 'failed', $2, $2, 'job.lease_expired')`, id, at)
			require.NoError(t, err)
		}
	})
	assert.Zero(t, w.plan().Started, "the order of ten minutes ago spaces it")
	inventory.SetACMERenewHook(nil)
}
