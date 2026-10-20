//go:build integration

package acmejobs

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/renew"
	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license/licensetest"
	"alice/internal/testutil/fakeacme"
)

const day = 24 * time.Hour

// renewing is a world with a ten-year licence (the tests move the clock months ahead) and the acme.schedule task.
func renewing(t *testing.T) (*world, jobs.Task) {
	t.Helper()
	w := newWorld(t)
	p := licensetest.Payload(w.lic.Snapshot().InstallationID, w.clock.Now(), w.clock.Now().Add(3650*day), 5)
	p.LicenseID = "LIC-ACME-RENEW"
	_, err := w.lic.Install(w.ctx, licensetest.Sign(p), audit.SystemActor("test"), uuid.Nil)
	require.NoError(t, err)
	return w, ScheduleTask(w.inv, time.Minute, nil)
}

// setClock moves the clock (and the fake CA's, which shares it) and evaluates the licence again.
func (w *world) setClock(at time.Time) {
	w.t.Helper()
	w.clock.Set(at)
	require.NoError(w.t, w.lic.Tick(w.ctx))
}

// notAfter is the end of the ACME certificate's current certificate.
func (w *world) notAfter(id uuid.UUID) (uuid.UUID, time.Time) {
	w.t.Helper()
	c := w.getCert(id)
	require.NotNil(w.t, c.CurrentCertificateID)
	var na time.Time
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT not_after FROM certificates WHERE id = $1", *c.CurrentCertificateID).Scan(&na))
	return *c.CurrentCertificateID, na.UTC()
}

// A short-lived (6-day) certificate is renewed by the planner and the issue job two days before its end: a new
// certificate row, the definition switched to it, the old one kept; the order is the planner's (trigger renewal, system
// actor jobs).
func TestRenewalOfAShortLivedCertificate(t *testing.T) {
	w, task := renewing(t)
	require.NoError(t, w.fake.SetLeafLifetime(6*day))
	c := w.dnsCert("short.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	old, na := w.notAfter(c.ID)
	assert.Equal(t, 6*day, na.Sub(w.clock.Now().UTC()).Round(time.Hour))

	w.setClock(na.Add(-2*day - time.Minute))
	require.NoError(t, task.Run(w.ctx))
	assert.Equal(t, 1, w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1", c.ID), "not due a minute early")

	w.setClock(na.Add(-2 * day))
	require.NoError(t, task.Run(w.ctx))
	w.drain()
	cur, newNA := w.notAfter(c.ID)
	assert.NotEqual(t, old, cur, "the definition points at the new certificate")
	assert.True(t, newNA.After(na))
	assert.Equal(t, 1, w.count("SELECT count(*) FROM certificates WHERE id = $1", old), "the old certificate is kept")
	assert.Equal(t, 2, w.count("SELECT count(*) FROM certificates WHERE source = 'acme'"))
	var trigger string
	var by *uuid.UUID
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, `SELECT trigger, requested_by FROM acme_orders WHERE acme_certificate_id = $1 AND state = 'succeeded'
ORDER BY started_at DESC LIMIT 1`, c.ID).Scan(&trigger, &by))
	assert.Equal(t, inventory.ACMETriggerRenewal, trigger)
	assert.Nil(t, by)
	got := w.getCert(c.ID)
	assert.Equal(t, inventory.ACMEStateActive, got.State)
	assert.Zero(t, got.Failures)
	assert.Zero(t, w.dnsLeft())
	require.NoError(t, task.Run(w.ctx))
	assert.Equal(t, 2, w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1", c.ID), "renewed: nothing more")
	w.noSecrets()
}

// The CA's renewal information pulls a renewal forward (a revocation at the CA): a window already in the past makes the
// certificate due now (R50: the time chosen in it is in the past), long before the local rule.
func TestRenewalPulledForwardByARI(t *testing.T) {
	w, task := renewing(t)
	c := w.dnsCert("ari.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	old, na := w.notAfter(c.ID)
	w.setClock(na.Add(-80 * day)) // 50 days before the local rule
	require.NoError(t, w.fake.SetARIWindow(w.clock.Now().Add(-2*time.Hour), w.clock.Now().Add(-time.Hour)))
	aris := w.fake.Counters()["ari"]
	require.NoError(t, task.Run(w.ctx))
	w.drain()
	assert.Equal(t, aris+1, w.fake.Counters()["ari"])
	cur, _ := w.notAfter(c.ID)
	assert.NotEqual(t, old, cur, "renewed on the CA's word")
}

// In lock the planner never contacts the CA and writes nothing, however due the certificate (the scheduler's gate
// pauses the task too; here the planner is called directly).
func TestRenewalInLockContactsNoCA(t *testing.T) {
	w, task := renewing(t)
	c := w.dnsCert("locked.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	_, na := w.notAfter(c.ID)
	w.setClock(na.Add(-day))
	w.gate.locked.Store(true)
	requests := len(w.fake.Requests())
	orders := w.count("SELECT count(*) FROM acme_orders")
	audits := w.count("SELECT count(*) FROM audit_log")
	require.NoError(t, task.Run(w.ctx))
	w.drain()
	assert.Equal(t, requests, len(w.fake.Requests()), "no CA contact in lock")
	assert.Equal(t, orders, w.count("SELECT count(*) FROM acme_orders"))
	assert.Equal(t, audits, w.count("SELECT count(*) FROM audit_log"))
	assert.Zero(t, w.getCert(c.ID).Failures)
}

// Failed renewals through the real job: the backoff paces the planner, the third failure mails the Administrators once,
// the fifth stops automatic renewal; a lock during an order counts nothing.
func TestRenewalFailuresThroughTheJob(t *testing.T) {
	w, task := renewing(t)
	c := w.dnsCert("failing.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	_, na := w.notAfter(c.ID)
	w.setClock(na.Add(-25 * day))
	require.NoError(t, w.fake.FailValidation(fakeacme.DNS01, true))
	for n := 1; n <= 5; n++ {
		require.NoError(t, task.Run(w.ctx))
		w.drain()
		got := w.getCert(c.ID)
		require.Equal(t, n, got.Failures, "failure %d", n)
		assert.Equal(t, "acme.validation_failed_dns", got.LastErrorCode)
		mails := w.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'acme.renewal_failed'")
		if n < 3 {
			assert.Zero(t, mails)
		} else {
			assert.Equal(t, 1, mails, "failure %d: one e-mail to the one Administrator, once", n)
		}
		if n < 5 {
			require.NotNil(t, got.NextAttemptAt)
			assert.Equal(t, w.clock.Now().UTC().Add(renew.Backoff(n)), *got.NextAttemptAt)
			require.NoError(t, task.Run(w.ctx))
			assert.Equal(t, n, w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1 AND trigger = 'renewal'", c.ID),
				"failure %d: no order before the backoff", n)
			w.setClock(*got.NextAttemptAt)
		}
	}
	assert.Equal(t, inventory.ACMEStateStopped, w.getCert(c.ID).State)
	assert.Equal(t, 1, w.audits("acme.auto_renew.stopped"))
	assert.Equal(t, 1, w.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'acme.auto_renew_stopped'"))
	w.setClock(w.clock.Now().Add(2 * day))
	require.NoError(t, task.Run(w.ctx))
	assert.Equal(t, 5, w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1 AND trigger = 'renewal'", c.ID), "stopped")

	// A person's "Renew now" after the cause is gone makes it active again; the planner renews it from then on.
	require.NoError(t, w.fake.FailValidation(fakeacme.DNS01, false))
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	got := w.getCert(c.ID)
	assert.Equal(t, inventory.ACMEStateActive, got.State)
	assert.Zero(t, got.Failures)
}

// A lock that begins during a renewal order ends it with license.locked and counts no failure (neutral).
func TestRenewalEndedByALockIsNotAFailure(t *testing.T) {
	w, task := renewing(t)
	c := w.dnsCert("midlock.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	_, na := w.notAfter(c.ID)
	w.setClock(na.Add(-day))
	require.NoError(t, task.Run(w.ctx))
	w.gate.lockWhen = func() bool { return w.fake.Counters()["hook-present"] >= 2 }
	w.drain()
	var code string
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, `SELECT error_code FROM acme_orders WHERE acme_certificate_id = $1 AND trigger = 'renewal'`, c.ID).
		Scan(&code))
	assert.Equal(t, inventory.ACMELicenseLocked, code)
	got := w.getCert(c.ID)
	assert.Zero(t, got.Failures, "a lock is not the certificate's failure")
	assert.Nil(t, got.NextAttemptAt)
	assert.Equal(t, inventory.ACMEStateActive, got.State)
}
