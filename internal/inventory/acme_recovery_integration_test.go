//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/renew"
	"alice/internal/inventory"
)

// Recovery of ACME renewals after an outage (owner decision 2026-10-20; docs/superpowers/rulings/acme-renewal-recovery.md).

// Transient failures (an unreachable CA) never stop automatic renewal while the certificate is valid: the planner keeps
// ordering at the backoff (capped at a day, shorter near the end); the "renewal failed" e-mail goes once, no stop.
// Permanent failures after them stop it at the fifth permanent one.
func TestACMETransientFailuresDoNotStop(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("outage.example.test")
	na := w.notAfter(c)
	w.setClock(na.Add(-20 * day))
	for n := 1; n <= 8; n++ {
		require.Equal(t, 1, w.plan().Started, "failure %d: ordered again", n)
		now := w.clock.Now().UTC()
		require.NoError(t, w.svc.FailACMEOrderClass(w.ctx, w.running(c.ID), acme.ReasonProviderUnreachable, renew.ClassTransient, 0))
		r := w.get(c.ID)
		assert.Equal(t, n, r.Failures)
		assert.Zero(t, r.PermanentFailures)
		assert.Equal(t, renew.ClassTransient, r.LastFailureClass)
		assert.Equal(t, inventory.ACMEStateFailing, r.State, "failure %d: never stopped by an outage", n)
		require.NotNil(t, r.NextAttemptAt)
		assert.Equal(t, now.Add(renew.RetryWait(n, renew.ClassTransient, na.Sub(now))), *r.NextAttemptAt, "failure %d", n)
		w.setClock(*r.NextAttemptAt)
	}
	assert.Empty(t, w.outbox(inventory.TemplateACMEAutoRenewStopped))
	assert.Len(t, w.outbox(inventory.TemplateACMERenewalFailed), 2, "the failed e-mail once, to each Administrator")
	assert.Zero(t, w.audits("acme.auto_renew.stopped"))

	// Then the cause becomes one that needs a person: the fifth permanent failure stops it.
	for n := 1; n <= 5; n++ {
		r := w.get(c.ID)
		if r.NextAttemptAt != nil && r.NextAttemptAt.After(w.clock.Now()) {
			w.setClock(*r.NextAttemptAt)
		}
		require.Equal(t, 1, w.plan().Started, "permanent failure %d", n)
		require.NoError(t, w.svc.FailACMEOrderClass(w.ctx, w.running(c.ID), acme.ReasonValidationFailedDNS, renew.ClassPermanent, 0))
	}
	r := w.get(c.ID)
	assert.Equal(t, 13, r.Failures)
	assert.Equal(t, 5, r.PermanentFailures)
	assert.Equal(t, inventory.ACMEStateStopped, r.State)
	assert.Equal(t, 1, w.audits("acme.auto_renew.stopped"))
	w.advance(2 * day)
	assert.Zero(t, w.plan().Started, "a permanent stop waits for a person")
}

// A class the caller does not know is the class of the code; a failure of an expired certificate counts toward the stop
// whatever its class.
func TestACMEFailureClassFallbackAndExpiry(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("fallback.example.test")
	na := w.notAfter(c)
	w.setClock(na.Add(-20 * day))
	require.Equal(t, 1, w.plan().Started)
	require.NoError(t, w.svc.FailACMEOrderClass(w.ctx, w.running(c.ID), acme.ReasonCARateLimited, "flaky", time.Hour))
	assert.Equal(t, renew.ClassTransient, w.get(c.ID).LastFailureClass, "a rate limit is an outage")

	// Expired, four transient failures: the fifth stops it (no unbounded retry after the end).
	w.setClock(na.Add(time.Hour))
	_, err := w.db.Owner.Exec(w.ctx, `UPDATE acme_certificates SET failures = 4, permanent_failures = 0, last_failure_class = 'transient',
    next_attempt_at = NULL, last_attempt_at = $2 WHERE id = $1`, c.ID, w.clock.Now().Add(-3*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, w.plan().Started, "an expired certificate is still ordered")
	require.NoError(t, w.svc.FailACMEOrderClass(w.ctx, w.running(c.ID), acme.ReasonProviderUnreachable, renew.ClassTransient, 0))
	r := w.get(c.ID)
	assert.Equal(t, inventory.ACMEStateStopped, r.State)
	assert.Equal(t, 1, w.audits("acme.auto_renew.stopped"))
	w.advance(2 * day)
	assert.Zero(t, w.plan().Started, "expired: no recovery")
}

// A certificate stopped while its last failure was transient (a series from before the classes, or a person's order of a
// stopped certificate that failed in an outage) is ordered again by itself at the slow cadence until it expires; one
// stopped by a permanent failure is not.
func TestACMEStoppedAfterAnOutageRecovers(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("recover.example.test")
	perm := w.issued("perm.example.test")
	na := w.notAfter(c)
	w.setClock(na.Add(-6 * day))
	now := w.clock.Now()
	stop := func(id uuid.UUID, class string, lastAttempt time.Time) {
		_, err := w.db.Owner.Exec(w.ctx, `UPDATE acme_certificates SET state = 'stopped', failures = 6, permanent_failures = 0, last_failure_class = $2,
    last_error_code = 'acme.provider_unreachable', last_attempt_at = $3, next_attempt_at = $4, failure_notified_at = $3 WHERE id = $1`,
			id, class, lastAttempt, lastAttempt.Add(renew.MaxBackoff))
		require.NoError(t, err)
	}
	stop(c.ID, renew.ClassTransient, now.Add(-time.Hour))
	stop(perm.ID, renew.ClassPermanent, now.Add(-48*time.Hour))
	assert.Zero(t, w.plan().Started, "the recovery waits for the slow cadence")
	w.advance(23 * time.Hour)
	run := w.plan()
	assert.Equal(t, 1, run.Started, "recovered by itself; the permanent stop is not")
	assert.Equal(t, 1, w.renewals(c.ID))
	assert.Zero(t, w.renewals(perm.ID))
	assert.Equal(t, inventory.ACMEStateStopped, w.get(c.ID).State, "stopped until an order succeeds")

	// An outage again: still stopped, still recovered later; then a success re-arms it.
	require.NoError(t, w.svc.FailACMEOrderClass(w.ctx, w.running(c.ID), acme.ReasonNotIssuedInTime, renew.ClassTransient, 0))
	r := w.get(c.ID)
	assert.Equal(t, inventory.ACMEStateStopped, r.State)
	assert.Equal(t, 7, r.Failures)
	require.NotNil(t, r.NextAttemptAt)
	assert.Equal(t, w.clock.Now().UTC().Add(12*time.Hour), *r.NextAttemptAt, "within 7 days of the end: every 12 hours")
	assert.Zero(t, w.audits("acme.auto_renew.stopped"), "no second stop row or e-mail")
	w.setClock(*r.NextAttemptAt)
	require.Equal(t, 1, w.plan().Started)
	w.complete(w.running(c.ID))
	r = w.get(c.ID)
	assert.Equal(t, inventory.ACMEStateActive, r.State)
	assert.Zero(t, r.Failures)
	assert.Empty(t, r.LastFailureClass)

	// A recovery whose order fails for a cause that needs a person stays stopped for good.
	stop(c.ID, renew.ClassTransient, w.clock.Now().Add(-25*time.Hour))
	w.setClock(w.notAfter(w.get(c.ID)).Add(-5 * day))
	require.Equal(t, 1, w.plan().Started)
	require.NoError(t, w.svc.FailACMEOrderClass(w.ctx, w.running(c.ID), acme.ReasonIdentifierRefused, renew.ClassPermanent, 0))
	w.advance(3 * day)
	assert.Zero(t, w.plan().Started, "no further order after the permanent failure")
	assert.Equal(t, inventory.ACMEStateStopped, w.get(c.ID).State)
}

// While a renewal fails, the Administrators are e-mailed 14, 7, 3 and 1 days before the current certificate ends, once
// per threshold (the ledger), with the days left and the template of the last failure's class; after a downtime only the
// most urgent threshold goes; a certificate whose renewal does not fail gets none.
func TestACMEExpiryNotices(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("soon.example.test", "www.soon.example.test")
	quiet := w.issued("quiet.example.test")
	na := w.notAfter(c)
	fail := func(id uuid.UUID, state, class string, failures, permanent int) {
		_, err := w.db.Owner.Exec(w.ctx, `UPDATE acme_certificates SET state = $2, failures = $3, permanent_failures = $4, last_failure_class = $5,
    last_error_code = 'acme.provider_unreachable', last_attempt_at = $6, next_attempt_at = $7, failure_notified_at = $6 WHERE id = $1`,
			id, state, failures, permanent, class, w.clock.Now(), w.clock.Now().Add(renew.MaxBackoff))
		require.NoError(t, err)
	}
	w.setClock(na.Add(-20 * day))
	fail(c.ID, inventory.ACMEStateFailing, renew.ClassTransient, 4, 0)
	assert.Zero(t, w.plan().Warned, "20 days left: no threshold yet")

	w.setClock(na.Add(-13 * day))
	fail(c.ID, inventory.ACMEStateFailing, renew.ClassTransient, 4, 0)
	assert.Equal(t, 1, w.plan().Warned)
	mails := w.outbox(inventory.TemplateACMERenewalExpiringTransient)
	require.Len(t, mails, 2, "one per Administrator")
	assert.Equal(t, map[string]string{"name": "soon.example.test", "names": "soon.example.test, www.soon.example.test", "count": "4",
		"error_reason": acme.ReasonProviderUnreachable, "expires_at": na.Format("2006-01-02 15:04 UTC"), "days": "13",
		"acme_certificate_id": c.ID.String()}, mails[0].Params)
	assert.Zero(t, w.plan().Warned, "once per threshold")
	assert.Equal(t, 1, w.count("SELECT count(*) FROM alerts WHERE kind = 'acme_renewal_expiry' AND object_id = $1 AND threshold_days = 14", c.ID))

	// A cause that needs a person, 6 days left: the 7-day threshold with the permanent template.
	w.setClock(na.Add(-6 * day))
	fail(c.ID, inventory.ACMEStateFailing, renew.ClassPermanent, 5, 2)
	assert.Equal(t, 1, w.plan().Warned)
	assert.Len(t, w.outbox(inventory.TemplateACMERenewalExpiringPermanent), 2)

	// Stopped, then a downtime past the 3-day threshold: only the 1-day one goes, with the stopped template.
	w.setClock(na.Add(-12 * time.Hour))
	fail(c.ID, inventory.ACMEStateStopped, renew.ClassPermanent, 6, 5)
	assert.Equal(t, 1, w.plan().Warned)
	stopped := w.outbox(inventory.TemplateACMERenewalExpiringStopped)
	require.Len(t, stopped, 2)
	assert.Equal(t, "1", stopped[0].Params["days"])
	assert.Equal(t, 3, w.count("SELECT count(*) FROM alerts WHERE kind = 'acme_renewal_expiry' AND object_id = $1", c.ID),
		"14, 7 and 1: the skipped 3-day threshold is not sent late")
	assert.Zero(t, w.count("SELECT count(*) FROM alerts WHERE object_id = $1", quiet.ID), "a renewal that does not fail is not reminded")
	w.advance(time.Hour)
	assert.Zero(t, w.plan().Warned)

	// Automatic renewal off: no reminder (a person renews it by hand).
	other := w.issued("manual.example.test")
	_, err := w.svc.UpdateACMECertificate(w.ctx, w.admin, other.ID, inventory.ACMECertificatePatch{AutoRenew: ptr(false)})
	require.NoError(t, err)
	fail(other.ID, inventory.ACMEStateFailing, renew.ClassPermanent, 2, 2)
	w.setClock(w.notAfter(other).Add(-2 * day))
	w.plan()
	assert.Zero(t, w.count("SELECT count(*) FROM alerts WHERE object_id = $1", other.ID))
}

// The certificate's page shows how its newest renewal e-mail was delivered: one copy per recipient, by outcome.
func TestACMENoticeDelivery(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("mail.example.test")
	none, err := w.svc.ACMENoticeDelivery(w.ctx, c.ID)
	require.NoError(t, err)
	assert.Nil(t, none, "no renewal e-mail yet")
	_, err = w.svc.ACMENoticeDelivery(w.ctx, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	w.setClock(w.notAfter(c).Add(-20 * day))
	for n := 1; n <= 3; n++ {
		r := w.get(c.ID)
		if r.NextAttemptAt != nil {
			w.setClock(*r.NextAttemptAt)
		}
		require.Equal(t, 1, w.plan().Started)
		require.NoError(t, w.svc.FailACMEOrderClass(w.ctx, w.running(c.ID), acme.ReasonHookRefused, renew.ClassPermanent, 0))
	}
	d, err := w.svc.ACMENoticeDelivery(w.ctx, c.ID)
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.Equal(t, inventory.TemplateACMERenewalFailed, d.Template)
	assert.Equal(t, 2, d.Recipients)
	assert.Equal(t, 2, d.Pending)
	assert.Nil(t, d.SentAt)

	sentAt := w.clock.Now().UTC().Add(time.Minute)
	_, err = w.db.Owner.Exec(w.ctx, `UPDATE notifications_outbox SET status = 'sent', sent_at = $1 WHERE template_key = $2 AND locale = 'en'`, sentAt,
		inventory.TemplateACMERenewalFailed)
	require.NoError(t, err)
	_, err = w.db.Owner.Exec(w.ctx, `UPDATE notifications_outbox SET status = 'failed', last_error_code = 'smtp.auth' WHERE template_key = $1 AND locale = 'tr'`,
		inventory.TemplateACMERenewalFailed)
	require.NoError(t, err)
	d, err = w.svc.ACMENoticeDelivery(w.ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, d.Sent)
	assert.Equal(t, 1, d.Failed)
	assert.Zero(t, d.Pending)
	assert.Equal(t, "smtp.auth", d.LastErrorCode)
	require.NotNil(t, d.SentAt)
	assert.Equal(t, sentAt, d.SentAt.UTC())

	// Another certificate's e-mails are not this one's.
	other := w.issued("other.example.test")
	d, err = w.svc.ACMENoticeDelivery(w.ctx, other.ID)
	require.NoError(t, err)
	assert.Nil(t, d)
}

// Check again and resume refuses as a whole when the order cannot start (no active account): nothing changes.
func TestACMEReArmRefusedOrderChangesNothing(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("refused.example.test")
	_, err := w.db.Owner.Exec(w.ctx, `UPDATE acme_certificates SET state = 'stopped', failures = 5, permanent_failures = 5,
    last_failure_class = 'permanent' WHERE id = $1`, c.ID)
	require.NoError(t, err)
	_, err = w.db.Owner.Exec(w.ctx, "UPDATE acme_accounts SET state = 'deactivated' WHERE provider_id = $1", c.ProviderID)
	require.NoError(t, err)
	before := w.snapshot()
	_, err = w.svc.ReArmACMEAutoRenew(w.ctx, w.admin, c.ID)
	require.ErrorIs(t, err, inventory.ErrACMEAccountState)
	assert.Equal(t, before, w.snapshot())
}
