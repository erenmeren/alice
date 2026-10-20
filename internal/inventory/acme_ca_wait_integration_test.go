//go:build integration

package inventory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/keygen"
	"alice/internal/acme/solver"
	"alice/internal/inventory"
	"alice/internal/testutil/fakeacme"
)

// failFromCA runs an order's CA conversation, which must fail, and ends the order as the acme.issue job does
// (ACMEOrderFailure: the code, the class and the CA's Retry-After).
func (w *renewWorld) failFromCA(order uuid.UUID) {
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
	_, err = client.Order(w.ctx, work.Names, csr, sol)
	require.Error(w.t, err)
	code, class, after := inventory.ACMEOrderFailure(err)
	require.NoError(w.t, w.svc.FailACMEOrderClass(w.ctx, order, code, class, after))
}

// R47: the CA's Retry-After of 48 hours (a rate limit) is waited for in full. Alice's own backoff (1 h after the first
// failure) and its cap (24 h) do not shorten it: no new order 24 hours after the limit, one after 48 hours.
func TestACMEPlannerWaitsForTheCAsRetryAfter(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("wait.example.test")
	w.setClock(w.notAfter(c).Add(-29 * day))
	require.Equal(t, 1, w.plan().Started)
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: 48 * time.Hour}))
	w.failFromCA(w.running(c.ID))
	limitedAt := w.clock.Now()
	r := w.get(c.ID)
	require.Equal(t, "acme.ca_rate_limited", r.LastErrorCode)
	for _, h := range []time.Duration{1, 2, 12, 24, 25, 47} {
		w.setClock(limitedAt.Add(h * time.Hour))
		assert.Zero(t, w.plan().Started, "%d hours after the limit: the CA asked for 48", h)
	}
	w.setClock(limitedAt.Add(48*time.Hour - time.Minute))
	assert.Zero(t, w.plan().Started, "a minute before the CA's time")
	assert.Equal(t, 1, w.renewals(c.ID), "one order so far: the limited one")
	w.setClock(limitedAt.Add(48 * time.Hour))
	assert.Equal(t, 1, w.plan().Started, "the CA's time has come")
	assert.Equal(t, 2, w.renewals(c.ID))
}

// R47: the renewal information's Retry-After (here a rate limit of the renewalInfo resource for 48 hours) is waited
// for in full too, bounded at a week.
func TestACMEARIRetryAfterIsHonouredPastADay(t *testing.T) {
	w := newRenewWorld(t)
	c := w.issued("ariwait.example.test")
	w.setClock(w.notAfter(c).Add(-45 * day))
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "ari", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: 48 * time.Hour}))
	assert.Equal(t, inventory.ACMERenewRun{ARIChecked: 1}, w.plan())
	var next time.Time
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, "SELECT ari_next_check_at FROM acme_certificates WHERE id = $1", c.ID).Scan(&next))
	assert.Equal(t, w.clock.Now().UTC().Add(48*time.Hour), next.UTC(), "the CA's 48 hours")
	w.advance(24 * time.Hour)
	assert.Equal(t, inventory.ACMERenewRun{}, w.plan(), "not asked again after a day")
	w.advance(24 * time.Hour)
	assert.Equal(t, inventory.ACMERenewRun{ARIChecked: 1}, w.plan(), "asked again after two days")
}

// R47: a person's order (issue or test) and Check again and resume do not override the CA either: the order is refused
// without contacting the CA (acme.ca_rate_limited with the time left); the re-arm happens without an order. Only a
// successful order clears the CA's time.
func TestACMEPersonsOrderWaitsForTheCA(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("person.example.test")
	o, err := w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, "acme.ca_rate_limited", 48*time.Hour))
	r := w.get(c.ID)
	require.NotNil(t, r.CANotBefore)
	assert.Equal(t, w.clock.Now().UTC().Add(48*time.Hour), *r.CANotBefore)
	require.NotNil(t, r.NextAttemptAt)
	assert.Equal(t, w.clock.Now().UTC().Add(time.Hour), *r.NextAttemptAt, "Alice's own backoff stays apart")

	w.advance(30 * time.Hour)
	newOrders := w.fake.Counters()["new-order"]
	for _, kind := range []string{inventory.ACMEOrderIssue, inventory.ACMEOrderTest} {
		_, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, kind)
		var ae *inventory.ACMEError
		require.ErrorAs(t, err, &ae, kind)
		assert.ErrorIs(t, err, inventory.ErrACMECAWait)
		assert.Equal(t, "acme.ca_rate_limited", ae.Reason)
		assert.Equal(t, 18*time.Hour, ae.RetryAfter, "the time left")
	}
	assert.Equal(t, newOrders, w.fake.Counters()["new-order"], "the CA was not contacted")
	orders := w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1", c.ID)
	r, err = w.svc.ReArmACMEAutoRenew(w.ctx, w.admin, c.ID)
	require.NoError(t, err)
	assert.Nil(t, r.RunningOrderID, "re-armed, but no order before the CA's time")
	assert.Zero(t, r.Failures)
	assert.Nil(t, r.NextAttemptAt)
	require.NotNil(t, r.CANotBefore, "the CA's time stays")
	assert.Equal(t, orders, w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1", c.ID))

	w.advance(18 * time.Hour)
	o, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err, "the CA's time has come")
	w.complete(o.ID)
	assert.Nil(t, w.get(c.ID).CANotBefore, "a successful order clears it")

	// A test run's Retry-After is the CA's too.
	o, err = w.svc.RequestOrder(w.ctx, w.operator, c.ID, inventory.ACMEOrderTest)
	require.NoError(t, err)
	require.NoError(t, w.svc.FailACMEOrder(w.ctx, o.ID, "acme.ca_rate_limited", 36*time.Hour))
	r = w.get(c.ID)
	require.NotNil(t, r.CANotBefore)
	assert.Equal(t, w.clock.Now().UTC().Add(36*time.Hour), *r.CANotBefore)
	assert.Nil(t, r.NextAttemptAt, "a test run counts no failure")
	assert.Zero(t, r.Failures)
}

// R47: a CA's Retry-After is bounded at a week (a hostile or buggy CA cannot park a renewal longer); a stored time
// beyond a week from now (the clock moved back) is bounded to now + a week, never cut to the local cap of a day.
func TestACMECAWaitBounds(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("bound.example.test")
	w.setClock(w.notAfter(c).Add(-29 * day))
	require.Equal(t, 1, w.plan().Started)
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: 30 * day}))
	w.failFromCA(w.running(c.ID))
	r := w.get(c.ID)
	require.NotNil(t, r.CANotBefore)
	assert.Equal(t, w.clock.Now().UTC().Add(7*day), *r.CANotBefore, "a week, not thirty days")

	far := w.clock.Now().Add(400 * day)
	_, err := w.db.Owner.Exec(w.ctx, "UPDATE acme_certificates SET ca_not_before = $2 WHERE id = $1", c.ID, far)
	require.NoError(t, err)
	w.advance(time.Hour) // past Alice's own backoff: the planner reads the certificate again
	assert.Zero(t, w.plan().Started)
	assert.Equal(t, w.clock.Now().UTC().Add(7*day), *w.get(c.ID).CANotBefore, "bounded to a week from now, not a day")
	w.advance(7*day - time.Minute)
	assert.Zero(t, w.plan().Started)
	w.advance(time.Minute)
	assert.Equal(t, 1, w.plan().Started)
}

// R47: a CA wait that leaves less than half of the renewal window is not cut short; the Administrators are e-mailed at
// once (one English, one Turkish), once per such wait.
func TestACMECriticalCAWaitIsToldAtOnce(t *testing.T) {
	w := newRenewWorld(t)
	require.NoError(t, w.fake.Advertise("renewalInfo", "off"))
	c := w.issued("critical.example.test")
	na := w.notAfter(c)
	w.setClock(na.Add(-29 * day)) // due 30 days before the end: the middle of the window is 15 days before it
	require.Equal(t, 1, w.plan().Started)
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: 2 * day}))
	w.failFromCA(w.running(c.ID))
	assert.Empty(t, w.outbox(inventory.TemplateACMERenewalCAWait), "two days of 29 left: not critical")

	w.setClock(na.Add(-20 * day))
	require.Equal(t, 1, w.plan().Started)
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "new-order", Kind: fakeacme.FaultRateLimited, Times: 1, RetryAfter: 7 * day}))
	w.failFromCA(w.running(c.ID))
	mails := w.outbox(inventory.TemplateACMERenewalCAWait)
	require.Len(t, mails, 2, "a week of 20 days left: past the middle of the window")
	assert.Equal(t, w.clock.Now().UTC().Add(7*day).Format("2006-01-02 15:04 UTC"), mails[0].Params["ca_not_before"])
	assert.Equal(t, "20", mails[0].Params["days"])
	assert.Equal(t, "critical.example.test", mails[0].Params["name"])
	assert.Equal(t, c.ID.String(), mails[0].Params["acme_certificate_id"])
	assert.Equal(t, 1, w.count("SELECT count(*) FROM alerts WHERE kind = 'acme_renewal_ca_wait' AND object_id = $1", c.ID))

	// Alice still waits for the CA: no order before its time, though the end nears.
	w.advance(7*day - time.Minute)
	assert.Zero(t, w.plan().Started)
	w.advance(time.Minute)
	assert.Equal(t, 1, w.plan().Started)
	// A new wait with fewer days left at its end is told again.
	require.NoError(t, w.svc.FailACMEOrder(w.ctx, w.running(c.ID), "acme.ca_rate_limited", 7*day))
	assert.Len(t, w.outbox(inventory.TemplateACMERenewalCAWait), 4, "a week of 13 days left: a new wait")
	assert.Equal(t, 2, w.count("SELECT count(*) FROM alerts WHERE kind = 'acme_renewal_ca_wait' AND object_id = $1", c.ID))
}
