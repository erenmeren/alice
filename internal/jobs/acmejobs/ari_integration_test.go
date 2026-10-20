//go:build integration

package acmejobs

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/renew"
	"alice/internal/inventory"
)

// certIDOf is the RFC 9773 identifier of a stored certificate.
func (w *world) certIDOf(certificateID uuid.UUID) string {
	w.t.Helper()
	var chain string
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT pem_chain FROM certificates WHERE id = $1", certificateID).Scan(&chain))
	block, _ := pem.Decode([]byte(chain))
	require.NotNil(w.t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(w.t, err)
	id, err := acme.CertID(leaf)
	require.NoError(w.t, err)
	return id
}

// lastOrder is the newest order of an ACME certificate with its replaces columns and CA URLs.
func (w *world) lastOrder(acmeCertificateID uuid.UUID) (o inventory.ACMEOrder, orderURL, accountURL string) {
	w.t.Helper()
	var id uuid.UUID
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, `SELECT id, order_url, account_url FROM acme_orders WHERE acme_certificate_id = $1
ORDER BY started_at DESC, id DESC LIMIT 1`, acmeCertificateID).Scan(&id, &orderURL, &accountURL))
	return w.getOrder(id), orderURL, accountURL
}

// ariRenewAt is the stored time chosen in the CA's window.
func (w *world) ariRenewAt(id uuid.UUID) *time.Time {
	w.t.Helper()
	var at *time.Time
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, "SELECT ari_renew_at FROM acme_certificates WHERE id = $1", id).Scan(&at))
	if at != nil {
		u := at.UTC()
		at = &u
	}
	return at
}

// A renewal through the planner and the job names its predecessor in newOrder (RFC 9773 replaces): the identifier of
// the current certificate, recorded on the order with the outcome and the account; a first order names none.
func TestRenewalSendsReplaces(t *testing.T) {
	w, task := renewing(t)
	c := w.dnsCert("replaces.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	assert.Empty(t, w.fake.Replacements(), "a first order names no predecessor")
	first, _, account := w.lastOrder(c.ID)
	assert.Empty(t, first.Replaces)
	assert.Empty(t, first.ReplacesOutcome)
	assert.Equal(t, w.account.AccountURL, account, "the order records the account it ran under")

	old, na := w.notAfter(c.ID)
	w.setClock(na.Add(-29 * day)) // past the local rule; the fake's default window starts at it (not used)
	require.NoError(t, task.Run(w.ctx))
	w.drain()
	cur, _ := w.notAfter(c.ID)
	require.NotEqual(t, old, cur, "renewed")
	rs := w.fake.Replacements()
	require.Len(t, rs, 1)
	assert.Equal(t, w.certIDOf(old), rs[0].CertID, "base64url(AKI).base64url(serial) of the predecessor")
	o, _, _ := w.lastOrder(c.ID)
	assert.Equal(t, inventory.ACMEOrderSucceeded, o.State)
	assert.Equal(t, inventory.ACMETriggerRenewal, o.Trigger)
	assert.Equal(t, w.certIDOf(old), o.Replaces)
	assert.Equal(t, acme.ReplacesSent, o.ReplacesOutcome)
}

// The time chosen in the CA's window is stored once: later runs, the CA asked again with the same window, and a restart
// (a new planner over the same database; the planner keeps nothing in memory) never move it. When it comes the
// certificate is renewed with replaces, and the new certificate starts without a chosen time.
func TestARIChosenTimeIsKept(t *testing.T) {
	w, task := renewing(t)
	c := w.dnsCert("chosen.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	old, na := w.notAfter(c.ID)
	ws := w.clock.Now().UTC().Add(20 * day).Truncate(time.Second)
	we := ws.Add(5 * day) // well before the local rule (na - 30 d)
	require.NoError(t, w.fake.SetARIWindowFor(w.certIDOf(old), ws, we))

	w.setClock(w.clock.Now().Add(time.Hour)) // past the spacing after the first order
	require.NoError(t, task.Run(w.ctx))
	chosen := w.ariRenewAt(c.ID)
	require.NotNil(t, chosen, "chosen at the first lookup")
	assert.False(t, chosen.Before(ws))
	assert.True(t, chosen.Before(we))
	got := w.getCert(c.ID)
	require.NotNil(t, got.ARIRenewAt)
	assert.Equal(t, *chosen, *got.ARIRenewAt)

	aris := w.fake.Counters()["ari"]
	for _, step := range []time.Duration{time.Hour, renew.ARIRefresh, renew.ARIRefresh} {
		w.setClock(w.clock.Now().Add(step))
		require.NoError(t, task.Run(w.ctx))
		assert.Equal(t, *chosen, *w.ariRenewAt(c.ID))
	}
	assert.Greater(t, w.fake.Counters()["ari"], aris, "the CA was asked again")
	restarted := ScheduleTask(w.inv, time.Minute, nil)
	w.setClock(w.clock.Now().Add(renew.ARIRefresh))
	require.NoError(t, restarted.Run(w.ctx))
	assert.Equal(t, *chosen, *w.ariRenewAt(c.ID), "a restart does not move it")
	assert.Equal(t, 1, w.count("SELECT count(*) FROM acme_orders WHERE acme_certificate_id = $1", c.ID), "not due before the chosen time")

	w.setClock(*chosen)
	require.NoError(t, restarted.Run(w.ctx))
	w.drain()
	cur, newNA := w.notAfter(c.ID)
	assert.NotEqual(t, old, cur, "renewed at the chosen time")
	assert.True(t, newNA.After(na))
	require.Len(t, w.fake.Replacements(), 1)
	assert.Equal(t, w.certIDOf(old), w.fake.Replacements()[0].CertID)
	assert.Nil(t, w.ariRenewAt(c.ID), "the new certificate starts without a chosen time")
	assert.Nil(t, w.getCert(c.ID).ARIWindowStart)
}

// The CA moves the window into the past (a revocation or a mass renewal at the CA): at the next lookup the time is
// chosen again inside it and the certificate is renewed at once.
func TestARIWindowMovedIntoThePast(t *testing.T) {
	w, task := renewing(t)
	c := w.dnsCert("moved.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	old, _ := w.notAfter(c.ID)
	id := w.certIDOf(old)
	now := w.clock.Now().UTC().Truncate(time.Second)
	require.NoError(t, w.fake.SetARIWindowFor(id, now.Add(40*day), now.Add(45*day)))
	w.setClock(w.clock.Now().Add(time.Hour))
	require.NoError(t, task.Run(w.ctx))
	chosen := w.ariRenewAt(c.ID)
	require.NotNil(t, chosen)

	w.setClock(w.clock.Now().Add(renew.ARIRefresh))
	require.NoError(t, w.fake.SetARIWindowFor(id, w.clock.Now().Add(-2*time.Hour), w.clock.Now().Add(-time.Hour)))
	require.NoError(t, task.Run(w.ctx))
	w.drain()
	cur, _ := w.notAfter(c.ID)
	assert.NotEqual(t, old, cur, "renewed on the CA's word")
	o, _, _ := w.lastOrder(c.ID)
	assert.Equal(t, inventory.ACMETriggerRenewal, o.Trigger)
	assert.Equal(t, acme.ReplacesSent, o.ReplacesOutcome)
}

// alreadyReplaced after an interrupted renewal: the CA still holds the order the dead run created (pending, replacing
// the certificate), so the next renewal takes it over instead of ordering anew.
func TestAlreadyReplacedTakesOverTheInterruptedRenewal(t *testing.T) {
	w, task := renewing(t)
	c := w.dnsCert("adopt.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	old, na := w.notAfter(c.ID)
	w.setClock(na.Add(-29 * day))
	w.h.crash = func(stage string) bool { return stage == "presented" }
	require.NoError(t, task.Run(w.ctx))
	w.drain()
	w.h.crash = nil
	dead, deadURL, _ := w.lastOrder(c.ID)
	require.Equal(t, inventory.ACMEOrderRunning, dead.State)
	require.Equal(t, acme.ReplacesSent, dead.ReplacesOutcome)
	require.NotEmpty(t, deadURL)
	w.clock.Advance(StaleAfter + time.Minute)
	require.NoError(t, w.h.sweep(w.ctx))
	w.drain()
	require.Equal(t, inventory.ACMEOrderAbandoned, w.getOrder(dead.ID).ErrorCode)

	w.setClock(w.clock.Now().Add(renew.MinSpacing))
	require.NoError(t, task.Run(w.ctx))
	w.drain()
	cur, _ := w.notAfter(c.ID)
	assert.NotEqual(t, old, cur, "renewed")
	o, url, _ := w.lastOrder(c.ID)
	assert.Equal(t, inventory.ACMEOrderSucceeded, o.State)
	assert.Equal(t, acme.ReplacesAdopted, o.ReplacesOutcome)
	assert.Equal(t, w.certIDOf(old), o.Replaces)
	assert.Equal(t, deadURL, url, "the CA's order of the dead run was finished")
	assert.Len(t, w.fake.Replacements(), 1, "no second order replaced the certificate")
	assert.Zero(t, w.getCert(c.ID).Failures)
}

// alreadyReplaced when Alice holds no order it can take over (the dead run's order is older than an order lives at a
// CA): the renewal is ordered once more without the field, and the order records why.
func TestAlreadyReplacedOrdersAgainWithoutTheField(t *testing.T) {
	w, task := renewing(t)
	c := w.dnsCert("again.example.test")
	w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	old, na := w.notAfter(c.ID)
	w.setClock(na.Add(-29 * day))
	w.h.crash = func(stage string) bool { return stage == "presented" }
	require.NoError(t, task.Run(w.ctx))
	w.drain()
	w.h.crash = nil
	w.clock.Advance(StaleAfter + time.Minute)
	require.NoError(t, w.h.sweep(w.ctx))
	w.drain()

	w.setClock(w.clock.Now().Add(8 * day))
	require.NoError(t, task.Run(w.ctx))
	w.drain()
	cur, _ := w.notAfter(c.ID)
	assert.NotEqual(t, old, cur, "renewed")
	o, _, _ := w.lastOrder(c.ID)
	assert.Equal(t, inventory.ACMEOrderSucceeded, o.State)
	assert.Equal(t, acme.ReplacesAlreadyReplaced, o.ReplacesOutcome)
	assert.Len(t, w.fake.Replacements(), 1, "the order made again carries no replaces")
}
