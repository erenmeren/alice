//go:build integration

package inventory_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// gateSwitch wraps the license gate of the harness so a test can close it for a poll without the
// license service (the real state stays open): locked, or unverified.
type gateSwitch struct {
	inventory.LicenseGate
	mu  sync.Mutex
	err error
}

func (g *gateSwitch) Allow(c license.Class) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return g.err
	}
	return g.LicenseGate.Allow(c)
}

func (g *gateSwitch) set(err error) {
	g.mu.Lock()
	g.err = err
	g.mu.Unlock()
}

func withGateSwitch(g *gateSwitch) harnessOption {
	return func(c *inventory.Config) {
		g.LicenseGate = c.License
		c.License = g
	}
}

// created gives a listed certificate (and its first version) the creation time Azure reports; nil
// means Azure did not say.
func created(c providers.KVCertificate, at *time.Time) providers.KVCertificate {
	c.Created = at
	if len(c.Versions) > 0 {
		c.Versions[0].Created = at
	}
	return c
}

func (h *harness) held(cert uuid.UUID, version string) (bool, string) {
	h.t.Helper()
	v, ok := h.versionRows(cert)[version]
	require.True(h.t, ok, "version %s is stored", version)
	return v.Held, v.HeldReason
}

// lockAndReopen locks the license (evaluation over), lets an hour pass (no poll runs: the renewals
// of the lock happen in Azure then) and installs a license: it returns the time of the lock's end
// and the time the gate reopened.
func (h *harness) lockAndReopen(t *testing.T) (lockedAt, reopenedAt time.Time) {
	t.Helper()
	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	lockedAt = h.clock.Now()
	h.clock.Advance(time.Hour)
	h.installLicense("LIC-REOPEN-"+uuid.NewString()[:6], 5, 365)
	reopenedAt = h.clock.Now()
	h.clock.Advance(time.Minute)
	return lockedAt, reopenedAt
}

// The hold rule (ruling on S8): a version that is new on a certificate Alice knows is stored held
// when the gate is closed, or its Azure creation time is not later than the time the gate last
// reopened (however late it is detected), or its creation time is unknown and no poll with a
// complete certificate listing has run since the gate reopened.
func TestRenewalSeenAfterALockIsHeld(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	prod, unr, trunc, late := h.vault("prod"), h.vault("unr"), h.vault("trunc"), h.vault("late-vault")
	t0 := h.clock.Now()
	for _, v := range []uuid.UUID{prod, unr, trunc} {
		h.reconcile(v, kvResult(h.kvc("web-cert", h.kvLeaf("www.example.test"), ver(1), t0, true), h.kvc("other", h.kvLeaf("o.example.test"), ver(1), t0, true)))
	}
	lockedAt, reopenedAt := h.lockAndReopen(t)
	duringLock := lockedAt.Add(30 * time.Minute) // the renewal was made while no poll could run
	renewal := func(version int, at *time.Time, older ...string) providers.KVCertificate {
		return created(h.kvc("web-cert", h.kvLeaf("www.example.test"), ver(version), h.clock.Now(), true, older...), at)
	}

	// Its creation time is before the reopening: held, whenever it is detected (b).
	sum := h.reconcile(prod, kvResult(renewal(2, &duringLock, ver(1)), h.kvc("other", h.kvLeaf("o.example.test"), "", t0, false)))
	assert.Equal(t, 1, sum.NewVersions)
	assert.Equal(t, 1, sum.HeldVersions)
	c := h.certRow(prod, "web-cert")
	isHeld, reason := h.held(c.ID, ver(2))
	assert.True(t, isHeld)
	assert.Equal(t, "license", reason)
	assert.Nil(t, h.versionRows(c.ID)[ver(2)].Notified, "no plan or notify mark from the poll")
	ev := h.auditDetails("kv.certificate.new_version")
	require.Len(t, ev, 1)
	assert.Equal(t, "true", ev[0]["held"])
	assert.Equal(t, "created_before_reopening", ev[0]["hold_rule"], "rule (b) says why")
	// A renewal created after the reopening is not held.
	h.clock.Advance(15 * time.Minute)
	after := h.clock.Now()
	sum = h.reconcile(prod, kvResult(renewal(3, &after, ver(2), ver(1))))
	assert.Equal(t, 1, sum.NewVersions)
	assert.Zero(t, sum.HeldVersions)
	isHeld, _ = h.held(c.ID, ver(3))
	assert.False(t, isHeld)
	isHeld, _ = h.held(c.ID, ver(2))
	assert.True(t, isHeld, "the held version stays held")

	// N1: a poll whose certificate list failed as a row does not count as the first complete poll
	// since the reopening: a renewal with no creation time seen by the next good poll is held (c).
	r := kvResult()
	r.KV.Failures = rows("azure.unreachable", "certificates")
	h.reconcile(unr, r)
	h.clock.Advance(time.Minute)
	sum = h.reconcile(unr, kvResult(renewal(2, nil, ver(1)), h.kvc("other", h.kvLeaf("o.example.test"), "", t0, false)))
	assert.Equal(t, 1, sum.HeldVersions, "after a failed list the first complete poll still holds")
	evs := h.auditDetails("kv.certificate.new_version")
	assert.Equal(t, "unconfirmed_since_reopening", evs[len(evs)-1]["hold_rule"], "rule (c) says why")
	// ... and once a complete poll has run, a renewal without a creation time is not held.
	h.clock.Advance(time.Minute)
	sum = h.reconcile(unr, kvResult(renewal(3, nil, ver(2), ver(1))))
	assert.Equal(t, 1, sum.NewVersions)
	assert.Zero(t, sum.HeldVersions)
	evs = h.auditDetails("kv.certificate.new_version")
	assert.Equal(t, "false", evs[len(evs)-1]["held"])
	assert.NotContains(t, evs[len(evs)-1], "hold_rule", "a version that is not held names no rule")

	// N1: a poll truncated before the renewed certificate is no complete poll either.
	r = kvResult(h.kvc("other", h.kvLeaf("o.example.test"), "", t0, false))
	r.KV.Truncated = []string{"certificates"}
	h.reconcile(trunc, r)
	h.clock.Advance(time.Minute)
	sum = h.reconcile(trunc, kvResult(renewal(2, nil, ver(1)), h.kvc("other", h.kvLeaf("o.example.test"), "", t0, false)))
	assert.Equal(t, 1, sum.HeldVersions)

	// A vault that never completed a poll: its first poll is a baseline (a certificate Alice sees
	// for the first time cannot have a binding, so no auto-deploy can exist for it), a renewal after
	// a complete poll is not held.
	h.reconcile(late, kvResult(h.kvc("fresh", h.kvLeaf("f.example.test"), ver(1), duringLock, true)))
	assert.Zero(t, h.count("SELECT count(*) FROM kv_certificate_versions v JOIN kv_certificates c ON c.id = v.kv_certificate_id WHERE c.target_id = $1 AND v.held", late))
	h.clock.Advance(15 * time.Minute)
	fresh2 := h.clock.Now()
	h.reconcile(late, kvResult(created(h.kvc("fresh", h.kvLeaf("f.example.test"), ver(2), fresh2, true, ver(1)), &fresh2)))
	assert.Zero(t, h.count("SELECT count(*) FROM kv_certificate_versions v JOIN kv_certificates c ON c.id = v.kv_certificate_id WHERE c.target_id = $1 AND v.held", late))
	_ = reopenedAt
}

// N2: certificates whose details can never be stored do not hold anything back: a genuine renewal of
// another certificate, created after the reopening, is not held, and one created during the lock but
// detected days later is.
func TestStuckDetailsDoNotHoldGenuineRenewals(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("stuck")
	t0 := h.clock.Now()
	bad := func() providers.KVCertificate { // the leaf is not the certificate of its thumbprint: never stored
		c := h.kvc("bad", h.kvLeaf("b.example.test"), ver(1), t0, true)
		c.Details.CER = h.kvLeaf("x.example.test").Cert.Raw
		return c
	}
	goodLeaf, lateLeaf := h.kvLeaf("g.example.test"), h.kvLeaf("l.example.test")
	h.reconcile(v, kvResult(h.kvc("good", goodLeaf, ver(1), t0, true), h.kvc("latecomer", lateLeaf, ver(1), t0, true)))
	lockedAt, _ := h.lockAndReopen(t)
	duringLock := lockedAt.Add(10 * time.Minute)
	listOnly := func() []providers.KVCertificate {
		return []providers.KVCertificate{bad(), h.kvc("good", goodLeaf, "", t0, false), h.kvc("latecomer", lateLeaf, "", t0, false)}
	}
	for range 3 { // several polls over days
		h.reconcile(v, kvResult(listOnly()...))
		h.clock.Advance(24 * time.Hour)
		require.NoError(t, h.lic.Tick(h.ctx)) // the gate stays verified
	}
	assert.True(t, h.certRow(v, "bad").Pending, "its details never arrive")
	now := h.clock.Now()
	goodRenewal := created(h.kvc("good", h.kvLeaf("g.example.test"), ver(2), now, true, ver(1)), &now)
	sum := h.reconcile(v, kvResult(bad(), goodRenewal, h.kvc("latecomer", lateLeaf, "", t0, false)))
	assert.Equal(t, 1, sum.NewVersions)
	assert.Zero(t, sum.HeldVersions, "a renewal created after the reopening is not held")
	late := created(h.kvc("latecomer", h.kvLeaf("l.example.test"), ver(2), now, true, ver(1)), &duringLock)
	h.clock.Advance(time.Hour)
	sum = h.reconcile(v, kvResult(bad(), goodRenewal, late))
	assert.Equal(t, 1, sum.HeldVersions, "a renewal created during the lock is held however late it is detected")
}

// N3: a version that is held stays held, with its reason, when a later poll carries its details at a
// time when the rule would not hold it anew.
func TestAHeldVersionIsNeverReleasedByAPoll(t *testing.T) {
	g := &gateSwitch{}
	h := newHarness(t, withAzure(), withGateSwitch(g))
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	t0 := h.clock.Now()
	h.reconcile(v, kvResult(h.kvc("web-cert", h.kvLeaf("www.example.test"), ver(1), t0, true)))
	h.clock.Advance(time.Hour)
	g.set(license.ErrLocked)
	now := h.clock.Now()
	l2 := h.kvLeaf("www.example.test")
	renewal := func() providers.KVCertificate {
		return created(h.kvc("web-cert", l2, ver(2), now, true, ver(1)), &now)
	}
	sum := h.reconcile(v, kvResult(renewal()))
	assert.Equal(t, 1, sum.HeldVersions)
	c := h.certRow(v, "web-cert")
	isHeld, reason := h.held(c.ID, ver(2))
	require.True(t, isHeld)
	require.Equal(t, "license", reason)
	ev := h.auditDetails("kv.certificate.new_version")
	require.Len(t, ev, 1)
	assert.Equal(t, "gate_closed", ev[0]["hold_rule"], "rule (a) says why")
	// The gate is open again and no reopening is on record: the rule would not hold this version.
	g.set(nil)
	h.clock.Advance(time.Hour)
	sum = h.reconcile(v, kvResult(renewal()))
	assert.Zero(t, sum.NewVersions)
	isHeld, reason = h.held(c.ID, ver(2))
	assert.True(t, isHeld, "a poll never releases a held version")
	assert.Equal(t, "license", reason)
	// A later renewal is not held (nothing holds it).
	h.clock.Advance(time.Hour)
	n3 := h.clock.Now()
	sum = h.reconcile(v, kvResult(created(h.kvc("web-cert", h.kvLeaf("www.example.test"), ver(3), n3, true, ver(2), ver(1)), &n3)))
	assert.Zero(t, sum.HeldVersions)
}

// A poll stored while the gate is unverified is no evidence that the gate has been open since it
// reopened: it holds what it detects and does not weaken the hold of later polls.
func TestAnUnverifiedPollChangesNothingAboutLaterHolds(t *testing.T) {
	g := &gateSwitch{}
	h := newHarness(t, withAzure(), withGateSwitch(g))
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	t0 := h.clock.Now()
	h.reconcile(v, kvResult(h.kvc("web-cert", h.kvLeaf("www.example.test"), ver(1), t0, true), h.kvc("other", h.kvLeaf("o.example.test"), ver(1), t0, true)))
	h.lockAndReopen(t)
	before := h.vaultRow(v).Facts.KVReconciledAt
	g.set(license.ErrUnverified)
	h.reconcile(v, kvResult(h.kvc("web-cert", h.kvLeaf("www.example.test"), "", t0, false), h.kvc("other", h.kvLeaf("o.example.test"), "", t0, false)))
	after := h.vaultRow(v).Facts.KVReconciledAt
	assert.Equal(t, before, after, "an unverified poll does not move the mark of the last complete poll")
	g.set(nil)
	h.clock.Advance(time.Minute)
	sum := h.reconcile(v, kvResult(created(h.kvc("web-cert", h.kvLeaf("www.example.test"), ver(2), t0, true, ver(1)), nil), h.kvc("other", h.kvLeaf("o.example.test"), "", t0, false)))
	assert.Equal(t, 1, sum.HeldVersions, "no complete poll with an open gate has run since the reopening")
}

// N7 (a, b): which license history rows are a reopening of the gate: a transition into an open phase
// (evaluation, active, grace) from a phase in which the gate was closed or could be closed (locked,
// evaluation_expired and grace, whose end locks before the tick records it), recorded by a state
// change, an install or a renewal. Nothing else is.
func TestOnlyAClosedToOpenTransitionIsAReopening(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	t0 := h.clock.Now()
	h.reconcile(v, kvResult(h.kvc("web-cert", h.kvLeaf("www.example.test"), ver(1), t0, true)))
	row := func(at time.Time, event, from, to string) {
		_, err := h.db.Owner.Exec(h.ctx, "INSERT INTO license_history (id, at, event, from_state, to_state) VALUES ($1, $2, $3, $4, $5)",
			uuid.Must(uuid.NewV7()), at, event, from, to)
		require.NoError(t, err)
	}
	at := t0.Add(time.Hour)
	for _, r := range [][3]string{{"installed", "active", "active"}, {"renewed", "active", "active"}, {"renewed", "evaluation", "active"},
		{"state_change", "grace", "grace"}, {"state_change", "locked", "locked"}, {"renewed", "locked", "evaluation_expired"},
		{"installed", "evaluation", "active"}, {"installed", "active", "grace"}, {"state_change", "locked", ""}, {"installed", "active", "locked"}, {"clock_anomaly", "locked", "active"}, {"rejected", "locked", "active"}} {
		row(at, r[0], r[1], r[2])
	}
	h.clock.Advance(3 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	probe := func(n int, createdAt time.Time) bool {
		h.clock.Advance(time.Minute)
		sum := h.reconcile(v, kvResult(created(h.kvc("web-cert", h.kvLeaf("www.example.test"), ver(n), createdAt, true), &createdAt)))
		return sum.HeldVersions == 1
	}
	assert.False(t, probe(2, t0.Add(30*time.Minute)), "no row is a closed-to-open transition")
	for i, r := range [][3]string{{"state_change", "grace", "active"}, {"installed", "locked", "active"}, {"renewed", "evaluation_expired", "grace"}} {
		at = at.Add(time.Hour)
		row(at, r[0], r[1], r[2])
		assert.True(t, probe(3+i, at.Add(-time.Minute)), "%v is a reopening", r)
		assert.False(t, probe(10+i, at.Add(time.Minute)), "created after it: not held")
		assert.True(t, probe(20+i, at), "created at the very time of the reopening: not later than it, held (R4)")
	}
	// Azure's creation time has whole seconds: a reopening at 12:00:00.4 holds a version created at 12:00:00.
	at = at.Add(time.Hour).Add(400 * time.Millisecond)
	row(at, "installed", "locked", "active")
	assert.True(t, probe(40, at.Truncate(time.Second)), "created in the second of the reopening")
	assert.False(t, probe(41, at.Truncate(time.Second).Add(time.Second)), "created in the next second")
}

// N4, N5, N6: the status follows the list that failed. The certificate list's own failure decides
// the status class, keys and secrets only degrade; the backoff follows the certificate list (or a
// budget cut); a persistent malformed answer leaves its code.
func TestStatusFollowsTheListThatFailed(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	type row struct {
		name              string
		certs, keys, secs string // reasons, "" = the list answered
		status, code      string
		failures, cycles  int
		success           bool // last_success_at moves
	}
	cases := []row{
		{"keys unreachable", "", "azure.unreachable", "", inventory.StatusDegraded, "azure.unreachable", 0, 0, true},
		{"secrets sign-in", "", "", "azure.auth_failed", inventory.StatusDegraded, "azure.auth_failed", 0, 0, true},
		{"keys unexpected", "", "azure.unexpected_response", "", inventory.StatusOK, "azure.unexpected_response", 0, 0, true},
		{"keys throttled", "", "azure.throttled", "", inventory.StatusOK, "", 0, 1, true},
		{"certs unreachable", "azure.unreachable", "", "", inventory.StatusUnreachable, "azure.unreachable", 1, 0, false},
		{"certs unreachable keys forbidden", "azure.unreachable", "azure.forbidden", "", inventory.StatusUnreachable, "azure.unreachable", 1, 0, false},
		{"certs forbidden keys unreachable", "azure.forbidden", "azure.unreachable", "", inventory.StatusDegraded, "azure.forbidden", 0, 0, false},
		{"certs throttled keys forbidden", "azure.throttled", "azure.forbidden", "", inventory.StatusDegraded, "azure.forbidden", 1, 1, false},
		{"certs unexpected keys forbidden", "azure.unexpected_response", "azure.forbidden", "", inventory.StatusDegraded, "azure.forbidden", 1, 0, false},
		{"every list unexpected", "azure.unexpected_response", "azure.unexpected_response", "azure.unexpected_response", inventory.StatusOK, "azure.unexpected_response", 1, 0, false},
	}
	for i, c := range cases {
		v := h.vault(fmt.Sprintf("lst%02d", i))
		res := kvResult()
		if c.certs != "" {
			res.KV.Failures = append(res.KV.Failures, rows(c.certs, "certificates")...)
		}
		if c.keys != "" {
			res.KV.Failures = append(res.KV.Failures, rows(c.keys, "keys")...)
		}
		if c.secs != "" {
			res.KV.Failures = append(res.KV.Failures, rows(c.secs, "secrets")...)
		}
		h.reconcile(v, res)
		got := h.vaultRow(v)
		assert.Equal(t, c.status, got.Status, c.name)
		assert.Equal(t, c.code, got.Code, c.name)
		assert.Equal(t, c.failures, got.PollFailures, c.name)
		assert.Equal(t, c.cycles, got.Facts.KVThrottledCycles, c.name)
		assert.Equal(t, c.success, got.LastSuccess != nil, c.name)
		assert.Zero(t, h.emails("kv.auth_failed"), c.name+": no sign-in streak from keys or secrets")
	}
}

// N7 (c): the summary mail has a singular text for exactly one more certificate.
func TestRemovalSummaryIsSingularForOne(t *testing.T) {
	h := newHarness(t, withAzure())
	h.user("ada", rbac.Admin, "ada@example.com")
	v := h.vault("prod")
	now := h.clock.Now()
	var cs []providers.KVCertificate
	for i := range 22 {
		cs = append(cs, providers.KVCertificate{Name: fmt.Sprintf("c%02d", i), Thumbprint: fmt.Sprintf("%040x", i+1), Enabled: true, Updated: &now})
	}
	h.reconcile(v, kvResult(cs...))
	h.clock.Advance(time.Minute)
	h.reconcile(v, kvResult(cs[21])) // 21 removed: 20 mails and one more
	assert.Equal(t, 20, h.removalEmails())
	assert.Equal(t, 1, h.emails("kv.certificates_removed_more_one"))
	assert.Equal(t, 0, h.emails("kv.certificates_removed_more"))
	var params string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT params::text FROM notifications_outbox WHERE template_key = 'kv.certificates_removed_more_one'").Scan(&params))
	assert.JSONEq(t, `{"target_name":"prod","count":"1"}`, params)
}
