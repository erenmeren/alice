//go:build integration

package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/rbac"
)

func addN(h *harness, a inventory.Actor, from, n int) {
	for i := from; i < from+n; i++ {
		h.add(a, fmt.Sprintf("web-%02d", i), fmt.Sprintf("web-%02d.example.com", i))
	}
}

func liveTargets(h *harness) int {
	return h.count("SELECT count(*) FROM targets WHERE deleted_at IS NULL")
}

func banner(h *harness, kind string) bool {
	for _, b := range h.lic.Snapshot().Banners(true) {
		if b.Kind == kind {
			return true
		}
	}
	return false
}

// L-04: the evaluation allows 5 targets; the 6th is refused, audited and not stored.
func TestL04EvaluationAllowsFiveTargets(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	addN(h, admin, 1, 5)
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-06", Type: "linux", Host: "web-06.example.com"})
	var limit *license.TargetLimitError
	require.ErrorAs(t, err, &limit)
	assert.Equal(t, 5, limit.Max)
	assert.Equal(t, 5, liveTargets(h))
	assert.Equal(t, []map[string]string{{"reason": "target_limit", "used": "5", "max": "5", "name": "web-06"}},
		h.auditDetails("target.add.denied_license"))
	assert.Len(t, h.jobs.requests(), 5, "the refused add queued no job")
	assert.True(t, banner(h, "limit_reached"), "the snapshot counts the targets after each add")
}

// L-70, L-71: at 9 of 10 the 10th works; at 10 of 10 an 11th of any type is refused and nothing
// is locked.
func TestL70L71TargetLimit(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	h.installLicense("LIC-L70", 10, 365)
	h.seedTarget("nginx-01", "nginx", "nginx-01.example.com")
	h.seedTarget("vault-01", "azure_key_vault", "vault-01.vault.azure.net")
	addN(h, admin, 1, 7)
	require.NoError(t, h.lic.Tick(h.ctx))
	assert.Equal(t, 9, liveTargets(h))
	h.add(admin, "web-10", "web-10.example.com")
	assert.Equal(t, 10, liveTargets(h))

	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-11", Type: "linux", Host: "web-11.example.com"})
	require.ErrorIs(t, err, license.ErrTargetLimit)
	assert.Equal(t, 10, liveTargets(h))
	assert.Equal(t, license.PhaseActive, h.lic.Snapshot().Eval.Phase, "the limit never locks (R30)")
	require.NoError(t, h.lic.Allow(license.ClassChange))
	_, err = h.svc.RequestTest(h.ctx, admin, mustList(t, h)[0].ID)
	require.NoError(t, err, "existing targets keep working")

	// The 11th is refused whatever its type: the gate counts every type and decides before the
	// insert. Phase 3 can only create linux targets, so the other types are checked at the gate.
	for _, typ := range []string{"linux", "nginx", "azure_key_vault"} {
		err := db.InTx(h.ctx, h.db.App, func(tx pgx.Tx) error { return h.lic.CheckCanAddTarget(h.ctx, tx) })
		require.ErrorIs(t, err, license.ErrTargetLimit, typ)
		_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "eleven-" + typ, Type: typ, Host: "eleven.example.com"})
		require.Error(t, err, typ)
	}
	assert.Equal(t, 10, liveTargets(h))
}

// L-73 under concurrency: while a delete is still uncommitted its slot is not free; once it
// commits the add succeeds.
func TestDeleteAndAddRacingAtTheLimit(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	addN(h, admin, 1, 5)
	victim := mustList(t, h)[0]
	tx, err := h.db.App.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	_, err = tx.Exec(h.ctx, "UPDATE targets SET deleted_at = $2, version = version + 1, updated_at = $2 WHERE id = $1", victim.ID, h.clock.Now())
	require.NoError(t, err)

	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-06", Type: "linux", Host: "web-06.example.com"})
	require.ErrorIs(t, err, license.ErrTargetLimit, "the uncommitted delete does not free the slot")
	require.NoError(t, tx.Commit(h.ctx))
	h.add(admin, "web-06", "web-06.example.com")
	assert.Equal(t, 5, liveTargets(h))
}

// A refused add is audited even when the request's context ends right after the refusal.
func TestLicenseDenialIsAuditedAfterCancel(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	ctx, cancel := context.WithCancel(h.ctx)
	cancel()
	h.svc.AuditLicenseDenial(ctx, admin, "web-09", &license.TargetLimitError{Max: 5, Used: 5})
	assert.Equal(t, []map[string]string{{"reason": "target_limit", "used": "5", "max": "5", "name": "web-09"}},
		h.auditDetails("target.add.denied_license"))
}

// L-72 (counting part): 200 keys on existing targets at 10 of 10 do not count. Task 15 repeats
// it through Reconcile.
func TestL72KeysDoNotCount(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	h.installLicense("LIC-L72", 10, 365)
	addN(h, admin, 1, 10)
	for i := range 200 {
		_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'ssh-ed25519 AAAA', $3, $3)`, uuid.New(), fmt.Sprintf("SHA256:key%03d0000000000000000000000000000000000000", i), h.clock.Now())
		require.NoError(t, err)
	}
	n, err := inventory.Counter{}.CountTargets(h.ctx, h.db.App)
	require.NoError(t, err)
	assert.Equal(t, 10, n)
}

// L-73: deleting a target frees its slot at once.
func TestL73DeleteFreesASlot(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	addN(h, admin, 1, 5)
	list := mustList(t, h)
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, list[0].ID))
	h.add(admin, list[0].Name, list[0].Host) // the deleted name and address can be used again
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-07", Type: "linux", Host: "web-07.example.com"})
	require.ErrorIs(t, err, license.ErrTargetLimit)
}

// L-74: two administrators add the last allowed target at the same moment: exactly one wins.
func TestL74ConcurrentAddsNeverExceedTheLimit(t *testing.T) {
	for round := range 5 {
		h := newHarness(t)
		admin := h.user("ada", rbac.Admin, "")
		other := h.user("bora", rbac.Admin, "")
		addN(h, admin, 1, 4)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, a := range []inventory.Actor{admin, other} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, errs[i] = h.svc.CreateTarget(h.ctx, a, inventory.NewTarget{
					Name: fmt.Sprintf("race-%d-%d", round, i), Type: "linux", Host: fmt.Sprintf("race-%d-%d.example.com", round, i)})
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else {
				require.ErrorIs(t, err, license.ErrTargetLimit)
			}
		}
		assert.Equal(t, 1, ok, "round %d: exactly one add wins", round)
		assert.Equal(t, 5, liveTargets(h), "round %d: the count never exceeds the limit", round)
	}
}

// L-75, L-76: a smaller renewal keeps every target working, blocks adding, and shows the banner
// until the count is within the limit again.
func TestL75L76SmallerRenewal(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	h.installLicense("LIC-OLD-15", 15, 365)
	addN(h, admin, 1, 12)
	h.clock.Advance(time.Hour)
	h.installLicense("LIC-NEW-10", 10, 400)
	require.NoError(t, h.lic.Tick(h.ctx))
	assert.Equal(t, license.PhaseActive, h.lic.Snapshot().Eval.Phase)
	assert.Equal(t, 10, h.lic.Snapshot().Eval.MaxTargets)
	assert.True(t, banner(h, "over_limit"))
	for _, tg := range mustList(t, h) {
		_, err := h.svc.RequestTest(h.ctx, admin, tg.ID)
		require.NoError(t, err, "every existing target keeps working")
	}
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-13", Type: "linux", Host: "web-13.example.com"})
	require.ErrorIs(t, err, license.ErrTargetLimit)

	list := mustList(t, h)
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, list[0].ID))
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, list[1].ID))
	assert.False(t, banner(h, "over_limit"), "10 of 10: the over-limit banner is gone")
	assert.True(t, banner(h, "limit_reached"))
}

// L-77: a larger renewal raises the limit at once.
func TestL77LargerRenewal(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	h.installLicense("LIC-10", 10, 365)
	addN(h, admin, 1, 3)
	h.clock.Advance(time.Hour)
	h.installLicense("LIC-100", 100, 400)
	assert.Equal(t, 100, h.lic.Snapshot().Eval.MaxTargets)
	addN(h, admin, 4, 20)
	assert.Equal(t, 23, liveTargets(h))
}

// L-78: a license smaller than the evaluation's targets behaves like L-75.
func TestL78LicenseBelowEvaluationTargets(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	addN(h, admin, 1, 5)
	h.installLicense("LIC-3", 3, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	assert.True(t, banner(h, "over_limit"))
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-06", Type: "linux", Host: "web-06.example.com"})
	require.ErrorIs(t, err, license.ErrTargetLimit)
	assert.Equal(t, 5, liveTargets(h))
}

// L-26 (service part): in lock adding a target is refused with ErrLocked and audited.
func TestAddInLockIsRefused(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	h.clock.Advance(31 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(h.ctx))
	_, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-01", Type: "linux", Host: "web-01.example.com"})
	require.True(t, errors.Is(err, license.ErrLocked), "%v", err)
	assert.Equal(t, 0, liveTargets(h))
	assert.Equal(t, []map[string]string{{"reason": "locked", "name": "web-01"}}, h.auditDetails("target.add.denied_license"))
}

// tickProbe records the context of the license evaluation that follows a committed change.
type tickProbe struct {
	inventory.LicenseGate
	mu       sync.Mutex
	deadline time.Time
	err      error
}

func (p *tickProbe) Tick(ctx context.Context) error {
	p.mu.Lock()
	p.deadline, _ = ctx.Deadline()
	p.err = ctx.Err()
	p.mu.Unlock()
	return p.LicenseGate.Tick(ctx)
}

// The evaluation after a committed add or delete outlives the request (a client that disconnects
// does not skip it) but is bounded: it cannot hang the request's goroutine forever.
func TestLicenseRefreshAfterAChangeIsDetachedButBounded(t *testing.T) {
	probe := &tickProbe{}
	h := newHarness(t, func(c *inventory.Config) { probe.LicenseGate = c.License; c.License = probe })
	admin := h.user("ada", rbac.Admin, "")
	tg := h.add(admin, "web-01", "web-01.example.com")
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, tg.ID))
	probe.mu.Lock()
	defer probe.mu.Unlock()
	require.False(t, probe.deadline.IsZero(), "the evaluation has a deadline")
	assert.WithinDuration(t, time.Now().Add(30*time.Second), probe.deadline, 5*time.Second)
	assert.NoError(t, probe.err)
}
