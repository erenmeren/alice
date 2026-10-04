//go:build integration

package auth_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/rbac"
)

// Outcomes of a pair of parallel sign-ins, as seen from inside the first one's Argon2 run.
const (
	pairQueued     = "queued"     // the second attempt waits for the name lock while the first hashes
	pairOverlapped = "overlapped" // the second attempt hashes at the same time as the first
	pairUndecided  = "undecided"  // neither within the guard time (a broken test, not a result)
)

// nameLockSQL counts the per-name sign-in locks (pg_advisory_xact_lock(int4, int4) in the
// sign-in namespace) that are granted ($2 = true) or waited for ($2 = false).
const nameLockSQL = `SELECT count(*) FROM pg_locks
WHERE locktype = 'advisory' AND classid = $1::oid AND objsubid = 2 AND granted = $2`

// pairProbe watches the Argon2 runs of one pair of parallel sign-ins. In the first run it
// waits until the second attempt either starts hashing too (the runs overlap) or is seen
// queueing for the name lock (they are serialized), so the result is structural and does
// not depend on how long a hash takes.
type pairProbe struct {
	e       *env
	first   atomic.Bool
	starts  atomic.Int32 // Argon2 runs started; never decremented, so a short run is not missed
	outcome chan string

	mu       sync.Mutex
	ops      []string
	held     []int // granted name locks seen at the start of each run
	rowHeld  []bool
	accounts string // the account row checked for a held row lock ("" for none)
	single   bool   // one attempt only: nothing to wait for
	errs     []error
}

func newPairProbe(e *env, account string) *pairProbe {
	return &pairProbe{e: e, outcome: make(chan string, 1), accounts: account}
}

func (p *pairProbe) count(granted bool) (int, error) {
	var n int
	err := p.e.db.Owner.QueryRow(p.e.ctx, nameLockSQL, int64(auth.LoginNameLockNamespace), granted).Scan(&n)
	return n, err
}

// rowLocked reports whether some transaction holds the account's row lock.
func (p *pairProbe) rowLocked() (bool, error) {
	tx, err := p.e.db.Owner.Begin(p.e.ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(p.e.ctx) }()
	_, err = tx.Exec(p.e.ctx, "SELECT 1 FROM users WHERE username = $1 FOR UPDATE NOWAIT", p.accounts)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return true, nil
	}
	return false, err
}

func (p *pairProbe) hook(op string) {
	if op == auth.HashOpHash {
		return // a new hash (rehash after a correct password) is not part of a failed attempt
	}
	p.starts.Add(1)
	held, err := p.count(true)
	var row bool
	if err == nil && p.accounts != "" {
		row, err = p.rowLocked()
	}
	p.mu.Lock()
	p.ops = append(p.ops, op)
	p.held = append(p.held, held)
	p.rowHeld = append(p.rowHeld, row)
	if err != nil {
		p.errs = append(p.errs, err)
	}
	p.mu.Unlock()
	if !p.first.CompareAndSwap(false, true) || p.single {
		return
	}
	guard := time.Now().Add(10 * time.Second) // a deadlock guard, not a timing threshold
	for time.Now().Before(guard) {
		// The first run is still going (its hook has not returned), so any other start overlaps it.
		if p.starts.Load() > 1 {
			p.outcome <- pairOverlapped
			return
		}
		if n, err := p.count(false); err == nil && n > 0 {
			p.outcome <- pairQueued
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	p.outcome <- pairUndecided
}

// TestParallelSignInsForOneNameQueueAlikeWhetherOrNotItExists is the audit's AUD-11 PoC made
// structural: two parallel sign-ins with one name must run their Argon2 work one after the
// other, under the name lock, for an unknown name exactly as for a real one, so a pair of
// requests takes as long (about 2T) whether or not the name exists. Before the fix the dummy
// check of an unknown name ran after the lock was released and the pair overlapped (about T).
// Every attempt runs exactly one Argon2 check and gets the generic answer.
func TestParallelSignInsForOneNameQueueAlikeWhetherOrNotItExists(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	e.insertUser(t, "pending", rbac.Operator, adminPassword) // TOTP not enrolled yet
	gone := e.insertUser(t, "gone", rbac.Operator, adminPassword)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE users SET disabled_at = $2 WHERE id = $1", gone, e.clk.Now())
	require.NoError(t, err)
	var usersBefore int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM users").Scan(&usersBefore))

	block := func(name string) func() {
		return func() {
			_, err := e.db.Owner.Exec(e.ctx, "UPDATE users SET failed_logins = 7, locked_until = $2 WHERE username = $1", name, e.clk.Now().Add(time.Minute))
			require.NoError(t, err)
		}
	}
	cases := []struct {
		label, typed, account, op string
		setup                     func()
	}{
		{label: "unknown name", typed: "ghost", op: auth.HashOpDummy},
		{label: "unknown name typed in another case", typed: "GHOST", op: auth.HashOpDummy},
		{label: "unknown name that is not ASCII", typed: "ghöst", op: auth.HashOpDummy},
		{label: "real name, wrong password", typed: "admin", account: "admin", op: auth.HashOpVerify},
		{label: "real name typed in another case", typed: "Admin", account: "admin", op: auth.HashOpVerify},
		{label: "real name in a delay or lockout", typed: "admin", account: "admin", op: auth.HashOpDummy, setup: block("admin")},
		{label: "user without TOTP yet", typed: "pending", account: "pending", op: auth.HashOpVerify},
		{label: "disabled user", typed: "gone", account: "gone", op: auth.HashOpVerify},
	}
	for _, c := range cases {
		e.setFailures(t, "admin", 0)
		if c.setup != nil {
			c.setup()
		}
		probe := newPairProbe(e, c.account)
		auth.SetHashHook(e.hasher, probe.hook)
		errs := parallel(2, func() error {
			_, err := e.svc.Login(e.ctx, c.typed, "definitely not it", meta)
			return err
		})
		auth.SetHashHook(e.hasher, nil)
		for _, err := range errs {
			require.ErrorIs(t, err, auth.ErrInvalidCredentials, c.label)
		}
		assert.Equal(t, pairQueued, <-probe.outcome, "%s: the second attempt waits for the name lock while the first hashes", c.label)
		assert.Empty(t, probe.errs, c.label)
		assert.Equal(t, []string{c.op, c.op}, probe.ops, "%s: one Argon2 run per attempt", c.label)
		assert.Equal(t, []int{1, 1}, probe.held, "%s: every Argon2 run holds the name lock", c.label)
		if c.account != "" {
			assert.Equal(t, []bool{true, true}, probe.rowHeld, "%s: and the account's row lock", c.label)
		}
	}

	// An unknown name never gains a row, a counter or a lockout answer, however often it is tried.
	for range auth.LockThreshold + 2 {
		_, err := e.svc.Login(e.ctx, "ghost", "definitely not it", meta)
		require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	}
	var usersAfter int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM users").Scan(&usersAfter))
	assert.Equal(t, usersBefore, usersAfter)
	assert.Zero(t, e.countAction(t, "auth.lockout", "failure"))
}

// TestBlockedPasswordChangeChecksUnderTheAccountLock: a password change on a delayed or locked
// account runs its dummy check while it holds the account's row lock, like the real check.
func TestBlockedPasswordChangeChecksUnderTheAccountLock(t *testing.T) {
	e := newEnv(t)
	_, res := e.bootstrap(t)
	p := e.principal(t, res.Token)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE users SET failed_logins = 7, locked_until = $1 WHERE username = 'admin'", e.clk.Now().Add(time.Minute))
	require.NoError(t, err)
	probe := newPairProbe(e, "admin")
	probe.single = true
	auth.SetHashHook(e.hasher, probe.hook)
	_, err = e.svc.ChangePassword(e.ctx, p, adminPassword, "another long passphrase", meta)
	auth.SetHashHook(e.hasher, nil)
	require.ErrorIs(t, err, auth.ErrCurrentPasswordInvalid)
	assert.Empty(t, probe.errs)
	assert.Equal(t, []string{auth.HashOpDummy}, probe.ops)
	assert.Equal(t, []bool{true}, probe.rowHeld)
}
