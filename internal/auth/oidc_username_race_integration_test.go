//go:build integration

package auth_test

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/rbac"
)

// waitForBlockedInsert waits until some session waits for another transaction (the unique index of users.username
// makes an INSERT of a name that an open transaction just inserted wait for that transaction).
func (e *env) waitForBlockedInsert(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		var n int
		require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM pg_locks WHERE locktype = 'transactionid' AND NOT granted").Scan(&n))
		return n > 0
	}, 5*time.Second, 5*time.Millisecond)
}

// Review M-2: the per-identity lock does not cover the user name. A first SSO sign-in whose free name is taken by
// another transaction between the check and the INSERT gets the next free name instead of a 500.
func TestSignInOIDCRetriesAUserNameTakenMeanwhile(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	other, err := e.db.Owner.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = other.Rollback(e.ctx) }()
	_, err = other.Exec(e.ctx, `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'jsmith', 'J. Smith', 'x', 'operator', now(), now())`, uuid.Must(uuid.NewV7()))
	require.NoError(t, err)

	type result struct {
		userID uuid.UUID
		err    error
	}
	done := make(chan result, 1)
	go func() {
		res, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "jsmith", ""), rbac.Operator, meta)
		if err != nil {
			done <- result{err: err}
			return
		}
		done <- result{userID: e.principal(t, res.Token).UserID}
	}()
	e.waitForBlockedInsert(t) // the sign-in saw "jsmith" free and waits on the other transaction's row
	require.NoError(t, other.Commit(e.ctx))
	r := <-done
	require.NoError(t, r.err)
	u, err := e.svc.GetUser(e.ctx, r.userID)
	require.NoError(t, err)
	assert.Equal(t, "jsmith-2", u.Username)
}

// Review M-2: two people with the same short name at two providers (or one provider) sign in for the first time at
// the same moment: every sign-in succeeds, each with its own name.
func TestConcurrentFirstSSOSignInsWithOneUserName(t *testing.T) {
	e := newEnv(t)
	p1, p2 := e.provider(t), e.provider(t)
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := p1
			if i%2 == 1 {
				p = p2
			}
			_, errs[i] = e.svc.SignInOIDC(e.ctx, identity(p, fmt.Sprintf("sub-%d", i), "jsmith", ""), rbac.Operator, meta)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "sign-in %d", i)
	}
	rows, err := e.db.Owner.Query(e.ctx, `SELECT username::text FROM users WHERE auth_source = 'oidc'`)
	require.NoError(t, err)
	var names []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		names = append(names, s)
	}
	require.NoError(t, rows.Err())
	sort.Strings(names)
	want := []string{"jsmith"}
	for i := 2; i <= n; i++ {
		want = append(want, fmt.Sprintf("jsmith-%d", i))
	}
	sort.Strings(want)
	assert.Equal(t, want, names)
}
