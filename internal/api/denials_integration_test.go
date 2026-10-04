//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/db"
)

// AUD-06: an Operator's repeated refused requests add one audit row per window, whatever the
// number of sessions; the window's count is appended as one more row (never an update), and the
// chain still verifies and still detects a change of that row.
func TestRepeatedDenialsAreCoalesced(t *testing.T) {
	s, olga := installedWithOperator(t)
	before := s.countWhere("audit_log", "action = 'authz.denied'")
	for range 2 { // two sessions of the same user: the rate limit is per session, the window per person
		op := s.freshClient()
		s.signIn(op, olga)
		for range 290 {
			requireError(t, op.do(http.MethodGet, "/api/v1/audit", nil), http.StatusForbidden, "ALC-AUTH-0002")
		}
	}
	assert.Equal(t, before+1, s.countWhere("audit_log", "action = 'authz.denied'"), "580 refusals, one row")

	op := s.freshClient()
	s.signIn(op, olga)
	requireError(t, op.do(http.MethodPost, "/api/v1/audit/verify", nil), http.StatusForbidden, "ALC-AUTH-0002")
	assert.Equal(t, before+2, s.countWhere("audit_log", "action = 'authz.denied'"), "another route has its own row (S3)")

	s.clock.Advance(10 * time.Minute)
	requireError(t, op.do(http.MethodGet, "/api/v1/audit", nil), http.StatusForbidden, "ALC-AUTH-0002")
	assert.Equal(t, before+4, s.countWhere("audit_log", "action = 'authz.denied'"), "the summary, then the new window's row")
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'authz.denied' AND details->>'suppressed_count' = '579'"+
		" AND details->>'path' = '/api/v1/audit' AND details->>'method' = 'GET' AND details->>'reason' = 'permission'"+
		" AND actor_name = 'olga' AND ip IS NULL AND request_id = ''"))
	var summarySeq, firstSeq int64
	require.NoError(t, s.db.Owner.QueryRow(context.Background(),
		"SELECT seq FROM audit_log WHERE details ? 'suppressed_count'").Scan(&summarySeq))
	require.NoError(t, s.db.Owner.QueryRow(context.Background(),
		"SELECT max(seq) FROM audit_log WHERE action = 'authz.denied' AND NOT details ? 'suppressed_count'").Scan(&firstSeq))
	assert.Less(t, summarySeq, firstSeq, "the ended window's count comes before the new window's row")

	// The open window of the verify route had nothing left out; the new one of GET /audit gets a
	// count at shutdown.
	requireError(t, op.do(http.MethodGet, "/api/v1/audit", nil), http.StatusForbidden, "ALC-AUTH-0002")
	s.api.FlushDenials(context.Background())
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'authz.denied' AND details->>'suppressed_count' = '1'"))

	rep, err := s.auditSvc.VerifyReadOnly(context.Background())
	require.NoError(t, err)
	require.True(t, rep.Intact, "summary rows are ordinary chain links")

	// Tamper evidence is unchanged: lowering a count is detected by the full recomputation.
	ctx := context.Background()
	require.NoError(t, db.InTx(ctx, s.db.Owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "ALTER TABLE audit_log DISABLE TRIGGER USER"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE audit_log SET details = jsonb_set(details, '{suppressed_count}', '"3"') WHERE seq = $1`, summarySeq); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "ALTER TABLE audit_log ENABLE TRIGGER USER")
		return err
	}))
	rep, err = s.auditSvc.VerifyReadOnly(ctx)
	require.NoError(t, err)
	assert.False(t, rep.Intact)
	assert.Equal(t, summarySeq, rep.FirstBadSeq)
	assert.Equal(t, audit.ProblemHashMismatch, rep.Problem)
}

// cancelAfterAuth stands for a client that drops the connection right after the session lookup:
// the request context is cancelled before the guard writes authz.denied. Both lookups are
// overridden, so whichever the guard uses cancels.
type cancelAfterAuth struct {
	*auth.Service
	cancel *context.CancelFunc
}

func (c cancelAfterAuth) Authenticate(ctx context.Context, tok string) (auth.Principal, error) {
	p, err := c.Service.Authenticate(ctx, tok)
	if *c.cancel != nil {
		(*c.cancel)()
	}
	return p, err
}

func (c cancelAfterAuth) AuthenticatePassive(ctx context.Context, tok string) (auth.Principal, error) {
	p, err := c.Service.AuthenticatePassive(ctx, tok)
	if *c.cancel != nil {
		(*c.cancel)()
	}
	return p, err
}

// AUD-15: a refusal is recorded even when the client disconnects before the audit write.
func TestDenialIsRecordedWhenTheClientDisconnects(t *testing.T) {
	s, olga := installedWithOperator(t)
	op := s.freshClient()
	s.signIn(op, olga)

	before := s.countWhere("audit_log", "action = 'authz.denied'")
	requireError(t, op.do(http.MethodGet, "/api/v1/audit", nil), http.StatusForbidden, "ALC-AUTH-0002")
	require.Equal(t, before+1, s.countWhere("audit_log", "action = 'authz.denied'"), "baseline: a denial is audited")

	// A rebuilt handler is a new coalescer (a new process), so the same refusal is due a row again.
	var cancel context.CancelFunc
	var reqCtx context.Context
	deps := s.deps()
	deps.Auth = cancelAfterAuth{Service: s.auth, cancel: &cancel}
	s.handler = New(deps).Handler()
	logged := len(s.logs.String())
	// Unmarked (no X-Alice-Activity): a marked read records the activity first, and a request whose
	// context ended there is dropped before any decision, with no answer to anyone (AUD-01).
	rec := op.do(http.MethodGet, "/api/v1/audit", nil, withoutHeader(activityHeader), func(r *http.Request) {
		ctx, c := context.WithCancel(r.Context())
		cancel, reqCtx = c, ctx
		*r = *r.WithContext(ctx)
	})
	require.NotNil(t, reqCtx)
	require.Error(t, reqCtx.Err(), "the request's context ended before the audit write")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, before+2, s.countWhere("audit_log", "action = 'authz.denied'"), "the second denial is recorded")
	assert.NotContains(t, s.logs.String()[logged:], "audit write failed")
}

// AUD-06 (I1): asking for other users' token lists with many user IDs is one authz.denied row per
// window, never a lookup, and the summary counts the IDs asked for.
func TestForeignTokenListEnumerationIsCoalesced(t *testing.T) {
	s, olga := installedWithOperator(t)
	op := s.freshClient()
	s.signIn(op, olga)
	before := s.countWhere("audit_log", "action = 'authz.denied'")
	for range 50 {
		requireError(t, op.do(http.MethodGet, "/api/v1/tokens?user_id="+uuid.NewString(), nil), http.StatusNotFound, "ALC-SYS-0001")
	}
	assert.Equal(t, before+1, s.countWhere("audit_log", "action = 'authz.denied'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'authz.denied' AND details->>'reason' = 'not_owner' AND object_type = 'user'"))
	s.api.FlushDenials(context.Background())
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'authz.denied' AND details->>'suppressed_count' = '49'"+
		" AND details->>'distinct_object_count' = '50' AND details->>'distinct_ip_count' = '1' AND details->>'ip_samples' <> ''"+
		" AND details->>'path' = '/api/v1/tokens' AND object_id = ''"))
	rep, err := s.auditSvc.VerifyReadOnly(context.Background())
	require.NoError(t, err)
	assert.True(t, rep.Intact)
}
