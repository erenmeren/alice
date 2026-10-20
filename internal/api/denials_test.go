package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/rbac"
)

func denialEvent(user string) audit.Event {
	return audit.Event{Actor: audit.Actor{Type: audit.ActorUser, Name: user, RequestID: "req-1"}, Action: "authz.denied",
		Result: audit.Denied, Details: map[string]string{"permission": "audit.read", "method": "GET", "path": "/api/v1/audit", "reason": "permission"}}
}

// AUD-06: the first refusal of a key is written at once; repeats within the window are left out;
// the window's end appends one summary row with the count; another key has its own window.
func TestDenialCoalescer(t *testing.T) {
	start := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	clk := clock.NewFake(start)
	c := newDenialCoalescer(clk)
	_, write, sums := c.admit("u:1|audit.read|permission|GET /api/v1/audit", denialEvent("olga"))
	assert.True(t, write, "the first refusal is written at once")
	assert.Empty(t, sums)
	for range 99 {
		clk.Advance(time.Second)
		_, write, sums = c.admit("u:1|audit.read|permission|GET /api/v1/audit", denialEvent("olga"))
		assert.False(t, write)
		assert.Empty(t, sums)
	}
	_, write, _ = c.admit("u:2|audit.read|permission|GET /api/v1/audit", denialEvent("omar"))
	assert.True(t, write, "another subject has its own window")
	_, write, _ = c.admit("u:1|audit.read|permission|POST /api/v1/audit/verify", denialEvent("olga"))
	assert.True(t, write, "another route has its own window (S3)")
	_, write, _ = c.admit("u:1|audit.read|stepup|GET /api/v1/audit", denialEvent("olga"))
	assert.True(t, write, "another reason has its own window")

	clk.Set(start.Add(denialWindow))
	_, write, sums = c.admit("u:1|audit.read|permission|GET /api/v1/audit", denialEvent("olga"))
	assert.True(t, write, "after the window the next refusal is written again")
	require.Len(t, sums, 1, "and the ended window's count is appended first")
	sm := sums[0]
	assert.Equal(t, "authz.denied", sm.Action)
	assert.Equal(t, audit.Denied, sm.Result)
	assert.Equal(t, "olga", sm.Actor.Name)
	assert.Empty(t, sm.Actor.RequestID, "a summary stands for many requests")
	assert.Equal(t, map[string]string{"permission": "audit.read", "method": "GET", "path": "/api/v1/audit", "reason": "permission",
		"suppressed_count": "99", "window_start": "2026-10-04T09:00:00Z", "window_end": "2026-10-04T09:10:00Z"}, sm.Details)
	assert.Equal(t, "req-1", denialEvent("olga").Actor.RequestID, "the template is not changed")
}

func TestDenialCoalescerSweepAndDrain(t *testing.T) {
	start := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	clk := clock.NewFake(start)
	c := newDenialCoalescer(clk)
	c.admit("a", denialEvent("a"))
	c.admit("a", denialEvent("a"))
	c.admit("a", denialEvent("a"))
	c.admit("quiet", denialEvent("quiet")) // nothing left out: no summary
	clk.Advance(5 * time.Minute)
	c.admit("b", denialEvent("b"))
	c.admit("b", denialEvent("b"))

	assert.Empty(t, c.sweep(), "no window has ended yet")
	clk.Set(start.Add(denialWindow))
	sums := c.sweep()
	require.Len(t, sums, 1)
	assert.Equal(t, "2", sums[0].Details["suppressed_count"])
	assert.Equal(t, "2026-10-04T09:10:00Z", sums[0].Details["window_end"])
	assert.Equal(t, 1, c.len(), "ended windows are dropped, the open one is kept")

	clk.Advance(time.Minute)
	sums = c.drain()
	require.Len(t, sums, 1)
	assert.Equal(t, "1", sums[0].Details["suppressed_count"])
	assert.Equal(t, "2026-10-04T09:05:00Z", sums[0].Details["window_start"])
	assert.Equal(t, "2026-10-04T09:11:00Z", sums[0].Details["window_end"], "an open window drained at shutdown ends now")
	assert.Zero(t, c.len())
}

// The coalescer's memory is bounded, and the bound never costs a row: a new key is always written,
// and a window dropped to make room has its count appended at once.
func TestDenialCoalescerIsBoundedAndNeverDropsARow(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC))
	c := newDenialCoalescer(clk)
	c.admit("oldest", denialEvent("oldest"))
	c.admit("oldest", denialEvent("oldest"))
	for i := range maxDenialKeys - 1 {
		clk.Advance(time.Millisecond)
		_, write, sums := c.admit(fmt.Sprintf("u:%d|p|r|GET /x", i), denialEvent("x"))
		require.True(t, write)
		require.Empty(t, sums)
	}
	require.Equal(t, maxDenialKeys, c.len())
	clk.Advance(time.Millisecond)
	_, write, sums := c.admit("newcomer", denialEvent("newcomer"))
	assert.True(t, write, "a new key at the cap is still written")
	require.Len(t, sums, 1, "the oldest window makes room and its count is written early")
	assert.Equal(t, "oldest", sums[0].Actor.Name)
	assert.Equal(t, "1", sums[0].Details["suppressed_count"])
	assert.LessOrEqual(t, c.len(), maxDenialKeys)
	_, write, _ = c.admit("oldest", denialEvent("oldest"))
	assert.True(t, write, "the evicted key starts a new window with a row")
}

func TestDenialCoalescerReleaseWritesAgain(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC))
	c := newDenialCoalescer(clk)
	gen, write, _ := c.admit("k", denialEvent("k"))
	require.True(t, write)
	c.admit("k", denialEvent("k"))
	sums := c.release("k", gen)
	require.Len(t, sums, 1, "refusals left out behind the lost row are still counted")
	assert.Equal(t, "1", sums[0].Details["suppressed_count"])
	_, write, _ = c.admit("k", denialEvent("k"))
	assert.True(t, write, "after a failed first row the next refusal is written")
	assert.Empty(t, c.release("k", gen), "a stale release does not drop the new window")
	assert.Equal(t, 1, c.len())
}

func auditGetHandler(d Deps) (http.Handler, *Server) {
	s := newServer(d)
	srv := &Server{s: s}
	srv.h = s.handler([]route{
		{method: http.MethodGet, pattern: "/api/v1/audit", scope: scopeAny, perm: rbac.AuditRead, handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}},
		{method: http.MethodPost, pattern: "/api/v1/audit/verify", scope: scopeAny, perm: rbac.AuditRead, lic: license.ClassAlways,
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }},
	})
	return srv.h, srv
}

func eventsWith(fa *fakeAudit, action, key string) []audit.Event {
	var out []audit.Event
	for _, e := range fa.Events() {
		if e.Action == action && (key == "" || e.Details[key] != "") {
			out = append(out, e)
		}
	}
	return out
}

// AUD-06 through the guard: an Operator repeating a refused request gets one authz.denied row per
// window and route; the summary row follows from the sweep on the injected clock.
func TestGuardCoalescesRepeatedRefusals(t *testing.T) {
	d := testDeps(t, nil)
	clk := d.Clock.(*clock.Fake)
	fa := d.Audit.(*fakeAudit)
	h, srv := auditGetHandler(d)
	for range 40 {
		require.Equal(t, http.StatusForbidden, call(h, http.MethodGet, "/api/v1/audit", "operator", "").Code)
	}
	require.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/audit/verify", "operator", "").Code)
	require.Equal(t, http.StatusForbidden, call(h, http.MethodGet, "/api/v1/audit", "alice_operate_operator", "").Code)
	rows := eventsWith(fa, "authz.denied", "")
	require.Len(t, rows, 3, "one row per route and subject")
	assert.Equal(t, "/api/v1/audit", rows[0].Details["path"])
	assert.Equal(t, "/api/v1/audit/verify", rows[1].Details["path"])
	assert.Equal(t, "api_token", string(rows[2].Actor.Type))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.RunDenialSummaries(ctx); close(done) }()
	clk.BlockUntil(0, 1)
	clk.Advance(denialWindow)
	require.Eventually(t, func() bool { return len(eventsWith(fa, "authz.denied", "suppressed_count")) == 1 }, 5*time.Second, time.Millisecond)
	cancel()
	<-done
	sm := eventsWith(fa, "authz.denied", "suppressed_count")[0]
	assert.Equal(t, "39", sm.Details["suppressed_count"])
	assert.Equal(t, "GET", sm.Details["method"])
	assert.Equal(t, "/api/v1/audit", sm.Details["path"])
	assert.Equal(t, "permission", sm.Details["reason"])
	assert.Equal(t, operatorID, sm.Actor.ID)
	assert.Len(t, eventsWith(fa, "authz.denied", ""), 4, "the summary is appended; no row is changed")
}

// A license refusal is coalesced the same way, keyed on the class instead of the permission.
func TestGuardCoalescesLicenseRefusals(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	fa := d.Audit.(*fakeAudit)
	fl.set(license.ErrLocked)
	h := gatedHandler(d, license.ClassChange)
	for range 5 {
		require.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/targets", "admin", `{}`).Code)
	}
	assert.Equal(t, 1, fa.Count("request.denied_license"))
	fl.set(license.ErrUnverified)
	require.Equal(t, http.StatusServiceUnavailable, call(h, http.MethodPost, "/api/v1/targets", "admin", `{}`).Code)
	assert.Equal(t, 2, fa.Count("request.denied_license"), "another reason has its own row")
}

// Summaries of windows still open are written at shutdown (FlushDenials), best effort within ctx.
func TestFlushDenialsWritesOpenWindows(t *testing.T) {
	d := testDeps(t, nil)
	fa := d.Audit.(*fakeAudit)
	h, srv := auditGetHandler(d)
	for range 3 {
		call(h, http.MethodGet, "/api/v1/audit", "operator", "")
	}
	call(h, http.MethodGet, "/api/v1/audit", "auditor", "") // allowed: no row at all
	srv.FlushDenials(context.Background())
	sums := eventsWith(fa, "authz.denied", "suppressed_count")
	require.Len(t, sums, 1)
	assert.Equal(t, "2", sums[0].Details["suppressed_count"])
	srv.FlushDenials(context.Background())
	assert.Len(t, eventsWith(fa, "authz.denied", "suppressed_count"), 1, "a flushed window is not written twice")

	var logs bytes.Buffer
	d2 := testDeps(t, nil)
	d2.Log = slog.New(slog.NewTextHandler(&logs, nil))
	h2, srv2 := auditGetHandler(d2)
	call(h2, http.MethodGet, "/api/v1/audit", "operator", "")
	call(h2, http.MethodGet, "/api/v1/audit", "operator", "")
	done, cancel := context.WithCancel(context.Background())
	cancel()
	srv2.FlushDenials(done)
	assert.Contains(t, logs.String(), "denial summaries not written")
	assert.Contains(t, logs.String(), "count=1")
}

// AUD-15: the refusal's row is written on a context the client's disconnect does not end, bounded
// by auditWriteTimeout.
func TestRefusalIsAuditedAfterTheClientLeft(t *testing.T) {
	d := testDeps(t, nil)
	fa := d.Audit.(*fakeAudit)
	var mu sync.Mutex
	var ctxErr error
	var deadline time.Duration
	fa.WriteFn = func(ctx context.Context, _ audit.Event) error {
		mu.Lock()
		defer mu.Unlock()
		ctxErr = ctx.Err()
		dl, ok := ctx.Deadline()
		require.True(t, ok, "the detached write has its own deadline")
		deadline = time.Until(dl)
		return nil
	}
	h, _ := auditGetHandler(d)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client has gone before the guard writes
	req := as(httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/audit", nil), "operator")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, 1, fa.Count("authz.denied"))
	mu.Lock()
	defer mu.Unlock()
	assert.NoError(t, ctxErr)
	assert.LessOrEqual(t, deadline, auditWriteTimeout)
	assert.Positive(t, deadline)
}

// A refusal whose row cannot be written is still refused; the failure is logged with fixed labels,
// and the next identical refusal tries to write a row again (the first row is never left out).
func TestFailedRefusalAuditStillRefusesAndRetries(t *testing.T) {
	var logs bytes.Buffer
	d := testDeps(t, nil)
	d.Log = slog.New(slog.NewTextHandler(&logs, nil))
	fa := d.Audit.(*fakeAudit)
	attempts := 0
	fail := true
	fa.WriteFn = func(context.Context, audit.Event) error {
		attempts++
		if fail {
			return errors.New("database is gone: secret detail")
		}
		return nil
	}
	h, _ := auditGetHandler(d)
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodGet, "/api/v1/audit", "operator", "").Code)
	assert.Contains(t, logs.String(), "audit write failed")
	assert.Contains(t, logs.String(), "error_type=")
	assert.Contains(t, logs.String(), "actor_id="+operatorID.String(), "the log names who was refused (M2)")
	assert.Contains(t, logs.String(), "route=/api/v1/audit", "and the route template")
	assert.NotContains(t, logs.String(), "secret detail")
	fail = false
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodGet, "/api/v1/audit", "operator", "").Code)
	assert.Equal(t, 2, attempts, "the second refusal is written because the first row was lost")
	assert.Equal(t, 1, fa.Count("authz.denied"))
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodGet, "/api/v1/audit", "operator", "").Code)
	assert.Equal(t, 2, attempts, "then the window holds")
}

// I2: all API tokens of one owner are one subject (tokens are unlimited per user), apart from the
// owner's sessions; each first row names its token, and the summary counts the tokens. M1: the
// summary counts the client addresses and names up to three of them.
func TestTokensOfOneOwnerShareAWindow(t *testing.T) {
	d := testDeps(t, nil)
	fa := d.Audit.(*fakeAudit)
	first, second := uuid.New(), uuid.New()
	d.Auth.(*fakeAuth).AuthenticateTokenFn = func(_ context.Context, b string) (auth.Principal, error) {
		id := first
		if b == "alice_second" {
			id = second
		}
		return auth.Principal{Kind: rbac.APIToken, UserID: operatorID, Username: "operator", Role: rbac.Operator, TokenID: id,
			Scope: rbac.ScopeOperate}, nil
	}
	h, srv := auditGetHandler(d)
	for i, tok := range []string{"alice_first", "alice_second", "alice_first", "alice_second", "alice_second"} {
		req := as(httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil), tok)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:4000", 10+i)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code)
	}
	rows := eventsWith(fa, "authz.denied", "")
	require.Len(t, rows, 1, "two tokens of one owner: one row")
	assert.Equal(t, first.String(), rows[0].Details["token_id"], "the first row names its token")
	assert.Equal(t, audit.ActorToken, rows[0].Actor.Type)

	require.Equal(t, http.StatusForbidden, call(h, http.MethodGet, "/api/v1/audit", "operator", "").Code)
	assert.Len(t, eventsWith(fa, "authz.denied", ""), 2, "the owner's sessions are another subject")

	srv.FlushDenials(context.Background())
	sums := eventsWith(fa, "authz.denied", "suppressed_count")
	require.Len(t, sums, 1)
	sm := sums[0]
	assert.Equal(t, "4", sm.Details["suppressed_count"])
	assert.Equal(t, "2", sm.Details["distinct_token_count"])
	assert.Equal(t, "5", sm.Details["distinct_ip_count"])
	assert.Equal(t, "198.51.100.10,198.51.100.11,198.51.100.12", sm.Details["ip_samples"])
	assert.NotContains(t, sm.Details, "token_id", "the summary stands for several tokens")
	assert.NotContains(t, sm.Details, "distinct_object_count")
}

func TestDistinctSetIsBounded(t *testing.T) {
	var d distinctSet
	seed := maphash.MakeSeed()
	for i := range maxDistinct + 10 {
		d.add(seed, strconv.Itoa(i))
		d.add(seed, strconv.Itoa(i))
	}
	assert.Len(t, d.seen, maxDistinct)
	assert.Equal(t, strconv.Itoa(maxDistinct)+"+", d.count())
}

// The busy refusal of a chain scan is keyed and labelled by exportRoute / verifyRoute: they must
// name exactly the operations of the route table (method, pattern, permission), or a refusal would
// be recorded under a route that does not exist.
func TestChainScanRoutesMatchTheRouteTable(t *testing.T) {
	s := &server{}
	for _, want := range []route{exportRoute, verifyRoute} {
		var found []route
		for _, rt := range s.apiRoutes() {
			if rt.method == want.method && rt.pattern == want.pattern {
				found = append(found, rt)
			}
		}
		require.Len(t, found, 1, "%s %s in the route table", want.method, want.pattern)
		assert.Equal(t, want.perm, found[0].perm, "%s %s permission", want.method, want.pattern)
	}
	assert.Equal(t, 64, maxDistinct, "distinct counts read 64+ beyond the bound")
}
