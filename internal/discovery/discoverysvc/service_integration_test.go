//go:build integration

package discoverysvc

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/discovery"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var t0 = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)

type allowAll struct{}

func (allowAll) Allow(license.Class) error { return nil }

// fakeResolver answers the names it knows and records every lookup; block makes a lookup wait for its context.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	block   bool
	asked   []string
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.asked = append(f.asked, host)
	a, ok := f.answers[host]
	block := f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if !ok {
		return nil, errors.New("no such host")
	}
	return a, nil
}

func (f *fakeResolver) lookups() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

type world struct {
	t     *testing.T
	ctx   context.Context
	db    *pgtest.DB
	clock *clock.Fake
	res   *fakeResolver
	svc   *Service
	admin Actor
	op    Actor
	queue *jobs.Queue
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	w := &world{t: t, ctx: ctx, db: pgtest.New(t), clock: clock.NewFake(t0),
		res: &fakeResolver{answers: map[string][]netip.Addr{"web.example": {netip.MustParseAddr("10.0.0.80")}}}}
	keyring, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	al := audit.New(w.clock)
	w.queue = jobs.NewQueue(jobs.QueueConfig{Pool: w.db.App, Keyring: keyring, Audit: al, Clock: w.clock, Gate: allowAll{}})
	w.svc = New(Config{Pool: w.db.App, Audit: al, Queue: w.queue, Clock: w.clock, Resolver: w.res})
	w.admin = w.user("ada", "admin")
	w.op = w.user("otto", "operator")
	w.allow("10.0.0.0/16")
	return w
}

func (w *world) user(name, role string) Actor {
	w.t.Helper()
	id := uuid.New()
	w.exec(`INSERT INTO users (id, username, email, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, $2, $5, $6, 'x', $3, $4, $4)`, id, name, role, t0, name+"@example.test", name)
	return Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: id, Name: name, RequestID: "req-" + name}, UserID: id, Role: role}
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	_, err := w.db.Owner.Exec(w.ctx, sql, args...)
	require.NoError(w.t, err)
}

func (w *world) count(sql string, args ...any) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, sql, args...).Scan(&n))
	return n
}

func (w *world) allow(networks ...string) {
	w.t.Helper()
	_, err := w.svc.SaveSettings(w.ctx, w.admin, Settings{AllowedNetworks: networks, RetentionDays: 90})
	require.NoError(w.t, err)
}

// auditRows lists the audit rows of an action: their actor name, object id and details.
type auditRow struct {
	actor, object, result, requestID string
	details                          map[string]string
}

func (w *world) audits(action string) []auditRow {
	w.t.Helper()
	rows, err := w.db.Owner.Query(w.ctx, `SELECT actor_name, object_id, result, request_id, details FROM audit_log WHERE action = $1 ORDER BY seq`, action)
	require.NoError(w.t, err)
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (auditRow, error) {
		var a auditRow
		return a, r.Scan(&a.actor, &a.object, &a.result, &a.requestID, &a.details)
	})
	require.NoError(w.t, err)
	return out
}

func lab() discovery.Scope {
	return discovery.Scope{Name: "Lab", Entries: []string{"10.0.1.0/24", "10.0.2.5", "WEB.example."}, Ports: []int{443, 8443, 443},
		SNINames: []string{"a.example"}, Exclusions: []string{"10.0.1.128/25"}, Enabled: true}
}

// A scope is saved canonical (the validator's form), with its audit row in the same transaction; the name is unique
// case-insensitively among live scopes; reads, the version and the list's keyset.
func TestCreateGetListScopes(t *testing.T) {
	w := newWorld(t)
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.1.0/24", "10.0.2.5", "web.example"}, v.Scope.Entries)
	assert.Equal(t, []int{443, 8443}, v.Scope.Ports)
	assert.Equal(t, discovery.DefaultRate, v.Scope.RatePerSec)
	assert.Equal(t, "UTC", v.Scope.Schedule.TimeZone)
	assert.Equal(t, 1, v.Version)
	assert.Equal(t, uuid.NullUUID{UUID: w.admin.UserID, Valid: true}, v.CreatedBy)
	assert.Equal(t, t0, v.CreatedAt)
	assert.False(t, v.ActiveScanID.Valid)
	assert.Nil(t, v.LastScan)
	created := w.audits("discovery.scope.created")
	require.Len(t, created, 1)
	assert.Equal(t, auditRow{actor: "ada", object: v.ID.String(), result: "success", requestID: "req-ada", details: map[string]string{
		"scope_id": v.ID.String(), "name": "Lab", "entries_count": "3", "ports_count": "2", "sni_names_count": "1", "exclusions_count": "1",
		"enabled": "true", "schedule_hours": "0"}}, created[0])
	assert.Equal(t, []string{"web.example"}, w.res.lookups(), "only the host name is looked up")

	dup := lab()
	dup.Name = "LAB"
	_, err = w.svc.CreateScope(w.ctx, w.admin, dup)
	require.ErrorIs(t, err, ErrNameTaken)
	assert.Len(t, w.audits("discovery.scope.created"), 1, "a refused save writes no audit row")

	got, err := w.svc.GetScope(w.ctx, v.ID)
	require.NoError(t, err)
	assert.Equal(t, v, got)
	_, err = w.svc.GetScope(w.ctx, uuid.New())
	require.ErrorIs(t, err, discovery.ErrScopeNotFound)

	var ids []uuid.UUID
	ids = append(ids, v.ID)
	for _, name := range []string{"b", "c"} {
		w.clock.Advance(time.Second)
		s := lab()
		s.Name = name
		x, err := w.svc.CreateScope(w.ctx, w.admin, s)
		require.NoError(t, err)
		ids = append(ids, x.ID)
	}
	first, more, err := w.svc.ListScopes(w.ctx, ScopeFilter{Limit: 2})
	require.NoError(t, err)
	require.True(t, more)
	require.Equal(t, ids[:2], scopeIDs(first))
	rest, more, err := w.svc.ListScopes(w.ctx, ScopeFilter{Limit: 2, After: &ScopeCursor{CreatedAt: first[1].CreatedAt, ID: first[1].ID}})
	require.NoError(t, err)
	require.False(t, more)
	require.Equal(t, ids[2:], scopeIDs(rest))
}

func scopeIDs(list []ScopeView) []uuid.UUID {
	var out []uuid.UUID
	for _, s := range list {
		out = append(out, s.ID)
	}
	return out
}

// Save-time refusals come from the validator (DSC-0001/0002/0003/0009) with the allowed networks and global exclusions
// of the settings; ALC-DSC-0010 is the save-time look-up of a new host name: never the addresses, only which entry.
func TestCreateRefusals(t *testing.T) {
	w := newWorld(t)
	s := lab()
	s.Entries = []string{"192.168.1.1"}
	_, err := w.svc.CreateScope(w.ctx, w.admin, s)
	require.ErrorIs(t, err, discovery.ErrNotAllowed, "outside the allowed networks")
	s.Entries = []string{"10.0.0.0/8"}
	_, err = w.svc.CreateScope(w.ctx, w.admin, s)
	require.ErrorIs(t, err, discovery.ErrTooLarge)
	s.Entries = []string{"0177.0.0.1"}
	_, err = w.svc.CreateScope(w.ctx, w.admin, s)
	require.ErrorIs(t, err, discovery.ErrInvalid)
	s = lab()
	s.Schedule = discovery.Schedule{Hours: 200}
	_, err = w.svc.CreateScope(w.ctx, w.admin, s)
	require.ErrorIs(t, err, discovery.ErrSchedule)

	s = lab()
	s.Entries = []string{"10.0.0.1", "10.0.0.1", "nowhere.example", "web.example"}
	_, err = w.svc.CreateScope(w.ctx, w.admin, s)
	require.ErrorIs(t, err, ErrNameUnresolved)
	var nu *NameUnresolvedError
	require.ErrorAs(t, err, &nu)
	assert.Equal(t, 2, nu.Index, "the index in the list as sent")
	assert.NotContains(t, err.Error(), "10.0.0.80")

	// A resolver that never answers: every lookup has the 5-second deadline (here shortened), and the save is refused.
	w.res.block = true
	w.svc.resolveTimeout = 20 * time.Millisecond
	s = lab()
	_, err = w.svc.CreateScope(w.ctx, w.admin, s)
	require.ErrorIs(t, err, ErrNameUnresolved)
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_scopes`))
	assert.Empty(t, w.audits("discovery.scope.created"))

	// No allowed networks at all: nothing may be scanned, so nothing may be saved.
	w.res.block = false
	_, err = w.svc.SaveSettings(w.ctx, w.admin, Settings{RetentionDays: 90})
	require.NoError(t, err)
	_, err = w.svc.CreateScope(w.ctx, w.admin, lab())
	require.ErrorIs(t, err, discovery.ErrNotAllowed)
}

// An update applies the given fields, validates the result, looks up only the host names it adds, needs the version
// it was based on (when given), marks the endpoints that left the scope gone at once (A4), cancels the scope's scan when
// it is switched off, and writes its audit row in the same transaction.
func TestUpdateScope(t *testing.T) {
	w := newWorld(t)
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	// Endpoints as a scan left them: in and out of the new shape.
	for _, e := range []struct {
		addr string
		port int
		sni  string
		host string
	}{
		{"10.0.1.7", 443, "a.example", ""},               // stays
		{"10.0.1.7", 8443, "a.example", ""},              // port removed
		{"10.0.2.5", 443, "a.example", ""},               // entry removed
		{"10.0.1.8", 443, "", ""},                        // SNI not listed
		{"10.0.0.80", 443, "web.example", "web.example"}, // host removed
	} {
		w.exec(`INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, host, state, last_error_code, first_seen, last_scanned_at)
VALUES ($1, $2, $3, $4, $5, $6, 'unreachable', 'refused', $7, $7)`, uuid.New(), v.ID, e.addr, e.port, e.sni, e.host, t0)
	}
	w.res.answers["new.example"] = []netip.Addr{netip.MustParseAddr("10.0.0.81")}
	before := len(w.res.lookups())
	entries, ports := []string{"10.0.1.0/24", "new.example"}, []int{443}
	stale := 7
	_, err = w.svc.UpdateScope(w.ctx, w.admin, v.ID, &stale, ScopePatch{Ports: &ports})
	require.ErrorIs(t, err, ErrVersion)
	w.clock.Advance(time.Minute)
	one := 1
	u, err := w.svc.UpdateScope(w.ctx, w.admin, v.ID, &one, ScopePatch{Entries: &entries, Ports: &ports})
	require.NoError(t, err)
	assert.Equal(t, 2, u.Version)
	assert.Equal(t, entries, u.Scope.Entries)
	assert.Equal(t, "Lab", u.Scope.Name, "absent fields stay")
	assert.Equal(t, []string{"new.example"}, w.res.lookups()[before:], "only the added name is looked up")
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM discovery_endpoints WHERE scope_id = $1 AND state <> 'gone'`, v.ID))
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM discovery_endpoints WHERE address = '10.0.1.7' AND port = 443 AND state = 'unreachable'`))
	assert.Equal(t, 4, w.count(`SELECT count(*) FROM discovery_endpoints WHERE state = 'gone' AND gone_since = $1`, t0.Add(time.Minute)))
	upd := w.audits("discovery.scope.updated")
	require.Len(t, upd, 1)
	assert.Equal(t, map[string]string{"scope_id": v.ID.String(), "name": "Lab", "changed": "entries,ports", "entries_count": "2",
		"ports_count": "1", "sni_names_count": "1", "exclusions_count": "1", "enabled": "true", "schedule_hours": "0",
		"endpoints_gone_count": "4", "scans_cancelled_count": "0"}, upd[0].details)

	// A refused update changes nothing.
	bad := []string{"192.168.0.1"}
	_, err = w.svc.UpdateScope(w.ctx, w.admin, v.ID, nil, ScopePatch{Entries: &bad})
	require.ErrorIs(t, err, discovery.ErrNotAllowed)
	got, err := w.svc.GetScope(w.ctx, v.ID)
	require.NoError(t, err)
	assert.Equal(t, u, got)

	// Switching off cancels the running scan.
	scan, err := w.svc.StartScan(w.ctx, w.op, v.ID)
	require.NoError(t, err)
	off := false
	u, err = w.svc.UpdateScope(w.ctx, w.admin, v.ID, nil, ScopePatch{Enabled: &off})
	require.NoError(t, err)
	assert.False(t, u.Scope.Enabled)
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM discovery_scans WHERE id = $1 AND cancel_requested`, scan.ID))
	assert.Equal(t, "1", w.audits("discovery.scope.updated")[1].details["scans_cancelled_count"])

	// The name is checked on update too.
	other := lab()
	other.Name = "Other"
	_, err = w.svc.CreateScope(w.ctx, w.admin, other)
	require.NoError(t, err)
	name := "other"
	_, err = w.svc.UpdateScope(w.ctx, w.admin, v.ID, nil, ScopePatch{Name: &name})
	require.ErrorIs(t, err, ErrNameTaken)
	_, err = w.svc.UpdateScope(w.ctx, w.admin, uuid.New(), nil, ScopePatch{Name: &name})
	require.ErrorIs(t, err, discovery.ErrScopeNotFound)
}

// Deleting a scope frees its name, requests the cancellation of its scan, and is audited; its endpoints are left to
// retention.
func TestDeleteScope(t *testing.T) {
	w := newWorld(t)
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	scan, err := w.svc.StartScan(w.ctx, w.op, v.ID)
	require.NoError(t, err)
	stale := 3
	require.ErrorIs(t, w.svc.DeleteScope(w.ctx, w.admin, v.ID, &stale), ErrVersion)
	require.NoError(t, w.svc.DeleteScope(w.ctx, w.admin, v.ID, nil))
	require.ErrorIs(t, w.svc.DeleteScope(w.ctx, w.admin, v.ID, nil), discovery.ErrScopeNotFound)
	_, err = w.svc.GetScope(w.ctx, v.ID)
	require.ErrorIs(t, err, discovery.ErrScopeNotFound)
	assert.Equal(t, 1, w.count(`SELECT count(*) FROM discovery_scans WHERE id = $1 AND cancel_requested`, scan.ID))
	del := w.audits("discovery.scope.deleted")
	require.Len(t, del, 1)
	assert.Equal(t, map[string]string{"scope_id": v.ID.String(), "name": "Lab", "scans_cancelled_count": "1"}, del[0].details)
	_, err = w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err, "the name is free again")
	list, _, err := w.svc.ListScopes(w.ctx, ScopeFilter{})
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

// The start of a scan (A5, ruling of Task 8): the scan row, its job and the audit row commit together; a scope already
// scanning is ALC-DSC-0004, two scans active anywhere ALC-DSC-0007 (refused, not queued), a deleted scope 0008 and a
// switched-off one ALC-DSC-0013.
func TestStartScan(t *testing.T) {
	w := newWorld(t)
	var scopes []uuid.UUID
	for _, name := range []string{"a", "b", "c"} {
		s := lab()
		s.Name = name
		v, err := w.svc.CreateScope(w.ctx, w.admin, s)
		require.NoError(t, err)
		scopes = append(scopes, v.ID)
	}
	scan, err := w.svc.StartScan(w.ctx, w.op, scopes[0])
	require.NoError(t, err)
	assert.Equal(t, discovery.ScanQueued, scan.State)
	assert.Equal(t, "manual", scan.Trigger)
	assert.Equal(t, "a", scan.ScopeName)
	assert.Equal(t, uuid.NullUUID{UUID: w.op.UserID, Valid: true}, scan.RequestedBy)
	started := w.audits("discovery.scan.started")
	require.Len(t, started, 1)
	var job uuid.UUID
	require.NoError(t, w.db.Owner.QueryRow(w.ctx, `SELECT id FROM jobs WHERE type = 'netdisco.scan' AND payload->>'scan_id' = $1
  AND created_by = $2 AND created_by_role = 'operator'`, scan.ID.String(), w.op.UserID).Scan(&job))
	assert.Equal(t, auditRow{actor: "otto", object: scan.ID.String(), result: "success", requestID: "req-otto", details: map[string]string{
		"scan_id": scan.ID.String(), "scope_id": scopes[0].String(), "job_id": job.String(), "trigger": "manual"}}, started[0])

	_, err = w.svc.StartScan(w.ctx, w.op, scopes[0])
	require.ErrorIs(t, err, discovery.ErrScanRunning)
	_, err = w.svc.StartScan(w.ctx, w.op, scopes[1])
	require.NoError(t, err)
	_, err = w.svc.StartScan(w.ctx, w.op, scopes[2])
	require.ErrorIs(t, err, ErrTooManyScans)
	_, err = w.svc.StartScan(w.ctx, w.op, scopes[0])
	require.ErrorIs(t, err, discovery.ErrScanRunning, "the scope's own scan is the more precise answer")
	assert.Len(t, w.audits("discovery.scan.started"), 2)
	assert.Equal(t, 2, w.count(`SELECT count(*) FROM jobs WHERE type = 'netdisco.scan'`))

	w.exec(`UPDATE discovery_scans SET state = 'running', started_at = $1 WHERE scope_id = $2`, t0, scopes[1])
	w.exec(`UPDATE discovery_scans SET state = 'done', finished_at = $1 WHERE scope_id = $2`, t0, scopes[1])
	w.exec(`UPDATE jobs SET status = 'succeeded', finished_at = $1 WHERE payload->>'scan_id' IN (SELECT id::text FROM discovery_scans WHERE scope_id = $2)`, t0, scopes[1])
	off := false
	_, err = w.svc.UpdateScope(w.ctx, w.admin, scopes[2], nil, ScopePatch{Enabled: &off})
	require.NoError(t, err)
	_, err = w.svc.StartScan(w.ctx, w.op, scopes[2])
	require.ErrorIs(t, err, ErrScopeDisabled)
	require.NoError(t, w.svc.DeleteScope(w.ctx, w.admin, scopes[2], nil))
	_, err = w.svc.StartScan(w.ctx, w.op, scopes[2])
	require.ErrorIs(t, err, discovery.ErrScopeNotFound)
	_, err = w.svc.StartScan(w.ctx, w.op, uuid.New())
	require.ErrorIs(t, err, discovery.ErrScopeNotFound)

	v, err := w.svc.GetScope(w.ctx, scopes[0])
	require.NoError(t, err)
	assert.Equal(t, uuid.NullUUID{UUID: scan.ID, Valid: true}, v.ActiveScanID)
	v, err = w.svc.GetScope(w.ctx, scopes[1])
	require.NoError(t, err)
	require.NotNil(t, v.LastScan)
	assert.Equal(t, discovery.ScanDone, v.LastScan.State)
}

// Cancel sets the flag the workers poll; it is idempotent (one audit row) and a no-op on a scan that is over.
func TestCancelScan(t *testing.T) {
	w := newWorld(t)
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	scan, err := w.svc.StartScan(w.ctx, w.op, v.ID)
	require.NoError(t, err)
	got, err := w.svc.CancelScan(w.ctx, w.op, scan.ID)
	require.NoError(t, err)
	assert.True(t, got.CancelRequested)
	assert.Equal(t, discovery.ScanQueued, got.State, "the scanner ends it (cancelled) when it sees the flag")
	got, err = w.svc.CancelScan(w.ctx, w.admin, scan.ID)
	require.NoError(t, err)
	assert.True(t, got.CancelRequested)
	c := w.audits("discovery.scan.cancelled")
	require.Len(t, c, 1, "idempotent: one audit row")
	assert.Equal(t, map[string]string{"scan_id": scan.ID.String(), "scope_id": v.ID.String(), "state": "queued"}, c[0].details)

	w.exec(`UPDATE discovery_scans SET state = 'running', started_at = $1 WHERE id = $2`, t0, scan.ID)
	w.exec(`UPDATE discovery_scans SET state = 'done', finished_at = $1 WHERE id = $2`, t0, scan.ID)
	got, err = w.svc.CancelScan(w.ctx, w.op, scan.ID)
	require.NoError(t, err)
	assert.Equal(t, discovery.ScanDone, got.State)
	assert.Len(t, w.audits("discovery.scan.cancelled"), 1)
	_, err = w.svc.CancelScan(w.ctx, w.op, uuid.New())
	require.ErrorIs(t, err, ErrNotFound)
}

// The scan list: newest first, keyset (queued_at, id), filters scope and state.
func TestListScans(t *testing.T) {
	w := newWorld(t)
	a, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	s := lab()
	s.Name = "B"
	b, err := w.svc.CreateScope(w.ctx, w.admin, s)
	require.NoError(t, err)
	var ids []uuid.UUID
	for i := range 3 {
		w.clock.Advance(time.Minute)
		scope := a.ID
		if i == 1 {
			scope = b.ID
		}
		x, err := w.svc.StartScan(w.ctx, w.op, scope)
		require.NoError(t, err)
		ids = append(ids, x.ID)
		if i < 2 {
			w.exec(`UPDATE discovery_scans SET state = 'running', started_at = $1 WHERE id = $2`, w.clock.Now(), x.ID)
			w.exec(`UPDATE discovery_scans SET state = 'done', finished_at = $1 WHERE id = $2`, w.clock.Now(), x.ID)
			w.exec(`UPDATE jobs SET status = 'succeeded', finished_at = $1 WHERE payload->>'scan_id' = $2`, w.clock.Now(), x.ID.String())
		}
	}
	all, more, err := w.svc.ListScans(w.ctx, ScanFilter{})
	require.NoError(t, err)
	assert.False(t, more)
	assert.Equal(t, []uuid.UUID{ids[2], ids[1], ids[0]}, scanIDs(all))
	page, more, err := w.svc.ListScans(w.ctx, ScanFilter{Limit: 1})
	require.NoError(t, err)
	assert.True(t, more)
	rest, _, err := w.svc.ListScans(w.ctx, ScanFilter{After: &ScanCursor{QueuedAt: page[0].QueuedAt, ID: page[0].ID}})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{ids[1], ids[0]}, scanIDs(rest))
	only, _, err := w.svc.ListScans(w.ctx, ScanFilter{ScopeID: a.ID, State: discovery.ScanDone})
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{ids[0]}, scanIDs(only))
	one, err := w.svc.GetScan(w.ctx, ids[1])
	require.NoError(t, err)
	assert.Equal(t, "B", one.ScopeName)
	_, err = w.svc.GetScan(w.ctx, uuid.New())
	require.ErrorIs(t, err, ErrNotFound)
}

func scanIDs(list []ScanView) []uuid.UUID {
	var out []uuid.UUID
	for _, s := range list {
		out = append(out, s.ID)
	}
	return out
}

// The settings (A2): absent rows are the defaults (no allowed networks: nothing may be scanned, 90 days); a save stores
// the canonical lists, is audited with its lists and counts, and refuses a bad element or a retention outside 7..730.
func TestSettings(t *testing.T) {
	w := newWorld(t)
	w.exec(`DELETE FROM settings WHERE key LIKE 'discovery.%'`)
	got, err := w.svc.Settings(w.ctx)
	require.NoError(t, err)
	assert.Equal(t, SettingsView{Settings: Settings{AllowedNetworks: []string{}, GlobalExclusions: []string{}, RetentionDays: 90}}, got)
	assert.False(t, got.ScanningEnabled)

	saved, err := w.svc.SaveSettings(w.ctx, w.admin, Settings{AllowedNetworks: []string{"10.0.0.0/16", "::ffff:10.1.0.0/112", "10.0.0.0/16"},
		GlobalExclusions: []string{"10.0.9.9/32"}, RetentionDays: 30})
	require.NoError(t, err)
	assert.Equal(t, SettingsView{Settings: Settings{AllowedNetworks: []string{"10.0.0.0/16", "10.1.0.0/16"}, GlobalExclusions: []string{"10.0.9.9"},
		RetentionDays: 30}, ScanningEnabled: true}, saved)
	got, err = w.svc.Settings(w.ctx)
	require.NoError(t, err)
	assert.Equal(t, saved, got)
	upd := w.audits("discovery.exclusions.updated")
	last := upd[len(upd)-1]
	assert.Equal(t, map[string]string{"allowed_networks": "10.0.0.0/16, 10.1.0.0/16", "allowed_networks_count": "2",
		"global_exclusions": "10.0.9.9", "global_exclusions_count": "1", "retention_days": "30", "scans_cancelled_count": "0"}, last.details)

	for _, bad := range []Settings{
		{AllowedNetworks: []string{"intranet.example"}, RetentionDays: 30},
		{GlobalExclusions: []string{"10.0.0.1/33"}, RetentionDays: 30},
		{RetentionDays: 6},
		{RetentionDays: 731},
	} {
		_, err := w.svc.SaveSettings(w.ctx, w.admin, bad)
		var de *discovery.Error
		require.ErrorAs(t, err, &de, "%+v", bad)
	}
	_, err = w.svc.SaveSettings(w.ctx, w.admin, Settings{AllowedNetworks: []string{"x"}, RetentionDays: 30})
	var de *discovery.Error
	require.ErrorAs(t, err, &de)
	assert.Equal(t, "allowed_networks", de.Field)
	_, err = w.svc.SaveSettings(w.ctx, w.admin, Settings{RetentionDays: 1})
	require.ErrorAs(t, err, &de)
	assert.Equal(t, "retention_days", de.Field)
	got, err = w.svc.Settings(w.ctx)
	require.NoError(t, err)
	assert.Equal(t, saved, got, "a refused save changes nothing")

	// An empty allowed list is valid and means: nothing may be scanned.
	empty, err := w.svc.SaveSettings(w.ctx, w.admin, Settings{RetentionDays: 7})
	require.NoError(t, err)
	assert.False(t, empty.ScanningEnabled)
	assert.Equal(t, []string{}, empty.AllowedNetworks)
}

// The preview: the size of a scope as typed, validated against the settings, without any look-up.
func TestPreview(t *testing.T) {
	w := newWorld(t)
	before := len(w.res.lookups())
	p, err := w.svc.Preview(w.ctx, lab())
	require.NoError(t, err)
	assert.Equal(t, 257, p.Addresses)
	assert.Equal(t, 1, p.Hostnames)
	assert.Equal(t, 2, p.Ports)
	assert.Equal(t, 128, p.ExcludedAddresses)
	assert.Equal(t, before, len(w.res.lookups()), "no DNS")
	bad := lab()
	bad.Entries = []string{"192.168.0.1"}
	_, err = w.svc.Preview(w.ctx, bad)
	require.ErrorIs(t, err, discovery.ErrNotAllowed)
}

// The summary of the Overview metric: unmanaged leaves presented by an endpoint that is not gone, the ones of them
// expiring within 30 days (not expired), live scopes, the last finished scan.
func TestSummary(t *testing.T) {
	w := newWorld(t)
	s, err := w.svc.Summary(w.ctx)
	require.NoError(t, err)
	assert.Equal(t, Summary{}, s)
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	cert := func(fp string, notAfter time.Time) {
		w.exec(`INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before, not_after, key_algorithm,
    self_signed, pem, first_seen, last_seen) VALUES ($1, true, 'cn', '{}', 'ca', $2, $3, 'ecdsa', false,
    '-----BEGIN CERTIFICATE-----' || chr(10) || 'AA==' || chr(10) || '-----END CERTIFICATE-----', $2, $2)`, fp, t0.AddDate(-1, 0, 0), notAfter)
	}
	endpoint := func(addr, fp, state string) {
		code, gone := "", any(nil)
		if state == "gone" {
			code, gone = "", t0
		}
		if state == "excluded" {
			code = "policy"
		}
		w.exec(`INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, fingerprint_sha256, state, last_error_code, first_seen, last_seen,
    last_scanned_at, gone_since, tls_version, cipher) VALUES ($1, $2, $3, 443, '', $4, $5, $6, $7, $7, $7, $8, 'TLS 1.3', 'TLS_AES_128_GCM_SHA256')`,
			uuid.New(), v.ID, addr, fp, state, code, t0, gone)
	}
	fp := func(c byte) string { return string(bytes.Repeat([]byte{c}, 64)) }
	cert(fp('a'), t0.AddDate(0, 0, 10)) // unmanaged, expiring
	cert(fp('b'), t0.AddDate(0, 0, 90)) // unmanaged
	cert(fp('c'), t0.AddDate(0, 0, -1)) // unmanaged, expired
	cert(fp('d'), t0.AddDate(0, 0, 5))  // gone only
	cert(fp('e'), t0.AddDate(0, 0, 5))  // managed
	endpoint("10.0.1.1", fp('a'), "present")
	endpoint("10.0.1.2", fp('b'), "present")
	endpoint("10.0.1.3", fp('c'), "present")
	endpoint("10.0.1.4", fp('d'), "gone")
	endpoint("10.0.1.5", fp('e'), "present")
	w.exec(`INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm, public_key_sha256, pem_chain, source,
    first_seen_at, last_seen_at, created_at) VALUES ($1, $2, 'cn', $3, $3, 'ecdsa', $2, '', 'uploaded', $3, $3, $3)`, uuid.New(), fp('e'), t0)
	// An excluded place is never dialed, and a place of a deleted scope is not scanned: neither is "still found".
	cert(fp('f'), t0.AddDate(0, 0, 6))
	endpoint("10.0.1.6", fp('f'), "excluded")
	cert(fp('g'), t0.AddDate(0, 0, 7))
	deleted := uuid.New()
	w.exec(`INSERT INTO discovery_scopes (id, name, entries, ports, deleted_at, created_at, updated_at) VALUES ($1, 'old', '["10.0.9.0/24"]', '{443}', $2, $2, $2)`, deleted, t0)
	w.exec(`INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, fingerprint_sha256, state, first_seen, last_seen, last_scanned_at,
    tls_version, cipher) VALUES ($1, $2, '10.0.9.1', 443, '', $3, 'present', $4, $4, $4, 'TLS 1.3', 'TLS_AES_128_GCM_SHA256')`, uuid.New(), deleted, fp('g'), t0)
	scan, err := w.svc.StartScan(w.ctx, w.op, v.ID)
	require.NoError(t, err)
	w.exec(`UPDATE discovery_scans SET state = 'running', started_at = $1 WHERE id = $2`, t0, scan.ID)
	w.exec(`UPDATE discovery_scans SET state = 'done', finished_at = $1 WHERE id = $2`, t0.Add(time.Minute), scan.ID)
	s, err = w.svc.Summary(w.ctx)
	require.NoError(t, err)
	at := t0.Add(time.Minute)
	assert.Equal(t, Summary{UnmanagedTotal: 3, UnmanagedExpiring30d: 1, Scopes: 1, LastScanAt: &at}, s)

	// One definition of "unmanaged and still found": the summary's counts are the lengths of the lists the UI links to
	// (status=unmanaged&current=true, with expiring_within_days=30 for the Overview's line).
	all, _, err := w.svc.ListCertificates(w.ctx, discovery.CertificateFilter{Status: discovery.StatusUnmanaged, Current: true, Limit: 200})
	require.NoError(t, err)
	assert.Len(t, all, s.UnmanagedTotal)
	soon, _, err := w.svc.ListCertificates(w.ctx, discovery.CertificateFilter{Status: discovery.StatusUnmanaged, Current: true, Limit: 200,
		Now: t0, ExpiringBy: t0.AddDate(0, 0, 30)})
	require.NoError(t, err)
	assert.Len(t, soon, s.UnmanagedExpiring30d)
	every, _, err := w.svc.ListCertificates(w.ctx, discovery.CertificateFilter{Status: discovery.StatusUnmanaged, Limit: 200})
	require.NoError(t, err)
	assert.Len(t, every, 4, "without current the gone-only certificate stays listed until retention")
}

// insertCert and insertEndpoint put read-side rows in place (the scanner's work in production).
func (w *world) insertCert(fp, cn string, sans []string, notAfter time.Time, selfSigned bool) {
	w.t.Helper()
	w.exec(`INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before, not_after, key_algorithm,
    self_signed, pem, first_seen, last_seen) VALUES ($1, true, $2, $3, 'ca', $4, $5, 'ecdsa', $6,
    '-----BEGIN CERTIFICATE-----' || chr(10) || 'AA==' || chr(10) || '-----END CERTIFICATE-----', $4, $4)`, fp, cn, sans, t0.AddDate(-1, 0, 0),
		notAfter, selfSigned)
}

func (w *world) insertEndpoint(scope uuid.UUID, addr string, port int, fp string) {
	w.t.Helper()
	w.exec(`INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, fingerprint_sha256, state, first_seen, last_seen, last_scanned_at,
    tls_version, cipher) VALUES ($1, $2, $3, $4, '', $5, 'present', $6, $6, $6, 'TLS 1.3', 'TLS_AES_128_GCM_SHA256')`, uuid.New(), scope, addr, port, fp, t0)
}

func hexFP(c byte) string { return string(bytes.Repeat([]byte{c}, 64)) }

// The read side pages the discovery package's lists (more: a page follows), fills the reference time of a time filter
// from the clock, and a certificate's detail lists the endpoints presenting it.
func TestReadSide(t *testing.T) {
	w := newWorld(t)
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	w.insertCert(hexFP('a'), "a.example", []string{"a.example"}, t0.AddDate(0, 0, 3), false)
	w.insertCert(hexFP('b'), "b.example", []string{"b.example"}, t0.AddDate(0, 0, 60), true)
	w.insertCert(hexFP('c'), "c.example", []string{}, t0.AddDate(0, 0, -2), false)
	for i, fp := range []string{hexFP('a'), hexFP('a'), hexFP('b'), hexFP('c')} {
		w.insertEndpoint(v.ID, "10.0.1."+strconv.Itoa(i+1), 443, fp)
	}
	page, more, err := w.svc.ListCertificates(w.ctx, discovery.CertificateFilter{Limit: 2})
	require.NoError(t, err)
	assert.True(t, more)
	assert.Equal(t, []string{hexFP('c'), hexFP('a')}, certFPs(page))
	rest, more, err := w.svc.ListCertificates(w.ctx, discovery.CertificateFilter{After: &discovery.CertificateCursor{NotAfter: page[1].NotAfter,
		Fingerprint: page[1].Fingerprint}})
	require.NoError(t, err)
	assert.False(t, more)
	assert.Equal(t, []string{hexFP('b')}, certFPs(rest))
	no := false
	live, _, err := w.svc.ListCertificates(w.ctx, discovery.CertificateFilter{Expired: &no})
	require.NoError(t, err, "the service's clock is the reference time")
	assert.Equal(t, []string{hexFP('a'), hexFP('b')}, certFPs(live))
	soon, _, err := w.svc.ListCertificates(w.ctx, discovery.CertificateFilter{ExpiringBy: t0.AddDate(0, 0, 30)})
	require.NoError(t, err)
	assert.Equal(t, []string{hexFP('a')}, certFPs(soon))

	c, eps, more, err := w.svc.Certificate(w.ctx, hexFP('a'))
	require.NoError(t, err)
	assert.False(t, more)
	assert.Equal(t, discovery.StatusUnmanaged, c.Status)
	assert.Equal(t, 2, c.Endpoints)
	require.Len(t, eps, 2)
	assert.Equal(t, "10.0.1.1", eps[0].Address.String())
	_, _, _, err = w.svc.Certificate(w.ctx, hexFP('f'))
	require.ErrorIs(t, err, ErrNotFound)

	first, more, err := w.svc.ListEndpoints(w.ctx, discovery.EndpointFilter{ScopeID: v.ID, Limit: 3})
	require.NoError(t, err)
	assert.True(t, more)
	require.Len(t, first, 3)
	last := first[2]
	tail, more, err := w.svc.ListEndpoints(w.ctx, discovery.EndpointFilter{ScopeID: v.ID,
		After: &discovery.EndpointCursor{Address: last.Address, Port: last.Port, SNI: last.SNI}})
	require.NoError(t, err)
	assert.False(t, more)
	require.Len(t, tail, 1)
	assert.Equal(t, "10.0.1.4", tail[0].Address.String())
}

func certFPs(list []discovery.CertificateRow) []string {
	out := []string{}
	for _, c := range list {
		out = append(out, c.Fingerprint)
	}
	return out
}

// A scope with a schedule window, no SNI names and no exclusions, created by an actor with no user (created_by stays
// empty), keeps its window and lists as stored.
func TestScheduleWindowAndEmptyLists(t *testing.T) {
	w := newWorld(t)
	sc := discovery.Scope{Name: "Night", Entries: []string{"10.0.3.0/24"}, Ports: []int{443}, Enabled: true,
		Schedule: discovery.Schedule{Hours: 24, WindowStart: "22:00", WindowEnd: "04:30", TimeZone: "Europe/Istanbul"}}
	v, err := w.svc.CreateScope(w.ctx, Actor{Audit: audit.SystemActor("test")}, sc)
	require.NoError(t, err)
	assert.False(t, v.CreatedBy.Valid)
	assert.Equal(t, discovery.Schedule{Hours: 24, WindowStart: "22:00", WindowEnd: "04:30", TimeZone: "Europe/Istanbul"}, v.Scope.Schedule)
	assert.Equal(t, []string{}, v.Scope.SNINames)
	assert.Equal(t, []string{}, v.Scope.Exclusions)
	none := discovery.Schedule{}
	alert, rate, conc := true, 50, 4
	u, err := w.svc.UpdateScope(w.ctx, w.admin, v.ID, nil, ScopePatch{Schedule: &none, AlertOnExpiry: &alert, RatePerSec: &rate, Concurrency: &conc,
		SNINames: &[]string{"x.example"}, Exclusions: &[]string{"10.0.3.7"}})
	require.NoError(t, err)
	assert.Equal(t, 0, u.Scope.Schedule.Hours)
	assert.Empty(t, u.Scope.Schedule.WindowStart)
	assert.True(t, u.Scope.AlertOnExpiry)
	assert.Equal(t, 50, u.Scope.RatePerSec)
	assert.Equal(t, []string{"10.0.3.7"}, u.Scope.Exclusions)
	assert.Equal(t, "sni_names,exclusions,schedule,alert_on_expiry,rate_per_sec,concurrency", w.audits("discovery.scope.updated")[0].details["changed"])
}

// A database that cannot be reached is an error of every call (never a panic, never a half-done change).
func TestEveryCallReturnsTheDatabaseFailure(t *testing.T) {
	w := newWorld(t)
	pool, err := pgxpool.New(w.ctx, w.db.AppURL)
	require.NoError(t, err)
	pool.Close()
	svc := New(Config{Pool: pool, Audit: audit.New(w.clock), Queue: w.queue, Clock: w.clock, Resolver: w.res})
	id := uuid.New()
	one := 1
	calls := map[string]func() error{
		"Settings":     func() error { _, err := svc.Settings(w.ctx); return err },
		"SaveSettings": func() error { _, err := svc.SaveSettings(w.ctx, w.admin, Settings{RetentionDays: 30}); return err },
		"CreateScope":  func() error { _, err := svc.CreateScope(w.ctx, w.admin, lab()); return err },
		"GetScope":     func() error { _, err := svc.GetScope(w.ctx, id); return err },
		"ListScopes":   func() error { _, _, err := svc.ListScopes(w.ctx, ScopeFilter{}); return err },
		"UpdateScope":  func() error { _, err := svc.UpdateScope(w.ctx, w.admin, id, &one, ScopePatch{}); return err },
		"DeleteScope":  func() error { return svc.DeleteScope(w.ctx, w.admin, id, nil) },
		"Preview":      func() error { _, err := svc.Preview(w.ctx, lab()); return err },
		"StartScan":    func() error { _, err := svc.StartScan(w.ctx, w.op, id); return err },
		"CancelScan":   func() error { _, err := svc.CancelScan(w.ctx, w.op, id); return err },
		"GetScan":      func() error { _, err := svc.GetScan(w.ctx, id); return err },
		"ListScans":    func() error { _, _, err := svc.ListScans(w.ctx, ScanFilter{}); return err },
		"ListCertificates": func() error {
			_, _, err := svc.ListCertificates(w.ctx, discovery.CertificateFilter{})
			return err
		},
		"Certificate":   func() error { _, _, _, err := svc.Certificate(w.ctx, hexFP('a')); return err },
		"ListEndpoints": func() error { _, _, err := svc.ListEndpoints(w.ctx, discovery.EndpointFilter{}); return err },
		"Summary":       func() error { _, err := svc.Summary(w.ctx); return err },
	}
	for name, call := range calls {
		err := call()
		require.Error(t, err, name)
		assert.NotErrorIs(t, err, ErrNotFound, name)
		assert.NotErrorIs(t, err, discovery.ErrScopeNotFound, name)
	}
}

// A request that ends while its names are looked up decides nothing about them: the request's error, not 0010.
func TestCancelledRequestIsNotAnUnresolvedName(t *testing.T) {
	w := newWorld(t)
	w.res.block = true
	ctx, cancel := context.WithCancel(w.ctx)
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, err := w.svc.CreateScope(ctx, w.admin, lab())
	require.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, ErrNameUnresolved)
	assert.Equal(t, "discoverysvc: a host name of the scope does not resolve: entries[3]", (&NameUnresolvedError{Index: 3}).Error())
}

// Changing what a scope covers (entries, ports, SNI names, exclusions) asks its scan in flight to stop, in the same
// transaction, as switching it off does; changing only its name does not (Task 9 review 5).
func TestEditingTheShapeCancelsTheRunningScan(t *testing.T) {
	w := newWorld(t)
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	scan, err := w.svc.StartScan(w.ctx, w.op, v.ID)
	require.NoError(t, err)
	name := "Renamed"
	_, err = w.svc.UpdateScope(w.ctx, w.admin, v.ID, nil, ScopePatch{Name: &name})
	require.NoError(t, err)
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_scans WHERE id = $1 AND cancel_requested`, scan.ID), "a new name changes no target")
	for i, p := range []ScopePatch{
		{Ports: &[]int{443}},
		{Entries: &[]string{"10.0.1.0/24"}},
		{SNINames: &[]string{"b.example"}},
		{Exclusions: &[]string{"10.0.1.0/26"}},
	} {
		w.exec(`UPDATE discovery_scans SET cancel_requested = false WHERE id = $1`, scan.ID)
		_, err := w.svc.UpdateScope(w.ctx, w.admin, v.ID, nil, p)
		require.NoError(t, err, i)
		assert.Equal(t, 1, w.count(`SELECT count(*) FROM discovery_scans WHERE id = $1 AND cancel_requested`, scan.ID), i)
		upd := w.audits("discovery.scope.updated")
		assert.Equal(t, "1", upd[len(upd)-1].details["scans_cancelled_count"], i)
	}
}

// A start and a concurrent switch-off cannot both win (Task 9 review 6): the start reads the scope FOR SHARE, so it
// waits for the uncommitted switch-off and then refuses with ALC-DSC-0013; nothing is queued.
func TestStartWaitsForAConcurrentSwitchOff(t *testing.T) {
	w := newWorld(t)
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	tx, err := w.db.Owner.Begin(w.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(w.ctx) }()
	_, err = tx.Exec(w.ctx, `UPDATE discovery_scopes SET enabled = false WHERE id = $1`, v.ID)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := w.svc.StartScan(w.ctx, w.op, v.ID)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the start did not wait for the switch-off: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	require.NoError(t, tx.Commit(w.ctx))
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrScopeDisabled)
	case <-time.After(10 * time.Second):
		t.Fatal("the start never finished")
	}
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_scans`))
}

// The look-ups of one save have a budget: names it could not decide in time are not "does not resolve" (ALC-DSC-0010)
// but ErrLookupBudget (503, retry later); and a save may add at most MaxNewNames host names (Task 9 review 7).
func TestLookupBudgetAndNameCap(t *testing.T) {
	w := newWorld(t)
	w.res.block = true
	w.svc.resolveTimeout = time.Hour
	w.svc.resolveBudget = 30 * time.Millisecond
	_, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.ErrorIs(t, err, ErrLookupBudget)
	assert.NotErrorIs(t, err, ErrNameUnresolved)
	assert.Zero(t, w.count(`SELECT count(*) FROM discovery_scopes`))

	w.res.block = false
	w.svc.resolveTimeout, w.svc.resolveBudget = discovery.ResolveTimeout, defaultResolveBudget
	many := lab()
	many.Entries = []string{"10.0.1.0/24"}
	for i := range MaxNewNames + 1 {
		host := "h" + strconv.Itoa(i) + ".example"
		w.res.answers[host] = []netip.Addr{netip.MustParseAddr("10.0.0.90")}
		many.Entries = append(many.Entries, host)
	}
	before := len(w.res.lookups())
	_, err = w.svc.CreateScope(w.ctx, w.admin, many)
	var ve validate.Errors
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, "entries", ve[0].Field)
	assert.Equal(t, before, len(w.res.lookups()), "nothing is looked up")
	many.Entries = many.Entries[:MaxNewNames+1]
	v, err := w.svc.CreateScope(w.ctx, w.admin, many)
	require.NoError(t, err, "exactly MaxNewNames new names")
	// On a change only the names it adds count.
	more := append(slices.Clone(v.Scope.Entries), "h16.example")
	_, err = w.svc.UpdateScope(w.ctx, w.admin, v.ID, nil, ScopePatch{Entries: &more})
	require.NoError(t, err)
}

// An empty change is refused (422): it would bump the version and write an audit row for nothing (Task 9 review 8).
func TestEmptyPatchIsRefused(t *testing.T) {
	w := newWorld(t)
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	_, err = w.svc.UpdateScope(w.ctx, w.admin, v.ID, nil, ScopePatch{})
	var ve validate.Errors
	require.ErrorAs(t, err, &ve)
	got, err := w.svc.GetScope(w.ctx, v.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version)
	assert.Empty(t, w.audits("discovery.scope.updated"))
}

// Changing the allowed networks or the exclusions asks the scans in flight to stop (the new rules must hold for what
// they connect to next); changing the retention alone does not.
func TestSaveSettingsCancelsScansInFlight(t *testing.T) {
	w := newWorld(t)
	w.allow("10.0.0.0/16")
	v, err := w.svc.CreateScope(w.ctx, w.admin, lab())
	require.NoError(t, err)
	scan, err := w.svc.StartScan(w.ctx, w.op, v.ID)
	require.NoError(t, err)
	cancelled := func() int {
		return w.count(`SELECT count(*) FROM discovery_scans WHERE id = $1 AND cancel_requested`, scan.ID)
	}
	_, err = w.svc.SaveSettings(w.ctx, w.admin, Settings{AllowedNetworks: []string{"10.0.0.0/16"}, RetentionDays: 30})
	require.NoError(t, err)
	assert.Zero(t, cancelled(), "the retention alone changes nothing a scan connects to")
	_, err = w.svc.SaveSettings(w.ctx, w.admin, Settings{AllowedNetworks: []string{"10.0.0.0/16"}, GlobalExclusions: []string{"10.0.0.5"}, RetentionDays: 30})
	require.NoError(t, err)
	assert.Equal(t, 1, cancelled())
	upd := w.audits("discovery.exclusions.updated")
	assert.Equal(t, "1", upd[len(upd)-1].details["scans_cancelled_count"])
}
