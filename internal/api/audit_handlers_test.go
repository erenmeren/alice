package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
)

func sampleEntries() []audit.Entry {
	return []audit.Entry{
		{Seq: 1, At: testNow, ActorType: audit.ActorUser, ActorID: adminID, ActorName: "admin", IP: "192.0.2.1",
			Action: "setup.admin_created", ObjectType: "user", ObjectID: adminID.String(), Result: audit.Success,
			Details: map[string]string{"city": "İzmir"}, RequestID: "req-1", Hash: []byte{0xab, 0xcd}},
		{Seq: 2, At: testNow.Add(time.Second), ActorType: audit.ActorUser, ActorName: "=HYPERLINK(\"http://evil\")",
			Action: "auth.login", Result: audit.Failure, Details: map[string]string{"reason": "unknown_user"}, Hash: []byte{0x01}},
	}
}

func intactReport() audit.Report {
	return audit.Report{Intact: true, Checked: 2, HeadSeq: 2, HeadHash: []byte{0x01}}
}

func TestListAuditPassesFiltersAndReturnsCursor(t *testing.T) {
	d := testDeps(t, nil)
	var got audit.Filter
	d.Audit.(*fakeAudit).ListFn = func(_ context.Context, f audit.Filter) ([]audit.Entry, int64, error) {
		got = f
		return sampleEntries()[:1], 1, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/audit?limit=1&cursor=10&action=auth.&actor=admin&result=failure", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, audit.Filter{Action: "auth.", Actor: "admin", Result: audit.Failure, BeforeSeq: 10, Limit: 1}, got)
	assert.JSONEq(t, `{"items":[{"seq":1,"at":"2026-09-30T12:00:00Z","actor_type":"user","actor_id":"0190f5a0-0000-7000-8000-000000000001",
	  "actor_name":"admin","ip":"192.0.2.1","action":"setup.admin_created","object_type":"user","object_id":"0190f5a0-0000-7000-8000-000000000001",
	  "result":"success","details":{"city":"İzmir"},"request_id":"req-1","hash":"abcd"}],"next_cursor":"1"}`, rec.Body.String())

	d.Audit.(*fakeAudit).ListFn = func(_ context.Context, f audit.Filter) ([]audit.Entry, int64, error) {
		got = f
		return nil, 0, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/audit", "admin", "")
	assert.JSONEq(t, `{"items":[],"next_cursor":null}`, rec.Body.String())
	assert.Equal(t, 50, got.Limit, "default page size")
}

func TestListAuditRejectsBadParameters(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	for _, q := range []string{"limit=0", "limit=201", "limit=x", "cursor=-1", "cursor=abc", "result=maybe"} {
		rec := call(h, http.MethodGet, "/api/v1/audit?"+q, "admin", "")
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
		assert.Equal(t, "ALC-SYS-0006", decodeErr(t, rec).Error.Code, q)
	}
}

func TestVerifyAudit(t *testing.T) {
	d := testDeps(t, nil)
	var actor audit.Actor
	d.Audit.(*fakeAudit).VerifyFn = func(_ context.Context, a audit.Actor) (audit.Report, error) {
		actor = a
		return audit.Report{Intact: false, Checked: 7, HeadSeq: 9, HeadHash: []byte{0xff}, FirstBadSeq: 7, Problem: audit.ProblemHashMismatch}, nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/audit/verify", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"intact":false,"checked":7,"head_seq":9,"head_hash":"ff","first_bad_seq":7,"problem":"hash_mismatch"}`, rec.Body.String())
	assert.Equal(t, auditorID, actor.ID)
	assert.Equal(t, audit.ActorUser, actor.Type)

	d.Audit.(*fakeAudit).VerifyFn = func(context.Context, audit.Actor) (audit.Report, error) { return intactReport(), nil }
	rec = call(NewHandler(d), http.MethodPost, "/api/v1/audit/verify", "admin", "")
	assert.JSONEq(t, `{"intact":true,"checked":2,"head_seq":2,"head_hash":"01","first_bad_seq":null,"problem":null}`, rec.Body.String())
}

// exported returns the audit.exported events with result res.
func exported(fa *fakeAudit, res audit.Result) []audit.Event {
	var out []audit.Event
	for _, e := range fa.Events() {
		if e.Action == "audit.exported" && e.Result == res {
			out = append(out, e)
		}
	}
	return out
}

// exportDeps wires fakes so that Iterate fails the test if the export was not
// audited first.
func exportDeps(t *testing.T) (Deps, *fakeAudit) {
	d := testDeps(t, nil)
	fa := d.Audit.(*fakeAudit)
	fa.VerifyReadOnlyFn = func(context.Context) (audit.Report, error) { return intactReport(), nil }
	fa.IterateFn = func(_ context.Context, fn func(audit.Entry) error) error {
		assert.Len(t, exported(fa, audit.Success), 1, "the export must be audited before entries are streamed")
		for _, e := range sampleEntries() {
			if err := fn(e); err != nil {
				return err
			}
		}
		return nil
	}
	return d, fa
}

func TestExportCSV(t *testing.T) {
	d, fa := exportDeps(t)
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/audit/export?format=csv", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "true", rec.Header().Get("X-Alice-Audit-Intact"))
	assert.Equal(t, `attachment; filename="alice-audit-2026-09-30.csv"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	body := rec.Body.String()
	require.True(t, strings.HasPrefix(body, "\xEF\xBB\xBF"), "UTF-8 BOM")
	// AUD-25 (c): the first line carries the verification the JSON export has; the header follows.
	first, rest, _ := strings.Cut(strings.TrimPrefix(body, "\xEF\xBB\xBF"), "\n")
	assert.Equal(t, "# alice audit export: intact=true checked=2 head_seq=2 head_hash=01", first)
	assert.True(t, strings.HasPrefix(rest, "seq,at,"), "the header row is the second line")
	rd := csv.NewReader(strings.NewReader(strings.TrimPrefix(body, "\xEF\xBB\xBF")))
	rd.Comment = '#'
	rows, err := rd.ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, "seq", rows[0][0])
	assert.Equal(t, "hash", rows[0][12])
	assert.Equal(t, `{"city":"İzmir"}`, rows[1][10])
	assert.Equal(t, `'=HYPERLINK("http://evil")`, rows[2][4], "formula injection is neutralised")

	events := fa.Events()
	require.Len(t, events, 1, "export is read-only: only audit.exported is written, never audit.verified or a checkpoint")
	assert.Equal(t, "audit.exported", events[0].Action)
	assert.Equal(t, map[string]string{"format": "csv", "intact": "true"}, events[0].Details)
	assert.Equal(t, auditorID, events[0].Actor.ID)
}

// A broken chain names the first bad entry and the problem in the CSV's first line too.
func TestExportCSVFirstLineOfABrokenChain(t *testing.T) {
	d, _ := exportDeps(t)
	d.Audit.(*fakeAudit).VerifyReadOnlyFn = func(context.Context) (audit.Report, error) {
		return audit.Report{Intact: false, Checked: 6, HeadSeq: 6, HeadHash: []byte{0xfe, 0xed}, FirstBadSeq: 7, Problem: audit.ProblemHashMismatch}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/audit/export?format=csv", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "false", rec.Header().Get("X-Alice-Audit-Intact"))
	first, _, _ := strings.Cut(strings.TrimPrefix(rec.Body.String(), "\xEF\xBB\xBF"), "\n")
	assert.Equal(t, "# alice audit export: intact=false checked=6 head_seq=6 head_hash=feed first_bad_seq=7 problem=hash_mismatch", first)
}

// AUD-06: one verification or export reads the whole chain at a time in a process; another one
// is refused at once with a retryable answer instead of running beside it.
func TestChainScansRunOneAtATime(t *testing.T) {
	d, fa := exportDeps(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	fa.VerifyReadOnlyFn = func(ctx context.Context) (audit.Report, error) {
		once.Do(func() { close(started) })
		select {
		case <-release:
		case <-ctx.Done():
		}
		return intactReport(), nil
	}
	fa.VerifyFn = func(context.Context, audit.Actor) (audit.Report, error) { return intactReport(), nil }
	h := NewHandler(d)
	first := make(chan int)
	go func() { first <- call(h, http.MethodGet, "/api/v1/audit/export?format=json", "auditor", "").Code }()
	<-started
	for _, rq := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/audit/export?format=csv"},
		{http.MethodPost, "/api/v1/audit/verify"},
	} {
		rec := call(h, rq.method, rq.path, "admin", "")
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, rq.path)
		body := decodeErr(t, rec)
		assert.Equal(t, "ALC-AUD-0001", body.Error.Code)
		assert.Equal(t, "audit.busy", body.Error.Reason)
		assert.True(t, body.Error.Retryable)
		assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	}
	// M4: each busy refusal is recorded once per person, route and window (who keeps the slot busy
	// is visible to an administrator), as a denied verification or export.
	require.Equal(t, http.StatusServiceUnavailable, call(h, http.MethodGet, "/api/v1/audit/export?format=csv", "admin", "").Code)
	busy := exported(fa, audit.Denied)
	require.Len(t, busy, 1, "a repeated busy refusal is coalesced")
	assert.Equal(t, map[string]string{"format": "csv", "method": "GET", "path": "/api/v1/audit/export", "reason": "busy"}, busy[0].Details)
	assert.Equal(t, adminID, busy[0].Actor.ID)
	verifies := 0
	for _, e := range fa.Events() {
		if e.Action == "audit.verified" && e.Result == audit.Denied && e.Details["reason"] == "busy" {
			verifies++
		}
	}
	assert.Equal(t, 1, verifies)
	close(release)
	assert.Equal(t, http.StatusOK, <-first)
	assert.Len(t, exported(fa, audit.Success), 1, "a refused export is not recorded as an export")
	assert.Equal(t, http.StatusOK, call(h, http.MethodPost, "/api/v1/audit/verify", "admin", "").Code, "the slot is free again")
}

// I3: StopScans ends a running verification at once and frees the slot; the answer is 503
// (retryable), and later scans end the same way.
func TestStopScansEndsARunningScan(t *testing.T) {
	d := testDeps(t, nil)
	fa := d.Audit.(*fakeAudit)
	started := make(chan struct{})
	fa.VerifyFn = func(ctx context.Context, _ audit.Actor) (audit.Report, error) {
		close(started)
		<-ctx.Done() // a scan that would otherwise run for its full 10 minutes
		return audit.Report{}, ctx.Err()
	}
	srv := New(d)
	h := srv.Handler()
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- call(h, http.MethodPost, "/api/v1/audit/verify", "admin", "") }()
	<-started
	srv.StopScans()
	select {
	case rec := <-done:
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "ALC-SYS-0002", decodeErr(t, rec).Error.Code)
		assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	case <-time.After(time.Second):
		t.Fatal("the verification did not end within a second of StopScans")
	}
	select {
	case srv.s.chainScan <- struct{}{}:
		<-srv.s.chainScan
	default:
		t.Fatal("the slot was not freed")
	}
}

// I3: an export cut by StopScans after its first byte is aborted (a failed download), and the slot
// is freed.
func TestStopScansAbortsAStartedExport(t *testing.T) {
	d, fa := exportDeps(t)
	srv := New(d)
	fa.IterateFn = func(ctx context.Context, fn func(audit.Entry) error) error {
		require.NoError(t, fn(sampleEntries()[0]))
		srv.StopScans()
		<-ctx.Done()
		return ctx.Err()
	}
	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		call(srv.Handler(), http.MethodGet, "/api/v1/audit/export?format=csv", "admin", "")
	})
	select {
	case srv.s.chainScan <- struct{}{}:
	default:
		t.Fatal("the slot was not freed")
	}
}

// The export's scans and writes are bounded by its own 10-minute limit, not the request's.
func TestExportRunsUnderItsOwnDeadline(t *testing.T) {
	d, fa := exportDeps(t)
	var left time.Duration
	fa.VerifyReadOnlyFn = func(ctx context.Context) (audit.Report, error) {
		dl, ok := ctx.Deadline()
		require.True(t, ok)
		left = time.Until(dl)
		return intactReport(), nil
	}
	require.Equal(t, http.StatusOK, call(NewHandler(d), http.MethodGet, "/api/v1/audit/export?format=csv", "admin", "").Code)
	assert.Greater(t, left, 9*time.Minute)
	assert.LessOrEqual(t, left, chainScanTimeout)
	assert.Equal(t, 10*time.Minute, chainScanTimeout)
}

func TestExportJSON(t *testing.T) {
	d, _ := exportDeps(t)
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/audit/export?format=json", "admin", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	var body struct {
		Verification auditReportDTO  `json:"verification"`
		Entries      []auditEntryDTO `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.True(t, body.Verification.Intact)
	require.Len(t, body.Entries, 2)
	assert.Equal(t, "=HYPERLINK(\"http://evil\")", body.Entries[1].ActorName, "JSON keeps values verbatim")
	assert.Nil(t, body.Entries[1].ActorID)
}

func TestExportRejectsUnknownFormatAndStopsWhenAuditFails(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	rec := call(h, http.MethodGet, "/api/v1/audit/export?format=xlsx", "admin", "")
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	d := testDeps(t, nil)
	d.Audit = failingWriteAudit{fakeAudit: &fakeAudit{VerifyReadOnlyFn: func(context.Context) (audit.Report, error) { return intactReport(), nil }}}
	rec = call(NewHandler(d), http.MethodGet, "/api/v1/audit/export?format=csv", "admin", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code, "no export without an audit record")
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
}

// failingWriteAudit is a fakeAudit whose Write always fails.
type failingWriteAudit struct{ *fakeAudit }

func (failingWriteAudit) Write(context.Context, audit.Event) error {
	return errors.New("database down")
}

// The audit export uses the shared formula-safe writer (Phase 7, Task 3): a hostile actor name is neutralised and the
// verification line still sits between the byte order mark and the header.
func TestAuditCSVUsesCsvx(t *testing.T) {
	report := audit.Report{Intact: true, Checked: 1, HeadSeq: 1, HeadHash: []byte{1}}
	fa := &fakeAudit{IterateFn: func(_ context.Context, fn func(audit.Entry) error) error {
		return fn(audit.Entry{Seq: 1, ActorType: audit.ActorUser, ActorName: "=HYPERLINK(\"x\")", Action: "auth.login",
			Result: audit.Success, Hash: []byte{1}})
	}}
	s := newServer(Deps{Audit: fa})
	rec := httptest.NewRecorder()
	require.NoError(t, s.writeAuditCSV(context.Background(), rec, report))
	body := rec.Body.String()
	assert.True(t, strings.HasPrefix(body, "\xEF\xBB\xBF# alice audit export: intact=true"), body)
	assert.Contains(t, body, "\nseq,at,actor_type,")
	assert.Contains(t, body, `"'=HYPERLINK(""x"")"`)
}
