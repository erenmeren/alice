package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/csvx"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// auditRoutes expose the audit log to Administrators and Auditors (SEC-070..075).
func (s *server) auditRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/audit", scope: scopePlatform, perm: rbac.AuditRead, handler: s.listAudit},
		{method: http.MethodGet, pattern: "/api/v1/audit/export", scope: scopePlatform, perm: rbac.AuditRead, getOnly: true, handler: s.exportAudit},
		{method: http.MethodPost, pattern: "/api/v1/audit/verify", scope: scopePlatform, perm: rbac.AuditRead, lic: license.ClassAlways, handler: s.verifyAudit},
	}
}

type auditEntryDTO struct {
	Seq        int64             `json:"seq"`
	At         time.Time         `json:"at"`
	ActorType  string            `json:"actor_type"`
	ActorID    *string           `json:"actor_id"`
	ActorName  string            `json:"actor_name"`
	IP         *string           `json:"ip"`
	Action     string            `json:"action"`
	ObjectType string            `json:"object_type"`
	ObjectID   string            `json:"object_id"`
	Result     string            `json:"result"`
	Details    map[string]string `json:"details"`
	RequestID  string            `json:"request_id"`
	Hash       string            `json:"hash"`
}

func auditEntryJSON(e audit.Entry) auditEntryDTO {
	d := auditEntryDTO{
		Seq: e.Seq, At: e.At.UTC(), ActorType: string(e.ActorType), ActorName: e.ActorName,
		Action: e.Action, ObjectType: e.ObjectType, ObjectID: e.ObjectID, Result: string(e.Result),
		Details: e.Details, RequestID: e.RequestID, Hash: hex.EncodeToString(e.Hash),
	}
	if e.ActorID != uuid.Nil {
		id := e.ActorID.String()
		d.ActorID = &id
	}
	if e.IP != "" {
		ip := e.IP
		d.IP = &ip
	}
	if d.Details == nil {
		d.Details = map[string]string{}
	}
	return d
}

type auditReportDTO struct {
	Intact      bool    `json:"intact"`
	Checked     int64   `json:"checked"`
	HeadSeq     int64   `json:"head_seq"`
	HeadHash    string  `json:"head_hash"`
	FirstBadSeq *int64  `json:"first_bad_seq"`
	Problem     *string `json:"problem"`
}

func auditReportJSON(r audit.Report) auditReportDTO {
	d := auditReportDTO{Intact: r.Intact, Checked: r.Checked, HeadSeq: r.HeadSeq, HeadHash: hex.EncodeToString(r.HeadHash)}
	if !r.Intact {
		seq, problem := r.FirstBadSeq, r.Problem
		d.FirstBadSeq, d.Problem = &seq, &problem
	}
	return d
}

func (s *server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := audit.Filter{Action: q.Get("action"), Actor: q.Get("actor"), Limit: 50}
	var v validate.Errors
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			v.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": "200"})
		}
		f.Limit = n
	}
	if raw := q.Get("cursor"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 {
			v.Add("cursor", validate.Pattern, nil)
		}
		f.BeforeSeq = n
	}
	switch res := audit.Result(q.Get("result")); res {
	case "", audit.Success, audit.Failure, audit.Denied:
		f.Result = res
	default:
		v.Add("result", validate.OneOf, map[string]string{"values": "success, failure, denied"})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	entries, next, err := s.deps.Audit.List(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]auditEntryDTO, 0, len(entries))
	for _, e := range entries {
		items = append(items, auditEntryJSON(e))
	}
	var cursor *string
	if next > 0 {
		c := strconv.FormatInt(next, 10)
		cursor = &c
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": cursor})
}

// chainScanTimeout bounds one verification or export through the API, and replaces the server's
// 60-second write limit for its response (AUD-06): a large log can take minutes to read and send.
const chainScanTimeout = 10 * time.Minute

// chainScanRetryAfter is the Retry-After of ErrAuditBusy, in seconds.
const chainScanRetryAfter = "30"

// scanChain runs fn in the process's one chain-scan slot. When another verification or export
// holds it, fn does not run, ErrAuditBusy (retryable) is answered and the refusal is recorded once
// per person (or token owner), route and window through the coalescer (M4): the action that was
// refused (audit.verified or audit.exported) with result denied and reason busy, so an
// administrator can see who keeps asking. The slot is per process; the scheduled audit.verify task
// and `alice audit verify` do not take it.
func (s *server) scanChain(w http.ResponseWriter, r *http.Request, refused audit.Event, rt route, fn func()) {
	select {
	case s.chainScan <- struct{}{}:
	default:
		s.auditBusy(r, refused, rt)
		w.Header().Set("Retry-After", chainScanRetryAfter)
		s.writeError(w, r, ErrAuditBusy)
		return
	}
	defer func() { <-s.chainScan }()
	fn()
}

// auditBusy records a verification or export refused because the chain-scan slot was taken.
func (s *server) auditBusy(r *http.Request, ev audit.Event, rt route) {
	p := principalFrom(r.Context())
	if p.Kind != rbac.UserSession && p.Kind != rbac.APIToken {
		return
	}
	ev.Details["method"], ev.Details["path"], ev.Details["reason"] = rt.method, rt.pattern, "busy"
	ev.Actor, ev.Result = s.denialActor(r, p, ev.Details), audit.Denied
	s.recordDenial(r, denialKey(p, string(rt.perm), "busy", rt), ev)
}

// scanContext is the context of one chain scan: the request's, for at most chainScanTimeout, and
// ended by StopScans at shutdown (I3), so a scan never holds the shutdown for its full length.
func (s *server) scanContext(r *http.Request) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(r.Context(), chainScanTimeout)
	stop := context.AfterFunc(s.scanCtx, cancel)
	return ctx, func() { stop(); cancel() }
}

// failScan answers a scan that failed before its first byte. A scan cut by StopScans is answered
// 503 (retryable): the server is stopping.
func (s *server) failScan(w http.ResponseWriter, r *http.Request, err error) {
	if s.scanCtx.Err() != nil {
		w.Header().Set("Retry-After", chainScanRetryAfter)
		s.writeError(w, r, ErrUnavailable)
		return
	}
	s.fail(w, r, err)
}

// StopScans ends every running audit verification and export of this server at once (I3). cmd/alice
// calls it at the start of shutdown, so the HTTP drain does not wait up to chainScanTimeout for
// them: a verification not yet answered gets 503 (retryable); an export whose file has started is
// aborted (the client sees a failed download, never a short file that looks complete). Their slot
// is freed. Later scans end at once the same way.
func (s *Server) StopScans() { s.s.stopScans() }

// extendWriteDeadline lets the response of a chain scan be written for up to chainScanTimeout
// instead of the server's WriteTimeout. It is an absolute network deadline, so it uses the real
// clock; a writer that cannot set one (httptest) keeps its own.
func extendWriteDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(clock.Real{}.Now().Add(chainScanTimeout))
}

var (
	exportRoute = route{method: http.MethodGet, pattern: "/api/v1/audit/export", scope: scopePlatform, perm: rbac.AuditRead}
	verifyRoute = route{method: http.MethodPost, pattern: "/api/v1/audit/verify", scope: scopePlatform, perm: rbac.AuditRead}
)

func (s *server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	extendWriteDeadline(w)
	ctx, cancel := s.scanContext(r)
	defer cancel()
	refused := audit.Event{Action: "audit.verified", ObjectType: "audit_log", Details: map[string]string{}}
	s.scanChain(w, r, refused, verifyRoute, func() {
		report, err := s.deps.Audit.Verify(ctx, principalFrom(r.Context()).Actor(s.meta(r)))
		if err != nil {
			s.failScan(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, auditReportJSON(report))
	})
}

// exportAudit streams the whole log as CSV or JSON (SEC-075): the chain is verified first
// (read-only: no checkpoint, no audit.verified row), the export itself is audited before any entry
// leaves, and the verification result travels with the file (the JSON's verification object, the
// CSV's first line, the X-Alice-Audit-Intact header). One verification or export runs at a time per
// process, for at most chainScanTimeout or until StopScans (AUD-06); entries are streamed, never
// collected.
func (s *server) exportAudit(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "json" {
		var v validate.Errors
		v.Add("format", validate.OneOf, map[string]string{"values": "csv, json"})
		s.fail(w, r, v)
		return
	}
	extendWriteDeadline(w)
	ctx, cancel := s.scanContext(r)
	defer cancel()
	refused := audit.Event{Action: "audit.exported", Details: map[string]string{"format": format}}
	s.scanChain(w, r, refused, exportRoute, func() { s.exportScanned(ctx, w, r, format) })
}

// exportScanned is exportAudit inside the chain-scan slot. Before the first byte it answers errors
// itself; after it, a failure aborts the response so the client sees a broken download instead of
// a file that looks complete.
func (s *server) exportScanned(ctx context.Context, w http.ResponseWriter, r *http.Request, format string) {
	m := s.meta(r)
	actor := principalFrom(r.Context()).Actor(m)
	report, err := s.deps.Audit.VerifyReadOnly(ctx)
	if err != nil {
		s.failScan(w, r, err)
		return
	}
	err = s.deps.Audit.Write(ctx, audit.Event{
		Actor: actor, Action: "audit.exported", Result: audit.Success,
		Details: map[string]string{"format": format, "intact": strconv.FormatBool(report.Intact)},
	})
	if err != nil {
		s.failScan(w, r, err)
		return
	}

	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Alice-Audit-Intact", strconv.FormatBool(report.Intact))
	h.Set("Content-Disposition", `attachment; filename="alice-audit-`+s.deps.Clock.Now().UTC().Format("2006-01-02")+"."+format+`"`)
	if format == "csv" {
		h.Set("Content-Type", "text/csv; charset=utf-8")
		err = s.writeAuditCSV(ctx, w, report)
	} else {
		h.Set("Content-Type", "application/json; charset=utf-8")
		err = s.writeAuditJSON(ctx, w, report)
	}
	if err != nil {
		s.deps.Log.Error("audit export failed", append([]any{"request_id", m.RequestID}, errorAttrs(err)...)...)
		panic(http.ErrAbortHandler) // the deferred release of the chain-scan slot still runs
	}
}

// csvVerificationLine is the CSV export's first line (after the BOM): the verification the JSON
// export carries, as a comment line (AUD-25 c). Every value is a number, a boolean, hex or a fixed
// problem label: nothing a user wrote.
func csvVerificationLine(report audit.Report) string {
	line := fmt.Sprintf("# alice audit export: intact=%t checked=%d head_seq=%d head_hash=%s",
		report.Intact, report.Checked, report.HeadSeq, hex.EncodeToString(report.HeadHash))
	if !report.Intact {
		line += fmt.Sprintf(" first_bad_seq=%d problem=%s", report.FirstBadSeq, report.Problem)
	}
	return line + "\n"
}

func (s *server) writeAuditCSV(ctx context.Context, w http.ResponseWriter, report audit.Report) error {
	cw, err := csvx.NewWriter(w) // writes the BOM so spreadsheet tools read UTF-8 (spec §10.5)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, csvVerificationLine(report)); err != nil {
		return err
	}
	header := []string{"seq", "at", "actor_type", "actor_id", "actor_name", "ip", "action", "object_type", "object_id", "result", "details", "request_id", "hash"}
	if err := cw.Write(header); err != nil {
		return err
	}
	err = s.deps.Audit.Iterate(ctx, func(e audit.Entry) error {
		d := auditEntryJSON(e)
		details, err := json.Marshal(d.Details)
		if err != nil {
			return err
		}
		actorID, ip := "", ""
		if d.ActorID != nil {
			actorID = *d.ActorID
		}
		if d.IP != nil {
			ip = *d.IP
		}
		rec := []string{
			strconv.FormatInt(d.Seq, 10), d.At.Format(time.RFC3339Nano), d.ActorType, actorID, d.ActorName, ip,
			d.Action, d.ObjectType, d.ObjectID, d.Result, string(details), d.RequestID, d.Hash,
		}
		return cw.Write(rec)
	})
	if err != nil {
		return err
	}
	return cw.Flush()
}

func (s *server) writeAuditJSON(ctx context.Context, w http.ResponseWriter, report audit.Report) error {
	head, err := json.Marshal(auditReportJSON(report))
	if err != nil {
		return err
	}
	if _, err := w.Write(append(append([]byte(`{"verification":`), head...), []byte(`,"entries":[`)...)); err != nil {
		return err
	}
	first := true
	err = s.deps.Audit.Iterate(ctx, func(e audit.Entry) error {
		b, err := json.Marshal(auditEntryJSON(e))
		if err != nil {
			return err
		}
		if !first {
			b = append([]byte{','}, b...)
		}
		first = false
		_, err = w.Write(b)
		return err
	})
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("]}\n"))
	return err
}
