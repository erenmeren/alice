package api

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// auditRoutes expose the audit log to Administrators and Auditors (SEC-070..075).
func (s *server) auditRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/audit", perm: rbac.AuditRead, handler: s.listAudit},
		{method: http.MethodGet, pattern: "/api/v1/audit/export", perm: rbac.AuditRead, handler: s.exportAudit},
		{method: http.MethodPost, pattern: "/api/v1/audit/verify", perm: rbac.AuditRead, lic: license.ClassAlways, handler: s.verifyAudit},
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

func (s *server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	report, err := s.deps.Audit.Verify(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, auditReportJSON(report))
}

// exportAudit streams the whole log as CSV or JSON (SEC-075): the chain is
// verified first (read-only: no checkpoint, no audit.verified row), the export itself is audited before any entry leaves, and
// the verification result travels with the file.
func (s *server) exportAudit(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "json" {
		var v validate.Errors
		v.Add("format", validate.OneOf, map[string]string{"values": "csv, json"})
		s.fail(w, r, v)
		return
	}
	m := s.meta(r)
	actor := principalFrom(r.Context()).Actor(m)
	report, err := s.deps.Audit.VerifyReadOnly(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = s.deps.Audit.Write(r.Context(), audit.Event{
		Actor: actor, Action: "audit.exported", Result: audit.Success,
		Details: map[string]string{"format": format, "intact": strconv.FormatBool(report.Intact)},
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Alice-Audit-Intact", strconv.FormatBool(report.Intact))
	h.Set("Content-Disposition", `attachment; filename="alice-audit-`+s.deps.Clock.Now().UTC().Format("2006-01-02")+"."+format+`"`)
	if format == "csv" {
		h.Set("Content-Type", "text/csv; charset=utf-8")
		err = s.writeAuditCSV(w, r)
	} else {
		h.Set("Content-Type", "application/json; charset=utf-8")
		err = s.writeAuditJSON(w, r, report)
	}
	if err != nil {
		// Headers are already sent: log and abort so the client sees a broken
		// download instead of a file that looks complete.
		s.deps.Log.Error("audit export failed", append([]any{"request_id", m.RequestID}, errorAttrs(err)...)...)
		panic(http.ErrAbortHandler)
	}
}

func (s *server) writeAuditCSV(w http.ResponseWriter, r *http.Request) error {
	if _, err := w.Write([]byte("\xEF\xBB\xBF")); err != nil { // BOM so spreadsheet tools read UTF-8 (spec §10.5)
		return err
	}
	cw := csv.NewWriter(w)
	header := []string{"seq", "at", "actor_type", "actor_id", "actor_name", "ip", "action", "object_type", "object_id", "result", "details", "request_id", "hash"}
	if err := cw.Write(header); err != nil {
		return err
	}
	err := s.deps.Audit.Iterate(r.Context(), func(e audit.Entry) error {
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
		for i := range rec {
			rec[i] = csvSafe(rec[i])
		}
		return cw.Write(rec)
	})
	if err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe neutralises spreadsheet formula injection: a cell that starts with
// = + - @ TAB or CR is prefixed with an apostrophe.
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

func (s *server) writeAuditJSON(w http.ResponseWriter, r *http.Request, report audit.Report) error {
	head, err := json.Marshal(auditReportJSON(report))
	if err != nil {
		return err
	}
	if _, err := w.Write(append(append([]byte(`{"verification":`), head...), []byte(`,"entries":[`)...)); err != nil {
		return err
	}
	first := true
	err = s.deps.Audit.Iterate(r.Context(), func(e audit.Entry) error {
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
