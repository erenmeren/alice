package api

import (
	"net/http"
	"net/url"

	"alice/internal/platform/validate"
)

// csvResponse sets the download headers when the first byte is written (R42 row 16): until then nothing is sent and a
// refusal (ALC-RPT-0001, a validation error) is an ordinary JSON error.
type csvResponse struct {
	w       http.ResponseWriter
	name    string
	started bool
}

func (c *csvResponse) Write(p []byte) (int, error) {
	if !c.started {
		c.started = true
		h := c.w.Header()
		h.Set("Content-Type", "text/csv; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="`+c.name+`"`)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		c.w.WriteHeader(http.StatusOK)
	}
	return c.w.Write(p)
}

// refusePaging refuses cursor and limit on an export: an export is the whole list for its filters, never a page.
func refusePaging(q url.Values, v *validate.Errors) {
	for _, k := range []string{"cursor", "limit"} {
		if q.Has(k) {
			v.Add(k, validate.Pattern, nil)
		}
	}
}

// exportName is the file name of an export made today (UTC).
func (s *server) exportName(kind string) string {
	return "alice-" + kind + "-" + s.deps.Clock.Now().UTC().Format("2006-01-02") + ".csv"
}

// exportCertificates streams the certificate list for the list's filters as CSV (C9, R42 row 16). The service refuses
// more than reports.MaxExportRows rows before anything is written or audited, and one export at a time per user.
func (s *server) exportCertificates(w http.ResponseWriter, r *http.Request) {
	f, ok := s.certificateFilter(w, r, false)
	if !ok {
		return
	}
	out := &csvResponse{w: w, name: s.exportName("certificates")}
	_, err := s.deps.Reports.ExportCertificates(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), f, out)
	s.endExport(w, r, out, err)
}

// exportSSHKeys is exportCertificates for the SSH key list.
func (s *server) exportSSHKeys(w http.ResponseWriter, r *http.Request) {
	f, ok := s.sshKeyFilter(w, r, false)
	if !ok {
		return
	}
	out := &csvResponse{w: w, name: s.exportName("ssh-keys")}
	_, err := s.deps.Reports.ExportSSHKeys(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), f, out)
	s.endExport(w, r, out, err)
}

// endExport answers an export's error: before the first byte as a JSON error; after it, never by ending a cut file as
// if it were complete — the connection is aborted.
func (s *server) endExport(w http.ResponseWriter, r *http.Request, out *csvResponse, err error) {
	if err == nil {
		return
	}
	if out.started {
		s.deps.Log.Error("inventory export failed", append([]any{"request_id", RequestID(r.Context())}, errorAttrs(err)...)...)
		panic(http.ErrAbortHandler)
	}
	s.fail(w, r, err)
}
