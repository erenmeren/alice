package api

import (
	"errors"
	"net/http"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/rbac"
)

// licenseRoutes serve the license status for every signed-in person (banners), the license
// page for Administrators and Auditors, and the upload for Administrators with step-up
// (spec §9.6, §19.1, §25.1). Uploading works in every license state (R9).
func (s *server) licenseRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/license/status", perm: rbac.Read, handler: s.licenseStatus},
		{method: http.MethodGet, pattern: "/api/v1/license", perm: rbac.LicenseRead, handler: s.licenseDetail},
		{method: http.MethodPost, pattern: "/api/v1/license/preview", perm: rbac.LicenseManage, lic: license.ClassAlways, handler: s.licensePreview},
		{method: http.MethodPost, pattern: "/api/v1/license", perm: rbac.LicenseManage, lic: license.ClassAlways, handler: s.licenseInstall},
	}
}

// licenseStatus answers from the in-memory snapshot: it never touches the database.
func (s *server) licenseStatus(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	snap := s.deps.License.Snapshot()
	if !snap.Ready {
		// Nothing has been evaluated yet (the service starts before the listener, so this is a
		// short window or a failed start): say "try again" rather than guess "not expired".
		w.Header().Set("Retry-After", "1")
		s.writeError(w, r, ErrUnavailable)
		return
	}
	out := licenseStatusDTO{Expired: snap.Eval.Expired(), Banners: bannersJSON(snap.Banners(p.Role == rbac.Admin))}
	if p.Role == rbac.Admin || p.Role == rbac.Auditor {
		phase := string(snap.Eval.Phase)
		out.Phase = &phase
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) licenseDetail(w http.ResponseWriter, r *http.Request) {
	d, err := s.deps.License.Detail(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, licenseDetailJSON(d))
}

// licenseUpload is the request body: the license file as text. The whole body is capped
// at the license size limit (64 KiB), so nothing larger is read, decoded or parsed; the
// license module checks the file itself again (spec §16.3).
type licenseUpload struct {
	License string `json:"license"`
}

// decodeLicense reads a license upload body; on failure it has answered the request. install is
// true for an upload (not a preview): a file refused at the edge because its text holds NUL is
// audited like any file the license module cannot read (S9).
func (s *server) decodeLicense(w http.ResponseWriter, r *http.Request, install bool) ([]byte, bool) {
	var req licenseUpload
	if err := readJSON(w, r, &req, license.MaxFileSize, false); err != nil {
		if install && errors.Is(err, errUnstorableText) {
			s.auditUnreadableLicense(r)
		}
		s.refuseBody(w, r, err)
		return nil, false
	}
	return []byte(req.License), true
}

// auditUnreadableLicense writes the row the license module writes for a file whose text holds NUL
// (license.upload.invalid, problem "not_json": a NUL byte is not valid JSON, and the module's
// structure check is the first to read past it), for an upload refused before the module saw it
// (S9, AUD-13; M3: one vocabulary with the module). The history row of the module is not written: no file reached it. Failures to write
// are logged, never shown to the caller.
func (s *server) auditUnreadableLicense(r *http.Request) {
	ev := audit.Event{
		Actor:      principalFrom(r.Context()).Actor(s.meta(r)),
		Action:     "license.upload.invalid", // "license.upload." + license.RejectReason of an *InvalidError
		ObjectType: "license",
		Result:     audit.Failure,
		Details:    map[string]string{"reason": "invalid", "problem": "not_json"},
	}
	if err := s.deps.Audit.Write(r.Context(), ev); err != nil {
		s.deps.Log.Error("audit write failed", append([]any{"request_id", RequestID(r.Context()), "action", ev.Action}, errorAttrs(err)...)...)
	}
}

// licensePreview checks a file and says what uploading it would do, storing nothing (§19.1).
func (s *server) licensePreview(w http.ResponseWriter, r *http.Request) {
	raw, ok := s.decodeLicense(w, r, false)
	if !ok {
		return
	}
	res, err := s.deps.License.Preview(r.Context(), raw)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, uploadResultJSON(res))
}

// licenseInstall stores a license and puts it into effect at once. The license module
// audits accepted and refused uploads; refusals answer with a fixed code and never echo the file.
func (s *server) licenseInstall(w http.ResponseWriter, r *http.Request) {
	raw, ok := s.decodeLicense(w, r, true)
	if !ok {
		return
	}
	p := principalFrom(r.Context())
	res, err := s.deps.License.Install(r.Context(), raw, p.Actor(s.meta(r)), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, uploadResultJSON(res))
}
