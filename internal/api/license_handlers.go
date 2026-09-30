package api

import (
	"net/http"

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

// decodeLicense reads a license upload body; on failure it has answered the request.
func (s *server) decodeLicense(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	var req licenseUpload
	if !s.decodeLimit(w, r, &req, license.MaxFileSize) {
		return nil, false
	}
	return []byte(req.License), true
}

// licensePreview checks a file and says what uploading it would do, storing nothing (§19.1).
func (s *server) licensePreview(w http.ResponseWriter, r *http.Request) {
	raw, ok := s.decodeLicense(w, r)
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
	raw, ok := s.decodeLicense(w, r)
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
