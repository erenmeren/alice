package api

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// certificateRoutes are the certificate inventory, uploads, signing requests and deployment
// requests (contract "API", R38). Every change is ClassChange: refused in lock by the guard before
// the body is read (R38 item 9). Uploads, signing requests and deploy requests need
// certificates.operate (Admin and Operator, operate tokens; R38 item 12); reads need read.
func (s *server) certificateRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/certificates", scope: scopeList, perm: rbac.Read, handler: s.listCertificates},
		{method: http.MethodGet, pattern: "/api/v1/certificates/{id}", scope: scopeResource, resolve: by(services.KindCertificate, "id"), perm: rbac.Read, handler: s.getCertificate},
		// Phase 7 (C13): the list as a CSV file, with the list's filters; a read, so it works in lock.
		{method: http.MethodGet, pattern: "/api/v1/certificates/export", scope: scopeList, perm: rbac.Read, limit: limitExport, getOnly: true,
			handler: s.exportCertificates},
		{method: http.MethodPost, pattern: "/api/v1/certificates/upload", scope: scopeCreate, perm: rbac.CertificatesOperate, lic: license.ClassChange, handler: s.uploadCertificate},
		{method: http.MethodPost, pattern: "/api/v1/certificates/{id}/deploy", scope: scopeCross, resolve: by(services.KindCertificate, "id"), perm: rbac.CertificatesOperate, lic: license.ClassChange, handler: s.deployCertificate},
		{method: http.MethodGet, pattern: "/api/v1/certificates/csr", scope: scopeList, perm: rbac.Read, handler: s.listCSRs},
		{method: http.MethodPost, pattern: "/api/v1/certificates/csr", scope: scopeCreate, perm: rbac.CertificatesOperate, lic: license.ClassChange, handler: s.createCSR},
		{method: http.MethodGet, pattern: "/api/v1/certificates/csr/{id}", scope: scopeResource, resolve: by(services.KindCSR, "id"), perm: rbac.Read, handler: s.getCSR},
		{method: http.MethodPost, pattern: "/api/v1/certificates/csr/{id}/actions/complete", scope: scopeResource, resolve: by(services.KindCSR, "id"), perm: rbac.CertificatesOperate, lic: license.ClassChange,
			handler: s.completeCSR},
		{method: http.MethodPost, pattern: "/api/v1/certificates/csr/{id}/actions/cancel", scope: scopeResource, resolve: by(services.KindCSR, "id"), perm: rbac.CertificatesOperate, lic: license.ClassChange,
			handler: s.cancelCSR},
	}
}

// locationRoutes change a certificate location's verification settings (R38 item 6): an
// Administrator's decision (targets.manage), refused in lock. A target's locations are listed under
// GET /targets/{id}/certificate-locations.
func (s *server) locationRoutes() []route {
	return []route{
		{method: http.MethodPatch, pattern: "/api/v1/locations/{id}", scope: scopeResource, resolve: by(services.KindLocation, "id"), perm: rbac.TargetsManage, lic: license.ClassChange, handler: s.updateLocation},
	}
}

// Body caps of the Phase 4 changes (SEC-023). A certificate, a key and a PFX file are each at most
// 256 KiB (internal/certs MaxInputSize; a PFX in base64 is about 342 KiB, more with line breaks),
// and JSON escapes every line break as two bytes: an upload fits in 768 KiB, a signing request's
// certificate in 384 KiB. A larger body is refused unread with ALC-SYS-0007 (413).
const (
	maxUploadBody      = 768 << 10
	maxCSRCompleteBody = 384 << 10
	maxCSRBody         = 32 << 10 // a common name, at most 50 names and a key type
	maxDeployBody      = 8 << 10  // at most 20 ids
	maxLocationBody    = 4 << 10
	maxCancelBody      = 4 << 10 // empty or {}
)

// certificateSources and expiryWindows are the list filter's values, the same as the inventory's (Task 10: the Key
// Vault source and the 7, 14 and 90 day windows; B5).
var (
	certificateSources = []string{"discovered", "uploaded", "csr", "azure_kv", "acme"}
	expiryWindows      = []string{"expired", "7", "14", "30", "60", "90"}
)

func (s *server) listCertificates(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	f, ok := s.certificateFilter(w, r, true)
	if !ok {
		return
	}
	page, err := s.deps.Inventory.ListCertificates(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]certificateDTO, 0, len(page.Items))
	for _, c := range page.Items {
		items = append(items, certificateJSON(c, refs))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(page.NextCursor)})
}

// certificateFilter reads the certificate list's filters: the list (paged) and its export, which is never a page and
// refuses cursor and limit. It answers 422 itself.
func (s *server) certificateFilter(w http.ResponseWriter, r *http.Request, paged bool) (inventory.CertificateFilter, bool) {
	q := r.URL.Query()
	var v validate.Errors
	f := inventory.CertificateFilter{
		TargetID: optionalUUID(q.Get("target_id"), "target_id", &v),
		Source:   q.Get("source"),
		Query:    q.Get("q"),
		Expiry:   q.Get("expiry"),
	}
	f.ServiceIDs = s.serviceFilter(r, &v) // R49: service_id and environment_id
	f.Reach = s.reachOf(r, rbac.Read)     // R49 Phase 2: the certificates the caller sees
	if paged {
		f.Cursor, f.Limit = q.Get("cursor"), pageLimit(q.Get("limit"), &v)
	} else {
		refusePaging(q, &v)
	}
	if f.Source != "" && !slices.Contains(certificateSources, f.Source) {
		v.Add("source", validate.OneOf, map[string]string{"values": strings.Join(certificateSources, ", ")})
	}
	if f.Expiry != "" && !slices.Contains(expiryWindows, f.Expiry) {
		v.Add("expiry", validate.OneOf, map[string]string{"values": strings.Join(expiryWindows, ", ")})
	}
	if utf8.RuneCountInString(f.Query) > maxQueryRunes {
		v.Add("q", validate.TooLong, map[string]string{"max": strconv.Itoa(maxQueryRunes)})
	}
	if len(f.Cursor) > maxCursorBytes {
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return inventory.CertificateFilter{}, false
	}
	return f, true
}

// nextCursor is a list's next_cursor: null on the last page.
func nextCursor(c string) any {
	if c == "" {
		return nil
	}
	return c
}

func (s *server) getCertificate(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	c, err := s.deps.Inventory.GetCertificate(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	target := func(l inventory.CertificateLocation) uuid.UUID { return l.TargetID }
	seen, err := s.targetsSeen(r, targetIDsOf(c.Locations, target))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var hidden int
	c.Locations, hidden = keepSeen(c.Locations, target, seen) // R49 Phase 2: the locations on the caller's servers
	d := certificateDetailJSON(c, refs)
	d.HiddenCount = hidden
	writeJSON(w, http.StatusOK, d)
}

// uploadResult is what an upload or a signing request's completion answers: the certificate as
// stored (public data only) and the warnings that did not block it.
type uploadResult struct {
	Certificate certificateDetailDTO `json:"certificate"`
	Warnings    []string             `json:"warnings"`
}

// uploadCertificate stores a certificate with its private key (PEM fields, or a PFX file in base64
// with its password). The request body is the only place the key and the password appear: it is
// size-capped before decoding, never logged, decoded into a local value that is not used after the
// service call, and the answer is built from the stored certificate, which carries no key
// material. A duplicate is refused (ALC-CRT-0008), except an upload of a held certificate with a
// complete chain where Alice's is incomplete: the chain is completed (200, warning chain_completed). When the certificate was stored but could not be
// read back, the request fails; sending it again is then refused as a duplicate, and the
// certificate is in the list.
func (s *server) uploadCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label          string `json:"label"`
		CertificatePEM string `json:"certificate_pem"`
		PrivateKeyPEM  string `json:"private_key_pem"`
		PFXBase64      string `json:"pfx_base64"`
		PFXPassword    string `json:"pfx_password"`
		// ServiceID is the service the new resource goes to (R49; absent: the Default service). Changes never take it:
		// a resource moves only by POST /api/v1/services/{id}/actions/assign.
		ServiceID *uuid.UUID `json:"service_id"`
	}
	if !s.decodeExact(w, r, &req, maxUploadBody, "label", "certificate_pem", "private_key_pem", "pfx_base64", "pfx_password", "service_id") {
		return
	}
	c, warnings, err := s.deps.Inventory.UploadCertificate(r.Context(), s.actor(r), inventory.UploadInput{
		CertificatePEM: req.CertificatePEM, PrivateKeyPEM: req.PrivateKeyPEM, PFXBase64: req.PFXBase64, PFXPassword: req.PFXPassword,
		Label: req.Label, ServiceID: derefOr(req.ServiceID, uuid.Nil),
	})
	s.writeUpload(w, r, c, warnings, err)
}

// writeUpload answers an upload or a signing request's completion: 201 with Location for a stored
// certificate, 200 when an upload only completed the chain of a certificate Alice already held
// (warning chain_completed).
func (s *server) writeUpload(w http.ResponseWriter, r *http.Request, c inventory.Certificate, warnings []string, err error) {
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := http.StatusCreated
	if slices.Contains(warnings, inventory.WarnChainCompleted) {
		status = http.StatusOK
	} else {
		w.Header().Set("Location", "/api/v1/certificates/"+c.ID.String())
	}
	writeJSON(w, status, uploadResult{Certificate: certificateDetailJSON(c, s.serviceRefs(r)), Warnings: nonNil(warnings)})
}

func (s *server) deployCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		LocationIDs            []string `json:"location_ids"`
		ConfirmIncompleteChain bool     `json:"confirm_incomplete_chain"`
	}
	if !s.decodeExact(w, r, &req, maxDeployBody, "location_ids", "confirm_incomplete_chain") {
		return
	}
	var v validate.Errors
	ids := make([]uuid.UUID, 0, len(req.LocationIDs))
	switch n := len(req.LocationIDs); {
	case n < 1 || n > inventory.MaxDeployLocations:
		v.Add("location_ids", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(inventory.MaxDeployLocations)})
	default:
		for _, raw := range req.LocationIDs {
			lid, err := uuid.Parse(raw)
			if err != nil || lid == uuid.Nil {
				v.Add("location_ids", validate.Pattern, nil)
				break
			}
			if slices.Contains(ids, lid) {
				v.Add("location_ids", validate.Duplicate, nil)
				break
			}
			ids = append(ids, lid)
		}
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	// confirm_incomplete_chain is passed on as sent: the inventory counts it for an Administrator
	// only (F-17) and refuses an Operator's incomplete chain with ALC-CRT-0011.
	got, err := s.deps.Inventory.RequestDeployment(r.Context(), s.actor(r), inventory.DeployRequestInput{
		CertificateID: id, LocationIDs: ids, ConfirmIncompleteChain: req.ConfirmIncompleteChain,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]requestedDeploymentDTO, 0, len(got))
	for _, d := range got {
		items = append(items, requestedDeploymentJSON(d))
	}
	writeJSON(w, http.StatusAccepted, map[string][]requestedDeploymentDTO{"deployments": items})
}

func (s *server) listCSRs(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	var v validate.Errors
	filter := s.serviceFilter(r, &v) // R49: service_id and environment_id
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	csrs, err := s.deps.Inventory.ListCSRsIn(r.Context(), s.reachOf(r, rbac.Read))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]csrDTO, 0, len(csrs))
	for _, c := range csrs {
		if inServices(filter, c.ServiceID) {
			items = append(items, csrJSON(c, refs))
		}
	}
	writeJSON(w, http.StatusOK, map[string][]csrDTO{"items": items})
}

func (s *server) createCSR(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	var req struct {
		CommonName string   `json:"common_name"`
		SANs       []string `json:"sans"`
		KeyType    string   `json:"key_type"`
		// ServiceID is the service the new resource goes to (R49; absent: the Default service). Changes never take it:
		// a resource moves only by POST /api/v1/services/{id}/actions/assign.
		ServiceID *uuid.UUID `json:"service_id"`
	}
	if !s.decodeExact(w, r, &req, maxCSRBody, "common_name", "sans", "key_type", "service_id") {
		return
	}
	// The name rules (a DNS name, at most 64 characters; at most 50 names) and the key types are
	// the inventory's.
	c, err := s.deps.Inventory.CreateCSR(r.Context(), s.actor(r), inventory.CSRInput{CommonName: req.CommonName, SANs: req.SANs, KeyType: req.KeyType,
		ServiceID: derefOr(req.ServiceID, uuid.Nil)})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/certificates/csr/"+c.ID.String())
	writeJSON(w, http.StatusCreated, csrJSON(c, refs))
}

func (s *server) getCSR(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	c, err := s.deps.Inventory.GetCSR(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, csrJSON(c, refs))
}

// completeCSR stores the certificate a CA signed for a pending request (with the request's key,
// which Alice generated and never hands out). Same answer as an upload.
func (s *server) completeCSR(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		CertificatePEM string `json:"certificate_pem"`
		Label          string `json:"label"`
	}
	if !s.decodeExact(w, r, &req, maxCSRCompleteBody, "certificate_pem", "label") {
		return
	}
	c, warnings, err := s.deps.Inventory.CompleteCSR(r.Context(), s.actor(r), id, req.CertificatePEM, req.Label)
	s.writeUpload(w, r, c, warnings, err)
}

func (s *server) cancelCSR(w http.ResponseWriter, r *http.Request) {
	refs := s.serviceRefs(r)
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct{} // no fields: an empty body or {}
	if !s.decodeOptionalLimit(w, r, &req, maxCancelBody) {
		return
	}
	c, err := s.deps.Inventory.CancelCSR(r.Context(), s.actor(r), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, csrJSON(c, refs))
}

// listTargetLocations lists a server's certificate locations (in use first; missing ones with
// ?missing=true), at most 1000: truncated says when some were left out.
func (s *server) listTargetLocations(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var v validate.Errors
	missing := parseBool(r.URL.Query().Get("missing"), "missing", &v)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.deps.Inventory.ListLocations(r.Context(), id, missing)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]locationDTO, 0, len(list.Items))
	for _, l := range list.Items {
		items = append(items, locationJSON(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "truncated": list.Truncated})
}

// updateLocation changes a location's verification settings. If-Match must name the version the
// caller read (a strong validator, as for PATCH /targets/{id}); the answer carries the new ETag.
func (s *server) updateLocation(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	version, ok := ifMatch(r)
	if !ok {
		s.writeError(w, r, ErrPreconditionFailed)
		return
	}
	var req struct {
		VerifyPort *int    `json:"verify_port"`
		VerifySNI  *string `json:"verify_sni"`
		SkipVerify *bool   `json:"skip_verify"`
	}
	if !s.decodeExact(w, r, &req, maxLocationBody, "verify_port", "verify_sni", "skip_verify") {
		return
	}
	// The value rules (port 0..65535 with 0 clearing, a DNS name or "" for the name, at least one
	// field) are the inventory's.
	l, err := s.deps.Inventory.UpdateLocation(r.Context(), s.actor(r), id, version,
		inventory.LocationPatch{VerifyPort: req.VerifyPort, VerifySNI: req.VerifySNI, SkipVerify: req.SkipVerify})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(l.Version))
	writeJSON(w, http.StatusOK, locationJSON(l))
}
