package api

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/azureid"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// importRoutes import a certificate Alice holds, with its private key, into a vault (spec §11.8). A private key
// leaves Alice, so the request is credentials.manage: an Administrator with step-up, never a token (ruling S6).
// The history is read through the vault (the inventory scopes imports by vault).
func (s *server) importRoutes() []route {
	return []route{
		{method: http.MethodPost, pattern: "/api/v1/certificates/{id}/actions/import-to-key-vault", scope: scopeCross, resolve: by(services.KindCertificate, "id"), perm: rbac.CredentialsManage, lic: license.ClassChange,
			handler: s.importToVault},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/kv/imports", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.Read, handler: s.listImports},
		{method: http.MethodGet, pattern: "/api/v1/targets/{id}/kv/imports/{import_id}", scope: scopeResource, resolve: by(services.KindTarget, "id"), perm: rbac.Read, handler: s.getImport},
	}
}

func (s *server) importToVault(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		TargetID          string `json:"target_id"`
		Name              string `json:"name"`
		ConfirmNewVersion bool   `json:"confirm_new_version"`
	}
	if !s.decodeExact(w, r, &req, maxImportBody, "target_id", "name", "confirm_new_version") {
		return
	}
	var v validate.Errors
	vault, err := uuid.Parse(req.TargetID)
	if err != nil || vault == uuid.Nil {
		v.Add("target_id", validate.Pattern, nil)
	}
	if req.Name == "" {
		v.Add("name", validate.Required, nil)
	} else if !azureid.ValidObjectName(req.Name) {
		v.Add("name", validate.Pattern, nil)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	im, err := s.deps.Inventory.RequestImport(r.Context(), s.actor(r), inventory.ImportInput{
		VaultID: vault, CertificateID: id, Name: req.Name, ConfirmExisting: req.ConfirmNewVersion,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	job := uuid.Nil
	if im.JobID != nil {
		job = *im.JobID
	}
	a := accepted(job)
	writeJSON(w, http.StatusAccepted, map[string]any{"import": importJSON(im), "job_id": a.JobID, "status_url": a.StatusURL})
}

// listImports lists a vault's imports, newest first. certificate_id and certificate_name narrow the list in the
// inventory's query (before the limit) and next_cursor pages it (a cursor belongs to the vault it came from).
func (s *server) listImports(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	q := r.URL.Query()
	var v validate.Errors
	f := inventory.ImportFilter{CertificateID: optionalUUID(q.Get("certificate_id"), "certificate_id", &v), CertificateName: q.Get("certificate_name"),
		Cursor: q.Get("cursor"), Limit: pageLimit(q.Get("limit"), &v)}
	if len(f.Cursor) > maxCursorBytes {
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	page, err := s.deps.Inventory.ListImportsPage(r.Context(), id, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]importDTO, 0, len(page.Items))
	for _, im := range page.Items {
		items = append(items, importJSON(im))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(page.NextCursor)})
}

func (s *server) getImport(w http.ResponseWriter, r *http.Request) {
	vault, ok1 := pathUUID(r, "id")
	id, ok2 := pathUUID(r, "import_id")
	if !ok1 || !ok2 {
		s.writeError(w, r, ErrNotFound)
		return
	}
	im, err := s.deps.Inventory.Import(r.Context(), vault, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, importJSON(im))
}
