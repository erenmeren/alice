package api

import (
	"net/http"
	"strconv"

	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// deploymentRoutes are the deployment history (R38 item 7): read-only, so they stay available in
// lock. A deployment is requested with POST /certificates/{id}/deploy; there is no retry or
// rollback operation (R38 item 13): a new request deploys again.
func (s *server) deploymentRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/deployments", scope: scopeList, perm: rbac.Read, handler: s.listDeployments},
		{method: http.MethodGet, pattern: "/api/v1/deployments/{id}", scope: scopeResource, resolve: by(services.KindDeployment, "id"), perm: rbac.Read, handler: s.getDeployment},
	}
}

func (s *server) listDeployments(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var v validate.Errors
	f := inventory.DeploymentFilter{
		TargetID:      optionalUUID(q.Get("target_id"), "target_id", &v),
		CertificateID: optionalUUID(q.Get("certificate_id"), "certificate_id", &v),
		LocationID:    optionalUUID(q.Get("location_id"), "location_id", &v),
		RolloutID:     optionalUUID(q.Get("rollout_id"), "rollout_id", &v),
		Cursor:        q.Get("cursor"),
		Limit:         pageLimit(q.Get("limit"), &v),
		Reach:         s.reachOf(r, rbac.Read), // R49 Phase 2: the deployments the caller sees
	}
	if len(f.Cursor) > maxCursorBytes {
		v.Add("cursor", validate.TooLong, map[string]string{"max": strconv.Itoa(maxCursorBytes)})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	page, err := s.deps.Inventory.ListDeployments(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]deploymentDTO, 0, len(page.Items))
	for _, d := range page.Items {
		items = append(items, deploymentJSON(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nextCursor(page.NextCursor)})
}

func (s *server) getDeployment(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	d, err := s.deps.Inventory.Deployment(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, deploymentDetailJSON(d))
}
