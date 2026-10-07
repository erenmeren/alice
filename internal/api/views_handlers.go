package api

import (
	"net/http"
	"slices"

	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/reports"
)

// viewRoutes are the saved views of the two list pages (C13, Phase 7): private to the signed-in person (session; API
// tokens have no use for them) and kept in lock (they change nothing outside Alice, ClassAlways).
func (s *server) viewRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/views", perm: rbac.Session, handler: s.listViews},
		{method: http.MethodPost, pattern: "/api/v1/views", perm: rbac.Session, lic: license.ClassAlways, handler: s.createView},
		{method: http.MethodDelete, pattern: "/api/v1/views/{id}", perm: rbac.Session, lic: license.ClassAlways, handler: s.deleteView},
	}
}

// viewPages are the pages a view belongs to (reports.Page*).
var viewPages = []string{reports.PageCertificates, reports.PageSSHKeys}

// maxViewBody caps a saved view: a name of 60 characters and at most five filters of 200 characters.
const maxViewBody = 8 << 10

func (s *server) listViews(w http.ResponseWriter, r *http.Request) {
	page := r.URL.Query().Get("page")
	switch {
	case page == "":
		s.fail(w, r, validate.Errors{{Field: "page", Code: validate.Required}})
		return
	case !slices.Contains(viewPages, page):
		s.fail(w, r, validate.Errors{{Field: "page", Code: validate.OneOf, Params: map[string]string{"values": reports.PageCertificates + ", " + reports.PageSSHKeys}}})
		return
	}
	views, err := s.deps.Reports.Views(r.Context(), principalFrom(r.Context()).UserID, page)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]viewDTO, 0, len(views))
	for _, v := range views {
		out = append(out, viewJSON(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// createView saves the current filters of a page under a name. The service checks the page, the name, the filter keys
// of the page and the 50-view limit.
func (s *server) createView(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Page  string            `json:"page"`
		Name  string            `json:"name"`
		Query map[string]string `json:"query"`
	}
	if !s.decodeExact(w, r, &req, maxViewBody, "page", "name", "query") {
		return
	}
	v, err := s.deps.Reports.CreateView(r.Context(), principalFrom(r.Context()).UserID, req.Page, req.Name, req.Query)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, viewJSON(v))
}

// deleteView removes one of the caller's views; another person's view is not found.
func (s *server) deleteView(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.Reports.DeleteView(r.Context(), principalFrom(r.Context()).UserID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
