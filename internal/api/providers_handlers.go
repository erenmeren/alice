package api

import (
	"net/http"

	"alice/internal/rbac"
)

// providerRoutes describe the compiled-in providers for the add-server form (§6.4, §9.6).
func (s *server) providerRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/providers", perm: rbac.Read, handler: s.listProviders},
	}
}

func (s *server) listProviders(w http.ResponseWriter, _ *http.Request) {
	items := []providerDTO{}
	if s.deps.Providers != nil {
		for _, d := range s.deps.Providers.List() {
			items = append(items, providerJSON(d))
		}
	}
	writeJSON(w, http.StatusOK, map[string][]providerDTO{"items": items})
}
