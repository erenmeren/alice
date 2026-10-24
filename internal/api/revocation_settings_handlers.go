package api

import (
	"context"
	"net/http"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/rbac"
)

// RevocationService is the revocation check switch (R64, D5; inventory.Service).
type RevocationService interface {
	RevocationSettings(ctx context.Context) (inventory.RevocationSettings, error)
	SaveRevocationSettings(ctx context.Context, a audit.Actor, version int, enabled bool) (inventory.RevocationSettings, error)
}

var _ RevocationService = (*inventory.Service)(nil)

// revocationSettingsRoutes are Settings, General: whether Alice asks the authorities about revocations (R64 Ruling 19).
// Settings are an Administrator's with a fresh step-up (settings.manage); a change works in every licence state.
func (s *server) revocationSettingsRoutes() []route {
	const path = "/api/v1/settings/revocation-checks"
	return []route{
		{method: http.MethodGet, pattern: path, scope: scopePlatform, perm: rbac.SettingsManage, handler: s.getRevocationSettings},
		{method: http.MethodPut, pattern: path, scope: scopePlatform, perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.putRevocationSettings},
	}
}

func (s *server) writeRevocationSettings(w http.ResponseWriter, set inventory.RevocationSettings) {
	w.Header().Set("ETag", etag(set.Version))
	writeJSON(w, http.StatusOK, map[string]any{"enabled": set.Enabled, "version": set.Version})
}

func (s *server) getRevocationSettings(w http.ResponseWriter, r *http.Request) {
	if s.deps.Revocation == nil {
		s.writeError(w, r, ErrUnavailable)
		return
	}
	set, err := s.deps.Revocation.RevocationSettings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeRevocationSettings(w, set)
}

// putRevocationSettings switches the check on or off; If-Match names the version read ("0": never saved).
func (s *server) putRevocationSettings(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	var req struct {
		Enabled opt[bool] `json:"enabled"`
	}
	if !s.decodeExact(w, r, &req, maxSettingsBody, "enabled") {
		return
	}
	if err := requireKeys(present{"enabled", req.Enabled.Set}); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.deps.Revocation == nil {
		s.writeError(w, r, ErrUnavailable)
		return
	}
	set, err := s.deps.Revocation.SaveRevocationSettings(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version, req.Enabled.Value)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeRevocationSettings(w, set)
}
