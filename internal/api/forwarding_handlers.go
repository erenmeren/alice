package api

import (
	"net/http"

	"alice/internal/audit/forward"
	"alice/internal/license"
	"alice/internal/rbac"
)

// forwardingRoutes are audit forwarding to syslog (C12, Phase 8): the setting with its progress, a change, and a test
// message (rate limited like a download: it opens a connection). settings.manage, in lock too.
func (s *server) forwardingRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/settings/audit-forwarding", perm: rbac.SettingsManage, handler: s.getForwarding},
		{method: http.MethodPut, pattern: "/api/v1/settings/audit-forwarding", perm: rbac.SettingsManage, lic: license.ClassAlways,
			handler: s.putForwarding},
		{method: http.MethodPost, pattern: "/api/v1/settings/audit-forwarding/test", perm: rbac.SettingsManage, limit: limitForwardTest,
			lic: license.ClassAlways, handler: s.testForwarding},
	}
}

// maxForwardingBody caps a change: a CA bundle of at most 64 KiB, JSON-escaped.
const maxForwardingBody = 160 << 10

var forwardingKeys = []string{"enabled", "host", "port", "transport", "ca_pem"}

// forwardingBody is a change or a test: ca_pem absent keeps the stored CA bundle, "" removes it, a PEM replaces it
// (the bundle is write-only: answers carry ca_set).
type forwardingBody struct {
	Enabled   bool    `json:"enabled"`
	Host      string  `json:"host"`
	Port      int     `json:"port"`
	Transport string  `json:"transport"`
	CAPEM     *string `json:"ca_pem"`
}

func (b forwardingBody) settings() forward.Settings {
	in := forward.Settings{Enabled: b.Enabled, Host: b.Host, Port: b.Port, Transport: forward.Transport(b.Transport), CASet: b.CAPEM == nil}
	if b.CAPEM != nil {
		in.CAPEM = *b.CAPEM
	}
	return in
}

func (s *server) getForwarding(w http.ResponseWriter, r *http.Request) {
	set, st, err := s.deps.Forward.Settings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(set.Version))
	writeJSON(w, http.StatusOK, forwardingJSON(set, st))
}

func (s *server) putForwarding(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	var req forwardingBody
	if !s.decodeExact(w, r, &req, maxForwardingBody, forwardingKeys...) {
		return
	}
	if _, err := s.deps.Forward.Save(r.Context(), req.settings(), version, principalFrom(r.Context()).Actor(s.meta(r))); err != nil {
		s.fail(w, r, err)
		return
	}
	s.getForwarding(w, r)
}

// testForwarding sends one test message with the given settings (not saved): 204, or ALC-AUD-0002..0004.
func (s *server) testForwarding(w http.ResponseWriter, r *http.Request) {
	var req forwardingBody
	if !s.decodeExact(w, r, &req, maxForwardingBody, forwardingKeys...) {
		return
	}
	if err := s.deps.Forward.Test(r.Context(), req.settings()); err != nil {
		s.fail(w, r, err)
		return
	}
	noContent(w)
}
