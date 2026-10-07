package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/google/uuid"

	"alice/internal/auth/oidc"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// ssoRoutes are the single sign-on administration (C13, Phase 7): identity providers, group mappings and the "SSO users
// may be Admin" switch. Every one is sso.manage (an Administrator's browser session with step-up, never an API token;
// SEC-009) and works in lock (platform administration, ClassAlways).
func (s *server) ssoRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/sso/providers", perm: rbac.SSOManage, handler: s.listSSOProviders},
		{method: http.MethodPost, pattern: "/api/v1/sso/providers", perm: rbac.SSOManage, lic: license.ClassAlways, handler: s.createSSOProvider},
		{method: http.MethodGet, pattern: "/api/v1/sso/providers/{id}", perm: rbac.SSOManage, handler: s.getSSOProvider},
		{method: http.MethodPatch, pattern: "/api/v1/sso/providers/{id}", perm: rbac.SSOManage, lic: license.ClassAlways, handler: s.updateSSOProvider},
		{method: http.MethodDelete, pattern: "/api/v1/sso/providers/{id}", perm: rbac.SSOManage, lic: license.ClassAlways, handler: s.deleteSSOProvider},
		{method: http.MethodPost, pattern: "/api/v1/sso/providers/{id}/actions/refresh", perm: rbac.SSOManage, lic: license.ClassAlways,
			handler: s.refreshSSOProvider},
		{method: http.MethodGet, pattern: "/api/v1/sso/group-mappings", perm: rbac.SSOManage, handler: s.listSSOMappings},
		{method: http.MethodPost, pattern: "/api/v1/sso/group-mappings", perm: rbac.SSOManage, lic: license.ClassAlways, handler: s.createSSOMapping},
		{method: http.MethodDelete, pattern: "/api/v1/sso/group-mappings/{id}", perm: rbac.SSOManage, lic: license.ClassAlways,
			handler: s.deleteSSOMapping},
		{method: http.MethodGet, pattern: "/api/v1/sso/settings", perm: rbac.SSOManage, handler: s.getSSOSettings},
		{method: http.MethodPut, pattern: "/api/v1/sso/settings", perm: rbac.SSOManage, lic: license.ClassAlways, handler: s.putSSOSettings},
	}
}

// maxProviderBody caps a provider: a CA bundle of at most 64 KiB, JSON-escaped, and short fields.
const maxProviderBody = 160 << 10

var providerKeys = []string{"name", "issuer_url", "client_id", "client_secret", "scopes", "groups_claim", "ca_pem", "enabled"}

// opt is a field of a partial change: Set when the key was given. null is refused (400): every provider field has a value.
type opt[T any] struct {
	Set   bool
	Value T
}

var errNullField = errors.New("api: null is not a value of this field")

func (o *opt[T]) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		return errNullField
	}
	o.Set = true
	return json.Unmarshal(b, &o.Value)
}

func (o opt[T]) ptr() *T {
	if !o.Set {
		return nil
	}
	v := o.Value
	return &v
}

// providerBody is a provider's create or change body. client_secret is a secretText the handler zeroes on every path.
type providerBody struct {
	Name         opt[string]   `json:"name"`
	IssuerURL    opt[string]   `json:"issuer_url"`
	ClientID     opt[string]   `json:"client_id"`
	ClientSecret secretField   `json:"client_secret"`
	Scopes       opt[[]string] `json:"scopes"`
	GroupsClaim  opt[string]   `json:"groups_claim"`
	CAPEM        opt[string]   `json:"ca_pem"`
	Enabled      opt[bool]     `json:"enabled"`
}

func (b *providerBody) zero() { b.ClientSecret.zero() }

// secretField is a secretText that records whether the key was given and refuses null (400), as every other provider
// field does (review M-7). A value field: encoding/json calls UnmarshalJSON for null only on a non-pointer field.
type secretField struct {
	secretText
	set bool
}

func (f *secretField) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		return errNullField
	}
	f.set = true
	return f.secretText.UnmarshalJSON(b)
}

// failSSO answers a provider or mapping refusal; too many providers or mappings is a field error on field (C15).
func (s *server) failSSO(w http.ResponseWriter, r *http.Request, err error, field string, max int) {
	if errors.Is(err, oidc.ErrTooMany) {
		s.fail(w, r, validate.Errors{{Field: field, Code: validate.OutOfRange, Params: map[string]string{"min": "1", "max": strconv.Itoa(max)}}})
		return
	}
	s.fail(w, r, err)
}

func (s *server) writeProvider(w http.ResponseWriter, status int, p oidc.Provider) {
	w.Header().Set("ETag", etag(p.Version))
	writeJSON(w, status, identityProviderJSON(p))
}

func (s *server) listSSOProviders(w http.ResponseWriter, r *http.Request) {
	ps, err := s.deps.SSO.Providers(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]identityProviderDTO, 0, len(ps))
	for _, p := range ps {
		out = append(out, identityProviderJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// createSSOProvider adds an identity provider: the service reads its discovery document once and fixes its endpoints.
// A provider is created switched off unless the body says enabled true (secure by default; review M-1).
func (s *server) createSSOProvider(w http.ResponseWriter, r *http.Request) {
	var req providerBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxProviderBody, providerKeys...) {
		return
	}
	in := oidc.ProviderInput{Name: req.Name.Value, IssuerURL: req.IssuerURL.Value, ClientID: req.ClientID.Value, GroupsClaim: req.GroupsClaim.Value,
		CAPEM: req.CAPEM.Value, Enabled: req.Enabled.Value}
	if req.Scopes.Set {
		in.Scopes = req.Scopes.Value
	}
	if req.ClientSecret.set {
		in.ClientSecret = secrets.NewPlaintext(req.ClientSecret.secretText)
	}
	p, err := s.deps.SSO.CreateProvider(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), in)
	req.zero()
	if err != nil {
		s.failSSO(w, r, err, "name", oidc.MaxProviders)
		return
	}
	s.writeProvider(w, http.StatusCreated, p)
}

func (s *server) getSSOProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	p, err := s.deps.SSO.Provider(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeProvider(w, http.StatusOK, p)
}

// updateSSOProvider changes the given fields (If-Match required). A new issuer or CA bundle reads discovery again.
func (s *server) updateSSOProvider(w http.ResponseWriter, r *http.Request) {
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
	var req providerBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxProviderBody, providerKeys...) {
		return
	}
	patch := oidc.ProviderPatch{Name: req.Name.ptr(), IssuerURL: req.IssuerURL.ptr(), ClientID: req.ClientID.ptr(),
		GroupsClaim: req.GroupsClaim.ptr(), CAPEM: req.CAPEM.ptr(), Scopes: req.Scopes.ptr(), Enabled: req.Enabled.ptr()}
	if req.ClientSecret.set {
		secret := secrets.NewPlaintext(req.ClientSecret.secretText)
		patch.ClientSecret = &secret
	}
	p, err := s.deps.SSO.UpdateProvider(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), id, version, patch)
	req.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeProvider(w, http.StatusOK, p)
}

func (s *server) deleteSSOProvider(w http.ResponseWriter, r *http.Request) {
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
	if err := s.deps.SSO.DeleteProvider(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), id, version); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// refreshSSOProvider reads the provider's discovery document and key list again (If-Match required; empty body or {}).
func (s *server) refreshSSOProvider(w http.ResponseWriter, r *http.Request) {
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
	if !s.decodeExactOptional(w, r, &struct{}{}, maxActionBody) {
		return
	}
	p, err := s.deps.SSO.RefreshProvider(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), id, version)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeProvider(w, http.StatusOK, p)
}

// providerQuery reads the required ?provider_id of the mapping routes; it answers 422 itself.
func (s *server) providerQuery(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := r.URL.Query().Get("provider_id")
	var v validate.Errors
	id := optionalUUID(raw, "provider_id", &v)
	if raw == "" {
		v.Add("provider_id", validate.Required, nil)
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return uuid.Nil, false
	}
	return id, true
}

func (s *server) listSSOMappings(w http.ResponseWriter, r *http.Request) {
	providerID, ok := s.providerQuery(w, r)
	if !ok {
		return
	}
	ms, err := s.deps.SSO.Mappings(r.Context(), providerID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]mappingDTO, 0, len(ms))
	for _, m := range ms {
		out = append(out, mappingJSON(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// createSSOMapping gives the members of a group a role. Mapping a group to Administrator needs "SSO users may be
// Admin" switched on (409 ALC-SSO-0002).
func (s *server) createSSOMapping(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderID string `json:"provider_id"`
		Group      string `json:"group"`
		Role       string `json:"role"`
	}
	if !s.decodeExact(w, r, &req, maxActionBody, "provider_id", "group", "role") {
		return
	}
	var v validate.Errors
	providerID := optionalUUID(req.ProviderID, "provider_id", &v)
	if req.ProviderID == "" {
		v.Add("provider_id", validate.Required, nil)
	}
	role, ok := rbac.ParseRole(req.Role)
	if !ok {
		v.Add("role", validate.OneOf, map[string]string{"values": "admin, operator, auditor"})
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.deps.SSO.CreateMapping(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), providerID, req.Group, role)
	if err != nil {
		s.failSSO(w, r, err, "group", oidc.MaxMappings)
		return
	}
	writeJSON(w, http.StatusCreated, mappingJSON(m))
}

// deleteSSOMapping removes a group mapping of the provider named by ?provider_id. The service deletes by mapping alone,
// so the handler first checks that this provider holds it (another provider's mapping is not found; Task 12 review).
func (s *server) deleteSSOMapping(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	providerID, ok := s.providerQuery(w, r)
	if !ok {
		return
	}
	ms, err := s.deps.SSO.Mappings(r.Context(), providerID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !slices.ContainsFunc(ms, func(m oidc.Mapping) bool { return m.ID == id }) {
		s.writeError(w, r, ErrNotFound)
		return
	}
	if err := s.deps.SSO.DeleteMapping(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) getSSOSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.deps.SSO.Settings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(st.Version))
	writeJSON(w, http.StatusOK, ssoSettingsDTO{AllowAdminRole: st.AllowAdminRole, Version: st.Version})
}

// putSSOSettings switches "SSO users may be Admin" (If-Match required; "0" for the first save). Switching it off is
// refused while groups are mapped to Administrator (409 ALC-SSO-0003); it demotes SSO Administrators and ends their
// sessions.
func (s *server) putSSOSettings(w http.ResponseWriter, r *http.Request) {
	version, ok := s.settingsChange(w, r)
	if !ok {
		return
	}
	var req struct {
		AllowAdminRole opt[bool] `json:"allow_admin_role"`
	}
	if !s.decodeExact(w, r, &req, maxActionBody, "allow_admin_role") {
		return
	}
	if !req.AllowAdminRole.Set {
		// Never a silent switch-off, which would demote every SSO Administrator (review M-2).
		s.fail(w, r, validate.Errors{{Field: "allow_admin_role", Code: validate.Required}})
		return
	}
	st, err := s.deps.SSO.SaveSettings(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), version, req.AllowAdminRole.Value)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(st.Version))
	writeJSON(w, http.StatusOK, ssoSettingsDTO{AllowAdminRole: st.AllowAdminRole, Version: st.Version})
}
