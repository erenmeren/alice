package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/oidc"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

func ssoDeps(t *testing.T) (Deps, *fakeSSO) {
	t.Helper()
	d := testDeps(t, nil)
	fs := &fakeSSO{}
	d.SSO = fs
	return d, fs
}

// ssoMappingID is the mapping the authorization test deletes; the fake's provider holds it.
var ssoMappingID = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000aa")

func ssoCalls() map[string]routeCall {
	v := map[string]string{"If-Match": `"1"`}
	return map[string]routeCall{
		"GET /api/v1/sso/providers":                       {},
		"POST /api/v1/sso/providers":                      {body: `{"name":"Corp","issuer_url":"https://idp.example.com","client_id":"alice","client_secret":"s"}`},
		"GET /api/v1/sso/providers/{id}":                  {},
		"PATCH /api/v1/sso/providers/{id}":                {body: `{"enabled":false}`, hdr: v},
		"DELETE /api/v1/sso/providers/{id}":               {hdr: v},
		"POST /api/v1/sso/providers/{id}/actions/refresh": {hdr: v},
		"GET /api/v1/sso/group-mappings":                  {},
		"POST /api/v1/sso/group-mappings":                 {body: `{"provider_id":"` + uuid.NewString() + `","group":"ops","role":"operator"}`},
		"DELETE /api/v1/sso/group-mappings/{id}":          {},
		"GET /api/v1/sso/settings":                        {},
		"PUT /api/v1/sso/settings":                        {body: `{"allow_admin_role":true}`, hdr: v},
	}
}

var ssoQueries = map[string]string{"GET /api/v1/sso/group-mappings": "?provider_id=" + uuid.NewString(),
	"DELETE /api/v1/sso/group-mappings/{id}": "?provider_id=" + uuid.NewString()}

// Review Focus 5: SSO configuration only for an Administrator with step-up (SEC-009, §25.1), in every license state.
func TestSSORoutesAuthz(t *testing.T) {
	calls := ssoCalls()
	for _, locked := range []bool{false, true} {
		d, fs := ssoDeps(t)
		fs.succeed()
		fs.MappingsFn = func(_ context.Context, providerID uuid.UUID) ([]oidc.Mapping, error) {
			return []oidc.Mapping{{ID: ssoMappingID, ProviderID: providerID, Group: "ops", Role: rbac.Operator}}, nil
		}
		if locked {
			d.License.(*fakeLicense).set(license.ErrLocked)
		}
		s := newServer(d)
		h := s.handler(s.apiRoutes())
		seen := 0
		for _, rt := range s.apiRoutes() {
			key := rt.method + " " + rt.pattern
			c, ok := calls[key]
			if !ok {
				continue
			}
			seen++
			assert.Equal(t, rbac.SSOManage, rt.perm, key)
			path := pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString())
			if key == "DELETE /api/v1/sso/group-mappings/{id}" {
				path = "/api/v1/sso/group-mappings/" + ssoMappingID.String()
			}
			target := path + ssoQueries[key]
			for _, id := range identities {
				(&Server{s: s}).ResetLimits()
				fs.reset()
				rec := callWith(h, rt.method, target, id, c.body, c.hdr)
				want := expectedMatrix[rt.perm][id]
				switch want {
				case allw:
					assert.Less(t, rec.Code, 300, "%s as %s (locked %v): %s", key, id, locked, rec.Body.String())
					assert.Positive(t, fs.calls(), key)
				case step:
					assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, key+" as "+id)
					assert.Zero(t, fs.calls())
				default:
					assert.Equal(t, want, rec.Code, key+" as "+id)
					assert.Zero(t, fs.calls())
				}
			}
		}
		assert.Equal(t, len(calls), seen)
	}
}

func TestAdminMappingRefusedWhileOffOverHTTP(t *testing.T) {
	d, fs := ssoDeps(t)
	fs.CreateMappingFn = func(context.Context, audit.Actor, uuid.UUID, string, rbac.Role) (oidc.Mapping, error) {
		return oidc.Mapping{}, oidc.ErrAdminMappingDisabled
	}
	s := newServer(d)
	rec := callWith(s.handler(s.apiRoutes()), http.MethodPost, "/api/v1/sso/group-mappings", "admin-stepup",
		`{"provider_id":"`+uuid.NewString()+`","group":"admins","role":"admin"}`, nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-SSO-0002", decodeErr(t, rec).Error.Code)
}

func TestOIDCStartSetsTheBindingCookie(t *testing.T) {
	d, fs := ssoDeps(t)
	pid := uuid.New()
	fs.BeginFn = func(_ context.Context, in oidc.BeginInput) (oidc.Begin, error) {
		assert.Equal(t, "/certificates", in.Next)
		assert.Equal(t, pid, in.ProviderID)
		assert.False(t, in.StepUp)
		return oidc.Begin{AuthorizeURL: "https://idp.example.com/authorize?x=1", Binding: "bind-value"}, nil
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	rec := callWith(h, http.MethodPost, "/api/v1/auth/oidc/"+pid.String()+"/start", "", `{"next":"/certificates"}`, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"authorize_url":"https://idp.example.com/authorize?x=1"}`, rec.Body.String())
	c := rec.Result().Cookies()
	require.Len(t, c, 1)
	assert.Equal(t, "__Host-alice_oidc", c[0].Name)
	assert.Equal(t, "bind-value", c[0].Value)
	assert.True(t, c[0].HttpOnly && c[0].Secure)
	assert.Equal(t, http.SameSiteLaxMode, c[0].SameSite)
	assert.Equal(t, "/", c[0].Path)
	assert.Equal(t, 600, c[0].MaxAge)

	// Refusals before anything is stored are JSON errors without a cookie.
	for _, c := range []struct {
		err  error
		code string
	}{{oidc.ErrNotFound, "ALC-SYS-0001"}, {&oidc.LoginError{Reason: "provider_disabled"}, "ALC-SSO-0013"},
		{oidc.ErrPublicURLMissing, "ALC-SSO-0004"}} {
		fs.BeginFn = func(context.Context, oidc.BeginInput) (oidc.Begin, error) { return oidc.Begin{}, c.err }
		rec = callWith(h, http.MethodPost, "/api/v1/auth/oidc/"+pid.String()+"/start", "", "", nil)
		assert.Equal(t, c.code, decodeErr(t, rec).Error.Code)
		assert.Nil(t, cookieNamed(rec, oidcCookie))
	}
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPost, "/api/v1/auth/oidc/"+pid.String()+"/start", "", `{"Next":"/"}`, nil).Code)
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodPost, "/api/v1/auth/oidc/nope/start", "", "", nil).Code)
}

// The start is the sign-in form's limit (10 a minute per address): each start stores a state row (S-11).
func TestOIDCStartIsLimitedPerAddress(t *testing.T) {
	d, fs := ssoDeps(t)
	fs.BeginFn = func(context.Context, oidc.BeginInput) (oidc.Begin, error) {
		return oidc.Begin{AuthorizeURL: "https://x", Binding: "b"}, nil
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	for i := 0; i < 10; i++ {
		require.Equal(t, http.StatusOK, callWith(h, http.MethodPost, "/api/v1/auth/oidc/"+uuid.NewString()+"/start", "", "", nil).Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, callWith(h, http.MethodPost, "/api/v1/auth/oidc/"+uuid.NewString()+"/start", "", "", nil).Code)
}

func TestOIDCCallbackRedirects(t *testing.T) {
	d, fs := ssoDeps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	cb := "/api/v1/auth/oidc/" + uuid.NewString() + "/callback?code=c&state=s"
	fs.CompleteFn = func(_ context.Context, _ uuid.UUID, q url.Values, binding string, _ auth.Meta) (oidc.Completion, error) {
		assert.Equal(t, "c", q.Get("code"))
		assert.Equal(t, "bind", binding)
		return oidc.Completion{Session: auth.SessionResult{Token: "tok"}, Next: "/certificates"}, nil
	}
	rec := callWith(h, http.MethodGet, cb, "", "", map[string]string{"Cookie": "__Host-alice_oidc=bind"})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/certificates", rec.Header().Get("Location"))
	assert.Equal(t, "tok", cookieNamed(rec, "__Host-alice_session").Value)
	assert.Equal(t, -1, cookieNamed(rec, "__Host-alice_oidc").MaxAge, "the binding is cleared")

	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{}, &oidc.LoginError{Reason: "no_access"}
	}
	rec = callWith(h, http.MethodGet, cb, "", "", nil)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login?sso_error=sso.no_access", rec.Header().Get("Location"))
	assert.Nil(t, cookieNamed(rec, "__Host-alice_session"), "no session")
	assert.Equal(t, -1, cookieNamed(rec, "__Host-alice_oidc").MaxAge, "the binding is cleared on a refusal too")
	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{}, &oidc.LoginError{Reason: "stepup_other_user", StepUp: true, Next: "/settings?tab=sso"}
	}
	rec = callWith(h, http.MethodGet, cb, "", "", nil)
	assert.Equal(t, "/settings?tab=sso&sso_error=sso.stepup_other_user", rec.Header().Get("Location"))

	// S-13: the reason goes before a fragment.
	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{}, &oidc.LoginError{Reason: "login_invalid", StepUp: true, Next: "/settings#mail"}
	}
	rec = callWith(h, http.MethodGet, cb, "", "", nil)
	assert.Equal(t, "/settings?sso_error=sso.login_invalid#mail", rec.Header().Get("Location"))

	// A sign-in refusal never follows the state's Next; an unknown reason or a non-LoginError is login_invalid, never a 500.
	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{}, &oidc.LoginError{Reason: "made_up", Next: "/certificates"}
	}
	rec = callWith(h, http.MethodGet, cb, "", "", nil)
	assert.Equal(t, "/login?sso_error=sso.login_invalid", rec.Header().Get("Location"))
	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{}, errNotConfigured
	}
	rec = callWith(h, http.MethodGet, cb, "", "", nil)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login?sso_error=sso.login_invalid", rec.Header().Get("Location"))

	// An unsafe next from the service is never followed (defence in depth over claims.SafeNext in Begin).
	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{Session: auth.SessionResult{Token: "tok"}, Next: "//evil.example.com/"}, nil
	}
	rec = callWith(h, http.MethodGet, cb, "", "", nil)
	assert.Equal(t, "/", rec.Header().Get("Location"))
	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{}, &oidc.LoginError{Reason: "idp_error", StepUp: true, Next: "https://evil.example.com/"}
	}
	rec = callWith(h, http.MethodGet, cb, "", "", nil)
	assert.Equal(t, "/?sso_error=sso.idp_error", rec.Header().Get("Location"))

	rec = callWith(h, http.MethodGet, "/api/v1/auth/oidc/nope/callback", "", "", nil)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login?sso_error=sso.login_invalid", rec.Header().Get("Location"), "an unknown provider never shows a JSON page")
}

// S-11: the callback is limited per binding cookie, not per address: one browser's retries stop at 10 a minute while
// other browsers behind the same address still finish their sign-ins.
func TestOIDCCallbackIsLimitedPerBinding(t *testing.T) {
	d, fs := ssoDeps(t)
	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{}, &oidc.LoginError{Reason: "login_expired"}
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	cb := "/api/v1/auth/oidc/" + uuid.NewString() + "/callback?state=s"
	for i := 0; i < 10; i++ {
		require.Equal(t, http.StatusSeeOther, callWith(h, http.MethodGet, cb, "", "", map[string]string{"Cookie": "__Host-alice_oidc=one"}).Code)
	}
	assert.Equal(t, http.StatusTooManyRequests, callWith(h, http.MethodGet, cb, "", "", map[string]string{"Cookie": "__Host-alice_oidc=one"}).Code)
	for i := 0; i < 20; i++ {
		assert.Equal(t, http.StatusSeeOther, callWith(h, http.MethodGet, cb, "", "", map[string]string{"Cookie": "__Host-alice_oidc=other-" + string(rune('a'+i))}).Code)
	}
}

func TestOIDCStepUp(t *testing.T) {
	d, fs := ssoDeps(t)
	fs.BeginFn = func(_ context.Context, in oidc.BeginInput) (oidc.Begin, error) {
		assert.True(t, in.StepUp)
		assert.Equal(t, operatorID, in.UserID)
		assert.Equal(t, []byte("operator"), in.SessionHash)
		assert.Equal(t, "/settings", in.Next)
		return oidc.Begin{AuthorizeURL: "https://idp.example.com/authorize?prompt=login", Binding: "b2"}, nil
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	rec := callWith(h, http.MethodPost, "/api/v1/auth/oidc/stepup", "operator", `{"next":"/settings"}`, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"authorize_url":"https://idp.example.com/authorize?prompt=login"}`, rec.Body.String())
	assert.Equal(t, "b2", cookieNamed(rec, oidcCookie).Value)
	fs.BeginFn = func(context.Context, oidc.BeginInput) (oidc.Begin, error) { return oidc.Begin{}, auth.ErrNotSSOUser }
	rec = callWith(h, http.MethodPost, "/api/v1/auth/oidc/stepup", "admin", "", nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-SSO-0016", decodeErr(t, rec).Error.Code)
	assert.Equal(t, http.StatusForbidden, callWith(h, http.MethodPost, "/api/v1/auth/oidc/stepup", "alice_operate_admin", "", nil).Code,
		"a token cannot step up")
}

func TestOIDCPublicProviders(t *testing.T) {
	d, fs := ssoDeps(t)
	id := uuid.New()
	fs.PublicProvidersFn = func(context.Context) ([]oidc.PublicProvider, error) {
		return []oidc.PublicProvider{{ID: id, Name: "Corp"}}, nil
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	rec := callWith(h, http.MethodGet, "/api/v1/auth/oidc/providers", "", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"items":[{"id":"`+id.String()+`","name":"Corp"}]}`, rec.Body.String())
	fs.PublicProvidersFn = func(context.Context) ([]oidc.PublicProvider, error) { return nil, nil }
	assert.JSONEq(t, `{"items":[]}`, callWith(h, http.MethodGet, "/api/v1/auth/oidc/providers", "", "", nil).Body.String())
	fs.PublicProvidersFn = func(context.Context) ([]oidc.PublicProvider, error) { return nil, errNotConfigured }
	assert.Equal(t, http.StatusInternalServerError, callWith(h, http.MethodGet, "/api/v1/auth/oidc/providers", "", "", nil).Code)
}

// Review Focus 3: the client secret is write-only.
func TestProviderSecretIsWriteOnly(t *testing.T) {
	d, fs := ssoDeps(t)
	var seen []byte
	onSecretBytes = func(b []byte) { seen = b }
	t.Cleanup(func() { onSecretBytes = nil })
	fs.CreateProviderFn = func(_ context.Context, _ audit.Actor, in oidc.ProviderInput) (oidc.Provider, error) {
		assert.Equal(t, "CANARY-cs", string(in.ClientSecret.Bytes()))
		assert.True(t, in.Enabled, "a new provider is on unless the body says otherwise")
		assert.Nil(t, in.Scopes, "no scopes: the service's defaults")
		return oidc.Provider{ID: uuid.New(), Name: in.Name, HasClientSecret: true, Version: 1}, nil
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	rec := callWith(h, http.MethodPost, "/api/v1/sso/providers", "admin-stepup",
		`{"name":"Corp","issuer_url":"https://idp.example.com","client_id":"alice","client_secret":"CANARY-cs"}`, nil)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	assert.NotContains(t, rec.Body.String(), "CANARY")
	assert.True(t, strings.Contains(rec.Body.String(), `"has_client_secret":true`))
	assert.Equal(t, make([]byte, len("CANARY-cs")), seen)

	// A refused patch zeroes the new secret too.
	seen = nil
	fs.UpdateProviderFn = func(_ context.Context, _ audit.Actor, _ uuid.UUID, version int, p oidc.ProviderPatch) (oidc.Provider, error) {
		assert.Equal(t, 4, version)
		require.NotNil(t, p.ClientSecret)
		assert.Equal(t, "CANARY-2", string(p.ClientSecret.Bytes()))
		return oidc.Provider{}, &oidc.DiscoveryError{Cause: "tls"}
	}
	rec = callWith(h, http.MethodPatch, "/api/v1/sso/providers/"+uuid.NewString(), "admin-stepup", `{"client_secret":"CANARY-2"}`,
		map[string]string{"If-Match": `"4"`})
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Equal(t, "ALC-SSO-0001", decodeErr(t, rec).Error.Code)
	assert.Equal(t, map[string]any{"cause": "tls"}, decodeMap(t, rec.Body.Bytes())["error"].(map[string]any)["params"])
	assert.NotContains(t, rec.Body.String(), "CANARY")
	assert.Equal(t, make([]byte, len("CANARY-2")), seen)
}

func TestProviderHandlers(t *testing.T) {
	d, fs := ssoDeps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	at := time.Date(2026, 9, 1, 10, 0, 0, 0, time.FixedZone("x", 3600))
	pid := uuid.New()
	p := oidc.Provider{ID: pid, Name: "Corp", IssuerURL: "https://idp.example.com", ClientID: "alice", HasClientSecret: true,
		Scopes: []string{"openid", "email"}, GroupsClaim: "groups", Endpoints: oidc.Endpoints{Authorization: "https://idp.example.com/a",
			Token: "https://idp.example.com/t", JWKS: "https://idp.example.com/k"}, Enabled: true,
		RedirectURI: "https://alice.example.com/api/v1/auth/oidc/" + pid.String() + "/callback", Version: 3, CreatedAt: at, UpdatedAt: at}
	fs.ProvidersFn = func(context.Context) ([]oidc.Provider, error) { return []oidc.Provider{p}, nil }
	rec := callWith(h, http.MethodGet, "/api/v1/sso/providers", "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	want := `{"id":"` + pid.String() + `","name":"Corp","issuer_url":"https://idp.example.com","client_id":"alice","has_client_secret":true,
		"scopes":["openid","email"],"groups_claim":"groups","ca_pem":"","endpoints":{"authorization":"https://idp.example.com/a",
		"token":"https://idp.example.com/t","jwks":"https://idp.example.com/k"},"enabled":true,
		"redirect_uri":"https://alice.example.com/api/v1/auth/oidc/` + pid.String() + `/callback","version":3,
		"created_at":"2026-09-01T09:00:00Z","updated_at":"2026-09-01T09:00:00Z"}`
	assert.JSONEq(t, `{"items":[`+want+`]}`, rec.Body.String())
	fs.ProviderFn = func(_ context.Context, id uuid.UUID) (oidc.Provider, error) {
		if id == pid {
			return p, nil
		}
		return oidc.Provider{}, oidc.ErrNotFound
	}
	rec = callWith(h, http.MethodGet, "/api/v1/sso/providers/"+pid.String(), "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"3"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, want, rec.Body.String())
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodGet, "/api/v1/sso/providers/"+uuid.NewString(), "admin-stepup", "", nil).Code)
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodGet, "/api/v1/sso/providers/x", "admin-stepup", "", nil).Code)

	fs.UpdateProviderFn = func(_ context.Context, _ audit.Actor, id uuid.UUID, version int, pt oidc.ProviderPatch) (oidc.Provider, error) {
		assert.Equal(t, pid, id)
		assert.Equal(t, 3, version)
		require.NotNil(t, pt.Enabled)
		assert.False(t, *pt.Enabled)
		require.NotNil(t, pt.Scopes)
		assert.Equal(t, []string{"openid"}, *pt.Scopes)
		require.NotNil(t, pt.CAPEM)
		assert.Empty(t, *pt.CAPEM)
		assert.Nil(t, pt.Name)
		assert.Nil(t, pt.ClientSecret)
		q := p
		q.Enabled, q.Version = false, 4
		return q, nil
	}
	rec = callWith(h, http.MethodPatch, "/api/v1/sso/providers/"+pid.String(), "admin-stepup", `{"enabled":false,"scopes":["openid"],"ca_pem":""}`,
		map[string]string{"If-Match": `"3"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `"4"`, rec.Header().Get("ETag"))
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPatch, "/api/v1/sso/providers/"+pid.String(), "admin-stepup", `{}`, nil).Code)
	rec = callWith(h, http.MethodPatch, "/api/v1/sso/providers/"+pid.String(), "admin-stepup", `{"name":null}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "null is not a value of a provider field")
	rec = callWith(h, http.MethodPatch, "/api/v1/sso/providers/"+pid.String(), "admin-stepup", `{"issuer":"x"}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	fs.UpdateProviderFn = func(context.Context, audit.Actor, uuid.UUID, int, oidc.ProviderPatch) (oidc.Provider, error) {
		return oidc.Provider{}, oidc.ErrVersion
	}
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPatch, "/api/v1/sso/providers/"+pid.String(), "admin-stepup", `{}`,
		map[string]string{"If-Match": `"2"`}).Code)

	fs.CreateProviderFn = func(context.Context, audit.Actor, oidc.ProviderInput) (oidc.Provider, error) {
		return oidc.Provider{}, oidc.ErrTooMany
	}
	rec = callWith(h, http.MethodPost, "/api/v1/sso/providers", "admin-stepup", `{"name":"N","issuer_url":"https://i","client_id":"c","client_secret":"s"}`, nil)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), `{"field":"name","code":"validation.out_of_range","params":{"max":"5","min":"1"}}`)
	fs.CreateProviderFn = func(_ context.Context, _ audit.Actor, in oidc.ProviderInput) (oidc.Provider, error) {
		assert.False(t, in.Enabled)
		assert.Equal(t, []string{"openid", "groups"}, in.Scopes)
		assert.Equal(t, "roles", in.GroupsClaim)
		return oidc.Provider{}, validate.Errors{{Field: "issuer_url", Code: validate.Pattern}}
	}
	rec = callWith(h, http.MethodPost, "/api/v1/sso/providers", "admin-stepup",
		`{"name":"N","issuer_url":"http://i","client_id":"c","client_secret":"s","enabled":false,"scopes":["openid","groups"],"groups_claim":"roles","ca_pem":""}`, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	fs.RefreshProviderFn = func(_ context.Context, _ audit.Actor, id uuid.UUID, version int) (oidc.Provider, error) {
		assert.Equal(t, 3, version)
		return p, nil
	}
	rec = callWith(h, http.MethodPost, "/api/v1/sso/providers/"+pid.String()+"/actions/refresh", "admin-stepup", "", map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPost, "/api/v1/sso/providers/"+pid.String()+"/actions/refresh", "admin-stepup", "", nil).Code)
	rec = callWith(h, http.MethodPost, "/api/v1/sso/providers/"+pid.String()+"/actions/refresh", "admin-stepup", `{"x":1}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	fs.DeleteProviderFn = func(context.Context, audit.Actor, uuid.UUID, int) error { return oidc.ErrProviderInUse }
	rec = callWith(h, http.MethodDelete, "/api/v1/sso/providers/"+pid.String(), "admin-stepup", "", map[string]string{"If-Match": `"3"`})
	assert.Equal(t, "ALC-SSO-0005", decodeErr(t, rec).Error.Code)
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodDelete, "/api/v1/sso/providers/"+pid.String(), "admin-stepup", "", nil).Code)
	fs.ProvidersFn = func(context.Context) ([]oidc.Provider, error) { return nil, errNotConfigured }
	assert.Equal(t, http.StatusInternalServerError, callWith(h, http.MethodGet, "/api/v1/sso/providers", "admin-stepup", "", nil).Code)
}

func TestMappingAndSettingsHandlers(t *testing.T) {
	d, fs := ssoDeps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	pid, mid := uuid.New(), uuid.New()
	at := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	fs.MappingsFn = func(_ context.Context, providerID uuid.UUID) ([]oidc.Mapping, error) {
		if providerID != pid {
			return []oidc.Mapping{}, nil
		}
		return []oidc.Mapping{{ID: mid, ProviderID: pid, Group: "ops", Role: rbac.Operator, CreatedAt: at}}, nil
	}
	rec := callWith(h, http.MethodGet, "/api/v1/sso/group-mappings?provider_id="+pid.String(), "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"items":[{"id":"`+mid.String()+`","provider_id":"`+pid.String()+`","group":"ops","role":"operator","created_at":"2026-09-02T00:00:00Z"}]}`,
		rec.Body.String())
	for _, q := range []string{"", "?provider_id=x"} {
		assert.Equal(t, http.StatusUnprocessableEntity, callWith(h, http.MethodGet, "/api/v1/sso/group-mappings"+q, "admin-stepup", "", nil).Code, q)
	}

	fs.CreateMappingFn = func(_ context.Context, _ audit.Actor, providerID uuid.UUID, group string, role rbac.Role) (oidc.Mapping, error) {
		assert.Equal(t, pid, providerID)
		assert.Equal(t, rbac.Auditor, role)
		return oidc.Mapping{ID: mid, ProviderID: providerID, Group: group, Role: role, CreatedAt: at}, nil
	}
	rec = callWith(h, http.MethodPost, "/api/v1/sso/group-mappings", "admin-stepup", `{"provider_id":"`+pid.String()+`","group":"audit","role":"auditor"}`, nil)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"role":"auditor"`)
	rec = callWith(h, http.MethodPost, "/api/v1/sso/group-mappings", "admin-stepup", `{"provider_id":"x","group":"a","role":"root"}`, nil)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), `"field":"provider_id"`)
	assert.Contains(t, rec.Body.String(), `"field":"role"`)
	fs.CreateMappingFn = func(context.Context, audit.Actor, uuid.UUID, string, rbac.Role) (oidc.Mapping, error) {
		return oidc.Mapping{}, oidc.ErrTooMany
	}
	rec = callWith(h, http.MethodPost, "/api/v1/sso/group-mappings", "admin-stepup", `{"provider_id":"`+pid.String()+`","group":"a","role":"operator"}`, nil)
	assert.Contains(t, rec.Body.String(), `{"field":"group","code":"validation.out_of_range","params":{"max":"200","min":"1"}}`)

	// DeleteMapping is not scoped to a provider in the service: the handler checks that the named provider holds it.
	var deleted []uuid.UUID
	fs.DeleteMappingFn = func(_ context.Context, _ audit.Actor, id uuid.UUID) error {
		deleted = append(deleted, id)
		return nil
	}
	rec = callWith(h, http.MethodDelete, "/api/v1/sso/group-mappings/"+mid.String()+"?provider_id="+uuid.NewString(), "admin-stepup", "", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code, "another provider's mapping")
	rec = callWith(h, http.MethodDelete, "/api/v1/sso/group-mappings/"+mid.String(), "admin-stepup", "", nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "provider_id is required")
	assert.Empty(t, deleted)
	rec = callWith(h, http.MethodDelete, "/api/v1/sso/group-mappings/"+mid.String()+"?provider_id="+pid.String(), "admin-stepup", "", nil)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, []uuid.UUID{mid}, deleted)
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodDelete, "/api/v1/sso/group-mappings/x?provider_id="+pid.String(), "admin-stepup", "", nil).Code)
	fs.MappingsFn = func(context.Context, uuid.UUID) ([]oidc.Mapping, error) { return nil, errNotConfigured }
	assert.Equal(t, http.StatusInternalServerError,
		callWith(h, http.MethodDelete, "/api/v1/sso/group-mappings/"+mid.String()+"?provider_id="+pid.String(), "admin-stepup", "", nil).Code)

	fs.SettingsFn = func(context.Context) (oidc.SSOSettings, error) {
		return oidc.SSOSettings{AllowAdminRole: false, Version: 0}, nil
	}
	rec = callWith(h, http.MethodGet, "/api/v1/sso/settings", "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"0"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"allow_admin_role":false,"version":0}`, rec.Body.String())
	fs.SaveSettingsFn = func(_ context.Context, _ audit.Actor, version int, allow bool) (oidc.SSOSettings, error) {
		assert.Equal(t, 0, version)
		return oidc.SSOSettings{AllowAdminRole: allow, Version: 1}, nil
	}
	rec = callWith(h, http.MethodPut, "/api/v1/sso/settings", "admin-stepup", `{"allow_admin_role":true}`, map[string]string{"If-Match": `"0"`})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"allow_admin_role":true,"version":1}`, rec.Body.String())
	fs.SaveSettingsFn = func(context.Context, audit.Actor, int, bool) (oidc.SSOSettings, error) {
		return oidc.SSOSettings{}, oidc.ErrAdminMappingsExist
	}
	rec = callWith(h, http.MethodPut, "/api/v1/sso/settings", "admin-stepup", `{"allow_admin_role":false}`, map[string]string{"If-Match": `"1"`})
	assert.Equal(t, "ALC-SSO-0003", decodeErr(t, rec).Error.Code)
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPut, "/api/v1/sso/settings", "admin-stepup", `{}`, nil).Code)
	fs.SettingsFn = func(context.Context) (oidc.SSOSettings, error) { return oidc.SSOSettings{}, errNotConfigured }
	assert.Equal(t, http.StatusInternalServerError, callWith(h, http.MethodGet, "/api/v1/sso/settings", "admin-stepup", "", nil).Code)
}

func TestWithQuery(t *testing.T) {
	for in, want := range map[string]string{
		"/login": "/login?k=v", "/a?b=c": "/a?b=c&k=v", "/a#f": "/a?k=v#f", "/a?b=c#f": "/a?b=c&k=v#f",
	} {
		assert.Equal(t, want, withQuery(in, "k", "v"), in)
	}
	assert.Equal(t, "/x?k=a+b%26c", withQuery("/x", "k", "a b&c"))
}

// A-s4-02 (C10): the user and session answers say how a person signs in and through which identity provider.
func TestUserAndSessionCarryTheAuthSource(t *testing.T) {
	pid := uuid.New()
	sso := userJSON(auth.User{ID: uuid.New(), Username: "ada", Role: rbac.Operator, AuthSource: auth.AuthOIDC, SSOProviderID: &pid})
	b := encodeJSON(t, sso)
	assert.Contains(t, b, `"auth_source":"oidc"`)
	assert.Contains(t, b, `"sso_provider_id":"`+pid.String()+`"`)
	local := encodeJSON(t, sessionJSON(auth.SessionInfo{User: auth.User{ID: uuid.New(), AuthSource: auth.AuthLocal}}, nil))
	assert.Contains(t, local, `"auth_source":"local"`)
	assert.Contains(t, local, `"sso_provider_id":null`)
	assert.Contains(t, encodeJSON(t, userJSON(auth.User{ID: uuid.New()})), `"auth_source":"local"`, "a user from before Phase 7 is local")
}

func encodeJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// Path IDs that are not UUIDs are not found; service failures are the generic 500 or their code.
func TestSSOHandlerRefusals(t *testing.T) {
	d, fs := ssoDeps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	v := map[string]string{"If-Match": `"1"`}
	for _, c := range []struct{ method, path string }{{http.MethodPatch, "/api/v1/sso/providers/x"}, {http.MethodDelete, "/api/v1/sso/providers/x"},
		{http.MethodPost, "/api/v1/sso/providers/x/actions/refresh"}} {
		assert.Equal(t, http.StatusNotFound, callWith(h, c.method, c.path, "admin-stepup", "", v).Code, c.path)
	}
	fs.RefreshProviderFn = func(context.Context, audit.Actor, uuid.UUID, int) (oidc.Provider, error) {
		return oidc.Provider{}, &oidc.DiscoveryError{Cause: "jwks"}
	}
	rec := callWith(h, http.MethodPost, "/api/v1/sso/providers/"+uuid.NewString()+"/actions/refresh", "admin-stepup", "{}", v)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.True(t, decodeErr(t, rec).Error.Retryable)
	fs.MappingsFn = func(context.Context, uuid.UUID) ([]oidc.Mapping, error) { return nil, errNotConfigured }
	assert.Equal(t, http.StatusInternalServerError,
		callWith(h, http.MethodGet, "/api/v1/sso/group-mappings?provider_id="+uuid.NewString(), "admin-stepup", "", nil).Code)
	mid := uuid.New()
	fs.MappingsFn = func(_ context.Context, pid uuid.UUID) ([]oidc.Mapping, error) {
		return []oidc.Mapping{{ID: mid, ProviderID: pid}}, nil
	}
	fs.DeleteMappingFn = func(context.Context, audit.Actor, uuid.UUID) error { return oidc.ErrNotFound }
	assert.Equal(t, http.StatusNotFound,
		callWith(h, http.MethodDelete, "/api/v1/sso/group-mappings/"+mid.String()+"?provider_id="+uuid.NewString(), "admin-stepup", "", nil).Code,
		"deleted meanwhile")
	rec = callWith(h, http.MethodPost, "/api/v1/sso/group-mappings", "admin-stepup", `{"group":"a","role":"operator"}`, nil)
	assert.Contains(t, rec.Body.String(), `{"field":"provider_id","code":"validation.required"}`)
	fs.SaveSettingsFn = func(context.Context, audit.Actor, int, bool) (oidc.SSOSettings, error) {
		return oidc.SSOSettings{}, oidc.ErrVersion
	}
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPut, "/api/v1/sso/settings", "admin-stepup", `{"allow_admin_role":true}`, v).Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPut, "/api/v1/sso/settings", "admin-stepup", `{"allow":true}`, v).Code)
	fs.BeginFn = func(context.Context, oidc.BeginInput) (oidc.Begin, error) { return oidc.Begin{}, nil }
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPost, "/api/v1/auth/oidc/stepup", "operator", `{"nxt":"/"}`, nil).Code)
}
