//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz/services"
	"alice/internal/testutil/fakeidp"
	"alice/internal/testutil/seed"
)

// Scoped access, Phase 3 (R49, R54; design §12 Phase 3, SR-17..SR-21) over the wire: directory groups bound to a
// service let SSO and directory users without a mapped group in, on that service only; automation accounts and their
// tokens; tokens limited to services.

type listBody struct {
	Items []map[string]any `json:"items"`
}

// twoServices makes services A and B, each with one server, and returns the services and the servers.
func (s *stack) twoServices(t *testing.T) (a, b, aServer, bServer uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	for _, x := range []struct {
		name   string
		svc    *uuid.UUID
		server *uuid.UUID
	}{{"Alpha", &a, &aServer}, {"Bravo", &b, &bServer}} {
		sv, err := s.serviceStore.CreateService(ctx, sysActor, services.ServiceInput{Name: x.name})
		require.NoError(t, err)
		*x.svc = sv.ID
		*x.server, err = seed.Target(ctx, s.db.Owner, x.name+"-web", "nginx", "ok", nil)
		require.NoError(t, err)
		_, err = s.serviceStore.Assign(ctx, sysActor, sv.ID, []services.Resource{{Type: services.KindTarget, ID: *x.server}}, false)
		require.NoError(t, err)
	}
	return a, b, aServer, bServer
}

// declareGroup declares a directory group through the API and binds it to role on service; it returns the group's id.
func (s *stack) declareGroup(t *testing.T, admin *client, body map[string]any, role string, service uuid.UUID) string {
	t.Helper()
	rec := admin.do(http.MethodPost, "/api/v1/directory-groups", body)
	requireStatus(t, rec, http.StatusCreated)
	g := decodeBody[map[string]any](t, rec)["id"].(string)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/role-bindings", map[string]any{"directory_group_id": g, "role": role, "service_id": service}),
		http.StatusCreated)
	return g
}

// sessionServices is the names of the services of a session's access, and its global role.
func sessionServices(t *testing.T, c *client) (globalRole any, names []string) {
	t.Helper()
	rec := c.do(http.MethodGet, "/api/v1/auth/session", nil)
	requireStatus(t, rec, http.StatusOK)
	access := decodeBody[map[string]any](t, rec)["access"].(map[string]any)
	for _, sv := range access["services"].([]any) {
		names = append(names, sv.(map[string]any)["name"].(string))
	}
	return access["global_role"], names
}

func TestDirectoryGroupBindingsOverTheWire(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	p := s.ssoReady(t, admin, adminAcct) // alice-operators -> operator
	dir := s.directoryReady(t, admin, adminAcct, false)
	_, b, aServer, bServer := s.twoServices(t)

	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPost, "/api/v1/directory-groups", map[string]any{"source": "oidc", "provider_id": p, "value": " pay-ops"})
	requireError(t, rec, http.StatusUnprocessableEntity, ErrValidation.Code)
	ssoGroup := s.declareGroup(t, admin, map[string]any{"source": "oidc", "provider_id": p, "value": "pay-ops", "label": "Ödeme"}, "operator", b)
	requireError(t, admin.do(http.MethodPost, "/api/v1/directory-groups", map[string]any{"source": "oidc", "provider_id": p, "value": "pay-ops"}),
		http.StatusConflict, ErrACCGroupExists.Code)
	s.declareGroup(t, admin, map[string]any{"source": "ldap", "directory_id": dir, "value": "cn=pay"}, "operator", b)

	// An SSO user in pay-ops, no mapped group: signed in without a global role, on B only.
	s.idp.NextLogin(fakeidp.Login{Subject: "u-pinar", Username: "pinar", Name: "Pınar", Groups: []string{"pay-ops", "eng"}})
	browser := s.freshClient()
	rec = s.browserSSO(t, browser, p)
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	assert.Equal(t, "/certificates", rec.Header().Get("Location"))
	role, names := sessionServices(t, browser)
	assert.Nil(t, role, "no global role")
	assert.Equal(t, []string{"Bravo"}, names)
	rec = browser.do(http.MethodGet, "/api/v1/targets", nil)
	requireStatus(t, rec, http.StatusOK)
	list := decodeBody[listBody](t, rec)
	require.Len(t, list.Items, 1, "B's server only")
	assert.Equal(t, bServer.String(), list.Items[0]["id"])
	requireError(t, browser.do(http.MethodGet, "/api/v1/targets/"+aServer.String(), nil), http.StatusNotFound, ErrNotFound.Code)
	requireError(t, browser.do(http.MethodGet, "/api/v1/users", nil), http.StatusForbidden, ErrForbidden.Code)

	// The Groups tab: the declared groups with their members and the values seen at sign-in.
	rec = admin.do(http.MethodGet, "/api/v1/directory-groups", nil)
	requireStatus(t, rec, http.StatusOK)
	groups := decodeBody[struct {
		Items []map[string]any `json:"items"`
		Seen  []map[string]any `json:"seen"`
	}](t, rec)
	require.Len(t, groups.Items, 2)
	require.Len(t, groups.Seen, 2, "pay-ops and eng")
	for _, g := range groups.Items {
		if g["id"] == ssoGroup {
			assert.EqualValues(t, 1, g["members"])
			assert.Equal(t, "Corp IdP", g["source_name"])
		}
	}

	// An Administrator binding of the group acts as Operator while SSO users may not be Admin.
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/role-bindings", map[string]any{"directory_group_id": ssoGroup, "role": "admin", "service_id": b}),
		http.StatusCreated)
	pinar := s.userID("pinar")
	rec = admin.do(http.MethodGet, "/api/v1/users/"+pinar+"/access", nil)
	requireStatus(t, rec, http.StatusOK)
	acc := decodeBody[map[string]any](t, rec)
	assert.Len(t, acc["group_bindings"], 2)
	assert.Equal(t, true, acc["admin_capped"])
	grants := acc["grants"].([]any)
	require.Len(t, grants, 1)
	assert.Equal(t, "operator", grants[0].(map[string]any)["role"])
	rec = browser.do(http.MethodGet, "/api/v1/targets/"+bServer.String(), nil)
	requireStatus(t, rec, http.StatusOK)
	assert.NotContains(t, decodeBody[map[string]any](t, rec)["allowed_actions"], "targets.manage", "capped at Operator")

	// Out of the group at the provider: the next sign-in is refused no_access and ends her sessions.
	s.idp.NextLogin(fakeidp.Login{Subject: "u-pinar", Username: "pinar", Groups: []string{"eng"}})
	before := s.countWhere("audit_log", "action = 'auth.oidc.denied'")
	s.requireRefused(t, s.browserSSO(t, s.freshClient(), p), "/login?sso_error=sso.no_access", "no_access", before, "out of the group")
	requireError(t, browser.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	// Nobody with neither a mapping nor a binding is let in, and nobody is provisioned for them.
	s.idp.NextLogin(fakeidp.Login{Subject: "u-nobody", Username: "nobody", Groups: []string{"eng"}})
	before = s.countWhere("audit_log", "action = 'auth.oidc.denied'")
	s.requireRefused(t, s.browserSSO(t, s.freshClient(), p), "/login?sso_error=sso.no_access", "no_access", before, "neither")
	assert.Zero(t, s.countWhere("users", "username = 'nobody'"))

	// A directory user in cn=pay, no mapped group: signed in on B only; out of the group, refused no_access.
	s.dir.add(fakeDirUser{login: "pelin", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000010", name: "Pelin", password: dirUserPassword,
		groups: []string{"cn=pay"}})
	dirBrowser := s.freshClient()
	rec, _ = s.dirLogin(dirBrowser, dir, "pelin", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "signed_in", decodeBody[map[string]string](t, rec)["status"])
	role, names = sessionServices(t, dirBrowser)
	assert.Nil(t, role)
	assert.Equal(t, []string{"Bravo"}, names)
	s.dir.set(func(f *fakeDirectory) {
		for i := range f.users {
			if f.users[i].login == "pelin" {
				f.users[i].groups = []string{"cn=other"}
			}
		}
	})
	rec, _ = s.dirLogin(s.freshClient(), dir, "pelin", dirUserPassword)
	requireError(t, rec, http.StatusUnauthorized, ErrLDAPSignInRefused.Code)
	reason, _, _ := s.lastDenial(t)
	assert.Equal(t, "no_access", reason)
	requireError(t, dirBrowser.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")

	// Deleting the group counts what went with it; a token cannot manage groups.
	rec = admin.do(http.MethodDelete, "/api/v1/directory-groups/"+ssoGroup, nil)
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"bindings_removed":2,"owners_removed":0}`, rec.Body.String())
	requireError(t, admin.do(http.MethodDelete, "/api/v1/directory-groups/"+ssoGroup, nil), http.StatusNotFound, ErrACCGroupNotFound.Code)
}

func TestAutomationAccountsOverTheWire(t *testing.T) {
	s := newStack(t)
	adminAcct := &account{username: "ada", password: "correct horse battery staple"}
	admin := s.setupAdmin(adminAcct, "a long enough recovery passphrase", nil)
	a, b, aServer, bServer := s.twoServices(t)
	s.stepUp(admin, adminAcct)

	requireError(t, admin.do(http.MethodPost, "/api/v1/automation-accounts", map[string]any{"username": "ci", "display_name": "CI", "role": "admin"}),
		http.StatusUnprocessableEntity, ErrACCRoleNotAllowed.Code)
	rec := admin.do(http.MethodPost, "/api/v1/automation-accounts", map[string]any{"username": "ci-deployer", "display_name": "CI deployer",
		"description": "Bravo's pipeline"})
	requireStatus(t, rec, http.StatusCreated)
	robot := decodeBody[map[string]any](t, rec)
	id := robot["id"].(string)
	assert.Nil(t, robot["role"])

	// Not a person: not in the people list, never signed in, no person-only change.
	rec = admin.do(http.MethodGet, "/api/v1/users", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.NotContains(t, rec.Body.String(), id)
	unknown := s.login("no-such-person", "anything at all, really")
	rec = s.login("ci-deployer", "anything at all, really")
	assert.Equal(t, unknown.Code, rec.Code, "the password form answers as for an unknown name")
	assert.Equal(t, decodeErr(t, unknown).Error.Code, decodeErr(t, rec).Error.Code)
	requireError(t, admin.do(http.MethodPatch, "/api/v1/users/"+id, map[string]any{"role": "operator"}), http.StatusConflict, ErrACCAutomationAccount.Code)

	// A token within the account's binding: Operator on B.
	token := func(body map[string]any) (string, map[string]any) {
		t.Helper()
		rec := admin.do(http.MethodPost, "/api/v1/automation-accounts/"+id+"/tokens", body)
		requireStatus(t, rec, http.StatusCreated)
		out := decodeBody[map[string]any](t, rec)
		return out["token"].(string), out["item"].(map[string]any)
	}
	operate := map[string]any{"name": "pipeline", "scope": "operate", "expires_in_days": 30}
	requireError(t, admin.do(http.MethodPost, "/api/v1/automation-accounts/"+id+"/tokens", operate), http.StatusUnprocessableEntity,
		ErrTokenScopeNotAllowed.Code)
	rec = admin.do(http.MethodPost, "/api/v1/role-bindings", map[string]any{"user_id": id, "role": "operator", "service_id": b})
	requireStatus(t, rec, http.StatusCreated)
	binding := decodeBody[map[string]any](t, rec)
	assert.Equal(t, true, binding["automation"])
	requireError(t, admin.do(http.MethodPost, "/api/v1/automation-accounts/"+id+"/tokens", map[string]any{"name": "x", "scope": "operate",
		"expires_in_days": 30, "service_ids": []string{a.String()}}), http.StatusUnprocessableEntity, ErrTokenServiceNotAllowed.Code)
	secret, item := token(operate)
	assert.Nil(t, item["service_ids"])
	bot := s.freshClient()
	bot.bearer = secret
	rec = bot.do(http.MethodGet, "/api/v1/targets", nil)
	requireStatus(t, rec, http.StatusOK)
	list := decodeBody[listBody](t, rec)
	require.Len(t, list.Items, 1)
	assert.Equal(t, bServer.String(), list.Items[0]["id"])
	requireError(t, bot.do(http.MethodGet, "/api/v1/targets/"+aServer.String(), nil), http.StatusNotFound, ErrNotFound.Code)
	requireError(t, bot.do(http.MethodGet, "/api/v1/automation-accounts", nil), http.StatusForbidden, ErrForbidden.Code)
	rec = admin.do(http.MethodGet, "/api/v1/automation-accounts/"+id+"/tokens", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Len(t, decodeBody[listBody](t, rec).Items, 1)

	// Never with a token: an Administrator's own token cannot make accounts or their tokens.
	rec = admin.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "admin", "scope": "operate", "expires_in_days": 1})
	requireStatus(t, rec, http.StatusCreated)
	adminTok := s.freshClient()
	adminTok.bearer = decodeBody[map[string]any](t, rec)["token"].(string)
	requireError(t, adminTok.do(http.MethodPost, "/api/v1/automation-accounts", map[string]any{"username": "x2", "display_name": "x"}),
		http.StatusForbidden, ErrForbidden.Code)
	requireError(t, adminTok.do(http.MethodPost, "/api/v1/automation-accounts/"+id+"/tokens", operate), http.StatusForbidden, ErrForbidden.Code)

	// The token shrinks with the account's grants: the binding goes, the next request is refused.
	requireStatus(t, admin.do(http.MethodDelete, "/api/v1/role-bindings/"+binding["id"].(string), nil), http.StatusNoContent)
	requireError(t, bot.do(http.MethodGet, "/api/v1/targets", nil), http.StatusUnauthorized, ErrUnauthenticated.Code)

	// Disabling revokes the tokens and refuses new ones.
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/role-bindings", map[string]any{"user_id": id, "role": "operator", "service_id": b}),
		http.StatusCreated)
	secret, _ = token(operate)
	bot.bearer = secret
	requireStatus(t, bot.do(http.MethodGet, "/api/v1/targets", nil), http.StatusOK)
	rec = admin.do(http.MethodPatch, "/api/v1/automation-accounts/"+id, map[string]any{"disabled": true})
	requireStatus(t, rec, http.StatusOK)
	assert.EqualValues(t, 0, decodeBody[map[string]any](t, rec)["tokens"])
	requireError(t, bot.do(http.MethodGet, "/api/v1/targets", nil), http.StatusUnauthorized, ErrUnauthenticated.Code)
	requireError(t, admin.do(http.MethodPost, "/api/v1/automation-accounts/"+id+"/tokens", operate), http.StatusConflict, ErrACCAutomationDisabled.Code)
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'automation.updated' AND details->>'disabled' = 'true'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'automation.created'"))
}

// A global Administrator's token limited to B (design §6.3, §12 Phase 3): B's resources work, A's are absent, platform
// routes are refused; the Tokens list shows the limit.
func TestTokenLimitedToAServiceOverTheWire(t *testing.T) {
	s := newStack(t)
	adminAcct := &account{username: "ada", password: "correct horse battery staple"}
	admin := s.setupAdmin(adminAcct, "a long enough recovery passphrase", nil)
	_, b, aServer, bServer := s.twoServices(t)
	s.stepUp(admin, adminAcct)
	requireError(t, admin.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "x", "scope": "operate", "expires_in_days": 1,
		"service_ids": []string{uuid.NewString()}}), http.StatusUnprocessableEntity, ErrTokenServiceNotAllowed.Code)
	requireError(t, admin.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "x", "scope": "operate", "expires_in_days": 1,
		"service_ids": []string{}}), http.StatusUnprocessableEntity, ErrValidation.Code)
	rec := admin.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "deploy B", "scope": "operate", "expires_in_days": 1,
		"service_ids": []string{b.String()}})
	requireStatus(t, rec, http.StatusCreated)
	tok := s.freshClient()
	tok.bearer = decodeBody[map[string]any](t, rec)["token"].(string)

	rec = tok.do(http.MethodGet, "/api/v1/targets", nil)
	requireStatus(t, rec, http.StatusOK)
	list := decodeBody[listBody](t, rec)
	require.Len(t, list.Items, 1)
	assert.Equal(t, bServer.String(), list.Items[0]["id"])
	assert.Contains(t, list.Items[0]["allowed_actions"], "targets.manage", "an Administrator's operate token on B")
	requireError(t, tok.do(http.MethodGet, "/api/v1/targets/"+aServer.String(), nil), http.StatusNotFound, ErrNotFound.Code)
	requireError(t, tok.do(http.MethodGet, "/api/v1/users", nil), http.StatusForbidden, ErrForbidden.Code)
	requireError(t, tok.do(http.MethodGet, "/api/v1/audit", nil), http.StatusForbidden, ErrForbidden.Code)

	rec = admin.do(http.MethodGet, "/api/v1/tokens", nil)
	requireStatus(t, rec, http.StatusOK)
	items := decodeBody[listBody](t, rec).Items
	require.Len(t, items, 1)
	assert.Equal(t, []any{b.String()}, items[0]["service_ids"])
}
