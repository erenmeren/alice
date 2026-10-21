package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/ldap"
	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

var errCovDBoom = errors.New("database is down")

// covDServices is fakeServices whose TargetServices can fail.
type covDServices struct {
	*fakeServices
	targetErr error
}

func (c covDServices) TargetServices(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	if c.targetErr != nil {
		return nil, c.targetErr
	}
	return c.fakeServices.TargetServices(ctx, ids)
}

// covDScopedDeps are incident deps with "covd-scoped": a person with no global role and Operator on svcPay alone.
func covDScopedDeps(t *testing.T) (Deps, *fakeIncidents, *covDServices) {
	t.Helper()
	d := testDeps(t, nil)
	fa := d.Auth.(*fakeAuth)
	base := fa.AuthenticateFn
	fa.AuthenticateFn = func(ctx context.Context, tok string) (auth.Principal, error) {
		if tok == "covd-scoped" {
			return auth.Principal{Kind: rbac.UserSession, UserID: operatorID, Username: "scoped", Role: auth.NoGlobalRole, Locale: "en",
				SessionHash: []byte("covd-scoped"), Grants: []rbac.ScopedGrant{{Role: rbac.Operator, Services: []uuid.UUID{svcPay}}}}, nil
		}
		return base(ctx, tok)
	}
	inc := &fakeIncidents{}
	sv := &covDServices{fakeServices: &fakeServices{refs: map[uuid.UUID]authz.ServiceRef{}, targetServices: map[uuid.UUID]uuid.UUID{}}}
	d.Incidents, d.Services = inc, sv
	return d, inc, sv
}

// A malformed id is the route's 404 on every incident route; a failure of the service is a 500, never an answer.
func TestCovDIncidentRoutesAnswerBadIDsAndFailures(t *testing.T) {
	h, _, inc := incidentDeps(t)
	for _, c := range []struct{ method, path, who, body string }{
		{http.MethodGet, "/api/v1/certificate-impact/nope", "auditor", ""},
		{http.MethodPost, "/api/v1/certificates/nope/incidents", "admin-stepup", ""},
		{http.MethodGet, "/api/v1/incidents/nope", "auditor", ""},
		{http.MethodPost, "/api/v1/incidents/nope/retry", "admin-stepup", ""},
		{http.MethodPost, "/api/v1/incidents/nope/replacement", "admin-stepup", `{"certificate_id":"` + incCertID.String() + `"}`},
	} {
		rec := call(h, c.method, c.path, c.who, c.body)
		assert.Equal(t, http.StatusNotFound, rec.Code, c.path)
		assert.Equal(t, "ALC-SYS-0001", decodeErr(t, rec).Error.Code, c.path)
	}

	// The fake answers errNotConfigured until a Fn is set: every route fails closed.
	base := "/api/v1/incidents/" + incidentID.String()
	for _, c := range []struct{ method, path, who string }{
		{http.MethodGet, "/api/v1/certificate-impact/" + incCertID.String(), "auditor"},
		{http.MethodGet, "/api/v1/incidents", "auditor"},
		{http.MethodGet, base, "auditor"},
		{http.MethodPost, base + "/retry", "admin-stepup"},
		{http.MethodPost, base + "/revoke-now", "admin-stepup"},
		{http.MethodPost, base + "/close", "admin-stepup"},
	} {
		rec := call(h, c.method, c.path, c.who, "")
		assert.Equal(t, http.StatusInternalServerError, rec.Code, c.path)
		assert.NotContains(t, rec.Body.String(), errNotConfigured.Error(), c.path)
	}

	// A global reader sees every Key Vault version with the key.
	inc.CertificateImpactFn = func(context.Context, uuid.UUID) (inventory.CertificateImpact, error) {
		return inventory.CertificateImpact{Certificate: inventory.Certificate{ID: incCertID, Source: "azure_kv"},
			Vaults: []inventory.ImpactVaultVersion{{VaultID: targetID, VaultName: "kv-prod", KVCertificateID: uuid.New(), Name: "www", Version: "v2",
				CertificateID: incCertID, Current: true, Match: inventory.ImpactMatchCertificate}}}, nil
	}
	rec := call(h, http.MethodGet, "/api/v1/certificate-impact/"+incCertID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := jsonObj(t, rec)
	vaults := body["vaults"].([]any)
	require.Len(t, vaults, 1)
	v := vaults[0].(map[string]any)
	assert.Equal(t, "kv-prod", v["vault_name"])
	assert.Equal(t, "v2", v["version"])
	assert.Equal(t, true, v["current"])
	assert.Equal(t, float64(0), body["hidden_count"])
}

// R49 Phase 2 (design §5.8): a caller with a role on one service sees the impact on its servers and vaults and the
// certificates with the key it may read; everything else is left out and counted, and the network map stays hidden.
func TestCovDImpactOfAScopedCallerHidesOtherServices(t *testing.T) {
	d, inc, sv := covDScopedDeps(t)
	seenServer, otherServer := uuid.New(), uuid.New()
	seenVault, otherVault := uuid.New(), uuid.New()
	seenCert, otherCert, goneCert := uuid.New(), uuid.New(), uuid.New()
	sv.targetServices[seenServer], sv.targetServices[seenVault] = svcPay, svcPay
	sv.targetServices[otherServer], sv.targetServices[otherVault] = svcDefault, svcDefault
	resolveErr := error(nil)
	sv.ResolveFn = func(kind string, id any) (services.Resolution, error) {
		switch {
		case kind == services.KindIncidentReach:
			return services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}, nil
		case kind == services.KindCertificate && resolveErr != nil:
			return services.Resolution{}, resolveErr
		case kind == services.KindCertificate && id == seenCert:
			return services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}, nil
		case kind == services.KindCertificate && id == otherCert:
			return services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault}}, nil
		}
		return services.Resolution{}, services.ErrResourceNotFound
	}
	inc.CertificateImpactFn = func(context.Context, uuid.UUID) (inventory.CertificateImpact, error) {
		return inventory.CertificateImpact{Certificate: inventory.Certificate{ID: incCertID, Source: "uploaded"},
			Certificates: []inventory.ImpactCertificate{{ID: seenCert, SubjectCN: "seen"}, {ID: otherCert, SubjectCN: "other"}, {ID: goneCert, SubjectCN: "gone"}},
			Locations: []inventory.ImpactLocation{{LocationID: uuid.New(), TargetID: seenServer, TargetName: "web-pay"},
				{LocationID: uuid.New(), TargetID: otherServer, TargetName: "web-other"}},
			Vaults:    []inventory.ImpactVaultVersion{{VaultID: seenVault, VaultName: "kv-pay"}, {VaultID: otherVault, VaultName: "kv-other"}},
			Endpoints: []inventory.ImpactEndpoint{{EndpointID: uuid.New(), ScopeID: uuid.New(), ScopeName: "LAN"}}}, nil
	}
	h := NewHandler(d)
	target := "/api/v1/certificate-impact/" + incCertID.String()
	rec := call(h, http.MethodGet, target, "covd-scoped", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := jsonObj(t, rec)
	assert.Equal(t, float64(4), body["hidden_count"], "one location, one vault version and two certificates are elsewhere")
	locs := body["locations"].([]any)
	require.Len(t, locs, 1)
	assert.Equal(t, "web-pay", locs[0].(map[string]any)["target_name"])
	vaults := body["vaults"].([]any)
	require.Len(t, vaults, 1)
	assert.Equal(t, "kv-pay", vaults[0].(map[string]any)["vault_name"])
	certs := body["certificates"].([]any)
	require.Len(t, certs, 1)
	assert.Equal(t, "seen", certs[0].(map[string]any)["subject_cn"])
	assert.Equal(t, true, body["endpoints_hidden"], "the network map is a global reader's")
	assert.NotContains(t, rec.Body.String(), "web-other")
	assert.NotContains(t, rec.Body.String(), "kv-other")

	// A certificate whose service cannot be read fails the answer; so do the servers' services.
	resolveErr = errCovDBoom
	rec = call(h, http.MethodGet, target, "covd-scoped", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	resolveErr = nil
	sv.targetErr = errCovDBoom
	rec = call(h, http.MethodGet, target, "covd-scoped", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "web-pay")
}

// An incident's locations are read with their servers' services; when those cannot be read nothing is answered.
func TestCovDIncidentAnswerFailsWhenServersCannotBeRead(t *testing.T) {
	d, inc, sv := covDScopedDeps(t)
	sv.ResolveFn = func(string, any) (services.Resolution, error) {
		return services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}, nil
	}
	inc.GetIncidentFn = func(context.Context, uuid.UUID) (inventory.Incident, error) { return sampleIncident(), nil }
	h := NewHandler(d)
	target := "/api/v1/incidents/" + incidentID.String()

	sv.targetServices[targetID] = svcDefault
	rec := call(h, http.MethodGet, target, "covd-scoped", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := jsonObj(t, rec)
	assert.Empty(t, body["locations"], "web-01 is in another service")
	assert.Equal(t, float64(1), body["hidden_count"])

	sv.targetErr = errCovDBoom
	rec = call(h, http.MethodGet, target, "covd-scoped", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "web-01")
}

// covDLDAP is the LDAP harness with the refusal floor off and the server's log captured.
func covDLDAP(t *testing.T) (*server, http.Handler, *fakeLDAP, *fakeAuth, *syncLog) {
	t.Helper()
	d, fl, fa := ldapDeps(t)
	logs := &syncLog{}
	d.Log = slog.New(slog.NewTextHandler(logs, nil))
	s := newServer(d)
	s.ldapRefusalFloor = 0
	return s, s.handler(s.apiRoutes()), fl, fa, logs
}

// A malformed id is the route's 404 on every directory route with an id, before the service is asked.
func TestCovDDirectoryRoutesAnswerAMalformedID(t *testing.T) {
	_, h, fl, _, _ := covDLDAP(t)
	dirQuery := "?directory_id=" + testDirectoryID.String()
	cases := []struct{ method, path, who, body string }{
		{http.MethodPost, "/api/v1/auth/ldap/nope/login", "", `{"username":"deniz","password":"pw-1"}`},
		{http.MethodGet, "/api/v1/ldap/directories/nope", "admin-stepup", ""},
		{http.MethodPatch, "/api/v1/ldap/directories/nope", "admin-stepup", `{"name":"x"}`},
		{http.MethodDelete, "/api/v1/ldap/directories/nope", "admin-stepup", ""},
		{http.MethodPost, "/api/v1/ldap/directories/nope/actions/test-connection", "admin-stepup", ""},
		{http.MethodPost, "/api/v1/ldap/directories/nope/actions/test-signin", "admin-stepup", `{"username":"deniz","password":"pw-1"}`},
		{http.MethodDelete, "/api/v1/ldap/group-mappings/nope" + dirQuery, "admin-stepup", ""},
	}
	before := fl.calls()
	for _, c := range cases {
		rec := call(h, c.method, c.path, c.who, c.body)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s: %s", c.method, c.path, rec.Body.String())
		assert.Equal(t, "ALC-SYS-0001", decodeErr(t, rec).Error.Code, c.path)
	}
	assert.Equal(t, before, fl.calls(), "the directory service was never asked")
}

// A failure of the directory service or the database is a 500 on every directory route, never a refusal or an answer.
func TestCovDDirectoryRoutesFailClosed(t *testing.T) {
	_, h, fl, _, _ := covDLDAP(t)
	login := "/api/v1/auth/ldap/" + testDirectoryID.String() + "/login"
	one := "/api/v1/ldap/directories/" + testDirectoryID.String()
	mappings := "/api/v1/ldap/group-mappings?directory_id=" + testDirectoryID.String()
	fl.PublicDirectoriesFn = func(context.Context) ([]ldap.PublicDirectory, error) { return nil, errCovDBoom }
	fl.TestSignInFn = func(_ context.Context, _ audit.Actor, _ uuid.UUID, _ string, password secrets.Plaintext) (ldap.TestResult, error) {
		password.Zero()
		return ldap.TestResult{}, errCovDBoom
	}

	expect500 := func(method, path, who, body string) {
		t.Helper()
		rec := call(h, method, path, who, body)
		assert.Equal(t, http.StatusInternalServerError, rec.Code, "%s %s: %s", method, path, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), errCovDBoom.Error())
	}
	expect500(http.MethodGet, "/api/v1/auth/ldap/directories", "", "")
	expect500(http.MethodGet, "/api/v1/ldap/directories", "admin-stepup", "") // DirectoriesFn unset
	expect500(http.MethodPost, one+"/actions/test-connection", "admin-stepup", "")
	expect500(http.MethodPost, one+"/actions/test-signin", "admin-stepup", `{"username":"deniz","password":"pw-1"}`)
	expect500(http.MethodGet, mappings, "admin-stepup", "")
	mappingID := uuid.New()
	expect500(http.MethodDelete, "/api/v1/ldap/group-mappings/"+mappingID.String()+"?directory_id="+testDirectoryID.String(), "admin-stepup", "")
	// The directory holds the mapping, and the delete itself fails.
	fl.MappingsFn = func(context.Context, uuid.UUID) ([]ldap.Mapping, error) { return []ldap.Mapping{{ID: mappingID}}, nil }
	expect500(http.MethodDelete, "/api/v1/ldap/group-mappings/"+mappingID.String()+"?directory_id="+testDirectoryID.String(), "admin-stepup", "")

	// The sign-in: the directory cannot be read, or the role of the groups cannot be.
	fl.DirectoryFn = func(context.Context, uuid.UUID) (ldap.Directory, error) { return ldap.Directory{}, errCovDBoom }
	expect500(http.MethodPost, login, "", `{"username":"deniz","password":"pw-1"}`)
	fl.DirectoryFn = func(context.Context, uuid.UUID) (ldap.Directory, error) {
		return ldap.Directory{ID: testDirectoryID, Enabled: true, MFARequired: true, Version: 1}, nil
	}
	fl.ResolveRoleFn = func(context.Context, uuid.UUID, []string) (rbac.Role, bool, error) { return "", false, errCovDBoom }
	expect500(http.MethodPost, login, "", `{"username":"deniz","password":"pw-1"}`)
	expect500(http.MethodPost, "/api/v1/auth/ldap/stepup", "ldap-user", `{"password":"pw-1"}`)
}

// The directory forms are checked before anything is sent to a directory: a step-up code over 16 characters, a test
// sign-in name over the form's limit, a mapping without a directory or with an unknown role, and too many mappings
// (a field error on group).
func TestCovDDirectoryFormsAreValidated(t *testing.T) {
	_, h, fl, _, _ := covDLDAP(t)
	rec := call(h, http.MethodPost, "/api/v1/auth/ldap/stepup", "ldap-user", `{"password":"pw-1","code":"`+strings.Repeat("1", 17)+`"}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"field":"code"`)

	rec = call(h, http.MethodPost, "/api/v1/ldap/directories/"+testDirectoryID.String()+"/actions/test-signin", "admin-stepup",
		`{"username":"`+strings.Repeat("a", maxLoginUsername+1)+`","password":"pw-1"}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"field":"username"`)

	var created int
	fl.CreateMappingFn = func(context.Context, audit.Actor, uuid.UUID, string, rbac.Role) (ldap.Mapping, error) {
		created++
		return ldap.Mapping{}, ldap.ErrTooMany
	}
	rec = call(h, http.MethodPost, "/api/v1/ldap/group-mappings", "admin-stepup", `{"directory_id":"","group":"ops","role":"operator"}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"field":"directory_id"`)
	rec = call(h, http.MethodPost, "/api/v1/ldap/group-mappings", "admin-stepup",
		`{"directory_id":"`+testDirectoryID.String()+`","group":"ops","role":"owner"}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"field":"role"`)
	assert.Zero(t, created, "a refused form never reaches the service")

	rec = call(h, http.MethodPost, "/api/v1/ldap/group-mappings", "admin-stepup",
		`{"directory_id":"`+testDirectoryID.String()+`","group":"ops","role":"operator"}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"field":"group"`)
	assert.Contains(t, rec.Body.String(), `"max":"`+strconv.Itoa(ldap.MaxMappings)+`"`)
	assert.Equal(t, 1, created)
}

// A refusal and a lockout are recorded on the side: when recording fails the person still gets the refusal, and the
// failure is logged. An entry whose account key is locked is refused by the gate before any bind, and that refusal
// is no guess: it does not count against the name the person typed.
func TestCovDDirectoryRecordingFailuresAreLoggedAndTheLockedAccountIsNoGuess(t *testing.T) {
	s, h, fl, fa, logs := covDLDAP(t)
	login := "/api/v1/auth/ldap/" + testDirectoryID.String() + "/login"
	fa.RefuseLDAPFn = func(context.Context, auth.LDAPIdentity, string, auth.Meta) error { return errCovDBoom }
	fa.RecordLDAPLockoutFn = func(context.Context, auth.LDAPIdentity, string, int, auth.Meta) error { return errCovDBoom }
	// Every name finds the one entry 0a0b; only pw-1 is its password.
	fl.VerifyFn = func(_ context.Context, _ uuid.UUID, login string, password secrets.Plaintext) (ldap.Identity, ldap.Directory, error) {
		defer password.Zero()
		dir := ldap.Directory{ID: testDirectoryID, Enabled: true, MFARequired: true, Version: 1}
		if string(password.Bytes()) != "pw-1" {
			return ldap.Identity{UniqueID: "0a0b", Login: login}, dir, &ldap.LoginError{Reason: ldap.ReasonBadCredentials, Detail: ldap.DetailUserBind}
		}
		return ldap.Identity{UniqueID: "0a0b", Login: login, Groups: []string{"ops"}}, dir, nil
	}
	refuse := func(name, password string) {
		t.Helper()
		s.login.Reset() // the per-address sign-in limit is not what this test is about
		rec := call(h, http.MethodPost, login, "", `{"username":"`+name+`","password":"`+password+`"}`)
		require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		assert.Equal(t, "ALC-LDAP-0001", decodeErr(t, rec).Error.Code)
	}
	// Three wrong passwords under three names lock the account (each name has one failure).
	refuse("ada1", "pw-2")
	assert.Contains(t, logs.String(), "recording a refused directory sign-in failed")
	refuse("ada2", "pw-2")
	refuse("ada3", "pw-2")
	assert.Contains(t, logs.String(), "recording a directory sign-in lockout failed")
	assert.NotContains(t, logs.String(), "pw-2")

	// The account is locked: the right password under a fourth name is refused by the gate.
	assert.True(t, s.ldapAccountLockout.Locked(ldapAccountKey(testDirectoryID, "0a0b")))
	refuse("ada4", "pw-1")
}

// countsAsFailure: a wrong password and several entries are guesses; a refusal before the bind (a locked account), an
// unreachable directory and other errors are not; a password whose groups give no access is.
func TestCovDCountsAsFailure(t *testing.T) {
	assert.True(t, countsAsFailure(&ldap.LoginError{Reason: ldap.ReasonBadCredentials, Detail: ldap.DetailUserBind}))
	assert.True(t, countsAsFailure(&ldap.LoginError{Reason: ldap.ReasonAmbiguousUser}))
	assert.False(t, countsAsFailure(&ldap.LoginError{Reason: ldap.ReasonBadCredentials, Detail: ldap.DetailLocked}), "no guess was made")
	assert.False(t, countsAsFailure(&ldap.LoginError{Reason: ldap.ReasonUnreachable}))
	assert.True(t, countsAsFailure(errNoAccess))
	assert.False(t, countsAsFailure(errCovDBoom))
}
