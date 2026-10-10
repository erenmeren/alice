//go:build integration

package oidc_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth/oidc"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeidp"
)

func TestCreateProviderReadsDiscoveryOnce(t *testing.T) {
	x := newHarness(t)
	p := x.prov
	assert.Equal(t, x.idp.Issuer()+"/authorize", p.Endpoints.Authorization)
	assert.Equal(t, x.idp.Issuer()+"/token", p.Endpoints.Token)
	assert.Equal(t, x.idp.Issuer()+"/jwks", p.Endpoints.JWKS)
	assert.Equal(t, publicURL+"/api/v1/auth/oidc/"+p.ID.String()+"/callback", p.RedirectURI)
	assert.True(t, p.HasClientSecret)
	assert.Equal(t, []string{"openid", "profile", "email"}, p.Scopes)
	assert.Equal(t, "groups", p.GroupsClaim)
	assert.Equal(t, 1, p.Version)
	before := x.idp.Stats().Discovery
	_, err := x.login(t, "/")
	require.Error(t, err) // no identity or mapping yet
	assert.Equal(t, before, x.idp.Stats().Discovery, "endpoints are fixed at configuration time, never read at sign-in")
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.provider_created'`))

	got, err := x.svc.Provider(x.ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, p.RedirectURI, got.RedirectURI)
	all, err := x.svc.Providers(x.ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)
	public, err := x.svc.PublicProviders(x.ctx)
	require.NoError(t, err)
	assert.Equal(t, []oidc.PublicProvider{{ID: p.ID, Name: "Corp IdP"}}, public)
	_, err = x.svc.Provider(x.ctx, [16]byte{1})
	assert.ErrorIs(t, err, oidc.ErrNotFound)
	assert.Equal(t, "", oidc.RedirectURI("", p.ID))
	assert.Equal(t, publicURL+"/api/v1/auth/oidc/"+p.ID.String()+"/callback", oidc.RedirectURI(publicURL+"/", p.ID))
}

// Review Focus 3: the client secret is only an envelope; nothing else holds it.
func TestClientSecretIsAnEnvelope(t *testing.T) {
	x := newHarness(t)
	var dump string
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT (SELECT string_agg(t::text, ' ') FROM oidc_providers t) ||
(SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log) || (SELECT coalesce(string_agg(value::text, ' '), '') FROM settings)`).Scan(&dump))
	assert.NotContains(t, dump, x.idp.ClientSecret())
	var ct []byte
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT ciphertext FROM setting_secrets WHERE key = $1`,
		"sso.provider."+x.prov.ID.String()+".client_secret").Scan(&ct))
	assert.NotContains(t, string(ct), x.idp.ClientSecret())
}

// O-12: plain HTTP and an untrusted certificate are refused at configuration.
func TestO12InsecureIssuerRefused(t *testing.T) {
	x := newHarness(t)
	plain := fakeidp.Start(t, fakeidp.Options{Plain: true})
	_, err := x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Plain", IssuerURL: plain.Issuer(), ClientID: "alice",
		ClientSecret: secrets.NewPlaintext([]byte("s"))})
	var v validate.Errors
	require.True(t, errors.As(err, &v), "%v", err)
	assert.Equal(t, "issuer_url", v[0].Field)
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "No CA", IssuerURL: x.idp.Issuer(), ClientID: "other",
		ClientSecret: secrets.NewPlaintext([]byte("s"))})
	var de *oidc.DiscoveryError
	require.True(t, errors.As(err, &de), "%v", err)
	assert.Equal(t, "tls", de.Cause)
	assert.Contains(t, de.Error(), "tls")
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Mismatch", IssuerURL: x.idp.Issuer() + "/realms/x",
		ClientID: "other", ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: string(x.idp.CAPEM())})
	require.True(t, errors.As(err, &de))
	assert.Contains(t, []string{"status", "issuer_mismatch"}, de.Cause)
	x.idp.Down()
	_, err = x.svc.RefreshProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version)
	require.True(t, errors.As(err, &de))
	assert.Equal(t, "status", de.Cause)
	x.idp.Up()
	unreachable := "https://127.0.0.1:1"
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Gone", IssuerURL: unreachable, ClientID: "other",
		ClientSecret: secrets.NewPlaintext([]byte("s"))})
	require.True(t, errors.As(err, &de), "%v", err)
	assert.Equal(t, "connect", de.Cause)
}

func TestProviderValidation(t *testing.T) {
	x := newHarness(t)
	fields := func(err error) []string {
		var v validate.Errors
		require.True(t, errors.As(err, &v), "%v", err)
		var out []string
		for _, f := range v {
			out = append(out, f.Field)
		}
		return out
	}
	_, err := x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "", IssuerURL: "https://idp.example.com", ClientID: "a b",
		GroupsClaim: "bad claim", Scopes: []string{"profile"}, CAPEM: "not pem"})
	assert.Equal(t, []string{"name", "client_id", "client_secret", "scopes", "groups_claim", "ca_pem"}, fields(err))
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: strings.Repeat("n", 61), IssuerURL: x.idp.Issuer(),
		ClientID: strings.Repeat("c", 256), ClientSecret: secrets.NewPlaintext([]byte(strings.Repeat("s", 1025))),
		Scopes: []string{"openid", "bad scope"}})
	assert.Equal(t, []string{"name", "client_id", "client_secret", "scopes"}, fields(err))
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Corp IdP", IssuerURL: x.idp.Issuer(), ClientID: "other",
		ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: string(x.idp.CAPEM())})
	assert.Equal(t, []string{"name"}, fields(err), "the name is taken")
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Second", IssuerURL: x.idp.Issuer(), ClientID: x.idp.ClientID(),
		ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: string(x.idp.CAPEM())})
	assert.Equal(t, []string{"client_id"}, fields(err), "issuer and client ID are taken")
	key := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Key", IssuerURL: x.idp.Issuer(), ClientID: "k",
		ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: key})
	assert.Equal(t, []string{"ca_pem"}, fields(err), "only CERTIFICATE blocks")

	// Alice's address is needed for an enabled provider.
	require.NoError(t, settings.Set(x.ctx, x.d.App, settings.GeneralKey, settings.General{RetiredKeyRetentionDays: 30, Version: 2}, x.clk.Now()))
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Enabled", IssuerURL: x.idp.Issuer(), ClientID: "e",
		ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: string(x.idp.CAPEM()), Enabled: true})
	assert.ErrorIs(t, err, oidc.ErrPublicURLMissing)
	off, err := x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Off", IssuerURL: x.idp.Issuer(), ClientID: "off",
		ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: string(x.idp.CAPEM())})
	require.NoError(t, err)
	assert.Empty(t, off.RedirectURI, "no address, no redirect URI")
	_, err = x.svc.UpdateProvider(x.ctx, x.admin, off.ID, off.Version, oidc.ProviderPatch{Enabled: ptrBool(true)})
	assert.ErrorIs(t, err, oidc.ErrPublicURLMissing)
	_, err = x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	assert.ErrorIs(t, err, oidc.ErrPublicURLMissing)
}

func TestProviderUpdateRefreshAndLimit(t *testing.T) {
	x := newHarness(t)
	name, scopes, claim := "Renamed", []string{"openid", "email"}, "roles"
	p, err := x.svc.UpdateProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version, oidc.ProviderPatch{Name: &name, Scopes: &scopes,
		GroupsClaim: &claim, ClientSecret: ptrSecret("new-secret")})
	require.NoError(t, err)
	assert.Equal(t, [3]any{"Renamed", "roles", 2}, [3]any{p.Name, p.GroupsClaim, p.Version})
	assert.Equal(t, scopes, p.Scopes)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.provider_changed' AND details->>'client_auth_replaced' = 'true'`))
	discoveries := x.idp.Stats().Discovery
	issuer := x.idp.Issuer() + "/"
	_, err = x.svc.UpdateProvider(x.ctx, x.admin, p.ID, p.Version, oidc.ProviderPatch{IssuerURL: &issuer, ClientSecret: ptrSecret("s2")})
	var de *oidc.DiscoveryError
	require.True(t, errors.As(err, &de), "a changed issuer is discovered again: %v", err)
	assert.Equal(t, discoveries+1, x.idp.Stats().Discovery)
	bad := ""
	_, err = x.svc.UpdateProvider(x.ctx, x.admin, p.ID, p.Version, oidc.ProviderPatch{Name: &bad})
	var v validate.Errors
	assert.True(t, errors.As(err, &v))
	p, err = x.svc.RefreshProvider(x.ctx, x.admin, p.ID, p.Version)
	require.NoError(t, err)
	assert.Equal(t, 3, p.Version)
	_, err = x.svc.RefreshProvider(x.ctx, x.admin, p.ID, 1)
	assert.ErrorIs(t, err, oidc.ErrVersion)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.provider_refreshed'`))
	_, err = x.svc.UpdateProvider(x.ctx, x.admin, [16]byte{9}, 1, oidc.ProviderPatch{})
	assert.ErrorIs(t, err, oidc.ErrNotFound)

	for i := 2; i <= oidc.MaxProviders; i++ {
		_, err := x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "P" + strconv.Itoa(i), IssuerURL: x.idp.Issuer(),
			ClientID: "c" + strconv.Itoa(i), ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: string(x.idp.CAPEM())})
		require.NoError(t, err)
	}
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Six", IssuerURL: x.idp.Issuer(), ClientID: "c6",
		ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: string(x.idp.CAPEM())})
	assert.ErrorIs(t, err, oidc.ErrTooMany)
}

// Final review minor 11: the stored client secret is never sent to another issuer. An issuer change without a new
// secret is a 422 on client_secret before any discovery, and changes nothing; with the secret it goes through. Other
// changes, the CA bundle included, keep the stored secret.
func TestIssuerChangeNeedsTheClientSecret(t *testing.T) {
	x := newHarness(t)
	idp2 := fakeidp.Start(t, fakeidp.Options{Now: x.clk.Now})
	issuer2, ca2 := idp2.Issuer(), string(idp2.CAPEM())
	discoveries := idp2.Stats().Discovery
	_, err := x.svc.UpdateProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version, oidc.ProviderPatch{IssuerURL: &issuer2, CAPEM: &ca2})
	var v validate.Errors
	require.True(t, errors.As(err, &v), "%v", err)
	require.Len(t, v, 1)
	assert.Equal(t, [2]string{"client_secret", validate.Required}, [2]string{v[0].Field, v[0].Code})
	assert.Equal(t, discoveries, idp2.Stats().Discovery, "refused before discovery")
	got, err := x.svc.Provider(x.ctx, x.prov.ID)
	require.NoError(t, err)
	assert.Equal(t, [2]any{x.idp.Issuer(), x.prov.Version}, [2]any{got.IssuerURL, got.Version}, "nothing changed")

	ca := string(x.idp.CAPEM()) + "\n"
	p, err := x.svc.UpdateProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version, oidc.ProviderPatch{CAPEM: &ca})
	require.NoError(t, err, "the same issuer keeps its secret")
	p, err = x.svc.UpdateProvider(x.ctx, x.admin, p.ID, p.Version, oidc.ProviderPatch{IssuerURL: &issuer2, CAPEM: &ca2,
		ClientSecret: ptrSecret(idp2.ClientSecret())})
	require.NoError(t, err, "a new issuer with its secret")
	assert.Equal(t, issuer2, p.IssuerURL)
}

func ptrSecret(s string) *secrets.Plaintext { p := secrets.NewPlaintext([]byte(s)); return &p }

// O-13, R42 row 24.
func TestAdminMappingRefusedWhileOff(t *testing.T) {
	x := newHarness(t)
	set, err := x.svc.Settings(x.ctx)
	require.NoError(t, err)
	assert.Equal(t, oidc.SSOSettings{}, set, "off by default, never saved")
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, "admins", rbac.Admin)
	assert.ErrorIs(t, err, oidc.ErrAdminMappingDisabled)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.mapping.denied' AND details->>'reason' = 'admin_disabled'`))
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, " ", rbac.Operator)
	var v validate.Errors
	assert.True(t, errors.As(err, &v), "no all-users mapping")
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, "ops", rbac.Role("root"))
	require.True(t, errors.As(err, &v))
	assert.Equal(t, "role", v[0].Field)
	set, err = x.svc.SaveSettings(x.ctx, x.admin, 0, true)
	require.NoError(t, err)
	assert.Equal(t, oidc.SSOSettings{AllowAdminRole: true, Version: 1}, set)
	_, err = x.svc.SaveSettings(x.ctx, x.admin, 0, true)
	assert.ErrorIs(t, err, oidc.ErrVersion)
	m, err := x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, "admins", rbac.Admin)
	require.NoError(t, err)

	// An SSO Administrator signs in, so the switch-off has someone to demote.
	x.idp.NextLogin(fakeidp.Login{Subject: "boss", Username: "boss", Groups: []string{"admins"}})
	c, err := x.login(t, "/")
	require.NoError(t, err)
	pr, err := x.auth.Authenticate(x.ctx, c.Session.Token)
	require.NoError(t, err)
	assert.Equal(t, rbac.Admin, pr.Role)

	_, err = x.svc.SaveSettings(x.ctx, x.admin, set.Version, false)
	assert.ErrorIs(t, err, oidc.ErrAdminMappingsExist)
	require.NoError(t, x.svc.DeleteMapping(x.ctx, x.admin, m.ID))
	assert.ErrorIs(t, x.svc.DeleteMapping(x.ctx, x.admin, m.ID), oidc.ErrNotFound)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.mapping_created' AND details->>'role' = 'admin'`))
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.mapping_deleted'`))
	set, err = x.svc.SaveSettings(x.ctx, x.admin, set.Version, false)
	require.NoError(t, err)
	assert.Equal(t, oidc.SSOSettings{AllowAdminRole: false, Version: 2}, set)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.admin_role_disallowed'
AND details->>'demoted_count' = '1' AND details->>'ended_count' = '1'`))
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.admin_role_allowed'`))
	_, err = x.auth.Authenticate(x.ctx, c.Session.Token)
	assert.Error(t, err, "the demoted Administrator's session ended")
}

// Task 2 review: a group is mapped once per provider; the list is by group value.
func TestDuplicateMappingRefused(t *testing.T) {
	x := newHarness(t)
	x.mapGroup(t, "ops", rbac.Operator)
	x.mapGroup(t, "audit", rbac.Auditor)
	_, err := x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, "ops", rbac.Auditor)
	var v validate.Errors
	require.True(t, errors.As(err, &v), "%v", err)
	assert.Equal(t, validate.FieldError{Field: "group", Code: validate.Duplicate}, v[0])
	ms, err := x.svc.Mappings(x.ctx, x.prov.ID)
	require.NoError(t, err)
	require.Len(t, ms, 2)
	assert.Equal(t, [2]string{"audit", "ops"}, [2]string{ms[0].Group, ms[1].Group})
	_, err = x.svc.CreateMapping(x.ctx, x.admin, [16]byte{3}, "ops", rbac.Operator)
	assert.ErrorIs(t, err, oidc.ErrNotFound)
}

// S-5: the mapping create and the switch-off take the setting row FOR UPDATE, so they serialize.
func TestMappingCreateWaitsForTheSwitch(t *testing.T) {
	x := newHarness(t)
	set, err := x.svc.SaveSettings(x.ctx, x.admin, 0, true)
	require.NoError(t, err)
	tx, err := x.d.Owner.Begin(x.ctx)
	require.NoError(t, err)
	_, err = tx.Exec(x.ctx, `SELECT 1 FROM settings WHERE key = $1 FOR UPDATE`, oidc.AllowAdminKey)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, "admins", rbac.Admin)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("CreateMapping did not wait for the setting row: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	// The switch goes off while the create waits; the create then sees it off.
	_, err = tx.Exec(x.ctx, `UPDATE settings SET value = '{"allow": false, "version": 2}' WHERE key = $1`, oidc.AllowAdminKey)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(x.ctx))
	assert.ErrorIs(t, <-done, oidc.ErrAdminMappingDisabled)
	_ = set
}

func TestProviderLimitsAndDeletion(t *testing.T) {
	x := newHarness(t)
	x.mapGroup(t, "ops", rbac.Operator)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"ops"}})
	_, err := x.login(t, "/")
	require.NoError(t, err)
	err = x.svc.DeleteProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version)
	assert.ErrorIs(t, err, oidc.ErrProviderInUse)
	p, err := x.svc.UpdateProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version, oidc.ProviderPatch{Enabled: ptrBool(false)})
	require.NoError(t, err)
	assert.False(t, p.Enabled)
	_, err = x.svc.UpdateProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version, oidc.ProviderPatch{Enabled: ptrBool(true)})
	assert.ErrorIs(t, err, oidc.ErrVersion)
	public, err := x.svc.PublicProviders(x.ctx)
	require.NoError(t, err)
	assert.Empty(t, public, "a disabled provider is not offered on the sign-in page")

	// I-1: the issuer of a provider with users cannot change (their subjects belong to that issuer, O-09).
	discoveries := x.idp.Stats().Discovery
	issuer := x.idp.Issuer() + "/"
	_, err = x.svc.UpdateProvider(x.ctx, x.admin, p.ID, p.Version, oidc.ProviderPatch{IssuerURL: &issuer, ClientSecret: ptrSecret("s2")})
	assert.ErrorIs(t, err, oidc.ErrProviderInUse)
	assert.Equal(t, discoveries, x.idp.Stats().Discovery, "refused before discovery")
	renamed := "Corp IdP (old)"
	_, err = x.svc.UpdateProvider(x.ctx, x.admin, p.ID, p.Version, oidc.ProviderPatch{Name: &renamed})
	require.NoError(t, err, "other fields still change")

	other, err := x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Unused", IssuerURL: x.idp.Issuer(), ClientID: "unused",
		ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: string(x.idp.CAPEM())})
	require.NoError(t, err)
	assert.ErrorIs(t, x.svc.DeleteProvider(x.ctx, x.admin, other.ID, other.Version+1), oidc.ErrVersion)
	require.NoError(t, x.svc.DeleteProvider(x.ctx, x.admin, other.ID, other.Version))
	assert.ErrorIs(t, x.svc.DeleteProvider(x.ctx, x.admin, other.ID, other.Version), oidc.ErrNotFound)
	assert.Zero(t, x.count(t, `SELECT count(*) FROM setting_secrets WHERE key = $1`, "sso.provider."+other.ID.String()+".client_secret"))
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.provider_deleted'`))
}

func ptrBool(v bool) *bool { return &v }

// I-1: an issuer change on a provider without users goes through; a first sign-in that inserts its user while the
// change runs discovery is seen under the provider's row lock, and the change is refused.
func TestIssuerChangeRefusedOnceAUserArrives(t *testing.T) {
	x := newHarness(t)
	idp2 := fakeidp.Start(t, fakeidp.Options{Now: x.clk.Now})
	issuer2, ca2 := idp2.Issuer(), string(idp2.CAPEM())
	p, err := x.svc.UpdateProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version, oidc.ProviderPatch{IssuerURL: &issuer2, CAPEM: &ca2,
		ClientSecret: ptrSecret(idp2.ClientSecret())})
	require.NoError(t, err, "no users yet: the issuer may change")
	assert.Equal(t, issuer2, p.IssuerURL)

	// A first sign-in's insert, not yet committed: the early check sees no user, the locked one waits for it.
	tx, err := x.d.Owner.Begin(x.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(x.ctx) }()
	_, err = tx.Exec(x.ctx, `INSERT INTO users (id, username, display_name, auth_source, role, role_source, oidc_provider_id, oidc_issuer,
oidc_subject, created_at, updated_at) VALUES ($1, 'late', 'Late', 'oidc', 'auditor', 'oidc_mapping', $2, $3, 'u9', now(), now())`,
		uuid.New(), p.ID, issuer2)
	require.NoError(t, err)
	issuer1, ca1 := x.idp.Issuer(), string(x.idp.CAPEM())
	done := make(chan error, 1)
	go func() {
		_, err := x.svc.UpdateProvider(x.ctx, x.admin, p.ID, p.Version, oidc.ProviderPatch{IssuerURL: &issuer1, CAPEM: &ca1,
			ClientSecret: ptrSecret("s1")})
		done <- err
	}()
	require.Eventually(t, func() bool {
		return x.count(t, `SELECT count(*) FROM pg_locks WHERE NOT granted`) > 0
	}, 10*time.Second, 10*time.Millisecond, "the change waits on the provider's row")
	require.NoError(t, tx.Commit(x.ctx))
	assert.ErrorIs(t, <-done, oidc.ErrProviderInUse)
	got, err := x.svc.Provider(x.ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, issuer2, got.IssuerURL, "the issuer did not change")
}
