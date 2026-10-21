//go:build integration

package services_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
)

// Directory groups (R49 Phase 3, R54; design §6.1): declared per SSO provider or directory with the mappings' value
// rules, listed with the people seen in them; their bindings reach the members by the groups of their last sign-in
// (their own provider's only); deleting one takes its bindings and owner entries with it.
func TestDirectoryGroups(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	provider, other := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{provider, other} {
		_, err = w.d.Owner.Exec(ctx, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at) VALUES ($1, $2, 'https://idp.example.test',
$3, '{openid}', 'groups', 'https://idp.example.test/a', 'https://idp.example.test/t', 'https://idp.example.test/j', true, now(), now())`, id, "IdP "+id.String(), "alice-"+id.String())
		require.NoError(t, err)
	}
	sam := uuid.New()
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO users (id, username, display_name, auth_source, role, role_source, oidc_provider_id, oidc_issuer,
    oidc_subject, created_at, updated_at) VALUES ($1, 'sam', 'Sam', 'oidc', NULL, 'oidc_mapping', $2, 'https://idp.example.test', 'sam', now(), now())`,
		sam, provider)
	require.NoError(t, err)
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO user_directory_groups (user_id, value, seen_at) VALUES ($1, 'pay-ops', now()), ($1, 'eng', now())`, sam)
	require.NoError(t, err)

	// The rules of the input.
	for _, bad := range []struct {
		in    services.DirectoryGroupInput
		field string
		code  string
	}{
		{services.DirectoryGroupInput{Source: "saml", Value: "x"}, "source", validate.OneOf},
		{services.DirectoryGroupInput{Source: services.SourceOIDC, Value: "x"}, "provider_id", validate.Required},
		{services.DirectoryGroupInput{Source: services.SourceLDAP, ProviderID: &provider, Value: "x"}, "directory_id", validate.Required},
		{services.DirectoryGroupInput{Source: services.SourceOIDC, ProviderID: &provider, Value: " pay-ops"}, "value", validate.Pattern},
		{services.DirectoryGroupInput{Source: services.SourceOIDC, ProviderID: &provider, Value: "pay​ops"}, "value", validate.Pattern},
		{services.DirectoryGroupInput{Source: services.SourceOIDC, ProviderID: &provider, Value: ""}, "value", validate.Required},
	} {
		_, err := w.store.CreateDirectoryGroup(ctx, w.admin, bad.in)
		fieldErr(t, err, bad.field, bad.code)
	}
	missing := uuid.New()
	_, err = w.store.CreateDirectoryGroup(ctx, w.admin, services.DirectoryGroupInput{Source: services.SourceOIDC, ProviderID: &missing, Value: "x"})
	fieldErr(t, err, "provider_id", validate.Required)

	// The values seen at sign-in are offered before any is declared.
	groups, seen, err := w.store.DirectoryGroups(ctx)
	require.NoError(t, err)
	assert.Empty(t, groups)
	require.Len(t, seen, 2)
	assert.Equal(t, provider, *seen[0].ProviderID)
	assert.Equal(t, 1, seen[0].Users)
	assert.Nil(t, seen[0].GroupID)

	g, err := w.store.CreateDirectoryGroup(ctx, w.admin, services.DirectoryGroupInput{Source: services.SourceOIDC, ProviderID: &provider,
		Value: "pay-ops", Label: "Ödeme ekibi"})
	require.NoError(t, err)
	assert.Equal(t, 1, g.Members)
	assert.Equal(t, "Ödeme ekibi", g.Label)
	assert.Equal(t, "IdP "+provider.String(), g.SourceName)
	_, err = w.store.CreateDirectoryGroup(ctx, w.admin, services.DirectoryGroupInput{Source: services.SourceOIDC, ProviderID: &provider, Value: "pay-ops"})
	assert.ErrorIs(t, err, services.ErrDirectoryGroupExists)
	elsewhere, err := w.store.CreateDirectoryGroup(ctx, w.admin, services.DirectoryGroupInput{Source: services.SourceOIDC, ProviderID: &other, Value: "eng"})
	require.NoError(t, err, "the same value of another provider is another group")
	assert.Zero(t, elsewhere.Members, "sam is not that provider's")
	assert.Equal(t, 2, w.auditCount(t, "access.directory_group_added"))

	// Bindings of groups: one subject, counted per group, audited with the group.
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: sam, DirectoryGroupID: g.ID, Role: "operator", ServiceID: &pay.ID})
	fieldErr(t, err, "directory_group_id", validate.Pattern)
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{DirectoryGroupID: uuid.New(), Role: "operator", ServiceID: &pay.ID})
	fieldErr(t, err, "directory_group_id", validate.Required)
	bound, err := w.store.CreateBinding(ctx, w.admin, services.BindingInput{DirectoryGroupID: g.ID, Role: "admin", ServiceID: &pay.ID})
	require.NoError(t, err)
	require.NotNil(t, bound.Group)
	assert.Equal(t, "pay-ops", bound.Group.Value)
	assert.Nil(t, bound.UserID)
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{DirectoryGroupID: g.ID, Role: "admin", ServiceID: &pay.ID})
	assert.ErrorIs(t, err, services.ErrBindingDuplicate)
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{DirectoryGroupID: elsewhere.ID, Role: "operator", ServiceID: &pay.ID})
	require.NoError(t, err)
	var details map[string]string
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT details FROM audit_log WHERE action = 'access.binding_added' ORDER BY seq LIMIT 1").Scan(&details))
	assert.Equal(t, map[string]string{"directory_group_id": g.ID.String(), "group_source": "oidc", "group": "pay-ops", "role": "admin",
		"service_id": pay.ID.String()}, details)

	// The member's grants: the group of their own provider only, capped at Operator while SSO users may not be Admin.
	grants, err := authz.LoadGrants(ctx, w.d.App, sam)
	require.NoError(t, err)
	assert.Equal(t, []rbac.ScopedGrant{{Role: rbac.Operator, Services: []uuid.UUID{pay.ID}}}, grants)
	acc, err := w.store.Access(ctx, sam)
	require.NoError(t, err)
	assert.Empty(t, acc.Bindings)
	require.Len(t, acc.GroupBindings, 1, "the explanation lists the rights through groups")
	assert.Equal(t, bound.ID, acc.GroupBindings[0].ID)
	list, err := w.store.Bindings(ctx, services.BindingFilter{DirectoryGroupID: &g.ID})
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// Deleting the group takes its binding and owner entry; the member loses the right at the next read.
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO service_owners (id, service_id, directory_group_id, created_at) VALUES (gen_random_uuid(), $1, $2, now())`,
		pay.ID, g.ID)
	require.NoError(t, err)
	removed, err := w.store.DeleteDirectoryGroup(ctx, w.admin, g.ID)
	require.NoError(t, err)
	assert.Equal(t, services.GroupRemoval{Bindings: 1, Owners: 1}, removed)
	_, err = w.store.DeleteDirectoryGroup(ctx, w.admin, g.ID)
	assert.ErrorIs(t, err, services.ErrDirectoryGroupNotFound)
	grants, err = authz.LoadGrants(ctx, w.d.App, sam)
	require.NoError(t, err)
	assert.Empty(t, grants)
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT details FROM audit_log WHERE action = 'access.directory_group_removed'").Scan(&details))
	assert.Equal(t, "1", details["bindings_removed"])
	assert.Equal(t, "1", details["owners_removed"])
}
