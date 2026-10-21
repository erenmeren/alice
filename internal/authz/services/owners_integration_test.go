//go:build integration

package services_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz/services"
	"alice/internal/platform/validate"
)

// SR-28 (R56, design §7.1): a service's owner team is people and directory groups, replaced as a whole with the
// service's version; an automation account is refused; each owner shows whether a role reaches the service; the change
// is audited with what was added and removed, and raises the service's version.
func TestServiceOwners(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	person := func(username, email string, role any) uuid.UUID {
		id := uuid.New()
		_, err := w.d.Owner.Exec(ctx, `INSERT INTO users (id, username, display_name, email, password_hash, role, created_at, updated_at)
VALUES ($1, $2::text, $2::text, $3, '$argon2id$x', $4, now(), now())`, id, username, email, role)
		require.NoError(t, err)
		return id
	}
	olga, sam := person("olga", "olga@example.com", nil), person("sam", "", "operator")
	robot := uuid.New()
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO users (id, username, display_name, auth_source, role, created_at, updated_at)
VALUES ($1, 'robot', 'Robot', 'automation', NULL, now(), now())`, robot)
	require.NoError(t, err)
	provider := uuid.New()
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at) VALUES ($1, 'IdP', 'https://idp.example.test',
'alice', '{openid}', 'groups', 'https://idp.example.test/a', 'https://idp.example.test/t', 'https://idp.example.test/j', true, now(), now())`, provider)
	require.NoError(t, err)
	group, err := w.store.CreateDirectoryGroup(ctx, w.admin, services.DirectoryGroupInput{Source: services.SourceOIDC, ProviderID: &provider,
		Value: "pay-ops"})
	require.NoError(t, err)

	got, err := w.store.Owners(ctx, pay.ID)
	require.NoError(t, err)
	assert.Equal(t, pay.Version, got.Version)
	assert.Empty(t, got.Items)

	// The refusals, before anything is stored.
	for _, bad := range []struct {
		in    []services.OwnerInput
		field string
		code  string
	}{
		{[]services.OwnerInput{{}}, "owners.0.user_id", validate.Required},
		{[]services.OwnerInput{{UserID: olga, DirectoryGroupID: group.ID}}, "owners.0.directory_group_id", validate.Pattern},
		{[]services.OwnerInput{{UserID: olga}, {UserID: olga}}, "owners.1.user_id", validate.Duplicate},
		{[]services.OwnerInput{{UserID: uuid.New()}}, "owners.0.user_id", validate.Required},
		{[]services.OwnerInput{{DirectoryGroupID: uuid.New()}}, "owners.0.directory_group_id", validate.Required},
		{make([]services.OwnerInput, services.MaxOwnersPerService+1), "owners", validate.TooLong},
	} {
		_, err := w.store.SetOwners(ctx, w.admin, pay.ID, pay.Version, bad.in)
		fieldErr(t, err, bad.field, bad.code)
	}
	_, err = w.store.SetOwners(ctx, w.admin, pay.ID, pay.Version, []services.OwnerInput{{UserID: olga}, {UserID: robot}})
	var notPerson *services.OwnerNotAPersonError
	require.ErrorAs(t, err, &notPerson, "an automation account owns nothing")
	assert.Equal(t, "owners.1.user_id", notPerson.Field)
	_, err = w.store.SetOwners(ctx, w.admin, uuid.New(), 1, nil)
	assert.ErrorIs(t, err, services.ErrNotFound)
	_, err = w.store.SetOwners(ctx, w.admin, pay.ID, pay.Version+1, nil)
	assert.ErrorIs(t, err, services.ErrOwnersVersion)
	assert.Zero(t, w.auditCount(t, "service.owners_changed"))

	got, err = w.store.SetOwners(ctx, w.admin, pay.ID, pay.Version, []services.OwnerInput{{DirectoryGroupID: group.ID}, {UserID: sam}, {UserID: olga}})
	require.NoError(t, err)
	assert.Equal(t, pay.Version+1, got.Version, "a change raises the service's version")
	require.Len(t, got.Items, 3)
	assert.Equal(t, []string{"olga", "sam", ""}, []string{got.Items[0].Username, got.Items[1].Username, got.Items[2].Username},
		"people by name, then groups")
	assert.True(t, got.Items[0].HasEmail)
	assert.False(t, got.Items[0].ReachesService, "olga holds no role: receives e-mails but cannot open the service")
	assert.False(t, got.Items[1].HasEmail)
	assert.True(t, got.Items[1].ReachesService, "sam's global role reaches every service")
	assert.Equal(t, "pay-ops", got.Items[2].Group.Value)
	assert.False(t, got.Items[2].ReachesService)
	var details map[string]string
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT details FROM audit_log WHERE action = 'service.owners_changed'").Scan(&details))
	assert.Equal(t, "Payments", details["name"])
	assert.Equal(t, "3", details["owner_count"])
	assert.ElementsMatch(t, []string{"group:" + group.ID.String(), "user:" + sam.String(), "user:" + olga.String()}, strings.Split(details["added"], ","))
	assert.Empty(t, details["removed"])

	// A binding of olga on the service, and one of the group, reach it now.
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: olga, Role: "auditor", ServiceID: &pay.ID})
	require.NoError(t, err)
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{DirectoryGroupID: group.ID, Role: "operator", ServiceID: &pay.ID})
	require.NoError(t, err)
	got, err = w.store.Owners(ctx, pay.ID)
	require.NoError(t, err)
	assert.True(t, got.Items[0].ReachesService)
	assert.True(t, got.Items[2].ReachesService)

	// The same team changes nothing; a smaller one is audited with what went.
	same, err := w.store.SetOwners(ctx, w.admin, pay.ID, got.Version, []services.OwnerInput{{UserID: olga}, {UserID: sam}, {DirectoryGroupID: group.ID}})
	require.NoError(t, err)
	assert.Equal(t, got.Version, same.Version)
	assert.Equal(t, 1, w.auditCount(t, "service.owners_changed"))
	_, err = w.store.SetOwners(ctx, w.admin, pay.ID, got.Version, []services.OwnerInput{{UserID: olga}})
	require.NoError(t, err)
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT details FROM audit_log WHERE action = 'service.owners_changed' ORDER BY seq DESC LIMIT 1").Scan(&details))
	assert.Empty(t, details["added"])
	assert.ElementsMatch(t, []string{"group:" + group.ID.String(), "user:" + sam.String()}, strings.Split(details["removed"], ","))

	// Deleting the service takes its owners.
	_, err = w.d.Owner.Exec(ctx, "DELETE FROM services WHERE id = $1", pay.ID)
	require.NoError(t, err)
	var n int
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT count(*) FROM service_owners").Scan(&n))
	assert.Zero(t, n)
}
