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

func (w world) person(t *testing.T, name, source string, role any) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var err error
	switch source {
	case "local":
		_, err = w.d.Owner.Exec(context.Background(), `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, $2::text, $2::text, '$argon2id$x', $3, now(), now())`, id, name, role)
	default:
		_, err = w.d.Owner.Exec(context.Background(), `INSERT INTO users (id, username, display_name, auth_source, role, role_source, oidc_provider_id,
    oidc_issuer, oidc_subject, created_at, updated_at)
SELECT $1, $2::text, $2::text, 'oidc', $3, 'oidc_mapping', p.id, 'https://idp.example.test', $2::text, now(), now() FROM oidc_providers p LIMIT 1`, id, name, role)
	}
	require.NoError(t, err)
	return id
}

func grantOf(grants []rbac.ScopedGrant, role rbac.Role) []uuid.UUID {
	for _, g := range grants {
		if g.Role == role {
			return g.Services
		}
	}
	return nil
}

// Role bindings (R49 Phase 2, design §5.1): a binding on a service or on an environment, read per request as grants
// (one per role, the union of its services); an environment binding reaches a service created in it later at once and
// stops reaching one relabelled away. Duplicates and unknown references are refused; adding and removing are audited.
func TestBindingsAndGrants(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	prod := w.environment(t, "production")
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	op := w.person(t, "olga", "local", nil)

	b1, err := w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: op, Role: "operator", ServiceID: &pay.ID})
	require.NoError(t, err)
	assert.Equal(t, rbac.Operator, b1.Role)
	require.NotNil(t, b1.Service)
	assert.Equal(t, "Payments", b1.Service.Name)
	assert.Equal(t, []authz.ServiceRef{{ID: pay.ID, Name: "Payments"}}, b1.Services)
	assert.Equal(t, "olga", b1.Username)
	assert.Equal(t, 1, w.auditCount(t, "access.binding_added"))

	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: op, Role: "operator", ServiceID: &pay.ID})
	assert.ErrorIs(t, err, services.ErrBindingDuplicate)
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: uuid.New(), Role: "operator", ServiceID: &pay.ID})
	fieldErr(t, err, "user_id", validate.Required)
	missing := uuid.New()
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: op, Role: "operator", ServiceID: &missing})
	fieldErr(t, err, "service_id", validate.Required)
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: op, Role: "root", ServiceID: &pay.ID})
	fieldErr(t, err, "role", validate.OneOf)
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: op, Role: "auditor"})
	fieldErr(t, err, "service_id", validate.Required)
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: op, Role: "auditor", ServiceID: &pay.ID, EnvironmentID: &prod})
	fieldErr(t, err, "environment_id", validate.Pattern)

	// An environment binding: no service in production yet, so the grant covers nothing.
	envB, err := w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: op, Role: "auditor", EnvironmentID: &prod})
	require.NoError(t, err)
	assert.Empty(t, envB.Services)
	grants, err := authz.LoadGrants(ctx, w.d.App, op)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{pay.ID}, grantOf(grants, rbac.Operator))
	assert.Empty(t, grantOf(grants, rbac.Auditor))

	// A service created in production is in reach at once; relabelling it away takes it out again.
	shop, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Shop", EnvironmentID: &prod})
	require.NoError(t, err)
	grants, err = authz.LoadGrants(ctx, w.d.App, op)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{shop.ID}, grantOf(grants, rbac.Auditor))
	_, err = w.store.UpdateService(ctx, w.admin, shop.ID, shop.Version, services.ServicePatch{SetEnvironment: true})
	require.NoError(t, err)
	grants, err = authz.LoadGrants(ctx, w.d.App, op)
	require.NoError(t, err)
	assert.Empty(t, grantOf(grants, rbac.Auditor))

	// Listing by service includes the environment bindings that reach it.
	_, err = w.store.UpdateService(ctx, w.admin, pay.ID, pay.Version, services.ServicePatch{SetEnvironment: true, EnvironmentID: &prod})
	require.NoError(t, err)
	list, err := w.store.Bindings(ctx, services.BindingFilter{ServiceID: &pay.ID})
	require.NoError(t, err)
	assert.Len(t, list, 2, "the service binding and the production binding")
	list, err = w.store.Bindings(ctx, services.BindingFilter{UserID: &op})
	require.NoError(t, err)
	assert.Len(t, list, 2)

	acc, err := w.store.Access(ctx, op)
	require.NoError(t, err)
	assert.Equal(t, rbac.Role(""), acc.GlobalRole)
	assert.Len(t, acc.Bindings, 2)
	assert.False(t, acc.AdminCap, "a local person is never capped")
	_, err = w.store.Access(ctx, uuid.New())
	assert.ErrorIs(t, err, services.ErrUserNotFound)

	require.NoError(t, w.store.DeleteBinding(ctx, w.admin, b1.ID))
	assert.ErrorIs(t, w.store.DeleteBinding(ctx, w.admin, b1.ID), services.ErrBindingNotFound)
	assert.Equal(t, 1, w.auditCount(t, "access.binding_removed"))
	var details map[string]string
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT details FROM audit_log WHERE action = 'access.binding_removed'").Scan(&details))
	assert.Equal(t, map[string]string{"user_id": op.String(), "username": "olga", "role": "operator", "service_id": pay.ID.String()}, details)
	grants, err = authz.LoadGrants(ctx, w.d.App, op)
	require.NoError(t, err)
	assert.Empty(t, grantOf(grants, rbac.Operator), "a removed binding stops at the next read")
}

// The SSO Admin cap (design §5.1 step 4): an SSO user's Administrator binding counts as Operator while "SSO users may be
// Admin" is off; a local person's never.
func TestGrantsCapSSOAdministrators(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at) VALUES (gen_random_uuid(), 'IdP', 'https://idp.example.test',
'alice', '{openid}', 'groups', 'https://idp.example.test/a', 'https://idp.example.test/t', 'https://idp.example.test/j', true, now(), now())`)
	require.NoError(t, err)
	sso := w.person(t, "sam", "oidc", "auditor")
	_, err = w.store.CreateBinding(ctx, w.admin, services.BindingInput{UserID: sso, Role: "admin", ServiceID: &pay.ID})
	require.NoError(t, err)
	grants, err := authz.LoadGrants(ctx, w.d.App, sso)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{pay.ID}, grantOf(grants, rbac.Operator), "capped while the switch is off")
	assert.Empty(t, grantOf(grants, rbac.Admin))
	acc, err := w.store.Access(ctx, sso)
	require.NoError(t, err)
	assert.True(t, acc.AdminCap)

	_, err = w.d.Owner.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, '{"allow": true}')`, authz.SSOAllowAdminKey)
	require.NoError(t, err)
	grants, err = authz.LoadGrants(ctx, w.d.App, sso)
	require.NoError(t, err)
	assert.Equal(t, []uuid.UUID{pay.ID}, grantOf(grants, rbac.Admin))
}

// The resolvers of the derived kinds (design §4.5) answer the owning service and where a row is visible from.
func TestResolveDerivedKinds(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a := seedAssign(t, w)
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	_, err = w.store.Assign(ctx, w.admin, pay.ID, []services.Resource{{Type: services.KindTarget, ID: a.server}}, false)
	require.NoError(t, err)

	res, err := w.store.Resolve(ctx, services.KindLocation, a.kvLoc)
	require.NoError(t, err)
	assert.Equal(t, pay.ID, res.Owning, "a location is its server's")
	res, err = w.store.Resolve(ctx, services.KindKVBinding, a.binding)
	require.NoError(t, err)
	assert.Equal(t, w.def, res.Owning, "a Key Vault binding is its vault's")
	assert.ElementsMatch(t, []uuid.UUID{w.def, pay.ID}, res.Visible, "and seen from its websites' services")
	res, err = w.store.Resolve(ctx, services.KindIncidentReach, a.cert)
	require.NoError(t, err)
	assert.ElementsMatch(t, []uuid.UUID{w.def, pay.ID}, res.Visible)
	res, err = w.store.Resolve(ctx, services.KindService, pay.ID)
	require.NoError(t, err)
	assert.Equal(t, pay.ID, res.Owning)
	job := uuid.New()
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO jobs (id, type, class, kind, payload, payload_mac, status, run_at, max_attempts, created_at)
VALUES ($1, 'test.job', 'always', 'system', '{}', decode(repeat('07', 32), 'hex'), 'queued', now(), 3, now())`, job)
	require.NoError(t, err)
	res, err = w.store.Resolve(ctx, services.KindJob, job)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, res.Owning, "platform work has no service")
	assert.Empty(t, res.Visible, "and is seen by global grants only")
	_, err = w.store.Resolve(ctx, services.KindDiscoveredCert, "0000000000000000000000000000000000000000000000000000000000000000")
	assert.ErrorIs(t, err, services.ErrResourceNotFound)
	assert.Contains(t, services.ResolveKinds(), services.KindRotationReach)
}
