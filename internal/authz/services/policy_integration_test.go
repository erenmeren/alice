//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/platform/validate"
	"alice/internal/testutil/seed"
)

// Design §7.3: a certificate moved into a service is judged by its domains (dry run included); nothing moves.
func TestAssignChecksTheDestinationsDomains(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	_, err = w.store.SetPolicy(ctx, w.admin, pay.ID, 1, json.RawMessage(`{"schema":1,"domains":["*.pay.example.com"]}`), true)
	require.NoError(t, err)
	inside, err := seed.Certificate(ctx, w.d.Owner, "api.pay.example.com", time.Now().Add(30*24*time.Hour), nil)
	require.NoError(t, err)
	outside, err := seed.Certificate(ctx, w.d.Owner, "shop.example.org", time.Now().Add(30*24*time.Hour), nil)
	require.NoError(t, err)

	for _, dry := range []bool{true, false} {
		_, err = w.store.Assign(ctx, w.admin, pay.ID, []services.Resource{{Type: services.KindCertificate, ID: inside},
			{Type: services.KindCertificate, ID: outside}}, dry)
		var de *authz.DomainError
		require.ErrorAs(t, err, &de, "dry run %v", dry)
		assert.Equal(t, authz.DomainError{Name: "shop.example.org", Field: "resources.1"}, *de)
	}
	var service uuid.UUID
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT service_id FROM certificates WHERE id = $1", inside).Scan(&service))
	assert.Equal(t, w.def, service, "nothing moved")

	res, err := w.store.Assign(ctx, w.admin, pay.ID, []services.Resource{{Type: services.KindCertificate, ID: inside}}, false)
	require.NoError(t, err)
	require.Len(t, res.Moves, 1)
	assert.True(t, res.Moves[0].Changed)
}

// Design §12 Phase 5: a stale version is refused, history lists every version with its author, the audit row names the
// changed keys, the domains need a global grant, reserved keys are refused.
func TestSetPolicyVersionsAndAudit(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	provider := uuid.New()
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO acme_providers (id, name, directory_url, preset, created_at, updated_at)
VALUES ($1, 'Test CA', 'https://ca.example.test/directory', 'custom', now(), now())`, provider)
	require.NoError(t, err)

	doc := json.RawMessage(`{"schema":1,"domains":["*.pay.example.com"],"certificate_sources":["acme"],
"acme":{"providers":["` + provider.String() + `"],"renew_before_days":20},"deployment":{"auto_deploy":"forbidden"}}`)
	p, err := w.store.SetPolicy(ctx, w.admin, pay.ID, 1, doc, true)
	require.NoError(t, err)
	assert.Equal(t, 2, p.Version)
	assert.Equal(t, "Ada", p.CreatedByName)
	assert.JSONEq(t, `{"schema":1,"domains":["*.pay.example.com"],"certificate_sources":["acme"],
"acme":{"providers":["`+provider.String()+`"],"renew_before_days":20},"deployment":{"auto_deploy":"forbidden"}}`, string(p.Document))
	assert.Equal(t, 1, w.auditCount(t, "service.policy_changed"))
	var keys, version string
	require.NoError(t, w.d.Owner.QueryRow(ctx, `SELECT details->>'fields', details->>'version' FROM audit_log WHERE action = 'service.policy_changed'`).
		Scan(&keys, &version))
	assert.Equal(t, "acme,certificate_sources,deployment,domains", keys)
	assert.Equal(t, "2", version)

	// The stored policy is what the checks read.
	loaded, err := authz.LoadPolicy(ctx, w.d.App, pay.ID)
	require.NoError(t, err)
	assert.True(t, loaded.AutoDeployForbidden())
	assert.Equal(t, 20, loaded.RenewBeforeDays())

	// A stale version.
	_, err = w.store.SetPolicy(ctx, w.admin, pay.ID, 1, doc, true)
	assert.ErrorIs(t, err, services.ErrPolicyVersion)

	// A service Administrator (no global grant) changes the other fields, not the domains.
	_, err = w.store.SetPolicy(ctx, w.admin, pay.ID, 2, json.RawMessage(`{"schema":1,"domains":["*.example.com"]}`), false)
	assert.ErrorIs(t, err, services.ErrDomainsGlobalOnly)
	p, err = w.store.SetPolicy(ctx, w.admin, pay.ID, 2, json.RawMessage(`{"schema":1,"domains":["*.pay.example.com"],
"incident":{"revoke_mode":"now"}}`), false)
	require.NoError(t, err)
	assert.Equal(t, 3, p.Version)
	require.NoError(t, w.d.Owner.QueryRow(ctx, `SELECT details->>'fields' FROM audit_log WHERE action = 'service.policy_changed'
ORDER BY seq DESC LIMIT 1`).Scan(&keys))
	assert.Equal(t, "acme,certificate_sources,deployment,incident", keys)

	// The same document again stores nothing.
	p, err = w.store.SetPolicy(ctx, w.admin, pay.ID, 3, json.RawMessage(`{"incident":{"revoke_mode":"now"},"schema":1,"domains":["*.pay.example.com"]}`), false)
	require.NoError(t, err)
	assert.Equal(t, 3, p.Version)
	assert.Equal(t, 2, w.auditCount(t, "service.policy_changed"))

	// Refusals change nothing.
	_, err = w.store.SetPolicy(ctx, w.admin, pay.ID, 3, json.RawMessage(`{"schema":1,"drift":{}}`), true)
	var fu *authz.FieldUnavailableError
	require.ErrorAs(t, err, &fu)
	assert.Equal(t, "drift", fu.Key)
	_, err = w.store.SetPolicy(ctx, w.admin, pay.ID, 3, json.RawMessage(`{"schema":1,"acme":{"providers":["`+uuid.NewString()+`"]}}`), true)
	fieldErr(t, err, "body.acme.providers.0", validate.Required)
	_, err = w.store.SetPolicy(ctx, w.admin, pay.ID, 3, json.RawMessage(`{"schema":1,"surprise":1}`), true)
	assert.ErrorIs(t, err, authz.ErrPolicyMalformed)
	_, err = w.store.SetPolicy(ctx, w.admin, uuid.New(), 1, json.RawMessage(`{"schema":1}`), true)
	assert.ErrorIs(t, err, services.ErrNotFound)

	// The history: every version, newest first, with its author.
	versions, err := w.store.PolicyVersions(ctx, pay.ID)
	require.NoError(t, err)
	require.Len(t, versions, 3)
	for i, v := range versions {
		assert.Equal(t, 3-i, v.Version)
		assert.Equal(t, "Ada", v.CreatedByName)
	}
	assert.JSONEq(t, `{"schema":1}`, string(versions[2].Document))
	sv, err := w.store.Service(ctx, pay.ID)
	require.NoError(t, err)
	assert.Equal(t, 3, sv.PolicyVersion)
	assert.Equal(t, 1, sv.Version, "the service's own version is the name, description and environment's")
}

// CAN-04 (R65, design §5.2): the canary's first locations must be locations of live servers of the service itself when
// the policy is saved.
func TestSetPolicyCanaryFirstMustBeTheServicesLocations(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	b, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Shop"})
	require.NoError(t, err)
	server, err := seed.Target(ctx, w.d.Owner, "web-1", "nginx", "ok", nil)
	require.NoError(t, err)
	gone, err := seed.Target(ctx, w.d.Owner, "web-2", "nginx", "ok", nil)
	require.NoError(t, err)
	_, err = seed.Certificate(ctx, w.d.Owner, "www.example.test", time.Now().Add(30*24*time.Hour), []uuid.UUID{server, gone})
	require.NoError(t, err)
	_, err = w.d.Owner.Exec(ctx, "UPDATE targets SET service_id = $1 WHERE id = ANY($2)", a.ID, []uuid.UUID{server, gone})
	require.NoError(t, err)
	var loc, goneLoc uuid.UUID
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT id FROM certificate_locations WHERE target_id = $1", server).Scan(&loc))
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT id FROM certificate_locations WHERE target_id = $1", gone).Scan(&goneLoc))
	_, err = w.d.Owner.Exec(ctx, "UPDATE targets SET deleted_at = now() WHERE id = $1", gone)
	require.NoError(t, err)

	doc := func(ids ...uuid.UUID) json.RawMessage {
		first, _ := json.Marshal(ids)
		return json.RawMessage(`{"schema":1,"canary":{"enabled":true,"first":` + string(first) + `}}`)
	}
	p, err := w.store.SetPolicy(ctx, w.admin, a.ID, 1, doc(loc), false)
	require.NoError(t, err)
	assert.Equal(t, 2, p.Version)
	var keys string
	require.NoError(t, w.d.Owner.QueryRow(ctx, `SELECT details->>'fields' FROM audit_log WHERE action = 'service.policy_changed'`).Scan(&keys))
	assert.Equal(t, "canary", keys)

	_, err = w.store.SetPolicy(ctx, w.admin, b.ID, 1, doc(loc), false)
	fieldErr(t, err, "body.canary.first.0", validate.Required)
	_, err = w.store.SetPolicy(ctx, w.admin, a.ID, 2, doc(loc, uuid.New()), false)
	fieldErr(t, err, "body.canary.first.1", validate.Required)
	_, err = w.store.SetPolicy(ctx, w.admin, a.ID, 2, doc(goneLoc), false)
	fieldErr(t, err, "body.canary.first.0", validate.Required)

	// Switching it off keeps nothing: the document is {"schema":1} again.
	p, err = w.store.SetPolicy(ctx, w.admin, a.ID, 2, json.RawMessage(`{"schema":1,"canary":{"enabled":false}}`), false)
	require.NoError(t, err)
	assert.JSONEq(t, `{"schema":1}`, string(p.Document))
}
