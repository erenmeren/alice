//go:build integration

package services_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/authz/services"
	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

type world struct {
	d     *pgtest.DB
	store *services.Store
	admin services.Actor
	def   uuid.UUID
}

func newWorld(t *testing.T) world {
	t.Helper()
	d := pgtest.New(t)
	ctx := context.Background()
	admin := uuid.New()
	_, err := d.Owner.Exec(ctx, `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'ada', 'Ada', '$argon2id$x', 'admin', now(), now())`, admin)
	require.NoError(t, err)
	var def uuid.UUID
	require.NoError(t, d.App.QueryRow(ctx, "SELECT id FROM services WHERE is_default").Scan(&def))
	return world{d: d, store: services.New(d.App, audit.New(clock.Real{}), clock.Real{}), def: def,
		admin: services.Actor{Audit: audit.Actor{Type: audit.ActorUser, ID: admin, Name: "ada"}, UserID: admin}}
}

func (w world) environment(t *testing.T, key string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, w.d.App.QueryRow(context.Background(), "SELECT id FROM environments WHERE key = $1", key).Scan(&id))
	return id
}

func (w world) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	require.NoError(t, w.d.Owner.QueryRow(context.Background(), "SELECT count(*) FROM audit_log WHERE action = $1", action).Scan(&n))
	return n
}

func fieldErr(t *testing.T, err error, field, code string) {
	t.Helper()
	var v validate.Errors
	require.True(t, errors.As(err, &v), "%v", err)
	for _, f := range v {
		if f.Field == field && f.Code == code {
			return
		}
	}
	t.Fatalf("no %s %s in %v", field, code, v)
}

func TestEnvironments(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	envs, err := w.store.Environments(ctx)
	require.NoError(t, err)
	require.Len(t, envs, 4)
	assert.Equal(t, []string{"production", "staging", "test", "development"}, []string{envs[0].Key, envs[1].Key, envs[2].Key, envs[3].Key})

	qa, err := w.store.CreateEnvironment(ctx, w.admin, services.EnvironmentInput{Key: "qa", Name: "QA", Sort: 25})
	require.NoError(t, err)
	assert.Equal(t, 1, qa.Version)
	_, err = w.store.CreateEnvironment(ctx, w.admin, services.EnvironmentInput{Key: "qa", Name: "QA again"})
	assert.ErrorIs(t, err, services.ErrEnvironmentKeyTaken)
	_, err = w.store.CreateEnvironment(ctx, w.admin, services.EnvironmentInput{Key: "QA", Name: " x", Sort: -1})
	fieldErr(t, err, "key", validate.Pattern)
	fieldErr(t, err, "name", validate.Pattern)
	fieldErr(t, err, "sort", validate.OutOfRange)

	name := "Quality"
	qa2, err := w.store.UpdateEnvironment(ctx, w.admin, qa.ID, qa.Version, services.EnvironmentPatch{Name: &name})
	require.NoError(t, err)
	assert.Equal(t, "Quality", qa2.Name)
	assert.Equal(t, 2, qa2.Version)
	_, err = w.store.UpdateEnvironment(ctx, w.admin, qa.ID, qa.Version, services.EnvironmentPatch{Name: &name})
	assert.ErrorIs(t, err, services.ErrVersionMismatch)

	// In use by a service: kept.
	_, err = w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "QA app", EnvironmentID: &qa.ID})
	require.NoError(t, err)
	assert.ErrorIs(t, w.store.DeleteEnvironment(ctx, w.admin, qa.ID, qa2.Version), services.ErrEnvironmentInUse)
	staging := w.environment(t, "staging")
	assert.NoError(t, w.store.DeleteEnvironment(ctx, w.admin, staging, 1))
	assert.ErrorIs(t, w.store.DeleteEnvironment(ctx, w.admin, staging, 1), services.ErrEnvironmentNotFound)
	assert.Equal(t, 1, w.auditCount(t, "environment.created"))
	assert.Equal(t, 1, w.auditCount(t, "environment.updated"))
	assert.Equal(t, 1, w.auditCount(t, "environment.deleted"))
}

func TestServicesLifecycle(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	prod := w.environment(t, "production")
	list, err := w.store.Services(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.True(t, list[0].IsDefault)
	assert.Equal(t, "Default", list[0].Name)

	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments", Description: "Card processing", EnvironmentID: &prod})
	require.NoError(t, err)
	assert.Equal(t, "production", pay.Environment.Key)
	assert.Equal(t, 1, pay.PolicyVersion)
	p, err := w.store.Policy(ctx, pay.ID)
	require.NoError(t, err)
	assert.JSONEq(t, `{"schema":1}`, string(p.Body))
	assert.Equal(t, "Ada", p.CreatedByName)
	versions, err := w.store.PolicyVersions(ctx, pay.ID)
	require.NoError(t, err)
	assert.Len(t, versions, 1)

	_, err = w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "PAYMENTS"})
	assert.ErrorIs(t, err, services.ErrNameTaken)
	_, err = w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "", Description: strings.Repeat("x", 501)})
	fieldErr(t, err, "name", validate.Required)
	fieldErr(t, err, "description", validate.TooLong)
	unknown := uuid.New()
	_, err = w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Elsewhere", EnvironmentID: &unknown})
	fieldErr(t, err, "environment_id", validate.Required)

	// Relabel: audited with both environments.
	staging := w.environment(t, "staging")
	pay2, err := w.store.UpdateService(ctx, w.admin, pay.ID, pay.Version, services.ServicePatch{SetEnvironment: true, EnvironmentID: &staging})
	require.NoError(t, err)
	assert.Equal(t, "staging", pay2.Environment.Key)
	var details map[string]string
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT details FROM audit_log WHERE action = 'service.updated'").Scan(&details))
	assert.Equal(t, map[string]string{"old_environment_id": prod.String(), "environment_id": staging.String()}, details)
	pay3, err := w.store.UpdateService(ctx, w.admin, pay.ID, pay2.Version, services.ServicePatch{SetEnvironment: true})
	require.NoError(t, err)
	assert.Nil(t, pay3.Environment)
	_, err = w.store.UpdateService(ctx, w.admin, pay.ID, pay2.Version, services.ServicePatch{})
	assert.ErrorIs(t, err, services.ErrVersionMismatch)

	// The Default service is protected; a service with resources is kept; an empty one goes.
	def, err := w.store.Service(ctx, w.def)
	require.NoError(t, err)
	assert.ErrorIs(t, w.store.DeleteService(ctx, w.admin, w.def, def.Version), services.ErrDefaultProtected)
	cert, err := seed.Certificate(ctx, w.d.Owner, "pay.example.test", time.Now().Add(48*time.Hour), nil)
	require.NoError(t, err)
	_, err = w.d.Owner.Exec(ctx, "UPDATE certificates SET service_id = $2 WHERE id = $1", cert, pay.ID)
	require.NoError(t, err)
	err = w.store.DeleteService(ctx, w.admin, pay.ID, pay3.Version)
	var ne *services.NotEmptyError
	require.ErrorAs(t, err, &ne)
	assert.Equal(t, 1, ne.Counts.Certificates)
	_, err = w.d.Owner.Exec(ctx, "UPDATE certificates SET service_id = $2 WHERE id = $1", cert, w.def)
	require.NoError(t, err)
	// A deleted server is history: it moves to Default with the deletion.
	gone, err := seed.Target(ctx, w.d.Owner, "gone", "nginx", "ok", nil)
	require.NoError(t, err)
	_, err = w.d.Owner.Exec(ctx, "UPDATE targets SET service_id = $2, deleted_at = now() WHERE id = $1", gone, pay.ID)
	require.NoError(t, err)
	require.NoError(t, w.store.DeleteService(ctx, w.admin, pay.ID, pay3.Version))
	var owner uuid.UUID
	require.NoError(t, w.d.App.QueryRow(ctx, "SELECT service_id FROM targets WHERE id = $1", gone).Scan(&owner))
	assert.Equal(t, w.def, owner)
	_, err = w.store.Service(ctx, pay.ID)
	assert.ErrorIs(t, err, services.ErrNotFound)
	assert.Equal(t, 1, w.auditCount(t, "service.created"))
	assert.Equal(t, 2, w.auditCount(t, "service.updated"))
	assert.Equal(t, 1, w.auditCount(t, "service.deleted"))
}

func TestTrusts(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	tr, err := w.store.CreateTrust(ctx, w.admin, w.def, pay.ID)
	require.NoError(t, err)
	assert.Equal(t, "Default", tr.Source.Name)
	assert.Equal(t, "Payments", tr.Target.Name)
	assert.Equal(t, "Ada", tr.CreatedByName)
	_, err = w.store.CreateTrust(ctx, w.admin, w.def, pay.ID)
	assert.ErrorIs(t, err, services.ErrTrustExists)
	_, err = w.store.CreateTrust(ctx, w.admin, pay.ID, pay.ID)
	fieldErr(t, err, "target_service_id", validate.Pattern)
	_, err = w.store.CreateTrust(ctx, w.admin, uuid.New(), pay.ID)
	fieldErr(t, err, "source_service_id", validate.Required)

	// The check other modules run in their transactions.
	require.NoError(t, authz.CheckTrust(ctx, w.d.App, w.def, pay.ID))
	require.NoError(t, authz.CheckTrust(ctx, w.d.App, pay.ID, pay.ID), "the same service needs no trust")
	err = authz.CheckTrust(ctx, w.d.App, pay.ID, w.def)
	var ue *authz.UntrustedError
	require.ErrorAs(t, err, &ue, "a trust is directed")
	assert.Equal(t, authz.UntrustedError{Source: pay.ID, Target: w.def}, *ue)
	assert.ErrorIs(t, err, authz.ErrUntrusted)

	list, err := w.store.Trusts(ctx, &pay.ID)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	require.NoError(t, w.store.DeleteTrust(ctx, w.admin, tr.ID))
	assert.ErrorIs(t, w.store.DeleteTrust(ctx, w.admin, tr.ID), services.ErrTrustNotFound)
	assert.ErrorIs(t, authz.CheckTrust(ctx, w.d.App, w.def, pay.ID), authz.ErrUntrusted)
	assert.Equal(t, 1, w.auditCount(t, "service.trust_added"))
	assert.Equal(t, 1, w.auditCount(t, "service.trust_removed"))
}

func TestResolveService(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	got, err := authz.ResolveService(ctx, w.d.App, uuid.Nil)
	require.NoError(t, err)
	assert.Equal(t, w.def, got, "omitted: the Default service")
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	got, err = authz.ResolveService(ctx, w.d.App, pay.ID)
	require.NoError(t, err)
	assert.Equal(t, pay.ID, got)
	_, err = authz.ResolveService(ctx, w.d.App, uuid.New())
	fieldErr(t, err, "service_id", validate.Required)
}

// assignWorld: a Key Vault with a binding to a location on a server, an ACME certificate bound to another location on
// that server, and one resource of every other kind.
type assignWorld struct {
	vault, server, cert, acme, csr, key, scope, binding, kvLoc, acmeLoc uuid.UUID
}

func seedAssign(t *testing.T, w world) assignWorld {
	t.Helper()
	ctx := context.Background()
	var a assignWorld
	var err error
	a.vault, err = seed.Target(ctx, w.d.Owner, "kv-1", "azure_key_vault", "ok", nil)
	require.NoError(t, err)
	a.server, err = seed.Target(ctx, w.d.Owner, "web-1", "nginx", "ok", nil)
	require.NoError(t, err)
	a.cert, err = seed.Certificate(ctx, w.d.Owner, "www.example.test", time.Now().Add(30*24*time.Hour), []uuid.UUID{a.server})
	require.NoError(t, err)
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT id FROM certificate_locations WHERE certificate_id = $1", a.cert).Scan(&a.kvLoc))
	kvCert, _, err := seed.KeyVault(ctx, w.d.Owner, a.vault, "www", time.Now().Add(30*24*time.Hour), &a.cert, "k", time.Now().Add(time.Hour))
	require.NoError(t, err)
	a.binding = uuid.New()
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO bindings (id, kv_certificate_id, kv_target_id, created_at) VALUES ($1, $2, $3, now())`,
		a.binding, kvCert, a.vault)
	require.NoError(t, err)
	_, err = w.d.Owner.Exec(ctx, "UPDATE certificate_locations SET binding_id = $2 WHERE id = $1", a.kvLoc, a.binding)
	require.NoError(t, err)
	other, err := seed.Certificate(ctx, w.d.Owner, "api.example.test", time.Now().Add(30*24*time.Hour), []uuid.UUID{a.server})
	require.NoError(t, err)
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT id FROM certificate_locations WHERE certificate_id = $1", other).Scan(&a.acmeLoc))
	var provider, account uuid.UUID
	provider, account, a.acme = uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO acme_providers (id, name, directory_url, preset, created_at, updated_at)
VALUES ($1, 'CA', 'https://ca.example.test/directory', 'custom', now(), now())`, []any{provider}},
		{`INSERT INTO acme_accounts (id, provider_id, contact_email, account_url, key_ct, key_nonce, key_wrapped_dek, key_version, state, created_at,
updated_at) VALUES ($1, $2, 'ops@example.test', 'https://ca.example.test/acct/1', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, 'active', now(), now())`,
			[]any{account, provider}},
		{`INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, http_target_id, state, created_at, updated_at)
VALUES ($1, $2, $3, '{api.example.test}', 'ecdsa_p256', 'http01', $4, 'active', now(), now())`, []any{a.acme, provider, account, a.server}},
		{`INSERT INTO acme_bindings (acme_certificate_id, location_id, auto_deploy, created_at) VALUES ($1, $2, true, now())`, []any{a.acme, a.acmeLoc}},
	} {
		_, err := w.d.Owner.Exec(ctx, q.sql, q.args...)
		require.NoError(t, err, q.sql)
	}
	pk := uuid.New()
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
wrapped_dek, key_version, created_at) VALUES ($1, 'csr', 'ecdsa', 256, repeat('c', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, pk)
	require.NoError(t, err)
	a.csr = uuid.New()
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO csr_requests (id, private_key_id, common_name, csr_pem, status, created_at)
VALUES ($1, $2, 'req.example.test', 'x', 'pending', now())`, a.csr, pk)
	require.NoError(t, err)
	a.key = uuid.New()
	_, err = w.d.Owner.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES ($1, 'SHA256:' || repeat('K', 43), 'ssh-ed25519', 'ssh-ed25519 AAAA', now(), now())`, a.key)
	require.NoError(t, err)
	a.scope, err = seed.DiscoveryScope(ctx, w.d.Owner, "Office", false)
	require.NoError(t, err)
	return a
}

func TestAssignMovesEachKindAndListsUntrustedBindings(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a := seedAssign(t, w)
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)

	// Dry run: the server moves away from the vault and the ACME certificate; nothing changes, nothing is audited.
	server := []services.Resource{{Type: services.KindTarget, ID: a.server}}
	dry, err := w.store.Assign(ctx, w.admin, pay.ID, server, true)
	require.NoError(t, err)
	assert.True(t, dry.DryRun)
	require.Len(t, dry.Moves, 1)
	assert.Equal(t, "web-1", dry.Moves[0].Name)
	assert.Equal(t, "Default", dry.Moves[0].From.Name)
	assert.True(t, dry.Moves[0].Changed)
	require.Len(t, dry.Untrusted, 2)
	kinds := map[string]services.UntrustedBinding{dry.Untrusted[0].Kind: dry.Untrusted[0], dry.Untrusted[1].Kind: dry.Untrusted[1]}
	assert.Equal(t, a.kvLoc, kinds["key_vault"].LocationID)
	assert.Equal(t, "www", kinds["key_vault"].SourceName)
	assert.Equal(t, "Default", kinds["key_vault"].Source.Name)
	assert.Equal(t, "Payments", kinds["key_vault"].Target.Name)
	assert.Equal(t, a.acmeLoc, kinds["acme"].LocationID)
	assert.Equal(t, a.acme, kinds["acme"].SourceID)
	res, err := w.store.Resolve(ctx, services.KindTarget, a.server)
	require.NoError(t, err)
	assert.Equal(t, w.def, res.Owning, "a dry run changes nothing")
	assert.Zero(t, w.auditCount(t, "service.assigned"))

	// With a trust from Default to Payments, nothing would stop.
	tr, err := w.store.CreateTrust(ctx, w.admin, w.def, pay.ID)
	require.NoError(t, err)
	dry, err = w.store.Assign(ctx, w.admin, pay.ID, server, true)
	require.NoError(t, err)
	assert.Empty(t, dry.Untrusted)
	require.NoError(t, w.store.DeleteTrust(ctx, w.admin, tr.ID))

	// Every kind moves, once audited with the ids.
	all := []services.Resource{
		{Type: services.KindTarget, ID: a.server}, {Type: services.KindTarget, ID: a.vault},
		{Type: services.KindCertificate, ID: a.cert}, {Type: services.KindCSR, ID: a.csr},
		{Type: services.KindSSHKey, ID: a.key}, {Type: services.KindACMECertificate, ID: a.acme},
		{Type: services.KindDiscoveryScope, ID: a.scope},
	}
	got, err := w.store.Assign(ctx, w.admin, pay.ID, all, false)
	require.NoError(t, err)
	assert.Len(t, got.Moves, 7)
	assert.Empty(t, got.Untrusted, "the vault, the server and the ACME certificate moved together")
	for _, r := range all {
		res, err := w.store.Resolve(ctx, r.Type, r.ID)
		require.NoError(t, err, r.Type)
		assert.Equal(t, pay.ID, res.Owning, r.Type)
	}
	assert.Equal(t, 1, w.auditCount(t, "service.assigned"))
	var details map[string]string
	require.NoError(t, w.d.Owner.QueryRow(ctx, "SELECT details FROM audit_log WHERE action = 'service.assigned'").Scan(&details))
	assert.Equal(t, "7", details["moved_count"])
	assert.Contains(t, details["resources"], "ssh_key:"+a.key.String())
	assert.Contains(t, details["resources"], "target:"+a.vault.String())

	// Again: nothing changes, nothing more is audited.
	got, err = w.store.Assign(ctx, w.admin, pay.ID, all, false)
	require.NoError(t, err)
	for _, m := range got.Moves {
		assert.False(t, m.Changed)
	}
	assert.Equal(t, 1, w.auditCount(t, "service.assigned"))

	// Refusals.
	_, err = w.store.Assign(ctx, w.admin, pay.ID, []services.Resource{{Type: services.KindTarget, ID: uuid.New()}}, false)
	fieldErr(t, err, "resources.0.id", validate.Required)
	_, err = w.store.Assign(ctx, w.admin, pay.ID, []services.Resource{{Type: "deployment", ID: uuid.New()}}, false)
	fieldErr(t, err, "resources.0.type", validate.OneOf)
	_, err = w.store.Assign(ctx, w.admin, pay.ID, []services.Resource{all[0], all[0]}, false)
	fieldErr(t, err, "resources.1", validate.Duplicate)
	_, err = w.store.Assign(ctx, w.admin, pay.ID, nil, false)
	fieldErr(t, err, "resources", validate.OutOfRange)
	_, err = w.store.Assign(ctx, w.admin, uuid.New(), all[:1], false)
	assert.ErrorIs(t, err, services.ErrNotFound)
}

// Design §4.5: a certificate is visible from its own service and from every service holding a location of it or the
// Key Vault or the ACME certificate it came from; an ACME certificate from the services of its bound servers.
func TestResolveVisibleFrom(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	a := seedAssign(t, w)
	pay, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Payments"})
	require.NoError(t, err)
	shop, err := w.store.CreateService(ctx, w.admin, services.ServiceInput{Name: "Shop"})
	require.NoError(t, err)
	_, err = w.store.Assign(ctx, w.admin, pay.ID, []services.Resource{{Type: services.KindCertificate, ID: a.cert}}, false)
	require.NoError(t, err)
	_, err = w.store.Assign(ctx, w.admin, shop.ID, []services.Resource{{Type: services.KindTarget, ID: a.server}}, false)
	require.NoError(t, err)
	res, err := w.store.Resolve(ctx, services.KindCertificate, a.cert)
	require.NoError(t, err)
	assert.Equal(t, pay.ID, res.Owning)
	assert.ElementsMatch(t, []uuid.UUID{pay.ID, shop.ID, w.def}, res.Visible, "own, the server's and the vault's")
	res, err = w.store.Resolve(ctx, services.KindACMECertificate, a.acme)
	require.NoError(t, err)
	assert.Equal(t, w.def, res.Owning)
	assert.ElementsMatch(t, []uuid.UUID{w.def, shop.ID}, res.Visible)
	_, err = w.store.Resolve(ctx, services.KindTarget, uuid.New())
	assert.ErrorIs(t, err, services.ErrResourceNotFound)
}
