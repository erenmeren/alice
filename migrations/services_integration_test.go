//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// SQLSTATE of the 00026 Down refusal: scoped access exists.
const scopedAccessExists = "Z1026"

// ownedTables are the tables with an owning service (design §4.2).
var ownedTables = []string{"targets", "certificates", "csr_requests", "ssh_keys", "acme_certificates", "discovery_scopes"}

func defaultService(t *testing.T, d *pgtest.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, d.App.QueryRow(context.Background(), "SELECT id FROM services WHERE is_default").Scan(&id))
	return id
}

// countsByTable is the row count of each owned table, and how many of its rows are in the given service.
func countsByTable(t *testing.T, d *pgtest.DB, service *uuid.UUID) map[string][2]int {
	t.Helper()
	out := map[string][2]int{}
	for _, tbl := range ownedTables {
		var all, in int
		require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT count(*) FROM "+tbl).Scan(&all))
		if service != nil {
			require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT count(*) FROM "+tbl+" WHERE service_id = $1", *service).Scan(&in))
		}
		out[tbl] = [2]int{all, in}
	}
	return out
}

// 00026 (R49) goes up over a populated database: every owned row lands in the Default service (counts unchanged, no
// history trigger fires: a finished incident is filled too), a job with a target and every alert take Default, an
// enabled rotation policy is approved for Default; the Down works without scoped state and refuses with it.
func TestMigration00026ServicesBackfillAndDown(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 23)
	require.NoError(t, err)
	assert.False(t, tableExists(t, d, "services"))
	assert.False(t, hasColumn(t, d, "targets", "service_id"))
	assert.Empty(t, grantProblems(t, d), "the grant guard describes the schema below 00026 too")

	// A populated installation: inventory, ACME, discovery, a signing request, an SSH key with an enabled and a disabled
	// rotation policy, jobs with and without a target, an alert and a finished (frozen) incident.
	w := seedAcme(t, d)
	dw := seedDiscovery(t, d)
	user := seedUser(t, d, "Ada", "ada@example.test")
	require.NoError(t, insertRow(t, d.App, "csr_requests", csrRow(w.key)))
	key, _ := seedSSHKey(t, d, "SHA256:"+repeat43("S"))
	otherKey, _ := seedSSHKey(t, d, "SHA256:"+repeat43("T"))
	enabled, disabled := uuid.New(), uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO rotation_policies (id, ssh_key_id, name, interval_days, enabled, next_run_at, created_at, updated_at)
VALUES ($1, $2, 'on', 90, true, now() + interval '1 day', now(), now())`, enabled, key))
	require.NoError(t, exec(t, d.App, `INSERT INTO rotation_policies (id, ssh_key_id, name, interval_days, created_at, updated_at)
VALUES ($1, $2, 'off', 90, now(), now())`, disabled, otherKey))
	targetJob := uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO jobs (id, type, class, kind, payload_mac, target_id, status, run_at, max_attempts, created_at)
VALUES ($1, 'target.discover', 'read_only', 'scheduled', decode(repeat('00', 32), 'hex'), $2, 'succeeded', now(), 5, now())`, targetJob, w.target))
	platformJob, err := seedJob(t, d, nil, "succeeded")
	require.NoError(t, err)
	require.NoError(t, exec(t, d.App, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, 'certificate_expiry', $2, 'www.example.com', now() + interval '10 days', 30, false, true, now())`, uuid.New(), w.cert))
	incident := uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, state, revocation, created_at, updated_at)
VALUES ($1, $2, $3, 'awaiting_replacement', 'not_possible', now(), now())`, incident, w.cert, hex64("b")))
	require.NoError(t, exec(t, d.App, "UPDATE certificate_incidents SET state = 'closed', closed_by = $2, finished_at = now() WHERE id = $1", incident, user))
	before := countsByTable(t, d, nil)
	for tbl, n := range before {
		require.Positive(t, n[0], tbl)
	}

	_, err = p.Up(ctx)
	require.NoError(t, err)
	def := defaultService(t, d)
	for tbl, n := range countsByTable(t, d, &def) {
		assert.Equal(t, before[tbl][0], n[0], "%s keeps its rows", tbl)
		assert.Equal(t, n[0], n[1], "every row of %s is in the Default service", tbl)
	}
	var jobService, platformService *uuid.UUID
	require.NoError(t, d.App.QueryRow(ctx, "SELECT service_id FROM jobs WHERE id = $1", targetJob).Scan(&jobService))
	require.NoError(t, d.App.QueryRow(ctx, "SELECT service_id FROM jobs WHERE id = $1", platformJob).Scan(&platformService))
	assert.Equal(t, &def, jobService, "a job with a target is the target's service's")
	assert.Nil(t, platformService, "a job without a target is platform work")
	var alertsOutside, incidentServices int
	require.NoError(t, d.App.QueryRow(ctx, "SELECT count(*) FROM alerts WHERE service_id IS DISTINCT FROM $1", def).Scan(&alertsOutside))
	assert.Zero(t, alertsOutside)
	require.NoError(t, d.App.QueryRow(ctx, "SELECT count(*) FROM certificate_incidents WHERE service_ids = ARRAY[$1::uuid]", def).Scan(&incidentServices))
	assert.Equal(t, 1, incidentServices, "the finished incident holds the Default service")
	var approved, notApproved []uuid.UUID
	require.NoError(t, d.App.QueryRow(ctx, "SELECT approved_service_ids FROM rotation_policies WHERE id = $1", enabled).Scan(&approved))
	require.NoError(t, d.App.QueryRow(ctx, "SELECT approved_service_ids FROM rotation_policies WHERE id = $1", disabled).Scan(&notApproved))
	assert.Equal(t, []uuid.UUID{def}, approved)
	assert.Empty(t, notApproved)
	var roles int
	require.NoError(t, d.App.QueryRow(ctx, "SELECT count(*) FROM users WHERE role IS NULL").Scan(&roles))
	assert.Zero(t, roles, "every user keeps its global role")
	assert.Empty(t, grantProblems(t, d))
	_ = dw

	// Down without scoped state, and up again.
	_, err = p.DownTo(ctx, 23)
	require.NoError(t, err)
	assert.False(t, tableExists(t, d, "service_trusts"))
	assert.Equal(t, before, countsByTable(t, d, nil), "the Down keeps every row")
	_, err = p.Up(ctx)
	require.NoError(t, err)

	// Each kind of scoped state stops the Down, and nothing is changed then.
	env := seedEnvironment(t, d, "production")
	second := seedService(t, d, "Payments", &env)
	refused := func(what string) {
		t.Helper()
		_, err := p.DownTo(ctx, 23)
		assert.Equal(t, scopedAccessExists, sqlState(err), what)
		assert.True(t, tableExists(t, d, "services"), what)
	}
	refused("a second service")
	require.NoError(t, exec(t, d.App, "DELETE FROM services WHERE id = $1", second))
	binding := uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO role_bindings (id, user_id, role, environment_id, created_at) VALUES ($1, $2, 'operator', $3, now())`,
		binding, user, env))
	refused("a role binding")
	require.NoError(t, exec(t, d.App, "DELETE FROM role_bindings WHERE id = $1", binding))
	automation := uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, role, created_at, updated_at)
VALUES ($1, 'ci-bot', 'CI', 'automation', 'operator', now(), now())`, automation))
	refused("an automation account")
	require.NoError(t, exec(t, d.Owner, "DELETE FROM users WHERE id = $1", automation))
	require.NoError(t, exec(t, d.App, "UPDATE users SET role = NULL WHERE id = $1", user))
	refused("a user without a global role")
	require.NoError(t, exec(t, d.App, "UPDATE users SET role = 'admin' WHERE id = $1", user))
	_, err = p.DownTo(ctx, 23)
	require.NoError(t, err)
	_, err = p.Up(ctx)
	require.NoError(t, err)
}

func seedEnvironment(t *testing.T, d *pgtest.DB, key string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, d.App.QueryRow(context.Background(), "SELECT id FROM environments WHERE key = $1", key).Scan(&id))
	return id
}

func seedService(t *testing.T, d *pgtest.DB, name string, env *uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO services (id, name, environment_id, created_at, updated_at) VALUES ($1, $2, $3, now(), now())`,
		id, name, env))
	return id
}

// The seeded rows and the constraints of the new tables.
func TestMigration00026ServiceConstraints(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	rows, err := d.App.Query(ctx, "SELECT key FROM environments ORDER BY sort")
	require.NoError(t, err)
	var keys []string
	for rows.Next() {
		var k string
		require.NoError(t, rows.Scan(&k))
		keys = append(keys, k)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"production", "staging", "test", "development"}, keys)
	def := defaultService(t, d)
	var body string
	require.NoError(t, d.App.QueryRow(ctx, "SELECT body::text FROM service_policies WHERE service_id = $1 AND version = 1", def).Scan(&body))
	assert.JSONEq(t, `{"schema":1}`, body)

	// Environments: a key is lower-case and unique; a name is trimmed text.
	insertEnv := func(key, name string) error {
		return exec(t, d.App, "INSERT INTO environments (id, key, name, created_at, updated_at) VALUES ($1, $2, $3, now(), now())", uuid.New(), key, name)
	}
	require.NoError(t, insertEnv("qa-2", "QA 2"))
	assert.Equal(t, uniqueViolation, sqlState(insertEnv("qa-2", "Again")))
	for _, bad := range [][2]string{{"QA", "QA"}, {"2qa", "QA"}, {"qa", " QA"}, {"qa", ""}, {"qa", "Q\tA"}} {
		assert.Equal(t, checkViolation, sqlState(insertEnv(bad[0], bad[1])), "%v", bad)
	}

	// Services: one Default, names unique without regard to case, trimmed, no control characters.
	payments := seedService(t, d, "Payments", nil)
	insertService := func(name string, isDefault bool) error {
		return exec(t, d.App, "INSERT INTO services (id, name, is_default, created_at, updated_at) VALUES ($1, $2, $3, now(), now())",
			uuid.New(), name, isDefault)
	}
	assert.Equal(t, uniqueViolation, sqlState(insertService("PAYMENTS", false)))
	assert.Equal(t, uniqueViolation, sqlState(insertService("Second default", true)))
	for _, bad := range []string{"", " Pay", "Pay\n"} {
		assert.Equal(t, checkViolation, sqlState(insertService(bad, false)), "%q", bad)
	}

	// Policies are append-only for the application.
	require.NoError(t, exec(t, d.App, "INSERT INTO service_policies (service_id, version, body, created_at) VALUES ($1, 1, '{\"schema\":1}', now())", payments))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "INSERT INTO service_policies (service_id, version, body, created_at) VALUES ($1, 2, '[]', now())", payments)))
	assert.Equal(t, insufficientPrivilege, sqlState(exec(t, d.App, "UPDATE service_policies SET body = '{}'")))
	assert.Equal(t, insufficientPrivilege, sqlState(exec(t, d.App, "DELETE FROM service_policies")))

	// Trusts are directed, between two different services, once.
	trust := func(from, to uuid.UUID) error {
		return exec(t, d.App, "INSERT INTO service_trusts (id, source_service_id, target_service_id, created_at) VALUES ($1, $2, $3, now())",
			uuid.New(), from, to)
	}
	require.NoError(t, trust(def, payments))
	require.NoError(t, trust(payments, def), "the other direction is another trust")
	assert.Equal(t, uniqueViolation, sqlState(trust(def, payments)))
	assert.Equal(t, checkViolation, sqlState(trust(def, def)))

	// The owning service of a row moves only through its column grant; a service in use cannot be deleted.
	w := seedWorld(t, d)
	require.NoError(t, exec(t, d.App, "UPDATE targets SET service_id = $2 WHERE id = $1", w.target, payments))
	require.NoError(t, exec(t, d.App, "UPDATE certificates SET service_id = $2 WHERE id = $1", w.cert, payments))
	assert.Equal(t, "23503", sqlState(exec(t, d.App, "DELETE FROM services WHERE id = $1", payments)), "a service with resources is kept")

	// Users: a role may be absent; automation accounts are no people; the break-glass account may still be demoted (as
	// today: Phase 1 changes nobody's rights).
	user := seedUser(t, d, "Grace", "grace@example.test")
	require.NoError(t, exec(t, d.App, "UPDATE users SET role = NULL WHERE id = $1", user))
	require.NoError(t, exec(t, d.App, "UPDATE users SET role = 'admin', is_break_glass = true WHERE id = $1", user))
	require.NoError(t, exec(t, d.App, "UPDATE users SET role = 'operator' WHERE id = $1", user))
	automation := func(role any, password any) error {
		return exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, role, password_hash, created_at, updated_at)
VALUES ($1, $2, 'Bot', 'automation', $3, $4, now(), now())`, uuid.New(), "bot-"+uuid.NewString()[:8], role, password)
	}
	require.NoError(t, automation(nil, nil))
	require.NoError(t, automation("auditor", nil))
	assert.Equal(t, checkViolation, sqlState(automation("admin", nil)), "never a global Administrator")
	assert.Equal(t, checkViolation, sqlState(automation("operator", "$argon2id$x")), "never a password")

	// Bindings: one subject and one place.
	binding := func(user, group, role, service, env any) error {
		return exec(t, d.App, `INSERT INTO role_bindings (id, user_id, directory_group_id, role, service_id, environment_id, created_at)
VALUES ($1, $2, $3, $4, $5, $6, now())`, uuid.New(), user, group, role, service, env)
	}
	env := seedEnvironment(t, d, "staging")
	require.NoError(t, binding(user, nil, "operator", payments, nil))
	assert.Equal(t, uniqueViolation, sqlState(binding(user, nil, "operator", payments, nil)))
	assert.Equal(t, checkViolation, sqlState(binding(user, nil, "operator", payments, env)))
	assert.Equal(t, checkViolation, sqlState(binding(nil, nil, "operator", payments, nil)))
	assert.Equal(t, checkViolation, sqlState(binding(user, nil, "owner", payments, nil)))

	// Token limits name 1 to 50 services.
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at,
service_ids, created_at) VALUES ($1, $2, 't', '\x01', 'alc_', '{read}', $3, '{}', now())`, uuid.New(), user, time.Now().Add(time.Hour))))
}
