//go:build integration

package notify_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/db"
	"alice/internal/testutil/pgtest"
)

// outboxRows is every column of the queued e-mails but the row id (a new UUID each time), in queue order, as text.
func outboxRows(t *testing.T, d *pgtest.DB) []string {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), `SELECT concat_ws(' | ', kind, to_address, template_key, params::text, locale, status,
    attempts::text, next_attempt_at::text, created_at::text, last_error_code, coalesce(sent_at::text, '')) FROM notifications_outbox ORDER BY id`)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}

func clearOutbox(t *testing.T, d *pgtest.DB) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(), "DELETE FROM notifications_outbox")
	require.NoError(t, err)
}

func defaultService(t *testing.T, d *pgtest.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT id FROM services WHERE is_default").Scan(&id))
	return id
}

func addService(t *testing.T, d *pgtest.DB, name, policy string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO services (id, name, policy_version, created_at, updated_at) VALUES ($1, $2, 2, now(), now())`, id, name)
	require.NoError(t, err)
	_, err = d.Owner.Exec(context.Background(), `INSERT INTO service_policies (service_id, version, body, created_at)
VALUES ($1, 1, '{"schema":1}', now()), ($1, 2, $2::jsonb, now())`, id, policy)
	require.NoError(t, err)
	return id
}

func userID(t *testing.T, d *pgtest.DB, username string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT id FROM users WHERE username = $1", username).Scan(&id))
	return id
}

func ownedBy(t *testing.T, d *pgtest.DB, service uuid.UUID, user, group *uuid.UUID) {
	t.Helper()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO service_owners (id, service_id, user_id, directory_group_id, created_at)
VALUES (gen_random_uuid(), $1, $2, $3, now())`, service, user, group)
	require.NoError(t, err)
}

// recipientsOf queues one e-mail about services (nil: a platform e-mail) and answers "address:locale" in queue order.
func recipientsOf(t *testing.T, h harness, services []uuid.UUID) []string {
	t.Helper()
	clearOutbox(t, h.d)
	require.NoError(t, db.InTx(context.Background(), h.d.App, func(tx pgx.Tx) error {
		return notify.ServiceNotifier{Clock: h.clk}.NotifyServices(context.Background(), tx, services, "target.auth_failed",
			map[string]string{"target_name": "web-01"})
	}))
	rows, err := h.d.Owner.Query(context.Background(), `SELECT to_address || ':' || locale FROM notifications_outbox ORDER BY id`)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return got
}

// SR-22 (R56, design §7.2 and its Phase 4 acceptance): with only the Default service, no owners and the default policy,
// a service e-mail, a summary and a platform e-mail queue byte for byte the rows the Administrator e-mail queued before
// (the golden file, written by AdminNotifier at the time routing came), for every recipients setting the notify suite
// uses: every Administrator, Administrators and extra addresses (one of them an Administrator's in another case), extra
// addresses only.
func TestOnlyDefaultQueuesTodaysRows(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	addUser(t, h.d, "ada", "admin", "ada@example.com", "tr", false)
	addUser(t, h.d, "bob", "admin", "bob@example.com", "en", false)
	addUser(t, h.d, "dis", "admin", "dis@example.com", "en", true)
	addUser(t, h.d, "nomail", "admin", "", "en", false)
	addUser(t, h.d, "op", "operator", "op@example.com", "en", false)
	def := defaultService(t, h.d)
	params := map[string]string{"target_name": "web-01", "count": "2"}
	settings := []string{
		``,
		`{"administrators": true, "version": 1, "addresses": [{"email": "noc@example.com", "locale": "en"}, {"email": "ADA@example.com", "locale": "en"}]}`,
		`{"administrators": false, "version": 2, "addresses": [{"email": "noc@example.com", "locale": "tr"}]}`,
	}
	var golden []string
	for _, raw := range settings {
		if raw != "" {
			_, err := h.d.Owner.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('notify.recipients', $1::jsonb, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, raw)
			require.NoError(t, err)
		}
		clearOutbox(t, h.d)
		require.NoError(t, db.InTx(ctx, h.d.App, func(tx pgx.Tx) error {
			return notify.AdminNotifier{Clock: h.clk}.NotifyAdmins(ctx, tx, "target.auth_failed", params)
		}))
		before := outboxRows(t, h.d)
		require.NotEmpty(t, before)
		golden = append(golden, before...)
		sn := notify.ServiceNotifier{Clock: h.clk}
		for name, queue := range map[string]func(pgx.Tx) error{
			"the Default service": func(tx pgx.Tx) error {
				return sn.NotifyServices(ctx, tx, []uuid.UUID{def}, "target.auth_failed", params)
			},
			"no service": func(tx pgx.Tx) error { return sn.NotifyServices(ctx, tx, nil, "target.auth_failed", params) },
			"the Default service twice": func(tx pgx.Tx) error {
				return sn.NotifyServices(ctx, tx, []uuid.UUID{def, def, uuid.Nil}, "target.auth_failed", params)
			},
			"a summary of two items": func(tx pgx.Tx) error {
				return sn.NotifyDigest(ctx, tx, "target.auth_failed", [][]uuid.UUID{{def}, {def}}, func(n int) map[string]string {
					return map[string]string{"target_name": "web-01", "count": strconv.Itoa(n)}
				})
			},
			"a platform e-mail": func(tx pgx.Tx) error { return sn.NotifyAdmins(ctx, tx, "target.auth_failed", params) },
		} {
			clearOutbox(t, h.d)
			require.NoError(t, db.InTx(ctx, h.d.App, queue))
			assert.Equal(t, before, outboxRows(t, h.d), "%s, setting %q", name, raw)
		}
	}
	path := filepath.Join("testdata", "only_default.golden")
	text := strings.Join(golden, "\n") + "\n"
	if os.Getenv("ALICE_UPDATE_GOLDEN") != "" {
		require.NoError(t, os.WriteFile(path, []byte(text), 0o600))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(want), text, "the Administrator e-mail's rows are today's (testdata/only_default.golden)")
}

// SR-24 (R56, design §7.2): an owner group reaches the enabled members of its own provider seen in the group at their
// last sign-in, with an address; a disabled member, a member without an address, a person of another provider with the
// same group value and an automation account never. A person owner gets it when enabled with an address.
func TestOwnerGroupsReachTheirEnabledMembers(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	addUser(t, h.d, "olga", "operator", "olga@example.com", "tr", false)
	addUser(t, h.d, "gone", "operator", "gone@example.com", "en", true)
	pay := addService(t, h.d, "Payments", `{"schema":1,"notifications":{"administrators":false}}`)
	provider, other := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{provider, other} {
		_, err := h.d.Owner.Exec(ctx, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at) VALUES ($1, $2, 'https://idp.example.test',
$3, '{openid}', 'groups', 'https://idp.example.test/a', 'https://idp.example.test/t', 'https://idp.example.test/j', true, now(), now())`,
			id, "IdP "+id.String(), "alice-"+id.String())
		require.NoError(t, err)
	}
	member := func(username, email string, prov uuid.UUID, disabled bool, groups ...string) {
		id := uuid.New()
		var at any
		if disabled {
			at = h.clk.Now()
		}
		_, err := h.d.Owner.Exec(ctx, `INSERT INTO users (id, username, display_name, email, auth_source, role, role_source, oidc_provider_id,
    oidc_issuer, oidc_subject, disabled_at, created_at, updated_at)
VALUES ($1, $2::text, $2::text, $3, 'oidc', NULL, 'oidc_mapping', $4, 'https://idp.example.test', $2::text, $5, now(), now())`,
			id, username, email, prov, at)
		require.NoError(t, err)
		for _, g := range groups {
			_, err := h.d.Owner.Exec(ctx, `INSERT INTO user_directory_groups (user_id, value, seen_at) VALUES ($1, $2, now())`, id, g)
			require.NoError(t, err)
		}
	}
	member("sam", "sam@example.com", provider, false, "pay-ops", "eng")
	member("sue", "sue@example.com", provider, true, "pay-ops")
	member("sid", "", provider, false, "pay-ops")
	member("tom", "tom@example.com", provider, false, "eng")
	member("xen", "xen@example.com", other, false, "pay-ops")
	_, err := h.d.Owner.Exec(ctx, `INSERT INTO users (id, username, display_name, email, auth_source, role, created_at, updated_at)
VALUES (gen_random_uuid(), 'robot', 'Robot', 'robot@example.com', 'automation', NULL, now(), now())`)
	require.NoError(t, err)
	group := uuid.New()
	_, err = h.d.Owner.Exec(ctx, `INSERT INTO directory_groups (id, source, oidc_provider_id, value, created_at) VALUES ($1, 'oidc', $2, 'pay-ops', now())`,
		group, provider)
	require.NoError(t, err)

	ownedBy(t, h.d, pay, nil, &group)
	assert.Equal(t, []string{"sam@example.com:en"}, recipientsOf(t, h, []uuid.UUID{pay}),
		"the group's enabled member of its provider with an address; the policy leaves the Administrators out")
	o, g := userID(t, h.d, "olga"), userID(t, h.d, "gone")
	ownedBy(t, h.d, pay, &o, nil)
	ownedBy(t, h.d, pay, &g, nil)
	assert.Equal(t, []string{"olga@example.com:tr", "sam@example.com:en"}, recipientsOf(t, h, []uuid.UUID{pay}),
		"a person owner too, a disabled one not")
	_, err = h.d.Owner.Exec(ctx, `DELETE FROM user_directory_groups WHERE user_id = (SELECT id FROM users WHERE username = 'sam') AND value = 'pay-ops'`)
	require.NoError(t, err)
	assert.Equal(t, []string{"olga@example.com:tr"}, recipientsOf(t, h, []uuid.UUID{pay}), "left the group at the last sign-in: no more e-mails")
}

// SR-24 (R56, design §7.2 and §7.3 notifications): the Administrators get a service's e-mails while one of its services'
// policies keeps them (absent: kept); the policy's extra addresses get them in their language, every mailbox once (an
// owner's address first); a service whose policy names nobody, and has no owner, still reaches the Administrators.
func TestPolicyNotificationsDecideTheAdministratorsAndAddExtraAddresses(t *testing.T) {
	h := newHarness(t, nil)
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	addUser(t, h.d, "olga", "operator", "olga@example.com", "tr", false)
	def := defaultService(t, h.d)
	quiet := addService(t, h.d, "Quiet", `{"schema":1,"notifications":{"administrators":false,
"addresses":[{"email":"pay-team@example.com","locale":"tr"},{"email":"OLGA@example.com","locale":"en"}]}}`)
	loud := addService(t, h.d, "Loud", `{"schema":1,"notifications":{"addresses":[{"email":"noc@example.com","locale":"en"}]}}`)
	nobody := addService(t, h.d, "Nobody", `{"schema":1,"notifications":{"administrators":false}}`)
	o := userID(t, h.d, "olga")
	ownedBy(t, h.d, quiet, &o, nil)

	assert.Equal(t, []string{"olga@example.com:tr", "pay-team@example.com:tr"}, recipientsOf(t, h, []uuid.UUID{quiet}))
	assert.Equal(t, []string{"ada@example.com:en", "noc@example.com:en"}, recipientsOf(t, h, []uuid.UUID{loud}))
	assert.Equal(t, []string{"ada@example.com:en", "olga@example.com:tr", "pay-team@example.com:tr"}, recipientsOf(t, h, []uuid.UUID{quiet, def}),
		"one service keeping the Administrators is enough")
	assert.Equal(t, []string{"ada@example.com:en"}, recipientsOf(t, h, []uuid.UUID{nobody}), "never dropped for want of a recipient")
	assert.Equal(t, []string{"ada@example.com:en"}, recipientsOf(t, h, []uuid.UUID{uuid.New()}), "a service deleted since: the default policy")
}

// SR-26 (R56, design §7.2): the platform e-mails (license, backup, lockout, audit, a job's tampering, the test e-mail)
// go through NotifyAdmins, which never reaches an owner or a policy's address, however the services are set.
func TestPlatformEmailsNeverReachOwners(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	addUser(t, h.d, "olga", "operator", "olga@example.com", "tr", false)
	o := userID(t, h.d, "olga")
	def := defaultService(t, h.d)
	ownedBy(t, h.d, def, &o, nil)
	_, err := h.d.Owner.Exec(ctx, `UPDATE services SET policy_version = 2 WHERE id = $1`, def)
	require.NoError(t, err)
	_, err = h.d.Owner.Exec(ctx, `INSERT INTO service_policies (service_id, version, body, created_at)
VALUES ($1, 2, '{"schema":1,"notifications":{"administrators":false,"addresses":[{"email":"pay@example.com","locale":"en"}]}}', now())`, def)
	require.NoError(t, err)
	for _, tpl := range []string{"license.locked", "backup.failed", "auth.lockout", "audit.broken", "job.tampered", "notify.test"} {
		clearOutbox(t, h.d)
		for _, n := range []interface {
			NotifyAdmins(context.Context, pgx.Tx, string, map[string]string) error
		}{notify.AdminNotifier{Clock: h.clk}, notify.ServiceNotifier{Clock: h.clk}} {
			require.NoError(t, db.InTx(ctx, h.d.App, func(tx pgx.Tx) error { return n.NotifyAdmins(ctx, tx, tpl, nil) }))
		}
		rows, err := h.d.Owner.Query(ctx, `SELECT to_address FROM notifications_outbox`)
		require.NoError(t, err)
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		assert.Equal(t, []string{"ada@example.com", "ada@example.com"}, got, tpl)
	}
	assert.Equal(t, []string{"olga@example.com:tr", "pay@example.com:en"}, recipientsOf(t, h, []uuid.UUID{def}),
		"the same services' own e-mails reach the owner and the address")
}
