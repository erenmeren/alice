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

// SQLSTATE of the ACME order trigger (00013).
const orderFrozen = "Z1017" // a finished ACME order is never rewritten

// SQLSTATE of the ACME account delete trigger (00013).
const accountKept = "Z1018" // only a pending rollover key is ever deleted

// SQLSTATE of the ACME account state trigger (00013).
const accountStateFrozen = "Z1019" // active -> retired|deactivated, pending_rollover -> active, nothing else

var acmeTables = []string{"acme_providers", "acme_accounts", "acme_hooks", "acme_certificates", "acme_orders", "acme_bindings"}

// envelope is the dummy sealed-secret column values (the migration checks shapes, not contents).
const envelope = `'\x01', decode(repeat('00', 12), 'hex'), '\x02', 1`

type acmeWorld struct {
	world
	provider, account, hook, acmeCert, order uuid.UUID
}

// seedAcme inserts, through the application role, one provider with EAB, one active account, one DNS hook, one ACME
// certificate (state active, bound to the seeded location) and one finished and one running order.
func seedAcme(t *testing.T, d *pgtest.DB) acmeWorld {
	t.Helper()
	w := acmeWorld{world: seedWorld(t, d), provider: uuid.New(), account: uuid.New(), hook: uuid.New(), acmeCert: uuid.New(), order: uuid.New()}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO acme_providers (id, name, directory_url, preset, eab_kid, eab_hmac_ct, eab_hmac_nonce, eab_hmac_wrapped_dek, eab_hmac_key_version,
created_at, updated_at) VALUES ($1, 'Corp CA', 'https://ca.corp.example/directory', 'custom', 'kid-1', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), now())`, []any{w.provider}},
		{`INSERT INTO acme_accounts (id, provider_id, contact_email, account_url, tos_url, tos_accepted_at, key_ct, key_nonce, key_wrapped_dek, key_version,
state, created_at, updated_at) VALUES ($1, $2, 'ops@corp.example', 'https://ca.corp.example/acct/1', 'https://ca.corp.example/tos', now(), ` + envelope + `, 'active', now(), now())`, []any{w.account, w.provider}},
		{`INSERT INTO acme_hooks (id, name, url, secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version, created_at, updated_at)
VALUES ($1, 'dns-hook', 'https://dns.corp.example/hook', ` + envelope + `, now(), now())`, []any{w.hook}},
		{`INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, state, created_at, updated_at)
VALUES ($1, $2, $3, '{www.corp.example}', 'ecdsa_p256', 'dns01', $4, 'active', now(), now())`, []any{w.acmeCert, w.provider, w.account, w.hook}},
		{`INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, finished_at, order_url)
VALUES ($1, $2, 'issue', 'succeeded', now(), now(), 'https://ca.corp.example/order/1')`, []any{w.order, w.acmeCert}},
		{`INSERT INTO acme_bindings (acme_certificate_id, location_id, auto_deploy, created_at) VALUES ($1, $2, true, now())`, []any{w.acmeCert, w.loc}},
	} {
		_, err := d.App.Exec(context.Background(), q.sql, q.args...)
		require.NoError(t, err, q.sql)
	}
	return w
}

func TestAcmeTablesExistAndAreGranted(t *testing.T) {
	d := pgtest.New(t)
	for _, tbl := range acmeTables {
		assert.True(t, tableExists(t, d, tbl), tbl)
	}
	assert.Empty(t, grantProblems(t, d), "every ACME grant is the one the guard lists")
	var ok bool
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT has_table_privilege('alice_app', 'acme_orders', 'DELETE')").Scan(&ok))
	assert.False(t, ok, "orders are history")
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT has_table_privilege('alice_app', 'acme_bindings', 'DELETE')").Scan(&ok))
	assert.True(t, ok, "a binding is removed")
}

func TestAcmeSourceAndTriggerAreAccepted(t *testing.T) {
	d := pgtest.New(t)
	w := seedAcme(t, d)
	// certificates.source = 'acme' obeys certificates_check_key (Z1001) on INSERT, like every other source.
	row := certRow()
	row["source"] = "acme"
	row["private_key_id"] = w.key
	assert.Equal(t, keyMismatch, sqlState(insertRow(t, d.App, "certificates", row)), "the key's public hash must equal the certificate's")
	row["public_key_sha256"] = hex64("c")
	require.NoError(t, insertRow(t, d.App, "certificates", row))
	// ... and a source never changes to or from 'acme' (Z1004).
	_, err := d.App.Exec(context.Background(), "UPDATE certificates SET source = 'uploaded' WHERE id = $1", row["id"])
	assert.Equal(t, sourceFixed, sqlState(err))
	// deployments.trigger = 'acme_renewal'.
	dep := deploymentRow(w.world)
	dep["trigger"] = "acme_renewal"
	require.NoError(t, insertRow(t, d.App, "deployments", dep))
}

func TestAcmeConstraints(t *testing.T) {
	d := pgtest.New(t)
	w := seedAcme(t, d)
	ctx := context.Background()
	bad := func(name, sql string, args ...any) {
		t.Helper()
		_, err := d.App.Exec(ctx, sql, args...)
		assert.Equal(t, checkViolation, sqlState(err), name)
	}
	provider := `INSERT INTO acme_providers (id, name, directory_url, preset, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now())`
	bad("http directory", provider, uuid.New(), "x1", "http://ca.example/dir", "custom")
	bad("directory with userinfo", provider, uuid.New(), "x1u", "https://user:pw@ca.example/dir", "custom")
	bad("unknown preset", provider, uuid.New(), "x2", "https://ca.example/dir", "buypass")
	bad("kid without secret", `INSERT INTO acme_providers (id, name, directory_url, preset, eab_kid, created_at, updated_at)
VALUES ($1, 'x3', 'https://ca.example/dir', 'custom', 'kid', now(), now())`, uuid.New())
	_, err := d.App.Exec(ctx, provider, uuid.New(), "Corp CA", "https://ca.example/dir", "custom")
	assert.Equal(t, uniqueViolation, sqlState(err), "provider names are unique")
	_, err = d.App.Exec(ctx, provider, uuid.New(), "corp ca", "https://ca.example/dir", "custom")
	assert.Equal(t, uniqueViolation, sqlState(err), "case-insensitively")

	account := `INSERT INTO acme_accounts (id, provider_id, contact_email, key_ct, key_nonce, key_wrapped_dek, key_version, state, pending_since,
created_at, updated_at) VALUES ($1, $2, '', ` + envelope + `, $3, CASE WHEN $3 = 'pending_rollover' THEN now() END, now(), now())`
	_, err = d.App.Exec(ctx, account, uuid.New(), w.provider, "active")
	assert.Equal(t, uniqueViolation, sqlState(err), "one active account per provider")
	_, err = d.App.Exec(ctx, account, uuid.New(), w.provider, "pending_rollover")
	require.NoError(t, err, "a pending rollover key sits beside the active one (A6)")
	_, err = d.App.Exec(ctx, account, uuid.New(), w.provider, "pending_rollover")
	assert.Equal(t, uniqueViolation, sqlState(err), "one pending rollover per provider")
	_, err = d.App.Exec(ctx, account, uuid.New(), w.provider, "retired")
	require.NoError(t, err, "any number of retired keys")
	bad("a pending key has its start time", `INSERT INTO acme_accounts (id, provider_id, key_ct, key_nonce, key_wrapped_dek, key_version, state,
created_at, updated_at) VALUES ($1, $2, `+envelope+`, 'pending_rollover', now(), now())`, uuid.New(), uuid.New())
	bad("unknown account state", account, uuid.New(), w.provider, "gone")

	cert := `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, state, renew_before_days, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, now(), now())`
	ok := []any{uuid.New(), w.provider, w.account, []string{"a.corp.example"}, "rsa_2048", "dns01", w.hook, 30}
	with := func(i int, v any) []any { c := append([]any(nil), ok...); c[0], c[i] = uuid.New(), v; return c }
	_, err = d.App.Exec(ctx, cert, ok...)
	require.NoError(t, err)
	bad("no names", cert, with(3, []string{})...)
	bad("unknown key type", cert, with(4, "rsa_1024")...)
	bad("unknown challenge", cert, with(5, "tlsalpn01")...)
	bad("dns-01 needs a hook", cert, with(6, nil)...)
	bad("renew window 0", cert, with(7, 0)...)
	bad("renew window 61", cert, with(7, 61)...)
	bad("http-01 needs its server", cert, uuid.New(), w.provider, w.account, []string{"b.corp.example"}, "ecdsa_p384", "http01", nil, 30)
	withTarget := `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, http_target_id, state,
renew_before_days, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', 30, now(), now())`
	_, err = d.App.Exec(ctx, withTarget, uuid.New(), w.provider, w.account, []string{"b.corp.example"}, "ecdsa_p384", "http01", nil, w.target)
	require.NoError(t, err, "http-01 needs no hook, only the server the names point at")
	bad("a dns-01 certificate has no HTTP-01 server", withTarget, uuid.New(), w.provider, w.account, []string{"c.corp.example"}, "ecdsa_p256",
		"dns01", w.hook, w.target)

	order := `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, finished_at) VALUES ($1, $2, $3, $4, now(), $5)`
	now := time.Now()
	bad("running order with an end", order, uuid.New(), w.acmeCert, "issue", "running", now)
	bad("finished order without an end", order, uuid.New(), w.acmeCert, "issue", "failed", nil)
	bad("unknown kind", order, uuid.New(), w.acmeCert, "renew", "failed", now)
	_, err = d.App.Exec(ctx, order, uuid.New(), w.acmeCert, "issue", "running", nil)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, order, uuid.New(), w.acmeCert, "test", "running", nil)
	assert.Equal(t, uniqueViolation, sqlState(err), "one running order per ACME certificate")
	bad("half a pending key", `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, pending_key_ct) VALUES ($1, $2, 'test', 'running', now(), '\x01')`,
		uuid.New(), w.acmeCert)
	bad("presented is an array", `UPDATE acme_orders SET presented = '{}'::jsonb WHERE state = 'running'`)
	bad("unknown order trigger", `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, finished_at, trigger)
VALUES ($1, $2, 'issue', 'failed', now(), now(), 'cron')`, uuid.New(), w.acmeCert)
	_, err = d.App.Exec(ctx, `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, finished_at, trigger)
VALUES ($1, $2, 'issue', 'failed', now(), now(), 'renewal')`, uuid.New(), w.acmeCert)
	require.NoError(t, err, "the renewal planner's order")
	_, err = d.App.Exec(ctx, `UPDATE acme_orders SET trigger = 'manual'`)
	assert.Equal(t, privilegeDenied, sqlState(err), "an order's trigger never changes")

	ari := `UPDATE acme_certificates SET ari_window_start = $2, ari_window_end = $3 WHERE id = $1`
	bad("half an ARI window", ari, w.acmeCert, now, nil)
	bad("an ARI window that ends before it starts", ari, w.acmeCert, now, now.Add(-time.Hour))
	bad("an empty ARI window", ari, w.acmeCert, now, now)
	bad("an ARI window before 2000", ari, w.acmeCert, time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), now)
	_, err = d.App.Exec(ctx, ari, w.acmeCert, now, now.Add(time.Hour))
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `UPDATE acme_certificates SET ari_checked_at = now(), ari_next_check_at = now(), failure_notified_at = now(),
    rate_limited_since = now(), ari_window_start = NULL, ari_window_end = NULL WHERE id = $1`, w.acmeCert)
	require.NoError(t, err, "the planner's columns are the application's")

	hookWaits := `UPDATE acme_hooks SET propagation_wait_seconds = $2, poll_timeout_seconds = $3 WHERE id = $1`
	bad("propagation wait over 120 s", hookWaits, w.hook, 121, 1)
	bad("poll timeout 0", hookWaits, w.hook, 0, 0)
	bad("poll timeout over 100 s", hookWaits, w.hook, 0, 101)
	bad("waits over the 120 s call budget", hookWaits, w.hook, 30, 91)
	_, err = d.App.Exec(ctx, hookWaits, w.hook, 20, 100)
	require.NoError(t, err, "120 s together is the budget")
}

// A rollover the CA did not take deletes its pending key row; every other account row is history, and no state change
// through the application role can make one deletable (Z1019: the state only moves forward, never into pending).
func TestAcmeOnlyAPendingAccountKeyIsDeleted(t *testing.T) {
	d := pgtest.New(t)
	w := seedAcme(t, d)
	ctx := context.Background()
	insert := func(state string) uuid.UUID {
		id := uuid.New()
		_, err := d.App.Exec(ctx, `INSERT INTO acme_accounts (id, provider_id, key_ct, key_nonce, key_wrapped_dek, key_version, state, pending_since,
created_at, updated_at) VALUES ($1, $2, `+envelope+`, $3, CASE WHEN $3 = 'pending_rollover' THEN now() END, now(), now())`, id, w.provider, state)
		require.NoError(t, err, state)
		return id
	}
	setState := func(id uuid.UUID, state string) error {
		_, err := d.App.Exec(ctx, "UPDATE acme_accounts SET state = $2, updated_at = now() WHERE id = $1", id, state)
		return err
	}
	pending := insert("pending_rollover")
	_, err := d.App.Exec(ctx, "DELETE FROM acme_accounts WHERE id = $1", w.account)
	assert.Equal(t, accountKept, sqlState(err), "the active account is history")
	assert.Equal(t, accountStateFrozen, sqlState(setState(w.account, "pending_rollover")), "active never becomes pending")
	_, err = d.App.Exec(ctx, "DELETE FROM acme_accounts WHERE id = $1", w.account)
	assert.Equal(t, accountKept, sqlState(err))

	retired, deactivated := insert("retired"), insert("deactivated")
	for _, id := range []uuid.UUID{retired, deactivated} {
		for _, to := range []string{"pending_rollover", "active", "retired", "deactivated"} {
			if err := setState(id, to); err != nil {
				assert.Equal(t, accountStateFrozen, sqlState(err), to)
			}
		}
		_, err = d.App.Exec(ctx, "DELETE FROM acme_accounts WHERE id = $1", id)
		assert.Equal(t, accountKept, sqlState(err), "retired and deactivated are final and kept")
	}
	var st string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT state FROM acme_accounts WHERE id = $1", retired).Scan(&st))
	assert.Equal(t, "retired", st)
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT state FROM acme_accounts WHERE id = $1", deactivated).Scan(&st))
	assert.Equal(t, "deactivated", st)
	assert.Equal(t, accountStateFrozen, sqlState(setState(pending, "retired")), "a pending key is settled or deleted, never retired")
	assert.Equal(t, accountStateFrozen, sqlState(setState(pending, "deactivated")))
	_, err = d.App.Exec(ctx, "UPDATE acme_accounts SET pending_since = now() WHERE id = $1", pending)
	assert.Equal(t, privilegeDenied, sqlState(err), "the start of a pending key is fixed")
	_, err = d.App.Exec(ctx, "UPDATE acme_accounts SET contact_email = 'x@corp.example' WHERE id = $1", retired)
	require.NoError(t, err, "other columns of a final row may change")

	// The legitimate moves: active -> retired, pending -> active (settle), and the delete of a pending key.
	require.NoError(t, setState(w.account, "retired"))
	require.NoError(t, setState(pending, "active"))
	other := insert("pending_rollover")
	require.NoError(t, setState(pending, "deactivated"))
	tag, err := d.App.Exec(ctx, "DELETE FROM acme_accounts WHERE id = $1", other)
	require.NoError(t, err)
	assert.Equal(t, int64(1), tag.RowsAffected())
}

func TestAcmeOrdersAreFrozenOnceFinished(t *testing.T) {
	d := pgtest.New(t)
	w := seedAcme(t, d)
	ctx := context.Background()
	_, err := d.App.Exec(ctx, "UPDATE acme_orders SET error_code = 'ALC-ACM-0001' WHERE id = $1", w.order)
	assert.Equal(t, orderFrozen, sqlState(err), "a finished order is history")

	// A running order carries the sealed pending key and the presented records; both are deletable at any time (A8, A12).
	running := uuid.New()
	_, err = d.App.Exec(ctx, `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at, pending_key_ct, pending_key_nonce,
pending_key_wrapped_dek, pending_key_version, presented) VALUES ($1, $2, 'issue', 'running', now(), `+`'\x01', decode(repeat('00', 12), 'hex'), '\x02', 1,
'[{"kind":"dns","name":"_acme-challenge.www.corp.example"},{"kind":"dns","name":"_acme-challenge.corp.example"}]')`, running, w.acmeCert)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, "UPDATE acme_orders SET order_url = 'https://ca.corp.example/order/2' WHERE id = $1", running)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, "UPDATE acme_orders SET state = 'failed', finished_at = now(), error_code = 'ALC-ACM-0006' WHERE id = $1", running)
	require.NoError(t, err)
	// After the end only the pending key may go (to NULL, all four together) and the presented list may be emptied.
	_, err = d.App.Exec(ctx, "UPDATE acme_orders SET error_code = '' WHERE id = $1", running)
	assert.Equal(t, orderFrozen, sqlState(err))
	_, err = d.App.Exec(ctx, "UPDATE acme_orders SET presented = '[{\"x\":1}]' WHERE id = $1", running)
	assert.Equal(t, orderFrozen, sqlState(err), "presented may only shrink")
	_, err = d.App.Exec(ctx, `UPDATE acme_orders SET presented = presented || '[{"kind":"dns","name":"_acme-challenge.api.corp.example"}]'
WHERE id = $1`, running)
	assert.Equal(t, orderFrozen, sqlState(err), "a finished order never gains a presented record")
	_, err = d.App.Exec(ctx, `UPDATE acme_orders SET presented = '[{"kind":"dns"}]' WHERE id = $1`, running)
	assert.Equal(t, orderFrozen, sqlState(err), "a record is never cut down to a part of itself")
	_, err = d.App.Exec(ctx, `UPDATE acme_orders SET presented = '[{"kind":"dns","name":"_acme-challenge.corp.example"}]' WHERE id = $1`, running)
	require.NoError(t, err, "the cleanup job removes the records it cleaned one by one")
	_, err = d.App.Exec(ctx, "UPDATE acme_orders SET cleanup_at = now(), cleanup_error_code = 'acme.hook_refused' WHERE id = $1", running)
	require.NoError(t, err, "the cleanup job records its attempt on a finished order")
	_, err = d.App.Exec(ctx, "UPDATE acme_orders SET cleanup_error_code = 'not a code!' WHERE id = $1", running)
	assert.Equal(t, checkViolation, sqlState(err))
	_, err = d.App.Exec(ctx, "UPDATE acme_orders SET presented = '[]', cleanup_error_code = '' WHERE id = $1", running)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `UPDATE acme_orders SET pending_key_ct = NULL, pending_key_nonce = NULL, pending_key_wrapped_dek = NULL,
pending_key_version = NULL WHERE id = $1`, running)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `UPDATE acme_orders SET pending_key_ct = '\x01', pending_key_nonce = decode(repeat('00', 12), 'hex'),
pending_key_wrapped_dek = '\x02', pending_key_version = 1 WHERE id = $1`, running)
	assert.Equal(t, orderFrozen, sqlState(err), "a finished order never gains a key")
	_, err = d.App.Exec(ctx, "DELETE FROM acme_orders WHERE id = $1", running)
	assert.Equal(t, privilegeDenied, sqlState(err))
}

func TestAcmeImmutableColumns(t *testing.T) {
	d := pgtest.New(t)
	w := seedAcme(t, d)
	ctx := context.Background()
	_, err := d.App.Exec(ctx, "UPDATE acme_accounts SET key_ct = '\\x09' WHERE id = $1", w.account)
	assert.Equal(t, privilegeDenied, sqlState(err), "the sealed account key is never replaced; a rollover is a new row")
	_, err = d.App.Exec(ctx, "UPDATE acme_accounts SET state = 'retired', updated_at = now() WHERE id = $1", w.account)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, "UPDATE acme_certificates SET failures = 1, next_attempt_at = now(), last_error_code = 'ALC-ACM-0005', last_attempt_at = now(), state = 'failing', updated_at = now() WHERE id = $1", w.acmeCert)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, "DELETE FROM acme_bindings WHERE acme_certificate_id = $1", w.acmeCert)
	require.NoError(t, err)
}

// A4: the Down re-maps acme certificates to 'uploaded' and acme_renewal deployments to 'retry' before it restores the
// CHECKs, drops the ACME tables and leaves every grant as 00012 had it; the Up goes through again.
func TestMigration00013DownRemapsAndUpAgain(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	w := seedAcme(t, d)
	cert := certRow()
	cert["source"], cert["private_key_id"], cert["public_key_sha256"] = "acme", w.key, hex64("c")
	require.NoError(t, insertRow(t, d.App, "certificates", cert))
	require.NoError(t, exec(t, d.App, "UPDATE acme_certificates SET current_certificate_id = $1 WHERE id = $2", cert["id"], w.acmeCert))
	dep := deploymentRow(w.world)
	dep["trigger"], dep["state"], dep["status"], dep["finished_at"] = "acme_renewal", "done", "succeeded", time.Now()
	require.NoError(t, insertRow(t, d.App, "deployments", dep))

	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 12)
	require.NoError(t, err)
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(12), version)
	for _, tbl := range acmeTables {
		assert.False(t, tableExists(t, d, tbl), tbl)
	}
	var source, trigger string
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT source FROM certificates WHERE id = $1", cert["id"]).Scan(&source))
	assert.Equal(t, "uploaded", source)
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT trigger FROM deployments WHERE id = $1", dep["id"]).Scan(&trigger))
	assert.Equal(t, "retry", trigger)
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "certificates", with(certRow(), map[string]any{"id": uuid.New(), "fingerprint_sha256": hex64("f"), "source": "acme"}))),
		"the old CHECK is back")
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_trigger WHERE tgname IN ('certificates_key_check', 'deployments_done_frozen') AND tgenabled = 'O'`).Scan(&n))
	assert.Equal(t, 2, n, "the triggers the Down switched off are enabled again")
	assert.Empty(t, grantProblems(t, d), "the Down leaves 00012's grants as they were")

	_, err = p.Up(ctx)
	require.NoError(t, err)
	for _, tbl := range acmeTables {
		assert.True(t, tableExists(t, d, tbl), tbl)
	}
	assert.Empty(t, grantProblems(t, d))
}

// Task 12: a location follows one ACME certificate (the unique index), an attention mark has its reason, and a deployment
// hold has its reason; the planner's marks are updatable by the application, nothing else of a binding is.
func TestAcmeBindingsAndDeployMarks(t *testing.T) {
	d := pgtest.New(t)
	w := seedAcme(t, d)
	ctx := context.Background()
	other := uuid.New()
	_, err := d.App.Exec(ctx, `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, state, created_at, updated_at)
VALUES ($1, $2, $3, '{api.corp.example}', 'ecdsa_p256', 'dns01', $4, 'active', now(), now())`, other, w.provider, w.account, w.hook)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `INSERT INTO acme_bindings (acme_certificate_id, location_id, created_at) VALUES ($1, $2, now())`, other, w.loc)
	assert.Equal(t, uniqueViolation, sqlState(err), "a location follows one ACME certificate")

	bad := func(name, sql string, args ...any) {
		t.Helper()
		_, err := d.App.Exec(ctx, sql, args...)
		assert.Equal(t, checkViolation, sqlState(err), name)
	}
	bad("attention without its reason", "UPDATE acme_bindings SET attention_at = now() WHERE acme_certificate_id = $1", w.acmeCert)
	bad("a reason without attention", "UPDATE acme_bindings SET attention_code = 'deployment.reload_failed' WHERE acme_certificate_id = $1", w.acmeCert)
	bad("a reason that is not a code", "UPDATE acme_bindings SET attention_at = now(), attention_code = 'no spaces' WHERE acme_certificate_id = $1", w.acmeCert)
	_, err = d.App.Exec(ctx, "UPDATE acme_bindings SET attention_at = now(), attention_code = 'deployment.reload_failed' WHERE acme_certificate_id = $1",
		w.acmeCert)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, "UPDATE acme_bindings SET created_at = now() WHERE acme_certificate_id = $1", w.acmeCert)
	assert.Equal(t, privilegeDenied, sqlState(err))

	cert := certRow()
	cert["source"], cert["private_key_id"], cert["public_key_sha256"] = "acme", w.key, hex64("c")
	require.NoError(t, insertRow(t, d.App, "certificates", cert))
	bad("a hold without its reason", "UPDATE acme_certificates SET deploy_held_certificate_id = $2 WHERE id = $1", w.acmeCert, cert["id"])
	bad("a reason without a hold", "UPDATE acme_certificates SET deploy_held_reason = 'license' WHERE id = $1", w.acmeCert)
	bad("an unknown reason", "UPDATE acme_certificates SET deploy_held_certificate_id = $2, deploy_held_reason = 'later' WHERE id = $1", w.acmeCert, cert["id"])
	_, err = d.App.Exec(ctx, `UPDATE acme_certificates SET deploy_held_certificate_id = $2, deploy_held_reason = 'chain_incomplete',
deploy_released_certificate_id = $2, deploy_stopped_certificate_id = $2 WHERE id = $1`, w.acmeCert, cert["id"])
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, "UPDATE acme_certificates SET deploy_stopped_certificate_id = $2 WHERE id = $1", w.acmeCert, uuid.New())
	assert.Equal(t, "23503", sqlState(err), "the marks name stored certificates")
}
