# Vendor Console Phase 1 (Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A vendor-side record in PostgreSQL (customers, license requests, issued licenses, hash-chained audit) with database-enforced roles, and a command line that issues a license from a request using the existing passphrase key file.

**Architecture:** New packages under `internal/vconsole/` and a new command `cmd/vendor-console`. The schema lives in its own goose migration directory, separate from Alice's `migrations/`, because it runs in a different database (Neon). Authorization is done by PostgreSQL roles, grants and row-level security; the audit chain is computed inside the database by a `SECURITY DEFINER` function so no client can write or forge audit rows. Signing goes through a `Signer` interface; Phase 1 ships only the file-key implementation (YubiKey is Phase 2).

**Tech Stack:** Go 1.27, `pgx/v5`, `goose/v3` (already in `go.mod`), testcontainers PostgreSQL 16 for integration tests, `internal/license` and `internal/license/issuer` for the license format.

**Spec:** `docs/superpowers/specs/2026-10-15-vendor-console-design.md` (sections 3, 4.1, 4.3, 5, 6, 10 phase 1)

## Global Constraints

- Branch `vendor-console`. Nothing here is merged into `master` or pushed without the owner saying so.
- The `alice` binary must never link anything under `alice/internal/vconsole/` or `alice/cmd/vendor-console` (extends `TestReleaseBinaryLinksNoTestOrVendorCode`).
- No private key or database password in the repository, in logs or in error messages. Connection URLs contain passwords: never print them.
- The license file format, `internal/license` and `internal/license/issuer` are not changed.
- Roles are database roles: `vendor_sales`, `vendor_signer` (member of `vendor_sales`), `vendor_owner` (member of `vendor_signer`). One login per person is created by the operator as a member of one of them; Phase 1 never creates logins outside tests.
- Licenses and audit rows are never updated or deleted by any role; the only permitted change to a license row is setting `revoked_at`.
- Go style of this repository: errors lower-case, wrapped with `%w`, no `panic` in library code, comments explain why.
- Commits end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Git has no identity in this environment: commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit ...`.

## Spec deviations (decided here, to be reflected in the spec at the end of the phase)

1. `Signer` is at payload level (`Issue(ctx, payload) ([]byte, error)`), not `Sign(ctx, msg)`. The file key already exposes only `Issue`; the YubiKey signer in Phase 2 builds the file with `license.SignedBytes` and `license.EncodeFile` behind the same interface.
2. There is no stored `content_hash` column. The request hash is recomputed from the locked database row at signing time and compared with the hash the signer saw (spec 4.3). A stored hash would be changed together with the fields by whoever changes the fields.
3. Audit hashing lives in SQL (`audit_append`, `audit_verify`), so there is one definition of the chain.

## Review Focus

- A request row changed between the moment a signer looked at it and the moment they sign must be refused (`ErrRequestChanged`). Pinned in Task 6.
- Two signers issuing from the same open request at the same time: exactly one license, the other gets `ErrNotOpen`. Pinned in Task 6.
- A license ID supplied twice, a correction for an unknown license, for another installation, or ending earlier than the license it replaces: refused with distinct errors, as `licensectl` does today. Pinned in Task 6.
- A sales login trying to write `licenses`, update someone else's request, read `audit`, or call `audit_verify`. Pinned in Task 2.
- Deleting a middle audit row or editing one field of an audit row is reported by `audit_verify` with the first bad sequence number. Deleting the newest rows is not detectable from inside the table; this is a known limit, recorded for Phase 5 (signed head checkpoint). Pinned in Task 3.
- A customer name with surrounding spaces or different Unicode normalization must not create a second customer. Pinned in Task 4.

---

## File Structure

| Path | Responsibility |
|---|---|
| `internal/vconsole/migrations/embed.go`, `00001_vendor.sql` | Schema, roles, grants, RLS, audit functions |
| `internal/vconsole/vpgtest/vpgtest.go` (build tag `integration`) | Postgres container, template database, `As(role)` pools |
| `internal/vconsole/audit/audit.go` | Go wrappers: `Append`, `Verify` |
| `internal/vconsole/store/store.go` | Customers and requests; `RequestHash` |
| `internal/vconsole/sign/sign.go` | `Signer` interface, `FileSigner` |
| `internal/vconsole/issue/issue.go` | The issuing transaction |
| `cmd/vendor-console/main.go`, `run.go` | Command line |
| `docs/vendor-console.md` | Operator notes for Phase 1 |

Package dependency direction: `cmd/vendor-console` -> `issue` -> `store`, `sign`, `audit`; `store` -> `audit`. `vpgtest` -> `migrations`.

---

### Task 1: Schema, migration package and test harness

**Files:**
- Create: `internal/vconsole/migrations/embed.go`
- Create: `internal/vconsole/migrations/00001_vendor.sql`
- Create: `internal/vconsole/vpgtest/vpgtest.go`
- Test: `internal/vconsole/migrations/migrations_integration_test.go`

**Interfaces:**
- Produces: `migrations.FS embed.FS`; `vpgtest.Main(m *testing.M) int`; `vpgtest.New(t testing.TB) *DB` where `type DB struct{ Owner *pgxpool.Pool; OwnerURL string }`; `func (d *DB) As(t testing.TB, group, login string) *pgxpool.Pool` (creates `login` as a member of `group`, returns a pool whose every connection ran `SET ROLE login`; the role is dropped at test end).

- [ ] **Step 1: Write the failing test**

```go
//go:build integration

package migrations_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

func TestSchemaHasTablesAndRoles(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	for _, table := range []string{"customers", "license_requests", "licenses", "audit"} {
		var ok bool
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&ok))
		assert.True(t, ok, table)
	}
	for _, role := range []string{"vendor_sales", "vendor_signer", "vendor_owner"} {
		var ok bool
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1 AND NOT rolcanlogin)`, role).Scan(&ok))
		assert.True(t, ok, role)
	}
	// vendor_signer inherits vendor_sales, vendor_owner inherits vendor_signer.
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_auth_members m
		JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles r ON r.oid = m.member
		WHERE (g.rolname, r.rolname) IN (('vendor_sales','vendor_signer'), ('vendor_signer','vendor_owner'))`).Scan(&n))
	assert.Equal(t, 2, n)
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test -tags integration -count=1 ./internal/vconsole/migrations/`
Expected: FAIL to compile (`vpgtest` does not exist).

- [ ] **Step 3: Write the migration package**

`internal/vconsole/migrations/embed.go`:

```go
// Package migrations embeds the goose SQL migrations of the vendor console database. It is
// separate from alice/migrations: this schema lives in the vendor's own database.
package migrations

import "embed"

// FS holds the migration files at its root.
//
//go:embed *.sql
var FS embed.FS
```

`internal/vconsole/migrations/00001_vendor.sql`:

```sql
-- +goose Up

-- Group roles. Individual logins are created by the operator as members of one of them.
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_sales') THEN
        CREATE ROLE vendor_sales NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_signer') THEN
        CREATE ROLE vendor_signer NOLOGIN IN ROLE vendor_sales;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_owner') THEN
        CREATE ROLE vendor_owner NOLOGIN IN ROLE vendor_signer;
    END IF;
END
$$;
-- +goose StatementEnd

CREATE TABLE customers (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200 AND name = btrim(name)),
    contact    text NOT NULL DEFAULT '' CHECK (length(contact) <= 500),
    notes      text NOT NULL DEFAULT '' CHECK (length(notes) <= 4000),
    created_by text NOT NULL DEFAULT current_user,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX customers_name_key ON customers (lower(name));

CREATE TABLE license_requests (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id  bigint NOT NULL REFERENCES customers (id),
    installation text NOT NULL CHECK (length(installation) BETWEEN 5 AND 64),
    targets      integer NOT NULL CHECK (targets BETWEEN 1 AND 100000),
    valid_from   text NOT NULL DEFAULT '' CHECK (length(valid_from) <= 40),
    months       integer NOT NULL DEFAULT 12 CHECK (months BETWEEN 1 AND 60),
    features     text[] NOT NULL DEFAULT '{}',
    replaces     text NOT NULL DEFAULT '' CHECK (length(replaces) <= 64),
    status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'signed', 'rejected', 'cancelled')),
    requested_by text NOT NULL DEFAULT current_user,
    requested_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX license_requests_status_idx ON license_requests (status, requested_at);

CREATE TABLE licenses (
    license_id   text PRIMARY KEY,
    request_id   bigint NOT NULL UNIQUE REFERENCES license_requests (id),
    customer_id  bigint NOT NULL REFERENCES customers (id),
    installation text NOT NULL,
    key_id       text NOT NULL,
    issued_at    timestamptz NOT NULL,
    valid_from   timestamptz NOT NULL,
    valid_until  timestamptz NOT NULL,
    targets      integer NOT NULL,
    replaces     text NOT NULL DEFAULT '',
    file         bytea NOT NULL,
    file_sha256  text NOT NULL,
    signed_by    text NOT NULL DEFAULT current_user,
    revoked_at   timestamptz
);
CREATE INDEX licenses_valid_until_idx ON licenses (valid_until);
CREATE INDEX licenses_customer_idx ON licenses (customer_id);

CREATE TABLE audit (
    seq       bigint PRIMARY KEY,
    at        timestamptz NOT NULL,
    actor     text NOT NULL,
    action    text NOT NULL,
    subject   text NOT NULL,
    details   jsonb NOT NULL,
    prev_hash text NOT NULL,
    hash      text NOT NULL UNIQUE
);

-- Append-only rules, for every role including the table owner.
-- +goose StatementBegin
CREATE FUNCTION vendor_forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'vendor: % is append-only', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit
    FOR EACH ROW EXECUTE FUNCTION vendor_forbid_change();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit
    FOR EACH STATEMENT EXECUTE FUNCTION vendor_forbid_change();
CREATE TRIGGER licenses_no_delete BEFORE DELETE ON licenses
    FOR EACH ROW EXECUTE FUNCTION vendor_forbid_change();
-- +goose StatementBegin
CREATE FUNCTION vendor_license_update_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(OLD) - 'revoked_at') IS DISTINCT FROM (to_jsonb(NEW) - 'revoked_at') THEN
        RAISE EXCEPTION 'vendor: only revoked_at of a license may change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER licenses_update_guard BEFORE UPDATE ON licenses
    FOR EACH ROW EXECUTE FUNCTION vendor_license_update_guard();

-- The audit chain. The hash covers the previous hash, so changing or removing a row in the middle
-- breaks every later row. Only these functions write audit rows.
-- +goose StatementBegin
CREATE FUNCTION audit_hash(prev text, s bigint, t timestamptz, a text, ac text, sub text, d jsonb)
RETURNS text LANGUAGE sql STABLE AS $$
    SELECT encode(sha256(convert_to(concat_ws('|', prev, s::text,
        to_char(t AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'), a, ac, sub, d::text), 'UTF8')), 'hex')
$$;
-- +goose StatementEnd

-- The actor is the role the caller acts as (SET ROLE), or the login when there is none.
-- +goose StatementBegin
CREATE FUNCTION audit_actor() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN current_setting('role') = 'none' THEN session_user::text ELSE current_setting('role') END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION audit_append(p_action text, p_subject text, p_details jsonb DEFAULT '{}'::jsonb)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    prev text;
    s    bigint;
    t    timestamptz;
    a    text;
BEGIN
    PERFORM pg_advisory_xact_lock(727001);
    SELECT seq, hash INTO s, prev FROM audit ORDER BY seq DESC LIMIT 1;
    s := COALESCE(s, 0) + 1;
    prev := COALESCE(prev, repeat('0', 64));
    t := date_trunc('microseconds', clock_timestamp());
    a := audit_actor();
    INSERT INTO audit (seq, at, actor, action, subject, details, prev_hash, hash)
    VALUES (s, t, a, p_action, p_subject, p_details, prev,
            audit_hash(prev, s, t, a, p_action, p_subject, p_details));
    RETURN s;
END
$$;
-- +goose StatementEnd

-- Returns 0 when the chain is intact, otherwise the first sequence number that does not fit.
-- +goose StatementBegin
CREATE FUNCTION audit_verify() RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    r      audit%ROWTYPE;
    prev   text := repeat('0', 64);
    expect bigint := 1;
BEGIN
    FOR r IN SELECT * FROM audit ORDER BY seq LOOP
        IF r.seq <> expect OR r.prev_hash <> prev
           OR r.hash <> audit_hash(prev, r.seq, r.at, r.actor, r.action, r.subject, r.details) THEN
            RETURN r.seq;
        END IF;
        prev := r.hash;
        expect := expect + 1;
    END LOOP;
    RETURN 0;
END
$$;
-- +goose StatementEnd

-- Privileges. Nothing is granted to PUBLIC.
REVOKE ALL ON customers, license_requests, licenses, audit FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_append(text, text, jsonb), audit_verify(), audit_hash(text, bigint, timestamptz, text, text, text, jsonb),
    audit_actor() FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO vendor_sales;

GRANT SELECT, INSERT ON customers TO vendor_sales;
GRANT UPDATE ON customers TO vendor_signer;
GRANT SELECT, INSERT, UPDATE ON license_requests TO vendor_sales;
GRANT SELECT ON licenses TO vendor_sales;
GRANT INSERT ON licenses TO vendor_signer;
GRANT UPDATE (revoked_at) ON licenses TO vendor_owner;
GRANT SELECT ON audit TO vendor_owner;
GRANT EXECUTE ON FUNCTION audit_append(text, text, jsonb), audit_actor() TO vendor_sales;
GRANT EXECUTE ON FUNCTION audit_verify() TO vendor_owner;

-- Row-level security on requests: everybody who may read can read all; a sales login changes only
-- its own open requests (and may only cancel them); signers change any.
ALTER TABLE license_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY requests_read ON license_requests FOR SELECT TO vendor_sales USING (true);
CREATE POLICY requests_insert ON license_requests FOR INSERT TO vendor_sales
    WITH CHECK (requested_by = current_user AND status = 'open');
CREATE POLICY requests_update_own ON license_requests FOR UPDATE TO vendor_sales
    USING (requested_by = current_user AND status = 'open')
    WITH CHECK (requested_by = current_user AND status IN ('open', 'cancelled'));
CREATE POLICY requests_update_signer ON license_requests FOR UPDATE TO vendor_signer
    USING (true) WITH CHECK (true);

-- +goose Down
DROP FUNCTION audit_verify();
DROP FUNCTION audit_append(text, text, jsonb);
DROP FUNCTION audit_actor();
DROP FUNCTION audit_hash(text, bigint, timestamptz, text, text, text, jsonb);
DROP TABLE audit;
DROP TABLE licenses;
DROP TABLE license_requests;
DROP TABLE customers;
DROP FUNCTION vendor_license_update_guard();
DROP FUNCTION vendor_forbid_change();
```

Note for the implementer: `GRANT UPDATE (revoked_at) ON licenses TO vendor_owner` combined with the guard trigger means even the owner role can change nothing but `revoked_at`. The roles themselves are not dropped on `Down` (they are cluster-wide and may be shared).

- [ ] **Step 4: Write the harness**

`internal/vconsole/vpgtest/vpgtest.go`:

```go
//go:build integration

// Package vpgtest gives vendor console integration tests a real PostgreSQL 16: one container per
// test package and a fresh, fully migrated database per test, cloned from a template. It mirrors
// internal/testutil/pgtest, which is tied to Alice's own migrations and roles.
package vpgtest

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"alice/internal/platform/db"
	"alice/internal/vconsole/migrations"
)

const template = "vendor_template"

var (
	ownerBase string
	counter   atomic.Int64
)

// Main starts the container, prepares the template database, runs the tests and removes the
// container. Use it as: func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }.
func Main(m *testing.M) int {
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
		postgres.WithDatabase("vendor"),
		postgres.WithUsername("vendor"),
		postgres.WithPassword("s3cret-pw"),
		postgres.BasicWaitStrategies(),
	)
	if ctr != nil {
		defer func() { _ = testcontainers.TerminateContainer(ctr) }()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpgtest: start postgres container:", err)
		return 1
	}
	if ownerBase, err = ctr.ConnectionString(ctx, "sslmode=disable"); err != nil {
		fmt.Fprintln(os.Stderr, "vpgtest: connection string:", err)
		return 1
	}
	if err := prepareTemplate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "vpgtest: prepare template:", err)
		return 1
	}
	return m.Run()
}

func prepareTemplate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	admin, err := db.Open(ctx, ownerBase)
	if err != nil {
		return err
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+template); err != nil {
		return err
	}
	tpl, err := db.Open(ctx, withDatabase(ownerBase, template))
	if err != nil {
		return err
	}
	err = db.Migrate(ctx, tpl, migrations.FS)
	tpl.Close() // a template must have no open connections when it is cloned
	return err
}

// DB is one fresh database for one test.
type DB struct {
	Owner    *pgxpool.Pool // the migration role (a superuser here): bypasses privileges and RLS
	OwnerURL string
}

// New creates a fresh, migrated database. The pool is closed when the test ends.
func New(t testing.TB) *DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := db.Open(ctx, ownerBase)
	if err != nil {
		t.Fatalf("vpgtest: open admin pool: %v", err)
	}
	defer admin.Close()
	name := fmt.Sprintf("vtest_%d_%d", os.Getpid(), counter.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name+" TEMPLATE "+template); err != nil {
		t.Fatalf("vpgtest: create database: %v", err)
	}
	d := &DB{OwnerURL: withDatabase(ownerBase, name)}
	if d.Owner, err = db.Open(ctx, d.OwnerURL); err != nil {
		t.Fatalf("vpgtest: open owner pool: %v", err)
	}
	t.Cleanup(d.Owner.Close)
	return d
}

// As creates login (NOLOGIN, a member of group) and returns a pool whose every connection acts as
// that role, so grants, row-level security and current_user behave as for a real login. The role
// is dropped when the test ends. login must be unique per test run (roles are cluster-wide).
func (d *DB) As(t testing.TB, group, login string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	role := pgx.Identifier{login}.Sanitize()
	if _, err := d.Owner.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN IN ROLE "+pgx.Identifier{group}.Sanitize()); err != nil {
		t.Fatalf("vpgtest: create role %s: %v", login, err)
	}
	cfg, err := pgxpool.ParseConfig(d.OwnerURL)
	if err != nil {
		t.Fatalf("vpgtest: parse url: %v", err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+role)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("vpgtest: open pool as %s: %v", login, err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = d.Owner.Exec(context.Background(), "DROP OWNED BY "+role)
		_, _ = d.Owner.Exec(context.Background(), "DROP ROLE IF EXISTS "+role)
	})
	return pool
}

func withDatabase(base, name string) string {
	u, err := url.Parse(base)
	if err != nil {
		panic("vpgtest: container URL does not parse: " + err.Error())
	}
	u.Path = "/" + name
	return u.String()
}
```

- [ ] **Step 5: Run the test**

Run: `go test -tags integration -count=1 ./internal/vconsole/migrations/`
Expected: PASS (needs Docker). If goose rejects `CREATE ROLE` inside the transaction, keep it as is: PostgreSQL allows it; if the failure is about `DO` blocks, check the `StatementBegin/End` markers.

- [ ] **Step 6: Commit**

```bash
git add internal/vconsole/migrations internal/vconsole/vpgtest
git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit -m "feat(vendor): schema, roles and integration test harness

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Roles, grants and row-level security

**Files:**
- Test: `internal/vconsole/migrations/roles_integration_test.go`
- Modify (only if a test fails): `internal/vconsole/migrations/00001_vendor.sql`

**Interfaces:**
- Consumes: `vpgtest.New`, `(*DB).As` (Task 1).
- Produces: confidence that the SQL grants match spec section 5. No new code interface.

- [ ] **Step 1: Write the tests**

```go
//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/vpgtest"
)

const goodInstallation = "ALICE-TESTX-AAAAA" // only length matters at this layer

func addCustomer(t *testing.T, p *pgxpool.Pool, name string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, p.QueryRow(context.Background(),
		`INSERT INTO customers (name) VALUES ($1) RETURNING id`, name).Scan(&id))
	return id
}

func addRequest(t *testing.T, p *pgxpool.Pool, customer int64) (int64, error) {
	t.Helper()
	var id int64
	err := p.QueryRow(context.Background(),
		`INSERT INTO license_requests (customer_id, installation, targets) VALUES ($1, $2, 5) RETURNING id`,
		customer, goodInstallation).Scan(&id)
	return id, err
}

func TestSalesCanCreateCustomersAndRequests(t *testing.T) {
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_sales_a")
	c := addCustomer(t, sales, "Acme Ltd")
	id, err := addRequest(t, sales, c)
	require.NoError(t, err)

	var by, status string
	require.NoError(t, sales.QueryRow(context.Background(),
		`SELECT requested_by, status FROM license_requests WHERE id = $1`, id).Scan(&by, &status))
	assert.Equal(t, "t_sales_a", by)
	assert.Equal(t, "open", status)
}

func TestSalesCannotForgeTheRequester(t *testing.T) {
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_sales_b")
	c := addCustomer(t, sales, "Beta Ltd")
	_, err := sales.Exec(context.Background(),
		`INSERT INTO license_requests (customer_id, installation, targets, requested_by) VALUES ($1, $2, 5, 'someone_else')`,
		c, goodInstallation)
	assert.Error(t, err)
	_, err = sales.Exec(context.Background(),
		`INSERT INTO license_requests (customer_id, installation, targets, status) VALUES ($1, $2, 5, 'signed')`,
		c, goodInstallation)
	assert.Error(t, err)
}

func TestSalesChangeOnlyTheirOwnOpenRequestsAndOnlyCancel(t *testing.T) {
	d := vpgtest.New(t)
	a := d.As(t, "vendor_sales", "t_sales_c1")
	b := d.As(t, "vendor_sales", "t_sales_c2")
	c := addCustomer(t, a, "Gamma Ltd")
	id, err := addRequest(t, a, c)
	require.NoError(t, err)
	ctx := context.Background()

	// Someone else's request: zero rows affected.
	tag, err := b.Exec(ctx, `UPDATE license_requests SET targets = 99 WHERE id = $1`, id)
	require.NoError(t, err)
	assert.EqualValues(t, 0, tag.RowsAffected())

	// Own request may be edited while open.
	tag, err = a.Exec(ctx, `UPDATE license_requests SET targets = 7 WHERE id = $1`, id)
	require.NoError(t, err)
	assert.EqualValues(t, 1, tag.RowsAffected())

	// ... but may not be marked signed.
	_, err = a.Exec(ctx, `UPDATE license_requests SET status = 'signed' WHERE id = $1`, id)
	assert.Error(t, err)

	// ... and may be cancelled; after that it is no longer editable.
	_, err = a.Exec(ctx, `UPDATE license_requests SET status = 'cancelled' WHERE id = $1`, id)
	require.NoError(t, err)
	tag, err = a.Exec(ctx, `UPDATE license_requests SET targets = 8 WHERE id = $1`, id)
	require.NoError(t, err)
	assert.EqualValues(t, 0, tag.RowsAffected())
}

func TestSalesCannotWriteLicensesOrReadAudit(t *testing.T) {
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_sales_d")
	ctx := context.Background()
	_, err := sales.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ('LIC-1', 1, 1, 'x', 'vk-1', now(), now(), now(), 1, '\x00', 'x')`)
	assert.Error(t, err)
	_, err = sales.Exec(ctx, `SELECT * FROM audit`)
	assert.Error(t, err)
	_, err = sales.Exec(ctx, `SELECT audit_verify()`)
	assert.Error(t, err)
	_, err = sales.Exec(ctx, `INSERT INTO audit (seq, at, actor, action, subject, details, prev_hash, hash)
		VALUES (1, now(), 'x', 'x', 'x', '{}', 'x', 'x')`)
	assert.Error(t, err)
	_, err = sales.Exec(ctx, `UPDATE customers SET name = 'x'`)
	assert.Error(t, err, "only signers may change a customer")
}

func TestSalesMaySeeLicensesButOnlyOwnersVerifyAudit(t *testing.T) {
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_sales_e")
	owner := d.As(t, "vendor_owner", "t_owner_e")
	ctx := context.Background()
	_, err := sales.Exec(ctx, `SELECT count(*) FROM licenses`)
	assert.NoError(t, err)
	var bad int64
	require.NoError(t, owner.QueryRow(ctx, `SELECT audit_verify()`).Scan(&bad))
	assert.EqualValues(t, 0, bad)
}

func TestOnlyOwnersRevokeAndNothingElseChanges(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	signer := d.As(t, "vendor_signer", "t_signer_f")
	owner := d.As(t, "vendor_owner", "t_owner_f")
	c := addCustomer(t, signer, "Delta Ltd")
	rid, err := addRequest(t, signer, c)
	require.NoError(t, err)
	_, err = signer.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256) VALUES ('LIC-F', $1, $2, 'x', 'vk-1', now(), now(), now(), 1, '\x00', 'x')`, rid, c)
	require.NoError(t, err)

	_, err = signer.Exec(ctx, `UPDATE licenses SET revoked_at = now() WHERE license_id = 'LIC-F'`)
	assert.Error(t, err, "a signer may not revoke")
	_, err = owner.Exec(ctx, `UPDATE licenses SET revoked_at = now() WHERE license_id = 'LIC-F'`)
	assert.NoError(t, err)
	_, err = owner.Exec(ctx, `UPDATE licenses SET targets = 1000 WHERE license_id = 'LIC-F'`)
	assert.Error(t, err, "not even an owner changes the content of a license")
	_, err = d.Owner.Exec(ctx, `UPDATE licenses SET targets = 1000 WHERE license_id = 'LIC-F'`)
	assert.Error(t, err, "the guard trigger also stops the migration role")
	_, err = d.Owner.Exec(ctx, `DELETE FROM licenses WHERE license_id = 'LIC-F'`)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run the tests**

Run: `go test -tags integration -count=1 -run 'Sales|Owners' ./internal/vconsole/migrations/`
Expected: PASS. If one fails, fix the SQL grant or policy named by the failing assertion (do not weaken the test). Likely candidates: `UPDATE ... WITH CHECK` on `status`, and `SELECT audit_verify()` privileges.

- [ ] **Step 3: Commit**

```bash
git add internal/vconsole/migrations
git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit -m "test(vendor): roles, grants and row-level security

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Audit chain wrappers and tamper detection

**Files:**
- Create: `internal/vconsole/audit/audit.go`
- Test: `internal/vconsole/audit/audit_integration_test.go`

**Interfaces:**
- Consumes: SQL functions `audit_append`, `audit_verify` (Task 1), `vpgtest`.
- Produces:
  - `type Q interface{ Exec(ctx, string, ...any) (pgconn.CommandTag, error); Query(ctx, string, ...any) (pgx.Rows, error); QueryRow(ctx, string, ...any) pgx.Row }` (satisfied by `*pgxpool.Pool` and `pgx.Tx`)
  - `func Append(ctx context.Context, q Q, action, subject string, details map[string]any) (int64, error)`
  - `func Verify(ctx context.Context, q Q) (firstBad int64, err error)` (0 means intact)
  - `var ErrBroken = errors.New("audit: the chain is broken")` and `func Check(ctx, q) error` returning `fmt.Errorf("%w at sequence %d", ErrBroken, n)`.

- [ ] **Step 1: Write the failing test**

```go
//go:build integration

package audit_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

func seed(t *testing.T, n int) (*vpgtest.DB, context.Context) {
	t.Helper()
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_audit_"+t.Name())
	for i := 0; i < n; i++ {
		_, err := audit.Append(ctx, sales, "customer.add", "c", map[string]any{"i": i})
		require.NoError(t, err)
	}
	return d, ctx
}

func TestAppendBuildsAVerifiableChain(t *testing.T) {
	d, ctx := seed(t, 5)
	require.NoError(t, audit.Check(ctx, d.Owner))

	var seqs, actors int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(DISTINCT seq), count(DISTINCT actor) FROM audit`).Scan(&seqs, &actors))
	assert.Equal(t, 5, seqs)
	assert.Equal(t, 1, actors)
	var actor string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT actor FROM audit WHERE seq = 1`).Scan(&actor))
	assert.Equal(t, "t_audit_TestAppendBuildsAVerifiableChain", actor, "the actor is the role the caller acts as")
}

func TestEmptyChainIsIntact(t *testing.T) {
	d := vpgtest.New(t)
	require.NoError(t, audit.Check(context.Background(), d.Owner))
}

func TestEditingAnyFieldIsDetected(t *testing.T) {
	d, ctx := seed(t, 4)
	_, err := d.Owner.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_append_only`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `UPDATE audit SET details = '{"i": 99}' WHERE seq = 2`)
	require.NoError(t, err)
	n, err := audit.Verify(ctx, d.Owner)
	require.NoError(t, err)
	assert.EqualValues(t, 2, n)
	assert.ErrorIs(t, audit.Check(ctx, d.Owner), audit.ErrBroken)
}

func TestDeletingAMiddleRowIsDetected(t *testing.T) {
	d, ctx := seed(t, 4)
	_, err := d.Owner.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_append_only`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `DELETE FROM audit WHERE seq = 2`)
	require.NoError(t, err)
	n, err := audit.Verify(ctx, d.Owner)
	require.NoError(t, err)
	assert.EqualValues(t, 3, n, "the first row that no longer follows its predecessor")
}

func TestTriggersStopEditsAndDeletesForEveryone(t *testing.T) {
	d, ctx := seed(t, 2)
	_, err := d.Owner.Exec(ctx, `UPDATE audit SET actor = 'x' WHERE seq = 1`)
	assert.Error(t, err)
	_, err = d.Owner.Exec(ctx, `DELETE FROM audit`)
	assert.Error(t, err)
	_, err = d.Owner.Exec(ctx, `TRUNCATE audit`)
	assert.Error(t, err)
}

// Known limit (spec section 9, phase 5): the newest rows can be removed without breaking the chain
// from the inside. This test documents it so nobody believes Verify proves completeness.
func TestRemovingTheNewestRowsIsNotDetectable(t *testing.T) {
	d, ctx := seed(t, 3)
	_, err := d.Owner.Exec(ctx, `ALTER TABLE audit DISABLE TRIGGER audit_append_only`)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `DELETE FROM audit WHERE seq = 3`)
	require.NoError(t, err)
	assert.NoError(t, audit.Check(ctx, d.Owner))
}

func TestConcurrentAppendsKeepASingleChain(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	pool := d.As(t, "vendor_sales", "t_audit_conc")
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() { _, err := audit.Append(ctx, pool, "x", "y", nil); errs <- err }()
	}
	for i := 0; i < 20; i++ {
		require.NoError(t, <-errs)
	}
	require.NoError(t, audit.Check(ctx, d.Owner))
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit`).Scan(&n))
	assert.Equal(t, 20, n)
}
```

Note: `t.Name()` in a role name contains only letters and underscores for these test names, which `pgx.Identifier.Sanitize` quotes safely.

- [ ] **Step 2: Run to see it fail**

Run: `go test -tags integration -count=1 ./internal/vconsole/audit/`
Expected: FAIL to compile (`audit` package missing).

- [ ] **Step 3: Implement**

```go
// Package audit is the Go side of the vendor console audit chain. The chain itself is computed by
// the database (audit_append, audit_verify in the first migration), so there is one definition of
// the hash and no client can write or forge an audit row.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Q is what a pool or a transaction offers.
type Q interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrBroken means the audit chain does not verify.
var ErrBroken = errors.New("audit: the chain is broken")

// Append writes one audit row and returns its sequence number. Call it in the same transaction as
// the change it records. details may be nil.
func Append(ctx context.Context, q Q, action, subject string, details map[string]any) (int64, error) {
	if details == nil {
		details = map[string]any{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return 0, fmt.Errorf("audit: details: %w", err)
	}
	var seq int64
	if err := q.QueryRow(ctx, `SELECT audit_append($1, $2, $3::jsonb)`, action, subject, string(raw)).Scan(&seq); err != nil {
		return 0, fmt.Errorf("audit: append %s: %w", action, err)
	}
	return seq, nil
}

// Verify returns 0 when the chain is intact, otherwise the first sequence number that does not fit.
// It does not prove that newer rows were not removed.
func Verify(ctx context.Context, q Q) (int64, error) {
	var n int64
	if err := q.QueryRow(ctx, `SELECT audit_verify()`).Scan(&n); err != nil {
		return 0, fmt.Errorf("audit: verify: %w", err)
	}
	return n, nil
}

// Check is Verify as an error: nil when intact, ErrBroken (with the sequence) otherwise.
func Check(ctx context.Context, q Q) error {
	n, err := Verify(ctx, q)
	if err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("%w at sequence %d", ErrBroken, n)
	}
	return nil
}
```

- [ ] **Step 4: Run to see it pass**

Run: `go test -tags integration -race -count=1 ./internal/vconsole/audit/`
Expected: PASS. If `TestAppendBuildsAVerifiableChain` shows the actor as the login instead of the role, `current_setting('role')` is not visible inside the `SECURITY DEFINER` function in this PostgreSQL version: change `audit_actor()` to read `current_setting('role')` in the wrapper query and pass it as a parameter only from the trusted Go wrapper is NOT acceptable (forgeable). Instead keep the function and report it; the production logins connect directly, where `session_user` is the right value, so the fallback branch is what runs in production.

- [ ] **Step 5: Commit**

```bash
git add internal/vconsole/audit
git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit -m "feat(vendor): audit chain wrappers and tamper tests

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Customers and requests (the store)

**Files:**
- Create: `internal/vconsole/store/store.go`
- Test: `internal/vconsole/store/store_test.go` (unit, no build tag: `RequestHash`, validation)
- Test: `internal/vconsole/store/store_integration_test.go`

**Interfaces:**
- Consumes: `audit.Q`, `audit.Append` (Task 3); `issuer.Request`, `issuer.BuildPayload` for validation; `license.ParseInstallationID`.
- Produces:
  - `type Customer struct{ ID int64; Name, Contact, Notes, CreatedBy string; CreatedAt time.Time }`
  - `type NewCustomer struct{ Name, Contact, Notes string }`
  - `func AddCustomer(ctx, q audit.Q, c NewCustomer) (int64, error)`; `var ErrDuplicateCustomer`
  - `type NewRequest struct{ CustomerID int64; Installation string; Targets int; From string; Months int; Features []string; Replaces string }`
  - `type Request struct{ ID int64; Customer string; NewRequest; Status, RequestedBy string; RequestedAt time.Time }` (`Installation` holds the canonical id)
  - `func AddRequest(ctx, q audit.Q, r NewRequest, now time.Time) (int64, error)` (validates by building a payload; audit `request.add`)
  - `func GetRequest(ctx, q audit.Q, id int64) (Request, error)`; `var ErrNotFound`
  - `func ListRequests(ctx, q audit.Q, status string) ([]Request, error)`
  - `func RequestHash(r Request) string` (hex SHA-256 over the canonical fields, see the code)

- [ ] **Step 1: Write the failing unit test**

```go
package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestHashCoversEveryContentField(t *testing.T) {
	base := Request{ID: 1, Customer: "Acme Ltd", NewRequest: NewRequest{CustomerID: 1, Installation: "ALICE-AAAAA-BBBBB",
		Targets: 5, From: "2026-11-01", Months: 12, Features: []string{"ssh", "tls"}, Replaces: ""}}
	h := RequestHash(base)
	assert.Len(t, h, 64)
	assert.Equal(t, h, RequestHash(base), "stable")

	for name, mutate := range map[string]func(*Request){
		"customer":     func(r *Request) { r.Customer = "Other Ltd" },
		"installation": func(r *Request) { r.Installation = "ALICE-AAAAA-BBBBC" },
		"targets":      func(r *Request) { r.Targets = 6 },
		"from":         func(r *Request) { r.From = "2026-11-02" },
		"months":       func(r *Request) { r.Months = 13 },
		"features":     func(r *Request) { r.Features = []string{"ssh"} },
		"replaces":     func(r *Request) { r.Replaces = "LIC-2026-000001" },
	} {
		changed := base
		changed.Features = append([]string(nil), base.Features...)
		mutate(&changed)
		assert.NotEqual(t, h, RequestHash(changed), name)
	}
}

func TestRequestHashSeparatesFields(t *testing.T) {
	a := Request{Customer: "ab", NewRequest: NewRequest{Installation: "c"}}
	b := Request{Customer: "a", NewRequest: NewRequest{Installation: "bc"}}
	assert.NotEqual(t, RequestHash(a), RequestHash(b))
}

func TestRequestHashIgnoresStatusAndTimes(t *testing.T) {
	a := Request{Status: "open", RequestedBy: "x"}
	b := Request{Status: "signed", RequestedBy: "y"}
	assert.Equal(t, RequestHash(a), RequestHash(b))
}
```

- [ ] **Step 2: Run to see it fail**

Run: `go test -count=1 ./internal/vconsole/store/`
Expected: FAIL to compile.

- [ ] **Step 3: Implement**

```go
// Package store reads and writes vendor customers and license requests. Every write is one audit
// row in the same transaction when the caller passes a pgx.Tx.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/text/unicode/norm"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/db"
	"alice/internal/vconsole/audit"
)

// Errors.
var (
	ErrDuplicateCustomer = errors.New("store: a customer with this name already exists")
	ErrNotFound          = errors.New("store: not found")
)

// Customer is a company that buys licenses.
type Customer struct {
	ID        int64
	Name      string
	Contact   string
	Notes     string
	CreatedBy string
	CreatedAt time.Time
}

// NewCustomer is what a sales person enters.
type NewCustomer struct{ Name, Contact, Notes string }

// AddCustomer creates a customer. The name is NFC-normalized and trimmed, and compared without
// regard to case, so the same company typed twice is one customer.
func AddCustomer(ctx context.Context, q audit.Q, c NewCustomer) (int64, error) {
	name := strings.TrimSpace(norm.NFC.String(c.Name))
	var id int64
	err := q.QueryRow(ctx, `INSERT INTO customers (name, contact, notes) VALUES ($1, $2, $3) RETURNING id`,
		name, strings.TrimSpace(c.Contact), strings.TrimSpace(c.Notes)).Scan(&id)
	if db.IsUniqueViolationOn(err, "customers_name_key") {
		return 0, ErrDuplicateCustomer
	}
	if err != nil {
		return 0, fmt.Errorf("store: add customer: %w", err)
	}
	if _, err := audit.Append(ctx, q, "customer.add", fmt.Sprint(id), map[string]any{"name": name}); err != nil {
		return 0, err
	}
	return id, nil
}

// NewRequest is a license a sales person asks for.
type NewRequest struct {
	CustomerID   int64
	Installation string   // as typed; stored in canonical form
	Targets      int      // 1..100000
	From         string   // "" = today; "2026-10-01" or RFC 3339
	Months       int      // 0 = 12
	Features     []string // empty entries are dropped
	Replaces     string   // license ID a correction replaces
}

// Request is a stored request.
type Request struct {
	ID       int64
	Customer string // the customer's name
	NewRequest
	Status      string
	RequestedBy string
	RequestedAt time.Time
}

func normalizedFeatures(in []string) []string {
	out := []string{}
	for _, f := range in {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// AddRequest validates the request by building the payload it would produce (so a request that
// could never be signed is refused now, not at signing time) and stores it.
func AddRequest(ctx context.Context, q audit.Q, r NewRequest, now time.Time) (int64, error) {
	var name string
	if err := q.QueryRow(ctx, `SELECT name FROM customers WHERE id = $1`, r.CustomerID).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("%w: customer %d", ErrNotFound, r.CustomerID)
		}
		return 0, fmt.Errorf("store: read customer: %w", err)
	}
	if _, err := issuer.BuildPayload(issuer.Request{
		Installation: r.Installation, Customer: name, Targets: r.Targets, From: r.From,
		Months: r.Months, Features: r.Features, Replaces: r.Replaces,
	}, now); err != nil {
		return 0, fmt.Errorf("store: the request cannot become a license: %w", err)
	}
	inst, err := license.ParseInstallationID(r.Installation)
	if err != nil {
		return 0, err
	}
	months := r.Months
	if months == 0 {
		months = 12
	}
	var id int64
	err = q.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, valid_from, months, features, replaces)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		r.CustomerID, inst, r.Targets, strings.TrimSpace(r.From), months, normalizedFeatures(r.Features),
		strings.TrimSpace(r.Replaces)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: add request: %w", err)
	}
	if _, err := audit.Append(ctx, q, "request.add", fmt.Sprint(id),
		map[string]any{"customer": name, "installation": inst, "targets": r.Targets}); err != nil {
		return 0, err
	}
	return id, nil
}

const requestColumns = `r.id, c.name, r.customer_id, r.installation, r.targets, r.valid_from, r.months, r.features,
	r.replaces, r.status, r.requested_by, r.requested_at`

func scanRequest(row pgx.Row) (Request, error) {
	var r Request
	err := row.Scan(&r.ID, &r.Customer, &r.CustomerID, &r.Installation, &r.Targets, &r.From, &r.Months, &r.Features,
		&r.Replaces, &r.Status, &r.RequestedBy, &r.RequestedAt)
	return r, err
}

// GetRequest returns one request.
func GetRequest(ctx context.Context, q audit.Q, id int64) (Request, error) {
	r, err := scanRequest(q.QueryRow(ctx, `SELECT `+requestColumns+` FROM license_requests r
		JOIN customers c ON c.id = r.customer_id WHERE r.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	return r, err
}

// ListRequests returns requests, oldest first. An empty status means all.
func ListRequests(ctx context.Context, q audit.Q, status string) ([]Request, error) {
	rows, err := q.Query(ctx, `SELECT `+requestColumns+` FROM license_requests r
		JOIN customers c ON c.id = r.customer_id WHERE $1 = '' OR r.status = $1 ORDER BY r.requested_at, r.id`, status)
	if err != nil {
		return nil, fmt.Errorf("store: list requests: %w", err)
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list requests: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RequestHash is the SHA-256 (hex) of the content a signer approves: customer name, canonical
// installation ID, targets, start, months, features and the license it replaces. A JSON array
// keeps the fields apart. It is recomputed from the database row at signing time, so a request
// that changed after the signer looked at it is noticed.
func RequestHash(r Request) string {
	feats := r.Features
	if feats == nil {
		feats = []string{}
	}
	raw, _ := json.Marshal([]any{r.Customer, r.Installation, r.Targets, r.From, r.Months, feats, r.Replaces})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run the unit test**

Run: `go test -count=1 ./internal/vconsole/store/`
Expected: PASS.

- [ ] **Step 5: Write the integration tests**

```go
//go:build integration

package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

var now = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

func TestCustomerNamesAreNormalizedAndUnique(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_a")
	_, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Çelik A.Ş."})
	require.NoError(t, err)
	// Same name: decomposed Unicode, extra spaces, other case.
	_, err = store.AddCustomer(ctx, sales, store.NewCustomer{Name: "  ÇELIK a.ş. "})
	assert.ErrorIs(t, err, store.ErrDuplicateCustomer)
}

func TestAddRequestStoresCanonicalInstallationAndAudits(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_b")
	cid, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Acme Ltd"})
	require.NoError(t, err)
	inst := license.NewInstallationID()
	id, err := store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: " " + inst + " ",
		Targets: 5, Features: []string{" ssh ", ""}}, now)
	require.NoError(t, err)

	got, err := store.GetRequest(ctx, sales, id)
	require.NoError(t, err)
	assert.Equal(t, inst, got.Installation)
	assert.Equal(t, "Acme Ltd", got.Customer)
	assert.Equal(t, 12, got.Months)
	assert.Equal(t, []string{"ssh"}, got.Features)
	assert.Equal(t, "open", got.Status)
	assert.Equal(t, "t_store_b", got.RequestedBy)
	require.NoError(t, audit.Check(ctx, d.Owner))
}

func TestAddRequestRefusesWhatCouldNeverBeSigned(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_c")
	cid, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Beta Ltd"})
	require.NoError(t, err)
	valid := license.NewInstallationID()

	for name, r := range map[string]store.NewRequest{
		"bad installation id": {CustomerID: cid, Installation: "ALICE-AAAAA-AAAAA", Targets: 5},
		"zero targets":        {CustomerID: cid, Installation: valid, Targets: 0},
		"too many months":     {CustomerID: cid, Installation: valid, Targets: 5, Months: 61},
		"start long ago":      {CustomerID: cid, Installation: valid, Targets: 5, From: "2020-01-01"},
		"unknown customer":    {CustomerID: 9999, Installation: valid, Targets: 5},
	} {
		_, err := store.AddRequest(ctx, sales, r, now)
		assert.Error(t, err, name)
	}
	list, err := store.ListRequests(ctx, sales, "")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestListRequestsFiltersByStatus(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	sales := d.As(t, "vendor_sales", "t_store_d")
	cid, err := store.AddCustomer(ctx, sales, store.NewCustomer{Name: "Gamma Ltd"})
	require.NoError(t, err)
	a, err := store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: license.NewInstallationID(), Targets: 1}, now)
	require.NoError(t, err)
	_, err = store.AddRequest(ctx, sales, store.NewRequest{CustomerID: cid, Installation: license.NewInstallationID(), Targets: 2}, now)
	require.NoError(t, err)
	_, err = sales.Exec(ctx, `UPDATE license_requests SET status = 'cancelled' WHERE id = $1`, a)
	require.NoError(t, err)

	open, err := store.ListRequests(ctx, sales, "open")
	require.NoError(t, err)
	assert.Len(t, open, 1)
	all, err := store.ListRequests(ctx, sales, "")
	require.NoError(t, err)
	assert.Len(t, all, 2)
}
```

Note on `"start long ago"`: `BuildPayload` refuses a start more than a day in the past unless the request replaces a license; that is the behavior being pinned.

- [ ] **Step 6: Run the integration tests**

Run: `go test -tags integration -race -count=1 ./internal/vconsole/store/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/vconsole/store
git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit -m "feat(vendor): customers and license requests with request hash

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: The Signer interface and the file-key signer

**Files:**
- Create: `internal/vconsole/sign/sign.go`
- Test: `internal/vconsole/sign/sign_test.go`

**Interfaces:**
- Consumes: `issuer.SigningKey` (`KeyID()`, `Public()`, `Issue(license.Payload)`), `license.Check`, `license.NewKeySet`.
- Produces:
  - `type Signer interface{ KeyID() string; Public() ed25519.PublicKey; Issue(ctx context.Context, p license.Payload) ([]byte, error) }`
  - `type FileSigner struct{ ... }`; `func NewFileSigner(k *issuer.SigningKey) *FileSigner`
  - `func Verify(raw []byte, s Signer) (license.File, error)` (checks a signed file against the signer's public key)

- [ ] **Step 1: Write the failing test**

```go
package sign_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/vconsole/sign"
)

var fastKDF = issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

const words = "amber canyon violet orbit lantern quiet"

func newSigner(t *testing.T, keyID string) *sign.FileSigner {
	t.Helper()
	priv, _, err := issuer.GenerateKey(keyID, []byte(words), fastKDF)
	require.NoError(t, err)
	k, err := issuer.OpenKey(priv, []byte(words))
	require.NoError(t, err)
	return sign.NewFileSigner(k)
}

func payload() license.Payload {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	return license.Payload{
		LicenseID: "LIC-2026-000001", Customer: "Acme Ltd", InstallationID: license.NewInstallationID(),
		IssuedAt: now, ValidFrom: now, ValidUntil: now.AddDate(1, 0, 0), MaxTargets: 5,
		Features: []string{}, Format: license.FormatVersion,
	}
}

var _ sign.Signer = (*sign.FileSigner)(nil)

func TestFileSignerIssuesAFileThatVerifies(t *testing.T) {
	s := newSigner(t, "vk-2026-01")
	assert.Equal(t, "vk-2026-01", s.KeyID())
	raw, err := s.Issue(context.Background(), payload())
	require.NoError(t, err)
	f, err := sign.Verify(raw, s)
	require.NoError(t, err)
	assert.Equal(t, "vk-2026-01", f.KeyID)
	assert.Equal(t, "Acme Ltd", f.Payload.Customer)
}

func TestVerifyRefusesAnotherKeyAndATamperedFile(t *testing.T) {
	a, b := newSigner(t, "vk-2026-01"), newSigner(t, "vk-2026-02")
	raw, err := a.Issue(context.Background(), payload())
	require.NoError(t, err)
	_, err = sign.Verify(raw, b)
	assert.Error(t, err, "signed by another key")

	tampered := []byte(string(raw))
	for i := range tampered {
		if tampered[i] == '5' { // MaxTargets
			tampered[i] = '9'
			break
		}
	}
	_, err = sign.Verify(tampered, a)
	assert.Error(t, err)
}

func TestIssueHonoursACancelledContext(t *testing.T) {
	s := newSigner(t, "vk-2026-01")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Issue(ctx, payload())
	assert.ErrorIs(t, err, context.Canceled)
}
```

The tamper test depends on the targets value `5` appearing in the encoded file before any other `5`. If `license.EncodeFile` output changes that, pick the byte by locating `"max_targets"` instead. Run it first (step 2/4) and adjust only the byte search.

- [ ] **Step 2: Run to see it fail**

Run: `go test -count=1 ./internal/vconsole/sign/`
Expected: FAIL to compile.

- [ ] **Step 3: Implement**

```go
// Package sign is the seam between the vendor console and whatever holds the license signing key.
// Phase 1 has the passphrase key file; a YubiKey implementation (PIV or OpenPGP) joins in Phase 2
// behind the same interface.
package sign

import (
	"context"
	"crypto/ed25519"

	"alice/internal/license"
	"alice/internal/license/issuer"
)

// Signer issues a signed license file for a payload. Implementations may ask for a PIN or a touch;
// Issue must honour ctx.
type Signer interface {
	KeyID() string
	Public() ed25519.PublicKey
	Issue(ctx context.Context, p license.Payload) ([]byte, error)
}

// FileSigner signs with the passphrase-protected key file opened by issuer.OpenKey.
type FileSigner struct{ key *issuer.SigningKey }

// NewFileSigner wraps an opened license signing key.
func NewFileSigner(k *issuer.SigningKey) *FileSigner { return &FileSigner{key: k} }

// KeyID returns the key ID written into every license.
func (s *FileSigner) KeyID() string { return s.key.KeyID() }

// Public returns the verification key.
func (s *FileSigner) Public() ed25519.PublicKey { return s.key.Public() }

// Issue signs p.
func (s *FileSigner) Issue(ctx context.Context, p license.Payload) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.key.Issue(p)
}

// Verify checks a license file against the signer's own public key, the way the product would
// with that key in its key set. The issuing code calls it on every file it just produced.
func Verify(raw []byte, s Signer) (license.File, error) {
	ks := license.NewKeySet(license.PublicKey{ID: s.KeyID(), Key: s.Public(), Status: license.KeyActive})
	return license.Check(raw, ks)
}
```

- [ ] **Step 4: Run to see it pass**

Run: `go test -race -count=1 ./internal/vconsole/sign/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vconsole/sign
git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit -m "feat(vendor): Signer interface and file-key signer

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 6: The issuing transaction

**Files:**
- Create: `internal/vconsole/issue/issue.go`
- Test: `internal/vconsole/issue/issue_integration_test.go`

**Interfaces:**
- Consumes: `store.GetRequest`, `store.RequestHash`, `store.Request` (Task 4); `sign.Signer`, `sign.Verify` (Task 5); `audit.Append`; `issuer.BuildPayload`; `db.InTx(ctx, pool, func(pgx.Tx) error)` and `db.IsUniqueViolationOn`.
- Produces:
  - `type Params struct{ RequestID int64; ExpectedHash string; LicenseID string; Shorten bool }` (`LicenseID` empty means a random `LIC-<year>-<6 digits>`)
  - `type Result struct{ LicenseID string; File []byte; KeyID string; FileSHA256 string; ValidUntil time.Time }`
  - `func Issue(ctx context.Context, pool *pgxpool.Pool, s sign.Signer, p Params, now time.Time) (Result, error)`
  - errors: `ErrNotOpen`, `ErrRequestChanged`, `ErrUnknownReplaced`, `ErrOtherInstallation`, `ErrShortensTerm`, `ErrDuplicateLicenseID`

- [ ] **Step 1: Write the failing tests**

```go
//go:build integration

package issue_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/issue"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

var (
	now     = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	fastKDF = issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}
)

const words = "amber canyon violet orbit lantern quiet"

type env struct {
	d      *vpgtest.DB
	sales  *pgxpool.Pool
	signer *pgxpool.Pool
	key    *sign.FileSigner
	cust   int64
}

func setup(t *testing.T, tag string) env {
	t.Helper()
	d := vpgtest.New(t)
	priv, _, err := issuer.GenerateKey("vk-2026-01", []byte(words), fastKDF)
	require.NoError(t, err)
	k, err := issuer.OpenKey(priv, []byte(words))
	require.NoError(t, err)
	e := env{d: d, sales: d.As(t, "vendor_sales", "t_i_sales_"+tag), signer: d.As(t, "vendor_signer", "t_i_signer_"+tag),
		key: sign.NewFileSigner(k)}
	e.cust, err = store.AddCustomer(context.Background(), e.sales, store.NewCustomer{Name: "Acme Ltd"})
	require.NoError(t, err)
	return e
}

func (e env) request(t *testing.T, inst string, targets int, replaces string) (int64, string) {
	t.Helper()
	ctx := context.Background()
	id, err := store.AddRequest(ctx, e.sales, store.NewRequest{CustomerID: e.cust, Installation: inst, Targets: targets,
		From: "2026-10-15", Months: 12, Replaces: replaces}, now)
	require.NoError(t, err)
	r, err := store.GetRequest(ctx, e.signer, id)
	require.NoError(t, err)
	return id, store.RequestHash(r)
}

func TestIssueSignsRecordsAndAudits(t *testing.T) {
	e := setup(t, "a")
	ctx := context.Background()
	inst := license.NewInstallationID()
	id, hash := e.request(t, inst, 5, "")

	res, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
	require.NoError(t, err)
	assert.Regexp(t, `^LIC-2026-\d{6}$`, res.LicenseID)

	f, err := sign.Verify(res.File, e.key)
	require.NoError(t, err)
	assert.Equal(t, inst, f.Payload.InstallationID)
	assert.Equal(t, 5, f.Payload.MaxTargets)
	assert.Equal(t, "Acme Ltd", f.Payload.Customer)

	var status, signedBy, keyID string
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT r.status, l.signed_by, l.key_id FROM license_requests r
		JOIN licenses l ON l.request_id = r.id WHERE r.id = $1`, id).Scan(&status, &signedBy, &keyID))
	assert.Equal(t, "signed", status)
	assert.Equal(t, "t_i_signer_a", signedBy)
	assert.Equal(t, "vk-2026-01", keyID)
	var n int
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action = 'license.issue' AND subject = $1`, res.LicenseID).Scan(&n))
	assert.Equal(t, 1, n)
	require.NoError(t, audit.Check(ctx, e.d.Owner))
}

func TestIssueRefusesARequestThatChangedAfterTheSignerLooked(t *testing.T) {
	e := setup(t, "b")
	ctx := context.Background()
	id, hash := e.request(t, license.NewInstallationID(), 5, "")
	// The requester (or anyone with write access) raises the target count after the signer saw it.
	_, err := e.sales.Exec(ctx, `UPDATE license_requests SET targets = 500 WHERE id = $1`, id)
	require.NoError(t, err)

	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
	assert.ErrorIs(t, err, issue.ErrRequestChanged)
	var n int
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT count(*) FROM licenses`).Scan(&n))
	assert.Zero(t, n)
}

func TestIssueTwiceFromOneRequestYieldsOneLicense(t *testing.T) {
	e := setup(t, "c")
	ctx := context.Background()
	id, hash := e.request(t, license.NewInstallationID(), 5, "")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
		}()
	}
	wg.Wait()
	ok, notOpen := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case assert.ErrorIs(t, err, issue.ErrNotOpen):
			notOpen++
		}
	}
	assert.Equal(t, 1, ok)
	assert.Equal(t, 1, notOpen)
}

func TestIssueRefusesNonOpenAndUnknownRequests(t *testing.T) {
	e := setup(t, "d")
	ctx := context.Background()
	id, hash := e.request(t, license.NewInstallationID(), 5, "")
	_, err := e.sales.Exec(ctx, `UPDATE license_requests SET status = 'cancelled' WHERE id = $1`, id)
	require.NoError(t, err)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
	assert.ErrorIs(t, err, issue.ErrNotOpen)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: 9999, ExpectedHash: hash}, now)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestSalesCannotIssue(t *testing.T) {
	e := setup(t, "e")
	id, hash := e.request(t, license.NewInstallationID(), 5, "")
	_, err := issue.Issue(context.Background(), e.sales, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
	assert.Error(t, err)
	var n int
	require.NoError(t, e.d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM licenses`).Scan(&n))
	assert.Zero(t, n)
}

func TestDuplicateLicenseIDIsRefusedAndTheRequestStaysOpen(t *testing.T) {
	e := setup(t, "f")
	ctx := context.Background()
	id1, h1 := e.request(t, license.NewInstallationID(), 5, "")
	id2, h2 := e.request(t, license.NewInstallationID(), 6, "")
	_, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id1, ExpectedHash: h1, LicenseID: "LIC-2026-777777"}, now)
	require.NoError(t, err)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id2, ExpectedHash: h2, LicenseID: "LIC-2026-777777"}, now)
	assert.ErrorIs(t, err, issue.ErrDuplicateLicenseID)
	var status string
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT status FROM license_requests WHERE id = $1`, id2).Scan(&status))
	assert.Equal(t, "open", status)
}

func TestCorrectionRules(t *testing.T) {
	e := setup(t, "g")
	ctx := context.Background()
	inst := license.NewInstallationID()
	id, h := e.request(t, inst, 5, "")
	first, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: h}, now)
	require.NoError(t, err)

	// Unknown license.
	idU, hU := e.request(t, inst, 6, "LIC-2026-000000")
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: idU, ExpectedHash: hU}, now)
	assert.ErrorIs(t, err, issue.ErrUnknownReplaced)

	// Another installation.
	idO, hO := e.request(t, license.NewInstallationID(), 6, first.LicenseID)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: idO, ExpectedHash: hO}, now)
	assert.ErrorIs(t, err, issue.ErrOtherInstallation)

	// Ends earlier than the license it replaces: refused unless Shorten is set.
	idS, err := store.AddRequest(ctx, e.sales, store.NewRequest{CustomerID: e.cust, Installation: inst, Targets: 5,
		From: "2026-10-15", Months: 6, Replaces: first.LicenseID}, now)
	require.NoError(t, err)
	rS, err := store.GetRequest(ctx, e.signer, idS)
	require.NoError(t, err)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: idS, ExpectedHash: store.RequestHash(rS)}, now)
	assert.ErrorIs(t, err, issue.ErrShortensTerm)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: idS, ExpectedHash: store.RequestHash(rS), Shorten: true}, now)
	assert.NoError(t, err)
}
```

- [ ] **Step 2: Run to see it fail**

Run: `go test -tags integration -count=1 ./internal/vconsole/issue/`
Expected: FAIL to compile (`issue` package missing).

- [ ] **Step 3: Implement**

```go
// Package issue turns an open license request into a signed license in one database transaction:
// lock the request, check it is still what the signer saw, apply the correction rules, sign,
// record the license, close the request and write the audit row. If any step fails nothing is
// recorded.
package issue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/db"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/store"
)

// Errors. They mirror the refusals of licensectl's ledger.
var (
	ErrNotOpen            = errors.New("issue: the request is not open")
	ErrRequestChanged     = errors.New("issue: the request changed after it was shown; look at it again")
	ErrUnknownReplaced    = errors.New("issue: the license named by the request is not recorded")
	ErrOtherInstallation  = errors.New("issue: the replaced license is for another installation")
	ErrShortensTerm       = errors.New("issue: the correction ends earlier than the license it replaces; set Shorten if that is intended")
	ErrDuplicateLicenseID = errors.New("issue: a license with this ID was already issued")
)

// Params selects the request and what the signer saw.
type Params struct {
	RequestID    int64
	ExpectedHash string // store.RequestHash of the request as the signer saw it
	LicenseID    string // "" = LIC-<year>-<6 random digits>
	Shorten      bool   // allow a correction to end earlier than the license it replaces
}

// Result is the issued license.
type Result struct {
	LicenseID  string
	File       []byte
	KeyID      string
	FileSHA256 string
	ValidUntil time.Time
}

// Issue signs the request with s. pool must act as a signer login.
func Issue(ctx context.Context, pool *pgxpool.Pool, s sign.Signer, p Params, now time.Time) (Result, error) {
	var res Result
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		// Lock the row so two signers cannot both issue from one request.
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM license_requests WHERE id = $1 FOR UPDATE`, p.RequestID).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("issue: lock request: %w", err)
		}
		if status != "open" {
			return ErrNotOpen
		}
		req, err := store.GetRequest(ctx, tx, p.RequestID)
		if err != nil {
			return err
		}
		if store.RequestHash(req) != p.ExpectedHash {
			return ErrRequestChanged
		}
		payload, err := issuer.BuildPayload(issuer.Request{
			Installation: req.Installation, Customer: req.Customer, Targets: req.Targets, From: req.From,
			Months: req.Months, Features: req.Features, Replaces: req.Replaces, LicenseID: p.LicenseID,
		}, now)
		if err != nil {
			return err
		}
		if err := checkCorrection(ctx, tx, payload, p.Shorten); err != nil {
			return err
		}
		raw, err := s.Issue(ctx, payload)
		if err != nil {
			return fmt.Errorf("issue: sign: %w", err)
		}
		// Never record a file the product would not accept.
		if _, err := sign.Verify(raw, s); err != nil {
			return fmt.Errorf("issue: the signed file does not verify: %w", err)
		}
		sum := sha256.Sum256(raw)
		res = Result{LicenseID: payload.LicenseID, File: raw, KeyID: s.KeyID(), FileSHA256: hex.EncodeToString(sum[:]),
			ValidUntil: payload.ValidUntil}
		_, err = tx.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
			valid_from, valid_until, targets, replaces, file, file_sha256)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			payload.LicenseID, req.ID, req.CustomerID, payload.InstallationID, s.KeyID(), payload.IssuedAt,
			payload.ValidFrom, payload.ValidUntil, payload.MaxTargets, payload.Replaces, raw, res.FileSHA256)
		if db.IsUniqueViolationOn(err, "licenses_pkey") {
			return ErrDuplicateLicenseID
		}
		if err != nil {
			return fmt.Errorf("issue: record license: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE license_requests SET status = 'signed' WHERE id = $1`, req.ID); err != nil {
			return fmt.Errorf("issue: close request: %w", err)
		}
		_, err = audit.Append(ctx, tx, "license.issue", payload.LicenseID, map[string]any{
			"request": req.ID, "customer": req.Customer, "installation": payload.InstallationID,
			"targets": payload.MaxTargets, "valid_until": payload.ValidUntil.Format(time.RFC3339),
			"key_id": s.KeyID(), "file_sha256": res.FileSHA256, "replaces": payload.Replaces,
		})
		return err
	})
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// checkCorrection applies the rules licensectl's ledger applies to a license that replaces another.
func checkCorrection(ctx context.Context, q audit.Q, p license.Payload, shorten bool) error {
	if p.Replaces == "" {
		return nil
	}
	var inst string
	var until time.Time
	err := q.QueryRow(ctx, `SELECT installation, valid_until FROM licenses WHERE license_id = $1`, p.Replaces).Scan(&inst, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnknownReplaced
	}
	if err != nil {
		return fmt.Errorf("issue: read replaced license: %w", err)
	}
	if inst != p.InstallationID {
		return ErrOtherInstallation
	}
	if p.ValidUntil.Before(until) && !shorten {
		return ErrShortensTerm
	}
	return nil
}
```

The sales-cannot-issue test relies on the grants: a sales login has no `INSERT` on `licenses` and no `UPDATE` policy that allows `signed`; the transaction fails and rolls back, so no licence and no half-written audit row remain. If `SELECT ... FOR UPDATE` itself is refused for sales (no UPDATE row policy matches an other-user request), that also yields an error: either way the assertion `Error` holds.

- [ ] **Step 4: Run to see it pass**

Run: `go test -tags integration -race -count=1 ./internal/vconsole/issue/`
Expected: PASS. Failure hints: if `TestIssueTwiceFromOneRequestYieldsOneLicense` flakes, check that `FOR UPDATE` is the first statement of the transaction and `db.InTx` uses the default isolation (READ COMMITTED), under which the second waiter re-reads the row after the first commits and sees `signed`.

- [ ] **Step 5: Commit**

```bash
git add internal/vconsole/issue
git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit -m "feat(vendor): issue a license from a request in one transaction

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 7: The command line, import guard and operator notes

**Files:**
- Create: `cmd/vendor-console/main.go`
- Create: `cmd/vendor-console/run.go`
- Test: `cmd/vendor-console/run_test.go` (unit: usage, flags, no database)
- Test: `cmd/vendor-console/run_integration_test.go`
- Modify: `cmd/alice/license_release_test.go:37` (extend the forbidden import list)
- Create: `docs/vendor-console.md`

**Interfaces:**
- Consumes: everything above; `issuer.OpenKey`; `db.Open`, `db.Migrate`; `golang.org/x/term` for the passphrase prompt (same as `cmd/licensectl/terminal.go`).
- Produces: commands

```
vendor-console migrate
vendor-console customer add --name NAME [--contact C] [--notes N]
vendor-console request add --customer ID --installation ID --targets N [--from DATE] [--months N] [--features a,b] [--replaces ID]
vendor-console request list [--status open]
vendor-console request show ID                (prints the fields and the request hash)
vendor-console issue --request ID --hash HASH --key FILE --out FILE [--license-id ID] [--shorten]
vendor-console audit-verify
```

The database URL is read from `VENDOR_DATABASE_URL`. The key passphrase is asked on the terminal (no echo), never read from the environment or a flag. `run` has the signature `func run(args []string, getenv func(string) string, stdout, stderr io.Writer, ask prompter, clk clock.Clock) int` so tests inject everything (mirror `cmd/licensectl/main.go`; read its `terminalPassphrase`, `prompter` and `clock` usage and reuse the same shapes rather than inventing new ones).

- [ ] **Step 1: Write the unit tests**

```go
package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

func runArgs(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, func(string) string { return "" }, &out, &errOut, nil, clock.Real{})
	return code, out.String(), errOut.String()
}

func TestNoArgumentsPrintsUsage(t *testing.T) {
	code, _, stderr := runArgs()
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "Usage: vendor-console")
}

func TestUnknownCommandIsRefused(t *testing.T) {
	code, _, stderr := runArgs("frobnicate")
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "frobnicate")
}

func TestCommandsThatNeedTheDatabaseSayHowToSetIt(t *testing.T) {
	for _, args := range [][]string{{"migrate"}, {"request", "list"}, {"audit-verify"}} {
		code, _, stderr := runArgs(args...)
		assert.Equal(t, 1, code, args)
		assert.Contains(t, stderr, "VENDOR_DATABASE_URL", args)
	}
}

func TestIssueNeedsItsFlags(t *testing.T) {
	code, _, stderr := runArgs("issue", "--request", "1")
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "--hash")
}
```

- [ ] **Step 2: Write the integration test (migrate, add, show, issue, verify)**

```go
//go:build integration

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

const words = "amber canyon violet orbit lantern quiet"

func TestIssueJourney(t *testing.T) {
	d := vpgtest.New(t)
	// The CLI connects with a signer login. Give it one through the owner URL's database.
	// For this test the connection is the migration role (a superuser); role separation is covered by
	// the package tests.
	getenv := func(k string) string {
		if k == "VENDOR_DATABASE_URL" {
			return d.OwnerURL
		}
		return ""
	}
	dir := t.TempDir()
	priv, _, err := issuer.GenerateKey("vk-2026-01", []byte(words), issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1})
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, priv, 0o600))
	ask := func(string) ([]byte, error) { return []byte(words), nil }

	do := func(args ...string) (string, string, int) {
		var out, errOut bytes.Buffer
		code := run(args, getenv, &out, &errOut, ask, clock.Real{})
		return out.String(), errOut.String(), code
	}

	_, e, code := do("migrate")
	require.Equal(t, 0, code, e)
	out, e, code := do("customer", "add", "--name", "Acme Ltd")
	require.Equal(t, 0, code, e)
	cust := strings.TrimSpace(regexp.MustCompile(`\d+`).FindString(out))
	inst := license.NewInstallationID()
	out, e, code = do("request", "add", "--customer", cust, "--installation", inst, "--targets", "5")
	require.Equal(t, 0, code, e)
	reqID := regexp.MustCompile(`\d+`).FindString(out)

	out, e, code = do("request", "show", reqID)
	require.Equal(t, 0, code, e)
	hash := regexp.MustCompile(`[0-9a-f]{64}`).FindString(out)
	require.NotEmpty(t, hash)
	assert.Contains(t, out, "Acme Ltd")
	assert.Contains(t, out, inst)

	// A wrong hash is refused and nothing is written.
	outPath := filepath.Join(dir, "out.json")
	_, e, code = do("issue", "--request", reqID, "--hash", strings.Repeat("0", 64), "--key", keyPath, "--out", outPath)
	assert.Equal(t, 1, code)
	assert.Contains(t, e, "changed")
	assert.NoFileExists(t, outPath)

	_, e, code = do("issue", "--request", reqID, "--hash", hash, "--key", keyPath, "--out", outPath)
	require.Equal(t, 0, code, e)
	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	f, err := license.ParseFile(raw)
	require.NoError(t, err)
	assert.Equal(t, inst, f.Payload.InstallationID)
	info, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the license file is not world readable")

	out, e, code = do("audit-verify")
	require.Equal(t, 0, code, e)
	assert.Contains(t, out, "OK")
}
```

Note: running as the migration role means `current_user` is the owner; the audit `actor` is that login. That is acceptable here; role behavior has its own tests.

- [ ] **Step 3: Run both to see them fail**

Run: `go test -count=1 ./cmd/vendor-console/` and `go test -tags integration -count=1 ./cmd/vendor-console/`
Expected: FAIL to compile (`run` missing).

- [ ] **Step 4: Implement `main.go` and `run.go`**

`cmd/vendor-console/main.go` (mirror `cmd/licensectl`; read its `terminalPassphrase` first and copy that helper into `terminal.go` with the same `golang.org/x/term` use):

```go
// Command vendor-console is the vendor's license record and issuing tool (design spec
// 2026-10-15-vendor-console-design.md). It never ships to customers; the alice binary must not
// link it or anything under internal/vconsole (checked by cmd/alice tests).
package main

import (
	"os"

	"alice/internal/platform/clock"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr, terminalPassphrase, clock.Real{}))
}
```

`cmd/vendor-console/run.go` implements `usage`, the `prompter` type and `run`. Required behavior, all pinned by the tests above:

- `usage` starts with `Usage: vendor-console <command> [flags]` and lists the commands in the Interfaces block.
- no args: print usage to stderr, return 2. Unknown command: print `vendor-console: unknown command "<name>"` and the usage, return 2.
- commands that need the database read `VENDOR_DATABASE_URL`; if empty, print `vendor-console: set VENDOR_DATABASE_URL to the Neon connection string` to stderr and return 1. Errors never include the URL.
- `migrate`: `db.Open` then `db.Migrate(ctx, pool, migrations.FS)`; print `migrations applied`.
- `customer add`: `store.AddCustomer` on the pool; print `customer <id>`.
- `request add`: `store.AddRequest(ctx, pool, req, clk.Now())`; print `request <id>`. `--features` is comma separated.
- `request list`: one line per request: `<id>  <status>  <customer>  <targets>  <installation>`.
- `request show ID`: prints each field on its own line and a last line `hash <RequestHash>`.
- `issue`: requires `--request`, `--hash`, `--key`, `--out` (missing flag: print the flag name and the usage line, return 2). Reads the key file, asks `ask("Key passphrase: ")`, `issuer.OpenKey`, zeroes the key with `Zero()` on return, calls `issue.Issue`, writes the file with `issuer.WriteNew(path, data, 0o600)` (it refuses to overwrite) only after `Issue` returned nil, prints `issued <license id> valid until <date>`. Map `issue.ErrRequestChanged` to a message containing `changed`.
- `audit-verify`: `audit.Verify`; print `audit chain OK` and return 0, or `audit chain BROKEN at sequence <n>` and return 1.

Flag parsing uses `flag.NewFlagSet(name, flag.ContinueOnError)` with `SetOutput(stderr)`, exactly as `cmd/licensectl/main.go` does.

- [ ] **Step 5: Run the tests**

Run: `go test -race -count=1 ./cmd/vendor-console/ && go test -tags integration -race -count=1 ./cmd/vendor-console/`
Expected: PASS.

- [ ] **Step 6: Extend the product import guard**

In `cmd/alice/license_release_test.go`, change the forbidden list in `TestReleaseBinaryLinksNoTestOrVendorCode`:

```go
	for _, forbidden := range []string{
		"alice/internal/license/licensetest", "alice/internal/license/issuer",
		"alice/internal/vconsole/audit", "alice/internal/vconsole/issue", "alice/internal/vconsole/sign",
		"alice/internal/vconsole/store", "alice/internal/vconsole/migrations",
		"github.com/stretchr/testify/assert", "golang.org/x/term",
	} {
```

Run: `go test -count=1 -run TestReleaseBinaryLinksNoTestOrVendorCode ./cmd/alice/`
Expected: PASS.

- [ ] **Step 7: Architecture and whole-suite checks**

Run: `go vet ./... && go test -count=1 ./internal/archtest/ && make test`
Expected: all pass. If `TestImportRules` complains about a new package, add the narrowest rule that allows the import to `internal/archtest/arch_test.go` and a matching row in `TestAllowed`; do not widen an existing rule.

Run: `make lint` (if golangci-lint is installed) and fix findings in the new code only.

- [ ] **Step 8: Write the operator notes**

`docs/vendor-console.md` (short; plain language, no marketing):

```markdown
# Vendor console (Phase 1)

The vendor console keeps the vendor's customers, license requests and issued licenses in a
PostgreSQL database and issues licenses from requests. It is for the vendor only and is never
part of a customer build.

## Set up the database

1. Create the database (for example on Neon, EU region) and a migration login that may create
   roles. Set `VENDOR_DATABASE_URL` to its connection string. Never put the string in a file in
   this repository.
2. `vendor-console migrate`.
3. Create one login per person and add it to one group role:
   `CREATE ROLE "<login>" LOGIN PASSWORD '<password>' IN ROLE vendor_sales;` (sales people),
   `vendor_signer` (the people who sign) or `vendor_owner` (the owner).

## Daily use

    vendor-console customer add --name "Acme Ltd"
    vendor-console request add --customer 1 --installation ALICE-... --targets 5
    vendor-console request show 1          # note the hash on the last line
    vendor-console issue --request 1 --hash <hash> --key alice-license-private.pem --out acme.json
    vendor-console audit-verify

`issue` refuses when the request changed after you looked at it (the hash no longer matches),
when the request is no longer open, and when a correction would end earlier than the license it
replaces. The key passphrase is asked on the terminal.

## What the audit check proves

`audit-verify` proves that no audit row was edited or removed from the middle of the log. It does
not prove that the newest rows were not removed. A signed checkpoint that closes this gap is
planned for Phase 5.

## Not yet there

YubiKey signing (Phase 2), the sales web page (Phase 3), e-mail and reminders (Phase 4).
```

- [ ] **Step 9: Commit**

```bash
git add cmd/vendor-console cmd/alice/license_release_test.go docs/vendor-console.md
git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit -m "feat(vendor): vendor-console command, import guard and notes

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

## Self-review (done while writing)

**Spec coverage.** Spec 3 (components): store, sign, issue, audit, command are Tasks 3-7; the signing app UI and the sales web service are later phases by design. Spec 4.1 (`Signer`, file key): Task 5 (deviation 1 recorded). Spec 4.3 (what you see is what you sign): `RequestHash` and `ErrRequestChanged`, Tasks 4 and 6; the full-payload preview screen is Phase 2 UI. Spec 5 (tables, roles, RLS, append-only audit): Tasks 1-3; the `reminders` table belongs to Phase 4 and is not created now. Spec 6 (ledger rules): `checkCorrection` and duplicate ID in Task 6; the replace-cycle rule is not needed because the new license ID is always new (a duplicate ID is refused). The open item O2 (CSV export) is deferred to Phase 5 with the checkpoint. Spec 8 (product side) is not touched in this phase. Spec 10 phase 1 items: module layout, schema, roles with RLS, audit chain, `Signer` with the file key, issue from a request: all present.

**Placeholders.** None left in code steps. Task 7 step 4 describes `run.go` behavior in prose with exact messages instead of listing every line, because it is a mechanical flag-parsing wrapper whose observable behavior is pinned by the tests in steps 1-2 and whose template is `cmd/licensectl/main.go`; the implementer must read that file first.

**Type consistency.** `audit.Q` is used by `store` and `issue` (`pgx.Tx` and `*pgxpool.Pool` satisfy it). `store.Request` embeds `NewRequest`, so `Installation`, `Targets`, `From`, `Months`, `Features`, `Replaces`, `CustomerID` are promoted fields used in Task 6. `sign.Signer.Issue(ctx, license.Payload) ([]byte, error)` matches `FileSigner`. `issue.Params`, `Result` names match their uses in the tests and the command.

**Known risks to watch while executing.** (1) `current_setting('role')` inside the `SECURITY DEFINER` function (Task 3, step 4 note). (2) goose handling of `CREATE ROLE` and `DO` blocks (Task 1, step 5). (3) The tamper byte in the sign test (Task 5). (4) `BuildPayload` is called with the stored `From` text and the signer's clock, so a request left open for days with an empty `From` will start on the day it is signed, not the day it was requested; this is the intended behavior and is stated in the operator notes only if the owner wants a different rule.
