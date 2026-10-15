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

// AsPassword is the password of every role As creates (a throw-away test container).
const AsPassword = "login-test-pw" //nolint:gosec // G101: fixed password of a throw-away test container

// As creates login as a real LOGIN role that is a member of group and returns a pool connected as
// it, so grants, row-level security, session_user and current_user behave as for a real person.
// The role is dropped when the test ends. login must be unique per test run (roles are cluster-wide).
func (d *DB) As(t testing.TB, group, login string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	role := pgx.Identifier{login}.Sanitize()
	if _, err := d.Owner.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+AsPassword+"' IN ROLE "+pgx.Identifier{group}.Sanitize()); err != nil {
		t.Fatalf("vpgtest: create role %s: %v", login, err)
	}
	return d.Connect(t, login)
}

// Connect returns a pool connected as login, an existing role whose password is AsPassword (for a
// role the test created itself with special grants). The role is dropped when the test ends.
func (d *DB) Connect(t testing.TB, login string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	role := pgx.Identifier{login}.Sanitize()
	t.Cleanup(func() {
		_, _ = d.Owner.Exec(context.Background(), "DROP OWNED BY "+role)
		_, _ = d.Owner.Exec(context.Background(), "DROP ROLE IF EXISTS "+role)
	})
	u, err := url.Parse(d.OwnerURL)
	if err != nil {
		t.Fatalf("vpgtest: parse url: %v", err)
	}
	u.User = url.UserPassword(login, AsPassword)
	pool, err := db.Open(ctx, u.String())
	if err != nil {
		t.Fatalf("vpgtest: open pool as %s: %v", login, err)
	}
	t.Cleanup(pool.Close) // cleanups run last-in first-out: the pool closes before the role is dropped
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
