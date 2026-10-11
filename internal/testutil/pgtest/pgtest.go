//go:build integration

// Package pgtest gives integration tests a real PostgreSQL 16: one container per
// test package (started from TestMain via Main) and a fresh, fully migrated
// database per test, cloned from a template so each test starts in ~30 ms.
//
// Every database has two pools, mirroring production: Owner (the migration
// role, a superuser here) and App (the alice_app role with the grants from the
// migrations). Tests must exercise the application through App.
package pgtest

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"alice/internal/platform/db"
	"alice/migrations"
)

const (
	template = "alice_template"
	// AppPassword is the alice_app password inside the throw-away test container.
	AppPassword = "app-test-pw" //nolint:gosec // G101: fixed password of a throw-away test container
)

var (
	ownerBase string // superuser URL of the container's default database
	counter   atomic.Int64
)

// Main starts the container, prepares the template database, runs the tests and
// removes the container. Use it as: func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }.
func Main(m *testing.M) int {
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
		postgres.WithDatabase("alice"),
		postgres.WithUsername("alice"),
		postgres.WithPassword("s3cret-pw"),
		postgres.BasicWaitStrategies(),
	)
	if ctr != nil {
		defer func() { _ = testcontainers.TerminateContainer(ctr) }()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgtest: start postgres container:", err)
		return 1
	}
	ownerBase, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgtest: connection string:", err)
		return 1
	}
	if err := prepareTemplate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "pgtest: prepare template:", err)
		return 1
	}
	return m.Run()
}

// prepareTemplate migrates the template database once and gives alice_app a
// login so App pools can connect with the migration grants.
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
	tpl, err := db.Open(ctx, withDatabase(ownerBase, template, nil))
	if err != nil {
		return err
	}
	err = db.Migrate(ctx, tpl, migrations.FS)
	tpl.Close() // a template must have no open connections when it is cloned
	if err != nil {
		return err
	}
	_, err = admin.Exec(ctx, "ALTER ROLE alice_app LOGIN PASSWORD '"+AppPassword+"'")
	return err
}

// DB is one fresh database for one test.
type DB struct {
	Owner, App       *pgxpool.Pool
	OwnerURL, AppURL string
}

// New creates a fresh, migrated database and returns pools for both roles.
// The pools are closed when the test ends.
func New(t testing.TB) *DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := db.Open(ctx, ownerBase)
	if err != nil {
		t.Fatalf("pgtest: open admin pool: %v", err)
	}
	defer admin.Close()
	name := fmt.Sprintf("test_%d_%d", os.Getpid(), counter.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name+" TEMPLATE "+template); err != nil {
		t.Fatalf("pgtest: create database: %v", err)
	}

	d := &DB{
		OwnerURL: withDatabase(ownerBase, name, nil),
		AppURL:   withDatabase(ownerBase, name, url.UserPassword("alice_app", AppPassword)),
	}
	if d.Owner, err = db.Open(ctx, d.OwnerURL); err != nil {
		t.Fatalf("pgtest: open owner pool: %v", err)
	}
	t.Cleanup(d.Owner.Close)
	if d.App, err = db.Open(ctx, d.AppURL); err != nil {
		t.Fatalf("pgtest: open app pool: %v", err)
	}
	t.Cleanup(d.App.Close)
	return d
}

// withDatabase returns base with another database name and, if user is not
// nil, other credentials.
func withDatabase(base, name string, user *url.Userinfo) string {
	u, err := url.Parse(base)
	if err != nil {
		panic("pgtest: container URL does not parse: " + err.Error())
	}
	u.Path = "/" + name
	if user != nil {
		u.User = user
	}
	return u.String()
}
