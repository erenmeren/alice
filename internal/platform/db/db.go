// Package db opens the PostgreSQL pool, applies embedded migrations and reports health.
package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

var (
	// ErrUnreachable means the database cannot be reached.
	ErrUnreachable = errors.New("database is not reachable")
	// ErrMigrationsPending means the schema is older than this binary expects.
	ErrMigrationsPending = errors.New("database migrations are pending")
	// ErrAuthFailed means the server rejected the credentials; retrying cannot help.
	ErrAuthFailed = errors.New("the database rejected the user name or password")
	// ErrDatabaseMissing means the named database does not exist; retrying cannot help.
	ErrDatabaseMissing = errors.New("the database does not exist")
)

const (
	retryInterval = 500 * time.Millisecond

	// undefinedTable is the PostgreSQL SQLSTATE for a missing relation.
	undefinedTable = "42P01"
	// invalidPassword and invalidAuthorization are the SQLSTATEs for rejected credentials.
	invalidPassword      = "28P01"
	invalidAuthorization = "28000"
	// invalidCatalogName is the SQLSTATE for a database that does not exist.
	invalidCatalogName = "3D000"
)

// Open creates a pool and waits until the database answers a ping or ctx ends.
// Errors never include the connection string, because it contains the password.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("the database URL is not valid; check ALICE_DATABASE_URL")
	}
	cfg.MaxConns = 20
	where := fmt.Sprintf("%s:%d", cfg.ConnConfig.Host, cfg.ConnConfig.Port)

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not prepare the database connection to %s: %w", where, ErrUnreachable)
	}
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = pool.Ping(pingCtx)
		cancel()
		if err == nil {
			return pool, nil
		}
		if fatal := classify(err, where); fatal != nil {
			pool.Close()
			return nil, fatal
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, fmt.Errorf("could not connect to the database at %s: %w", where, ErrUnreachable)
		case <-time.After(retryInterval):
		}
	}
}

// classify turns errors that retrying cannot fix into a clear, final error.
// It returns nil for errors that may be transient (server starting, network).
// The driver message is never included: it could echo connection details.
func classify(err error, where string) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return nil
	}
	switch pgErr.Code {
	case invalidPassword, invalidAuthorization:
		return fmt.Errorf("the database server at %s rejected the user name or password; check the database URL: %w", where, ErrAuthFailed)
	case invalidCatalogName:
		return fmt.Errorf("the database named in the database URL does not exist on %s: %w", where, ErrDatabaseMissing)
	default:
		return nil
	}
}

// Migrate applies all pending migrations. A Postgres advisory lock serializes
// concurrent callers (for example two containers starting during an update).
func Migrate(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) error {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("create migration lock: %w", err)
	}
	p, err := newProvider(pool, fsys, goose.WithSessionLocker(locker))
	if err != nil {
		return err
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// HealthChecker reports whether the database is reachable and fully migrated.
type HealthChecker struct {
	pool     *pgxpool.Pool
	expected int64
}

// NewHealthChecker builds a checker for the given migrations.
func NewHealthChecker(pool *pgxpool.Pool, fsys fs.FS) (*HealthChecker, error) {
	p, err := newProvider(pool, fsys)
	if err != nil {
		return nil, err
	}
	var expected int64
	for _, s := range p.ListSources() {
		expected = max(expected, s.Version)
	}
	return &HealthChecker{pool: pool, expected: expected}, nil
}

const checkTimeout = 2 * time.Second

// Check returns nil, ErrUnreachable or ErrMigrationsPending. It only reads.
func (h *HealthChecker) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	if err := h.pool.Ping(ctx); err != nil {
		return ErrUnreachable
	}
	var applied int64
	err := h.pool.QueryRow(ctx,
		"SELECT coalesce(max(version_id), 0) FROM goose_db_version WHERE is_applied").Scan(&applied)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == undefinedTable {
			return ErrMigrationsPending
		}
		return ErrUnreachable
	}
	if applied < h.expected {
		return ErrMigrationsPending
	}
	return nil
}

func newProvider(pool *pgxpool.Pool, fsys fs.FS, opts ...goose.ProviderOption) (*goose.Provider, error) {
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(pool), fsys, opts...)
	if err != nil {
		return nil, fmt.Errorf("load migrations: %w", err)
	}
	return p, nil
}
