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
)

const (
	retryInterval = 500 * time.Millisecond

	// undefinedTable is the PostgreSQL SQLSTATE for a missing relation.
	undefinedTable = "42P01"
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
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, fmt.Errorf("could not connect to the database at %s: %w", where, ErrUnreachable)
		case <-time.After(retryInterval):
		}
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

// Check returns nil, ErrUnreachable or ErrMigrationsPending. It only reads.
func (h *HealthChecker) Check(ctx context.Context) error {
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
