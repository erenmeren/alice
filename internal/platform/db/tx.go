package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rollbackTimeout bounds InTx's rollback. It runs on a context that the caller's cancellation does not end (a
// cancelled request still rolls back), so without a bound a connection that no longer answers would hold the caller
// until the TCP timeout (review L-15). A rollback that times out closes the connection, and PostgreSQL rolls back
// the transaction of a session that ends.
var rollbackTimeout = 5 * time.Second

// uniqueViolation is the PostgreSQL SQLSTATE for a duplicate key.
const uniqueViolation = "23505"

// Querier is satisfied by *pgxpool.Pool, *pgxpool.Conn and pgx.Tx, so query
// helpers work both inside and outside a transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var (
	_ Querier = (*pgxpool.Pool)(nil)
	_ Querier = (*pgxpool.Conn)(nil)
	_ Querier = (pgx.Tx)(nil)
)

// InTx runs fn in a read-committed transaction. It commits when fn returns nil
// and rolls back when fn returns an error or panics (the panic is re-raised).
func InTx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) (err error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer func() {
		p := recover()
		if !committed {
			// Covers errors, panics and runtime.Goexit (t.FailNow inside fn).
			rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
			_ = tx.Rollback(rbCtx)
			cancel()
		}
		if p != nil {
			panic(p)
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true
	return nil
}

// IsUniqueViolation reports whether err is a PostgreSQL unique-constraint violation.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation
}
