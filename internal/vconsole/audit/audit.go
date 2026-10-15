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
