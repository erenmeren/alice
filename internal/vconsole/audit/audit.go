// Package audit is the Go side of the vendor console audit chain. The chain itself is computed by
// the database (audit_append, audit_verify in the first migration), so there is one definition of
// the hash and no client can write or forge an audit row.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

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

// ErrHeadMismatch means the checkpoint is not in the chain: rows were removed or replaced.
var ErrHeadMismatch = errors.New("audit: the checkpoint does not match the chain")

// Head is a checkpoint: the newest row's sequence number and hash at some time.
type Head struct {
	Seq  int64
	Hash string
}

// String is the form kept outside the database: "<seq>:<hash>".
func (h Head) String() string { return fmt.Sprintf("%d:%s", h.Seq, h.Hash) }

// ParseHead reads String's form. It accepts nothing but digits, ':' and 64 hex digits (upper case
// is normalised to lower case): the value comes from the paper log or a command line.
func ParseHead(s string) (Head, error) {
	seq, hash, ok := strings.Cut(s, ":")
	if !ok || len(seq) == 0 || len(seq) > 18 || len(hash) != 64 {
		return Head{}, errors.New("audit: head must be <seq>:<64 hex digits>")
	}
	for _, c := range seq {
		if c < '0' || c > '9' {
			return Head{}, errors.New("audit: head must be <seq>:<64 hex digits>")
		}
	}
	lower := make([]byte, len(hash)) // lower-cased by hand: the linter bans strings.ToLower
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			lower[i] = c
		case c >= 'A' && c <= 'F':
			lower[i] = c + ('a' - 'A')
		default:
			return Head{}, errors.New("audit: head must be <seq>:<64 hex digits>")
		}
	}
	n, err := strconv.ParseInt(seq, 10, 64)
	if err != nil || n < 1 {
		return Head{}, errors.New("audit: head sequence must be a positive number")
	}
	return Head{Seq: n, Hash: string(lower)}, nil
}

// CurrentHead returns the newest row's checkpoint; false when the chain is empty.
func CurrentHead(ctx context.Context, q Q) (Head, bool, error) {
	var h Head
	err := q.QueryRow(ctx, `SELECT seq, hash FROM audit_head()`).Scan(&h.Seq, &h.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Head{}, false, nil
	}
	if err != nil {
		return Head{}, false, fmt.Errorf("audit: head: %w", err)
	}
	return h, true, nil
}

// VerifyHead checks the whole chain (as Check does) and then that row h.Seq exists with hash
// h.Hash. A chain whose newest rows were deleted passes Check but fails here, once h was taken
// after those rows existed. It needs read access to the audit table (the owner).
func VerifyHead(ctx context.Context, q Q, h Head) error {
	if err := Check(ctx, q); err != nil {
		return err
	}
	var hash string
	err := q.QueryRow(ctx, `SELECT hash FROM audit WHERE seq = $1`, h.Seq).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: no row %d", ErrHeadMismatch, h.Seq)
	}
	if err != nil {
		return fmt.Errorf("audit: verify head: %w", err)
	}
	if hash != h.Hash {
		return fmt.Errorf("%w: row %d differs", ErrHeadMismatch, h.Seq)
	}
	return nil
}
