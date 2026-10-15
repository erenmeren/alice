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
	const form = "audit: head must be <seq>:<64 hex digits>"
	seq, hash, ok := strings.Cut(s, ":")
	if !ok || len(hash) != 64 {
		return Head{}, errors.New(form)
	}
	n, err := parseSeq(seq, form)
	if err != nil {
		return Head{}, err
	}
	lower, ok := lowerHex(hash)
	if !ok {
		return Head{}, errors.New(form)
	}
	return Head{Seq: n, Hash: lower}, nil
}

// Prefix lengths ParseHeadPrefix accepts: fewer than 16 hex digits (64 bits) would make a forged
// row too cheap to find; 64 digits are a whole Head.
const (
	minPrefixHex = 16
	maxPrefixHex = 63
)

// HeadPrefix is a checkpoint copied by hand with only the start of the hash: the sequence number
// and the first 16 to 63 hex digits. It is a weaker check than a Head (forging a row whose hash
// starts the same takes about 2^(4*len) work instead of 2^256), kept because the owner copies the
// head on paper every week.
type HeadPrefix struct {
	Seq    int64
	Prefix string
}

// String is "<seq>:<prefix>".
func (p HeadPrefix) String() string { return fmt.Sprintf("%d:%s", p.Seq, p.Prefix) }

// ParseHeadPrefix reads "<seq>:<hex>" with 16 to 63 hex digits (upper case is normalised to
// lower case). The sequence follows ParseHead's rules. A full 64-digit hash is refused: use
// ParseHead for it.
func ParseHeadPrefix(s string) (HeadPrefix, error) {
	const form = "audit: head prefix must be <seq>:<at least 16 hex digits>"
	seq, hash, ok := strings.Cut(s, ":")
	if !ok {
		return HeadPrefix{}, errors.New(form)
	}
	if len(hash) < minPrefixHex {
		return HeadPrefix{}, fmt.Errorf("audit: head prefix needs at least %d hex digits, got %d", minPrefixHex, len(hash))
	}
	if len(hash) > maxPrefixHex {
		return HeadPrefix{}, errors.New("audit: head prefix must be shorter than 64 hex digits (a full hash is a head)")
	}
	n, err := parseSeq(seq, form)
	if err != nil {
		return HeadPrefix{}, err
	}
	lower, ok := lowerHex(hash)
	if !ok {
		return HeadPrefix{}, errors.New(form)
	}
	return HeadPrefix{Seq: n, Prefix: lower}, nil
}

// parseSeq reads a checkpoint's sequence number: 1 to 18 decimal digits, at least 1 (leading
// zeros allowed). form is the error for anything but digits.
func parseSeq(seq, form string) (int64, error) {
	if len(seq) == 0 || len(seq) > 18 {
		return 0, errors.New(form)
	}
	for _, c := range seq {
		if c < '0' || c > '9' {
			return 0, errors.New(form)
		}
	}
	n, err := strconv.ParseInt(seq, 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New("audit: head sequence must be a positive number")
	}
	return n, nil
}

// lowerHex returns s lower-cased when it is hex digits only (by hand: the linter bans
// strings.ToLower).
func lowerHex(s string) (string, bool) {
	lower := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			lower[i] = c
		case c >= 'A' && c <= 'F':
			lower[i] = c + ('a' - 'A')
		default:
			return "", false
		}
	}
	return string(lower), true
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

// VerifyHeadPrefix is VerifyHead for a checkpoint copied with only the start of the hash: the
// whole chain must verify, and row p.Seq must exist with a hash that starts with p.Prefix.
func VerifyHeadPrefix(ctx context.Context, q Q, p HeadPrefix) error {
	if err := Check(ctx, q); err != nil {
		return err
	}
	var hash string
	err := q.QueryRow(ctx, `SELECT hash FROM audit WHERE seq = $1`, p.Seq).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: no row %d", ErrHeadMismatch, p.Seq)
	}
	if err != nil {
		return fmt.Errorf("audit: verify head: %w", err)
	}
	if !strings.HasPrefix(hash, p.Prefix) {
		return fmt.Errorf("%w: row %d differs", ErrHeadMismatch, p.Seq)
	}
	return nil
}
