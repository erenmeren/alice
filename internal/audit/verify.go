package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// Problems reported by Verify.
const (
	ProblemHashMismatch  = "hash_mismatch"
	ProblemSequenceGap   = "sequence_gap"
	ProblemTailTruncated = "tail_truncated"
)

// checkpointKey is the settings key holding the last verified chain head.
const checkpointKey = "audit.checkpoint"

// Report is the result of a chain verification.
type Report struct {
	Intact      bool
	Checked     int64
	HeadSeq     int64
	HeadHash    []byte
	FirstBadSeq int64  // 0 when intact
	Problem     string // "" when intact
}

type checkpoint struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
	At   string `json:"at"`
}

// Verify recomputes the whole chain from seq 1 and compares the head with the
// stored checkpoint, so deleting the newest rows is detected too (F-92).
func Verify(ctx context.Context, q db.Querier) (Report, error) {
	var cp checkpoint
	hasCP, err := settings.Get(ctx, q, checkpointKey, &cp)
	if err != nil {
		return Report{}, fmt.Errorf("audit: read checkpoint: %w", err)
	}
	rep := Report{Intact: true}
	prev := make([]byte, sha256.Size)
	errStop := errors.New("stop")
	err = Iterate(ctx, q, func(e Entry) error {
		expected := rep.HeadSeq + 1
		if e.Seq != expected {
			rep.fail(expected, ProblemSequenceGap)
			return errStop
		}
		if !bytes.Equal(e.PrevHash, prev) || !bytes.Equal(ComputeHash(prev, e), e.Hash) {
			rep.fail(e.Seq, ProblemHashMismatch)
			return errStop
		}
		if hasCP && e.Seq == cp.Seq && hex.EncodeToString(e.Hash) != cp.Hash {
			rep.fail(e.Seq, ProblemHashMismatch)
			return errStop
		}
		rep.Checked++
		rep.HeadSeq, rep.HeadHash, prev = e.Seq, e.Hash, e.Hash
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return Report{}, err
	}
	if rep.Intact && hasCP && cp.Seq > rep.HeadSeq {
		rep.fail(rep.HeadSeq+1, ProblemTailTruncated)
	}
	return rep, nil
}

func (r *Report) fail(seq int64, problem string) {
	r.Intact, r.FirstBadSeq, r.Problem = false, seq, problem
}

// Service binds the log to a pool for callers outside a transaction (the API and CLI).
type Service struct {
	log  *Log
	pool *pgxpool.Pool
}

// NewService returns a Service.
func NewService(l *Log, pool *pgxpool.Pool) *Service { return &Service{log: l, pool: pool} }

// Write appends e in its own transaction.
func (s *Service) Write(ctx context.Context, e Event) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.log.Append(ctx, tx, e)
		return err
	})
}

// List pages entries newest first.
func (s *Service) List(ctx context.Context, f Filter) ([]Entry, int64, error) {
	return List(ctx, s.pool, f)
}

// Iterate streams entries in ascending order.
func (s *Service) Iterate(ctx context.Context, fn func(Entry) error) error {
	return Iterate(ctx, s.pool, fn)
}

// Verify checks the chain, stores a new checkpoint when it is intact, and
// records "audit.verified" (success, or failure with the problem).
func (s *Service) Verify(ctx context.Context, actor Actor) (Report, error) {
	rep, err := Verify(ctx, s.pool)
	if err != nil {
		return Report{}, err
	}
	ev := Event{Actor: actor, Action: "audit.verified", ObjectType: "audit_log", Result: Success,
		Details: map[string]string{"checked": strconv.FormatInt(rep.Checked, 10), "head_seq": strconv.FormatInt(rep.HeadSeq, 10)}}
	if !rep.Intact {
		ev.Result = Failure
		ev.Details["problem"] = rep.Problem
		ev.Details["first_bad_seq"] = strconv.FormatInt(rep.FirstBadSeq, 10)
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if rep.Intact && rep.HeadSeq > 0 {
			cp := checkpoint{Seq: rep.HeadSeq, Hash: hex.EncodeToString(rep.HeadHash),
				At: s.log.clock.Now().UTC().Format(time.RFC3339)}
			if err := settings.Set(ctx, tx, checkpointKey, cp, s.log.clock.Now()); err != nil {
				return fmt.Errorf("audit: store checkpoint: %w", err)
			}
		}
		_, err := s.log.Append(ctx, tx, ev)
		return err
	})
	return rep, err
}
