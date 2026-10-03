package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// Claim names the job run on whose behalf a deployment record is written: the job's id and the
// attempt number of this run (the queue increments it on every claim, so a run whose lease expired
// and whose job was taken back or claimed again no longer matches). The deploy engine puts it on
// the context of every write it makes (WithClaim); it travels with every context derived from that
// one, the detached ones included, so no write of the engine can leave it out.
//
// Every write of the engine-facing methods (BeginDeployment, StartDeployment,
// RecordDeploymentStep, FinishDeployment, MarkRecovering, RequestRecovery, RecordOutcome) checks
// the claim first in its own transaction: the job row must still be this run (status running,
// attempts = Attempt), read FOR SHARE so that the reaper cannot take the job back until the write
// committed. Otherwise nothing is written and the method returns ErrClaimLost: the run that holds
// the job now (or the sweep) owns the record. A context without a claim (the zero Claim) is not a
// job: the sweep, the API and tests write unfenced, as before.
type Claim struct {
	JobID   uuid.UUID
	Attempt int
}

// ErrClaimLost: the job run named by the context's Claim no longer holds its job (its lease
// expired and the job was taken back or claimed again). Nothing was written.
var ErrClaimLost = errors.New("inventory: the job run no longer holds its job; nothing was written")

type claimKey struct{}

// WithClaim returns ctx carrying c (see Claim).
func WithClaim(ctx context.Context, c Claim) context.Context {
	return context.WithValue(ctx, claimKey{}, c)
}

// ClaimFrom returns the claim on ctx (false without one).
func ClaimFrom(ctx context.Context) (Claim, bool) { return claimOf(ctx) }

func claimOf(ctx context.Context) (Claim, bool) {
	c, ok := ctx.Value(claimKey{}).(Claim)
	return c, ok && c.JobID != uuid.Nil
}

// checkClaim is the fence of an engine write (see Claim); nil without a claim.
func checkClaim(ctx context.Context, tx pgx.Tx) error {
	c, ok := claimOf(ctx)
	if !ok {
		return nil
	}
	var one int
	err := tx.QueryRow(ctx, "SELECT 1 FROM jobs WHERE id = $1 AND attempts = $2 AND status = 'running' FOR SHARE", c.JobID, c.Attempt).Scan(&one)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrClaimLost
	case err != nil:
		return fmt.Errorf("inventory: check the job's claim: %w", err)
	}
	return nil
}

// CheckClaim reports whether the context's job run still holds its job (ErrClaimLost when not; nil
// without a claim). The engine calls it right before it sends a command that changes a server
// (DeployCertificate, RollbackDeployment), so a run that lost its lease does not change the server
// behind the back of the run that holds the job now. The check and the command are not atomic:
// the lease can still end in the instant between them.
func (s *Service) CheckClaim(ctx context.Context) error {
	if _, ok := claimOf(ctx); !ok {
		return nil
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error { return checkClaim(ctx, tx) })
}
