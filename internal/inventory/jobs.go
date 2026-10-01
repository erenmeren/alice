package inventory

// This file holds what the job queue needs from inventory: job types, JobRequest and Enqueuer.

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Job types that inventory starts (spec §8.2). jobs registers them with their license class.
const (
	JobTestConnection = "target.test_connection"
	JobDiscover       = "target.discover"
	JobSSHKeyRemove   = "sshkey.remove"
)

// JobRequest asks for one job. Payload holds ids and options only, never secrets.
type JobRequest struct {
	Type          string
	TargetID      uuid.UUID // uuid.Nil = none
	Payload       map[string]string
	Kind          string // "user" | "scheduled" | "system"
	CreatedBy     uuid.UUID
	CreatedByRole string
	DedupeKey     string
}

// Enqueuer is jobs.Queue: the job row is written in the caller's transaction, so a target and
// its first job commit or roll back together.
type Enqueuer interface {
	EnqueueTx(ctx context.Context, tx pgx.Tx, r JobRequest) (uuid.UUID, error)
}
