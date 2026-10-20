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
	// JobCertificateDeploy runs one deployment (payload deployment_id; dedupe
	// "certificate.deploy:<id>": one job per deployment).
	JobCertificateDeploy = "certificate.deploy"
	// JobCertificateDeployAuto runs one deployment the automatic planners (Key Vault, ACME) queued: the
	// certificate.deploy handler and dedupe key namespace, but continuity work (it runs in the continuity window
	// of a lock; owner decision 2026-10-20).
	JobCertificateDeployAuto = "certificate.deploy_auto"
	// JobACMERenew runs an order the renewal planner started for an issued ACME certificate: the acme.issue
	// handler and dedupe key (acme.issue:<acme certificate id>), but continuity work.
	JobACMERenew = "acme.renew"
	// JobDeployRecover finishes or undoes an interrupted deployment (payload deployment_id; dedupe
	// "certificate.deploy_recover:<id>": at most one live recovery per deployment).
	JobDeployRecover = "certificate.deploy_recover"
	// Phase 5 (Key Vault): the access check of a vault (payload read_secret_of, optional: a vault
	// certificate id whose current version's secret is read once to prove the role), the poll that
	// reads its inventory (dedupe "kv.poll:<id>") and the import of a certificate into it. The
	// runners arrive with Task 15; jobs registers the types so a request can be queued.
	JobKVTest   = "kv.test_connection"
	JobKVPoll   = "kv.poll"
	JobKVImport = "kv.import"
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
