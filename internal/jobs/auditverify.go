package jobs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// AuditVerifier verifies the audit chain and records audit.verified; *audit.Service.
type AuditVerifier interface {
	Verify(ctx context.Context, actor audit.Actor) (audit.Report, error)
}

// AuditVerifyConfig holds the dependencies of the periodic audit.verify task.
type AuditVerifyConfig struct {
	Pool     *pgxpool.Pool
	Verifier AuditVerifier
	Notifier AdminNotifier // emails the Administrators about a broken chain (platform); nil = no email
	Clock    clock.Clock
}

// TemplateAuditBroken is the email sent when the daily verification finds the audit chain
// broken. Its params are those of auditBrokenParams.
const TemplateAuditBroken = "audit.broken"

// ErrAuditChainBroken is returned by the audit.verify task when the chain does not verify;
// the scheduler logs it at Error level.
var ErrAuditChainBroken = errors.New("jobs: the audit chain is broken")

const (
	// auditVerifyTick is how often the task looks whether a verification is due. Ticking
	// hourly and remembering the last verification in the database means a restart or a new
	// leader never skips a day, which a 24-hour ticker would.
	auditVerifyTick = time.Hour
	// auditVerifyDue is the age of the last intact verification after which the next tick
	// verifies again: daily, with an hour of slack for the tick.
	auditVerifyDue = 23 * time.Hour
	// auditVerifyStateKey is the settings key of AuditVerifyState.
	auditVerifyStateKey = "jobs.audit_verify"
	// auditVerifyLock serializes the state update of two processes (a RunNow next to a tick),
	// next to the audit (…300), passphrase (…301), target-limit (…302) and leader (…303) keys.
	auditVerifyLock int64 = 7160927315633811304
)

// AuditVerifyState is what the task remembers between runs and restarts.
type AuditVerifyState struct {
	LastIntactAt   time.Time `json:"last_intact_at"`  // the last verification that found the chain intact
	LastBrokenAt   time.Time `json:"last_broken_at"`  // the last verification that found it broken
	AlertedBadSeq  int64     `json:"alerted_bad_seq"` // first_bad_seq of the last announced break; 0 = none
	AlertedProblem string    `json:"alerted_problem"` // its problem
}

// ReadAuditVerifyState reads what the daily verification remembers (the dashboard's integrity status, R42 row 27).
// The zero value means it never ran.
func ReadAuditVerifyState(ctx context.Context, q db.Querier) (AuditVerifyState, error) {
	var st AuditVerifyState
	if _, err := settings.Get(ctx, q, auditVerifyStateKey, &st); err != nil {
		return AuditVerifyState{}, fmt.Errorf("jobs: read the audit verify state: %w", err)
	}
	return st, nil
}

func auditBrokenParams(rep audit.Report) map[string]string {
	return map[string]string{"first_bad_seq": strconv.FormatInt(rep.FirstBadSeq, 10), "problem": rep.Problem}
}

// AuditVerifyTask is the periodic audit.verify task (spec §8.2, R37 item 15). It ticks hourly
// and verifies the chain when the last intact verification is at least 23 hours old; a broken
// chain is verified again on every tick until it is repaired. A broken chain makes the run
// fail with ErrAuditChainBroken and queues one audit.broken email per break: when no break is
// announced yet, when the new one lies further back, or when its problem changes.
//
// The email is queued in the transaction that records the alert state (AuditVerifyState), not
// in the one that writes the audit.verified row (audit.Service.Verify commits that first). A
// crash between the two only delays the email to the next tick, which verifies again because
// the state still shows no intact verification.
func AuditVerifyTask(c AuditVerifyConfig) Task {
	return Task{Type: AuditVerify, Every: auditVerifyTick, Run: func(ctx context.Context) error {
		return runAuditVerify(ctx, c)
	}}
}

func runAuditVerify(ctx context.Context, c AuditVerifyConfig) error {
	var st AuditVerifyState
	if _, err := settings.Get(ctx, c.Pool, auditVerifyStateKey, &st); err != nil {
		return fmt.Errorf("jobs: read the audit verification state: %w", err)
	}
	now := c.Clock.Now().UTC()
	// A last intact verification in the future (a clock set back, an edited row) is due.
	if !st.LastIntactAt.IsZero() && st.LastBrokenAt.Before(st.LastIntactAt) && !now.Before(st.LastIntactAt) &&
		now.Sub(st.LastIntactAt) < auditVerifyDue {
		return nil // verified within the day
	}
	rep, err := c.Verifier.Verify(ctx, audit.SystemActor("scheduler"))
	if err != nil {
		return err
	}
	err = db.InTx(ctx, c.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditVerifyLock); err != nil {
			return fmt.Errorf("jobs: lock the audit verification state: %w", err)
		}
		var st AuditVerifyState
		if _, err := settings.Get(ctx, tx, auditVerifyStateKey, &st); err != nil {
			return fmt.Errorf("jobs: read the audit verification state: %w", err)
		}
		if rep.Intact {
			st.LastIntactAt = now
			st.AlertedBadSeq, st.AlertedProblem = 0, ""
		} else {
			st.LastBrokenAt = now
			// A truncated tail is reported at head+1, and every failing run appends an
			// audit.verified row, so the same break moves forward on each run: announce a break
			// only when none is announced yet, when it lies further back, or when its problem
			// changes.
			if st.AlertedBadSeq == 0 || rep.FirstBadSeq < st.AlertedBadSeq || rep.Problem != st.AlertedProblem {
				if c.Notifier != nil {
					if err := c.Notifier.NotifyAdmins(ctx, tx, TemplateAuditBroken, auditBrokenParams(rep)); err != nil {
						return fmt.Errorf("jobs: queue the audit.broken email: %w", err)
					}
				}
				st.AlertedBadSeq, st.AlertedProblem = rep.FirstBadSeq, rep.Problem
			}
		}
		return settings.Set(ctx, tx, auditVerifyStateKey, st, now)
	})
	if err != nil {
		return err
	}
	if !rep.Intact {
		return fmt.Errorf("%w: %s at entry %d", ErrAuditChainBroken, rep.Problem, rep.FirstBadSeq)
	}
	return nil
}
