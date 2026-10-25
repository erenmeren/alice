package inventory

// The canary's decisions (R65, design §9, §11, §14, §15, §20.3): the periodic task canary.advance (ClassAlways) runs
// AdvanceRollouts, which takes every rollout that is unfinished or still has a holding deployment, one transaction each
// (the rollout row locked FOR UPDATE SKIP LOCKED first, then each location and deployment in FinishDeployment's order),
// reads a snapshot, decides purely (decideRollout) and applies the plan: releases, reverts, ends of queued wave-1
// deployments, the state change with its audit rows, wave 2 (a person's rollout, through the gate), the stop marks of an
// automatic source (Task 7), and the canary.check jobs of the rounds that are due.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
)

// Bounds of the advance (design §14, §18).
const (
	// CanaryWave1Limit is how long a rollout may stay in wave 1 while a wave-1 website has no deployment yet (an
	// automatic rollout's planner creates them over several runs) before it fails (final review C1).
	CanaryWave1Limit = time.Hour
	// CanaryGateWait is how long a person's rollout waits for a transient licence answer before it stops (decision 16).
	CanaryGateWait = time.Hour
	// rolloutBatch bounds the rollouts one advance handles.
	rolloutBatch = 100
	// canaryMinGrace is the floor of the grace after the hold (decision 11).
	canaryMinGrace = 5 * time.Minute
	// JobCanaryCheck is the job type of one observation round of one holding deployment (jobs registers it).
	JobCanaryCheck = "canary.check"
	// JobCanaryAdvance is the periodic task that decides every rollout (jobs registers it).
	JobCanaryAdvance = "canary.advance"
	// canaryCheckDedupePrefix + deployment id is the dedupe key of a round.
	canaryCheckDedupePrefix = JobCanaryCheck + ":"
)

// The rollout reasons (UI texts, design §17.2).
const (
	RolloutReasonCheckFailed      = "canary.check_failed"
	RolloutReasonCheckUnavailable = "canary.check_unavailable"
	RolloutReasonWave1Failed      = "canary.wave1_failed"
	RolloutReasonRevoked          = "canary.certificate_revoked"
	RolloutReasonAborted          = "canary.aborted"
	RolloutReasonWaveGone         = "canary.wave_gone"
	RolloutReasonWave1Incomplete  = "canary.wave1_incomplete"
	RolloutReasonPreempted        = "canary.preempted_by_incident"
	RolloutReasonLicenseLocked    = "license.locked"
)

// canaryGrace is how long after hold_until a rollout waits for a pass before it fails closed: max(2 x interval, 5 min).
func canaryGrace(interval time.Duration) time.Duration {
	return max(2*interval, canaryMinGrace)
}

// canaryCheck is a holding deployment's latest observation (canary_checks).
type canaryCheck struct {
	rounds, passes, consecutiveFailures int
	nextCheckAt                         time.Time
	lastAt, lastPassAt                  *time.Time
	lastResult, lastReason, lastTLS     string
	lastHTTPStatus, lastLatencyMS       *int
}

// rolloutDeployment is one deployment of a rollout as the decision reads it.
type rolloutDeployment struct {
	id, location, target     uuid.UUID
	wave                     int
	state, status, errorCode string
	targetDeleted            bool
	check                    *canaryCheck // nil when it never held
}

// gone reports whether the deployment's location left the rollout: its server was deleted.
func (d rolloutDeployment) gone() bool {
	return d.targetDeleted || (d.state == DeployStateDone && d.errorCode == "deployment.target_deleted")
}

// rolloutSnapshot is what decideRollout decides from.
type rolloutSnapshot struct {
	r           Rollout
	now         time.Time
	deployments []rolloutDeployment
	// certificateForbidden: the deployed certificate is revoked or its key compromised.
	certificateForbidden bool
	// earliestWave2NotAfter is the earliest not_after of the certificates wave 2's websites hold now (nil: none known).
	earliestWave2NotAfter *time.Time
}

// rolloutPlan is what an advance does to one rollout.
type rolloutPlan struct {
	next, reason string
	reasonParams map[string]string
	release      map[uuid.UUID]string // deployment -> hold cause
	revert       map[uuid.UUID]string // deployment -> revert reason
	endQueued    map[uuid.UUID]string // deployment -> failure reason (never sent)
	queueRounds  []uuid.UUID
	holdStart    bool
	insertWave2  bool // a person's rollout releases wave 1 and deploys wave 2 (through the gate)
	checkFailed  bool // the deciding round is audited (deployment.rollout_check_failed)
}

// revertReasonFor is the error code of a wave-1 deployment reverted (or ended unsent) for a rollout reason.
func revertReasonFor(rolloutReason string) string {
	switch rolloutReason {
	case RolloutReasonCheckFailed:
		return ReasonCanaryCheckFailed
	case RolloutReasonAborted:
		return ReasonCanaryAborted
	}
	return ReasonCanaryWaveFailed
}

// waveFailedCause is params.cause of ALC-DEP-0033 for a rollout reason.
func waveFailedCause(rolloutReason string) string {
	switch rolloutReason {
	case RolloutReasonWave1Failed:
		return "deployment_failed"
	case RolloutReasonCheckUnavailable:
		return "check_unavailable"
	case RolloutReasonRevoked:
		return "certificate_revoked"
	case RolloutReasonWaveGone:
		return "wave_gone"
	case RolloutReasonWave1Incomplete:
		return "wave1_incomplete"
	}
	return ""
}

func finalRolloutState(state string) bool {
	switch state {
	case RolloutCompleted, RolloutFailed, RolloutAborted, RolloutStopped, RolloutPreempted:
		return true
	}
	return false
}

// decideRollout decides one advance of one rollout (design §9.1, §11), purely. See the table in canary_advance_test.go.
func decideRollout(sn rolloutSnapshot) rolloutPlan {
	r := sn.r
	p := rolloutPlan{next: r.State, reasonParams: map[string]string{}, release: map[uuid.UUID]string{}, revert: map[uuid.UUID]string{},
		endQueued: map[uuid.UUID]string{}}
	var wave1, wave2 []rolloutDeployment
	for _, d := range sn.deployments {
		if d.wave == 1 {
			wave1 = append(wave1, d)
		} else {
			wave2 = append(wave2, d)
		}
	}
	releaseCause := func(d rolloutDeployment) string {
		if d.targetDeleted {
			return HoldCauseTargetDeleted
		}
		return HoldCauseRelease
	}
	switch r.State {
	case RolloutFailed, RolloutAborted:
		// A hold that arrived after the verdict (it was still sending) is reverted; a wave-1 deployment that never
		// sent ends.
		reason := revertReasonFor(r.Reason)
		if r.State == RolloutAborted {
			reason = ReasonCanaryAborted
		}
		for _, d := range wave1 {
			switch d.state {
			case DeployStateHolding:
				p.revert[d.id] = reason
			case DeployStateQueued, DeployStatePrecheck:
				p.endQueued[d.id] = reason
			}
		}
		return p
	case RolloutCompleted, RolloutStopped, RolloutPreempted:
		for _, d := range wave1 {
			if d.state == DeployStateHolding {
				p.release[d.id] = releaseCause(d)
			}
		}
		return p
	case RolloutWave2:
		for _, d := range wave2 {
			if d.state != DeployStateDone {
				return p
			}
		}
		p.next = RolloutCompleted
		return p
	}

	// wave1 and hold.
	byLocation := map[uuid.UUID]rolloutDeployment{}
	for _, d := range wave1 {
		byLocation[d.location] = d
		if d.state == DeployStateHolding && d.targetDeleted {
			p.release[d.id] = HoldCauseTargetDeleted // verified: the row stays truthful; the location leaves wave 1
		}
	}
	fail := func(reason string, params map[string]string) rolloutPlan {
		p.next, p.reason = RolloutFailed, reason
		for k, v := range params {
			p.reasonParams[k] = v
		}
		if c := waveFailedCause(reason); c != "" {
			p.reasonParams["cause"] = c
		}
		dep := revertReasonFor(reason)
		for _, d := range wave1 {
			if d.gone() {
				continue
			}
			switch d.state {
			case DeployStateHolding:
				p.revert[d.id] = dep
			case DeployStateQueued, DeployStatePrecheck:
				p.endQueued[d.id] = dep
			}
		}
		p.queueRounds = nil
		return p
	}
	if sn.certificateForbidden {
		return fail(RolloutReasonRevoked, nil)
	}
	var live []rolloutDeployment
	settled := true // every live wave-1 location has a deployment that holds or ended as a success
	missing := false
	for _, loc := range r.Wave1 {
		d, ok := byLocation[loc]
		if !ok {
			settled, missing = false, true
			continue
		}
		if d.gone() {
			continue
		}
		live = append(live, d)
		switch {
		case d.state == DeployStateDone && (d.status == DeployStatusFailed || d.status == DeployStatusRolledBack ||
			d.status == DeployStatusRollbackFailed):
			return fail(RolloutReasonWave1Failed, map[string]string{"location_id": d.location.String()})
		case d.state == DeployStateHolding, d.state == DeployStateDone:
		default:
			settled = false
		}
	}
	if len(live) == 0 && settled {
		return fail(RolloutReasonWaveGone, nil)
	}
	for _, d := range live {
		if d.state == DeployStateHolding && d.check != nil && d.check.consecutiveFailures >= r.Settings.Failures {
			p.checkFailed = true
			params := map[string]string{"location_id": d.location.String(), "reason": d.check.lastReason}
			if d.check.lastHTTPStatus != nil {
				params["http_status"] = strconv.Itoa(*d.check.lastHTTPStatus)
			}
			if params["reason"] == "" {
				delete(params, "reason")
			}
			return fail(RolloutReasonCheckFailed, params)
		}
	}
	if r.State == RolloutWave1 && missing && !sn.now.Before(r.CreatedAt.Add(CanaryWave1Limit)) {
		// Final review C1: a wave-1 website that never got a deployment (a planner stopped offering it, or its budget
		// ran out) must not keep the others holding forever.
		return fail(RolloutReasonWave1Incomplete, nil)
	}
	holdStarted, holdUntil := r.HoldStartedAt, r.HoldUntil
	if r.State == RolloutWave1 && settled {
		p.next, p.holdStart = RolloutHold, true
		start, until := sn.now, sn.now.Add(r.Settings.Hold)
		holdStarted, holdUntil = &start, &until
	}
	if p.next == RolloutHold && holdUntil != nil && sn.now.Before(*holdUntil) && sn.earliestWave2NotAfter != nil &&
		sn.earliestWave2NotAfter.Before(holdUntil.Add(CanaryExpiryMargin)) {
		// Design §15: the expiry guard held at creation; a clock jump made it false. Release early rather than let a
		// wave-2 certificate expire while the hold waits.
		for _, d := range live {
			if d.state == DeployStateHolding {
				p.release[d.id] = HoldCauseRelease
			}
		}
		p.reasonParams["early"] = CanarySkipExpiry
		if r.Origin == RolloutOriginManual {
			p.next, p.insertWave2 = RolloutWave2, true
		} else {
			p.next = RolloutCompleted
		}
		return p
	}
	if p.next == RolloutHold && holdUntil != nil && !sn.now.Before(*holdUntil) {
		passed := true
		for _, d := range live {
			if d.state != DeployStateHolding {
				continue
			}
			c := d.check
			if c == nil || c.lastResult != "pass" || c.lastAt == nil || c.lastAt.Before(*holdStarted) {
				passed = false
				break
			}
		}
		switch {
		case passed:
			for _, d := range live {
				if d.state == DeployStateHolding {
					p.release[d.id] = HoldCauseRelease
				}
			}
			if r.Origin == RolloutOriginManual {
				p.next, p.insertWave2 = RolloutWave2, true
			} else {
				p.next = RolloutCompleted
			}
			return p
		case !sn.now.Before(holdUntil.Add(canaryGrace(r.Settings.Interval))):
			return fail(RolloutReasonCheckUnavailable, nil)
		}
	}
	for _, d := range live {
		if d.state == DeployStateHolding && d.check != nil && !d.check.nextCheckAt.After(sn.now) {
			p.queueRounds = append(p.queueRounds, d.id)
		}
	}
	return p
}

// AdvanceRollouts runs one advance of every rollout that is unfinished or still has a holding deployment (at most
// rolloutBatch, oldest first), each in its own transaction; a rollout another process holds is skipped. It answers how
// many rollouts changed state; one rollout's error is logged and does not stop the others.
func (s *Service) AdvanceRollouts(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM (
    SELECT id, created_at FROM deployment_rollouts WHERE finished_at IS NULL
    UNION
    SELECT r.id, r.created_at FROM deployment_rollouts r JOIN deployments d ON d.rollout_id = r.id AND d.state IN ('holding', 'queued', 'precheck')
    WHERE r.finished_at IS NOT NULL AND d.wave = 1
) x ORDER BY created_at, id LIMIT $1`, rolloutBatch)
	if err != nil {
		return 0, fmt.Errorf("inventory: find the rollouts to advance: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, fmt.Errorf("inventory: find the rollouts to advance: %w", err)
	}
	changed, failed := 0, 0
	for _, id := range ids {
		moved, err := s.advanceRollout(ctx, id)
		if err != nil {
			failed++
			s.log.Error("could not advance a canary rollout", "rollout_id", id.String(), "error_type", fmt.Sprintf("%T", err))
			continue
		}
		if moved {
			changed++
		}
	}
	if failed > 0 {
		return changed, fmt.Errorf("inventory: %d canary rollouts could not be advanced", failed)
	}
	return changed, nil
}

// lockRollout reads a rollout under its row lock; skip: FOR UPDATE SKIP LOCKED (pgx.ErrNoRows when another holds it).
func lockRollout(ctx context.Context, tx pgx.Tx, id uuid.UUID, skip bool) (Rollout, error) {
	q := "SELECT " + rolloutColumns + " FROM deployment_rollouts WHERE id = $1 FOR UPDATE"
	if skip {
		q += " SKIP LOCKED"
	}
	return scanRollout(tx.QueryRow(ctx, q, id))
}

// readRolloutSnapshot reads what decideRollout needs, in tx, after the rollout's lock.
func readRolloutSnapshot(ctx context.Context, tx pgx.Tx, r Rollout, now time.Time) (rolloutSnapshot, error) {
	sn := rolloutSnapshot{r: r, now: now}
	rows, err := tx.Query(ctx, `SELECT d.id, d.location_id, d.target_id, d.wave, d.state, d.status, d.error_code, t.deleted_at IS NOT NULL,
    c.deployment_id IS NOT NULL, coalesce(c.rounds, 0), coalesce(c.passes, 0), coalesce(c.consecutive_failures, 0), c.next_check_at, c.last_at,
    c.last_pass_at, coalesce(c.last_result, ''), coalesce(c.last_reason, ''), coalesce(c.last_tls, ''), c.last_http_status, c.last_latency_ms
FROM deployments d JOIN targets t ON t.id = d.target_id LEFT JOIN canary_checks c ON c.deployment_id = d.id
WHERE d.rollout_id = $1 ORDER BY d.wave, d.created_at, d.id`, r.ID)
	if err != nil {
		return sn, fmt.Errorf("inventory: read the rollout's deployments: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			d        rolloutDeployment
			c        canaryCheck
			hasCheck bool
			next     *time.Time
		)
		if err := rows.Scan(&d.id, &d.location, &d.target, &d.wave, &d.state, &d.status, &d.errorCode, &d.targetDeleted, &hasCheck, &c.rounds,
			&c.passes, &c.consecutiveFailures, &next, &c.lastAt, &c.lastPassAt, &c.lastResult, &c.lastReason, &c.lastTLS, &c.lastHTTPStatus,
			&c.lastLatencyMS); err != nil {
			return sn, fmt.Errorf("inventory: read the rollout's deployments: %w", err)
		}
		if hasCheck {
			if next != nil {
				c.nextCheckAt = *next
			}
			d.check = &c
		}
		sn.deployments = append(sn.deployments, d)
	}
	if err := rows.Err(); err != nil {
		return sn, fmt.Errorf("inventory: read the rollout's deployments: %w", err)
	}
	err = tx.QueryRow(ctx, "SELECT revoked_at IS NOT NULL OR compromised_at IS NOT NULL FROM certificates WHERE id = $1", r.CertificateID).
		Scan(&sn.certificateForbidden)
	if err != nil {
		return sn, fmt.Errorf("inventory: read the rollout's certificate: %w", err)
	}
	current, err := currentNotAfter(ctx, tx, r.Wave2)
	if err != nil {
		return sn, err
	}
	if _, at, ok := earliestExpiry(r.Wave2, current); ok {
		sn.earliestWave2NotAfter = &at
	}
	return sn, nil
}

// advanceRollout runs one advance of one rollout in its own transaction; it answers whether the state changed.
func (s *Service) advanceRollout(ctx context.Context, id uuid.UUID) (bool, error) {
	moved := false
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		moved = false
		r, err := lockRollout(ctx, tx, id, true)
		if errors.Is(err, ErrRolloutNotFound) {
			return nil // another process holds it (or it is gone)
		}
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		sn, err := readRolloutSnapshot(ctx, tx, r, now)
		if err != nil {
			return err
		}
		plan := decideRollout(sn)
		moved, err = s.applyRolloutPlan(ctx, tx, r, sn, plan, jobsActor, false)
		return err
	})
	return moved, err
}

// applyRolloutPlan applies a plan to the locked rollout r in tx (see AdvanceRollouts); early marks a person's continue.
// It answers whether the state changed.
func (s *Service) applyRolloutPlan(ctx context.Context, tx pgx.Tx, r Rollout, sn rolloutSnapshot, plan rolloutPlan, actor audit.Actor,
	early bool) (bool, error) {
	now := sn.now
	if plan.insertWave2 {
		// A person's rollout: wave 2 is a change the licence must allow now (design §14).
		gate := s.license.Allow(license.ClassChange)
		switch {
		case gate == nil:
		case license.ConfirmedLock(gate):
			plan.insertWave2, plan.next, plan.reason = false, RolloutStopped, RolloutReasonLicenseLocked
		case license.DenialReason(gate) != "":
			if r.GateWaitingSince == nil {
				if _, err := tx.Exec(ctx, "UPDATE deployment_rollouts SET gate_waiting_since = $2, version = version + 1 WHERE id = $1", r.ID, now); err != nil {
					return false, fmt.Errorf("inventory: record the licence wait: %w", err)
				}
				return false, s.queueRounds(ctx, tx, sn, holdingIDs(sn))
			}
			if now.Sub(*r.GateWaitingSince) < CanaryGateWait {
				return false, s.queueRounds(ctx, tx, sn, holdingIDs(sn))
			}
			plan.insertWave2, plan.next, plan.reason = false, RolloutStopped, license.DenialReason(gate)
		default:
			return false, gate
		}
	}
	if plan.insertWave2 {
		// Final review minor (a): a person's deploy locks servers, then websites; the release below locks wave-1 websites
		// and insertWave2 then wave-2 servers. Locking every server of the rollout first keeps one order for both.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM targets WHERE id IN (SELECT target_id FROM certificate_locations WHERE id = ANY($1))
ORDER BY id FOR NO KEY UPDATE`, append(slices.Clone(r.Wave1), r.Wave2...)); err != nil {
			return false, fmt.Errorf("inventory: lock the rollout's servers: %w", err)
		}
	}
	for _, id := range sortedKeys(plan.release) {
		err := s.ReleaseHold(ctx, tx, id, plan.release[id])
		if errors.Is(err, ErrCertificateRevoked) || errors.Is(err, ErrCertificateCompromised) {
			err = s.RequestRevert(ctx, tx, id, ReasonCanaryWaveFailed) // design §20.3: never released
		}
		if err != nil && !errors.Is(err, ErrDeploymentState) {
			return false, err
		}
	}
	for _, id := range sortedKeys(plan.revert) {
		if err := s.RequestRevert(ctx, tx, id, plan.revert[id]); err != nil && !errors.Is(err, ErrDeploymentState) {
			return false, err
		}
	}
	for _, id := range sortedKeys(plan.endQueued) {
		d, err := lockForHold(ctx, tx, id)
		if err != nil {
			return false, err
		}
		if d.state != DeployStateQueued && d.state != DeployStatePrecheck {
			continue
		}
		if err := s.finishLocked(ctx, tx, d, DeploymentFinish{Status: DeployStatusFailed, ErrorCode: plan.endQueued[id],
			Params: map[string]string{}}); err != nil && !errors.Is(err, errAlreadyFinished) {
			return false, err
		}
	}
	skipped := r.Skipped
	if plan.insertWave2 {
		var inserted int
		var err error
		skipped, inserted, err = s.insertWave2(ctx, tx, r, now)
		if err != nil {
			return false, err
		}
		if inserted == 0 {
			plan.next = RolloutCompleted
		}
		if err := s.auditRollout(ctx, tx, actor, "deployment.rollout_wave2_started", r.ID, map[string]string{
			"inserted": strconv.Itoa(inserted), "skipped": strconv.Itoa(len(skipped))}); err != nil {
			return false, err
		}
	}
	moved := plan.next != r.State
	if moved {
		if err := s.moveRollout(ctx, tx, r, plan, skipped, now, actor, early); err != nil {
			return false, err
		}
	}
	if finalRolloutState(plan.next) || plan.next == RolloutWave2 {
		return moved, nil
	}
	return moved, s.queueRounds(ctx, tx, sn, plan.queueRounds)
}

func holdingIDs(sn rolloutSnapshot) []uuid.UUID {
	var out []uuid.UUID
	for _, d := range sn.deployments {
		if d.state == DeployStateHolding && !d.targetDeleted && d.check != nil && !d.check.nextCheckAt.After(sn.now) {
			out = append(out, d.id)
		}
	}
	return out
}

func sortedKeys(m map[uuid.UUID]string) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return compareUUID(a, b) })
	return out
}

func compareUUID(a, b uuid.UUID) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// moveRollout writes the rollout's new state and its audit rows.
func (s *Service) moveRollout(ctx context.Context, tx pgx.Tx, r Rollout, plan rolloutPlan, skipped []RolloutSkip, now time.Time,
	actor audit.Actor, early bool) error {
	params, err := json.Marshal(plan.reasonParams)
	if err != nil {
		return err
	}
	if skipped == nil {
		skipped = []RolloutSkip{}
	}
	skippedJSON, err := json.Marshal(skipped)
	if err != nil {
		return err
	}
	holdStarted, holdUntil := r.HoldStartedAt, r.HoldUntil
	if plan.holdStart {
		start, until := now, now.Add(r.Settings.Hold)
		holdStarted, holdUntil = &start, &until
	}
	var finished *time.Time
	if finalRolloutState(plan.next) {
		finished = &now
	}
	reason := plan.reason
	if reason == "" {
		reason = r.Reason
	}
	if _, err := tx.Exec(ctx, `UPDATE deployment_rollouts SET state = $2, reason = $3, reason_params = $4, skipped = $5, hold_started_at = $6,
    hold_until = $7, finished_at = $8, gate_waiting_since = NULL, version = version + 1 WHERE id = $1`, r.ID, plan.next, reason, params,
		skippedJSON, holdStarted, holdUntil, finished); err != nil {
		return fmt.Errorf("inventory: move the rollout: %w", err)
	}
	details := map[string]string{"from": r.State, "to": plan.next}
	if r.ServiceID != nil {
		details["service_id"] = r.ServiceID.String()
	}
	if reason != "" {
		details["reason"] = reason
	}
	for k, v := range plan.reasonParams {
		details["param_"+k] = v
	}
	var actions []string
	switch plan.next {
	case RolloutHold:
		details["hold_until"] = holdUntil.UTC().Format(time.RFC3339)
		actions = []string{"deployment.rollout_hold_started"}
	case RolloutWave2:
		details["early"] = strconv.FormatBool(early)
		actions = []string{"deployment.rollout_released"}
	case RolloutCompleted:
		if r.State == RolloutHold || r.State == RolloutWave1 {
			details["early"] = strconv.FormatBool(early)
			actions = []string{"deployment.rollout_released"}
		}
		actions = append(actions, "deployment.rollout_completed")
	case RolloutFailed:
		if plan.checkFailed {
			actions = []string{"deployment.rollout_check_failed"}
		}
		actions = append(actions, "deployment.rollout_failed")
	case RolloutStopped:
		details["early"] = strconv.FormatBool(early)
		actions = []string{"deployment.rollout_released", "deployment.rollout_stopped"}
	case RolloutPreempted:
		actions = []string{"deployment.rollout_preempted"}
	case RolloutAborted:
		actions = []string{"deployment.rollout_aborted"}
	}
	for _, a := range actions {
		d := make(map[string]string, len(details))
		for k, v := range details {
			d[k] = v
		}
		if err := s.auditRollout(ctx, tx, actor, a, r.ID, d); err != nil {
			return err
		}
	}
	s.log.Info("canary rollout moved", "rollout_id", r.ID.String(), "from", r.State, "to", plan.next)
	switch plan.next {
	case RolloutStopped:
		return s.notifyRolloutStopped(ctx, tx, r)
	case RolloutFailed, RolloutAborted:
		return s.stopAutomaticSource(ctx, tx, r, revertReasonFor(reason), actor)
	}
	return nil
}

// queueRounds queues a canary.check job for each due holding deployment (dedupe canary.check:<id>: a live one answers).
func (s *Service) queueRounds(ctx context.Context, tx pgx.Tx, sn rolloutSnapshot, ids []uuid.UUID) error {
	targets := map[uuid.UUID]uuid.UUID{}
	for _, d := range sn.deployments {
		targets[d.id] = d.target
	}
	for _, id := range ids {
		if _, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobCanaryCheck, TargetID: targets[id], Payload: map[string]string{"deployment_id": id.String()},
			Kind: "system", DedupeKey: canaryCheckDedupePrefix + id.String()}); err != nil {
			return err
		}
	}
	return nil
}

// insertWave2 inserts wave 2 of a person's rollout (design §11): each location checked again (checkDeployLocation, with
// the trust of the source service); a refused one is skipped with its reason and audited deployment.denied (actor jobs);
// the others are ordinary deployments (trigger manual, requested_by the requester, rollout wave 2).
func (s *Service) insertWave2(ctx context.Context, tx pgx.Tx, r Rollout, now time.Time) ([]RolloutSkip, int, error) {
	src := deploySource{Trigger: "manual", BindingID: r.BindingID, KVVersionID: r.KVVersionID, RolloutID: &r.ID, Wave: 2}
	if err := tx.QueryRow(ctx, "SELECT coalesce(bool_or(confirm_incomplete_chain), false) FROM deployments WHERE rollout_id = $1 AND wave = 1",
		r.ID).Scan(&src.Confirmed); err != nil {
		return nil, 0, fmt.Errorf("inventory: read wave 1's confirmation: %w", err)
	}
	if r.KVVersionID != nil {
		if err := tx.QueryRow(ctx, "SELECT version FROM kv_certificate_versions WHERE id = $1", *r.KVVersionID).Scan(&src.Version); err != nil {
			return nil, 0, fmt.Errorf("inventory: read the version: %w", err)
		}
	}
	a := Actor{Audit: jobsActor}
	if r.RequestedBy != nil {
		a.UserID = *r.RequestedBy
	}
	skipped := []RolloutSkip{}
	inserted := 0
	for _, id := range r.Wave2 {
		reason, err := s.insertWave2Location(ctx, tx, a, r, id, src, now)
		if err != nil {
			return nil, 0, err
		}
		if reason != "" {
			skipped = append(skipped, RolloutSkip{LocationID: id, Reason: reason})
			if err := s.auditDenialTx(ctx, tx, r.CertificateID, id, reason); err != nil {
				return nil, 0, err
			}
			continue
		}
		inserted++
	}
	return skipped, inserted, nil
}

// insertWave2Location checks and inserts one wave-2 location in a savepoint (a refusal rolls back only its own writes);
// it answers the refusal's reason ("" when inserted).
func (s *Service) insertWave2Location(ctx context.Context, tx pgx.Tx, a Actor, r Rollout, id uuid.UUID, src deploySource,
	now time.Time) (string, error) {
	reason := ""
	err := pgx.BeginFunc(ctx, tx, func(sp pgx.Tx) error {
		c, err := readDeployCertificate(ctx, sp, r.CertificateID)
		if err != nil {
			return err
		}
		if r.ServiceID != nil {
			c.service = *r.ServiceID // the source service's trust (R49 §5.6 (c))
		}
		targets, locs, err := s.lockDeployTargets(ctx, sp, []uuid.UUID{id})
		if err != nil {
			var lr *LocationRefusalError
			if errors.As(err, &lr) || errors.Is(err, ErrNotFound) {
				reason = "location_not_found"
				return errSkipLocation
			}
			return err
		}
		l := locs[id]
		if why, err := s.checkDeployLocation(ctx, sp, c, l, targets[l.target]); err != nil {
			if why == "" {
				return err
			}
			reason = why
			return errSkipLocation
		}
		if _, err := s.insertDeployment(ctx, sp, a, c, l, src, now); err != nil {
			if errors.Is(err, ErrDeploymentInProgress) {
				reason = "in_progress"
				return errSkipLocation
			}
			return err
		}
		return nil
	})
	if errors.Is(err, errSkipLocation) {
		return reason, nil
	}
	return "", err
}

var errSkipLocation = errors.New("inventory: the location is skipped")

// auditDenialTx records a refused wave-2 location in tx (actor jobs).
func (s *Service) auditDenialTx(ctx context.Context, tx pgx.Tx, certificate, location uuid.UUID, reason string) error {
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "deployment.denied", ObjectType: "certificate",
		ObjectID: certificate.String(), Result: audit.Denied, Details: map[string]string{"certificate_id": certificate.String(),
			"location_id": location.String(), "reason": reason}})
	return err
}

// PreemptRolloutOf ends the canary rollout of a holding deployment for a key-compromise incident (design §20.3): under
// the rollout's lock every holding deployment of it is released (cause incident), the rollout ends preempted (no wave 2),
// audited deployment.rollout_preempted. A rollout whose deployed certificate is revoked or compromised is left to the
// canary, which reverts it (a forbidden certificate is never released). It answers whether the rollout moved.
func (s *Service) PreemptRolloutOf(ctx context.Context, deployment uuid.UUID) (bool, error) {
	moved := false
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		moved = false
		var rollout *uuid.UUID
		err := tx.QueryRow(ctx, "SELECT rollout_id FROM deployments WHERE id = $1 AND state = $2", deployment, DeployStateHolding).Scan(&rollout)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && rollout == nil) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inventory: read the hold: %w", err)
		}
		r, err := lockRollout(ctx, tx, *rollout, false)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		sn, err := readRolloutSnapshot(ctx, tx, r, now)
		if err != nil {
			return err
		}
		if sn.certificateForbidden {
			return nil // the canary reverts it (canary.certificate_revoked)
		}
		moved, err = s.applyRolloutPlan(ctx, tx, r, sn, preemptPlan(sn), incidentActor, false)
		return err
	})
	return moved, err
}

// preemptPlan is what an incident does to the rollout of a hold it reaches (design §20.3): a live rollout's holds are
// released (cause incident) and the rollout ends preempted; a finished passing one's holds are released. A hold of a
// rollout that already failed or was aborted (it arrived after the verdict while still sending) is reverted as the advance
// would, never released (final review I): it would otherwise be recorded a success with a certificate that failed its
// canary.
func preemptPlan(sn rolloutSnapshot) rolloutPlan {
	r := sn.r
	if r.State == RolloutFailed || r.State == RolloutAborted {
		return decideRollout(sn)
	}
	plan := rolloutPlan{next: r.State, reasonParams: map[string]string{}, release: map[uuid.UUID]string{}, revert: map[uuid.UUID]string{},
		endQueued: map[uuid.UUID]string{}}
	for _, d := range sn.deployments {
		if d.wave == 1 && d.state == DeployStateHolding {
			plan.release[d.id] = HoldCauseIncident
		}
	}
	if !finalRolloutState(r.State) {
		plan.next, plan.reason = RolloutPreempted, RolloutReasonPreempted
	}
	return plan
}
