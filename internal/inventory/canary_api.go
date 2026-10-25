package inventory

// A person's actions on a canary rollout and its detail (R65, design §13.2, §13.3, §17.1): Continue now releases wave 1
// before the hold ends (its last rounds must have passed), Abort reverts wave 1; both take the rollout's lock first and
// reuse the advance's transitions.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// ErrRolloutState: the rollout's state does not allow the action (*RolloutStateError names the state).
var ErrRolloutState = errors.New("inventory: the rollout's state does not allow this")

// RolloutStateError names the state of a rollout that refused an action.
type RolloutStateError struct{ State string }

func (e *RolloutStateError) Error() string { return ErrRolloutState.Error() + ": " + e.State }

// Is makes errors.Is(err, ErrRolloutState) true.
func (e *RolloutStateError) Is(target error) bool { return target == ErrRolloutState }

// continuable reports whether a person may continue the rollout now (design §13.2): in hold, or in wave1 once every
// wave-1 deployment holds or ended unchanged, and every holding deployment's last round passed.
func continuable(sn rolloutSnapshot) bool {
	r := sn.r
	if r.State != RolloutHold && r.State != RolloutWave1 {
		return false
	}
	byLocation := map[uuid.UUID]rolloutDeployment{}
	for _, d := range sn.deployments {
		if d.wave == 1 {
			byLocation[d.location] = d
		}
	}
	for _, loc := range r.Wave1 {
		d, ok := byLocation[loc]
		if !ok {
			return false
		}
		switch {
		case d.state == DeployStateHolding:
			if d.check == nil || d.check.lastResult != RoundPass {
				return false
			}
		case d.state == DeployStateDone && d.status == DeployStatusUnchanged:
		default:
			return false
		}
	}
	return true
}

// AllowedRolloutActions are the actions the rollout's state allows (continue, abort), whoever asks.
func (d RolloutDetail) AllowedRolloutActions() []string {
	out := []string{}
	if d.continuable {
		out = append(out, "continue")
	}
	if d.State == RolloutWave1 || d.State == RolloutHold {
		out = append(out, "abort")
	}
	return out
}

// ContinueRollout releases wave 1 of a rollout before its hold ends (design §13.2): audited deployment.rollout_continued
// with the remaining hold, then the release of the advance (a person's rollout deploys wave 2 through the gate).
// *RolloutStateError when the state or the last rounds do not allow it; ErrRolloutNotFound.
func (s *Service) ContinueRollout(ctx context.Context, a Actor, id uuid.UUID) (Rollout, error) {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		r, err := lockRollout(ctx, tx, id, false)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		sn, err := readRolloutSnapshot(ctx, tx, r, now)
		if err != nil {
			return err
		}
		if !continuable(sn) {
			return &RolloutStateError{State: r.State}
		}
		remaining := time.Duration(0)
		if r.HoldUntil != nil && r.HoldUntil.After(now) {
			remaining = r.HoldUntil.Sub(now)
		}
		details := map[string]string{"remaining_seconds": strconv.Itoa(int(remaining / time.Second))}
		if r.ServiceID != nil {
			details["service_id"] = r.ServiceID.String()
		}
		if err := s.auditRollout(ctx, tx, a.Audit, "deployment.rollout_continued", r.ID, details); err != nil {
			return err
		}
		plan := rolloutPlan{reasonParams: map[string]string{}, release: map[uuid.UUID]string{}, revert: map[uuid.UUID]string{},
			endQueued: map[uuid.UUID]string{}}
		for _, d := range sn.deployments {
			if d.wave == 1 && d.state == DeployStateHolding {
				plan.release[d.id] = HoldCauseRelease
			}
		}
		if r.Origin == RolloutOriginManual {
			plan.next, plan.insertWave2 = RolloutWave2, true
		} else {
			plan.next = RolloutCompleted
		}
		_, err = s.applyRolloutPlan(ctx, tx, r, sn, plan, a.Audit, true)
		return err
	})
	if err != nil {
		return Rollout{}, err
	}
	return s.Rollout(ctx, id)
}

// AbortRollout stops a rollout in wave1 or hold (design §13.3): every holding wave-1 deployment is reverted
// (deployment.canary_aborted), the queued ones end failed, a sending one is reverted once it holds; audited
// deployment.rollout_aborted; an automatic source is stopped. *RolloutStateError otherwise; ErrRolloutNotFound.
func (s *Service) AbortRollout(ctx context.Context, a Actor, id uuid.UUID) (Rollout, error) {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		r, err := lockRollout(ctx, tx, id, false)
		if err != nil {
			return err
		}
		if r.State != RolloutWave1 && r.State != RolloutHold {
			return &RolloutStateError{State: r.State}
		}
		now := s.clock.Now().UTC()
		sn, err := readRolloutSnapshot(ctx, tx, r, now)
		if err != nil {
			return err
		}
		plan := rolloutPlan{next: RolloutAborted, reason: RolloutReasonAborted, reasonParams: map[string]string{}, release: map[uuid.UUID]string{},
			revert: map[uuid.UUID]string{}, endQueued: map[uuid.UUID]string{}}
		for _, d := range sn.deployments {
			if d.wave != 1 {
				continue
			}
			switch d.state {
			case DeployStateHolding:
				plan.revert[d.id] = ReasonCanaryAborted
			case DeployStateQueued, DeployStatePrecheck:
				plan.endQueued[d.id] = ReasonCanaryAborted
			}
		}
		_, err = s.applyRolloutPlan(ctx, tx, r, sn, plan, a.Audit, false)
		return err
	})
	if err != nil {
		return Rollout{}, err
	}
	return s.Rollout(ctx, id)
}

// CanaryView is the latest observation of one holding (or once holding) wave-1 deployment.
type CanaryView struct {
	Rounds, Passes, ConsecutiveFailures int
	NextCheckAt                         time.Time
	LastAt                              *time.Time
	LastResult, LastReason, LastTLS     string
	LastHTTPStatus, LastLatencyMS       *int
}

func canaryViewOf(c *canaryCheck) *CanaryView {
	if c == nil {
		return nil
	}
	return &CanaryView{Rounds: c.rounds, Passes: c.passes, ConsecutiveFailures: c.consecutiveFailures, NextCheckAt: c.nextCheckAt.UTC(),
		LastAt: utcPtr(c.lastAt), LastResult: c.lastResult, LastReason: c.lastReason, LastTLS: c.lastTLS, LastHTTPStatus: c.lastHTTPStatus,
		LastLatencyMS: c.lastLatencyMS}
}

// RolloutLocation is one website of a rollout with its deployment (nil before wave 2 starts) and its server's service.
type RolloutLocation struct {
	Wave             int
	LocationID       uuid.UUID
	TargetID         uuid.UUID
	TargetName       string
	Site             string // the location's certificate path or canonical name
	ServiceID        uuid.UUID
	DeploymentID     *uuid.UUID
	DeploymentState  string
	DeploymentStatus string
	Canary           *CanaryView
}

// RolloutDetail is a rollout with its websites, its certificate's and service's names and the server's clock.
type RolloutDetail struct {
	Rollout
	CertificateName string
	ServiceName     string
	Locations       []RolloutLocation // wave 1 then wave 2, each in the rollout's order
	Now             time.Time
	continuable     bool
}

// RolloutDetail reads one rollout with its websites (ErrRolloutNotFound).
func (s *Service) RolloutDetail(ctx context.Context, id uuid.UUID) (RolloutDetail, error) {
	var d RolloutDetail
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		r, err := scanRollout(tx.QueryRow(ctx, "SELECT "+rolloutColumns+" FROM deployment_rollouts WHERE id = $1", id))
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		sn, err := readRolloutSnapshot(ctx, tx, r, now)
		if err != nil {
			return err
		}
		d = RolloutDetail{Rollout: r, Now: now, continuable: continuable(sn)}
		if err := tx.QueryRow(ctx, `SELECT coalesce(nullif(c.label, ''), nullif(c.subject_cn, ''), left(c.fingerprint_sha256, 16)),
    coalesce((SELECT name::text FROM services WHERE id = $2), '') FROM certificates c WHERE c.id = $1`, r.CertificateID, r.ServiceID).
			Scan(&d.CertificateName, &d.ServiceName); err != nil {
			return fmt.Errorf("inventory: read the rollout's names: %w", err)
		}
		byLocation := map[uuid.UUID]rolloutDeployment{}
		for _, dep := range sn.deployments {
			byLocation[dep.location] = dep
		}
		all := append(append([]uuid.UUID{}, r.Wave1...), r.Wave2...)
		rows, err := tx.Query(ctx, `SELECT l.id, l.target_id, t.name::text, l.cert_path, t.service_id FROM certificate_locations l
JOIN targets t ON t.id = l.target_id WHERE l.id = ANY($1)`, all)
		if err != nil {
			return fmt.Errorf("inventory: read the rollout's websites: %w", err)
		}
		defer rows.Close()
		info := map[uuid.UUID]RolloutLocation{}
		for rows.Next() {
			var l RolloutLocation
			if err := rows.Scan(&l.LocationID, &l.TargetID, &l.TargetName, &l.Site, &l.ServiceID); err != nil {
				return fmt.Errorf("inventory: read the rollout's websites: %w", err)
			}
			info[l.LocationID] = l
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("inventory: read the rollout's websites: %w", err)
		}
		for i, loc := range all {
			l := info[loc]
			l.LocationID, l.Wave = loc, 1
			if i >= len(r.Wave1) {
				l.Wave = 2
			}
			if dep, ok := byLocation[loc]; ok && dep.wave == l.Wave {
				depID := dep.id
				l.DeploymentID, l.DeploymentState, l.DeploymentStatus, l.Canary = &depID, dep.state, dep.status, canaryViewOf(dep.check)
			}
			d.Locations = append(d.Locations, l)
		}
		return nil
	})
	return d, err
}

// canaryViewOfDeployment reads a deployment's canary_checks row (nil when it never held).
func canaryViewOfDeployment(ctx context.Context, q db.Querier, id uuid.UUID) (*CanaryView, error) {
	var c canaryCheck
	var next time.Time
	err := q.QueryRow(ctx, `SELECT rounds, passes, consecutive_failures, next_check_at, last_at, last_pass_at, last_result, last_reason, last_tls,
    last_http_status, last_latency_ms FROM canary_checks WHERE deployment_id = $1`, id).Scan(&c.rounds, &c.passes, &c.consecutiveFailures, &next,
		&c.lastAt, &c.lastPassAt, &c.lastResult, &c.lastReason, &c.lastTLS, &c.lastHTTPStatus, &c.lastLatencyMS)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read the deployment's canary: %w", err)
	}
	c.nextCheckAt = next
	return canaryViewOf(&c), nil
}
