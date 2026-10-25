package inventory

// Canary rollouts (R65, design docs/superpowers/specs/2026-10-24-canary-deployment-design.md §5-§7, §13.1, §15): a
// deployment request to two or more websites whose source service's policy enables the canary key becomes a rollout.
// Wave 1 is inserted with the request (its deployments hold after their verified send, canary_hold.go); wave 2 waits
// in the rollout row until the canary releases wave 1 (canary_advance.go). The decision is pure (canaryDecision); the
// rollout row, the wave-1 deployments and the audit rows are one transaction with the request's other writes.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/platform/db"
)

// Rollout states (deployment_rollouts.state, design §11).
const (
	RolloutWave1     = "wave1"
	RolloutHold      = "hold"
	RolloutWave2     = "wave2"
	RolloutCompleted = "completed"
	RolloutFailed    = "failed"
	RolloutAborted   = "aborted"
	RolloutStopped   = "stopped"
	RolloutPreempted = "preempted"
)

// Rollout origins: a person's request (also an ACME or Key Vault Deploy now) or a planner's.
const (
	RolloutOriginManual   = "manual"
	RolloutOriginACME     = "acme"
	RolloutOriginKeyVault = "key_vault"
)

// Why a request deploys to all at once although a policy was read (canaryDecision); "" means the canary applies.
const (
	CanarySkipDisabled = "disabled"
	CanarySkipSingle   = "single"
	CanarySkipOverride = "override"
	CanarySkipExempt   = "exempt"
	CanarySkipExpiry   = "expiry"
)

// CanaryExpiryMargin is added to the hold by the expiry guard (design §15): wave 2's own pace and the grace.
const CanaryExpiryMargin = 24 * time.Hour

var (
	// ErrRolloutNotFound: no rollout has this id.
	ErrRolloutNotFound = errors.New("inventory: no such deployment rollout")
	// ErrCanaryOverrideForbidden: a person asked to deploy to all at once and the source service's policy forbids it.
	ErrCanaryOverrideForbidden = errors.New("inventory: the service's policy does not allow deploying to all at once")
)

// Rollout is one canary deployment of one certificate (deployment_rollouts).
type Rollout struct {
	ID                uuid.UUID
	CertificateID     uuid.UUID
	ServiceID         *uuid.UUID // the source service whose policy applied (nil once deleted)
	PolicyVersion     int
	Settings          authz.CanarySettings // the snapshot taken at creation (design §5.3)
	Origin            string
	ACMECertificateID *uuid.UUID
	BindingID         *uuid.UUID
	KVVersionID       *uuid.UUID
	RequestedBy       *uuid.UUID
	State             string
	Reason            string
	ReasonParams      map[string]string // never nil
	Wave1, Wave2      []uuid.UUID
	Skipped           []RolloutSkip // never nil
	HoldStartedAt     *time.Time
	HoldUntil         *time.Time
	GateWaitingSince  *time.Time
	CreatedAt         time.Time
	FinishedAt        *time.Time
	Version           int
}

// RolloutSkip is a wave-2 location that was not deployed when wave 2 started, and why.
type RolloutSkip struct {
	LocationID uuid.UUID `json:"location_id"`
	Reason     string    `json:"reason"`
}

// Finished reports whether the rollout is in a final state.
func (r Rollout) Finished() bool { return r.FinishedAt != nil }

// rolloutSource is where a rollout's key comes from: the origin and, for a Deploy now or a planner, the source link.
type rolloutSource struct {
	origin            string
	acmeCertificateID *uuid.UUID
	bindingID         *uuid.UUID
	kvVersionID       *uuid.UUID
}

// canaryDecision decides whether a request to dests becomes a rollout (design §6, §15), purely: the source service's
// policy p, each destination's current certificate's not_after (absent when unknown), the request's override and
// exemption (an incident's replacement). It answers the effective settings (zero when the policy has no enabled
// canary), the waves when the canary applies (skip ""), or why it does not.
func canaryDecision(p authz.Policy, dests []uuid.UUID, current map[uuid.UUID]time.Time, now time.Time, override, exempt bool) (
	s authz.CanarySettings, wave1, wave2 []uuid.UUID, skip string) {
	s, enabled := p.CanarySettings()
	switch {
	case !enabled:
		return s, nil, nil, CanarySkipDisabled
	case exempt:
		return s, nil, nil, CanarySkipExempt
	case len(dests) < 2:
		return s, nil, nil, CanarySkipSingle
	case override:
		return s, nil, nil, CanarySkipOverride
	}
	if _, at, ok := earliestExpiry(dests, current); ok && at.Before(now.Add(s.Hold+CanaryExpiryMargin)) {
		return s, nil, nil, CanarySkipExpiry
	}
	wave1, wave2 = authz.CanaryWaves(dests, s)
	return s, wave1, wave2, ""
}

// earliestExpiry is the destination whose current certificate ends first, and when (false when none is known).
func earliestExpiry(dests []uuid.UUID, current map[uuid.UUID]time.Time) (uuid.UUID, time.Time, bool) {
	var (
		loc   uuid.UUID
		at    time.Time
		found bool
	)
	for _, d := range dests {
		t, ok := current[d]
		if ok && (!found || t.Before(at)) {
			loc, at, found = d, t, true
		}
	}
	return loc, at, found
}

// canaryPlan is what a request does about the canary: the destinations to insert now (every one, or wave 1) and the
// rollout created for them (nil when none).
type canaryPlan struct {
	insert  []uuid.UUID
	rollout *Rollout
}

// planCanary applies the canary to a manual request in tx (after every location passed checkDeployLocation): it reads
// the source service's policy, decides, refuses a forbidden override (ErrCanaryOverrideForbidden, audit reason
// canary_override_forbidden through deny), audits an override or an expiry skip, and creates the rollout. An
// unchanged request (no enabled canary, one destination, an incident) audits nothing.
func (s *Service) planCanary(ctx context.Context, tx pgx.Tx, a Actor, c deployCertificate, dests []uuid.UUID, override, exempt bool,
	src rolloutSource, now time.Time) (canaryPlan, string, error) {
	all := canaryPlan{insert: dests}
	if exempt {
		return all, "", nil
	}
	p, version, err := loadPolicyVersion(ctx, tx, c.service)
	if err != nil {
		return canaryPlan{}, "", err
	}
	if !p.CanaryEnabled() || len(dests) < 2 {
		return all, "", nil
	}
	current, err := currentNotAfter(ctx, tx, dests)
	if err != nil {
		return canaryPlan{}, "", err
	}
	settings, wave1, wave2, skip := canaryDecision(p, dests, current, now, override, exempt)
	base := map[string]string{"certificate_id": c.id.String(), "service_id": c.service.String(), "policy_version": fmt.Sprint(version),
		"location_ids": joinIDs(dests)}
	switch skip {
	case CanarySkipOverride:
		if !settings.OverrideAllowed {
			return canaryPlan{}, "canary_override_forbidden", ErrCanaryOverrideForbidden
		}
		return all, "", s.auditCertificate(ctx, tx, a, "deployment.canary_overridden", c.id, base)
	case CanarySkipExpiry:
		loc, at, _ := earliestExpiry(dests, current)
		base["reason"], base["location_id"], base["not_after"] = CanarySkipExpiry, loc.String(), at.UTC().Format(time.RFC3339)
		return all, "", s.auditCertificate(ctx, tx, a, "deployment.canary_skipped", c.id, base)
	case "":
	default:
		return all, "", nil
	}
	r := Rollout{ID: uuid.Must(uuid.NewV7()), CertificateID: c.id, ServiceID: &c.service, PolicyVersion: version, Settings: settings,
		Origin: src.origin, ACMECertificateID: src.acmeCertificateID, BindingID: src.bindingID, KVVersionID: src.kvVersionID,
		RequestedBy: nullableUser(a.UserID), State: RolloutWave1, ReasonParams: map[string]string{}, Wave1: wave1, Wave2: wave2,
		Skipped: []RolloutSkip{}, CreatedAt: now, Version: 1}
	if err := s.createRollout(ctx, tx, a, r); err != nil {
		return canaryPlan{}, "", err
	}
	return canaryPlan{insert: wave1, rollout: &r}, "", nil
}

// createRollout inserts r and audits deployment.rollout_started (actor a).
func (s *Service) createRollout(ctx context.Context, tx pgx.Tx, a Actor, r Rollout) error {
	settings, err := json.Marshal(r.Settings)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO deployment_rollouts (id, certificate_id, service_id, policy_version, settings, origin,
    acme_certificate_id, binding_id, kv_version_id, requested_by, state, wave1_location_ids, wave2_location_ids, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`, r.ID, r.CertificateID, r.ServiceID, r.PolicyVersion, settings, r.Origin,
		r.ACMECertificateID, r.BindingID, r.KVVersionID, r.RequestedBy, r.State, r.Wave1, r.Wave2, r.CreatedAt); err != nil {
		return fmt.Errorf("inventory: store the rollout: %w", err)
	}
	details := map[string]string{"rollout_id": r.ID.String(), "certificate_id": r.CertificateID.String(), "origin": r.Origin,
		"policy_version": fmt.Sprint(r.PolicyVersion), "wave1": joinIDs(r.Wave1), "wave2": joinIDs(r.Wave2)}
	if r.ServiceID != nil {
		details["service_id"] = r.ServiceID.String()
	}
	return s.auditRollout(ctx, tx, a.Audit, "deployment.rollout_started", r.ID, details)
}

// auditRollout appends one rollout audit row (object deployment_rollout).
func (s *Service) auditRollout(ctx context.Context, tx pgx.Tx, actor audit.Actor, action string, id uuid.UUID, details map[string]string) error {
	details["rollout_id"] = id.String()
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, ObjectType: "deployment_rollout", ObjectID: id.String(),
		Result: audit.Success, Details: details})
	return err
}

// auditCertificate appends one audit row about a certificate (actor a).
func (s *Service) auditCertificate(ctx context.Context, tx pgx.Tx, a Actor, action string, id uuid.UUID, details map[string]string) error {
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: action, ObjectType: "certificate", ObjectID: id.String(),
		Result: audit.Success, Details: details})
	return err
}

func joinIDs(ids []uuid.UUID) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return strings.Join(out, ",")
}

// loadPolicyVersion reads a service's current policy and its version in q.
func loadPolicyVersion(ctx context.Context, q db.Querier, service uuid.UUID) (authz.Policy, int, error) {
	p, err := authz.LoadPolicy(ctx, q, service)
	if err != nil {
		return authz.Policy{}, 0, err
	}
	version := 1
	err = q.QueryRow(ctx, "SELECT policy_version FROM services WHERE id = $1", service).Scan(&version)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return authz.Policy{}, 0, fmt.Errorf("inventory: read the policy version: %w", err)
	}
	return p, version, nil
}

// currentNotAfter is the not_after of the certificate each location currently holds (locations with an unknown one
// are absent).
func currentNotAfter(ctx context.Context, q db.Querier, locs []uuid.UUID) (map[uuid.UUID]time.Time, error) {
	rows, err := q.Query(ctx, `SELECT l.id, c.not_after FROM certificate_locations l JOIN certificates c ON c.id = l.certificate_id
WHERE l.id = ANY($1)`, locs)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the current certificates: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]time.Time{}
	for rows.Next() {
		var id uuid.UUID
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, fmt.Errorf("inventory: read the current certificates: %w", err)
		}
		out[id] = at
	}
	return out, rows.Err()
}

// rolloutColumns are the columns scanRollout reads.
const rolloutColumns = `id, certificate_id, service_id, policy_version, settings, origin, acme_certificate_id, binding_id, kv_version_id,
requested_by, state, reason, reason_params, wave1_location_ids, wave2_location_ids, skipped, hold_started_at, hold_until, gate_waiting_since,
created_at, finished_at, version`

func scanRollout(row pgx.Row) (Rollout, error) {
	var (
		r                         Rollout
		settings, params, skipped []byte
	)
	err := row.Scan(&r.ID, &r.CertificateID, &r.ServiceID, &r.PolicyVersion, &settings, &r.Origin, &r.ACMECertificateID, &r.BindingID,
		&r.KVVersionID, &r.RequestedBy, &r.State, &r.Reason, &params, &r.Wave1, &r.Wave2, &skipped, &r.HoldStartedAt, &r.HoldUntil,
		&r.GateWaitingSince, &r.CreatedAt, &r.FinishedAt, &r.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Rollout{}, ErrRolloutNotFound
	}
	if err != nil {
		return Rollout{}, fmt.Errorf("inventory: read the rollout: %w", err)
	}
	if err := json.Unmarshal(settings, &r.Settings); err != nil {
		return Rollout{}, fmt.Errorf("inventory: decode the rollout's settings: %w", err)
	}
	r.ReasonParams = map[string]string{}
	if err := json.Unmarshal(params, &r.ReasonParams); err != nil {
		return Rollout{}, fmt.Errorf("inventory: decode the rollout's reason params: %w", err)
	}
	r.Skipped = []RolloutSkip{}
	if err := json.Unmarshal(skipped, &r.Skipped); err != nil {
		return Rollout{}, fmt.Errorf("inventory: decode the rollout's skipped locations: %w", err)
	}
	r.CreatedAt = r.CreatedAt.UTC()
	r.HoldStartedAt, r.HoldUntil, r.GateWaitingSince, r.FinishedAt = utcPtr(r.HoldStartedAt), utcPtr(r.HoldUntil), utcPtr(r.GateWaitingSince),
		utcPtr(r.FinishedAt)
	return r, nil
}

// Rollout reads one rollout (ErrRolloutNotFound).
func (s *Service) Rollout(ctx context.Context, id uuid.UUID) (Rollout, error) {
	return scanRollout(s.pool.QueryRow(ctx, "SELECT "+rolloutColumns+" FROM deployment_rollouts WHERE id = $1", id))
}
