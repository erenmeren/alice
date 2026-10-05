package sshkeys

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/sshkeys/keymat"
	"alice/internal/sshkeys/plan"
)

// Policy bounds (C13; rotation_policies CHECKs).
const (
	minIntervalDays          = 1
	maxIntervalDays          = 3650
	maxOverlapDays           = 90
	defaultNotifyBeforeHours = 24
	maxNotifyBeforeHours     = 168
	newKeyTypeSame           = "same"
	minutesPerDay            = 1440
)

// PolicyInput creates a rotation policy (C7).
type PolicyInput struct {
	SSHKeyID          uuid.UUID
	Name              string
	IntervalDays      int    // 1..3650
	OverlapDays       int    // 0..90 → overlap_minutes = days * 1440
	NotifyBeforeHours int    // 1..168, 0 = 24
	NewKeyType        string // "same" (default) or a keymat type
}

// PolicyPatch changes a policy; nil fields stay unchanged.
type PolicyPatch struct {
	Name              *string
	IntervalDays      *int
	OverlapDays       *int
	NotifyBeforeHours *int
	NewKeyType        *string
}

// Policy is a live rotation policy.
type Policy struct {
	ID, SSHKeyID         uuid.UUID
	Name                 string
	Enabled              bool
	IntervalDays         int
	OverlapMinutes       int
	NotifyBeforeHours    int
	NewKeyType           string
	NextRunAt            *time.Time
	OpenRotationID       *uuid.UUID
	Version              int
	CreatedAt, UpdatedAt time.Time
}

// policyRow is a policy with what only the module reads.
type policyRow struct {
	Policy
	previewMailedAt *time.Time
	deleted         bool
}

const policySelect = `SELECT p.id, p.ssh_key_id, p.name, p.enabled, p.interval_days, p.overlap_minutes, p.notify_before_hours,
    p.new_key_type, p.next_run_at, (SELECT r.id FROM rotations r WHERE r.policy_id = p.id AND r.status NOT IN ` + finishedStatuses + `),
    p.version, p.created_at, p.updated_at, p.preview_mailed_at, p.deleted_at IS NOT NULL
FROM rotation_policies p`

func scanPolicy(row pgx.Row) (policyRow, error) {
	var p policyRow
	err := row.Scan(&p.ID, &p.SSHKeyID, &p.Name, &p.Enabled, &p.IntervalDays, &p.OverlapMinutes, &p.NotifyBeforeHours, &p.NewKeyType,
		&p.NextRunAt, &p.OpenRotationID, &p.Version, &p.CreatedAt, &p.UpdatedAt, &p.previewMailedAt, &p.deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return policyRow{}, ErrNotFound
	}
	if err != nil {
		return policyRow{}, fmt.Errorf("sshkeys: read the rotation policy: %w", err)
	}
	p.CreatedAt, p.UpdatedAt = p.CreatedAt.UTC(), p.UpdatedAt.UTC()
	p.NextRunAt, p.previewMailedAt = utcPtr(p.NextRunAt), utcPtr(p.previewMailedAt)
	return p, nil
}

// getPolicy reads a live policy (FOR UPDATE OF p with lock); ErrNotFound when deleted or unknown.
func getPolicy(ctx context.Context, q db.Querier, id uuid.UUID, lock bool) (policyRow, error) {
	sql := policySelect + " WHERE p.id = $1 AND p.deleted_at IS NULL"
	if lock {
		sql += " FOR UPDATE OF p"
	}
	return scanPolicy(q.QueryRow(ctx, sql, id))
}

// onPolicyRead runs between the unlocked read of the open run and the policy lock (tests only; nil
// in production).
var onPolicyRead func()

// errConcurrentRun: another run of the policy became open between the unlocked read and the lock.
var errConcurrentRun = errors.New("sshkeys: a run of the policy changed while it was locked")

// lockPolicyRun locks, in the module's lock order, the policy's open run (when there is one) and
// then the live policy. run is nil when the policy has no open run.
func lockPolicyRun(ctx context.Context, tx pgx.Tx, id uuid.UUID) (policyRow, *runRow, error) {
	var open *uuid.UUID
	err := tx.QueryRow(ctx, "SELECT id FROM rotations WHERE policy_id = $1 AND status NOT IN "+finishedStatuses, id).Scan(&open)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return policyRow{}, nil, fmt.Errorf("sshkeys: read the policy's open run: %w", err)
	}
	var run *runRow
	if open != nil {
		r, err := lockRun(ctx, tx, *open)
		if err != nil {
			return policyRow{}, nil, err
		}
		run = &r
	}
	if onPolicyRead != nil {
		onPolicyRead()
	}
	p, err := getPolicy(ctx, tx, id, true)
	if err != nil {
		return policyRow{}, nil, err
	}
	// The open run read again in its own statement, after the policy lock (a fresh snapshot): a run
	// created by a transaction that held the policy lock while this one waited is seen here (Task 8
	// review I1); the subquery of the locking statement could not see it.
	var now *uuid.UUID
	err = tx.QueryRow(ctx, "SELECT id FROM rotations WHERE policy_id = $1 AND status NOT IN "+finishedStatuses, id).Scan(&now)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return policyRow{}, nil, fmt.Errorf("sshkeys: read the policy's open run: %w", err)
	}
	if run != nil && slices.Contains(finishedList, run.status) {
		run = nil // finished between the read and the lock
	}
	switch {
	case run == nil && now != nil, run != nil && (now == nil || *now != run.id):
		return policyRow{}, nil, errConcurrentRun
	}
	p.OpenRotationID = now
	return p, run, nil
}

// inPolicyTx runs fn in a transaction with the policy and its open run locked, starting over (at most
// three times) when another run of the policy became open meanwhile.
func (s *Service) inPolicyTx(ctx context.Context, id uuid.UUID, fn func(tx pgx.Tx, p policyRow, run *runRow) error) error {
	var err error
	for range 3 {
		err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
			p, run, err := lockPolicyRun(ctx, tx, id)
			if err != nil {
				return err
			}
			return fn(tx, p, run)
		})
		if !errors.Is(err, errConcurrentRun) {
			return err
		}
	}
	return err
}

// policyFields are a policy's settings after validation.
type policyFields struct {
	name                                 string
	intervalDays, overlapMinutes, notify int
	newKeyType                           string
}

func newKeyTypeValues() string { return newKeyTypeSame + ", " + keyTypeValues() }

// checkPolicy validates the fields that are set and fills them into f.
func checkPolicy(f *policyFields, p PolicyPatch) validate.Errors {
	var errs validate.Errors
	if p.Name != nil {
		name, fe := validName("name", *p.Name)
		if fe != nil {
			errs = append(errs, *fe)
		}
		f.name = name
	}
	if p.IntervalDays != nil {
		if *p.IntervalDays < minIntervalDays || *p.IntervalDays > maxIntervalDays {
			errs.Add("interval_days", validate.OutOfRange, map[string]string{"min": strconv.Itoa(minIntervalDays), "max": strconv.Itoa(maxIntervalDays)})
		}
		f.intervalDays = *p.IntervalDays
	}
	if p.OverlapDays != nil {
		if *p.OverlapDays < 0 || *p.OverlapDays > maxOverlapDays {
			errs.Add("overlap_days", validate.OutOfRange, map[string]string{"min": "0", "max": strconv.Itoa(maxOverlapDays)})
		}
		f.overlapMinutes = *p.OverlapDays * minutesPerDay
	}
	if p.NotifyBeforeHours != nil {
		h := *p.NotifyBeforeHours
		if h == 0 {
			h = defaultNotifyBeforeHours
		}
		if h < 1 || h > maxNotifyBeforeHours {
			errs.Add("notify_before_hours", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxNotifyBeforeHours)})
		}
		f.notify = h
	}
	if p.NewKeyType != nil {
		t := *p.NewKeyType
		if t == "" {
			t = newKeyTypeSame
		}
		if t != newKeyTypeSame && !keymat.KeyType(t).Valid() {
			errs.Add("new_key_type", validate.OneOf, map[string]string{"values": newKeyTypeValues()})
		}
		f.newKeyType = t
	}
	return errs
}

// CreatePolicy creates a rotation policy for a key Alice generated (§13.6), switched off. Alice's
// own key, a key Alice holds no private key for and a retired key are refused and audited
// (rotation.policy.denied); the new key of a live run is refused (S9: its run moves the old key's
// policy onto it).
func (s *Service) CreatePolicy(ctx context.Context, a inventory.Actor, in PolicyInput) (Policy, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Policy{}, err
	}
	var out Policy
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		key, err := readKeyRow(ctx, tx, in.SSHKeyID)
		if err != nil {
			return err
		}
		protected, err := inventory.ProtectedFingerprintsTx(ctx, tx)
		if err != nil {
			return err
		}
		switch {
		case key.isPlatform || slices.Contains(protected, key.fingerprint):
			return &denial{reason: DenyOwnKey, err: ErrOwnKeyProtected}
		case key.privateKeyID == uuid.Nil:
			return &denial{reason: DenyNotManaged, err: ErrNotManaged}
		case key.retired || key.destroyed:
			return &denial{reason: DenyRetired, err: ErrRetired}
		}
		var newOfLiveRun, hasPolicy bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rotations WHERE new_ssh_key_id = $1 AND status NOT IN `+finishedStatuses+`),
    EXISTS (SELECT 1 FROM rotation_policies WHERE ssh_key_id = $1 AND deleted_at IS NULL)`, key.id).Scan(&newOfLiveRun, &hasPolicy); err != nil {
			return fmt.Errorf("sshkeys: read the key's runs and policies: %w", err)
		}
		switch {
		case newOfLiveRun:
			return ErrRotationInProgress
		case hasPolicy:
			return ErrPolicyExists
		}
		f := policyFields{notify: defaultNotifyBeforeHours, newKeyType: newKeyTypeSame}
		notify, typ := in.NotifyBeforeHours, in.NewKeyType
		if errs := checkPolicy(&f, PolicyPatch{Name: &in.Name, IntervalDays: &in.IntervalDays, OverlapDays: &in.OverlapDays,
			NotifyBeforeHours: &notify, NewKeyType: &typ}); len(errs) > 0 {
			return errs
		}
		id, now := uuid.Must(uuid.NewV7()), s.clock.Now().UTC()
		_, err = tx.Exec(ctx, `INSERT INTO rotation_policies (id, ssh_key_id, name, enabled, interval_days, overlap_minutes, notify_before_hours,
    new_key_type, version, created_by, created_at, updated_at) VALUES ($1, $2, $3, false, $4, $5, $6, $7, 1, $8, $9, $9)`,
			id, key.id, f.name, f.intervalDays, f.overlapMinutes, f.notify, f.newKeyType, nullableUser(a.UserID), now)
		if err != nil {
			return policyWriteError(err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "rotation.policy_created", ObjectType: "rotation_policy",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"policy_id": id.String(), "ssh_key_id": key.id.String(),
				"interval_days": strconv.Itoa(f.intervalDays), "overlap_minutes": strconv.Itoa(f.overlapMinutes),
				"notify_before_hours": strconv.Itoa(f.notify), "new_type": f.newKeyType}})
		if err != nil {
			return err
		}
		p, err := getPolicy(ctx, tx, id, false)
		out = p.Policy
		return err
	})
	var d *denial
	if errors.As(err, &d) {
		s.auditDetached(ctx, audit.Event{Actor: a.Audit, Action: "rotation.policy.denied", ObjectType: "ssh_key",
			ObjectID: in.SSHKeyID.String(), Result: audit.Denied, Details: map[string]string{"reason": d.reason,
				"ssh_key_id": in.SSHKeyID.String()}})
		return Policy{}, d.err
	}
	if err != nil {
		return Policy{}, err
	}
	return out, nil
}

// policyWriteError maps the database's refusals of a policy write: the one-policy-per-key index
// (a concurrent create) and the key trigger (Z1010: the key was retired or is no longer usable).
func policyWriteError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			return ErrPolicyExists
		case "Z1010":
			return ErrRetired
		}
	}
	return fmt.Errorf("sshkeys: write the rotation policy: %w", err)
}

// UpdatePolicy changes the given fields of a policy (If-Match: version). An edit of what an
// enabled policy does (interval, overlap, notice, new key type) also switches it off (S2): switching
// on again is SetPolicyEnabled, which needs an Administrator with step-up. A name-only edit leaves it
// on. Nothing changed: the policy is returned as it is.
func (s *Service) UpdatePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, patch PolicyPatch) (Policy, error) {
	var out Policy
	err := s.inPolicyTx(ctx, id, func(tx pgx.Tx, p policyRow, run *runRow) error {
		if p.Version != version {
			return ErrVersionMismatch
		}
		f := policyFields{name: p.Name, intervalDays: p.IntervalDays, overlapMinutes: p.OverlapMinutes, notify: p.NotifyBeforeHours,
			newKeyType: p.NewKeyType}
		if errs := checkPolicy(&f, patch); len(errs) > 0 {
			return errs
		}
		changed := map[string]string{}
		if f.name != p.Name {
			changed["name"] = f.name
		}
		if f.intervalDays != p.IntervalDays {
			changed["interval_days"] = strconv.Itoa(f.intervalDays)
		}
		if f.overlapMinutes != p.OverlapMinutes {
			changed["overlap_minutes"] = strconv.Itoa(f.overlapMinutes)
		}
		if f.notify != p.NotifyBeforeHours {
			changed["notify_before_hours"] = strconv.Itoa(f.notify)
		}
		if f.newKeyType != p.NewKeyType {
			changed["new_type"] = f.newKeyType
		}
		if len(changed) == 0 {
			out = p.Policy
			return nil
		}
		_, nameOnly := changed["name"]
		nameOnly = nameOnly && len(changed) == 1
		switchOff := p.Enabled && !nameOnly
		now := s.clock.Now().UTC()
		_, err := tx.Exec(ctx, `UPDATE rotation_policies SET name = $2, interval_days = $3, overlap_minutes = $4, notify_before_hours = $5,
    new_key_type = $6, enabled = enabled AND NOT $7, next_run_at = CASE WHEN $7 THEN NULL ELSE next_run_at END, version = version + 1,
    updated_at = $8 WHERE id = $1`, id, f.name, f.intervalDays, f.overlapMinutes, f.notify, f.newKeyType, switchOff, now)
		if err != nil {
			return policyWriteError(err)
		}
		changed["policy_id"] = id.String()
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "rotation.policy_updated", ObjectType: "rotation_policy",
			ObjectID: id.String(), Result: audit.Success, Details: changed}); err != nil {
			return err
		}
		if switchOff {
			if err := s.switchedOff(ctx, tx, a.Audit, id, run, "edited"); err != nil {
				return err
			}
		}
		np, err := getPolicy(ctx, tx, id, false)
		out = np.Policy
		return err
	})
	return out, err
}

// switchedOff records a policy that was switched off and cancels its previewed run (C8: a run in
// dry_run_notified is cancelled with rotation.policy_off; a started run continues).
func (s *Service) switchedOff(ctx context.Context, tx pgx.Tx, actor audit.Actor, id uuid.UUID, run *runRow, reason string) error {
	if run != nil && run.status == StatusDryRunNotified {
		if err := s.cancelRun(ctx, tx, actor, *run, ReasonPolicyOff); err != nil {
			return err
		}
	}
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "rotation.policy_disabled", ObjectType: "rotation_policy",
		ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"policy_id": id.String(), "next_run_at": "",
			"reason": reason}})
	return err
}

// SetPolicyEnabled switches a policy on (the first run plan.FirstRun from now; the license gate must
// allow changes; the route needs an Administrator with step-up, S2) or off (no next run; a previewed
// run is cancelled, a started run continues).
func (s *Service) SetPolicyEnabled(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, enabled bool) (Policy, error) {
	if enabled {
		if err := s.license.Allow(license.ClassChange); err != nil {
			return Policy{}, err
		}
	}
	var out Policy
	err := s.inPolicyTx(ctx, id, func(tx pgx.Tx, p policyRow, run *runRow) error {
		if p.Version != version {
			return ErrVersionMismatch
		}
		if p.Enabled == enabled {
			out = p.Policy
			return nil
		}
		now := s.clock.Now().UTC()
		var next *time.Time
		if enabled {
			n := plan.FirstRun(now, p.IntervalDays)
			next = &n
		}
		// Switching on runs the database's key check again: a key retired meanwhile is refused (Z1010).
		if _, err := tx.Exec(ctx, `UPDATE rotation_policies SET enabled = $2, next_run_at = $3, version = version + 1, updated_at = $4
WHERE id = $1`, id, enabled, next, now); err != nil {
			return policyWriteError(err)
		}
		if enabled {
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "rotation.policy_enabled", ObjectType: "rotation_policy",
				ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"policy_id": id.String(),
					"next_run_at": next.Format(time.RFC3339)}}); err != nil {
				return err
			}
		} else if err := s.switchedOff(ctx, tx, a.Audit, id, run, "manual"); err != nil {
			return err
		}
		np, err := getPolicy(ctx, tx, id, false)
		out = np.Policy
		return err
	})
	return out, err
}

// DeletePolicy deletes a policy (If-Match: version). A previewed run is cancelled; a started run
// refuses the deletion (ErrRotationInProgress).
func (s *Service) DeletePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int) error {
	return s.inPolicyTx(ctx, id, func(tx pgx.Tx, p policyRow, run *runRow) error {
		if p.Version != version {
			return ErrVersionMismatch
		}
		if run != nil {
			if run.status != StatusDryRunNotified {
				return ErrRotationInProgress
			}
			if err := s.cancelRun(ctx, tx, a.Audit, *run, ReasonPolicyOff); err != nil {
				return err
			}
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE rotation_policies SET deleted_at = $2, enabled = false, next_run_at = NULL, version = version + 1,
    updated_at = $2 WHERE id = $1`, id, now); err != nil {
			return policyWriteError(err)
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "rotation.policy_deleted", ObjectType: "rotation_policy",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"policy_id": id.String()}})
		return err
	})
}

// Policy returns a live policy; ErrNotFound.
func (s *Service) Policy(ctx context.Context, id uuid.UUID) (Policy, error) {
	p, err := getPolicy(ctx, s.pool, id, false)
	return p.Policy, err
}

// Policies returns the live policies by name.
func (s *Service) Policies(ctx context.Context) ([]Policy, error) {
	rows, err := s.pool.Query(ctx, policySelect+" WHERE p.deleted_at IS NULL ORDER BY p.name, p.id")
	if err != nil {
		return nil, fmt.Errorf("sshkeys: list rotation policies: %w", err)
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Policy)
	}
	return out, rows.Err()
}

// plannerDisableReason is the policy_disabled reason of a planner refusal ("own_key", …).
func plannerDisableReason(err error) string {
	switch {
	case errors.Is(err, plan.ErrOwnKey):
		return DenyOwnKey
	case errors.Is(err, plan.ErrNotManaged):
		return DenyNotManaged
	case errors.Is(err, plan.ErrRetired):
		return DenyRetired
	case errors.Is(err, plan.ErrNewKeyType):
		return "new_key_type"
	}
	return strings.TrimPrefix(err.Error(), "plan: ")
}
