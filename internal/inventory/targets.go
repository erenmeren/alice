package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// targetColumns is the column list every target read uses (scanTarget's order).
const targetColumns = `id, name::text, type, config, status, last_error_code, last_success_at, last_discovery_at,
discovery_interval_seconds, keys_managed_elsewhere, facts, capabilities, version, created_at, updated_at`

func scanTarget(row pgx.Row) (Target, error) {
	var t Target
	var cfg, facts []byte
	var interval int
	err := row.Scan(&t.ID, &t.Name, &t.Type, &cfg, &t.Status, &t.LastErrorCode, &t.LastSuccessAt, &t.LastDiscoveryAt,
		&interval, &t.KeysManagedElsewhere, &facts, &t.Capabilities, &t.Version, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	if err != nil {
		return Target{}, fmt.Errorf("inventory: read target: %w", err)
	}
	var c targetConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return Target{}, fmt.Errorf("inventory: decode target config: %w", err)
	}
	if err := json.Unmarshal(facts, &t.Facts); err != nil {
		return Target{}, fmt.Errorf("inventory: decode target facts: %w", err)
	}
	t.Host, t.Port, t.Username = c.Host, c.Port, c.Username
	t.DiscoveryInterval = time.Duration(interval) * time.Second
	t.CreatedAt, t.UpdatedAt = t.CreatedAt.UTC(), t.UpdatedAt.UTC()
	t.LastSuccessAt, t.LastDiscoveryAt = utcPtr(t.LastSuccessAt), utcPtr(t.LastDiscoveryAt)
	if t.Capabilities == nil {
		t.Capabilities = []string{}
	}
	return t, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func nullableUser(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// GetTarget returns a live target.
func (s *Service) GetTarget(ctx context.Context, id uuid.UUID) (Target, error) {
	return getTarget(ctx, s.pool, id, false)
}

func getTarget(ctx context.Context, q db.Querier, id uuid.UUID, forUpdate bool) (Target, error) {
	sql := "SELECT " + targetColumns + " FROM targets WHERE id = $1 AND deleted_at IS NULL"
	if forUpdate {
		sql += " FOR UPDATE"
	}
	return scanTarget(q.QueryRow(ctx, sql, id))
}

// ListTargets returns every live target, oldest first.
func (s *Service) ListTargets(ctx context.Context) ([]Target, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+targetColumns+" FROM targets WHERE deleted_at IS NULL ORDER BY created_at, id")
	if err != nil {
		return nil, fmt.Errorf("inventory: list targets: %w", err)
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// providerFor returns the registered provider of a target type.
func (s *Service) providerFor(typ string) (providers.Provider, bool) {
	k, ok := providers.KindForTargetType(typ)
	if !ok {
		return nil, false
	}
	return s.registry.Get(k)
}

// CreateTarget validates and stores a new target and queues its first connection test, which
// shows the server's fingerprint for confirmation (F-30). The license limit is checked in the
// insert transaction (L-74, L-79); a refusal is audited (L-04) and stores nothing.
func (s *Service) CreateTarget(ctx context.Context, a Actor, in NewTarget) (Target, uuid.UUID, error) {
	n, errs := validateNewTarget(in)
	if len(errs) > 0 {
		return Target{}, uuid.Nil, errs
	}
	p, ok := s.providerFor(n.Type)
	if !ok {
		errs.Add("type", validate.OneOf, map[string]string{"values": "linux"})
		return Target{}, uuid.Nil, errs
	}
	cfg := targetConfig{Host: n.Host, Port: n.Port, Username: n.Username}
	if fes := p.ValidateConfig(providers.TargetConfig{"host": cfg.Host, "port": cfg.Port, "username": cfg.Username}); len(fes) > 0 {
		return Target{}, uuid.Nil, validate.Errors(fes)
	}
	pk, err := s.EnsurePlatformKey(ctx)
	if err != nil {
		return Target{}, uuid.Nil, err
	}
	caps := make([]string, 0, len(p.Capabilities()))
	for _, c := range p.Capabilities().Sorted() {
		caps = append(caps, string(c))
	}
	id := uuid.Must(uuid.NewV7())
	var jobID uuid.UUID
	var created Target
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.insertTarget(ctx, tx, id, n, cfg, pk.ID, caps, a.UserID); err != nil {
			return err
		}
		var err error
		if created, err = getTarget(ctx, tx, id, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "target.created", ObjectType: "target",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{
				"name": n.Name, "type": n.Type, "host": n.Host, "port": strconv.Itoa(n.Port), "username": n.Username}})
		if err != nil {
			return err
		}
		jobID, err = s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobTestConnection, TargetID: id, Payload: map[string]string{},
			Kind: a.jobKind(), CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: "target.test_connection:" + id.String()})
		return err
	})
	if err != nil {
		s.auditLicenseDenial(ctx, a, n.Name, err)
		return Target{}, uuid.Nil, err
	}
	s.refreshLicense(ctx)
	return created, jobID, nil
}

// insertTarget checks the license limit and inserts the row in the same transaction: the check
// serializes concurrent adds (license.Service takes an advisory lock) and counts the targets the
// transaction sees, so the count can never pass the limit (L-74). Every insert into targets goes
// through this function (L-79, internal/archtest/targets_test.go).
func (s *Service) insertTarget(ctx context.Context, tx pgx.Tx, id uuid.UUID, n NewTarget, cfg targetConfig, credential uuid.UUID, caps []string, by uuid.UUID) error {
	if err := s.license.CheckCanAddTarget(ctx, tx); err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	_, err = tx.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, capabilities, discovery_interval_seconds,
created_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)`,
		id, n.Name, n.Type, raw, credential, StatusPendingHostKey, caps, int(defaultInterval/time.Second), nullableUser(by), now)
	if db.IsUniqueViolation(err) {
		return ErrDuplicateTarget
	}
	if err != nil {
		return fmt.Errorf("inventory: insert target: %w", err)
	}
	return nil
}

// auditLicenseDenial records an add refused by the license (L-04) in its own transaction: the
// add's transaction was rolled back. Other errors are not audited here. The record does not
// depend on the request: a client that disconnects right after the refusal does not erase it.
func (s *Service) auditLicenseDenial(ctx context.Context, a Actor, name string, cause error) {
	ctx = context.WithoutCancel(ctx)
	var limit *license.TargetLimitError
	d := map[string]string{"name": name}
	switch {
	case errors.As(cause, &limit):
		d["reason"], d["used"], d["max"] = "target_limit", strconv.Itoa(limit.Used), strconv.Itoa(limit.Max)
	case errors.Is(cause, license.ErrLocked):
		d["reason"] = "locked"
	default:
		return
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "target.add.denied_license", ObjectType: "target",
			Result: audit.Denied, Details: d})
		return err
	})
	if err != nil {
		s.log.Error("could not audit a refused target add", "error_type", fmt.Sprintf("%T", err))
	}
}

// refreshLicense re-evaluates the license after a committed add or delete, so the snapshot's
// target count and the limit banners are current (L-76). A failure is logged: the next hourly
// evaluation repeats it. It runs for a committed change even if the request has ended.
func (s *Service) refreshLicense(ctx context.Context) {
	ctx = context.WithoutCancel(ctx)
	if err := s.license.Tick(ctx); err != nil {
		s.log.Error("license evaluation after a target change failed", "error_type", fmt.Sprintf("%T", err))
	}
}

// UpdateTarget changes the name and the discovery interval (R37 item 10). ifVersion must be the
// version the caller read (If-Match).
func (s *Service) UpdateTarget(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, p TargetPatch) (Target, error) {
	var errs validate.Errors
	var name string
	if p.Name != nil {
		n, fe := validName("name", *p.Name)
		if fe != nil {
			errs = append(errs, *fe)
		}
		name = n
	}
	if p.Name == nil && p.DiscoveryIntervalHours == nil {
		// Nothing to change: refused, so an empty edit neither bumps the version nor is audited.
		errs.Add("name", validate.Required, nil)
		errs.Add("discovery_interval_hours", validate.Required, nil)
	}
	if p.DiscoveryIntervalHours != nil && (*p.DiscoveryIntervalHours < 1 || *p.DiscoveryIntervalHours > 720) {
		errs.Add("discovery_interval_hours", validate.OutOfRange, map[string]string{"min": "1", "max": "720"})
	}
	if len(errs) > 0 {
		return Target{}, errs
	}
	var updated Target
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getTarget(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Version != ifVersion {
			return ErrVersionMismatch
		}
		var fields []string
		details := map[string]string{}
		if p.Name != nil {
			cur.Name = name
			fields = append(fields, "name")
			details["name"] = name
		}
		if p.DiscoveryIntervalHours != nil {
			cur.DiscoveryInterval = time.Duration(*p.DiscoveryIntervalHours) * time.Hour
			fields = append(fields, "discovery_interval")
		}
		details["fields"] = strings.Join(fields, ",")
		_, err = tx.Exec(ctx, `UPDATE targets SET name = $2, discovery_interval_seconds = $3, version = version + 1, updated_at = $4
WHERE id = $1`, id, cur.Name, int(cur.DiscoveryInterval/time.Second), s.clock.Now().UTC())
		if db.IsUniqueViolation(err) {
			return ErrDuplicateTarget
		}
		if err != nil {
			return fmt.Errorf("inventory: update target: %w", err)
		}
		if updated, err = getTarget(ctx, tx, id, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "target.updated", ObjectType: "target",
			ObjectID: id.String(), Result: audit.Success, Details: details})
		return err
	})
	if err != nil {
		return Target{}, err
	}
	return updated, nil
}

// DeleteTarget soft-deletes a target: its license slot is free at once and nothing is changed on
// the server (§7.3). Queued jobs of the target fail when they run (TargetRef answers ErrNotFound).
func (s *Service) DeleteTarget(ctx context.Context, a Actor, id uuid.UUID) error {
	var typ string
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getTarget(ctx, tx, id, true)
		if err != nil {
			return err
		}
		typ = cur.Type
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, "UPDATE targets SET deleted_at = $2, version = version + 1, updated_at = $2 WHERE id = $1", id, now); err != nil {
			return fmt.Errorf("inventory: delete target: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "target.deleted", ObjectType: "target",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"name": cur.Name, "host": cur.Host}})
		return err
	})
	if err != nil {
		return err
	}
	// The provider forgets the target's pooled connections (A-16): nothing stays connected to a
	// server that was removed, so its documented clean-up does not meet a live session.
	if p, ok := s.providerFor(typ); ok {
		if cc, ok := p.(providers.ConnectionCache); ok {
			cc.ForgetTarget(id)
		}
	}
	s.refreshLicense(ctx)
	return nil
}

// RequestTest queues a connection test. It is allowed in every status: on a changed host key the
// test stops at the key exchange and only confirms the block (owner step 5).
func (s *Service) RequestTest(ctx context.Context, a Actor, id uuid.UUID) (uuid.UUID, error) {
	return s.requestJob(ctx, a, id, JobTestConnection, "target.test_connection:"+id.String(), nil)
}

// RequestDiscovery queues an SSH key scan; it needs a confirmed, unchanged host key (F-30, F-31).
func (s *Service) RequestDiscovery(ctx context.Context, a Actor, id uuid.UUID) (uuid.UUID, error) {
	return s.requestJob(ctx, a, id, JobDiscover, "target.discover:"+id.String()+":manual", func(t Target) error {
		switch t.Status {
		case StatusPendingHostKey:
			return ErrHostKeyUnconfirmed
		case StatusHostKeyChanged:
			return ErrHostKeyChanged
		}
		return nil
	})
}

func (s *Service) requestJob(ctx context.Context, a Actor, id uuid.UUID, typ, dedupe string, check func(Target) error) (uuid.UUID, error) {
	var jobID uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getTarget(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if check != nil {
			if err := check(t); err != nil {
				return err
			}
		}
		jobID, err = s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: typ, TargetID: id, Payload: map[string]string{},
			Kind: a.jobKind(), CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: dedupe})
		return err
	})
	return jobID, err
}
