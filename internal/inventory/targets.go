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
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// targetColumns is the column list every target read uses (scanTarget's order).
//
// The last column is the public information of a vault's own credential ('null' for a server);
// every query that uses the list reads FROM targets without an alias.
const targetColumns = `id, name::text, type, config, status, last_error_code, last_success_at, last_discovery_at,
discovery_interval_seconds, keys_managed_elsewhere, facts, capabilities, version, created_at, updated_at, service_id,
coalesce((SELECT c.public_info FROM credentials c WHERE c.id = targets.credential_id AND c.purpose = 'azure_vault'), 'null'::jsonb)`

func scanTarget(row pgx.Row) (Target, error) {
	var t Target
	var cfg, facts, vaultInfoRaw []byte
	var interval int
	err := row.Scan(&t.ID, &t.Name, &t.Type, &cfg, &t.Status, &t.LastErrorCode, &t.LastSuccessAt, &t.LastDiscoveryAt,
		&interval, &t.KeysManagedElsewhere, &facts, &t.Capabilities, &t.Version, &t.CreatedAt, &t.UpdatedAt, &t.ServiceID, &vaultInfoRaw)
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
	t.CertificateCleanup = c.CertificateCleanup
	t.DiscoveryInterval = time.Duration(interval) * time.Second
	t.CreatedAt, t.UpdatedAt = t.CreatedAt.UTC(), t.UpdatedAt.UTC()
	t.LastSuccessAt, t.LastDiscoveryAt = utcPtr(t.LastSuccessAt), utcPtr(t.LastDiscoveryAt)
	if t.Capabilities == nil {
		t.Capabilities = []string{}
	}
	if t.Type == TypeAzureKeyVault {
		v, err := vaultInfoOf(c, vaultInfoRaw, t.DiscoveryInterval, t.Facts.Azure)
		if err != nil {
			return Target{}, err
		}
		t.Vault = &v
	}
	return t, nil
}

// requireServer refuses a Key Vault: the SSH record paths (connection results, host keys, key and
// certificate scans) belong to servers, and a vault's status and facts are its own.
func requireServer(t Target) error {
	if t.Type == TypeAzureKeyVault {
		return ErrNotAServer
	}
	return nil
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
		errs.Add("type", validate.OneOf, typeValues()) // a type of this build without its provider
		return Target{}, uuid.Nil, errs
	}
	cfg := targetConfig{Host: n.Host, Port: n.Port, Username: n.Username}
	if fes := p.ValidateConfig(providers.TargetConfig{"host": cfg.Host, "port": cfg.Port, "username": cfg.Username}); len(fes) > 0 {
		return Target{}, uuid.Nil, validate.Errors(fes)
	}
	if in.Config != nil {
		sw, _, errs := validateProviderSettings(p, providers.TargetConfig{"host": cfg.Host, "port": cfg.Port, "username": cfg.Username}, in.Config)
		if len(errs) > 0 {
			return Target{}, uuid.Nil, errs
		}
		cfg.CertificateCleanup = sw
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
		service, err := authz.ResolveService(ctx, tx, n.ServiceID)
		if err != nil {
			return err
		}
		if err := s.insertTarget(ctx, tx, targetRow{ID: id, Name: n.Name, Type: n.Type, Config: cfg, CredentialID: pk.ID,
			Status: StatusPendingHostKey, Capabilities: caps, IntervalSeconds: int(defaultInterval / time.Second), By: a.UserID,
			ServiceID: service}); err != nil {
			return err
		}
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

// targetRow is one targets row to insert (insertTarget).
type targetRow struct {
	ID              uuid.UUID
	Name            string
	Type            string
	Config          any
	CredentialID    uuid.UUID
	Status          string
	LastErrorCode   string
	LastSuccessAt   *time.Time
	Capabilities    []string
	IntervalSeconds int
	Facts           []byte // nil = {}
	By              uuid.UUID
	ServiceID       uuid.UUID // resolved by the caller (authz.ResolveService)
}

// insertTarget checks the license limit and inserts the row in the same transaction: the check
// serializes concurrent adds (license.Service takes an advisory lock) and counts the targets the
// transaction sees, so the count can never pass the limit (L-74). Every insert into targets goes
// through this function (L-79, internal/archtest/targets_test.go). A vault's credential row is
// inserted first in the same transaction (the foreign key to the vault is deferred).
func (s *Service) insertTarget(ctx context.Context, tx pgx.Tx, r targetRow) error {
	if err := s.license.CheckCanAddTarget(ctx, tx); err != nil {
		return err
	}
	raw, err := json.Marshal(r.Config)
	if err != nil {
		return err
	}
	facts := r.Facts
	if facts == nil {
		facts = []byte("{}")
	}
	now := s.clock.Now().UTC()
	_, err = tx.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, last_error_code, last_success_at, capabilities,
discovery_interval_seconds, facts, created_by, created_at, updated_at, service_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13, $14)`,
		r.ID, r.Name, r.Type, raw, r.CredentialID, r.Status, r.LastErrorCode, r.LastSuccessAt, r.Capabilities, r.IntervalSeconds, facts,
		nullableUser(r.By), now, r.ServiceID)
	if e, ok := closedTargetWriteError(err); ok {
		return e
	}
	if err != nil {
		return fmt.Errorf("inventory: insert target: %w", err)
	}
	return nil
}

// closedTargetWriteError maps the database's refusals of a write to targets to closed errors, so no
// SQLSTATE and no database text reaches a caller: a duplicate name or address, a credential that is
// not the target's own (Z1006) and the application role's attempt to change a server's credential
// (Z1005). ok is false for every other error (and for nil).
func closedTargetWriteError(err error) (error, bool) {
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return nil, false
	case db.IsUniqueViolation(err):
		return ErrDuplicateTarget, true
	case errors.As(err, &pg) && pg.Code == sqlstateCredentialMismatch:
		return ErrCredentialNotTheTargets, true
	case errors.As(err, &pg) && pg.Code == sqlstateServerCredential:
		return ErrNotAVault, true
	}
	return nil, false
}

// mapTargetWriteError is closedTargetWriteError that passes every other error through.
func mapTargetWriteError(err error) error {
	if e, ok := closedTargetWriteError(err); ok {
		return e
	}
	return err
}

// SQLSTATEs of migration 00008's trigger on targets.credential_id.
const (
	sqlstateServerCredential   = "Z1005"
	sqlstateCredentialMismatch = "Z1006"
)

// auditLicenseDenial records an add refused by the license (L-04) in its own transaction: the
// add's transaction was rolled back. Other errors are not audited here. The record does not
// depend on the request: a client that disconnects right after the refusal does not erase it.
func (s *Service) auditLicenseDenial(ctx context.Context, a Actor, name string, cause error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	var limit *license.TargetLimitError
	d := map[string]string{"name": name}
	switch {
	case errors.As(cause, &limit):
		d["reason"], d["used"], d["max"] = "target_limit", strconv.Itoa(limit.Used), strconv.Itoa(limit.Max)
	case license.DenialReason(cause) != "": // locked, lock_due or unverified (AUD-02)
		d["reason"] = license.DenialReason(cause)
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

// detachedTimeout bounds work that outlives its request (the evaluation after a committed change,
// the audit of a refusal): a client that disconnects does not skip it, a stuck database does not
// hold the goroutine forever.
const detachedTimeout = 30 * time.Second

// refreshLicense re-evaluates the license after a committed add or delete, so the snapshot's
// target count and the limit banners are current (L-76). A failure is logged: the next hourly
// evaluation repeats it. It runs for a committed change even if the request has ended, for at
// most detachedTimeout.
func (s *Service) refreshLicense(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	if err := s.license.Tick(ctx); err != nil {
		s.log.Error("license evaluation after a target change failed", "error_type", fmt.Sprintf("%T", err))
	}
}

// UpdateTarget changes the name and the scan interval (R37 item 10): the discovery interval of a
// server, in hours, or the poll interval of a vault, in minutes (R40 row 13); each is refused on the
// other kind of target. ifVersion must be the version the caller read (If-Match).
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
	if p.Name == nil && p.DiscoveryIntervalHours == nil && p.PollIntervalMinutes == nil {
		// Nothing to change: refused, so an empty edit neither bumps the version nor is audited.
		errs.Add("name", validate.Required, nil)
		errs.Add("discovery_interval_hours", validate.Required, nil)
	}
	if p.DiscoveryIntervalHours != nil && (*p.DiscoveryIntervalHours < 1 || *p.DiscoveryIntervalHours > 720) {
		errs.Add("discovery_interval_hours", validate.OutOfRange, map[string]string{"min": "1", "max": "720"})
	}
	if p.PollIntervalMinutes != nil {
		if fe := validPollMinutes(*p.PollIntervalMinutes); fe != nil {
			errs = append(errs, *fe)
		}
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
		// Each interval belongs to one kind of target.
		var kindErrs validate.Errors
		if p.DiscoveryIntervalHours != nil && cur.Type == TypeAzureKeyVault {
			kindErrs.Add("discovery_interval_hours", validate.Pattern, nil)
		}
		if p.PollIntervalMinutes != nil && cur.Type != TypeAzureKeyVault {
			kindErrs.Add("poll_interval_minutes", validate.Pattern, nil)
		}
		if len(kindErrs) > 0 {
			return kindErrs
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
		if p.PollIntervalMinutes != nil {
			cur.DiscoveryInterval = time.Duration(*p.PollIntervalMinutes) * time.Minute
			fields = append(fields, "poll_interval")
		}
		details["fields"] = strings.Join(fields, ",")
		_, err = tx.Exec(ctx, `UPDATE targets SET name = $2, discovery_interval_seconds = $3, version = version + 1, updated_at = $4
WHERE id = $1`, id, cur.Name, int(cur.DiscoveryInterval/time.Second), s.clock.Now().UTC())
		if e, ok := closedTargetWriteError(err); ok {
			return e
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

// validateProviderSettings checks the provider settings beyond the connection (R62 Ruling 13) that a create
// body carries (an update cannot: alice_app has no UPDATE on targets.config): only the cleanup switch, and only when the provider's schema declares it; the provider's own
// ParseConfig judges the value (base is the connection settings it is judged with). It returns the switch (nil when
// the body gives null) and whether the body named it.
func validateProviderSettings(p providers.Provider, base providers.TargetConfig, in map[string]any) (sw *bool, named bool, errs validate.Errors) {
	declared := map[string]bool{}
	for _, f := range p.ConfigSchema().Fields {
		declared[f.Name] = true
	}
	cfg := providers.TargetConfig{}
	for k, v := range base {
		cfg[k] = v
	}
	for k, v := range in {
		if k != providers.ConfigCertificateCleanup || !declared[k] {
			errs.Add("config."+k, validate.Pattern, nil)
			continue
		}
		cfg[k] = v
		named = true
	}
	if len(errs) > 0 {
		return nil, false, errs
	}
	for _, fe := range p.ValidateConfig(cfg) {
		errs = append(errs, validate.FieldError{Field: "config." + fe.Field, Code: fe.Code, Params: fe.Params})
	}
	if len(errs) > 0 {
		return nil, false, errs
	}
	if b, ok := cfg[providers.ConfigCertificateCleanup].(bool); ok {
		sw = &b
	}
	return sw, named, nil
}

// DeleteTarget soft-deletes a server: its license slot is free at once and nothing is changed on
// the server (§7.3). Queued jobs of the target fail when they run (TargetRef answers ErrNotFound).
// A Key Vault is deleted with DeleteVault, which deals with its bindings (ErrNotAServer here).
func (s *Service) DeleteTarget(ctx context.Context, a Actor, id uuid.UUID) error {
	var typ string
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getTarget(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Type == TypeAzureKeyVault {
			return ErrNotAServer
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

// RequestTest queues a connection test. It is allowed in every status; on a changed host key (or
// a disabled target) the job refuses before connecting at all (F-31: nothing runs on that target
// until an Administrator re-pins), so it only confirms the block (owner step 5). For a Key Vault it
// queues the access check (RequestAccessCheck without a secret read); a disabled vault is refused.
func (s *Service) RequestTest(ctx context.Context, a Actor, id uuid.UUID) (uuid.UUID, error) {
	return s.requestJob(ctx, a, id, func(t Target) (string, string, error) {
		if t.Type == TypeAzureKeyVault {
			if t.Status == StatusDisabled {
				return "", "", ErrTargetNotReady
			}
			return JobKVTest, "kv.test_connection:" + id.String(), nil
		}
		return JobTestConnection, "target.test_connection:" + id.String(), nil
	})
}

// RequestDiscovery queues an SSH key scan; it needs a confirmed, unchanged host key (F-30, F-31).
// For a Key Vault it queues a poll of the vault's inventory (a vault has no host key; only a
// disabled vault is refused).
func (s *Service) RequestDiscovery(ctx context.Context, a Actor, id uuid.UUID) (uuid.UUID, error) {
	return s.requestJob(ctx, a, id, func(t Target) (string, string, error) {
		switch {
		case t.Type == TypeAzureKeyVault && t.Status == StatusDisabled:
			return "", "", ErrTargetNotReady
		case t.Type == TypeAzureKeyVault:
			return JobKVPoll, "kv.poll:" + id.String(), nil
		case t.Status == StatusPendingHostKey:
			return "", "", ErrHostKeyUnconfirmed
		case t.Status == StatusHostKeyChanged:
			return "", "", ErrHostKeyChanged
		}
		return JobDiscover, "target.discover:" + id.String() + ":manual", nil
	})
}

// requestJob locks the target and queues the job that pick chooses for it (its type, dedupe key
// and refusal).
func (s *Service) requestJob(ctx context.Context, a Actor, id uuid.UUID, pick func(Target) (typ, dedupe string, err error)) (uuid.UUID, error) {
	var jobID uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getTarget(ctx, tx, id, true)
		if err != nil {
			return err
		}
		typ, dedupe, err := pick(t)
		if err != nil {
			return err
		}
		jobID, err = s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: typ, TargetID: id, Payload: map[string]string{},
			Kind: a.jobKind(), CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: dedupe})
		return err
	})
	return jobID, err
}
