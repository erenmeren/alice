package discoverysvc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/authz"
	"alice/internal/discovery"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// ScopeView is a live scope as stored, with its version (If-Match), its scan in flight (ActiveScanID) and its last
// finished scan (nil: none yet).
type ScopeView struct {
	ID              uuid.UUID
	Scope           discovery.Scope
	Version         int
	CreatedBy       uuid.NullUUID
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastScheduledAt *time.Time
	ActiveScanID    uuid.NullUUID
	LastScan        *ScanView
	ServiceID       uuid.UUID // the owning service (R49): its scans, endpoints and findings belong to it
}

// ScopeCursor is the position after a scope in the list's order (created_at, id).
type ScopeCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

// ScopeFilter pages the scope list: after a cursor (nil: the first page), at most Limit (1..discovery.MaxPage, else 50).
type ScopeFilter struct {
	After *ScopeCursor
	Limit int
	// ServiceIDs keeps the scopes owned by these services (R49); nil = every service, empty = none.
	ServiceIDs []uuid.UUID
}

// ScopePatch is a change of a scope: nil fields stay. Schedule replaces the whole schedule.
type ScopePatch struct {
	Name          *string
	Entries       *[]string
	Ports         *[]int
	SNINames      *[]string
	Exclusions    *[]string
	Enabled       *bool
	Schedule      *discovery.Schedule
	AlertOnExpiry *bool
	RatePerSec    *int
	Concurrency   *int
}

// apply returns s changed by p and the JSON names of the fields p changes, in a fixed order.
func (p ScopePatch) apply(s discovery.Scope) (discovery.Scope, []string) {
	var changed []string
	set := func(name string, given bool, do func()) {
		if given {
			do()
			changed = append(changed, name)
		}
	}
	set("name", p.Name != nil, func() { s.Name = *p.Name })
	set("entries", p.Entries != nil, func() { s.Entries = slices.Clone(*p.Entries) })
	set("ports", p.Ports != nil, func() { s.Ports = slices.Clone(*p.Ports) })
	set("sni_names", p.SNINames != nil, func() { s.SNINames = slices.Clone(*p.SNINames) })
	set("exclusions", p.Exclusions != nil, func() { s.Exclusions = slices.Clone(*p.Exclusions) })
	set("enabled", p.Enabled != nil, func() { s.Enabled = *p.Enabled })
	set("schedule", p.Schedule != nil, func() { s.Schedule = *p.Schedule })
	set("alert_on_expiry", p.AlertOnExpiry != nil, func() { s.AlertOnExpiry = *p.AlertOnExpiry })
	set("rate_per_sec", p.RatePerSec != nil, func() { s.RatePerSec = *p.RatePerSec })
	set("concurrency", p.Concurrency != nil, func() { s.Concurrency = *p.Concurrency })
	return s, changed
}

const defaultPage = 50

func pageSize(n int) int {
	if n < 1 || n > discovery.MaxPage-1 {
		return defaultPage
	}
	return n
}

const scopeColumns = `s.id, s.name::text, s.entries, s.ports, s.sni_names, s.exclusions, s.enabled, s.schedule_hours,
    coalesce(to_char(s.window_start, 'HH24:MI'), ''), coalesce(to_char(s.window_end, 'HH24:MI'), ''), s.window_tz, s.alert_on_expiry,
    s.rate_per_sec, s.concurrency, s.version, s.created_by, s.created_at, s.updated_at, s.last_scheduled_at, a.id, l.id, s.service_id
FROM discovery_scopes s
LEFT JOIN LATERAL (SELECT id FROM discovery_scans WHERE scope_id = s.id AND state IN ('queued', 'running') LIMIT 1) a ON true
LEFT JOIN LATERAL (SELECT id FROM discovery_scans WHERE scope_id = s.id AND state NOT IN ('queued', 'running')
    ORDER BY queued_at DESC, id DESC LIMIT 1) l ON true`

// scopeRow is a scope row and the id of its last finished scan.
type scopeRow struct {
	view ScopeView
	last uuid.NullUUID
}

func scanScope(row pgx.Row) (scopeRow, error) {
	var r scopeRow
	v := &r.view
	var hours *int
	err := row.Scan(&v.ID, &v.Scope.Name, &v.Scope.Entries, &v.Scope.Ports, &v.Scope.SNINames, &v.Scope.Exclusions, &v.Scope.Enabled, &hours,
		&v.Scope.Schedule.WindowStart, &v.Scope.Schedule.WindowEnd, &v.Scope.Schedule.TimeZone, &v.Scope.AlertOnExpiry, &v.Scope.RatePerSec,
		&v.Scope.Concurrency, &v.Version, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt, &v.LastScheduledAt, &v.ActiveScanID, &r.last,
		&v.ServiceID)
	if err != nil {
		return scopeRow{}, err
	}
	if hours != nil {
		v.Scope.Schedule.Hours = *hours
	}
	v.CreatedAt, v.UpdatedAt, v.LastScheduledAt = v.CreatedAt.UTC(), v.UpdatedAt.UTC(), utcPtr(v.LastScheduledAt)
	if v.Scope.SNINames == nil {
		v.Scope.SNINames = []string{}
	}
	if v.Scope.Exclusions == nil {
		v.Scope.Exclusions = []string{}
	}
	return r, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// getScope reads one live scope with its last scan.
func getScope(ctx context.Context, q db.Querier, id uuid.UUID) (ScopeView, error) {
	r, err := scanScope(q.QueryRow(ctx, `SELECT `+scopeColumns+` WHERE s.id = $1 AND s.deleted_at IS NULL`, id))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ScopeView{}, discovery.ErrScopeNotFound
	case err != nil:
		return ScopeView{}, fmt.Errorf("discoverysvc: read the scope: %w", err)
	}
	if r.last.Valid {
		last, err := getScan(ctx, q, r.last.UUID)
		if err != nil {
			return ScopeView{}, err
		}
		r.view.LastScan = &last
	}
	return r.view, nil
}

// GetScope reads a live scope (discovery.ErrScopeNotFound when it is deleted or unknown).
func (s *Service) GetScope(ctx context.Context, id uuid.UUID) (ScopeView, error) {
	return getScope(ctx, s.pool, id)
}

// ListScopes lists the live scopes, oldest first; more reports whether a page follows.
func (s *Service) ListScopes(ctx context.Context, f ScopeFilter) (list []ScopeView, more bool, err error) {
	n := pageSize(f.Limit)
	args := []any{n + 1, f.ServiceIDs}
	cond := " AND ($2::uuid[] IS NULL OR s.service_id = ANY($2))"
	if f.After != nil {
		cond += " AND (s.created_at, s.id) > ($3, $4)"
		args = append(args, f.After.CreatedAt, f.After.ID)
	}
	rows, err := s.pool.Query(ctx, `SELECT `+scopeColumns+` WHERE s.deleted_at IS NULL`+cond+` ORDER BY s.created_at, s.id LIMIT $1`, args...)
	if err != nil {
		return nil, false, fmt.Errorf("discoverysvc: list the scopes: %w", err)
	}
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (scopeRow, error) { return scanScope(r) })
	if err != nil {
		return nil, false, fmt.Errorf("discoverysvc: list the scopes: %w", err)
	}
	if more = len(got) > n; more {
		got = got[:n]
	}
	var lastIDs []uuid.UUID
	for _, r := range got {
		if r.last.Valid {
			lastIDs = append(lastIDs, r.last.UUID)
		}
	}
	scans, err := scansByID(ctx, s.pool, lastIDs)
	if err != nil {
		return nil, false, err
	}
	list = make([]ScopeView, 0, len(got))
	for _, r := range got {
		if sc, ok := scans[r.last.UUID]; r.last.Valid && ok {
			r.view.LastScan = &sc
		}
		list = append(list, r.view)
	}
	return list, more, nil
}

// scopeDetails are the audit details every scope row shares: ids, the name and counts.
func scopeDetails(id uuid.UUID, sc discovery.Scope) map[string]string {
	return map[string]string{"scope_id": id.String(), "name": sc.Name, "entries_count": strconv.Itoa(len(sc.Entries)),
		"ports_count": strconv.Itoa(len(sc.Ports)), "sni_names_count": strconv.Itoa(len(sc.SNINames)),
		"exclusions_count": strconv.Itoa(len(sc.Exclusions)), "enabled": strconv.FormatBool(sc.Enabled),
		"schedule_hours": strconv.Itoa(sc.Schedule.Hours)}
}

// validate checks sc against the stored rules and returns it canonical.
func (s *Service) validate(ctx context.Context, sc discovery.Scope) (discovery.Scope, error) {
	rules, err := readRules(ctx, s.pool)
	if err != nil {
		return discovery.Scope{}, err
	}
	return discovery.Validate(sc, rules)
}

// scheduleArgs are the schedule columns of sc: hours and the window as NULL when unset.
func scheduleArgs(sc discovery.Scope) (hours *int, start, end *string) {
	if sc.Schedule.Hours > 0 {
		h := sc.Schedule.Hours
		hours = &h
	}
	if sc.Schedule.WindowStart != "" {
		a, b := sc.Schedule.WindowStart, sc.Schedule.WindowEnd
		start, end = &a, &b
	}
	return hours, start, end
}

func nameTaken(err error) bool { return db.IsUniqueViolationOn(err, "discovery_scopes_name") }

// CreateScope is CreateScopeIn the Default service.
func (s *Service) CreateScope(ctx context.Context, a Actor, in discovery.Scope) (ScopeView, error) {
	return s.CreateScopeIn(ctx, a, in, uuid.Nil)
}

// CreateScopeIn validates in (the settings' allowed networks and exclusions, then ALC-DSC-0010 for its host names) and
// stores it canonical with the discovery.scope.created row in one transaction, in the service named (R49; uuid.Nil: the
// Default service; an unknown one is refused before any name is looked up).
func (s *Service) CreateScopeIn(ctx context.Context, a Actor, in discovery.Scope, service uuid.UUID) (ScopeView, error) {
	sc, err := s.validate(ctx, in)
	if err != nil {
		return ScopeView{}, err
	}
	if _, err := authz.ResolveService(ctx, s.pool, service); err != nil {
		return ScopeView{}, err
	}
	if err := s.checkNames(ctx, in.Entries, sc.Entries, nil); err != nil {
		return ScopeView{}, err
	}
	id, now := uuid.New(), s.now()
	hours, start, end := scheduleArgs(sc)
	var v ScopeView
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		service, err := authz.ResolveService(ctx, tx, service)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO discovery_scopes (id, name, entries, ports, sni_names, exclusions, enabled, schedule_hours, window_start,
    window_end, window_tz, alert_on_expiry, rate_per_sec, concurrency, created_by, created_at, updated_at, service_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::time, $10::time, $11, $12, $13, $14, $15, $16, $16, $17)`, id, sc.Name, sc.Entries, sc.Ports,
			nonNil(sc.SNINames), nonNil(sc.Exclusions), sc.Enabled, hours, start, end, sc.Schedule.TimeZone, sc.AlertOnExpiry, sc.RatePerSec,
			sc.Concurrency, a.userRef(), now, service)
		switch {
		case nameTaken(err):
			return ErrNameTaken
		case err != nil:
			return fmt.Errorf("discoverysvc: store the scope: %w", err)
		}
		if err := s.appendAudit(ctx, tx, a, "discovery.scope.created", "discovery_scope", id.String(), scopeDetails(id, sc)); err != nil {
			return err
		}
		v, err = getScope(ctx, tx, id)
		return err
	})
	return v, err
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// UpdateScope changes a live scope: ifVersion (nil: any) must be its version (ErrVersion). The result is validated like
// a new scope and only the host names it adds are looked up. In one transaction with the discovery.scope.updated row:
// the scope (version + 1), its endpoints that left the scope marked gone at once (A4), and, when it is switched off, the
// cancellation of its scan in flight.
func (s *Service) UpdateScope(ctx context.Context, a Actor, id uuid.UUID, ifVersion *int, p ScopePatch) (ScopeView, error) {
	cur, err := s.GetScope(ctx, id)
	if err != nil {
		return ScopeView{}, err
	}
	if ifVersion != nil && *ifVersion != cur.Version {
		return ScopeView{}, ErrVersion
	}
	next, changed := p.apply(cur.Scope)
	if len(changed) == 0 {
		return ScopeView{}, validate.Errors{{Field: "body", Code: validate.Required}} // nothing to change (Task 9 review 8)
	}
	sc, err := s.validate(ctx, next)
	if err != nil {
		return ScopeView{}, err
	}
	if err := s.checkNames(ctx, next.Entries, sc.Entries, cur.Scope.Entries); err != nil {
		return ScopeView{}, err
	}
	shape, err := shapeOf(sc)
	if err != nil {
		return ScopeView{}, err
	}
	now := s.now()
	hours, start, end := scheduleArgs(sc)
	var v ScopeView
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// The scope's scan in flight is locked first, as Ingest locks it before the endpoints: the other order deadlocks,
		// and a batch waiting here then finds the cancel flag this transaction sets.
		if err := lockActiveScans(ctx, tx, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE discovery_scopes SET name = $3, entries = $4, ports = $5, sni_names = $6, exclusions = $7, enabled = $8,
    schedule_hours = $9, window_start = $10::time, window_end = $11::time, window_tz = $12, alert_on_expiry = $13, rate_per_sec = $14,
    concurrency = $15, version = version + 1, updated_at = $16
WHERE id = $1 AND version = $2 AND deleted_at IS NULL`, id, cur.Version, sc.Name, sc.Entries, sc.Ports, nonNil(sc.SNINames),
			nonNil(sc.Exclusions), sc.Enabled, hours, start, end, sc.Schedule.TimeZone, sc.AlertOnExpiry, sc.RatePerSec, sc.Concurrency, now)
		switch {
		case nameTaken(err):
			return ErrNameTaken
		case err != nil:
			return fmt.Errorf("discoverysvc: change the scope: %w", err)
		case tag.RowsAffected() == 0:
			if _, err := getScope(ctx, tx, id); err != nil {
				return err
			}
			return ErrVersion // changed by another request since it was read
		}
		gone, err := markGone(ctx, tx, id, shape, now)
		if err != nil {
			return err
		}
		var cancelled int64
		if !sc.Enabled || changesTargets(changed) {
			if cancelled, err = cancelActive(ctx, tx, id); err != nil {
				return err
			}
		}
		d := scopeDetails(id, sc)
		d["changed"] = strings.Join(changed, ",")
		d["endpoints_gone_count"], d["scans_cancelled_count"] = strconv.FormatInt(gone, 10), strconv.FormatInt(cancelled, 10)
		if err := s.appendAudit(ctx, tx, a, "discovery.scope.updated", "discovery_scope", id.String(), d); err != nil {
			return err
		}
		v, err = getScope(ctx, tx, id)
		return err
	})
	return v, err
}

// changesTargets reports whether a change touches what the scope's scans connect to: its scan in flight is then asked
// to stop (it was expanded from the old scope), as when the scope is switched off (Task 9 review 5).
func changesTargets(changed []string) bool {
	return slices.ContainsFunc(changed, func(f string) bool {
		return f == "entries" || f == "ports" || f == "sni_names" || f == "exclusions"
	})
}

// shape is what a scope covers, as the endpoint rows key it: the ports, the address and range entries, the scope's own
// exclusions, the SNI names a literal endpoint carries (” when the scope lists none) and the host names.
type shape struct {
	ports      []int32
	ranges     []netip.Prefix
	exclusions []netip.Prefix
	snis       []string
	hosts      []string
}

func shapeOf(sc discovery.Scope) (shape, error) {
	var sh shape
	for _, p := range sc.Ports {
		sh.ports = append(sh.ports, int32(p)) //nolint:gosec // G115: ports are 1..65535 (validated)
	}
	for _, raw := range sc.Entries {
		e, err := discovery.ParseEntry(raw)
		if err != nil {
			return shape{}, err
		}
		if e.Kind == discovery.KindHost {
			sh.hosts = append(sh.hosts, e.Host)
		} else {
			sh.ranges = append(sh.ranges, e.Prefix)
		}
	}
	for _, raw := range sc.Exclusions {
		p, err := discovery.ParseExclusion(raw)
		if err != nil {
			return shape{}, err
		}
		sh.exclusions = append(sh.exclusions, p)
	}
	sh.snis = append(sh.snis, sc.SNINames...)
	if len(sh.snis) == 0 {
		sh.snis = []string{""}
	}
	sh.ranges, sh.exclusions, sh.hosts = nonNilP(sh.ranges), nonNilP(sh.exclusions), nonNil(sh.hosts)
	return sh, nil
}

func nonNilP(l []netip.Prefix) []netip.Prefix {
	if l == nil {
		return []netip.Prefix{}
	}
	return l
}

// markGone marks gone the endpoints of the scope that its new shape no longer covers: a port it no longer lists; for an
// address entry's endpoint, an address outside every address and range entry or inside one of the scope's exclusions,
// or an SNI name it no longer sends; for a host name's endpoint, a name it no longer lists.
func markGone(ctx context.Context, tx pgx.Tx, scope uuid.UUID, sh shape, now time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE discovery_endpoints e SET state = 'gone', gone_since = $2
WHERE e.scope_id = $1 AND e.state <> 'gone' AND (
    NOT (e.port = ANY ($3::int[]))
 OR (e.host = '' AND NOT (e.address <<= ANY ($4::cidr[])))
 OR (e.host = '' AND e.address <<= ANY ($5::cidr[]))
 OR (e.host = '' AND NOT (e.sni = ANY ($6::text[])))
 OR (e.host <> '' AND NOT (e.host = ANY ($7::text[]))))`, scope, now, sh.ports, sh.ranges, sh.exclusions, sh.snis, sh.hosts)
	if err != nil {
		return 0, fmt.Errorf("discoverysvc: mark the endpoints that left the scope: %w", err)
	}
	return tag.RowsAffected(), nil
}

// lockActiveScans locks the scope's scans in flight (queued or running) in id order.
func lockActiveScans(ctx context.Context, tx pgx.Tx, scope uuid.UUID) error {
	if _, err := tx.Exec(ctx, `SELECT id FROM discovery_scans WHERE scope_id = $1 AND state IN ('queued', 'running') ORDER BY id FOR UPDATE`, scope); err != nil {
		return fmt.Errorf("discoverysvc: lock the scope's scan: %w", err)
	}
	return nil
}

// cancelActive asks the scope's scan in flight to stop.
func cancelActive(ctx context.Context, tx pgx.Tx, scope uuid.UUID) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE discovery_scans SET cancel_requested = true WHERE scope_id = $1 AND state IN ('queued', 'running')
  AND NOT cancel_requested`, scope)
	if err != nil {
		return 0, fmt.Errorf("discoverysvc: cancel the scope's scan: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteScope soft-deletes a live scope (its name is free again) and asks its scan in flight to stop, with the
// discovery.scope.deleted row in the same transaction. Its endpoints are removed by retention.
func (s *Service) DeleteScope(ctx context.Context, a Actor, id uuid.UUID, ifVersion *int) error {
	now := s.now()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var version int
		var name string
		err := tx.QueryRow(ctx, `SELECT version, name::text FROM discovery_scopes WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&version, &name)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return discovery.ErrScopeNotFound
		case err != nil:
			return fmt.Errorf("discoverysvc: read the scope: %w", err)
		case ifVersion != nil && *ifVersion != version:
			return ErrVersion
		}
		if _, err := tx.Exec(ctx, `UPDATE discovery_scopes SET deleted_at = $2, updated_at = $2, version = version + 1 WHERE id = $1`, id, now); err != nil {
			return fmt.Errorf("discoverysvc: delete the scope: %w", err)
		}
		cancelled, err := cancelActive(ctx, tx, id)
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, a, "discovery.scope.deleted", "discovery_scope", id.String(), map[string]string{
			"scope_id": id.String(), "name": name, "scans_cancelled_count": strconv.FormatInt(cancelled, 10)})
	})
}

// Preview validates sc against the settings and returns its size: no name is looked up and nothing is dialed.
func (s *Service) Preview(ctx context.Context, sc discovery.Scope) (discovery.Preview, error) {
	rules, err := readRules(ctx, s.pool)
	if err != nil {
		return discovery.Preview{}, err
	}
	return discovery.PreviewScope(sc, rules)
}

// cancelAllActive asks every scan in flight to stop (the settings changed what a scan may connect to). The scans are
// locked in id order first, as Ingest locks its scan before anything else.
func cancelAllActive(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE discovery_scans SET cancel_requested = true WHERE id IN (
    SELECT id FROM discovery_scans WHERE state IN ('queued', 'running') AND NOT cancel_requested ORDER BY id FOR UPDATE)`)
	if err != nil {
		return 0, fmt.Errorf("discoverysvc: cancel the scans in flight: %w", err)
	}
	return tag.RowsAffected(), nil
}
