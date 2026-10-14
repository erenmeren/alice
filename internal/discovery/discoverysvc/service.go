// Package discoverysvc is the service behind the network discovery API (plan 2026-10-13-network-discovery, Task 9):
// scan scopes (validated with internal/discovery at save time, their new host names looked up once), the discovery
// settings (allowed scan networks, global exclusions, retention), scans (queued together with their job through
// netdiscojobs.StartTx), and the read side (discovered certificates and endpoints, the Overview summary). Every change
// writes its audit row in the transaction of the change; details hold ids, names, counts and the Administrator's own
// lists, never a certificate and never an address a name resolved to.
package discoverysvc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/discovery"
	"alice/internal/jobs/netdiscojobs"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

// Errors of the service besides the discovery package's (discovery.ErrScopeNotFound ALC-DSC-0008,
// discovery.ErrScanRunning ALC-DSC-0004, *discovery.Error ALC-DSC-0001/0002/0003/0009).
var (
	// ErrNotFound: no scan or discovered certificate has that id.
	ErrNotFound = errors.New("discoverysvc: not found")
	// ErrNameTaken is ALC-DSC-0011: a live scope has that name (case-insensitively).
	ErrNameTaken = errors.New("discoverysvc: a scope of that name exists")
	// ErrNameUnresolved is ALC-DSC-0010 (a *NameUnresolvedError names the entry).
	ErrNameUnresolved = errors.New("discoverysvc: a host name of the scope does not resolve")
	// ErrTooManyScans is ALC-DSC-0007: MaxActiveScans scans are queued or running (a manual start is refused, not queued).
	ErrTooManyScans = errors.New("discoverysvc: too many scans are active")
	// ErrScopeDisabled is ALC-DSC-0013: the scope is switched off (it is scanned neither by its schedule nor by hand).
	ErrScopeDisabled = errors.New("discoverysvc: the scope is switched off")
	// ErrLookupBudget: the save-time look-ups of the scope's new host names did not all answer within the request's
	// budget; nothing was decided or saved (503, retry later). Not ALC-DSC-0010: a slow name server is not a missing name.
	ErrLookupBudget = errors.New("discoverysvc: the host name look-ups did not finish in time")
	// ErrVersion: the If-Match version is not the scope's.
	ErrVersion = errors.New("discoverysvc: the scope changed since it was read")
)

// NameUnresolvedError is ErrNameUnresolved for the entry at Index of the list as sent. It never carries an address.
type NameUnresolvedError struct{ Index int }

func (e *NameUnresolvedError) Error() string {
	return ErrNameUnresolved.Error() + ": entries[" + strconv.Itoa(e.Index) + "]"
}

func (e *NameUnresolvedError) Unwrap() error { return ErrNameUnresolved }

// Limits of the settings (design decision 3).
const (
	DefaultRetentionDays = 90
	MinRetentionDays     = 7
	MaxRetentionDays     = 730
)

// MaxActiveScans is how many scans may be queued or running at once (design decision 1; the runner's cap).
const MaxActiveScans = 2

// defaultResolveBudget bounds the save-time look-ups of one request together; resolveWorkers how many run at once
// (MaxNewNames names at resolveWorkers at a time take two rounds of discovery.ResolveTimeout at most, so the budget is
// spent only by a name server slower than that).
const (
	defaultResolveBudget = 15 * time.Second
	resolveWorkers       = 8
)

// startLock is the transaction advisory lock that serialises manual scan starts, so two starts cannot both see one
// active scan and make three (the runner's cap holds anyway).
const startLock int64 = 7160927315633811401

// Actor is who acts: the audit identity, the user (a scope's creator, a scan's requester) and the role (job metadata).
type Actor struct {
	Audit  audit.Actor
	UserID uuid.UUID
	Role   string
}

func (a Actor) userRef() *uuid.UUID {
	if a.UserID == uuid.Nil {
		return nil
	}
	return &a.UserID
}

// Config are the service's dependencies. Resolver looks up the scopes' host names at save time (nil: the system
// resolver, the only one a release build uses).
type Config struct {
	Pool     *pgxpool.Pool
	Audit    *audit.Log
	Queue    netdiscojobs.Enqueuer
	Clock    clock.Clock
	Resolver discovery.Resolver
}

// Service is the discovery service.
type Service struct {
	pool           *pgxpool.Pool
	audit          *audit.Log
	queue          netdiscojobs.Enqueuer
	clock          clock.Clock
	resolver       discovery.Resolver
	resolveTimeout time.Duration
	resolveBudget  time.Duration
}

// New builds the service.
func New(c Config) *Service {
	r := c.Resolver
	if r == nil {
		r = discovery.SystemResolver
	}
	return &Service{pool: c.Pool, audit: c.Audit, queue: c.Queue, clock: c.Clock, resolver: r, resolveTimeout: discovery.ResolveTimeout,
		resolveBudget: defaultResolveBudget}
}

func (s *Service) now() time.Time { return s.clock.Now().UTC() }

// appendAudit writes one success row in tx.
func (s *Service) appendAudit(ctx context.Context, tx pgx.Tx, a Actor, action, objectType, objectID string, details map[string]string) error {
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: action, ObjectType: objectType, ObjectID: objectID,
		Result: audit.Success, Details: details})
	if err != nil {
		return fmt.Errorf("discoverysvc: audit %s: %w", action, err)
	}
	return nil
}

// --- settings ---

// Settings are the discovery settings: the allowed scan networks (empty: nothing may be scanned), the global exclusions
// and how many days gone endpoints are kept.
type Settings struct {
	AllowedNetworks  []string
	GlobalExclusions []string
	RetentionDays    int
}

// SettingsView is the settings as stored, and whether anything may be scanned at all.
type SettingsView struct {
	Settings
	ScanningEnabled bool
}

// Settings reads the settings; an absent row is the default (no networks, no exclusions, 90 days).
func (s *Service) Settings(ctx context.Context) (SettingsView, error) {
	return readSettings(ctx, s.pool)
}

func readSettings(ctx context.Context, q db.Querier) (SettingsView, error) {
	v := SettingsView{Settings: Settings{AllowedNetworks: []string{}, GlobalExclusions: []string{}, RetentionDays: DefaultRetentionDays}}
	if _, err := settings.Get(ctx, q, discovery.SettingAllowedNetworks, &v.AllowedNetworks); err != nil {
		return SettingsView{}, err
	}
	if _, err := settings.Get(ctx, q, discovery.SettingExclusions, &v.GlobalExclusions); err != nil {
		return SettingsView{}, err
	}
	if _, err := settings.Get(ctx, q, discovery.SettingRetentionDays, &v.RetentionDays); err != nil {
		return SettingsView{}, err
	}
	if v.AllowedNetworks == nil {
		v.AllowedNetworks = []string{}
	}
	if v.GlobalExclusions == nil {
		v.GlobalExclusions = []string{}
	}
	allowed, err := discovery.ParseNetworks(v.AllowedNetworks)
	v.ScanningEnabled = err == nil && len(allowed) > 0
	return v, nil
}

// rules are the parsed settings a scope is validated against; a list that does not parse allows nothing (fail closed).
func readRules(ctx context.Context, q db.Querier) (discovery.Rules, error) {
	v, err := readSettings(ctx, q)
	if err != nil {
		return discovery.Rules{}, err
	}
	allowed, aerr := discovery.ParseNetworks(v.AllowedNetworks)
	excluded, xerr := discovery.ParseNetworks(v.GlobalExclusions)
	if aerr != nil || xerr != nil {
		return discovery.Rules{}, nil
	}
	return discovery.Rules{AllowedNetworks: allowed, GlobalExclusions: excluded}, nil
}

// canonicalNetworks parses a settings list and returns it canonical (an address without its length, de-duplicated,
// first kept); a refusal names field and the element.
func canonicalNetworks(field string, list []string) ([]string, error) {
	ps, err := discovery.ParseNetworks(list)
	if err != nil {
		var de *discovery.Error
		if errors.As(err, &de) {
			de.Field = field
		}
		return nil, err
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		str := p.String()
		if p.IsSingleIP() {
			str = p.Addr().String()
		}
		if !slices.Contains(out, str) {
			out = append(out, str)
		}
	}
	return out, nil
}

// SaveSettings replaces the settings, with the discovery.exclusions.updated row in the same transaction. The lists are
// stored canonical; an element that does not parse, or a retention outside 7..730 days, is a *discovery.Error naming
// the field (allowed_networks, global_exclusions, retention_days). An empty allowed list is valid: nothing may be
// scanned then.
func (s *Service) SaveSettings(ctx context.Context, a Actor, in Settings) (SettingsView, error) {
	allowed, err := canonicalNetworks("allowed_networks", in.AllowedNetworks)
	if err != nil {
		return SettingsView{}, err
	}
	excluded, err := canonicalNetworks("global_exclusions", in.GlobalExclusions)
	if err != nil {
		return SettingsView{}, err
	}
	if in.RetentionDays < MinRetentionDays || in.RetentionDays > MaxRetentionDays {
		return SettingsView{}, &discovery.Error{Kind: discovery.ErrInvalid, Field: "retention_days", Index: -1,
			Detail: fmt.Sprintf("%d to %d days", MinRetentionDays, MaxRetentionDays)}
	}
	now := s.now()
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		for key, v := range map[string]any{discovery.SettingAllowedNetworks: allowed, discovery.SettingExclusions: excluded,
			discovery.SettingRetentionDays: in.RetentionDays} {
			if err := settings.Set(ctx, tx, key, v, now); err != nil {
				return err
			}
		}
		return s.appendAudit(ctx, tx, a, "discovery.exclusions.updated", "discovery_settings", "", map[string]string{
			"allowed_networks": strings.Join(allowed, ", "), "allowed_networks_count": strconv.Itoa(len(allowed)),
			"global_exclusions": strings.Join(excluded, ", "), "global_exclusions_count": strconv.Itoa(len(excluded)),
			"retention_days": strconv.Itoa(in.RetentionDays)})
	})
	if err != nil {
		return SettingsView{}, err
	}
	return SettingsView{Settings: Settings{AllowedNetworks: allowed, GlobalExclusions: excluded, RetentionDays: in.RetentionDays},
		ScanningEnabled: len(allowed) > 0}, nil
}

// --- the save-time look-up (ALC-DSC-0010) ---

// MaxNewNames is how many host names one save may add (each is looked up at save time).
const MaxNewNames = 16

// lookup outcomes of one name.
const (
	lookupUndecided = iota // not answered before the budget was spent
	lookupResolved
	lookupUnresolved
)

// checkNames looks up each host name of canon that old does not have (every look-up its own 5-second deadline, all of
// them within the request's budget, resolveWorkers at a time). More than MaxNewNames new names is a validation error of
// entries (nothing is looked up). It returns a *NameUnresolvedError (ALC-DSC-0010) for the first name that gives no
// address, at its index in sent; when no name was refused but the budget was spent before every name was answered, it
// returns ErrLookupBudget (retry later). The addresses are never kept, returned or logged.
func (s *Service) checkNames(ctx context.Context, sent []string, canon, old []string) error {
	var hosts []string
	for _, e := range canon {
		pe, err := discovery.ParseEntry(e)
		if err == nil && pe.Kind == discovery.KindHost && !slices.Contains(old, e) {
			hosts = append(hosts, e)
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	if len(hosts) > MaxNewNames {
		return validate.Errors{{Field: "entries", Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(MaxNewNames)}}}
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, s.resolveBudget)
	defer cancel()
	outcome := make([]int, len(hosts))
	work := make(chan int)
	var wg sync.WaitGroup
	for range min(resolveWorkers, len(hosts)) {
		wg.Go(func() {
			for i := range work {
				if ctx.Err() != nil {
					continue // the budget is spent: undecided
				}
				lctx, lcancel := context.WithTimeout(ctx, s.resolveTimeout)
				addrs, err := s.resolver.LookupNetIP(lctx, "ip", hosts[i])
				lcancel()
				switch {
				case err == nil && slices.ContainsFunc(addrs, netip.Addr.IsValid):
					outcome[i] = lookupResolved
				case ctx.Err() != nil:
					// the budget, not the name's own deadline, ended it: undecided
				default:
					outcome[i] = lookupUnresolved
				}
			}
		})
	}
	for i := range hosts {
		work <- i
	}
	close(work)
	wg.Wait()
	if err := parent.Err(); err != nil {
		return err // the request ended: nothing is decided about the names
	}
	for i, h := range hosts {
		if outcome[i] == lookupUnresolved {
			return &NameUnresolvedError{Index: sentIndex(sent, h)}
		}
	}
	if slices.Contains(outcome, lookupUndecided) {
		return ErrLookupBudget
	}
	return nil
}

// sentIndex is the index of the first entry of sent whose canonical form is canon (0 if none: cannot happen).
func sentIndex(sent []string, canon string) int {
	for i, raw := range sent {
		if e, err := discovery.ParseEntry(raw); err == nil && e.String() == canon {
			return i
		}
	}
	return 0
}
