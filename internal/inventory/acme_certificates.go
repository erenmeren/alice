package inventory

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

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// ACME certificate definitions (plan 2026-10-13 Task 10; design rows 1, 6, 7; amendments A9, A13).
//
// An ACME certificate is the ordered identity: the provider (and its current active account), the names, the key
// policy, the proof method (DNS-01 through a hook, HTTP-01 through the managed Nginx server the names point at) and
// the renewal settings. Creating, changing and deleting one is an Administrator's act (the API's AcmeManage with
// step-up, A9); the service takes the Actor for the audit row and the created_by column and does not check roles.
//
// Every name must be admitted by the provider's allow-list AND, for DNS-01, by the hook's (label boundaries; an empty
// list admits nothing): ErrACMENameNotAllowed (ALC-ACM-0015) otherwise. A wildcard needs DNS-01. The key policy
// cannot change while the certificate has bindings (A13/M2: the bound locations hold a key of the old type;
// ErrACMEKeyTypeLocked, ALC-ACM-0018), and nothing an order uses (names, provider, proof method, hook, server, key
// policy) changes while an order runs (ErrACMEOrderRunning, ALC-ACM-0016). No network call is made here.

// ACME certificate states (acme_certificates.state).
const (
	ACMEStatePending = "pending" // never issued
	ACMEStateIssuing = "issuing" // an issue order runs
	ACMEStateActive  = "active"  // the last order issued the current certificate
	ACMEStateFailing = "failing" // the last order failed
	ACMEStateStopped = "stopped" // automatic renewal stopped after repeated failures (Task 11)
)

// Proof methods (acme_certificates.challenge).
const (
	ACMEChallengeDNS01  = "dns01"
	ACMEChallengeHTTP01 = "http01"
)

// DefaultACMERenewBeforeDays is a new certificate's renewal window; the window is 1..60 days.
const (
	DefaultACMERenewBeforeDays = 30
	minACMERenewBeforeDays     = 1
	maxACMERenewBeforeDays     = 60
)

// Refusals of the ACME certificate definitions and orders.
var (
	// ErrACMENameNotAllowed: a name is outside the provider's (or, for DNS-01, the hook's) allow-list (A9).
	ErrACMENameNotAllowed = errors.New("inventory: a name is not allowed by the certificate authority's or the DNS hook's list")
	// ErrACMEOrderRunning: an order of the certificate is running (one at a time; what it uses cannot change).
	ErrACMEOrderRunning = errors.New("inventory: an order of the ACME certificate is running")
	// ErrACMEChallengeUnavailable: the proof method cannot serve these names or this server (a wildcard over
	// HTTP-01, an HTTP-01 server that is not an Nginx server).
	ErrACMEChallengeUnavailable = errors.New("inventory: the proof method cannot be used for these names or this server")
	// ErrACMEKeyTypeLocked: the key policy of a certificate with bindings cannot change (A13/M2).
	ErrACMEKeyTypeLocked = errors.New("inventory: the key type of an ACME certificate with bound locations cannot change")
)

// ACMECertificate is the view of an ACME certificate definition. It has no secret.
type ACMECertificate struct {
	ID                   uuid.UUID  `json:"id"`
	ProviderID           uuid.UUID  `json:"provider_id"`
	AccountID            uuid.UUID  `json:"account_id"`
	Names                []string   `json:"names"`
	KeyType              string     `json:"key_type"`
	Challenge            string     `json:"challenge"`
	HookID               *uuid.UUID `json:"hook_id,omitempty"`
	HTTPTargetID         *uuid.UUID `json:"http_target_id,omitempty"`
	RenewBeforeDays      int        `json:"renew_before_days"`
	AutoRenew            bool       `json:"auto_renew"`
	AutoDeploy           bool       `json:"auto_deploy"`
	State                string     `json:"state"`
	CurrentCertificateID *uuid.UUID `json:"current_certificate_id,omitempty"`
	Failures             int        `json:"failures"`
	NextAttemptAt        *time.Time `json:"next_attempt_at,omitempty"`
	LastAttemptAt        *time.Time `json:"last_attempt_at,omitempty"`
	LastErrorCode        string     `json:"last_error_code"`
	RunningOrderID       *uuid.UUID `json:"running_order_id,omitempty"`
	Bindings             int        `json:"bindings"`
	CreatedBy            *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// ACMECertificateInput is the input of CreateACMECertificate. KeyType "" is ecdsa_p256; RenewBeforeDays 0 is 30;
// AutoRenew nil is true. HookID is required for dns01 and HTTPTargetID for http01 (the other must be nil).
type ACMECertificateInput struct {
	ProviderID      uuid.UUID
	Names           []string
	KeyType         string
	Challenge       string
	HookID          *uuid.UUID
	HTTPTargetID    *uuid.UUID
	RenewBeforeDays int
	AutoRenew       *bool
	AutoDeploy      bool
}

// ACMECertificatePatch is the input of UpdateACMECertificate: nil fields stay. When the proof method changes, the id
// the old method used is dropped (a dns01 certificate has no server, an http01 one no hook).
type ACMECertificatePatch struct {
	ProviderID      *uuid.UUID
	Names           *[]string
	KeyType         *string
	Challenge       *string
	HookID          *uuid.UUID
	HTTPTargetID    *uuid.UUID
	RenewBeforeDays *int
	AutoRenew       *bool
	AutoDeploy      *bool
}

// acmeCertFields are the stored values of a definition.
type acmeCertFields struct {
	providerID   uuid.UUID
	names        []string
	keyType      string
	challenge    string
	hookID       *uuid.UUID
	httpTargetID *uuid.UUID
	renewBefore  int
	autoRenew    bool
	autoDeploy   bool
}

// normACMENames applies acme.NormalizeNames as field errors: 1..100 DNS names, a wildcard only as the whole first
// label, no IP addresses, no duplicates; lower case.
func normACMENames(field string, in []string) ([]string, *validate.FieldError) {
	switch {
	case len(in) == 0:
		return nil, &validate.FieldError{Field: field, Code: validate.Required}
	case len(in) > acme.MaxNames:
		return nil, &validate.FieldError{Field: field, Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(acme.MaxNames)}}
	}
	trimmed := make([]string, len(in))
	for i, n := range in {
		trimmed[i] = strings.TrimSpace(n)
	}
	out, err := acme.NormalizeNames(trimmed)
	if err != nil {
		return nil, &validate.FieldError{Field: field, Code: validate.Pattern}
	}
	return out, nil
}

// validateACMECertFields checks the values that need no database: names, key policy, proof method and its id, the
// renewal window, and a wildcard only over DNS-01.
func validateACMECertFields(f acmeCertFields) validate.Errors {
	var errs validate.Errors
	if _, err := keygen.ParseKeyPolicy(f.keyType); err != nil {
		vals := make([]string, 0, 5)
		for _, p := range keygen.Policies() {
			vals = append(vals, string(p))
		}
		errs.Add("key_type", validate.OneOf, map[string]string{"values": strings.Join(vals, ", ")})
	}
	switch f.challenge {
	case ACMEChallengeDNS01:
		if f.hookID == nil {
			errs.Add("hook_id", validate.Required, nil)
		}
	case ACMEChallengeHTTP01:
		if f.httpTargetID == nil {
			errs.Add("http_target_id", validate.Required, nil)
		}
	default:
		errs.Add("challenge", validate.OneOf, map[string]string{"values": ACMEChallengeDNS01 + ", " + ACMEChallengeHTTP01})
	}
	if f.renewBefore < minACMERenewBeforeDays || f.renewBefore > maxACMERenewBeforeDays {
		errs.Add("renew_before_days", validate.OutOfRange, map[string]string{"min": strconv.Itoa(minACMERenewBeforeDays),
			"max": strconv.Itoa(maxACMERenewBeforeDays)})
	}
	if f.providerID == uuid.Nil {
		errs.Add("provider_id", validate.Required, nil)
	}
	return errs
}

func hasWildcard(names []string) bool {
	return slices.ContainsFunc(names, func(n string) bool { return strings.HasPrefix(n, "*.") })
}

// checkACMECertRefs checks, in tx, what the definition refers to: a live provider with an active account (its id is
// returned), a live hook (dns01) or a live Nginx server (http01), the allow-lists of the provider and the hook, and a
// wildcard only over DNS-01. Missing rows are field errors (the request named something that is not there).
func checkACMECertRefs(ctx context.Context, tx pgx.Tx, f acmeCertFields) (uuid.UUID, error) {
	p, err := getACMEProvider(ctx, tx, f.providerID, false)
	if errors.Is(err, ErrNotFound) {
		return uuid.Nil, validate.Errors{{Field: "provider_id", Code: validate.Required}}
	}
	if err != nil {
		return uuid.Nil, err
	}
	if p.ActiveAccountID == nil {
		return uuid.Nil, ErrACMEAccountState
	}
	var hookSuffixes []string
	switch f.challenge {
	case ACMEChallengeDNS01:
		h, err := getACMEHook(ctx, tx, *f.hookID, false)
		if errors.Is(err, ErrNotFound) {
			return uuid.Nil, validate.Errors{{Field: "hook_id", Code: validate.Required}}
		}
		if err != nil {
			return uuid.Nil, err
		}
		hookSuffixes = h.AllowedSuffixes
	case ACMEChallengeHTTP01:
		if hasWildcard(f.names) {
			return uuid.Nil, ErrACMEChallengeUnavailable
		}
		var typ string
		err := tx.QueryRow(ctx, "SELECT type FROM targets WHERE id = $1 AND deleted_at IS NULL", *f.httpTargetID).Scan(&typ)
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, validate.Errors{{Field: "http_target_id", Code: validate.Required}}
		}
		if err != nil {
			return uuid.Nil, fmt.Errorf("inventory: read the HTTP-01 server: %w", err)
		}
		if typ != TypeNginx { // only the nginx profile's sudoers file has the HTTP-01 token lines
			return uuid.Nil, ErrACMEChallengeUnavailable
		}
	}
	for _, n := range f.names {
		if !ACMENameAllowed(p.AllowedSuffixes, n) || (f.challenge == ACMEChallengeDNS01 && !ACMENameAllowed(hookSuffixes, n)) {
			return uuid.Nil, ErrACMENameNotAllowed
		}
	}
	return *p.ActiveAccountID, nil
}

const acmeCertColumns = `c.id, c.provider_id, c.account_id, c.names, c.key_type, c.challenge, c.hook_id, c.http_target_id, c.renew_before_days,
c.auto_renew, c.auto_deploy, c.state, c.current_certificate_id, c.failures, c.next_attempt_at, c.last_attempt_at, c.last_error_code,
(SELECT o.id FROM acme_orders o WHERE o.acme_certificate_id = c.id AND o.state = 'running'),
(SELECT count(*) FROM acme_bindings b WHERE b.acme_certificate_id = c.id),
c.created_by, c.created_at, c.updated_at`

func scanACMECert(row pgx.Row) (ACMECertificate, error) {
	var c ACMECertificate
	err := row.Scan(&c.ID, &c.ProviderID, &c.AccountID, &c.Names, &c.KeyType, &c.Challenge, &c.HookID, &c.HTTPTargetID, &c.RenewBeforeDays,
		&c.AutoRenew, &c.AutoDeploy, &c.State, &c.CurrentCertificateID, &c.Failures, &c.NextAttemptAt, &c.LastAttemptAt, &c.LastErrorCode,
		&c.RunningOrderID, &c.Bindings, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	c.CreatedAt, c.UpdatedAt = c.CreatedAt.UTC(), c.UpdatedAt.UTC()
	for _, t := range []**time.Time{&c.NextAttemptAt, &c.LastAttemptAt} {
		if *t != nil {
			u := (*t).UTC()
			*t = &u
		}
	}
	return c, err
}

func getACMECert(ctx context.Context, q db.Querier, id uuid.UUID, forUpdate bool) (ACMECertificate, error) {
	sql := "SELECT " + acmeCertColumns + " FROM acme_certificates c WHERE c.id = $1 AND c.deleted_at IS NULL"
	if forUpdate {
		sql += " FOR UPDATE OF c"
	}
	c, err := scanACMECert(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMECertificate{}, ErrNotFound
	}
	if err != nil {
		return ACMECertificate{}, fmt.Errorf("inventory: read the ACME certificate: %w", err)
	}
	if forUpdate {
		// Under READ COMMITTED a row lock re-checks only the locked row: the subqueries above kept the snapshot the
		// statement started with, before a concurrent RequestOrder (or binding) that held the lock committed. Read
		// them again in statements of their own, which see everything committed before the lock was granted.
		c.RunningOrderID = nil
		err := q.QueryRow(ctx, "SELECT id FROM acme_orders WHERE acme_certificate_id = $1 AND state = 'running'", id).Scan(&c.RunningOrderID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ACMECertificate{}, fmt.Errorf("inventory: read the ACME certificate's running order: %w", err)
		}
		if err := q.QueryRow(ctx, "SELECT count(*) FROM acme_bindings WHERE acme_certificate_id = $1", id).Scan(&c.Bindings); err != nil {
			return ACMECertificate{}, fmt.Errorf("inventory: count the ACME certificate's bindings: %w", err)
		}
	}
	return c, nil
}

// GetACMECertificate returns a live ACME certificate (ErrNotFound otherwise).
func (s *Service) GetACMECertificate(ctx context.Context, id uuid.UUID) (ACMECertificate, error) {
	return getACMECert(ctx, s.pool, id, false)
}

// ListACMECertificates returns the live ACME certificates, oldest first.
func (s *Service) ListACMECertificates(ctx context.Context) ([]ACMECertificate, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+acmeCertColumns+" FROM acme_certificates c WHERE c.deleted_at IS NULL ORDER BY c.created_at, c.id")
	if err != nil {
		return nil, fmt.Errorf("inventory: list the ACME certificates: %w", err)
	}
	defer rows.Close()
	out := []ACMECertificate{}
	for rows.Next() {
		c, err := scanACMECert(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: read an ACME certificate: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// acmeCertDetails are the audit details of a definition: ids, names (bounded), the key policy (as "policy": the audit
// denylist refuses any key named "key"), the proof method and the renewal settings.
func acmeCertDetails(f acmeCertFields) map[string]string {
	d := map[string]string{"provider_id": f.providerID.String(), "names": truncRunes(strings.Join(f.names, ","), maxAuditNames),
		"names_count": strconv.Itoa(len(f.names)), "policy": f.keyType, "challenge": f.challenge,
		"renew_before_days": strconv.Itoa(f.renewBefore), "auto_renew": strconv.FormatBool(f.autoRenew),
		"auto_deploy": strconv.FormatBool(f.autoDeploy)}
	if f.hookID != nil {
		d["hook_id"] = f.hookID.String()
	}
	if f.httpTargetID != nil {
		d["http_target_id"] = f.httpTargetID.String()
	}
	return d
}

// CreateACMECertificate stores a definition: validation (validate.Errors), its references and allow-lists
// (checkACMECertRefs: ErrACMEAccountState without an active account, ErrACMENameNotAllowed,
// ErrACMEChallengeUnavailable), the row (state pending, the provider's active account) and the audit row
// acme.certificate.created in one transaction. Nothing is ordered and no network call is made.
func (s *Service) CreateACMECertificate(ctx context.Context, a Actor, in ACMECertificateInput) (ACMECertificate, error) {
	f := acmeCertFields{providerID: in.ProviderID, keyType: in.KeyType, challenge: strings.TrimSpace(in.Challenge), hookID: in.HookID,
		httpTargetID: in.HTTPTargetID, renewBefore: in.RenewBeforeDays, autoRenew: true, autoDeploy: in.AutoDeploy}
	if f.keyType == "" {
		f.keyType = string(keygen.Default)
	}
	if f.renewBefore == 0 {
		f.renewBefore = DefaultACMERenewBeforeDays
	}
	if in.AutoRenew != nil {
		f.autoRenew = *in.AutoRenew
	}
	var errs validate.Errors
	var fe *validate.FieldError
	if f.names, fe = normACMENames("names", in.Names); fe != nil {
		errs = append(errs, *fe)
	}
	errs = append(errs, validateACMECertFields(f)...)
	switch {
	case f.challenge == ACMEChallengeDNS01 && f.httpTargetID != nil:
		errs.Add("http_target_id", validate.Pattern, nil)
	case f.challenge == ACMEChallengeHTTP01 && f.hookID != nil:
		errs.Add("hook_id", validate.Pattern, nil)
	}
	if len(errs) > 0 {
		return ACMECertificate{}, errs
	}
	id := uuid.Must(uuid.NewV7())
	now := s.clock.Now().UTC()
	var out ACMECertificate
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		account, err := checkACMECertRefs(ctx, tx, f)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, http_target_id,
renew_before_days, auto_renew, auto_deploy, state, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending', $12, $13, $13)`, id, f.providerID, account, f.names, f.keyType, f.challenge,
			f.hookID, f.httpTargetID, f.renewBefore, f.autoRenew, f.autoDeploy, actorRef(a), now); err != nil {
			return fmt.Errorf("inventory: store the ACME certificate: %w", err)
		}
		if out, err = getACMECert(ctx, tx, id, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.certificate.created", ObjectType: "acme_certificate",
			ObjectID: id.String(), Result: audit.Success, Details: acmeCertDetails(f)})
		return err
	})
	if err != nil {
		return ACMECertificate{}, err
	}
	return out, nil
}

// patchACMECert applies a patch to the current values and lists the fields that change.
func patchACMECert(cur ACMECertificate, p ACMECertificatePatch) (acmeCertFields, []string, validate.Errors) {
	f := acmeCertFields{providerID: cur.ProviderID, names: cur.Names, keyType: cur.KeyType, challenge: cur.Challenge, hookID: cur.HookID,
		httpTargetID: cur.HTTPTargetID, renewBefore: cur.RenewBeforeDays, autoRenew: cur.AutoRenew, autoDeploy: cur.AutoDeploy}
	var changed []string
	var errs validate.Errors
	if p.ProviderID != nil && *p.ProviderID != f.providerID {
		f.providerID, changed = *p.ProviderID, append(changed, "provider_id")
	}
	if p.Names != nil {
		n, fe := normACMENames("names", *p.Names)
		switch {
		case fe != nil:
			errs = append(errs, *fe)
		case !slices.Equal(n, f.names):
			f.names, changed = n, append(changed, "names")
		}
	}
	if p.KeyType != nil && *p.KeyType != f.keyType {
		f.keyType, changed = *p.KeyType, append(changed, "key_type")
	}
	if p.Challenge != nil && strings.TrimSpace(*p.Challenge) != f.challenge {
		f.challenge, changed = strings.TrimSpace(*p.Challenge), append(changed, "challenge")
	}
	if p.HookID != nil && (f.hookID == nil || *p.HookID != *f.hookID) {
		id := *p.HookID
		f.hookID, changed = &id, append(changed, "hook_id")
	}
	if p.HTTPTargetID != nil && (f.httpTargetID == nil || *p.HTTPTargetID != *f.httpTargetID) {
		id := *p.HTTPTargetID
		f.httpTargetID, changed = &id, append(changed, "http_target_id")
	}
	// The method's own id only: a dns01 certificate has no server, an http01 one no hook.
	switch f.challenge {
	case ACMEChallengeDNS01:
		if f.httpTargetID != nil {
			if p.HTTPTargetID != nil {
				errs.Add("http_target_id", validate.Pattern, nil)
			}
			f.httpTargetID = nil
		}
	case ACMEChallengeHTTP01:
		if f.hookID != nil {
			if p.HookID != nil {
				errs.Add("hook_id", validate.Pattern, nil)
			}
			f.hookID = nil
		}
	}
	if p.RenewBeforeDays != nil && *p.RenewBeforeDays != f.renewBefore {
		f.renewBefore, changed = *p.RenewBeforeDays, append(changed, "renew_before_days")
	}
	if p.AutoRenew != nil && *p.AutoRenew != f.autoRenew {
		f.autoRenew, changed = *p.AutoRenew, append(changed, "auto_renew")
	}
	if p.AutoDeploy != nil && *p.AutoDeploy != f.autoDeploy {
		f.autoDeploy, changed = *p.AutoDeploy, append(changed, "auto_deploy")
	}
	errs = append(errs, validateACMECertFields(f)...)
	return f, changed, errs
}

// orderInputs are the fields an order uses: they cannot change while one runs.
var orderInputs = []string{"provider_id", "names", "key_type", "challenge", "hook_id", "http_target_id"}

// UpdateACMECertificate changes a definition. Refusals: validate.Errors; ErrACMEOrderRunning when a field an order
// uses changes while one runs; ErrACMEKeyTypeLocked when the key policy changes while the certificate has bindings;
// the reference and allow-list checks of CreateACMECertificate whenever the provider, names, method, hook or server
// change (a new provider brings its active account). One audit row acme.certificate.updated names the changed fields;
// a patch that changes nothing writes nothing.
func (s *Service) UpdateACMECertificate(ctx context.Context, a Actor, id uuid.UUID, p ACMECertificatePatch) (ACMECertificate, error) {
	var out ACMECertificate
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMECert(ctx, tx, id, true)
		if err != nil {
			return err
		}
		f, changed, errs := patchACMECert(cur, p)
		if len(errs) > 0 {
			return errs
		}
		if len(changed) == 0 {
			out = cur
			return nil
		}
		usesOrder := slices.ContainsFunc(changed, func(c string) bool { return slices.Contains(orderInputs, c) })
		if usesOrder && cur.RunningOrderID != nil {
			return ErrACMEOrderRunning
		}
		if slices.Contains(changed, "key_type") && cur.Bindings > 0 {
			return ErrACMEKeyTypeLocked
		}
		account := cur.AccountID
		if usesOrder {
			if account, err = checkACMECertRefs(ctx, tx, f); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE acme_certificates SET provider_id = $2, account_id = $3, names = $4, key_type = $5, challenge = $6,
hook_id = $7, http_target_id = $8, renew_before_days = $9, auto_renew = $10, auto_deploy = $11, updated_at = $12 WHERE id = $1`,
			id, f.providerID, account, f.names, f.keyType, f.challenge, f.hookID, f.httpTargetID, f.renewBefore, f.autoRenew, f.autoDeploy,
			s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("inventory: update the ACME certificate: %w", err)
		}
		d := acmeCertDetails(f)
		d["fields"] = strings.Join(changed, ",")
		if _, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.certificate.updated", ObjectType: "acme_certificate",
			ObjectID: id.String(), Result: audit.Success, Details: d}); err != nil {
			return err
		}
		if slices.Contains(changed, "auto_renew") && f.autoRenew {
			// Switched on again: a fresh start (the failures of the time it was off do not stop it at once).
			if err := s.rearmTx(ctx, tx, a, cur); err != nil {
				return err
			}
		}
		out, err = getACMECert(ctx, tx, id, false)
		return err
	})
	if err != nil {
		return ACMECertificate{}, err
	}
	return out, nil
}

// DeleteACMECertificate soft-deletes a definition and removes its bindings (the issued certificates stay in the
// inventory like any other). Refused while an order runs (ErrACMEOrderRunning). Audit acme.certificate.deleted with
// the number of bindings removed.
func (s *Service) DeleteACMECertificate(ctx context.Context, a Actor, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMECert(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.RunningOrderID != nil {
			return ErrACMEOrderRunning
		}
		tag, err := tx.Exec(ctx, "DELETE FROM acme_bindings WHERE acme_certificate_id = $1", id)
		if err != nil {
			return fmt.Errorf("inventory: remove the ACME certificate's bindings: %w", err)
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, "UPDATE acme_certificates SET deleted_at = $2, updated_at = $2 WHERE id = $1", id, now); err != nil {
			return fmt.Errorf("inventory: delete the ACME certificate: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.certificate.deleted", ObjectType: "acme_certificate",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"provider_id": cur.ProviderID.String(),
				"names": truncRunes(strings.Join(cur.Names, ","), maxAuditNames), "bindings_count": strconv.FormatInt(tag.RowsAffected(), 10)}})
		return err
	})
}

// ReArmACMEAutoRenew switches automatic renewal of a live ACME certificate on and starts it afresh (an Administrator's
// act, e.g. after it stopped at five failures): state active with a current certificate (issuing while an order runs,
// pending without a certificate), failures 0, no failure notice mark, no wait, no rate-limit series, in one statement
// with the audit row acme.auto_renew.rearmed. Switching auto_renew from off to on through UpdateACMECertificate does
// the same. A successful order re-arms as well (FinishACMEOrder). ErrNotFound.
func (s *Service) ReArmACMEAutoRenew(ctx context.Context, a Actor, id uuid.UUID) (ACMECertificate, error) {
	var out ACMECertificate
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMECert(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if err := s.rearmTx(ctx, tx, a, cur); err != nil {
			return err
		}
		out, err = getACMECert(ctx, tx, id, false)
		return err
	})
	if err != nil {
		return ACMECertificate{}, err
	}
	return out, nil
}

// rearmTx is the reset of ReArmACMEAutoRenew in tx; cur was read with the row lock.
func (s *Service) rearmTx(ctx context.Context, tx pgx.Tx, a Actor, cur ACMECertificate) error {
	if _, err := tx.Exec(ctx, `UPDATE acme_certificates SET auto_renew = true,
    state = CASE WHEN $2 THEN 'issuing' WHEN current_certificate_id IS NOT NULL THEN 'active' ELSE 'pending' END,
    failures = 0, failure_notified_at = NULL, next_attempt_at = NULL, rate_limited_since = NULL, updated_at = $3 WHERE id = $1`,
		cur.ID, cur.RunningOrderID != nil, s.clock.Now().UTC()); err != nil {
		return fmt.Errorf("inventory: re-arm the automatic renewal: %w", err)
	}
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.auto_renew.rearmed", ObjectType: "acme_certificate",
		ObjectID: cur.ID.String(), Result: audit.Success, Details: map[string]string{"acme_certificate_id": cur.ID.String(),
			"names": truncRunes(strings.Join(cur.Names, ","), maxAuditNames), "previous_state": cur.State,
			"previous_failures": strconv.Itoa(cur.Failures)}})
	return err
}
