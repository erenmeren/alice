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
	"alice/internal/authz"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
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
// policy) changes while an order runs (ErrACMEOrderRunning, ALC-ACM-0016). No network call is made here. The owning
// service's policy (R55) is judged in the same transaction before anything is stored: the source acme, the names within
// its domains, the provider, challenge and key type, automatic deployment; its renewal window is the default of a new one.

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
	// ErrACMECAWait: the CA asked Alice to wait before a new order of the certificate (ca_not_before, R47). It comes as
	// the cause of an *ACMEError with the reason acme.ca_rate_limited and the time left as RetryAfter (the API's
	// ALC-ACM-0005 with Retry-After); the CA is not contacted.
	ErrACMECAWait = errors.New("inventory: the certificate authority asked to wait before the next order")
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
	// CANotBefore is the CA's earliest retry time (the Retry-After of a rate limit; R47), apart from NextAttemptAt
	// (Alice's own backoff): no order starts before it.
	CANotBefore   *time.Time `json:"ca_not_before,omitempty"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastErrorCode string     `json:"last_error_code"`
	// LastFailureClass is the class of the last failure of the series (renew.ClassTransient, renew.ClassPermanent; ''
	// without one); PermanentFailures counts the permanent ones (five stop automatic renewal).
	LastFailureClass  string     `json:"last_failure_class"`
	PermanentFailures int        `json:"permanent_failures"`
	RunningOrderID    *uuid.UUID `json:"running_order_id,omitempty"`
	Bindings          int        `json:"bindings"`
	// The current certificate's leaf (nil before the first issuance): what is served once it is deployed.
	Current *ACMECurrentCertificate `json:"current,omitempty"`
	// The CA's suggested renewal window (ARI, RFC 9773) when one is cached.
	ARIWindowStart *time.Time `json:"ari_window_start,omitempty"`
	ARIWindowEnd   *time.Time `json:"ari_window_end,omitempty"`
	// ARIRenewAt is the time chosen at random in that window (R50; renew.ChooseARIRenewAt), stored by the renewal planner.
	ARIRenewAt *time.Time `json:"ari_renew_at,omitempty"`
	// DeployHeldReason is why automatic deployment holds the current certificate ('' when it does not: never held, or
	// released from the licence hold): ACMEHoldLicense or ACMEHoldChainIncomplete. DeployStopped: automatic deployment of
	// the current certificate stopped after repeated failures.
	DeployHeldReason string     `json:"deploy_held_reason"`
	DeployStopped    bool       `json:"deploy_stopped"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	// ServiceID is the owning service (R49): its issued certificates go there.
	ServiceID uuid.UUID `json:"service_id"`
}

// ACMECurrentCertificate summarises the current certificate of an ACME certificate (no key, no PEM).
type ACMECurrentCertificate struct {
	ID            uuid.UUID `json:"id"`
	Fingerprint   string    `json:"fingerprint_sha256"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	ChainComplete bool      `json:"chain_complete"`
	// RevokedAt and RevocationReason: the CA revoked it at Alice's request; Compromised: its key is marked compromised.
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason"`
	Compromised      bool       `json:"compromised"`
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
	// ServiceID is the service the definition goes to (R49); uuid.Nil = the Default service.
	ServiceID uuid.UUID
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

// MaxACMENames is the most names one ACME certificate may hold.
const MaxACMENames = acme.MaxNames

// CheckACMENames applies the name rules of a definition to names without a database (the API checks them at its
// boundary): 1..100 DNS names, a wildcard only as the whole first label, no IP address, no duplicates. A field error on
// "names" or nil.
func CheckACMENames(names []string) *validate.FieldError {
	_, fe := normACMENames("names", names)
	return fe
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
// wildcard only over DNS-01. Missing rows are field errors (the request named something that is not there). The rows
// are read FOR SHARE: a delete holding one (DeleteACMEProvider, DeleteACMEHook, DeleteTarget: FOR UPDATE) either
// commits first, and the row is then not live here, or waits for this transaction and then sees the certificate that
// uses the row.
func (s *Service) checkACMECertRefs(ctx context.Context, tx pgx.Tx, f acmeCertFields) (uuid.UUID, error) {
	p, err := readACMEProvider(ctx, tx, f.providerID, " FOR SHARE OF p")
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
		h, err := readACMEHook(ctx, tx, *f.hookID, " FOR SHARE")
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
		err := tx.QueryRow(ctx, "SELECT type FROM targets WHERE id = $1 AND deleted_at IS NULL FOR SHARE", *f.httpTargetID).Scan(&typ)
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, validate.Errors{{Field: "http_target_id", Code: validate.Required}}
		}
		if err != nil {
			return uuid.Nil, fmt.Errorf("inventory: read the HTTP-01 server: %w", err)
		}
		if !s.can(typ, providers.CapHTTP01) { // only a provider that publishes HTTP-01 tokens (the nginx profile's sudoers lines) may be the HTTP-01 server
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
(SELECT cur.fingerprint_sha256 FROM certificates cur WHERE cur.id = c.current_certificate_id),
(SELECT cur.not_before FROM certificates cur WHERE cur.id = c.current_certificate_id),
(SELECT cur.not_after FROM certificates cur WHERE cur.id = c.current_certificate_id),
(SELECT cur.chain_complete FROM certificates cur WHERE cur.id = c.current_certificate_id),
c.ari_window_start, c.ari_window_end,
CASE WHEN c.current_certificate_id IS NOT NULL AND c.deploy_held_certificate_id = c.current_certificate_id
    AND NOT (c.deploy_held_reason = 'license' AND c.deploy_released_certificate_id IS NOT DISTINCT FROM c.current_certificate_id)
    THEN c.deploy_held_reason ELSE '' END,
c.current_certificate_id IS NOT NULL AND c.deploy_stopped_certificate_id IS NOT DISTINCT FROM c.current_certificate_id,
c.created_by, c.created_at, c.updated_at, c.last_failure_class, c.permanent_failures,
(SELECT cur.revoked_at FROM certificates cur WHERE cur.id = c.current_certificate_id),
(SELECT cur.revocation_reason FROM certificates cur WHERE cur.id = c.current_certificate_id),
(SELECT cur.compromised_at IS NOT NULL FROM certificates cur WHERE cur.id = c.current_certificate_id), c.ca_not_before, c.ari_renew_at, c.service_id`

func scanACMECert(row pgx.Row) (ACMECertificate, error) {
	var (
		c           ACMECertificate
		fingerprint *string
		nb, na      *time.Time
		chainOK     *bool
		revokedAt   *time.Time
		reason      *string
		compromised *bool
	)
	err := row.Scan(&c.ID, &c.ProviderID, &c.AccountID, &c.Names, &c.KeyType, &c.Challenge, &c.HookID, &c.HTTPTargetID, &c.RenewBeforeDays,
		&c.AutoRenew, &c.AutoDeploy, &c.State, &c.CurrentCertificateID, &c.Failures, &c.NextAttemptAt, &c.LastAttemptAt, &c.LastErrorCode,
		&c.RunningOrderID, &c.Bindings, &fingerprint, &nb, &na, &chainOK, &c.ARIWindowStart, &c.ARIWindowEnd, &c.DeployHeldReason,
		&c.DeployStopped, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.LastFailureClass, &c.PermanentFailures, &revokedAt, &reason, &compromised, &c.CANotBefore,
		&c.ARIRenewAt, &c.ServiceID)
	c.CreatedAt, c.UpdatedAt = c.CreatedAt.UTC(), c.UpdatedAt.UTC()
	if c.CurrentCertificateID != nil && fingerprint != nil && nb != nil && na != nil && chainOK != nil {
		c.Current = &ACMECurrentCertificate{ID: *c.CurrentCertificateID, Fingerprint: *fingerprint, NotBefore: nb.UTC(), NotAfter: na.UTC(),
			ChainComplete: *chainOK, RevokedAt: utcPtr(revokedAt), Compromised: compromised != nil && *compromised}
		if reason != nil {
			c.Current.RevocationReason = *reason
		}
	}
	for _, t := range []**time.Time{&c.NextAttemptAt, &c.CANotBefore, &c.LastAttemptAt, &c.ARIWindowStart, &c.ARIWindowEnd, &c.ARIRenewAt} {
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
	return s.ListACMECertificatesIn(ctx, authz.Everywhere())
}

// ListACMECertificatesIn is ListACMECertificates over those visible from the services in reach (R49 Phase 2: the
// owning service or a bound location's server's).
func (s *Service) ListACMECertificatesIn(ctx context.Context, reach authz.Reach) ([]ACMECertificate, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+acmeCertColumns+" FROM acme_certificates c WHERE c.deleted_at IS NULL AND "+
		authz.ACMECertificateVisible("c", "$1")+" ORDER BY c.created_at, c.id", reach.SQL())
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
	renewDefault := f.renewBefore == 0 // the service's policy may set the default (R55)
	if renewDefault {
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
	if f.autoDeploy {
		// unattended deployment from the start (Task 12). strictSession true: only the acme.manage routes (an Administrator
		// with a fresh step-up, never a token) create and change definitions; the guard checks each request.
		if err := s.unattendedAllowed(a, true); err != nil {
			return ACMECertificate{}, err
		}
	}
	id := uuid.Must(uuid.NewV7())
	now := s.clock.Now().UTC()
	var out ACMECertificate
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		service, err := authz.ResolveService(ctx, tx, in.ServiceID)
		if err != nil {
			return err
		}
		// R55: the service's policy, before anything is stored (no order is ever placed here).
		policy, err := authz.LoadPolicy(ctx, tx, service)
		if err != nil {
			return err
		}
		if err := checkACMEPolicy(policy, f, true, nil); err != nil {
			return err
		}
		if renewDefault && policy.RenewBeforeDays() > 0 {
			f.renewBefore = policy.RenewBeforeDays()
		}
		account, err := s.checkACMECertRefs(ctx, tx, f)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, hook_id, http_target_id,
renew_before_days, auto_renew, auto_deploy, state, created_by, created_at, updated_at, service_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending', $12, $13, $13, $14)`, id, f.providerID, account, f.names, f.keyType, f.challenge,
			f.hookID, f.httpTargetID, f.renewBefore, f.autoRenew, f.autoDeploy, actorRef(a), now, service); err != nil {
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

// checkACMEPolicy is the service's policy for a definition (R55, design §7.3): the source acme, the names within the
// domains, the provider, challenge and key type among the allowed ones, and automatic deployment not forbidden. A new
// definition is judged whole; a change (changed lists its fields) only in what it changes.
func checkACMEPolicy(p authz.Policy, f acmeCertFields, create bool, changed []string) error {
	has := func(field string) bool { return create || slices.Contains(changed, field) }
	if create {
		if err := p.CheckSource(authz.SourceACME); err != nil {
			return err
		}
	}
	if has("names") {
		if err := p.CheckNames("names", f.names); err != nil {
			return err
		}
	}
	var provider *uuid.UUID
	var challenge, keyType *string
	if has("provider_id") {
		provider = &f.providerID
	}
	if has("challenge") {
		challenge = &f.challenge
	}
	if has("key_type") {
		keyType = &f.keyType
	}
	if err := p.CheckACMEChanges(provider, challenge, keyType); err != nil {
		return err
	}
	if f.autoDeploy && has("auto_deploy") {
		return p.CheckAutoDeploy()
	}
	return nil
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
		if slices.Contains(changed, "auto_deploy") && f.autoDeploy {
			// switching unattended deployment on (Task 12). strictSession true: only the acme.manage routes (an Administrator
			// with a fresh step-up, never a token) create and change definitions; the guard checks each request.
			if err := s.unattendedAllowed(a, true); err != nil {
				return err
			}
		}
		// R55: the changed fields are judged by the service's policy (the others were judged when they were set).
		policy, err := authz.LoadPolicy(ctx, tx, cur.ServiceID)
		if err != nil {
			return err
		}
		if err := checkACMEPolicy(policy, f, false, changed); err != nil {
			return err
		}
		account := cur.AccountID
		if usesOrder {
			if account, err = s.checkACMECertRefs(ctx, tx, f); err != nil {
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

// ReArmACMEAutoRenew is "Check again and resume" (the web's Renew now; owner decision 2026-10-20): it switches automatic
// renewal of a live ACME certificate on, starts it afresh and checks again at once (an Administrator's act, e.g. after
// it stopped or while it fails): state active with a current certificate (pending without one), failures 0 of either
// class, no failure notice mark, no wait of Alice's own (the CA's ca_not_before stays, R47), no rate-limit series, with
// the audit row acme.auto_renew.rearmed; then, for an issued certificate without a running order, an order of the
// person (trigger manual, acme.issue, audit acme.order.started), all in one transaction. The licence gate is asked first
// (changes). An order that cannot start refuses the whole act (ErrACMEAccountState, ErrACMERolloverPending: nothing
// changes); a job of an earlier order that is still finishing (ErrACMEOrderRunning) or the CA's wait (ErrACMECAWait)
// leaves the re-arm without a new order, and the planner orders at a later run. Switching auto_renew from off to on
// through UpdateACMECertificate re-arms without ordering. A successful order re-arms as well (FinishACMEOrder).
// ErrNotFound.
func (s *Service) ReArmACMEAutoRenew(ctx context.Context, a Actor, id uuid.UUID) (ACMECertificate, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return ACMECertificate{}, err
	}
	var out ACMECertificate
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMECert(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if err := s.rearmTx(ctx, tx, a, cur); err != nil {
			return err
		}
		if cur.CurrentCertificateID != nil && cur.RunningOrderID == nil {
			// A savepoint: an order refused because the previous order's job is still finishing must leave nothing behind
			// (startOrderTx may have written the order row before the job's dedupe key refused it).
			sp, err := tx.Begin(ctx)
			if err != nil {
				return fmt.Errorf("inventory: open a savepoint: %w", err)
			}
			_, err = s.startOrderTx(ctx, sp, a, cur, ACMEOrderIssue, ACMETriggerManual)
			switch {
			case errors.Is(err, ErrACMEOrderRunning), errors.Is(err, ErrACMECAWait):
				if rerr := sp.Rollback(ctx); rerr != nil {
					return fmt.Errorf("inventory: roll back a savepoint: %w", rerr)
				}
			case err != nil:
				_ = sp.Rollback(ctx)
				return err
			default:
				if err := sp.Commit(ctx); err != nil {
					return fmt.Errorf("inventory: release a savepoint: %w", err)
				}
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

// rearmTx is the reset of ReArmACMEAutoRenew in tx; cur was read with the row lock.
func (s *Service) rearmTx(ctx context.Context, tx pgx.Tx, a Actor, cur ACMECertificate) error {
	if _, err := tx.Exec(ctx, `UPDATE acme_certificates SET auto_renew = true,
    state = CASE WHEN $2 THEN 'issuing' WHEN current_certificate_id IS NOT NULL THEN 'active' ELSE 'pending' END,
    failures = 0, permanent_failures = 0, last_failure_class = '', failure_notified_at = NULL, next_attempt_at = NULL, rate_limited_since = NULL,
    updated_at = $3 WHERE id = $1`,
		cur.ID, cur.RunningOrderID != nil, s.clock.Now().UTC()); err != nil {
		return fmt.Errorf("inventory: re-arm the automatic renewal: %w", err)
	}
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.auto_renew.rearmed", ObjectType: "acme_certificate",
		ObjectID: cur.ID.String(), Result: audit.Success, Details: map[string]string{"acme_certificate_id": cur.ID.String(),
			"names": truncRunes(strings.Join(cur.Names, ","), maxAuditNames), "previous_state": cur.State,
			"previous_failures": strconv.Itoa(cur.Failures)}})
	return err
}
