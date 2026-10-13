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
	"alice/internal/acme/solver/dns01"
	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// DNS-01 hooks (plan 2026-10-13 Task 9; design row 1; amendments A9, A10). A hook is an HTTPS endpoint (no
// credentials, query or fragment in the URL) with an optional CA bundle, a shared secret (sealed, AAD
// acme_hooks/<id>/secret; write-only: views carry SecretConfigured only; the dns01 solver always sends it both as the
// bearer token and as the HMAC key of X-Alice-Signature, so there is no auth mode to choose), the name allow-list of
// A9 and the two waits of the solver. The waits are checked against the dns01 limits and, together, against the ACME client's call
// budget the challenge is published under (ledger ruling, Task 6 item 7). Creating or changing a hook makes no
// network call.

// Limits of a hook's secret and waits.
const (
	minACMEHookSecretLen = 16
	maxACMEHookSecretLen = 256
	// DefaultACMEPropagationWaitSeconds and DefaultACMEPollTimeoutSeconds are a new hook's waits.
	DefaultACMEPropagationWaitSeconds = 5
	DefaultACMEPollTimeoutSeconds     = 60
)

// acmeHookBudget is the time a challenge's publication may take: the ACME client's per-call deadline, under which
// the solver's Present runs.
var acmeHookBudget = acme.DefaultCallTimeout

// ACMEHook is the view of a hook. It has no secret.
type ACMEHook struct {
	ID                     uuid.UUID  `json:"id"`
	Name                   string     `json:"name"`
	URL                    string     `json:"url"`
	CABundlePEM            string     `json:"ca_bundle_pem"`
	SecretConfigured       bool       `json:"secret_configured"`
	AllowedSuffixes        []string   `json:"allowed_suffixes"`
	PropagationWaitSeconds int        `json:"propagation_wait_seconds"`
	PollTimeoutSeconds     int        `json:"poll_timeout_seconds"`
	CreatedBy              *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// ACMEHookInput is the input of CreateACMEHook. Secret is consumed: the call zeroes it, whatever the outcome.
// PropagationWaitSeconds 0 means no wait after a present; PollTimeoutSeconds 0 means the default (60).
type ACMEHookInput struct {
	Name                   string
	URL                    string
	CABundlePEM            string
	Secret                 secrets.Plaintext
	AllowedSuffixes        []string
	PropagationWaitSeconds *int // nil = 5
	PollTimeoutSeconds     int
}

// ACMEHookPatch is the input of UpdateACMEHook: nil fields stay; a non-empty Secret replaces the secret (and is
// zeroed by the call).
type ACMEHookPatch struct {
	Name                   *string
	URL                    *string
	CABundlePEM            *string
	Secret                 secrets.Plaintext
	AllowedSuffixes        *[]string
	PropagationWaitSeconds *int
	PollTimeoutSeconds     *int
}

// hookSecretLocation binds a hook's sealed secret to its row.
func hookSecretLocation(id uuid.UUID) secrets.Location {
	return secrets.Location{Table: "acme_hooks", RowID: id.String(), Column: "secret"}
}

// validHookSecret applies the dns01 rule (printable ASCII: it is an HTTP header value and an HMAC key) and the
// length bounds 16..256.
func validHookSecret(b []byte) *validate.FieldError {
	switch {
	case len(b) == 0:
		return &validate.FieldError{Field: "secret", Code: validate.Required}
	case len(b) < minACMEHookSecretLen:
		return &validate.FieldError{Field: "secret", Code: validate.TooShort, Params: map[string]string{"min": strconv.Itoa(minACMEHookSecretLen)}}
	case len(b) > maxACMEHookSecretLen:
		return &validate.FieldError{Field: "secret", Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(maxACMEHookSecretLen)}}
	}
	for _, c := range b {
		if c < 0x20 || c >= 0x7f {
			return &validate.FieldError{Field: "secret", Code: validate.Pattern}
		}
	}
	return nil
}

// validHookWaits checks the waits against the dns01 limits and their sum against the publication budget.
func validHookWaits(wait, poll int) validate.Errors {
	var errs validate.Errors
	maxWait, maxPoll := int(dns01.MaxPropagationWait/time.Second), int(dns01.MaxPollTimeout/time.Second)
	budget := int(acmeHookBudget / time.Second)
	if wait < 0 || wait > maxWait {
		errs.Add("propagation_wait_seconds", validate.OutOfRange, map[string]string{"min": "0", "max": strconv.Itoa(maxWait)})
	}
	if poll < 1 || poll > maxPoll {
		errs.Add("poll_timeout_seconds", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxPoll)})
	}
	if len(errs) == 0 && wait+poll > budget {
		errs.Add("poll_timeout_seconds", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(budget - wait)})
	}
	return errs
}

// hookFields are the stored values of a hook (secret as the plaintext about to be sealed; nil = unchanged).
type hookFields struct {
	name, url, bundle string
	suffixes          []string
	wait, poll        int
	secret            []byte
}

func validateACMEHook(in ACMEHookInput) (hookFields, validate.Errors) {
	var errs validate.Errors
	f := hookFields{wait: DefaultACMEPropagationWaitSeconds, poll: in.PollTimeoutSeconds}
	add := func(fe *validate.FieldError) {
		if fe != nil {
			errs = append(errs, *fe)
		}
	}
	var fe *validate.FieldError
	f.name, fe = validName("name", in.Name)
	add(fe)
	f.url, fe = normACMEURL("url", in.URL)
	add(fe)
	f.bundle, fe = normCABundle("ca_bundle_pem", in.CABundlePEM)
	add(fe)
	f.suffixes, fe = normSuffixes("allowed_suffixes", in.AllowedSuffixes)
	add(fe)
	add(validHookSecret(in.Secret.Bytes()))
	if in.PropagationWaitSeconds != nil {
		f.wait = *in.PropagationWaitSeconds
	}
	if f.poll == 0 {
		f.poll = DefaultACMEPollTimeoutSeconds
	}
	errs = append(errs, validHookWaits(f.wait, f.poll)...)
	if len(errs) > 0 {
		return hookFields{}, errs
	}
	f.secret = slices.Clone(in.Secret.Bytes())
	return f, nil
}

const hookColumns = `id, name::text, url, ca_bundle_pem, allowed_suffixes, propagation_wait_seconds, poll_timeout_seconds,
created_by, created_at, updated_at`

func scanHook(row pgx.Row) (ACMEHook, error) {
	h := ACMEHook{SecretConfigured: true} // secret_ct is NOT NULL
	err := row.Scan(&h.ID, &h.Name, &h.URL, &h.CABundlePEM, &h.AllowedSuffixes, &h.PropagationWaitSeconds, &h.PollTimeoutSeconds,
		&h.CreatedBy, &h.CreatedAt, &h.UpdatedAt)
	if h.AllowedSuffixes == nil {
		h.AllowedSuffixes = []string{}
	}
	h.CreatedAt, h.UpdatedAt = h.CreatedAt.UTC(), h.UpdatedAt.UTC()
	return h, err
}

func getACMEHook(ctx context.Context, q db.Querier, id uuid.UUID, forUpdate bool) (ACMEHook, error) {
	sql := "SELECT " + hookColumns + " FROM acme_hooks WHERE id = $1 AND deleted_at IS NULL"
	if forUpdate {
		sql += " FOR UPDATE"
	}
	h, err := scanHook(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEHook{}, ErrNotFound
	}
	if err != nil {
		return ACMEHook{}, fmt.Errorf("inventory: read the DNS hook: %w", err)
	}
	return h, nil
}

// GetACMEHook returns a live hook (ErrNotFound otherwise).
func (s *Service) GetACMEHook(ctx context.Context, id uuid.UUID) (ACMEHook, error) {
	return getACMEHook(ctx, s.pool, id, false)
}

// ListACMEHooks returns the live hooks by name.
func (s *Service) ListACMEHooks(ctx context.Context) ([]ACMEHook, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+hookColumns+" FROM acme_hooks WHERE deleted_at IS NULL ORDER BY name, id")
	if err != nil {
		return nil, fmt.Errorf("inventory: list the DNS hooks: %w", err)
	}
	defer rows.Close()
	out := []ACMEHook{}
	for rows.Next() {
		h, err := scanHook(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: read a DNS hook: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Service) sealHookSecret(id uuid.UUID, secret []byte) (secrets.Envelope, error) {
	env, err := s.keyring.Seal(hookSecretLocation(id), secret)
	if err != nil {
		return secrets.Envelope{}, fmt.Errorf("inventory: seal the DNS hook secret: %w", err)
	}
	return env, nil
}

func hookDetails(f hookFields) map[string]string {
	return map[string]string{"name": f.name, "url_host": urlHost(f.url), "allowed_suffixes": suffixesDetail(f.suffixes),
		"propagation_wait_seconds": strconv.Itoa(f.wait), "poll_timeout_seconds": strconv.Itoa(f.poll)}
}

// CreateACMEHook stores a DNS-01 hook: validation (validate.Errors), the sealed secret, the row and the audit row
// acme.hook.created in one transaction. No network call. ErrACMENameTaken for a live name.
func (s *Service) CreateACMEHook(ctx context.Context, a Actor, in ACMEHookInput) (ACMEHook, error) {
	defer in.Secret.Zero()
	f, errs := validateACMEHook(in)
	if len(errs) > 0 {
		return ACMEHook{}, errs
	}
	defer clear(f.secret)
	id := uuid.Must(uuid.NewV7())
	env, err := s.sealHookSecret(id, f.secret)
	if err != nil {
		return ACMEHook{}, err
	}
	now := s.clock.Now().UTC()
	var out ACMEHook
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO acme_hooks (id, name, url, ca_bundle_pem, secret_ct, secret_nonce, secret_wrapped_dek,
secret_key_version, allowed_suffixes, propagation_wait_seconds, poll_timeout_seconds, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)`,
			id, f.name, f.url, f.bundle, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, f.suffixes, f.wait, f.poll, actorRef(a), now)
		if err != nil {
			return mapACMENameTaken(fmt.Errorf("inventory: store the DNS hook: %w", err))
		}
		if out, err = getACMEHook(ctx, tx, id, false); err != nil {
			return err
		}
		d := hookDetails(f)
		d["ca_bundle"] = strconv.FormatBool(f.bundle != "")
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.hook.created", ObjectType: "acme_hook",
			ObjectID: id.String(), Result: audit.Success, Details: d})
		return err
	})
	if err != nil {
		return ACMEHook{}, err
	}
	return out, nil
}

// validateHookPatch normalizes the fields a patch sets and lists the fields that change.
func validateHookPatch(cur ACMEHook, p ACMEHookPatch) (hookFields, []string, validate.Errors) {
	var errs validate.Errors
	f := hookFields{name: cur.Name, url: cur.URL, bundle: cur.CABundlePEM, suffixes: cur.AllowedSuffixes,
		wait: cur.PropagationWaitSeconds, poll: cur.PollTimeoutSeconds}
	var changed []string
	add := func(fe *validate.FieldError) {
		if fe != nil {
			errs = append(errs, *fe)
		}
	}
	var fe *validate.FieldError
	if p.Name != nil {
		var v string
		if v, fe = validName("name", *p.Name); fe == nil && v != f.name {
			f.name, changed = v, append(changed, "name")
		}
		add(fe)
	}
	if p.URL != nil {
		var v string
		if v, fe = normACMEURL("url", *p.URL); fe == nil && v != f.url {
			f.url, changed = v, append(changed, "url")
		}
		add(fe)
	}
	if p.CABundlePEM != nil {
		var v string
		if v, fe = normCABundle("ca_bundle_pem", *p.CABundlePEM); fe == nil && v != f.bundle {
			f.bundle, changed = v, append(changed, "ca_bundle")
		}
		add(fe)
	}
	if p.AllowedSuffixes != nil {
		var v []string
		if v, fe = normSuffixes("allowed_suffixes", *p.AllowedSuffixes); fe == nil && !slices.Equal(v, f.suffixes) {
			f.suffixes, changed = v, append(changed, "allowed_suffixes")
		}
		add(fe)
	}
	if p.PropagationWaitSeconds != nil && *p.PropagationWaitSeconds != f.wait {
		f.wait, changed = *p.PropagationWaitSeconds, append(changed, "propagation_wait_seconds")
	}
	if p.PollTimeoutSeconds != nil && *p.PollTimeoutSeconds != f.poll {
		f.poll, changed = *p.PollTimeoutSeconds, append(changed, "poll_timeout_seconds")
	}
	errs = append(errs, validHookWaits(f.wait, f.poll)...)
	if len(p.Secret.Bytes()) > 0 {
		add(validHookSecret(p.Secret.Bytes()))
		changed = append(changed, "secret")
	}
	if len(errs) > 0 {
		return hookFields{}, nil, errs
	}
	if len(p.Secret.Bytes()) > 0 {
		f.secret = slices.Clone(p.Secret.Bytes())
	}
	return f, changed, nil
}

// UpdateACMEHook changes a hook; a new secret is sealed again. One audit row acme.hook.updated names the fields that
// changed ("secret" for a new secret, never its value); a patch that changes nothing writes nothing.
func (s *Service) UpdateACMEHook(ctx context.Context, a Actor, id uuid.UUID, p ACMEHookPatch) (ACMEHook, error) {
	defer p.Secret.Zero()
	var out ACMEHook
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMEHook(ctx, tx, id, true)
		if err != nil {
			return err
		}
		f, changed, errs := validateHookPatch(cur, p)
		if len(errs) > 0 {
			return errs
		}
		defer clear(f.secret)
		if len(changed) == 0 {
			out = cur
			return nil
		}
		var env secrets.Envelope
		rotate := f.secret != nil
		if rotate {
			if env, err = s.sealHookSecret(id, f.secret); err != nil {
				return err
			}
		}
		var version *int
		if rotate {
			version = &env.KeyVersion
		}
		_, err = tx.Exec(ctx, `UPDATE acme_hooks SET name = $2, url = $3, ca_bundle_pem = $4, allowed_suffixes = $5,
propagation_wait_seconds = $6, poll_timeout_seconds = $7, secret_ct = COALESCE($8, secret_ct), secret_nonce = COALESCE($9, secret_nonce),
secret_wrapped_dek = COALESCE($10, secret_wrapped_dek), secret_key_version = COALESCE($11, secret_key_version), updated_at = $12 WHERE id = $1`,
			id, f.name, f.url, f.bundle, f.suffixes, f.wait, f.poll, env.Ciphertext, env.Nonce, env.WrappedDEK, version, s.clock.Now().UTC())
		if err != nil {
			return mapACMENameTaken(fmt.Errorf("inventory: update the DNS hook: %w", err))
		}
		if out, err = getACMEHook(ctx, tx, id, false); err != nil {
			return err
		}
		d := hookDetails(f)
		d["fields"] = strings.Join(changed, ",")
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.hook.updated", ObjectType: "acme_hook",
			ObjectID: id.String(), Result: audit.Success, Details: d})
		return err
	})
	if err != nil {
		return ACMEHook{}, err
	}
	return out, nil
}

// DeleteACMEHook soft-deletes a hook; live ACME certificates that publish through it refuse the delete
// (ErrACMEHookInUse). Audit acme.hook.deleted.
func (s *Service) DeleteACMEHook(ctx context.Context, a Actor, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMEHook(ctx, tx, id, true)
		if err != nil {
			return err
		}
		var inUse bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM acme_certificates WHERE hook_id = $1 AND deleted_at IS NULL)", id).Scan(&inUse); err != nil {
			return fmt.Errorf("inventory: look for the DNS hook's users: %w", err)
		}
		if inUse {
			return ErrACMEHookInUse
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, "UPDATE acme_hooks SET deleted_at = $2, updated_at = $2 WHERE id = $1", id, now); err != nil {
			return fmt.Errorf("inventory: delete the DNS hook: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.hook.deleted", ObjectType: "acme_hook",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"name": cur.Name, "url_host": urlHost(cur.URL)}})
		return err
	})
}

// ACMEHookSolverConfig is the dns01 configuration of a live hook for an order (Task 10), with the opened secret: the
// caller builds the solver and zeroes cfg.Secret at once. ErrNotFound, ErrACMESecretUnreadable, *ACMEError
// tls_trust_failed when the e2e trust file (Config.ACMERoots) cannot be read.
func (s *Service) ACMEHookSolverConfig(ctx context.Context, hookID uuid.UUID) (dns01.Config, error) {
	return s.hookSolverConfig(ctx, hookID, true)
}

// ACMEHookCleanupConfig is ACMEHookSolverConfig for the cleanup of a record an order presented through the hook: the
// hook may have been deleted since (its row and secret stay), and the caller sets AllowedSuffixes to the record's own
// name (the record was published by Alice; removing it needs no allow-list).
func (s *Service) ACMEHookCleanupConfig(ctx context.Context, hookID uuid.UUID) (dns01.Config, error) {
	return s.hookSolverConfig(ctx, hookID, false)
}

func (s *Service) hookSolverConfig(ctx context.Context, hookID uuid.UUID, live bool) (dns01.Config, error) {
	sql := "SELECT " + hookColumns + " FROM acme_hooks WHERE id = $1"
	if live {
		sql += " AND deleted_at IS NULL"
	}
	h, err := scanHook(s.pool.QueryRow(ctx, sql, hookID))
	if errors.Is(err, pgx.ErrNoRows) {
		return dns01.Config{}, ErrNotFound
	}
	if err != nil {
		return dns01.Config{}, fmt.Errorf("inventory: read the DNS hook: %w", err)
	}
	base, err := s.acmeBaseRoots()
	if err != nil {
		return dns01.Config{}, acmeFailure(err)
	}
	var env secrets.Envelope
	if err := s.pool.QueryRow(ctx, "SELECT secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version FROM acme_hooks WHERE id = $1", hookID).
		Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion); err != nil {
		return dns01.Config{}, fmt.Errorf("inventory: read the DNS hook secret: %w", err)
	}
	pt, err := s.keyring.Open(hookSecretLocation(hookID), env)
	if err != nil {
		return dns01.Config{}, ErrACMESecretUnreadable
	}
	wait := time.Duration(h.PropagationWaitSeconds) * time.Second
	if wait == 0 {
		wait = -1 // dns01: a negative wait is none (0 would be its default)
	}
	return dns01.Config{URL: h.URL, Secret: pt, CABundlePEM: h.CABundlePEM, BaseRoots: base, PropagationWait: wait,
		PollTimeout: time.Duration(h.PollTimeoutSeconds) * time.Second, AllowedSuffixes: slices.Clone(h.AllowedSuffixes)}, nil
}
