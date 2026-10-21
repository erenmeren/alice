package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/acme"
	"alice/internal/acme/solver/dns01"
	"alice/internal/acme/solver/dnssolver"
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
//
// Since 00030 (R57) such a row is a DNS publisher of a kind: the hook above (webhook) or a built-in DNS provider
// (acme_dns_providers.go), which has no URL, CA bundle or shared secret but settings and credentials of its own; the
// name, the allow-list and the waits are common to every kind, and a kind never changes.

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

// ACMEHook is the view of a DNS publisher (a hook or a built-in provider). It has no secret.
type ACMEHook struct {
	ID                     uuid.UUID       `json:"id"`
	Kind                   string          `json:"kind"`
	Settings               ACMEDNSSettings `json:"settings"`
	Name                   string          `json:"name"`
	URL                    string          `json:"url"`
	CABundlePEM            string          `json:"ca_bundle_pem"`
	SecretConfigured       bool            `json:"secret_configured"`
	AllowedSuffixes        []string        `json:"allowed_suffixes"`
	PropagationWaitSeconds int             `json:"propagation_wait_seconds"`
	PollTimeoutSeconds     int             `json:"poll_timeout_seconds"`
	CreatedBy              *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt              time.Time       `json:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at"`
}

// ACMEHookInput is the input of CreateACMEHook. Secret and Credentials are consumed: the call zeroes them, whatever
// the outcome. PropagationWaitSeconds 0 means no wait after a present; PollTimeoutSeconds 0 means the default (60).
// Kind "" is a hook (webhook): URL and Secret are its; a provider kind takes Settings and Credentials instead.
type ACMEHookInput struct {
	Kind                   string
	Settings               ACMEDNSSettings
	Credentials            ACMEDNSCredentials
	Name                   string
	URL                    string
	CABundlePEM            string
	Secret                 secrets.Plaintext
	AllowedSuffixes        []string
	PropagationWaitSeconds *int // nil = 5
	PollTimeoutSeconds     int
}

// ACMEHookPatch is the input of UpdateACMEHook: nil fields stay; a non-empty Secret replaces a hook's secret (and is
// zeroed by the call). For a provider, Settings replaces its settings and any given Credentials replace its
// credentials (zeroed by the call); credentials are required again when the Azure sign-in method or the AWS access
// key changes.
type ACMEHookPatch struct {
	Settings               *ACMEDNSSettings
	Credentials            ACMEDNSCredentials
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

// hookFields are the stored values of a hook (secret as the plaintext about to be sealed; nil = unchanged): a hook's
// shared secret, or a provider's encoded credentials document.
type hookFields struct {
	kind              string
	settings          ACMEDNSSettings
	name, url, bundle string
	suffixes          []string
	wait, poll        int
	secret            []byte
}

// hookKind is the stored kind of an input's kind ("" is a hook).
func hookKind(k string) string {
	if k == "" {
		return ACMEHookKindWebhook
	}
	return k
}

// validateNewHook validates a new publisher of any kind.
func (s *Service) validateNewHook(in ACMEHookInput) (hookFields, validate.Errors) {
	kind := hookKind(in.Kind)
	if kind == ACMEHookKindWebhook {
		var errs validate.Errors
		if in.Settings != (ACMEDNSSettings{}) {
			errs.Add("settings", validate.Pattern, nil)
		}
		if in.Credentials.Given() {
			errs.Add("credentials", validate.Pattern, nil)
		}
		f, ferrs := validateACMEHook(in)
		if errs = append(errs, ferrs...); len(errs) > 0 {
			clear(f.secret)
			return hookFields{}, errs
		}
		return f, nil
	}
	var errs validate.Errors
	if !validKind(kind) {
		errs.Add("kind", validate.OneOf, kindValues())
		return hookFields{}, errs
	}
	f := hookFields{kind: kind, wait: DefaultACMEPropagationWaitSeconds, poll: in.PollTimeoutSeconds}
	errs = append(errs, s.commonHookFields(&f, in.Name, in.AllowedSuffixes, in.PropagationWaitSeconds)...)
	errs = append(errs, providerRefusesHookFields(in.URL != "", in.CABundlePEM != "", len(in.Secret.Bytes()) > 0)...)
	st, perrs := s.validateDNSProvider(kind, nil, in.Settings, in.Credentials, s.clock.Now().UTC())
	if errs = append(errs, perrs...); len(errs) > 0 {
		if st.doc != nil {
			st.doc.zero()
		}
		return hookFields{}, errs
	}
	f.settings = st.settings
	f.secret = st.doc.encode()
	st.doc.zero()
	return f, nil
}

// commonHookFields validates the name, the allow-list and the waits every kind has.
func (s *Service) commonHookFields(f *hookFields, name string, suffixes []string, wait *int) validate.Errors {
	var errs validate.Errors
	var fe *validate.FieldError
	if f.name, fe = validName("name", name); fe != nil {
		errs = append(errs, *fe)
	}
	if f.suffixes, fe = normSuffixes("allowed_suffixes", suffixes); fe != nil {
		errs = append(errs, *fe)
	}
	if wait != nil {
		f.wait = *wait
	}
	if f.poll == 0 {
		f.poll = DefaultACMEPollTimeoutSeconds
	}
	return append(errs, validHookWaits(f.wait, f.poll)...)
}

// providerRefusesHookFields refuses a hook's own fields on a provider.
func providerRefusesHookFields(url, bundle, secret bool) validate.Errors {
	var errs validate.Errors
	for field, given := range map[string]bool{"url": url, "ca_bundle_pem": bundle, "secret": secret} {
		if given {
			errs.Add(field, validate.Pattern, nil)
		}
	}
	slices.SortFunc(errs, func(a, b validate.FieldError) int { return strings.Compare(a.Field, b.Field) })
	return errs
}

func validateACMEHook(in ACMEHookInput) (hookFields, validate.Errors) {
	var errs validate.Errors
	f := hookFields{kind: ACMEHookKindWebhook, wait: DefaultACMEPropagationWaitSeconds, poll: in.PollTimeoutSeconds}
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

const hookColumns = `id, kind, settings, name::text, url, ca_bundle_pem, allowed_suffixes, propagation_wait_seconds, poll_timeout_seconds,
created_by, created_at, updated_at`

func scanHook(row pgx.Row) (ACMEHook, error) {
	h := ACMEHook{SecretConfigured: true} // secret_ct is NOT NULL
	var settings []byte
	err := row.Scan(&h.ID, &h.Kind, &settings, &h.Name, &h.URL, &h.CABundlePEM, &h.AllowedSuffixes, &h.PropagationWaitSeconds, &h.PollTimeoutSeconds,
		&h.CreatedBy, &h.CreatedAt, &h.UpdatedAt)
	if err == nil && len(settings) > 0 {
		if jerr := json.Unmarshal(settings, &h.Settings); jerr != nil {
			err = fmt.Errorf("inventory: decode the DNS provider settings: %w", jerr)
		}
	}
	if h.AllowedSuffixes == nil {
		h.AllowedSuffixes = []string{}
	}
	h.Settings.CertNotAfter = utcPtr(h.Settings.CertNotAfter)
	h.CreatedAt, h.UpdatedAt = h.CreatedAt.UTC(), h.UpdatedAt.UTC()
	return h, err
}

// settingsJSON is the stored form of a publisher's settings ("{}" for a hook and Cloudflare).
func settingsJSON(st ACMEDNSSettings) []byte {
	b, err := json.Marshal(st)
	if err != nil {
		return []byte("{}") // unreachable: the struct has strings and a time only
	}
	return b
}

func getACMEHook(ctx context.Context, q db.Querier, id uuid.UUID, forUpdate bool) (ACMEHook, error) {
	lock := ""
	if forUpdate {
		lock = " FOR UPDATE"
	}
	return readACMEHook(ctx, q, id, lock)
}

// readACMEHook reads a live hook with the row lock clause lock ("", " FOR UPDATE", " FOR SHARE").
func readACMEHook(ctx context.Context, q db.Querier, id uuid.UUID, lock string) (ACMEHook, error) {
	sql := "SELECT " + hookColumns + " FROM acme_hooks WHERE id = $1 AND deleted_at IS NULL" + lock
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

// hookDetails are a publisher's audit details. A hook's are what they were before 00030 (no kind key, so existing
// readers of the log see the same rows); a provider's add its kind and identifiers and have no URL.
func hookDetails(f hookFields) map[string]string {
	d := map[string]string{"name": f.name, "allowed_suffixes": suffixesDetail(f.suffixes),
		"propagation_wait_seconds": strconv.Itoa(f.wait), "poll_timeout_seconds": strconv.Itoa(f.poll)}
	if f.kind == ACMEHookKindWebhook || f.kind == "" {
		d["url_host"] = urlHost(f.url)
		return d
	}
	maps.Copy(d, dnsSettingsDetails(f.kind, f.settings))
	return d
}

// CreateACMEHook stores a DNS-01 hook: validation (validate.Errors), the sealed secret, the row and the audit row
// acme.hook.created in one transaction. No network call. ErrACMENameTaken for a live name.
func (s *Service) CreateACMEHook(ctx context.Context, a Actor, in ACMEHookInput) (ACMEHook, error) {
	defer in.Secret.Zero()
	defer in.Credentials.Zero()
	f, errs := s.validateNewHook(in)
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
		_, err := tx.Exec(ctx, `INSERT INTO acme_hooks (id, kind, settings, name, url, ca_bundle_pem, secret_ct, secret_nonce, secret_wrapped_dek,
secret_key_version, allowed_suffixes, propagation_wait_seconds, poll_timeout_seconds, created_by, created_at, updated_at)
VALUES ($1, $14, $15, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)`,
			id, f.name, f.url, f.bundle, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, f.suffixes, f.wait, f.poll, actorRef(a), now,
			f.kind, settingsJSON(f.settings))
		if err != nil {
			return mapACMENameTaken(fmt.Errorf("inventory: store the DNS hook: %w", err))
		}
		if out, err = getACMEHook(ctx, tx, id, false); err != nil {
			return err
		}
		d := hookDetails(f)
		if f.kind == ACMEHookKindWebhook {
			d["ca_bundle"] = strconv.FormatBool(f.bundle != "")
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.hook.created", ObjectType: "acme_hook",
			ObjectID: id.String(), Result: audit.Success, Details: d})
		return err
	})
	if err != nil {
		return ACMEHook{}, err
	}
	return out, nil
}

// validatePatch validates a change of a publisher of any kind: a hook's own fields (validateHookPatch) or a
// provider's (the common fields, then its settings and credentials).
func (s *Service) validatePatch(cur ACMEHook, p ACMEHookPatch) (hookFields, []string, validate.Errors) {
	if cur.Kind == ACMEHookKindWebhook || cur.Kind == "" {
		var errs validate.Errors
		if p.Settings != nil {
			errs.Add("settings", validate.Pattern, nil)
		}
		if p.Credentials.Given() {
			errs.Add("credentials", validate.Pattern, nil)
		}
		f, changed, ferrs := validateHookPatch(cur, p)
		if errs = append(errs, ferrs...); len(errs) > 0 {
			clear(f.secret)
			return hookFields{}, nil, errs
		}
		return f, changed, nil
	}
	// The common fields: a provider has no URL, bundle or shared secret, so those parts of a patch are refused.
	errs := providerRefusesHookFields(p.URL != nil && *p.URL != "", p.CABundlePEM != nil && *p.CABundlePEM != "", len(p.Secret.Bytes()) > 0)
	f, changed, ferrs := validateHookPatch(cur, ACMEHookPatch{Name: p.Name, AllowedSuffixes: p.AllowedSuffixes,
		PropagationWaitSeconds: p.PropagationWaitSeconds, PollTimeoutSeconds: p.PollTimeoutSeconds})
	errs = append(errs, ferrs...)
	f.kind, f.settings = cur.Kind, cur.Settings
	if p.Settings == nil && !p.Credentials.Given() {
		if len(errs) > 0 {
			return hookFields{}, nil, errs
		}
		return f, changed, nil
	}
	in := cur.Settings
	if p.Settings != nil {
		in = *p.Settings
	}
	st, perrs := s.validateDNSProvider(cur.Kind, &cur.Settings, in, p.Credentials, s.clock.Now().UTC())
	if errs = append(errs, perrs...); len(errs) > 0 {
		if st.doc != nil {
			st.doc.zero()
		}
		return hookFields{}, nil, errs
	}
	if !reflectEqualSettings(st.settings, cur.Settings) {
		f.settings, changed = st.settings, append(changed, "settings")
	}
	if st.doc != nil {
		f.secret = st.doc.encode()
		st.doc.zero()
		changed = append(changed, "credentials")
	}
	return f, changed, nil
}

func reflectEqualSettings(a, b ACMEDNSSettings) bool {
	return string(settingsJSON(a)) == string(settingsJSON(b))
}

// validateHookPatch normalizes the fields a patch sets and lists the fields that change.
func validateHookPatch(cur ACMEHook, p ACMEHookPatch) (hookFields, []string, validate.Errors) {
	var errs validate.Errors
	f := hookFields{kind: ACMEHookKindWebhook, name: cur.Name, url: cur.URL, bundle: cur.CABundlePEM, suffixes: cur.AllowedSuffixes,
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
	defer p.Credentials.Zero()
	var out ACMEHook
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMEHook(ctx, tx, id, true)
		if err != nil {
			return err
		}
		f, changed, errs := s.validatePatch(cur, p)
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
secret_wrapped_dek = COALESCE($10, secret_wrapped_dek), secret_key_version = COALESCE($11, secret_key_version), updated_at = $12,
settings = $13 WHERE id = $1`,
			id, f.name, f.url, f.bundle, f.suffixes, f.wait, f.poll, env.Ciphertext, env.Nonce, env.WrappedDEK, version, s.clock.Now().UTC(),
			settingsJSON(f.settings))
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
		d := map[string]string{"name": cur.Name, "url_host": urlHost(cur.URL)}
		if cur.Kind != ACMEHookKindWebhook {
			d = map[string]string{"name": cur.Name, "kind": cur.Kind}
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.hook.deleted", ObjectType: "acme_hook",
			ObjectID: id.String(), Result: audit.Success, Details: d})
		return err
	})
}

// ACMEHookSolverConfig is the solver configuration of a live DNS publisher for an order (Task 10, R57), with the
// opened secret or credentials: the caller builds the solver (dnssolver.New) and zeroes the configuration at once
// (cfg.Zero). ErrNotFound, ErrACMESecretUnreadable, *ACMEError tls_trust_failed when the e2e trust file
// (Config.ACMERoots) cannot be read.
func (s *Service) ACMEHookSolverConfig(ctx context.Context, hookID uuid.UUID) (dnssolver.Config, error) {
	return s.hookSolverConfig(ctx, hookID, true)
}

// ACMEHookCleanupConfig is ACMEHookSolverConfig for the cleanup of a record an order presented through the publisher:
// it may have been deleted since (its row and secret stay), and the caller sets the allow-list to the record's own
// name (cfg.WithCleanupNames: the record was published by Alice; removing it needs no allow-list).
func (s *Service) ACMEHookCleanupConfig(ctx context.Context, hookID uuid.UUID) (dnssolver.Config, error) {
	return s.hookSolverConfig(ctx, hookID, false)
}

func (s *Service) hookSolverConfig(ctx context.Context, hookID uuid.UUID, live bool) (dnssolver.Config, error) {
	sql := "SELECT " + hookColumns + " FROM acme_hooks WHERE id = $1"
	if live {
		sql += " AND deleted_at IS NULL"
	}
	h, err := scanHook(s.pool.QueryRow(ctx, sql, hookID))
	if errors.Is(err, pgx.ErrNoRows) {
		return dnssolver.Config{}, ErrNotFound
	}
	if err != nil {
		return dnssolver.Config{}, fmt.Errorf("inventory: read the DNS hook: %w", err)
	}
	base, err := s.acmeBaseRoots()
	if err != nil {
		return dnssolver.Config{}, acmeFailure(err)
	}
	var env secrets.Envelope
	if err := s.pool.QueryRow(ctx, "SELECT secret_ct, secret_nonce, secret_wrapped_dek, secret_key_version FROM acme_hooks WHERE id = $1", hookID).
		Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion); err != nil {
		return dnssolver.Config{}, fmt.Errorf("inventory: read the DNS hook secret: %w", err)
	}
	pt, err := s.keyring.Open(hookSecretLocation(hookID), env)
	if err != nil {
		return dnssolver.Config{}, ErrACMESecretUnreadable
	}
	wait := time.Duration(h.PropagationWaitSeconds) * time.Second
	if wait == 0 {
		wait = -1 // dns01 and dnsapi: a negative wait is none (0 would be their default)
	}
	poll := time.Duration(h.PollTimeoutSeconds) * time.Second
	cfg := dnssolver.Config{Kind: h.Kind, AllowedSuffixes: slices.Clone(h.AllowedSuffixes), PropagationWait: wait, PollTimeout: poll}
	if h.Kind == ACMEHookKindWebhook {
		cfg.Hook = dns01.Config{URL: h.URL, Secret: pt, CABundlePEM: h.CABundlePEM, BaseRoots: base, PropagationWait: wait,
			PollTimeout: poll, AllowedSuffixes: slices.Clone(h.AllowedSuffixes)}
		return cfg, nil
	}
	doc, err := decodeDNSCredentials(pt.Bytes())
	pt.Zero()
	if err != nil {
		return dnssolver.Config{}, ErrACMESecretUnreadable
	}
	dnsSolverConfig(h.Kind, h.Settings, doc, base, &cfg)
	return cfg, nil
}
