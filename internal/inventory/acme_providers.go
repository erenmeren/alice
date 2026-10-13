package inventory

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// ACME certificate authorities (plan 2026-10-13 Task 9; design rows 3 and 4; amendments A9, A10).
//
// A provider is an ACME directory URL, an optional CA bundle (public certificates added to the system roots of the
// guarded transport), an optional external account binding (a key id and a sealed HMAC key, AAD
// acme_providers/<id>/eab_hmac) and the name allow-list of A9. Creating or changing one makes no network call: the
// first contact with the CA is the account registration (acme_accounts.go). The EAB HMAC key is write-only: no view
// carries it, only EABConfigured. Audit rows name ids, names and the directory's host; never the bundle, a key id or
// a secret. Who may call these methods is the API's decision (AcmeManage, step-up); the service takes the Actor.

// Limits of a provider and a hook (the migration's CHECKs are the outer bound).
const (
	maxACMEURLLen         = 2048
	maxACMECABundleBytes  = 64 << 10
	maxACMECABundleCerts  = 10
	maxACMEEABKIDLen      = 255
	maxACMEEABHMACLen     = 1024
	minACMEEABHMACBytes   = 16
	maxACMEAllowedSuffix  = 100
	maxACMESuffixLen      = 253
	maxACMEAuditSuffixLen = 1024
)

// Presets of a provider: they only pre-fill the form (no call is made because of one).
const (
	ACMEPresetLetsEncrypt        = "letsencrypt"
	ACMEPresetLetsEncryptStaging = "letsencrypt_staging"
	ACMEPresetZeroSSL            = "zerossl"
	ACMEPresetCustom             = "custom"
)

// ACMEPresets lists the presets.
func ACMEPresets() []string {
	return []string{ACMEPresetLetsEncrypt, ACMEPresetLetsEncryptStaging, ACMEPresetZeroSSL, ACMEPresetCustom}
}

// Refusals of the ACME providers, accounts and hooks. None carries a value from the database or the CA.
var (
	// ErrACMEProviderInUse: the provider has an active (or pending) account or live ACME certificates (ALC-ACM-0012).
	ErrACMEProviderInUse = errors.New("inventory: the ACME provider still has an account or certificates")
	// ErrACMEHookInUse: live ACME certificates publish their DNS-01 challenges through the hook.
	ErrACMEHookInUse = errors.New("inventory: the DNS hook is used by ACME certificates")
	// ErrACMENameTaken: another live provider (or hook) has this name.
	ErrACMENameTaken = errors.New("inventory: an ACME provider or DNS hook with this name exists")
	// ErrACMEDirectoryChange: the directory URL of a provider with an active account changes only with an explicit
	// confirmation (the account then belongs to another CA and is retired), or it changed while an account was
	// being registered.
	ErrACMEDirectoryChange = errors.New("inventory: the directory of a provider with an active account changes only when confirmed")
	// ErrACMESecretUnreadable: a sealed ACME secret (account key, EAB HMAC key, hook secret) cannot be opened with
	// this master key.
	ErrACMESecretUnreadable = errors.New("inventory: a sealed ACME secret cannot be decrypted with this master key")
)

// ACMEProvider is the view of a provider. It has no secret: the EAB HMAC key is write-only (EABConfigured).
type ACMEProvider struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	DirectoryURL    string     `json:"directory_url"`
	Preset          string     `json:"preset"`
	CABundlePEM     string     `json:"ca_bundle_pem"` // public certificates only
	EABKID          string     `json:"eab_kid"`
	EABConfigured   bool       `json:"eab_configured"`
	AllowedSuffixes []string   `json:"allowed_suffixes"`
	ActiveAccountID *uuid.UUID `json:"active_account_id,omitempty"`
	PendingRollover bool       `json:"pending_rollover"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ACMEEABInput is an external account binding as the CA hands it out. HMAC is the base64url text; the call that
// receives it zeroes it, whatever the outcome.
type ACMEEABInput struct {
	KID  string
	HMAC secrets.Plaintext
}

// ACMEProviderInput is the input of CreateACMEProvider. EAB is optional.
type ACMEProviderInput struct {
	Name            string
	DirectoryURL    string
	Preset          string // "" = custom
	CABundlePEM     string // "" = system roots only
	EAB             *ACMEEABInput
	AllowedSuffixes []string // empty = every order is refused (A9)
}

// ACMEProviderPatch is the input of UpdateACMEProvider: nil fields stay. EAB replaces the binding; RemoveEAB drops it
// (not both). ConfirmDirectoryChange allows a new directory URL while the provider has an active account (that
// account is retired: it belongs to the old CA).
type ACMEProviderPatch struct {
	Name                   *string
	DirectoryURL           *string
	Preset                 *string
	CABundlePEM            *string
	AllowedSuffixes        *[]string
	EAB                    *ACMEEABInput
	RemoveEAB              bool
	ConfirmDirectoryChange bool
}

func (e *ACMEEABInput) clear() {
	if e != nil {
		e.HMAC.Zero()
	}
}

// eabLocation binds a provider's sealed EAB HMAC key to its row.
func eabLocation(id uuid.UUID) secrets.Location {
	return secrets.Location{Table: "acme_providers", RowID: id.String(), Column: "eab_hmac"}
}

// normACMEURL checks an https URL without credentials, query or fragment (the directory or a hook): a query is where
// a secret would hide, and the URL is shown to every role that may read the settings.
func normACMEURL(field, raw string) (string, *validate.FieldError) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", &validate.FieldError{Field: field, Code: validate.Required}
	}
	if len(s) > maxACMEURLLen {
		return "", &validate.FieldError{Field: field, Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(maxACMEURLLen)}}
	}
	if strings.ContainsFunc(s, func(r rune) bool { return r <= 0x20 || r >= 0x7f }) {
		return "", &validate.FieldError{Field: field, Code: validate.Pattern}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		return "", &validate.FieldError{Field: field, Code: validate.Pattern}
	}
	return u.String(), nil
}

// urlHost is the host (and port) of a stored URL: the only part of it an audit row keeps.
func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// normCABundle checks a CA bundle: PEM CERTIFICATE blocks only (no private key, no other block, no headers, nothing
// but white space around them), 1 to 10 parsable certificates, at most 64 KiB. The stored form is the certificates
// re-encoded, so nothing but them is ever kept. "" stays "" (no bundle).
func normCABundle(field, raw string) (string, *validate.FieldError) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	if len(raw) > maxACMECABundleBytes {
		return "", &validate.FieldError{Field: field, Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(maxACMECABundleBytes)}}
	}
	rest := []byte(raw)
	var out strings.Builder
	n := 0
	for {
		// pem.Decode skips any text before a block: only white space may stand there.
		if i := strings.Index(string(rest), "-----BEGIN"); i < 0 || strings.TrimSpace(string(rest[:i])) != "" {
			break
		}
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return "", &validate.FieldError{Field: field, Code: validate.Pattern}
		}
		if b.Type != "CERTIFICATE" || len(b.Headers) > 0 {
			return "", &validate.FieldError{Field: field, Code: validate.Pattern}
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return "", &validate.FieldError{Field: field, Code: validate.Pattern}
		}
		if n++; n > maxACMECABundleCerts {
			return "", &validate.FieldError{Field: field, Code: validate.OutOfRange, Params: map[string]string{"min": "1", "max": strconv.Itoa(maxACMECABundleCerts)}}
		}
		out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes}))
	}
	if n == 0 || strings.TrimSpace(string(rest)) != "" {
		return "", &validate.FieldError{Field: field, Code: validate.Pattern}
	}
	return out.String(), nil
}

// normEAB checks a binding: a printable key id and a base64url HMAC key of at least 16 bytes (padding allowed). It
// returns the key id and the HMAC text without padding, a fresh copy the caller seals and zeroes.
func normEAB(e *ACMEEABInput) (string, []byte, validate.Errors) {
	var errs validate.Errors
	kid := strings.TrimSpace(e.KID)
	switch {
	case kid == "":
		errs.Add("eab_kid", validate.Required, nil)
	case len(kid) > maxACMEEABKIDLen:
		errs.Add("eab_kid", validate.TooLong, map[string]string{"max": strconv.Itoa(maxACMEEABKIDLen)})
	case strings.ContainsFunc(kid, func(r rune) bool { return r < 0x21 || r > 0x7e }):
		errs.Add("eab_kid", validate.Pattern, nil)
	}
	text := e.HMAC.Bytes()
	for len(text) > 0 && (text[len(text)-1] == '=' || text[len(text)-1] == ' ' || text[len(text)-1] == '\n' || text[len(text)-1] == '\r') {
		text = text[:len(text)-1]
	}
	for len(text) > 0 && (text[0] == ' ' || text[0] == '\n' || text[0] == '\r') {
		text = text[1:]
	}
	switch {
	case len(text) == 0:
		errs.Add("eab_hmac", validate.Required, nil)
	case len(text) > maxACMEEABHMACLen:
		errs.Add("eab_hmac", validate.TooLong, map[string]string{"max": strconv.Itoa(maxACMEEABHMACLen)})
	default:
		raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(text)))
		n, err := base64.RawURLEncoding.Decode(raw, text)
		clear(raw)
		if err != nil || n < minACMEEABHMACBytes {
			errs.Add("eab_hmac", validate.Pattern, nil)
		}
	}
	if len(errs) > 0 {
		return "", nil, errs
	}
	return kid, slices.Clone(text), nil
}

// normDNSSuffix lower-cases a domain suffix and checks it: DNS labels of letters, digits and inner hyphens, an
// optional leading dot (names below the suffix only), no wildcard, no trailing dot.
func normDNSSuffix(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	dot := strings.HasPrefix(s, ".")
	d := []byte(strings.TrimPrefix(s, "."))
	for i, c := range d {
		if c >= 'A' && c <= 'Z' {
			d[i] = c + 'a' - 'A'
		}
	}
	if len(d) == 0 || len(d) > maxACMESuffixLen {
		return "", false
	}
	for _, l := range strings.Split(string(d), ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	if dot {
		return "." + string(d), true
	}
	return string(d), true
}

// normSuffixes checks an allow-list (A9): at most 100 distinct suffixes. The result is never nil (an empty list is
// stored as '{}' and refuses every name).
func normSuffixes(field string, in []string) ([]string, *validate.FieldError) {
	if len(in) > maxACMEAllowedSuffix {
		return nil, &validate.FieldError{Field: field, Code: validate.OutOfRange, Params: map[string]string{"min": "0", "max": strconv.Itoa(maxACMEAllowedSuffix)}}
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s, ok := normDNSSuffix(raw)
		if !ok {
			return nil, &validate.FieldError{Field: field, Code: validate.Pattern}
		}
		if slices.Contains(out, s) {
			return nil, &validate.FieldError{Field: field, Code: validate.Duplicate}
		}
		out = append(out, s)
	}
	return out, nil
}

// ACMENameAllowed reports whether an allow-list admits a DNS name (A9), on label boundaries: "example.com" admits
// example.com and every name below it, ".example.com" only the names below it; a wildcard name "*.x" is judged by
// x; an empty list admits nothing. Names are compared in ASCII lower case (IDNs arrive as xn-- labels).
func ACMENameAllowed(suffixes []string, name string) bool {
	n, ok := normDNSSuffix(strings.TrimPrefix(strings.TrimSpace(name), "*."))
	if !ok || strings.HasPrefix(n, ".") {
		return false
	}
	for _, raw := range suffixes {
		sf, ok := normDNSSuffix(raw)
		switch {
		case !ok:
			continue
		case strings.HasPrefix(sf, "."):
			if strings.HasSuffix(n, sf) {
				return true
			}
		case n == sf || strings.HasSuffix(n, "."+sf):
			return true
		}
	}
	return false
}

// suffixesDetail is the allow-list as one bounded audit value.
func suffixesDetail(s []string) string {
	v := strings.Join(s, ",")
	if len(v) > maxACMEAuditSuffixLen {
		v = v[:maxACMEAuditSuffixLen]
	}
	return v
}

func validPreset(field, raw string) (string, *validate.FieldError) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return ACMEPresetCustom, nil
	}
	if !slices.Contains(ACMEPresets(), p) {
		return "", &validate.FieldError{Field: field, Code: validate.OneOf, Params: map[string]string{"values": strings.Join(ACMEPresets(), ", ")}}
	}
	return p, nil
}

// providerFields are the stored values of a provider (EAB HMAC as the plaintext about to be sealed).
type providerFields struct {
	name, directoryURL, preset, bundle, eabKID string
	eabHMAC                                    []byte // nil = no binding
	suffixes                                   []string
}

func (f *providerFields) clear() { clear(f.eabHMAC) }

func validateACMEProvider(in ACMEProviderInput) (providerFields, validate.Errors) {
	var errs validate.Errors
	var f providerFields
	add := func(fe *validate.FieldError) {
		if fe != nil {
			errs = append(errs, *fe)
		}
	}
	var fe *validate.FieldError
	f.name, fe = validName("name", in.Name)
	add(fe)
	f.directoryURL, fe = normACMEURL("directory_url", in.DirectoryURL)
	add(fe)
	f.preset, fe = validPreset("preset", in.Preset)
	add(fe)
	f.bundle, fe = normCABundle("ca_bundle_pem", in.CABundlePEM)
	add(fe)
	f.suffixes, fe = normSuffixes("allowed_suffixes", in.AllowedSuffixes)
	add(fe)
	if in.EAB != nil {
		kid, hmac, eerrs := normEAB(in.EAB)
		errs = append(errs, eerrs...)
		f.eabKID, f.eabHMAC = kid, hmac
	}
	if len(errs) > 0 {
		f.clear()
	}
	return f, errs
}

// sealEAB seals a provider's EAB HMAC text; nil text seals nothing.
func (s *Service) sealEAB(id uuid.UUID, text []byte) (*secrets.Envelope, error) {
	if text == nil {
		return nil, nil
	}
	env, err := s.keyring.Seal(eabLocation(id), text)
	if err != nil {
		return nil, fmt.Errorf("inventory: seal the EAB key: %w", err)
	}
	return &env, nil
}

// envCols are the four columns of an optional envelope (all NULL for nil).
func envCols(e *secrets.Envelope) (ct, nonce, dek []byte, version *int) {
	if e == nil {
		return nil, nil, nil, nil
	}
	v := e.KeyVersion
	return e.Ciphertext, e.Nonce, e.WrappedDEK, &v
}

// actorRef is the user id of an actor for a created_by column (NULL for Alice herself).
func actorRef(a Actor) *uuid.UUID {
	if a.UserID == uuid.Nil {
		return nil
	}
	id := a.UserID
	return &id
}

// mapACMENameTaken turns the live-name unique indexes into ErrACMENameTaken.
func mapACMENameTaken(err error) error {
	if db.IsUniqueViolationOn(err, "acme_providers_name") || db.IsUniqueViolationOn(err, "acme_hooks_name") {
		return ErrACMENameTaken
	}
	return err
}

const providerColumns = `p.id, p.name::text, p.directory_url, p.preset, p.ca_bundle_pem, p.eab_kid, p.eab_hmac_ct IS NOT NULL,
p.allowed_suffixes, p.created_by, p.created_at, p.updated_at,
(SELECT a.id FROM acme_accounts a WHERE a.provider_id = p.id AND a.state = 'active'),
EXISTS (SELECT 1 FROM acme_accounts a WHERE a.provider_id = p.id AND a.state = 'pending_rollover')`

func scanProvider(row pgx.Row) (ACMEProvider, error) {
	var p ACMEProvider
	err := row.Scan(&p.ID, &p.Name, &p.DirectoryURL, &p.Preset, &p.CABundlePEM, &p.EABKID, &p.EABConfigured, &p.AllowedSuffixes,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.ActiveAccountID, &p.PendingRollover)
	if p.AllowedSuffixes == nil {
		p.AllowedSuffixes = []string{}
	}
	p.CreatedAt, p.UpdatedAt = p.CreatedAt.UTC(), p.UpdatedAt.UTC()
	return p, err
}

// getACMEProvider reads a live provider; forUpdate locks its row.
func getACMEProvider(ctx context.Context, q db.Querier, id uuid.UUID, forUpdate bool) (ACMEProvider, error) {
	sql := "SELECT " + providerColumns + " FROM acme_providers p WHERE p.id = $1 AND p.deleted_at IS NULL"
	if forUpdate {
		sql += " FOR UPDATE OF p"
	}
	p, err := scanProvider(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEProvider{}, ErrNotFound
	}
	if err != nil {
		return ACMEProvider{}, fmt.Errorf("inventory: read the ACME provider: %w", err)
	}
	return p, nil
}

// GetACMEProvider returns a live provider (ErrNotFound otherwise).
func (s *Service) GetACMEProvider(ctx context.Context, id uuid.UUID) (ACMEProvider, error) {
	return getACMEProvider(ctx, s.pool, id, false)
}

// ListACMEProviders returns the live providers by name.
func (s *Service) ListACMEProviders(ctx context.Context) ([]ACMEProvider, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+providerColumns+" FROM acme_providers p WHERE p.deleted_at IS NULL ORDER BY p.name, p.id")
	if err != nil {
		return nil, fmt.Errorf("inventory: list the ACME providers: %w", err)
	}
	defer rows.Close()
	out := []ACMEProvider{}
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: read an ACME provider: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreateACMEProvider stores a provider: validation (validate.Errors), the sealed EAB HMAC key, the row and the audit
// row acme.provider.created in one transaction. No network call is made. ErrACMENameTaken for a live name.
func (s *Service) CreateACMEProvider(ctx context.Context, a Actor, in ACMEProviderInput) (ACMEProvider, error) {
	defer in.EAB.clear()
	f, errs := validateACMEProvider(in)
	if len(errs) > 0 {
		return ACMEProvider{}, errs
	}
	defer f.clear()
	id := uuid.Must(uuid.NewV7())
	env, err := s.sealEAB(id, f.eabHMAC)
	if err != nil {
		return ACMEProvider{}, err
	}
	now := s.clock.Now().UTC()
	var out ACMEProvider
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		ct, nonce, dek, version := envCols(env)
		_, err := tx.Exec(ctx, `INSERT INTO acme_providers (id, name, directory_url, ca_bundle_pem, preset, eab_kid, eab_hmac_ct, eab_hmac_nonce,
eab_hmac_wrapped_dek, eab_hmac_key_version, allowed_suffixes, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)`,
			id, f.name, f.directoryURL, f.bundle, f.preset, f.eabKID, ct, nonce, dek, version, f.suffixes, actorRef(a), now)
		if err != nil {
			return mapACMENameTaken(fmt.Errorf("inventory: store the ACME provider: %w", err))
		}
		if out, err = getACMEProvider(ctx, tx, id, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.provider.created", ObjectType: "acme_provider",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"name": f.name, "directory_host": urlHost(f.directoryURL),
				"preset": f.preset, "eab_configured": strconv.FormatBool(env != nil), "ca_bundle": strconv.FormatBool(f.bundle != ""),
				"allowed_suffixes": suffixesDetail(f.suffixes)}})
		return err
	})
	if err != nil {
		return ACMEProvider{}, err
	}
	return out, nil
}

// validateProviderPatch normalizes the fields a patch sets (the others keep cur's values) and lists the fields that
// change.
func validateProviderPatch(cur ACMEProvider, p ACMEProviderPatch) (providerFields, []string, validate.Errors) {
	var errs validate.Errors
	f := providerFields{name: cur.Name, directoryURL: cur.DirectoryURL, preset: cur.Preset, bundle: cur.CABundlePEM, eabKID: cur.EABKID,
		suffixes: cur.AllowedSuffixes}
	var changed []string
	add := func(fe *validate.FieldError) {
		if fe != nil {
			errs = append(errs, *fe)
		}
	}
	var fe *validate.FieldError
	if p.Name != nil {
		var v string
		v, fe = validName("name", *p.Name)
		add(fe)
		if fe == nil && v != f.name {
			f.name, changed = v, append(changed, "name")
		}
	}
	if p.DirectoryURL != nil {
		var v string
		v, fe = normACMEURL("directory_url", *p.DirectoryURL)
		add(fe)
		if fe == nil && v != f.directoryURL {
			f.directoryURL, changed = v, append(changed, "directory_url")
		}
	}
	if p.Preset != nil {
		var v string
		v, fe = validPreset("preset", *p.Preset)
		add(fe)
		if fe == nil && v != f.preset {
			f.preset, changed = v, append(changed, "preset")
		}
	}
	if p.CABundlePEM != nil {
		var v string
		v, fe = normCABundle("ca_bundle_pem", *p.CABundlePEM)
		add(fe)
		if fe == nil && v != f.bundle {
			f.bundle, changed = v, append(changed, "ca_bundle")
		}
	}
	if p.AllowedSuffixes != nil {
		var v []string
		v, fe = normSuffixes("allowed_suffixes", *p.AllowedSuffixes)
		add(fe)
		if fe == nil && !slices.Equal(v, f.suffixes) {
			f.suffixes, changed = v, append(changed, "allowed_suffixes")
		}
	}
	switch {
	case p.EAB != nil && p.RemoveEAB:
		errs.Add("eab", validate.Pattern, nil)
	case p.EAB != nil:
		kid, hmac, eerrs := normEAB(p.EAB)
		errs = append(errs, eerrs...)
		f.eabKID, f.eabHMAC = kid, hmac
		changed = append(changed, "eab")
	case p.RemoveEAB && cur.EABConfigured:
		f.eabKID = ""
		changed = append(changed, "eab")
	}
	if len(errs) > 0 {
		f.clear()
	}
	return f, changed, errs
}

// UpdateACMEProvider changes a provider. A new EAB binding is sealed again; RemoveEAB drops it. The directory URL of
// a provider with an active account changes only with ConfirmDirectoryChange (ErrACMEDirectoryChange otherwise): the
// account then belongs to another CA and is retired in the same transaction. While a key rollover is unsettled the
// directory cannot change (ErrACMERolloverPending). One audit row acme.provider.updated names the fields that
// changed; a patch that changes nothing writes nothing.
func (s *Service) UpdateACMEProvider(ctx context.Context, a Actor, id uuid.UUID, p ACMEProviderPatch) (ACMEProvider, error) {
	defer p.EAB.clear()
	var out ACMEProvider
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMEProvider(ctx, tx, id, true)
		if err != nil {
			return err
		}
		f, changed, errs := validateProviderPatch(cur, p)
		if len(errs) > 0 {
			return errs
		}
		defer f.clear()
		if len(changed) == 0 {
			out = cur
			return nil
		}
		details := map[string]string{"name": f.name, "directory_host": urlHost(f.directoryURL), "fields": strings.Join(changed, ",")}
		now := s.clock.Now().UTC()
		if slices.Contains(changed, "directory_url") {
			if cur.PendingRollover {
				return ErrACMERolloverPending
			}
			if cur.ActiveAccountID != nil {
				if !p.ConfirmDirectoryChange {
					return ErrACMEDirectoryChange
				}
				if _, err := tx.Exec(ctx, "UPDATE acme_accounts SET state = 'retired', updated_at = $2 WHERE id = $1 AND state = 'active'",
					*cur.ActiveAccountID, now); err != nil {
					return fmt.Errorf("inventory: retire the ACME account: %w", err)
				}
				details["retired_account_id"] = cur.ActiveAccountID.String()
			}
		}
		eabChanged := slices.Contains(changed, "eab")
		var env *secrets.Envelope
		if eabChanged {
			if env, err = s.sealEAB(id, f.eabHMAC); err != nil {
				return err
			}
			details["eab_configured"] = strconv.FormatBool(env != nil)
		}
		if slices.Contains(changed, "allowed_suffixes") {
			details["allowed_suffixes"] = suffixesDetail(f.suffixes)
		}
		ct, nonce, dek, version := envCols(env)
		_, err = tx.Exec(ctx, `UPDATE acme_providers SET name = $2, directory_url = $3, preset = $4, ca_bundle_pem = $5, allowed_suffixes = $6,
eab_kid = CASE WHEN $7 THEN $8 ELSE eab_kid END, eab_hmac_ct = CASE WHEN $7 THEN $9 ELSE eab_hmac_ct END,
eab_hmac_nonce = CASE WHEN $7 THEN $10 ELSE eab_hmac_nonce END, eab_hmac_wrapped_dek = CASE WHEN $7 THEN $11 ELSE eab_hmac_wrapped_dek END,
eab_hmac_key_version = CASE WHEN $7 THEN $12 ELSE eab_hmac_key_version END, updated_at = $13 WHERE id = $1`,
			id, f.name, f.directoryURL, f.preset, f.bundle, f.suffixes, eabChanged, f.eabKID, ct, nonce, dek, version, now)
		if err != nil {
			return mapACMENameTaken(fmt.Errorf("inventory: update the ACME provider: %w", err))
		}
		if out, err = getACMEProvider(ctx, tx, id, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.provider.updated", ObjectType: "acme_provider",
			ObjectID: id.String(), Result: audit.Success, Details: details})
		return err
	})
	if err != nil {
		return ACMEProvider{}, err
	}
	return out, nil
}

// DeleteACMEProvider soft-deletes a provider. A provider with an active or pending account, or with live ACME
// certificates, is refused (ErrACMEProviderInUse): deactivate the account and delete the certificates first. The
// name can be used again at once. Audit acme.provider.deleted.
func (s *Service) DeleteACMEProvider(ctx context.Context, a Actor, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMEProvider(ctx, tx, id, true)
		if err != nil {
			return err
		}
		var inUse bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM acme_accounts WHERE provider_id = $1 AND state IN ('active', 'pending_rollover'))
OR EXISTS (SELECT 1 FROM acme_certificates WHERE provider_id = $1 AND deleted_at IS NULL)`, id).Scan(&inUse); err != nil {
			return fmt.Errorf("inventory: look for the ACME provider's users: %w", err)
		}
		if inUse {
			return ErrACMEProviderInUse
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, "UPDATE acme_providers SET deleted_at = $2, updated_at = $2 WHERE id = $1", id, now); err != nil {
			return fmt.Errorf("inventory: delete the ACME provider: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.provider.deleted", ObjectType: "acme_provider",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"name": cur.Name, "directory_host": urlHost(cur.DirectoryURL)}})
		return err
	})
}

// openEAB opens a provider's sealed EAB HMAC text (nil when the provider has none). The caller zeroes it.
func (s *Service) openEAB(ctx context.Context, q db.Querier, id uuid.UUID) (string, secrets.Plaintext, error) {
	var kid string
	var env secrets.Envelope
	var version *int
	err := q.QueryRow(ctx, `SELECT eab_kid, eab_hmac_ct, eab_hmac_nonce, eab_hmac_wrapped_dek, eab_hmac_key_version FROM acme_providers WHERE id = $1`, id).
		Scan(&kid, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", secrets.Plaintext{}, ErrNotFound
	}
	if err != nil {
		return "", secrets.Plaintext{}, fmt.Errorf("inventory: read the EAB key: %w", err)
	}
	if version == nil {
		return "", secrets.Plaintext{}, nil
	}
	env.KeyVersion = *version
	pt, err := s.keyring.Open(eabLocation(id), env)
	if err != nil {
		return "", secrets.Plaintext{}, ErrACMESecretUnreadable
	}
	return kid, pt, nil
}
