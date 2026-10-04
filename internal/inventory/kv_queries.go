package inventory

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/azureid"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// The vault inventory as the screens read it (spec §11.1): certificates (with their versions and
// binding), keys and secrets of one vault, paged by name. Names are ordered and matched by their
// ASCII fold (lower(name COLLATE "C")), as the unique indexes are.

const (
	defaultKVLimit = 50
	maxKVLimit     = 200
)

// KVMissing values of KVFilter.Missing.
const (
	KVMissingHide    = ""        // objects that are present (default)
	KVMissingInclude = "include" // present and missing
	KVMissingOnly    = "only"    // missing ones
)

// KVFilter selects objects of one vault. Query is a case-insensitive substring of the name;
// ExpiresBefore keeps objects that have an expiry before it (none without one); Cursor is the
// NextCursor of the previous page; Limit is 1..200 (0 = 50).
type KVFilter struct {
	Query         string
	ExpiresBefore *time.Time
	Missing       string
	Cursor        string
	Limit         int
}

// KVCertificate is one certificate of a vault.
type KVCertificate struct {
	ID, TargetID                      uuid.UUID
	Name                              string
	CurrentVersion, CurrentThumbprint string // "" until Alice read the details
	KVUpdatedAt                       *time.Time
	ListedThumbprint                  string
	Enabled                           bool
	NotBefore, Expires, KVCreatedAt   *time.Time
	Exportable                        *bool // nil until the policy was read
	KeyType                           string
	KeySize                           int
	ContentType, IssuerName           string
	AutoRenew, DetailsPending         bool
	FirstSeenAt, LastSeenAt           time.Time
	MissingSince                      *time.Time
	Bound                             bool   // a live binding names it
	CurrentHeld                       bool   // the current version is held
	CurrentHeldReason                 string // providers-independent: "license" | "incomplete_chain" | ""
}

// KVVersion is one version of a certificate Alice listed.
type KVVersion struct {
	ID                              uuid.UUID
	Version, Thumbprint             string
	CertificateID                   *uuid.UUID // the leaf's certificates row (versions Alice saw as current)
	Enabled                         bool
	NotBefore, Expires, KVCreatedAt *time.Time
	Exportable                      *bool
	KeyType, ContentType            string
	DetectedAt                      time.Time
	Held                            bool
	HeldReason                      string
	NotifiedAt, SkippedNotifiedAt   *time.Time
}

// BindingSummary is a certificate's live binding to websites (Task 12 adds the operations).
type BindingSummary struct {
	ID             uuid.UUID
	AutoDeploy     bool
	AutoSince      *time.Time
	StoppedVersion string
	LocationCount  int
	Version        int
	CreatedAt      time.Time
}

// DeployAccess values of KVCertificateDetail.
const (
	DeployAccessOK         = "ok"
	DeployAccessForbidden  = "forbidden"
	DeployAccessNotChecked = "not_checked"
)

// KVCertificateDetail is a certificate with its versions (newest first) and binding.
type KVCertificateDetail struct {
	KVCertificate
	Versions []KVVersion
	Binding  *BindingSummary
	// DeployAccess: ok after a Key Vault deployment from this vault succeeded or an access check
	// read a secret, forbidden when the access check says so, else not_checked. The most recent
	// evidence wins.
	DeployAccess string
}

// KVCertificatePage is one page of certificates.
type KVCertificatePage struct {
	Items      []KVCertificate
	NextCursor string
}

// KVKey is the metadata of one key (never key material).
type KVKey struct {
	ID, TargetID                  uuid.UUID
	Name, Version, KeyType, Curve string
	HSM, Managed, Enabled         bool
	KeySize                       int
	DetailsUpdatedAt              *time.Time
	DetailsProblem                string // "" | "forbidden" | "failed"
	NotBefore, Expires            *time.Time
	KVCreatedAt, KVUpdatedAt      *time.Time
	FirstSeenAt, LastSeenAt       time.Time
	MissingSince                  *time.Time
}

// KVSecret is the metadata of one secret (never its value).
type KVSecret struct {
	ID, TargetID             uuid.UUID
	Name, ContentType        string
	Managed, Enabled         bool
	NotBefore, Expires       *time.Time
	KVCreatedAt, KVUpdatedAt *time.Time
	FirstSeenAt, LastSeenAt  time.Time
	MissingSince             *time.Time
}

type kvPage struct {
	limit           int
	pattern, cursor string
}

// checkKVFilter validates a filter (every problem reported) and returns what the queries bind.
func checkKVFilter(f KVFilter) (kvPage, error) {
	var errs validate.Errors
	pg := kvPage{limit: f.Limit}
	switch {
	case f.Limit == 0:
		pg.limit = defaultKVLimit
	case f.Limit < 1 || f.Limit > maxKVLimit:
		errs.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": fmt.Sprint(maxKVLimit)})
	}
	if !slices.Contains([]string{KVMissingHide, KVMissingInclude, KVMissingOnly}, f.Missing) {
		errs.Add("missing", validate.OneOf, map[string]string{"values": KVMissingInclude + ", " + KVMissingOnly})
	}
	switch {
	case !utf8.ValidString(f.Query) || strings.ContainsRune(f.Query, 0):
		errs.Add("q", validate.Pattern, nil)
	case utf8.RuneCountInString(f.Query) > maxQueryRunes:
		errs.Add("q", validate.TooLong, map[string]string{"max": fmt.Sprint(maxQueryRunes)})
	default:
		if q := strings.TrimSpace(f.Query); q != "" {
			pg.pattern = likePattern(foldASCII(q))
		}
	}
	if f.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(f.Cursor)
		if err != nil || !azureid.ValidObjectName(string(raw)) || string(raw) != foldASCII(string(raw)) {
			errs.Add("cursor", validate.Pattern, nil)
		} else {
			pg.cursor = string(raw)
		}
	}
	if len(errs) > 0 {
		return kvPage{}, errs
	}
	return pg, nil
}

func kvCursor(name string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(foldASCII(name)))
}

// liveVault refuses an unknown or deleted vault (ErrNotFound) and a server (ErrNotAVault).
func (s *Service) liveVault(ctx context.Context, id uuid.UUID) error {
	t, err := readKVTarget(ctx, s.pool, id, "")
	if err != nil {
		return err
	}
	if t.deleted {
		return ErrNotFound
	}
	return nil
}

const kvCertificateColumns = `c.id, c.target_id, c.name, c.current_version, c.current_thumbprint, c.kv_updated_at, c.listed_thumbprint,
c.enabled, c.not_before, c.expires, c.kv_created_at, c.exportable, c.key_type, c.key_size, c.content_type, c.issuer_name, c.auto_renew,
c.details_pending, c.first_seen_at, c.last_seen_at, c.missing_since,
EXISTS (SELECT 1 FROM bindings b WHERE b.kv_certificate_id = c.id AND b.deleted_at IS NULL),
coalesce((SELECT v.held FROM kv_certificate_versions v WHERE v.kv_certificate_id = c.id AND v.version = c.current_version), false),
coalesce((SELECT v.held_reason FROM kv_certificate_versions v WHERE v.kv_certificate_id = c.id AND v.version = c.current_version), '')`

func scanKVCertificate(row pgx.Row) (KVCertificate, error) {
	var c KVCertificate
	err := row.Scan(&c.ID, &c.TargetID, &c.Name, &c.CurrentVersion, &c.CurrentThumbprint, &c.KVUpdatedAt, &c.ListedThumbprint,
		&c.Enabled, &c.NotBefore, &c.Expires, &c.KVCreatedAt, &c.Exportable, &c.KeyType, &c.KeySize, &c.ContentType, &c.IssuerName,
		&c.AutoRenew, &c.DetailsPending, &c.FirstSeenAt, &c.LastSeenAt, &c.MissingSince, &c.Bound, &c.CurrentHeld, &c.CurrentHeldReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return KVCertificate{}, ErrNotFound
	}
	if err != nil {
		return KVCertificate{}, fmt.Errorf("inventory: read a vault certificate: %w", err)
	}
	c.KVUpdatedAt, c.NotBefore, c.Expires, c.KVCreatedAt, c.MissingSince = utcPtr(c.KVUpdatedAt), utcPtr(c.NotBefore), utcPtr(c.Expires),
		utcPtr(c.KVCreatedAt), utcPtr(c.MissingSince)
	c.FirstSeenAt, c.LastSeenAt = c.FirstSeenAt.UTC(), c.LastSeenAt.UTC()
	return c, nil
}

// ListKVCertificates lists a vault's certificates by name (ErrNotFound for an unknown vault,
// ErrNotAVault for a server).
func (s *Service) ListKVCertificates(ctx context.Context, vault uuid.UUID, f KVFilter) (KVCertificatePage, error) {
	pg, err := checkKVFilter(f)
	if err != nil {
		return KVCertificatePage{}, err
	}
	if err := s.liveVault(ctx, vault); err != nil {
		return KVCertificatePage{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+kvCertificateColumns+` FROM kv_certificates c
WHERE c.target_id = $1 AND ($2 = '' OR lower(c.name COLLATE "C") LIKE $2 ESCAPE '\')
  AND ($3::timestamptz IS NULL OR c.expires < $3)
  AND CASE $4 WHEN 'only' THEN c.missing_since IS NOT NULL WHEN 'include' THEN true ELSE c.missing_since IS NULL END
  AND ($5 = '' OR lower(c.name COLLATE "C") > $5)
ORDER BY lower(c.name COLLATE "C") LIMIT $6`, vault, pg.pattern, f.ExpiresBefore, f.Missing, pg.cursor, pg.limit+1)
	if err != nil {
		return KVCertificatePage{}, fmt.Errorf("inventory: list vault certificates: %w", err)
	}
	defer rows.Close()
	page := KVCertificatePage{Items: []KVCertificate{}}
	for rows.Next() {
		c, err := scanKVCertificate(rows)
		if err != nil {
			return KVCertificatePage{}, err
		}
		page.Items = append(page.Items, c)
	}
	if err := rows.Err(); err != nil {
		return KVCertificatePage{}, err
	}
	if len(page.Items) > pg.limit {
		page.Items = page.Items[:pg.limit]
		page.NextCursor = kvCursor(page.Items[pg.limit-1].Name)
	}
	return page, nil
}

// KVCertificate returns one certificate of the vault with its versions (newest first), its live
// binding and what is known about the Deploy access (ErrNotFound for an unknown certificate or
// one of another vault).
func (s *Service) KVCertificate(ctx context.Context, vault, id uuid.UUID) (KVCertificateDetail, error) {
	if err := s.liveVault(ctx, vault); err != nil {
		return KVCertificateDetail{}, err
	}
	c, err := scanKVCertificate(s.pool.QueryRow(ctx, "SELECT "+kvCertificateColumns+" FROM kv_certificates c WHERE c.id = $1 AND c.target_id = $2", id, vault))
	if err != nil {
		return KVCertificateDetail{}, err
	}
	d := KVCertificateDetail{KVCertificate: c, Versions: []KVVersion{}}
	rows, err := s.pool.Query(ctx, `SELECT id, version, thumbprint, certificate_id, enabled, not_before, expires, kv_created_at, exportable, key_type,
content_type, detected_at, held, held_reason, notified_at, skipped_notified_at FROM kv_certificate_versions WHERE kv_certificate_id = $1
ORDER BY coalesce(kv_created_at, detected_at) DESC, detected_at DESC, version DESC`, id)
	if err != nil {
		return KVCertificateDetail{}, fmt.Errorf("inventory: list the versions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v KVVersion
		if err := rows.Scan(&v.ID, &v.Version, &v.Thumbprint, &v.CertificateID, &v.Enabled, &v.NotBefore, &v.Expires, &v.KVCreatedAt, &v.Exportable,
			&v.KeyType, &v.ContentType, &v.DetectedAt, &v.Held, &v.HeldReason, &v.NotifiedAt, &v.SkippedNotifiedAt); err != nil {
			return KVCertificateDetail{}, fmt.Errorf("inventory: read a version: %w", err)
		}
		v.NotBefore, v.Expires, v.KVCreatedAt, v.DetectedAt = utcPtr(v.NotBefore), utcPtr(v.Expires), utcPtr(v.KVCreatedAt), v.DetectedAt.UTC()
		v.NotifiedAt, v.SkippedNotifiedAt = utcPtr(v.NotifiedAt), utcPtr(v.SkippedNotifiedAt)
		d.Versions = append(d.Versions, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return KVCertificateDetail{}, err
	}
	var b BindingSummary
	err = s.pool.QueryRow(ctx, `SELECT b.id, b.auto_deploy, b.auto_since, b.stopped_version, b.version, b.created_at,
    (SELECT count(*) FROM certificate_locations l WHERE l.binding_id = b.id)
FROM bindings b WHERE b.kv_certificate_id = $1 AND b.deleted_at IS NULL`, id).Scan(&b.ID, &b.AutoDeploy, &b.AutoSince, &b.StoppedVersion, &b.Version, &b.CreatedAt, &b.LocationCount)
	switch {
	case err == nil:
		b.AutoSince, b.CreatedAt = utcPtr(b.AutoSince), b.CreatedAt.UTC()
		d.Binding = &b
	case !errors.Is(err, pgx.ErrNoRows):
		return KVCertificateDetail{}, fmt.Errorf("inventory: read the binding: %w", err)
	}
	if d.DeployAccess, err = s.deployAccess(ctx, vault); err != nil {
		return KVCertificateDetail{}, err
	}
	return d, nil
}

// deployAccess is what Alice knows about reading the vault's secrets (see KVCertificateDetail).
func (s *Service) deployAccess(ctx context.Context, vault uuid.UUID) (string, error) {
	var deployed *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT max(d.finished_at) FROM deployments d
JOIN kv_certificate_versions v ON v.id = d.kv_version_id JOIN kv_certificates c ON c.id = v.kv_certificate_id
WHERE c.target_id = $1 AND d.status IN ('succeeded', 'unchanged') AND d.finished_at IS NOT NULL`, vault).Scan(&deployed); err != nil {
		return "", fmt.Errorf("inventory: read the vault's deployments: %w", err)
	}
	t, err := getVault(ctx, s.pool, vault, false)
	if err != nil {
		return "", err
	}
	result, checkedAt := "", time.Time{}
	if a := t.Facts.Azure; a != nil {
		for _, c := range a.Checks {
			if c.Name == providers.AzureCheckReadSecret {
				result, checkedAt = c.Result, a.CheckedAt
			}
		}
	}
	switch {
	case result == providers.AzureResultOK && (deployed == nil || !deployed.After(checkedAt)):
		return DeployAccessOK, nil
	case result == providers.AzureResultForbidden && (deployed == nil || !deployed.After(checkedAt)):
		return DeployAccessForbidden, nil
	case deployed != nil:
		return DeployAccessOK, nil
	}
	return DeployAccessNotChecked, nil
}

// ListKVKeys lists a vault's keys by name (metadata only).
func (s *Service) ListKVKeys(ctx context.Context, vault uuid.UUID, f KVFilter) ([]KVKey, string, error) {
	pg, err := checkKVFilter(f)
	if err != nil {
		return nil, "", err
	}
	if err := s.liveVault(ctx, vault); err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT id, target_id, name, version, key_type, curve, hsm, managed, enabled, key_size, details_updated_at,
details_problem, not_before, expires, kv_created_at, kv_updated_at, first_seen_at, last_seen_at, missing_since FROM kv_keys
WHERE target_id = $1 AND ($2 = '' OR lower(name COLLATE "C") LIKE $2 ESCAPE '\')
  AND ($3::timestamptz IS NULL OR expires < $3)
  AND CASE $4 WHEN 'only' THEN missing_since IS NOT NULL WHEN 'include' THEN true ELSE missing_since IS NULL END
  AND ($5 = '' OR lower(name COLLATE "C") > $5)
ORDER BY lower(name COLLATE "C") LIMIT $6`, vault, pg.pattern, f.ExpiresBefore, f.Missing, pg.cursor, pg.limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("inventory: list vault keys: %w", err)
	}
	defer rows.Close()
	out := []KVKey{}
	for rows.Next() {
		var k KVKey
		if err := rows.Scan(&k.ID, &k.TargetID, &k.Name, &k.Version, &k.KeyType, &k.Curve, &k.HSM, &k.Managed, &k.Enabled, &k.KeySize,
			&k.DetailsUpdatedAt, &k.DetailsProblem, &k.NotBefore, &k.Expires, &k.KVCreatedAt, &k.KVUpdatedAt, &k.FirstSeenAt, &k.LastSeenAt,
			&k.MissingSince); err != nil {
			return nil, "", fmt.Errorf("inventory: read a vault key: %w", err)
		}
		k.DetailsUpdatedAt, k.NotBefore, k.Expires = utcPtr(k.DetailsUpdatedAt), utcPtr(k.NotBefore), utcPtr(k.Expires)
		k.KVCreatedAt, k.KVUpdatedAt, k.MissingSince = utcPtr(k.KVCreatedAt), utcPtr(k.KVUpdatedAt), utcPtr(k.MissingSince)
		k.FirstSeenAt, k.LastSeenAt = k.FirstSeenAt.UTC(), k.LastSeenAt.UTC()
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > pg.limit {
		out = out[:pg.limit]
		next = kvCursor(out[pg.limit-1].Name)
	}
	return out, next, nil
}

// ListKVSecrets lists a vault's secrets by name (metadata only: Alice never stores a value).
func (s *Service) ListKVSecrets(ctx context.Context, vault uuid.UUID, f KVFilter) ([]KVSecret, string, error) {
	pg, err := checkKVFilter(f)
	if err != nil {
		return nil, "", err
	}
	if err := s.liveVault(ctx, vault); err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT id, target_id, name, content_type, managed, enabled, not_before, expires, kv_created_at, kv_updated_at,
first_seen_at, last_seen_at, missing_since FROM kv_secrets
WHERE target_id = $1 AND ($2 = '' OR lower(name COLLATE "C") LIKE $2 ESCAPE '\')
  AND ($3::timestamptz IS NULL OR expires < $3)
  AND CASE $4 WHEN 'only' THEN missing_since IS NOT NULL WHEN 'include' THEN true ELSE missing_since IS NULL END
  AND ($5 = '' OR lower(name COLLATE "C") > $5)
ORDER BY lower(name COLLATE "C") LIMIT $6`, vault, pg.pattern, f.ExpiresBefore, f.Missing, pg.cursor, pg.limit+1)
	if err != nil {
		return nil, "", fmt.Errorf("inventory: list vault secrets: %w", err)
	}
	defer rows.Close()
	out := []KVSecret{}
	for rows.Next() {
		var k KVSecret
		if err := rows.Scan(&k.ID, &k.TargetID, &k.Name, &k.ContentType, &k.Managed, &k.Enabled, &k.NotBefore, &k.Expires, &k.KVCreatedAt,
			&k.KVUpdatedAt, &k.FirstSeenAt, &k.LastSeenAt, &k.MissingSince); err != nil {
			return nil, "", fmt.Errorf("inventory: read a vault secret: %w", err)
		}
		k.NotBefore, k.Expires, k.KVCreatedAt, k.KVUpdatedAt, k.MissingSince = utcPtr(k.NotBefore), utcPtr(k.Expires), utcPtr(k.KVCreatedAt),
			utcPtr(k.KVUpdatedAt), utcPtr(k.MissingSince)
		k.FirstSeenAt, k.LastSeenAt = k.FirstSeenAt.UTC(), k.LastSeenAt.UTC()
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > pg.limit {
		out = out[:pg.limit]
		next = kvCursor(out[pg.limit-1].Name)
	}
	return out, next, nil
}
