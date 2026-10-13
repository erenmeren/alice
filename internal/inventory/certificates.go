package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/certs"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// CertificateRef is the short form of a certificate shown with a location.
type CertificateRef struct {
	ID          uuid.UUID
	SubjectCN   string
	Label       string
	Fingerprint string
	NotAfter    time.Time
}

// Certificate is one certificate: one row per leaf fingerprint (spec §7.2), whatever number of
// servers use it. Certificates are public data; a held private key is only indicated
// (HasPrivateKey), never read here.
type Certificate struct {
	ID            uuid.UUID
	Fingerprint   string // hex SHA-256 of the leaf DER
	SubjectCN     string
	Subject       string
	Issuer        string
	Serial        string
	SANs          []string
	NotBefore     time.Time
	NotAfter      time.Time
	KeyAlgorithm  string // rsa | ecdsa | ed25519 | other
	KeyBits       int
	PEMChain      string // GetCertificate only (the list leaves it out)
	ChainComplete bool
	SelfSigned    bool
	Source        string // discovered | uploaded | csr | azure_kv | acme
	Label         string
	HasPrivateKey bool
	LocationCount int // locations on live targets that are not missing
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	Locations     []CertificateLocation // GetCertificate only: at most MaxListedLocations
	// LocationsTruncated: GetCertificate left locations out (more than MaxListedLocations).
	LocationsTruncated bool
}

// CertificateLocation is one certificate file an Nginx target uses (spec §7.3): its key file, the
// server blocks using it, whether Alice can deploy to it, and the certificate it holds.
type CertificateLocation struct {
	ID                  uuid.UUID
	TargetID            uuid.UUID
	TargetName          string
	CertPath            string
	KeyPath             string
	ResolvedCertPath    string // the file a symbolic link leads to ("" when not known)
	KeyType             string // "" | rsa | ecdsa: the key type of the certificate in the file
	Certificate         *CertificateRef
	Servers             []providers.CertServer
	Supported           bool
	UnsupportedReason   string // providers.Unsupported* (or a newer helper's reason); "" when supported
	Problem             string // providers.CertProblem* of the certificate file
	KeyProblem          string // providers.CertProblem* of the key file
	Inherited           bool
	CustomLocation      bool
	Symlinked           bool
	CertFileSHA256      string // the helper's hash of the file's bytes: a deployment's compare-and-swap value
	KeyExists           bool
	KeyMode             string
	KeyOwner            string
	KeyGroup            string
	Warnings            []string // the provider's location warnings plus WarnCertificateExpired, WarnSANMismatch, list_truncated
	DeployedFingerprint string
	ChangedOutsideAt    *time.Time
	VerifyPort          *int
	VerifySNI           string
	SkipVerify          bool
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
	MissingSince        *time.Time
	Version             int
	ActiveDeploymentID  *uuid.UUID
}

// CertificateFilter selects certificates for the certificate screen.
type CertificateFilter struct {
	TargetID uuid.UUID // certificates with a location on this target that is not missing
	Source   string    // "" | "discovered" | "uploaded" | "csr" | "azure_kv" | "acme"
	Query    string    // subject CN, SAN, label or fingerprint (case- and dotted-I-insensitive)
	Expiry   string    // "" | "expired" | "7" | "14" | "30" | "60" | "90" (days; the window includes expired ones)
	Cursor   string
	Limit    int // 1..200, default 50
}

// CertificatePage is one page of certificates.
type CertificatePage struct {
	Items      []Certificate
	NextCursor string
}

// MaxListedLocations bounds ListLocations and GetCertificate's locations. A target never has that
// many locations in use (the provider lists at most helperproto.MaxNginxFiles, 1000); only missing
// ones accumulate, and those are listed last.
const MaxListedLocations = 1000

const (
	defaultCertificateLimit = 50
	maxCertificateLimit     = 200
	// maxPEMChain is certificates.pem_chain's bound (1 MiB); certs.ParseChainPEM reads at most
	// 256 KiB, so only a leaf whose re-encoding alone is larger could not be stored.
	maxPEMChain = 1 << 20
)

var (
	certificateSources = []string{"discovered", "uploaded", "csr", "azure_kv", "acme"}
	expiryWindows      = []string{"expired", "7", "14", "30", "60", "90"}
)

// discoveredCertificate is one certificate read from a target, ready to be stored.
type discoveredCertificate struct {
	p        certs.Parsed
	complete bool
}

// upsertCertificates stores one certificates row per fingerprint (source discovered when new) and
// returns their ids by fingerprint and how many were new. An existing row keeps its source, label,
// key and first sighting; last_seen_at moves. The chain of a row found only on servers (source
// discovered, no private key) is the ordered path read from a server's file (certs.ParseServedChain)
// and a complete one replaces one that is not (never the reverse). The chain of a certificate a
// person brought (uploaded, completed signing request) or whose key Alice holds is what that person
// gave: a server's file never replaces it, nor its chain_complete (B1-I1: another server's file
// would otherwise choose what Alice deploys, and could lift the incomplete-chain confirmation).
// Rows are upserted in fingerprint order: scans of servers that share certificates lock the shared
// rows in the same order and so never deadlock (as upsertKeys).
//
// source is the source of a row this call inserts: "discovered" for a server's file and "azure_kv"
// for the leaf of a vault certificate's version (kv_reconcile.go). An existing row keeps its own.
func upsertCertificates(ctx context.Context, tx pgx.Tx, found map[string]discoveredCertificate, source string, now time.Time) (map[string]uuid.UUID, error) {
	fps := make([]string, 0, len(found))
	for fp := range found {
		fps = append(fps, fp)
	}
	slices.Sort(fps)
	ids := make(map[string]uuid.UUID, len(fps))
	for _, fp := range fps {
		d := found[fp]
		pemChain := d.p.PEMChain
		if len(pemChain) > maxPEMChain {
			pemChain, d.complete = leafPEM(d.p), false
		}
		sans, _ := boundSANs(d.p.SANs)
		var id uuid.UUID
		err := tx.QueryRow(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, subject, issuer, serial, sans, not_before, not_after,
    key_algorithm, key_bits, public_key_sha256, pem_chain, chain_complete, self_signed, source, first_seen_at, last_seen_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $17, $16, $16, $16)
ON CONFLICT (fingerprint_sha256) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at,
    pem_chain = CASE WHEN certificates.source = 'discovered' AND certificates.private_key_id IS NULL
                          AND NOT certificates.chain_complete AND EXCLUDED.chain_complete
                     THEN EXCLUDED.pem_chain ELSE certificates.pem_chain END,
    chain_complete = CASE WHEN certificates.source = 'discovered' AND certificates.private_key_id IS NULL
                          THEN certificates.chain_complete OR EXCLUDED.chain_complete ELSE certificates.chain_complete END
RETURNING id`, uuid.Must(uuid.NewV7()), fp, boundText(d.p.SubjectCN), boundText(d.p.Subject), boundText(d.p.Issuer), boundText(d.p.Serial), sans,
			d.p.NotBefore.UTC(), d.p.NotAfter.UTC(), d.p.Algorithm, d.p.Bits, d.p.PublicKeySHA256, pemChain, d.complete, d.p.SelfSigned,
			now, source).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("inventory: store certificate: %w", err)
		}
		ids[fp] = id
	}
	return ids, nil
}

// Bounds of the certificate text Alice keeps. sans has a GIN index, whose entries may not exceed
// about 2.7 KB: a SAN longer than a DNS name (253 characters) is dropped, never cut (a cut name is
// another name), and at most maxSANs are kept. The other text columns have no index or CHECK; they
// are cut at maxCertificateText characters so that no certificate makes a row unreasonably large.
const (
	maxSANLength       = 253
	maxSANs            = 1000
	maxCertificateText = 4096
)

// boundSANs is the SANs Alice stores, cleaned, and whether any was left out.
func boundSANs(in []string) ([]string, bool) {
	out := make([]string, 0, min(len(in), maxSANs))
	dropped := false
	for _, s := range in {
		s = clean(s)
		if len(s) > maxSANLength || len(out) >= maxSANs {
			dropped = true
			continue
		}
		out = append(out, s)
	}
	return out, dropped
}

// boundText is certificate text made storable and cut at maxCertificateText characters.
func boundText(s string) string { return truncRunes(clean(s), maxCertificateText) }

// leafPEM is the leaf of p alone, re-encoded.
func leafPEM(p certs.Parsed) string {
	first, _, _ := strings.Cut(p.PEMChain, "-----END CERTIFICATE-----")
	return first + "-----END CERTIFICATE-----\n"
}

// certificateColumns is the column list of a certificate read (scanCertificate's order).
const certificateColumns = `c.id, c.fingerprint_sha256, c.subject_cn, c.subject, c.issuer, c.serial, c.sans, c.not_before, c.not_after,
c.key_algorithm, c.key_bits, c.chain_complete, c.self_signed, c.source, c.label, c.private_key_id IS NOT NULL, c.first_seen_at, c.last_seen_at,
(SELECT count(*) FROM certificate_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
 WHERE l.certificate_id = c.id AND l.missing_since IS NULL)`

func scanCertificate(row pgx.Row, extra ...any) (Certificate, error) {
	var c Certificate
	dest := []any{&c.ID, &c.Fingerprint, &c.SubjectCN, &c.Subject, &c.Issuer, &c.Serial, &c.SANs, &c.NotBefore, &c.NotAfter,
		&c.KeyAlgorithm, &c.KeyBits, &c.ChainComplete, &c.SelfSigned, &c.Source, &c.Label, &c.HasPrivateKey, &c.FirstSeenAt, &c.LastSeenAt,
		&c.LocationCount}
	err := row.Scan(append(dest, extra...)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	if err != nil {
		return Certificate{}, fmt.Errorf("inventory: read certificate: %w", err)
	}
	c.NotBefore, c.NotAfter, c.FirstSeenAt, c.LastSeenAt = c.NotBefore.UTC(), c.NotAfter.UTC(), c.FirstSeenAt.UTC(), c.LastSeenAt.UTC()
	if c.SANs == nil {
		c.SANs = []string{}
	}
	return c, nil
}

// ListCertificates answers the certificate screen: certificates ordered by expiry (soonest first),
// keyset-paginated, with the number of locations that use each. The location counts come from the
// same statement, so a page costs one query whatever its size.
func (s *Service) ListCertificates(ctx context.Context, f CertificateFilter) (CertificatePage, error) {
	var errs validate.Errors
	limit := f.Limit
	switch {
	case limit == 0:
		limit = defaultCertificateLimit
	case limit < 1 || limit > maxCertificateLimit:
		errs.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxCertificateLimit)})
	}
	if f.Source != "" && !slices.Contains(certificateSources, f.Source) {
		errs.Add("source", validate.OneOf, map[string]string{"values": strings.Join(certificateSources, ", ")})
	}
	if f.Expiry != "" && !slices.Contains(expiryWindows, f.Expiry) {
		errs.Add("expiry", validate.OneOf, map[string]string{"values": strings.Join(expiryWindows, ", ")})
	}
	switch {
	case !utf8.ValidString(f.Query) || strings.ContainsRune(f.Query, 0):
		errs.Add("q", validate.Pattern, nil)
	case utf8.RuneCountInString(f.Query) > maxQueryRunes:
		errs.Add("q", validate.TooLong, map[string]string{"max": strconv.Itoa(maxQueryRunes)})
	}
	var afterAt *time.Time
	afterID := uuid.Nil
	if f.Cursor != "" {
		at, id, err := decodeCursor(f.Cursor)
		if err != nil {
			errs.Add("cursor", validate.Pattern, nil)
		} else {
			afterAt, afterID = &at, id
		}
	}
	if len(errs) > 0 {
		return CertificatePage{}, errs
	}
	var target *uuid.UUID
	if f.TargetID != uuid.Nil {
		target = &f.TargetID
	}
	pattern := ""
	if q := strings.TrimSpace(f.Query); q != "" {
		pattern = likePattern(foldSearch(q))
	}
	// The expiry bounds come from the injected clock: expired is not_after <= now, a window of
	// n days is not_after < now + n days (expired ones included).
	now := s.clock.Now().UTC()
	var expiredBy, before *time.Time
	switch f.Expiry {
	case "expired":
		expiredBy = &now
	case "":
	default: // 7, 14, 30, 60 or 90 (validated above)
		days, _ := strconv.Atoi(f.Expiry)
		b := now.AddDate(0, 0, days)
		before = &b
	}
	rows, err := s.pool.Query(ctx, `SELECT `+certificateColumns+`
FROM certificates c
WHERE ($1::uuid IS NULL OR EXISTS (SELECT 1 FROM certificate_locations x WHERE x.certificate_id = c.id AND x.target_id = $1
                                   AND x.missing_since IS NULL))
  AND ($2::text = '' OR c.source = $2)
  AND ($3::timestamptz IS NULL OR c.not_after <= $3)
  AND ($4::timestamptz IS NULL OR c.not_after < $4)
  AND ($5::text = ''
       OR translate(c.subject_cn, 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $5 ESCAPE '\'
       OR translate(c.label, 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $5 ESCAPE '\'
       OR translate(c.fingerprint_sha256, 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $5 ESCAPE '\'
       OR translate(array_to_string(c.sans, ' '), 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $5 ESCAPE '\')
  AND ($6::timestamptz IS NULL OR (c.not_after, c.id) > ($6::timestamptz, $7::uuid))
ORDER BY c.not_after, c.id
LIMIT $8`, target, f.Source, expiredBy, before, pattern, afterAt, afterID, limit+1)
	if err != nil {
		return CertificatePage{}, fmt.Errorf("inventory: list certificates: %w", err)
	}
	defer rows.Close()
	page := CertificatePage{Items: []Certificate{}}
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return CertificatePage{}, err
		}
		page.Items = append(page.Items, c)
	}
	if err := rows.Err(); err != nil {
		return CertificatePage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = encodeCursor(last.NotAfter, last.ID)
	}
	return page, nil
}

// GetCertificate returns a certificate with its chain and the locations on live targets that use
// it: those in use first, then missing ones, each most recently seen first; at most
// MaxListedLocations (LocationsTruncated says when some were left out).
func (s *Service) GetCertificate(ctx context.Context, id uuid.UUID) (Certificate, error) {
	var pemChain string
	c, err := scanCertificate(s.pool.QueryRow(ctx, "SELECT "+certificateColumns+", c.pem_chain FROM certificates c WHERE c.id = $1", id), &pemChain)
	if err != nil {
		return Certificate{}, err
	}
	c.PEMChain = pemChain
	rows, err := s.pool.Query(ctx, certLocationSelect+` WHERE l.certificate_id = $1
ORDER BY l.missing_since IS NOT NULL, l.last_seen_at DESC, l.first_seen_at DESC, l.id DESC
LIMIT $2`, id, MaxListedLocations+1)
	if err != nil {
		return Certificate{}, fmt.Errorf("inventory: list certificate locations: %w", err)
	}
	if c.Locations, err = collectCertLocations(rows); err != nil {
		return Certificate{}, err
	}
	if len(c.Locations) > MaxListedLocations {
		c.Locations, c.LocationsTruncated = c.Locations[:MaxListedLocations], true
	}
	return c, nil
}
