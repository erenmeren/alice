package discovery

// The read side (design decisions 3 and 5, amendment A10): discovered certificates joined to the managed inventory by
// SHA-256 fingerprint (the definition of certificates.fingerprint_sha256), and endpoints linked to live targets by
// address or host name. The API (Task 9) lists through these, keyset-paginated.

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// Certificate statuses. Unmanaged means Alice has no record of this exact certificate (no row of certificates has its
// fingerprint; A10: a certificate in front of Alice-managed hosts, on a proxy for example, is unmanaged unless Alice
// stores its fingerprint). Managed: Alice has it and a live location of a live target holds it (it is monitored).
// Known: Alice has a record of it but no live location holds it (not monitored).
const (
	StatusManaged   = "managed"
	StatusKnown     = "known"
	StatusUnmanaged = "unmanaged"
)

// MaxPage is the largest page a list returns.
const MaxPage = 500

// CertificateStatusSQL is the status of the discovered certificate d joined (LEFT JOIN certificates c ON
// c.fingerprint_sha256 = d.fingerprint_sha256) to the inventory: the one definition every read uses.
const CertificateStatusSQL = `CASE WHEN c.id IS NULL THEN 'unmanaged'
     WHEN EXISTS (SELECT 1 FROM certificate_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
                  WHERE l.certificate_id = c.id AND l.missing_since IS NULL) THEN 'managed'
     ELSE 'known' END`

// CertificateRow is a discovered leaf certificate. Endpoints counts the endpoints (not gone) presenting it (of the
// filter's scope, when it has one); ManagedID is the managed certificate with the same fingerprint.
type CertificateRow struct {
	Fingerprint  string
	SubjectCN    string
	SANs         []string
	IssuerCN     string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyAlgorithm string
	SelfSigned   bool
	FirstSeen    time.Time
	LastSeen     time.Time
	Endpoints    int
	Status       string
	ManagedID    uuid.NullUUID
}

// CertificateCursor is the position after a row, in the order of the list (not_after, fingerprint).
type CertificateCursor struct {
	NotAfter    time.Time
	Fingerprint string
}

// CertificateFilter selects leaf certificates: of one status ("" any), presented by an endpoint of one scope (uuid.Nil:
// any), one fingerprint ("" any); after a cursor (nil: from the start); at most Limit (1..MaxPage, else MaxPage).
type CertificateFilter struct {
	Status      string
	ScopeID     uuid.UUID
	Fingerprint string
	After       *CertificateCursor
	Limit       int
}

func limit(n int) int {
	if n < 1 || n > MaxPage {
		return MaxPage
	}
	return n
}

// ListCertificates lists discovered leaf certificates soonest expiry first (index discovery_certificates_expiry).
func ListCertificates(ctx context.Context, q db.Querier, f CertificateFilter) ([]CertificateRow, error) {
	var afterAt *time.Time
	afterFP := ""
	if f.After != nil {
		afterAt, afterFP = &f.After.NotAfter, f.After.Fingerprint
	}
	rows, err := q.Query(ctx, `SELECT * FROM (
    SELECT d.fingerprint_sha256, d.subject_cn, d.sans, d.issuer_cn, d.not_before, d.not_after, d.key_algorithm, d.self_signed,
        d.first_seen, d.last_seen,
        (SELECT count(*)::int FROM discovery_endpoints e WHERE e.fingerprint_sha256 = d.fingerprint_sha256 AND e.state <> 'gone'
            AND ($2::uuid IS NULL OR e.scope_id = $2)),
        `+CertificateStatusSQL+` AS status, c.id
    FROM discovery_certificates d LEFT JOIN certificates c ON c.fingerprint_sha256 = d.fingerprint_sha256
    WHERE d.is_leaf AND ($3 = '' OR d.fingerprint_sha256 = $3)
      AND ($4::timestamptz IS NULL OR (d.not_after, d.fingerprint_sha256) > ($4, $5))
      AND ($2::uuid IS NULL OR EXISTS (SELECT 1 FROM discovery_endpoints e WHERE e.fingerprint_sha256 = d.fingerprint_sha256 AND e.scope_id = $2))
) x WHERE $1 = '' OR x.status = $1
ORDER BY x.not_after, x.fingerprint_sha256 LIMIT $6`, f.Status, nullID(f.ScopeID), f.Fingerprint, afterAt, afterFP, limit(f.Limit))
	if err != nil {
		return nil, wrap("list the discovered certificates", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[CertificateRow])
	return out, wrap("list the discovered certificates", err)
}

// nullID is NULL for uuid.Nil.
func nullID(id uuid.UUID) uuid.NullUUID { return uuid.NullUUID{UUID: id, Valid: id != uuid.Nil} }

// EndpointRow is a discovered endpoint, with the live target it belongs to when one has its address or host name as
// its host (case-insensitively; TargetID null otherwise). ChainLen counts every certificate presented, the dropped
// ones included (0 when no leaf is known).
type EndpointRow struct {
	ID            uuid.UUID
	ScopeID       uuid.UUID
	Address       netip.Addr
	Port          int
	SNI           string
	Host          string
	Fingerprint   string
	ChainLen      int
	TLSVersion    string
	Cipher        string
	State         string
	LastErrorCode string
	MissedScans   int
	FirstSeen     time.Time
	LastSeen      *time.Time
	LastScannedAt time.Time
	GoneSince     *time.Time
	TargetID      uuid.NullUUID
	TargetName    string
}

// EndpointCursor is the position after a row, in the order of the list (address, port, sni, id).
type EndpointCursor struct {
	Address netip.Addr
	Port    int
	SNI     string
	ID      uuid.UUID
}

// EndpointFilter selects endpoints: of one scope (uuid.Nil: any), presenting one leaf ("" any), after a cursor, at most
// Limit.
type EndpointFilter struct {
	ScopeID     uuid.UUID
	Fingerprint string
	After       *EndpointCursor
	Limit       int
}

// ListEndpoints lists endpoints in (address, port, sni, id) order (index discovery_endpoints_list; inside a scope that is
// the order of its unique key).
func ListEndpoints(ctx context.Context, q db.Querier, f EndpointFilter) ([]EndpointRow, error) {
	var after *netip.Addr
	var c EndpointCursor
	if f.After != nil {
		c = *f.After
		after = &c.Address
	}
	rows, err := q.Query(ctx, `SELECT e.id, e.scope_id, e.address, e.port, e.sni, e.host, coalesce(e.fingerprint_sha256, ''),
    CASE WHEN e.fingerprint_sha256 IS NULL THEN 0 ELSE 1 + cardinality(e.chain_fingerprints) END,
    e.tls_version, e.cipher, e.state, e.last_error_code, e.missed_scans, e.first_seen, e.last_seen, e.last_scanned_at, e.gone_since,
    tg.id, coalesce(tg.name, '')
FROM discovery_endpoints e
LEFT JOIN LATERAL (SELECT t.id, t.name::text AS name FROM targets t
    WHERE t.deleted_at IS NULL AND (lower(t.config->>'host') = host(e.address) OR (e.host <> '' AND lower(t.config->>'host') = e.host))
    ORDER BY t.name, t.id LIMIT 1) tg ON true
WHERE ($1::uuid IS NULL OR e.scope_id = $1) AND ($2 = '' OR e.fingerprint_sha256 = $2)
  AND ($3::inet IS NULL OR (e.address, e.port, e.sni, e.id) > ($3, $4, $5, $6))
ORDER BY e.address, e.port, e.sni, e.id LIMIT $7`, nullID(f.ScopeID), f.Fingerprint, after, c.Port, c.SNI, c.ID, limit(f.Limit))
	if err != nil {
		return nil, wrap("list the discovered endpoints", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[EndpointRow])
	return out, wrap("list the discovered endpoints", err)
}
