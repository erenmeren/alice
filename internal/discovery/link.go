package discovery

// The read side (design decisions 3 and 5, amendment A10): discovered certificates joined to the managed inventory by
// SHA-256 fingerprint (the definition of certificates.fingerprint_sha256), and endpoints linked to live targets by
// address or host name. The API (Task 9) lists through these, keyset-paginated.

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/authz"
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

// CurrentEndpointSQL is the one definition of a "still found" endpoint (alias e): not gone, not excluded (an excluded
// place is never dialed, so what it presented is history) and of a scope that is not deleted. The alerting query
// (internal/alerts) applies the same rule.
const CurrentEndpointSQL = `e.state NOT IN ('gone', 'excluded')
  AND EXISTS (SELECT 1 FROM discovery_scopes sc WHERE sc.id = e.scope_id AND sc.deleted_at IS NULL)`

// liveLocationSQL: the inventory certificate whose id is the expression id has a live location on a live target (it
// is monitored).
func liveLocationSQL(id string) string {
	return `EXISTS (SELECT 1 FROM certificate_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
                  WHERE l.certificate_id = ` + id + ` AND l.missing_since IS NULL)`
}

// certificateStatusSQL is the status of a discovered certificate whose inventory certificate's id (LEFT JOIN
// certificates c ON c.fingerprint_sha256 = d.fingerprint_sha256: null when there is none) is the expression id: the one
// definition every read uses.
func certificateStatusSQL(id string) string {
	return `CASE WHEN ` + id + ` IS NULL THEN 'unmanaged' WHEN ` + liveLocationSQL(id) + ` THEN 'managed' ELSE 'known' END`
}

// statusConditions are the conditions on d and c equivalent to certificateStatusSQL("c.id") = status. A list filters
// on these, not on the CASE: the planner estimates them (unmanaged on the join column is an anti-join) and so walks the
// expiry index instead of computing every leaf's status and sorting them all (Task 12: status=unmanaged took 16 ms at
// 5,000 leaves and 160 ms at 50,000; now about 2 ms at both).
var statusConditions = map[string]string{
	StatusUnmanaged: "c.fingerprint_sha256 IS NULL",
	StatusManaged:   "c.id IS NOT NULL AND " + liveLocationSQL("c.id"),
	StatusKnown:     "c.id IS NOT NULL AND NOT " + liveLocationSQL("c.id"),
}

// CertificateRow is a discovered leaf certificate. Endpoints counts the endpoints presenting it now (state present),
// SeenOn those whose last leaf seen it is and that are neither gone nor excluded, of a scope not deleted (present, or unreachable since); both of the filter's
// scope when it has one. ManagedID is the managed certificate with the same fingerprint.
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
	SeenOn       int
	Status       string
	ManagedID    uuid.NullUUID
}

// CertificateCursor is the position after a row, in the order of the list (not_after, fingerprint).
type CertificateCursor struct {
	NotAfter    time.Time
	Fingerprint string
}

// CertificateFilter selects leaf certificates: of one status ("" any), presented by an endpoint of one scope (uuid.Nil:
// any), one fingerprint ("" any); whose subject CN or one of whose SANs contains Query (case-insensitive; "" any; LIKE
// characters are literal); expired at Now or not (Expired; nil: either); not expired at Now and expiring by ExpiringBy
// (zero: any); self-signed or not (SelfSigned; nil: either); still found (Current: some endpoint that is not gone, of
// the scope when ScopeID is set, presents or last presented it: the summary's and the alerts' "still found"); after a cursor (nil: the first page); at most Limit
// (1..MaxPage, else MaxPage). Now is required by Expired and ExpiringBy (ErrFilterNeedsNow).
type CertificateFilter struct {
	Status      string
	ScopeID     uuid.UUID
	Fingerprint string
	Query       string
	Expired     *bool
	ExpiringBy  time.Time
	SelfSigned  *bool
	Current     bool
	Now         time.Time
	After       *CertificateCursor
	Limit       int
	// Reach keeps the certificates seen by a scope of the caller's services (R49 Phase 2); the zero value is every
	// service.
	Reach authz.Reach
}

// ErrFilterNeedsNow: a time filter of a certificate list was given without its reference time.
var ErrFilterNeedsNow = errors.New("discovery: a time filter needs the reference time")

// likeEscaper makes a text match itself in a LIKE pattern with ESCAPE '\'.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// containsPattern is the ILIKE pattern of "contains q", q taken literally.
func containsPattern(q string) string { return "%" + likeEscaper.Replace(q) + "%" }

func limit(n int) int {
	if n < 1 || n > MaxPage {
		return MaxPage
	}
	return n
}

// query builds a statement from parts: each optional condition is added only when it applies (no "$n IS NULL OR"
// forms, so the planner sees the exact keyset predicate of the page).
type query struct {
	where []string
	args  []any
}

// arg adds a parameter and returns its placeholder.
func (q *query) arg(v any) string {
	q.args = append(q.args, v)
	return "$" + strconv.Itoa(len(q.args))
}

func (q *query) and(cond string) { q.where = append(q.where, cond) }

func (q *query) whereSQL() string {
	if len(q.where) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(q.where, " AND ")
}

// ListCertificates lists discovered leaf certificates soonest expiry first (index discovery_certificates_expiry).
func ListCertificates(ctx context.Context, q db.Querier, f CertificateFilter) ([]CertificateRow, error) {
	if (f.Expired != nil || !f.ExpiringBy.IsZero()) && f.Now.IsZero() {
		return nil, ErrFilterNeedsNow
	}
	var in query
	in.and("d.is_leaf")
	if f.Query != "" {
		pat := in.arg(containsPattern(f.Query))
		in.and("(d.subject_cn ILIKE " + pat + ` ESCAPE '\' OR EXISTS (SELECT 1 FROM unnest(d.sans) AS s(n) WHERE s.n ILIKE ` + pat + ` ESCAPE '\'))`)
	}
	switch {
	case f.Expired == nil:
	case *f.Expired:
		in.and("d.not_after < " + in.arg(f.Now) + "::timestamptz")
	default:
		in.and("d.not_after >= " + in.arg(f.Now) + "::timestamptz")
	}
	if !f.ExpiringBy.IsZero() {
		in.and("d.not_after >= " + in.arg(f.Now) + "::timestamptz AND d.not_after <= " + in.arg(f.ExpiringBy) + "::timestamptz")
	}
	if f.SelfSigned != nil {
		in.and("d.self_signed = " + in.arg(*f.SelfSigned))
	}
	scope := ""
	if f.ScopeID != uuid.Nil {
		scope = " AND e.scope_id = " + in.arg(f.ScopeID)
		in.and("EXISTS (SELECT 1 FROM discovery_endpoints e WHERE e.fingerprint_sha256 = d.fingerprint_sha256" + scope + ")")
	}
	if f.Current {
		in.and("EXISTS (SELECT 1 FROM discovery_endpoints e WHERE e.fingerprint_sha256 = d.fingerprint_sha256 AND " + CurrentEndpointSQL + scope + ")")
	}
	if f.Fingerprint != "" {
		in.and("d.fingerprint_sha256 = " + in.arg(f.Fingerprint))
	}
	if f.Reach.Limited {
		in.and(authz.DiscoveredCertificateVisible("d", in.arg(f.Reach.SQL())))
	}
	if f.After != nil {
		in.and("(d.not_after, d.fingerprint_sha256) > (" + in.arg(f.After.NotAfter) + "::timestamptz, " + in.arg(f.After.Fingerprint) + "::text)")
	}
	if f.Status != "" {
		cond, ok := statusConditions[f.Status]
		if !ok {
			cond = "false" // no certificate has another status
		}
		in.and("(" + cond + ")")
	}
	// The page is chosen first (filters, order, limit over the certificates and the inventory join only); the endpoint
	// counts and the status are computed for its rows alone (Task 12: a plan that sorts no longer counts every leaf).
	sql := `SELECT d.fingerprint_sha256, d.subject_cn, d.sans, d.issuer_cn, d.not_before, d.not_after, d.key_algorithm, d.self_signed,
    d.first_seen, d.last_seen, n.present, n.seen, ` + certificateStatusSQL("d.cid") + ` AS status, d.cid
FROM (
    SELECT d.fingerprint_sha256, d.subject_cn, d.sans, d.issuer_cn, d.not_before, d.not_after, d.key_algorithm, d.self_signed,
        d.first_seen, d.last_seen, c.id AS cid
    FROM discovery_certificates d LEFT JOIN certificates c ON c.fingerprint_sha256 = d.fingerprint_sha256` + in.whereSQL() + `
    ORDER BY d.not_after, d.fingerprint_sha256 LIMIT ` + in.arg(limit(f.Limit)) + `
) d
CROSS JOIN LATERAL (SELECT (count(*) FILTER (WHERE e.state = 'present'))::int AS present, count(*)::int AS seen
    FROM discovery_endpoints e WHERE e.fingerprint_sha256 = d.fingerprint_sha256 AND ` + CurrentEndpointSQL + scope + `) n
ORDER BY d.not_after, d.fingerprint_sha256`
	rows, err := q.Query(ctx, sql, in.args...)
	if err != nil {
		return nil, wrap("list the discovered certificates", err)
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[CertificateRow])
	return list, wrap("list the discovered certificates", err)
}

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
	// PreviousFingerprints are the last leaves it presented before its current one, newest first (at most 5).
	PreviousFingerprints []string
}

// EndpointCursor is the position after a row: (address, port, sni) inside a scope (its unique key), with ID across
// scopes.
type EndpointCursor struct {
	Address netip.Addr
	Port    int
	SNI     string
	ID      uuid.UUID
}

// EndpointFilter selects endpoints: of one scope (uuid.Nil: any), presenting one leaf ("" any), after a cursor (nil:
// the first page), at most Limit.
type EndpointFilter struct {
	ScopeID     uuid.UUID
	Fingerprint string
	After       *EndpointCursor
	Limit       int
	// Reach keeps the endpoints of scopes of the caller's services (R49 Phase 2); the zero value is every service.
	Reach authz.Reach
}

// ListEndpoints lists endpoints. Inside a scope the order is the unique key (scope_id, address, port, sni)
// (index discovery_endpoints_key); across scopes it is (address, port, sni, id) (index discovery_endpoints_list).
func ListEndpoints(ctx context.Context, q db.Querier, f EndpointFilter) ([]EndpointRow, error) {
	var w query
	order := "e.address, e.port, e.sni, e.id"
	if f.ScopeID != uuid.Nil {
		w.and("e.scope_id = " + w.arg(f.ScopeID))
		order = "e.scope_id, e.address, e.port, e.sni"
	}
	if f.Fingerprint != "" {
		w.and("e.fingerprint_sha256 = " + w.arg(f.Fingerprint))
	}
	if f.Reach.Limited {
		w.and(authz.ScopeVisible("e", w.arg(f.Reach.SQL())))
	}
	if c := f.After; c != nil {
		key := "(" + w.arg(c.Address) + "::inet, " + w.arg(c.Port) + "::int, " + w.arg(c.SNI) + "::text"
		if f.ScopeID != uuid.Nil {
			w.and("(e.address, e.port, e.sni) > " + key + ")")
		} else {
			w.and("(e.address, e.port, e.sni, e.id) > " + key + ", " + w.arg(c.ID) + "::uuid)")
		}
	}
	sql := `SELECT e.id, e.scope_id, e.address, e.port, e.sni, e.host, coalesce(e.fingerprint_sha256, ''),
    CASE WHEN e.fingerprint_sha256 IS NULL THEN 0 ELSE 1 + cardinality(e.chain_fingerprints) END,
    e.tls_version, e.cipher, e.state, e.last_error_code, e.missed_scans, e.first_seen, e.last_seen, e.last_scanned_at, e.gone_since,
    tg.id, coalesce(tg.name, ''), e.previous_fingerprints
FROM discovery_endpoints e
LEFT JOIN LATERAL (SELECT t.id, t.name::text AS name FROM targets t
    WHERE t.deleted_at IS NULL AND (lower(t.config->>'host') = host(e.address) OR (e.host <> '' AND lower(t.config->>'host') = e.host))
    ORDER BY t.name, t.id LIMIT 1) tg ON true` + w.whereSQL() + `
ORDER BY ` + order + ` LIMIT ` + w.arg(limit(f.Limit))
	rows, err := q.Query(ctx, sql, w.args...)
	if err != nil {
		return nil, wrap("list the discovered endpoints", err)
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[EndpointRow])
	return list, wrap("list the discovered endpoints", err)
}
