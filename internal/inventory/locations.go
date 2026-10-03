package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/certs"
	"alice/internal/providers"
)

// Warnings the inventory adds to a location (location level, beside the provider's).
const (
	// WarnCertificateExpired: the certificate in the file has expired (at the scan).
	WarnCertificateExpired = "certificate_expired"
	// WarnSANMismatch: a server name of the location is not covered by the certificate's SANs
	// (catch-all "_", empty and regular-expression names are not checked).
	WarnSANMismatch = "san_mismatch"
)

// locationKind is certificate_locations.kind of an Nginx certificate file.
const locationKind = "nginx_file"

// Bounds of certificate_locations (migration 00006): a reported value that does not fit is cut,
// emptied or flagged here, so that one odd location never fails the scan's transaction.
const (
	maxLocationPath     = 16400    // cert_path, key_path (the provider's quoted invalid path is at most 16386)
	maxResolvedPath     = 4096     // resolved_cert_path
	maxKeyAccount       = 64       // key_owner, key_group
	maxLocationWarnings = 32       // warnings
	maxServersJSON      = 32 << 20 // servers, as PostgreSQL renders the jsonb
)

var (
	// codeRE is the shape of a reason, problem and warning code (the columns' CHECK).
	codeRE = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)
	// keyModeRE is key_mode's CHECK (nginx.modeRE).
	keyModeRE    = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	fileSHA256RE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// certSummary counts what reconcileLocations did.
type certSummary struct {
	Certificates, Locations, NewLocations, MissingLocations, Skipped int
}

// preparedLocation is a reported location made storable.
type preparedLocation struct {
	loc     providers.CertLocation // cleaned and bounded; Supported agrees with Unsupported
	servers []byte                 // the servers as a JSON array
	cert    *certs.Parsed          // the certificate read from the file; nil when none was
	// gone: the file is known to hold no certificate (missing, or not a certificate), so the
	// location has none. Without a certificate and not gone, the file's content is unknown (the
	// helper did not describe or could not read it) and the location keeps the one last seen.
	gone     bool
	fileSHA  string // the helper's hash of the file's bytes, lower case; "" without a certificate
	keyType  string
	warnings []string
}

// code returns v when it has the shape of a code, "" for "", and def otherwise.
func code(v, def string) string {
	switch {
	case v == "":
		return ""
	case codeRE.MatchString(v):
		return v
	}
	return def
}

// truncRunes cuts s to at most n runes.
func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// prepareLocation turns one reported location into what is stored, or reports false when it
// cannot be stored at all (no certificate path, or one longer than the column; the provider emits
// neither). The provider's decision is kept: a location it calls unsupported stays unsupported,
// and the inventory only adds reasons (a file problem, a certificate it cannot read, a key type
// other than RSA or ECDSA, a key path that does not fit). A reason or problem that is not a
// well-formed code becomes "unknown".
func prepareLocation(d providers.DiscoveredCertificate, now time.Time) (preparedLocation, bool) {
	in := d.Location
	path := clean(in.CertPath)
	if path == "" || utf8.RuneCountInString(path) > maxLocationPath {
		return preparedLocation{}, false
	}
	l := providers.CertLocation{CertPath: path, Inherited: in.Inherited, Symlinked: in.Symlinked, CustomLocation: in.CustomLocation,
		KeyExists: in.KeyExists, FreeBytes: in.FreeBytes}
	l.Unsupported = code(in.Unsupported, providers.UnsupportedUnknown)
	l.Problem = code(in.Problem, providers.CertProblemUnknown)
	l.KeyProblem = code(in.KeyProblem, providers.CertProblemUnknown)
	if l.Unsupported == "" && !in.Supported {
		l.Unsupported = providers.UnsupportedUnknown
	}
	if l.Unsupported == "" && (l.Problem != "" || l.KeyProblem != "") {
		l.Unsupported = providers.UnsupportedFile
	}
	l.KeyPath = clean(in.KeyPath)
	if utf8.RuneCountInString(l.KeyPath) > maxLocationPath {
		l.KeyPath = ""
		if l.Unsupported == "" {
			l.Unsupported = providers.UnsupportedPathNotAllowed
		}
	}
	if l.ResolvedCertPath = clean(in.ResolvedCertPath); utf8.RuneCountInString(l.ResolvedCertPath) > maxResolvedPath {
		l.ResolvedCertPath = ""
	}
	if keyModeRE.MatchString(in.KeyMode) {
		l.KeyMode = in.KeyMode
	}
	l.KeyOwner, l.KeyGroup = truncRunes(clean(in.KeyOwner), maxKeyAccount), truncRunes(clean(in.KeyGroup), maxKeyAccount)

	p := preparedLocation{}
	switch {
	case l.Problem == providers.CertProblemMissing || l.Problem == providers.CertProblemNotACertificate:
		p.gone = true
	case l.Problem == "" && len(d.PEMChain) > 0:
		parsed, err := certs.ParseChainPEM(d.PEMChain)
		switch {
		case errors.Is(err, certs.ErrTooLarge):
			l.Problem = providers.CertProblemTooLarge
		case err != nil:
			l.Problem, p.gone = providers.CertProblemNotACertificate, true
		default:
			p.cert = &parsed
			if fileSHA256RE.MatchString(d.FileSHA256) {
				p.fileSHA = foldASCII(d.FileSHA256)
			} else {
				// No compare-and-swap value: a deployment could not prove what it replaces.
				l.Problem = providers.CertProblemUnreadable
			}
		}
		if l.Problem != "" && l.Unsupported == "" {
			l.Unsupported = providers.UnsupportedFile
		}
	}
	var added []string
	if p.cert != nil {
		switch p.cert.Algorithm {
		case "rsa", "ecdsa":
			p.keyType = p.cert.Algorithm
		default:
			if l.Unsupported == "" {
				l.Unsupported = providers.UnsupportedKeyType
			}
		}
		if !now.Before(p.cert.NotAfter) {
			added = append(added, WarnCertificateExpired)
		}
	}
	servers, cut := boundServers(cleanServers(in.Servers), maxServersJSON)
	if cut {
		added = append(added, providers.WarnListTruncated)
	}
	if p.cert != nil && sanMismatch(p.cert.SANs, servers) {
		added = append(added, WarnSANMismatch)
	}
	l.Servers = servers
	l.Supported = l.Unsupported == ""
	p.warnings = locationWarnings(in.Warnings, added)
	raw, err := json.Marshal(servers)
	if err != nil {
		return preparedLocation{}, false // cleaned strings and integers: cannot fail
	}
	p.loc, p.servers = l, raw
	return p, true
}

// cleanServers makes the server blocks storable: text is cleaned (jsonb refuses NUL), lists are
// never null.
func cleanServers(in []providers.CertServer) []providers.CertServer {
	out := make([]providers.CertServer, 0, len(in))
	for _, s := range in {
		c := providers.CertServer{Names: make([]string, 0, len(s.Names)), Listens: make([]providers.CertListen, 0, len(s.Listens)),
			File: clean(s.File), Line: s.Line}
		for _, n := range s.Names {
			c.Names = append(c.Names, clean(n))
		}
		for _, l := range s.Listens {
			c.Listens = append(c.Listens, providers.CertListen{Addr: clean(l.Addr), Port: l.Port, DefaultServer: l.DefaultServer})
		}
		out = append(out, c)
	}
	return out
}

// boundServers keeps the leading server blocks whose jsonb text fits in limit bytes and reports
// whether any was dropped. The size is an upper bound of PostgreSQL's rendering (servers::text,
// what the column's CHECK measures): Go's encoding without HTML escaping is never shorter than
// PostgreSQL's for cleaned text, and PostgreSQL adds a space after every ':' and ','.
func boundServers(servers []providers.CertServer, limit int) ([]providers.CertServer, bool) {
	total := 2 // []
	for i, s := range servers {
		size := serverTextSize(s)
		if i > 0 {
			size += 2 // ", "
		}
		if total+size > limit {
			return servers[:i], true
		}
		total += size
	}
	return servers, false
}

// serverTextSize is an upper bound of the length of one server block in PostgreSQL's jsonb text:
// Go's encoding without HTML escaping plus the space PostgreSQL writes after each of the object's
// four ':' and three ',', after the ',' between names and between listens, and after each listen's
// three ':' and two ','.
func serverTextSize(s providers.CertServer) int {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // strings and integers: cannot fail
	return buf.Len() - 1 + 7 + max(len(s.Names)-1, 0) + max(len(s.Listens)-1, 0) + 5*len(s.Listens)
}

// sanMismatch reports whether a server name is not covered by the certificate's SANs. The
// catch-all "_", an empty name and a regular expression (~...) say nothing about a host name.
func sanMismatch(sans []string, servers []providers.CertServer) bool {
	for _, s := range servers {
		for _, n := range s.Names {
			if n == "" || n == "_" || strings.HasPrefix(n, "~") {
				continue
			}
			if !certs.SANMatches(sans, n) {
				return true
			}
		}
	}
	return false
}

// locationWarnings is the provider's location warnings that have the code shape, each once, then
// the inventory's own; at most maxLocationWarnings, the inventory's kept.
func locationWarnings(reported, added []string) []string {
	out := []string{}
	room := maxLocationWarnings - len(added)
	for _, w := range reported {
		if len(out) < room && codeRE.MatchString(w) && !slices.Contains(out, w) && !slices.Contains(added, w) {
			out = append(out, w)
		}
	}
	return append(out, added...)
}

// scanCoversLocations reports whether a discovery result describes every certificate location of
// the target, so that a known location it does not name is gone: a valid configuration read in
// full (Nginx found, valid, no configuration error class), no failed source (Partial) and no list
// cut at a bound (list_truncated, too_many_files: some location may be absent).
func scanCoversLocations(res providers.DiscoveryResult) bool {
	return configUsable(res.Nginx) && !res.Partial && !slices.ContainsFunc(res.Warnings, func(w providers.Warning) bool {
		return w.Code == providers.WarnListTruncated || w.Code == providers.WarnTooManyFiles
	})
}

// configUsable reports whether the Nginx facts describe a configuration whose certificates may be
// stored: Nginx found, its configuration valid, and no error class (the provider sends none with a
// valid configuration; one with an error class is treated as invalid).
func configUsable(n *providers.NginxFacts) bool {
	return n != nil && n.Found && n.ConfigValid && n.ConfigError == ""
}

// existingLocation is what reconcileLocations reads of a stored location.
type existingLocation struct {
	id          uuid.UUID
	certID      *uuid.UUID
	fingerprint string
	deployed    string
	fileSHA     string
	keyType     string
}

// reconcileLocations stores the certificate locations of one discovery of the locked target t
// (called only for a usable configuration, see configUsable). Locations are identified by
// (target, kind, certificate path) through the path hash of migration 00006; reported duplicates
// keep the first. Certificates are upserted first, in fingerprint order. Then, by path:
//   - a new location is inserted;
//   - when complete (scanCoversLocations), a known location is updated with everything reported
//     (missing_since cleared, version bumped only when a stored value changed), and the known
//     locations not reported are marked missing (never deleted);
//   - when not complete, known locations are left exactly as they are (their reported state may be
//     cut short), and nothing is marked missing.
//
// A location whose file now holds another certificate moves to it; when the old one was known and
// the new one is not what Alice deployed there, changed_outside_at is set and an audit event is
// returned for the caller to append last.
func (s *Service) reconcileLocations(ctx context.Context, tx pgx.Tx, t Target, found []providers.DiscoveredCertificate, complete bool,
	now time.Time) (certSummary, []audit.Event, error) {
	var sum certSummary
	var items []preparedLocation
	paths := map[string]bool{}
	for _, d := range found {
		p, ok := prepareLocation(d, now)
		if !ok {
			sum.Skipped++
			continue
		}
		if paths[p.loc.CertPath] {
			continue
		}
		paths[p.loc.CertPath] = true
		items = append(items, p)
	}
	slices.SortFunc(items, func(a, b preparedLocation) int { return strings.Compare(a.loc.CertPath, b.loc.CertPath) })
	read := map[string]discoveredCertificate{}
	for _, p := range items {
		if p.cert != nil {
			read[p.cert.Fingerprint] = discoveredCertificate{p: *p.cert, complete: certs.ChainComplete(*p.cert, s.roots, now)}
		}
	}
	sum.Certificates = len(read)
	certIDs, err := upsertCertificates(ctx, tx, read, now)
	if err != nil {
		return certSummary{}, nil, err
	}
	var events []audit.Event
	seen := []uuid.UUID{}
	for _, p := range items {
		prev, err := lockLocation(ctx, tx, t.ID, p.loc.CertPath)
		if err != nil {
			return certSummary{}, nil, err
		}
		sum.Locations++
		var certID *uuid.UUID
		fp, fileSHA, keyType := "", p.fileSHA, p.keyType
		switch {
		case p.cert != nil:
			id := certIDs[p.cert.Fingerprint]
			certID, fp = &id, p.cert.Fingerprint
		case !p.gone && prev != nil:
			certID, fp, fileSHA, keyType = prev.certID, prev.fingerprint, prev.fileSHA, prev.keyType
		}
		if prev == nil {
			id, err := insertLocation(ctx, tx, t.ID, p, certID, fileSHA, keyType, now)
			if err != nil {
				return certSummary{}, nil, err
			}
			seen = append(seen, id)
			sum.NewLocations++
			continue
		}
		seen = append(seen, prev.id)
		if !complete {
			continue
		}
		changedOutside := prev.fingerprint != "" && fp != "" && fp != prev.fingerprint && fp != prev.deployed
		if err := updateLocation(ctx, tx, prev.id, p, certID, fileSHA, keyType, changedOutside, now); err != nil {
			return certSummary{}, nil, err
		}
		if changedOutside {
			events = append(events, audit.Event{Actor: audit.SystemActor("jobs"), Action: "location.changed_outside",
				ObjectType: "certificate_location", ObjectID: prev.id.String(), Result: audit.Success, Details: map[string]string{
					"target_id": t.ID.String(), "cert_path": p.loc.CertPath, "fingerprint": fp, "previous_fingerprint": prev.fingerprint}})
		}
	}
	if complete {
		tag, err := tx.Exec(ctx, `UPDATE certificate_locations SET missing_since = $3, version = version + 1
WHERE target_id = $1 AND kind = $2 AND missing_since IS NULL AND NOT (id = ANY($4))`, t.ID, locationKind, now, seen)
		if err != nil {
			return certSummary{}, nil, fmt.Errorf("inventory: mark missing certificate locations: %w", err)
		}
		sum.MissingLocations = int(tag.RowsAffected())
	}
	return sum, events, nil
}

// lockLocation reads and locks the stored location of the path (nil when there is none). The
// lookup is the path-hash expression of the unique index (migration 00006).
func lockLocation(ctx context.Context, tx pgx.Tx, target uuid.UUID, path string) (*existingLocation, error) {
	var e existingLocation
	err := tx.QueryRow(ctx, `SELECT l.id, l.certificate_id, coalesce(c.fingerprint_sha256, ''), l.deployed_fingerprint, l.cert_file_sha256, l.key_type
FROM certificate_locations l LEFT JOIN certificates c ON c.id = l.certificate_id
WHERE l.target_id = $1 AND l.kind = $2 AND certificate_location_path_hash(l.cert_path) = certificate_location_path_hash($3) AND l.cert_path = $3
FOR UPDATE OF l`, target, locationKind, path).Scan(&e.id, &e.certID, &e.fingerprint, &e.deployed, &e.fileSHA, &e.keyType)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read certificate location: %w", err)
	}
	return &e, nil
}

func insertLocation(ctx context.Context, tx pgx.Tx, target uuid.UUID, p preparedLocation, certID *uuid.UUID, fileSHA, keyType string,
	now time.Time) (uuid.UUID, error) {
	l := p.loc
	id := uuid.Must(uuid.NewV7())
	_, err := tx.Exec(ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, resolved_cert_path, certificate_id,
    key_type, servers, supported, unsupported_reason, problem, key_problem, inherited, custom_location, symlinked, cert_file_sha256,
    key_exists, key_mode, key_owner, key_group, warnings, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $23)`,
		id, target, locationKind, l.CertPath, l.KeyPath, l.ResolvedCertPath, certID, keyType, p.servers, l.Supported, l.Unsupported,
		l.Problem, l.KeyProblem, l.Inherited, l.CustomLocation, l.Symlinked, fileSHA, l.KeyExists, l.KeyMode, l.KeyOwner, l.KeyGroup,
		p.warnings, now)
	if err != nil {
		return uuid.Nil, fmt.Errorf("inventory: store certificate location: %w", err)
	}
	return id, nil
}

// updateLocation writes a reported location over the stored one. Settings a person made
// (verify_port, verify_sni, skip_verify) and what a deployment recorded (deployed_fingerprint)
// are not touched; the version moves only when a stored value changes, so an unchanged scan does
// not make a pending If-Match stale.
func updateLocation(ctx context.Context, tx pgx.Tx, id uuid.UUID, p preparedLocation, certID *uuid.UUID, fileSHA, keyType string,
	changedOutside bool, now time.Time) error {
	l := p.loc
	_, err := tx.Exec(ctx, `UPDATE certificate_locations SET
    version = version + CASE WHEN missing_since IS NOT NULL OR $20::boolean
        OR (key_path, resolved_cert_path, certificate_id, key_type, servers, supported, unsupported_reason, problem, key_problem, inherited,
            custom_location, symlinked, cert_file_sha256, key_exists, key_mode, key_owner, key_group, warnings)
           IS DISTINCT FROM ($2::text, $3::text, $4::uuid, $5::text, $6::jsonb, $7::boolean, $8::text, $9::text, $10::text, $11::boolean,
            $12::boolean, $13::boolean, $14::text, $15::boolean, $16::text, $17::text, $18::text, $19::text[])
        THEN 1 ELSE 0 END,
    key_path = $2, resolved_cert_path = $3, certificate_id = $4, key_type = $5, servers = $6, supported = $7, unsupported_reason = $8,
    problem = $9, key_problem = $10, inherited = $11, custom_location = $12, symlinked = $13, cert_file_sha256 = $14, key_exists = $15,
    key_mode = $16, key_owner = $17, key_group = $18, warnings = $19, last_seen_at = $21, missing_since = NULL,
    changed_outside_at = CASE WHEN $20 THEN $21 ELSE changed_outside_at END
WHERE id = $1`, id, l.KeyPath, l.ResolvedCertPath, certID, keyType, p.servers, l.Supported, l.Unsupported, l.Problem, l.KeyProblem,
		l.Inherited, l.CustomLocation, l.Symlinked, fileSHA, l.KeyExists, l.KeyMode, l.KeyOwner, l.KeyGroup, p.warnings, changedOutside, now)
	if err != nil {
		return fmt.Errorf("inventory: update certificate location: %w", err)
	}
	return nil
}

// certLocationSelect reads CertificateLocation rows of live targets (scanCertLocation's order).
// The active deployment (at most one, deployments_one_active) is a correlated lookup on its index.
const certLocationSelect = `SELECT l.id, l.target_id, t.name::text, l.cert_path, l.key_path, l.resolved_cert_path, l.key_type,
c.id, coalesce(c.subject_cn, ''), coalesce(c.label, ''), coalesce(c.fingerprint_sha256, ''), c.not_after,
l.servers, l.supported, l.unsupported_reason, l.problem, l.key_problem, l.inherited, l.custom_location, l.symlinked, l.cert_file_sha256,
l.key_exists, l.key_mode, l.key_owner, l.key_group, l.warnings, l.deployed_fingerprint, l.changed_outside_at, l.verify_port,
coalesce(l.verify_sni, ''), l.skip_verify, l.first_seen_at, l.last_seen_at, l.missing_since, l.version,
(SELECT d.id FROM deployments d WHERE d.location_id = l.id AND d.state <> 'done' LIMIT 1)
FROM certificate_locations l
JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
LEFT JOIN certificates c ON c.id = l.certificate_id`

func scanCertLocation(row pgx.Row) (CertificateLocation, error) {
	var (
		l        CertificateLocation
		certID   *uuid.UUID
		ref      CertificateRef
		notAfter *time.Time
		servers  []byte
	)
	err := row.Scan(&l.ID, &l.TargetID, &l.TargetName, &l.CertPath, &l.KeyPath, &l.ResolvedCertPath, &l.KeyType,
		&certID, &ref.SubjectCN, &ref.Label, &ref.Fingerprint, &notAfter,
		&servers, &l.Supported, &l.UnsupportedReason, &l.Problem, &l.KeyProblem, &l.Inherited, &l.CustomLocation, &l.Symlinked, &l.CertFileSHA256,
		&l.KeyExists, &l.KeyMode, &l.KeyOwner, &l.KeyGroup, &l.Warnings, &l.DeployedFingerprint, &l.ChangedOutsideAt, &l.VerifyPort,
		&l.VerifySNI, &l.SkipVerify, &l.FirstSeenAt, &l.LastSeenAt, &l.MissingSince, &l.Version, &l.ActiveDeploymentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return CertificateLocation{}, ErrNotFound
	}
	if err != nil {
		return CertificateLocation{}, fmt.Errorf("inventory: read certificate location: %w", err)
	}
	if certID != nil && notAfter != nil {
		ref.ID, ref.NotAfter = *certID, notAfter.UTC()
		l.Certificate = &ref
	}
	if err := json.Unmarshal(servers, &l.Servers); err != nil {
		return CertificateLocation{}, fmt.Errorf("inventory: decode location servers: %w", err)
	}
	if l.Servers == nil {
		l.Servers = []providers.CertServer{}
	}
	if l.Warnings == nil {
		l.Warnings = []string{}
	}
	l.FirstSeenAt, l.LastSeenAt = l.FirstSeenAt.UTC(), l.LastSeenAt.UTC()
	l.ChangedOutsideAt, l.MissingSince = utcPtr(l.ChangedOutsideAt), utcPtr(l.MissingSince)
	return l, nil
}

func collectCertLocations(rows pgx.Rows) ([]CertificateLocation, error) {
	defer rows.Close()
	out := []CertificateLocation{}
	for rows.Next() {
		l, err := scanCertLocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListLocations returns the certificate locations of a live target (missing ones only when
// asked), ordered by the first server name, then the certificate path.
func (s *Service) ListLocations(ctx context.Context, targetID uuid.UUID, includeMissing bool) ([]CertificateLocation, error) {
	if _, err := s.GetTarget(ctx, targetID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, certLocationSelect+` WHERE l.target_id = $1 AND ($2 OR l.missing_since IS NULL)
ORDER BY l.servers->0->'names'->>0 NULLS LAST, l.cert_path, l.id`, targetID, includeMissing)
	if err != nil {
		return nil, fmt.Errorf("inventory: list certificate locations: %w", err)
	}
	return collectCertLocations(rows)
}

// GetLocation returns one certificate location on a live target.
func (s *Service) GetLocation(ctx context.Context, id uuid.UUID) (CertificateLocation, error) {
	return scanCertLocation(s.pool.QueryRow(ctx, certLocationSelect+" WHERE l.id = $1", id))
}
