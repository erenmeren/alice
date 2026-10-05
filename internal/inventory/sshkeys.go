package inventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// SSHKey is one public key (one row per fingerprint, §7.3) with where it is used.
type SSHKey struct {
	ID            uuid.UUID
	Fingerprint   string
	KeyType       string
	Bits          int
	PublicKey     string
	Managed       bool
	IsPlatformKey bool
	Weak          bool
	Comment       string
	LocationCount int
	TargetCount   int
	Missing       bool // every location of the key is missing or removed
	FirstSeenAt   time.Time
	Locations     []KeyLocation
}

// KeyLocation is one authorized_keys entry: a key in one file of one user on one target.
type KeyLocation struct {
	ID                   uuid.UUID
	SSHKeyID             uuid.UUID
	Fingerprint          string
	KeyType              string
	TargetID             uuid.UUID
	TargetName           string
	OSUser               string
	FilePath             string
	LineNo               int
	Options              string
	Comment              string
	Flags                []string
	FirstSeenAt          time.Time
	LastSeenAt           time.Time
	MissingSince         *time.Time
	RemovedAt            *time.Time
	IsAliceConnectionKey bool
}

// KeyFilter selects keys for the inventory screen.
type KeyFilter struct {
	TargetID       uuid.UUID
	OSUser         string
	Query          string
	Flag           string
	IncludeMissing bool
	Cursor         string
	Limit          int
}

// KeyPage is one page of keys.
type KeyPage struct {
	Items      []SSHKey
	NextCursor string
}

// ReconcileSummary counts what one discovery changed. Keys, New and Missing are SSH key
// locations; Certificates (distinct certificates read), Locations (certificate files stored or
// recognised), NewLocations, MissingLocations and SkippedLocations (reported locations that could
// not be stored, see reconcileLocations) are the certificate half.
type ReconcileSummary struct {
	Keys, New, Missing                                                        int
	Certificates, Locations, NewLocations, MissingLocations, SkippedLocations int
}

const (
	defaultKeyLimit = 50
	maxKeyLimit     = 200
	maxQueryRunes   = 200
)

// fingerprintRE is the form of ssh.FingerprintSHA256, which the fingerprint columns' CHECK
// enforces: Reconcile skips an entry of another form instead of failing the whole scan.
var fingerprintRE = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

var knownFlags = []string{providers.FlagWeak, providers.FlagCommand, providers.FlagRootWithoutFrom,
	providers.FlagDuplicate, providers.FlagCertAuthority, providers.FlagSecurityKey}

// clean makes remote text storable: invalid UTF-8 and NUL become U+FFFD (as audit does). The
// text stays text: the UI renders it escaped (SC-4).
func clean(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "�")
}

// Reconcile stores one discovery result (§6.2). Keys are upserted by fingerprint and locations by
// (key, target, user, file); a location not seen again is marked missing only when its file was
// read completely (R37); nothing is deleted. A listed file that does not exist counts as read
// (the provider puts it in ReadFiles), so the keys of a deleted file are marked missing. The
// location of the platform key (the fingerprint in the platform_ssh credential) is marked as
// Alice's connection key (SEC-081); the mark is never cleared here (the protection trigger would
// refuse it). A successful scan also records the connection (markConnected): an unreachable or
// checking target is "ok" again. With a complete account list, the keys of users that are no
// longer accounts are marked missing as well. A result with Nginx facts also carries the
// certificate half (reconcileLocations), stored in the same transaction; a certificates-only
// result (sshHalfRead) leaves the stored SSH facts as they are. With a Claim on ctx (the discovery
// job's run) nothing is written once that run no longer holds its job: ErrClaimLost.
func (s *Service) Reconcile(ctx context.Context, id uuid.UUID, res providers.DiscoveryResult) (ReconcileSummary, error) {
	var sum ReconcileSummary
	now := s.clock.Now().UTC()
	// The certificate files are parsed before the transaction (prepareScan), never under the
	// target's row lock.
	var scan preparedScan
	if res.Nginx != nil && configUsable(res.Nginx) {
		var err error
		if scan, err = s.prepareScan(ctx, res.Certificates, now); err != nil {
			return ReconcileSummary{}, err
		}
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// A discovery job's run writes only while it holds its job (Claim): a run that stalled past
		// its lease must not store an old scan after a newer one, or after a deployment finished.
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		t, err := getTarget(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if err := requireServer(t); err != nil {
			return err
		}
		if t.Type != TypeNginx {
			// Certificates belong to Nginx targets only: another target type's result is its SSH half.
			res.Nginx, res.Certificates = nil, nil
		}
		platformFP := ""
		pk, err := loadPlatformKey(ctx, tx)
		switch {
		case err == nil:
			platformFP = pk.Fingerprint
		case !errors.Is(err, ErrNoPlatformKey):
			return err
		}
		type tuple struct{ fp, user, path string }
		done := map[tuple]bool{}
		var entries []providers.DiscoveredSSHKey
		for _, k := range res.SSHKeys {
			tp := tuple{k.Fingerprint, k.OSUser, k.FilePath}
			if done[tp] || !fingerprintRE.MatchString(k.Fingerprint) || k.LineNo < 1 {
				continue
			}
			done[tp] = true
			entries = append(entries, k)
		}
		keyIDs, err := upsertKeys(ctx, tx, entries, platformFP, now)
		if err != nil {
			return err
		}
		seen := []uuid.UUID{}
		for _, k := range entries {
			locID, inserted, err := upsertLocation(ctx, tx, id, keyIDs[clean(k.Fingerprint)], k, platformFP, now)
			if err != nil {
				return err
			}
			seen = append(seen, locID)
			sum.Keys++
			if inserted {
				sum.New++
			}
		}
		files := res.ReadFiles
		if files == nil {
			files = []string{}
		}
		tag, err := tx.Exec(ctx, `UPDATE ssh_key_locations SET missing_since = $2
WHERE target_id = $1 AND missing_since IS NULL AND removed_by_alice_at IS NULL
  AND file_path = ANY($3) AND NOT (id = ANY($4))`, id, now, files, seen)
		if err != nil {
			return fmt.Errorf("inventory: mark missing keys: %w", err)
		}
		sum.Missing = int(tag.RowsAffected())
		// Carry 1: the keys of an OS user that is no longer an account are missing, decided only on
		// a complete account list (AccountsComplete, never on the list alone). A list without root
		// comes from a broken helper and proves nothing. An account the scan did not read (no
		// login shell, no home) is in the list, so its keys are left alone; a certificates-only
		// result carries no list.
		if res.AccountsComplete && slices.Contains(res.Accounts, "root") {
			tag, err := tx.Exec(ctx, `UPDATE ssh_key_locations SET missing_since = $2
WHERE target_id = $1 AND missing_since IS NULL AND removed_by_alice_at IS NULL AND NOT (os_user = ANY($3)) AND NOT (id = ANY($4))`,
				id, now, res.Accounts, seen)
			if err != nil {
				return fmt.Errorf("inventory: mark keys of removed accounts missing: %w", err)
			}
			sum.Missing += int(tag.RowsAffected())
		}
		f := t.Facts
		if sshHalfRead(res) {
			sshd := res.SSHD
			f.SSHD, f.HostKeys, f.Warnings, f.Unreadable = &sshd, res.HostKeys, res.Warnings, res.UnreadableLines
			f.UID0Users = append([]string(nil), res.UID0Users...)
			f.KeyFiles = cleanKeyFiles(res.KeyFiles)
		}
		// The certificate half (D19: after the SSH facts, before they are stored). Only a usable
		// configuration's certificates are stored; any other Nginx result (invalid, untrusted or
		// unsupported configuration, Nginx not found) changes the facts only, which say why.
		var certEvents []audit.Event
		if res.Nginx != nil {
			f.Nginx = mergeNginxFacts(f.Nginx, *res.Nginx)
			if configUsable(res.Nginx) {
				cs, events, err := s.reconcileLocations(ctx, tx, t, scan, listsEveryLocation(res), now)
				if err != nil {
					return err
				}
				certEvents = events
				sum.Certificates, sum.Locations, sum.NewLocations = cs.Certificates, cs.Locations, cs.NewLocations
				sum.MissingLocations, sum.SkippedLocations = cs.MissingLocations, cs.Skipped
				if cs.Skipped > 0 && sshHalfRead(res) && !slices.ContainsFunc(f.Warnings, func(w providers.Warning) bool {
					return w.Code == providers.WarnListTruncated
				}) {
					// A reported location that could not be stored: what is shown is incomplete.
					f.Warnings = append(slices.Clone(f.Warnings), providers.Warning{Code: providers.WarnListTruncated, Params: map[string]string{}})
				}
			}
		}
		raw, err := json.Marshal(f)
		if err != nil {
			return err
		}
		// Only a scan that read sshd's settings decides F-35: the defaults assumed otherwise say nothing.
		// Only a scan of the SSH half is a discovery for the schedule (last_discovery_at).
		if _, err := tx.Exec(ctx, `UPDATE targets SET facts = $2,
    keys_managed_elsewhere = CASE WHEN $5 THEN $3 ELSE keys_managed_elsewhere END,
    last_discovery_at = CASE WHEN $6 THEN $4 ELSE last_discovery_at END, updated_at = $4
WHERE id = $1`, id, raw, res.SSHD.KeysManagedElsewhere, now, res.SSHD.Read, sshHalfRead(res)); err != nil {
			return fmt.Errorf("inventory: store discovery facts: %w", err)
		}
		// The scan reached the server: an unreachable target is connected again (statusAfterSuccess).
		if err := s.markConnected(ctx, tx, t, now, false, "discovery_ok", nil); err != nil {
			return err
		}
		for _, e := range certEvents {
			if _, err := s.audit.Append(ctx, tx, e); err != nil {
				return err
			}
		}
		details := map[string]string{"key_count": strconv.Itoa(sum.Keys), "new_count": strconv.Itoa(sum.New),
			"missing_count": strconv.Itoa(sum.Missing), "partial": strconv.FormatBool(res.Partial)}
		if res.Nginx != nil { // a scan that asked for certificates
			details["certificate_count"], details["location_count"] = strconv.Itoa(sum.Certificates), strconv.Itoa(sum.Locations)
			details["new_location_count"], details["missing_location_count"] = strconv.Itoa(sum.NewLocations), strconv.Itoa(sum.MissingLocations)
			details["skipped_location_count"] = strconv.Itoa(sum.SkippedLocations)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("jobs"), Action: "target.discovered",
			ObjectType: "target", ObjectID: id.String(), Result: audit.Success, Details: details})
		return err
	})
	return sum, err
}

// sshHalfRead reports whether res carries the SSH half of a discovery: linuxssh's host keys, sshd
// settings and (when asked) keys and accounts. A result with Nginx facts and none of those is a
// certificates-only discovery (nginx.Discover without SSHKeys), which knows nothing about SSH: the
// stored sshd, host-key, warning and account facts stay as they are. A combined scan that found
// nothing at all on the SSH side is read the same way, which only keeps the earlier facts.
func sshHalfRead(res providers.DiscoveryResult) bool {
	return res.Nginx == nil || res.SSHD.Read || len(res.HostKeys) > 0 || len(res.SSHKeys) > 0 || len(res.ReadFiles) > 0 ||
		len(res.UnreadableLines) > 0 || len(res.Accounts) > 0 || len(res.UID0Users) > 0
}

// upsertKeys stores one ssh_keys row per fingerprint and returns their ids by (cleaned)
// fingerprint. The rows are upserted in fingerprint order: scans of different servers that share
// keys (the platform key, an administrator's key) lock the shared rows in the same order and so
// never deadlock, whatever order each server lists its keys in.
func upsertKeys(ctx context.Context, tx pgx.Tx, entries []providers.DiscoveredSSHKey, platformFP string, now time.Time) (map[string]uuid.UUID, error) {
	byFP := map[string]providers.DiscoveredSSHKey{}
	newIDs := map[string]uuid.UUID{} // allocated in discovery order: keys first seen together list in that order
	weak := map[string]bool{}
	for _, k := range entries {
		fp := clean(k.Fingerprint)
		if _, ok := byFP[fp]; !ok {
			byFP[fp] = k
			newIDs[fp] = uuid.Must(uuid.NewV7())
		}
		weak[fp] = weak[fp] || slices.Contains(k.Flags, providers.FlagWeak)
	}
	fps := make([]string, 0, len(byFP))
	for fp := range byFP {
		fps = append(fps, fp)
	}
	slices.Sort(fps)
	ids := make(map[string]uuid.UUID, len(fps))
	for _, fp := range fps {
		k := byFP[fp]
		var keyID uuid.UUID
		err := tx.QueryRow(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, is_platform_key, weak, first_seen_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
ON CONFLICT (fingerprint_sha256) DO UPDATE SET is_platform_key = ssh_keys.is_platform_key OR EXCLUDED.is_platform_key,
    weak = EXCLUDED.weak
RETURNING id`, newIDs[fp], fp, clean(k.KeyType), k.Bits, clean(k.PublicKey), platformFP != "" && k.Fingerprint == platformFP,
			weak[fp], now).Scan(&keyID)
		if err != nil {
			return nil, fmt.Errorf("inventory: store ssh key: %w", err)
		}
		ids[fp] = keyID
	}
	return ids, nil
}

func upsertLocation(ctx context.Context, tx pgx.Tx, target, keyID uuid.UUID, k providers.DiscoveredSSHKey, platformFP string, now time.Time) (uuid.UUID, bool, error) {
	isPlatform := platformFP != "" && k.Fingerprint == platformFP
	flags := make([]string, 0, len(k.Flags))
	for _, f := range k.Flags {
		flags = append(flags, clean(f))
	}
	var locID uuid.UUID
	var inserted bool
	err := tx.QueryRow(ctx, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, options, comment, flags,
    first_seen_at, last_seen_at, is_alice_connection_key)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11)
ON CONFLICT (ssh_key_id, target_id, os_user, file_path) DO UPDATE SET line_no = EXCLUDED.line_no, options = EXCLUDED.options,
    comment = EXCLUDED.comment, flags = EXCLUDED.flags, last_seen_at = EXCLUDED.last_seen_at, missing_since = NULL,
    removed_by_alice_at = NULL, is_alice_connection_key = ssh_key_locations.is_alice_connection_key OR EXCLUDED.is_alice_connection_key
RETURNING id, (xmax = 0)`, uuid.Must(uuid.NewV7()), keyID, target, clean(k.OSUser), clean(k.FilePath), k.LineNo,
		clean(k.Options), clean(k.Comment), flags, now, isPlatform).Scan(&locID, &inserted)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("inventory: store key location: %w", err)
	}
	return locID, inserted, nil
}

// locationSelectAny reads KeyLocation rows whether or not their target was deleted
// (scanLocation's order): the record of a change made on a server is kept after the server was
// removed from Alice.
const locationSelectAny = `SELECT l.id, l.ssh_key_id, k.fingerprint_sha256, k.key_type, l.target_id, t.name::text, l.os_user, l.file_path,
l.line_no, l.options, l.comment, l.flags, l.first_seen_at, l.last_seen_at, l.missing_since, l.removed_by_alice_at,
l.is_alice_connection_key
FROM ssh_key_locations l JOIN ssh_keys k ON k.id = l.ssh_key_id JOIN targets t ON t.id = l.target_id`

// locationSelect reads KeyLocation rows of live targets (scanLocation's order).
const locationSelect = locationSelectAny + ` AND t.deleted_at IS NULL`

func scanLocation(row pgx.Row, extra ...any) (KeyLocation, error) {
	var l KeyLocation
	dest := []any{&l.ID, &l.SSHKeyID, &l.Fingerprint, &l.KeyType, &l.TargetID, &l.TargetName, &l.OSUser, &l.FilePath,
		&l.LineNo, &l.Options, &l.Comment, &l.Flags, &l.FirstSeenAt, &l.LastSeenAt, &l.MissingSince, &l.RemovedAt,
		&l.IsAliceConnectionKey}
	err := row.Scan(append(dest, extra...)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return KeyLocation{}, ErrNotFound
	}
	if err != nil {
		return KeyLocation{}, fmt.Errorf("inventory: read key location: %w", err)
	}
	l.FirstSeenAt, l.LastSeenAt = l.FirstSeenAt.UTC(), l.LastSeenAt.UTC()
	l.MissingSince, l.RemovedAt = utcPtr(l.MissingSince), utcPtr(l.RemovedAt)
	if l.Flags == nil {
		l.Flags = []string{}
	}
	return l, nil
}

func collectLocations(rows pgx.Rows) ([]KeyLocation, error) {
	defer rows.Close()
	out := []KeyLocation{}
	for rows.Next() {
		l, err := scanLocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// KeyLocation returns one location on a live target.
func (s *Service) KeyLocation(ctx context.Context, id uuid.UUID) (KeyLocation, error) {
	return scanLocation(s.pool.QueryRow(ctx, locationSelect+" WHERE l.id = $1", id))
}

// ListTargetKeys returns the key locations of a live target (missing and removed ones only when asked).
func (s *Service) ListTargetKeys(ctx context.Context, targetID uuid.UUID, includeMissing bool) ([]KeyLocation, error) {
	if _, err := s.GetTarget(ctx, targetID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, locationSelect+` WHERE l.target_id = $1
  AND ($2 OR (l.missing_since IS NULL AND l.removed_by_alice_at IS NULL))
ORDER BY l.os_user, l.file_path, l.line_no, l.id`, targetID, includeMissing)
	if err != nil {
		return nil, fmt.Errorf("inventory: list target keys: %w", err)
	}
	return collectLocations(rows)
}

// foldSearch maps the Turkish I variants to i and lowercases ASCII (§10.5 search rule); the
// query side of the search below applies the same mapping to stored text with translate(), so
// both sides fold exactly the same characters whatever the database's locale is.
func foldSearch(s string) string {
	return foldASCII(strings.NewReplacer("İ", "i", "I", "i", "ı", "i").Replace(s))
}

// likePattern is a contains-pattern with the LIKE wildcards of s escaped.
func likePattern(s string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
}

func encodeCursor(at time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UTC().UnixMicro(), 10) + "." + id.String()))
}

// cursorMinMicros and cursorMaxMicros bound the time of a list cursor (AUD-13). No stored time
// reaches them: certificates whose NotBefore or NotAfter lies outside 0001-01-01 … 9999-12-31T23:59:59
// in UTC are refused when they come in (internal/certs), and first sightings and deployments come
// from the server clock. The bounds are wider on purpose: years 0000-9999 plus one day each side,
// what an X.509 GeneralizedTime with a ±23:59 zone offset can say (D19: UTCTime NotAfter values
// before 1970 are real). They only keep a hand-made cursor, or a row written outside Alice, from
// reaching a query PostgreSQL timestamptz (which holds the whole range) would still answer, and
// keep every cursor the lists hand out decodable.
var (
	cursorMinMicros = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC).Add(-24 * time.Hour).UnixMicro()
	cursorMaxMicros = time.Date(10000, 1, 2, 0, 0, 0, 0, time.UTC).UnixMicro() - 1
)

func decodeCursor(c string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("inventory: bad cursor")
	}
	micros, rest, ok := strings.Cut(string(raw), ".")
	n, err1 := strconv.ParseInt(micros, 10, 64)
	id, err2 := uuid.Parse(rest)
	if !ok || err1 != nil || err2 != nil || id.String() != rest || n < cursorMinMicros || n > cursorMaxMicros {
		return time.Time{}, uuid.Nil, errors.New("inventory: bad cursor")
	}
	return time.UnixMicro(n).UTC(), id, nil
}

// ListSSHKeys answers the inventory screen: one item per key with the locations that match the
// filter, ordered by first sighting, keyset-paginated.
func (s *Service) ListSSHKeys(ctx context.Context, f KeyFilter) (KeyPage, error) {
	var errs validate.Errors
	limit := f.Limit
	switch {
	case limit == 0:
		limit = defaultKeyLimit
	case limit < 1 || limit > maxKeyLimit:
		errs.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxKeyLimit)})
	}
	if f.Flag != "" && !slices.Contains(knownFlags, f.Flag) {
		errs.Add("flag", validate.OneOf, map[string]string{"values": strings.Join(knownFlags, ", ")})
	}
	if !utf8.ValidString(f.Query) || utf8.RuneCountInString(f.Query) > maxQueryRunes || strings.ContainsRune(f.Query, 0) {
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
		return KeyPage{}, errs
	}
	var target *uuid.UUID
	if f.TargetID != uuid.Nil {
		target = &f.TargetID
	}
	pattern := ""
	if q := strings.TrimSpace(f.Query); q != "" {
		pattern = likePattern(foldSearch(q))
	}
	rows, err := s.pool.Query(ctx, `SELECT k.id, k.fingerprint_sha256, k.key_type, k.bits, k.public_key, k.managed, k.is_platform_key, k.weak, k.first_seen_at,
    count(l.id), count(DISTINCT l.target_id),
    coalesce((array_agg(l.comment ORDER BY l.last_seen_at DESC, l.id DESC) FILTER (WHERE l.id IS NOT NULL))[1], k.key_comment),
    coalesce(bool_and(l.missing_since IS NOT NULL OR l.removed_by_alice_at IS NOT NULL) FILTER (WHERE l.id IS NOT NULL), false)
FROM ssh_keys k
LEFT JOIN (ssh_key_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL) ON l.ssh_key_id = k.id
WHERE (l.id IS NOT NULL OR (k.managed AND ($5::boolean OR k.retired_at IS NULL) AND $1::uuid IS NULL AND $2::text = '' AND $4::text = ''))
  AND ($1::uuid IS NULL OR l.target_id = $1)
  AND ($2::text = '' OR l.os_user = $2)
  AND ($3::text = ''
       OR translate(k.fingerprint_sha256, 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $3 ESCAPE '\'
       OR translate(l.comment, 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $3 ESCAPE '\'
       OR translate(k.key_comment, 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $3 ESCAPE '\'
       OR translate(k.key_type, 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $3 ESCAPE '\')
  AND ($4::text = '' OR $4 = ANY (l.flags))
  AND ($5::boolean OR l.id IS NULL OR (l.missing_since IS NULL AND l.removed_by_alice_at IS NULL)
       OR (k.managed AND k.retired_at IS NULL AND NOT EXISTS (SELECT 1 FROM ssh_key_locations x JOIN targets xt ON xt.id = x.target_id AND xt.deleted_at IS NULL
                                     WHERE x.ssh_key_id = k.id AND x.missing_since IS NULL AND x.removed_by_alice_at IS NULL)))
  AND ($6::timestamptz IS NULL OR (k.first_seen_at, k.id) > ($6::timestamptz, $7::uuid))
GROUP BY k.id
ORDER BY k.first_seen_at, k.id
LIMIT $8`, target, f.OSUser, pattern, f.Flag, f.IncludeMissing, afterAt, afterID, limit+1)
	if err != nil {
		return KeyPage{}, fmt.Errorf("inventory: list ssh keys: %w", err)
	}
	defer rows.Close()
	page := KeyPage{Items: []SSHKey{}}
	for rows.Next() {
		var k SSHKey
		if err := rows.Scan(&k.ID, &k.Fingerprint, &k.KeyType, &k.Bits, &k.PublicKey, &k.Managed, &k.IsPlatformKey, &k.Weak,
			&k.FirstSeenAt, &k.LocationCount, &k.TargetCount, &k.Comment, &k.Missing); err != nil {
			return KeyPage{}, fmt.Errorf("inventory: read ssh key: %w", err)
		}
		k.FirstSeenAt = k.FirstSeenAt.UTC()
		page.Items = append(page.Items, k)
	}
	if err := rows.Err(); err != nil {
		return KeyPage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = encodeCursor(last.FirstSeenAt, last.ID)
	}
	return page, nil
}

// GetSSHKey returns a key with every location on a live target (including missing and removed ones).
func (s *Service) GetSSHKey(ctx context.Context, id uuid.UUID) (SSHKey, error) {
	var k SSHKey
	err := s.pool.QueryRow(ctx, `SELECT id, fingerprint_sha256, key_type, bits, public_key, managed, is_platform_key, weak, first_seen_at, key_comment
FROM ssh_keys WHERE id = $1`, id).Scan(&k.ID, &k.Fingerprint, &k.KeyType, &k.Bits, &k.PublicKey, &k.Managed, &k.IsPlatformKey, &k.Weak, &k.FirstSeenAt, &k.Comment)
	if errors.Is(err, pgx.ErrNoRows) {
		return SSHKey{}, ErrNotFound
	}
	if err != nil {
		return SSHKey{}, fmt.Errorf("inventory: read ssh key: %w", err)
	}
	k.FirstSeenAt = k.FirstSeenAt.UTC()
	rows, err := s.pool.Query(ctx, locationSelect+" WHERE l.ssh_key_id = $1 ORDER BY t.name, l.os_user, l.file_path, l.id", id)
	if err != nil {
		return SSHKey{}, fmt.Errorf("inventory: list key locations: %w", err)
	}
	if k.Locations, err = collectLocations(rows); err != nil {
		return SSHKey{}, err
	}
	targets := map[uuid.UUID]bool{}
	var newest time.Time
	k.Missing = len(k.Locations) > 0
	for _, l := range k.Locations {
		if l.MissingSince == nil && l.RemovedAt == nil {
			k.Missing = false
		}
		targets[l.TargetID] = true
		if l.LastSeenAt.After(newest) {
			newest, k.Comment = l.LastSeenAt, l.Comment
		}
	}
	k.LocationCount, k.TargetCount = len(k.Locations), len(targets)
	return k, nil
}

// Bounds of the key files a scan reports (the provider's own: 200 users, 8 files per user).
const (
	maxKeyFileUsers = 200
	maxKeyFiles     = 8
	maxKeyFileLen   = 4096
	maxKeyFileUser  = 64
)

// cleanKeyFiles makes the key files of a scan storable and safe to offer later: an entry whose text clean() would
// change (invalid UTF-8, NUL), that holds a control character, a user that is empty or too long, a path that
// is not absolute or too long is dropped (a NUL must not fail the scan's jsonb); the lists are capped. Complete is
// carried through and cleared for an account whenever one of its files is dropped or cut; a dropped account is
// absent, which readers treat as not known to be complete.
func cleanKeyFiles(in []providers.UserKeyFiles) []providers.UserKeyFiles {
	var out []providers.UserKeyFiles
	for _, u := range in {
		if len(out) == maxKeyFileUsers {
			break
		}
		if !plainText(u.OSUser, maxKeyFileUser) {
			continue
		}
		var files []string
		complete := u.Complete // a dropped or cut file makes the list incomplete
		for _, f := range u.Files {
			if !plainText(f, maxKeyFileLen) || !strings.HasPrefix(f, "/") {
				complete = false
				continue
			}
			if len(files) == maxKeyFiles {
				complete = false
				break
			}
			files = append(files, f)
		}
		if len(files) > 0 {
			out = append(out, providers.UserKeyFiles{OSUser: u.OSUser, Files: files, Complete: complete})
		}
	}
	return out
}

// blankLooking lists the characters no Unicode category catches: the Hangul fillers (U+115F, U+1160, U+3164,
// U+FFA0) and the braille blank (U+2800) render as nothing but are letters or symbols.
const blankLooking = "\u115f\u1160\u3164\uffa0\u2800"

// spoofingText reports text that must not be shown in the UI as a name or path because it can be made to look
// like something else: any control character (Cc), format character (Cf: zero-width, bidirectional controls such
// as U+202E and U+2066..U+2069), line or paragraph separator (Zl, Zp), space other than U+0020 (Zs: no-break,
// ideographic and the en/em spaces), one of the blank-looking characters above, or a combining mark (Mn, Me:
// variation selectors, U+034F) at the start of the text or of a path segment (right after a '/'): a mark in the
// middle of a segment belongs to its base letter and is allowed.
func spoofingText(s string) bool {
	start := true
	for _, r := range s {
		switch {
		case unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp), unicode.Is(unicode.Zs, r) && r != ' ',
			strings.ContainsRune(blankLooking, r), start && unicode.In(r, unicode.Mn, unicode.Me):
			return true
		}
		start = r == '/'
	}
	return false
}

// plainText: 1 to limit bytes of valid UTF-8 without control, invisible or bidirectional characters (clean leaves it as it is).
func plainText(s string, limit int) bool {
	return s != "" && len(s) <= limit && clean(s) == s && !spoofingText(s)
}
