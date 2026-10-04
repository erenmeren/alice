package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/providers"
)

// Polling a Key Vault (spec §11.6, §11.9; R40 rows 12, 13, 15-17, 21).
//
// A poll is three steps: KVPollRequest says what to read, the provider reads it, ReconcileKV stores
// the answer. ReconcileKV stores in batches (ruling S12): certificates with their versions, keys
// and secrets each in transactions of a bounded size that hold the vault's row, then one final
// transaction that marks what a complete listing did not contain, settles uncertain imports, moves
// the vault's status and counters and writes the poll's emails and audit rows. What a reader sees
// while that runs: whole certificates only (the row, its leaf, its current version and its older
// versions commit together, per batch); some certificates already as of this poll and others still
// as of the last one; never a "missing" mark, a new status, a new last_success_at or the
// kv_metadata_at of this poll before the end. A poll that stops half way (a lost claim, a cancelled
// context) leaves the batches it committed (each is a valid sighting) and marks nothing missing.

// MaxConcurrentKVPolls is how many vault polls run at the same time (ruling S12): the poll job
// holds a slot (AcquireKVPoll) around its provider calls and ReconcileKV.
const MaxConcurrentKVPolls = 2

const (
	// maxRemovedNotices bounds the emails and maxRemovedAudits the audit rows of one poll's removals
	// (a vault emptied at once is one event, not thousands of emails); every removal is marked.
	maxRemovedNotices = 20
	maxRemovedAudits  = 200
	// kvThrottledCycles is how many throttled cycles in a row degrade a vault (F-44).
	kvThrottledCycles = 3
	// kvAuthNotice is the failed sign-ins in a row that send the email (R40 row 12).
	kvAuthNotice = 3
	// keysEveryIntervals: keys and secrets are listed when the last read is this many intervals old.
	keysEveryIntervals = 4
)

// KVPollFacts is what the last poll found wrong (targets.facts.kv_poll).
type KVPollFacts struct {
	At             time.Time       `json:"at"`
	Failures       []KVPollFailure `json:"failures,omitempty"`
	Truncated      []string        `json:"truncated,omitempty"`
	DetailsPending int             `json:"details_pending,omitempty"`
}

// KVPollFailure is one failed list (Object "certificates", "keys" or "secrets") or the whole poll
// (Object "vault"): a closed reason and the allowlisted params of the provider's error, never text.
type KVPollFailure struct {
	Object        string `json:"object"`
	Reason        string `json:"reason"`
	Role          string `json:"role,omitempty"`
	ClientAddress string `json:"client_address,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	AzureCode     string `json:"azure_code,omitempty"`
	Aadsts        string `json:"aadsts,omitempty"`
}

// KVSummary is what ReconcileKV did.
type KVSummary struct {
	Certificates        int // certificates of the listing that were stored
	NewCertificates     int
	NewVersions         int // current versions that arrived on known certificates (each audited once)
	HeldVersions        int // versions stored held because the license gate was closed
	VersionConflicts    int // versions Azure reported with another thumbprint than Alice knows (kept as stored)
	MissingCertificates int
	Keys, NewKeys       int
	MissingKeys         int
	Secrets, NewSecrets int
	MissingSecrets      int
	Status              string // the vault's status after the poll
	// Dropped: the vault was deleted ("deleted") or disabled ("disabled") while the poll ran; what
	// was not stored yet was dropped and nothing else was changed.
	Dropped string
}

// AcquireKVPoll takes one of the MaxConcurrentKVPolls slots (it waits for one, or for ctx). The
// returned release may be called more than once.
func (s *Service) AcquireKVPoll(ctx context.Context) (func(), error) {
	select {
	case s.kvSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() { once.Do(func() { <-s.kvSlots }) }, nil
}

// KVPollRequest is what the provider is asked to read for the next poll of the vault: always the
// certificates (with what Alice knows, so details are read only for changes), and keys and secrets
// when their last read is older than four intervals or never happened (R40 row 15; with the key
// versions whose details Alice has). A disabled vault is not polled (ErrTargetNotReady).
func (s *Service) KVPollRequest(ctx context.Context, id uuid.UUID) (providers.DiscoverRequest, error) {
	t, err := getVault(ctx, s.pool, id, false)
	if err != nil {
		return providers.DiscoverRequest{}, err
	}
	if t.Status == StatusDisabled {
		return providers.DiscoverRequest{}, ErrTargetNotReady
	}
	now := s.clock.Now().UTC()
	asks := t.Facts.KVMetadataAt == nil || now.Sub(*t.Facts.KVMetadataAt) >= keysEveryIntervals*t.DiscoveryInterval
	req := providers.DiscoverRequest{Certificates: true, KVKeys: asks, KVSecrets: asks,
		KVKnown: map[string]providers.KVKnown{}, KVKnownKeys: map[string]time.Time{}}
	rows, err := s.pool.Query(ctx, `SELECT name, current_version, current_thumbprint, kv_updated_at FROM kv_certificates
WHERE target_id = $1 AND current_version <> '' AND kv_updated_at IS NOT NULL`, id)
	if err != nil {
		return providers.DiscoverRequest{}, fmt.Errorf("inventory: read the known certificates: %w", err)
	}
	for rows.Next() {
		var name string
		var k providers.KVKnown
		if err := rows.Scan(&name, &k.Version, &k.Thumbprint, &k.Updated); err != nil {
			rows.Close()
			return providers.DiscoverRequest{}, fmt.Errorf("inventory: read a known certificate: %w", err)
		}
		k.Updated = k.Updated.UTC()
		req.KVKnown[name] = k
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return providers.DiscoverRequest{}, err
	}
	if !asks {
		req.KVKnownKeys = nil
		return req, nil
	}
	rows, err = s.pool.Query(ctx, "SELECT name, details_updated_at FROM kv_keys WHERE target_id = $1 AND details_updated_at IS NOT NULL", id)
	if err != nil {
		return providers.DiscoverRequest{}, fmt.Errorf("inventory: read the known keys: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var at time.Time
		if err := rows.Scan(&name, &at); err != nil {
			return providers.DiscoverRequest{}, fmt.Errorf("inventory: read a known key: %w", err)
		}
		req.KVKnownKeys[name] = at.UTC()
	}
	return req, rows.Err()
}

// resolveImports settles the uncertain imports of the vault from what the poll stored (Task 14).
// complete says the certificate listing was whole, so the absence of a version means something.
// Until then it changes nothing.
func (s *Service) resolveImports(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ time.Time, _ bool) error {
	return nil
}

// ReconcileKV stores one poll's result (see the top of this file). Rules:
//   - an object of a kind is marked missing only when that kind was asked for, listed completely
//     (not cut at a bound, not missing an item Alice could not store, not failed) and the object is
//     absent: certificates by the certificate listing, keys by KeysListed, secrets by SecretsListed;
//   - a version is new when its row is inserted (the unique (certificate, version) decides, so a
//     repeated or concurrent poll finds it already there): its first-seen time, its held flag and
//     its audit row are written once, in the batch that inserts it. The first details of a
//     certificate are a first sight, not a new version (§11.6 item 7). A version stored while the
//     license gate refuses changes is held (reason license) in the same statement and is never
//     released by a later poll;
//   - a version ID that Alice knows with another thumbprint is kept as stored and recorded
//     (audit kv.certificate.version_conflict, facts warning kv_version_conflict);
//   - last_success_at and last_discovery_at move only when the certificate listing answered; the
//     failure transitions are in kvPollStatus.
//
// With a Claim on ctx nothing is written once the run no longer holds its job (ErrClaimLost). A
// result for a vault deleted or disabled meanwhile is dropped (KVSummary.Dropped, no error).
func (s *Service) ReconcileKV(ctx context.Context, id uuid.UUID, res providers.DiscoveryResult) (KVSummary, error) {
	var sum KVSummary
	tg, err := readKVTarget(ctx, s.pool, id, "")
	if err != nil {
		return sum, err
	}
	if d := tg.dropped(); d != "" {
		sum.Dropped = d
		return sum, nil
	}
	now := s.clock.Now().UTC()
	p, err := s.prepareKV(res, now)
	if err != nil {
		return sum, err
	}
	// Decided before anything is stored, once for the whole poll (L-87, ruling S8).
	held := s.license.Allow(license.ClassChange) != nil
	var st kvStored
	dropped, err := s.storeKV(ctx, id, p, now, held, &st)
	sum.NewCertificates, sum.NewVersions, sum.HeldVersions, sum.VersionConflicts = st.newCerts, st.newVersions, st.heldVersions, st.conflicts
	sum.NewKeys, sum.NewSecrets = st.newKeys, st.newSecrets
	if err != nil {
		return sum, err
	}
	if dropped != "" {
		sum.Dropped = dropped
		return sum, nil
	}
	sum.Certificates, sum.Keys, sum.Secrets = len(p.certs), len(p.keys), len(p.secrets)

	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		cur, err := readKVTarget(ctx, tx, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if d := cur.dropped(); d != "" {
			sum.Dropped = d
			return nil
		}
		t, err := getVault(ctx, tx, id, false)
		if err != nil {
			return err
		}
		var removed []removedCert
		// Defence in depth: an empty complete listing of a vault that has stored certificates is
		// believed only on the second successful poll in a row (the spec has no mass-disappearance
		// rule). The first is recorded (facts.kv_empty_polls, warning kv_listing_empty).
		emptyPolls, hold := t.Facts.KVEmptyPolls, false
		if p.certsAnswered && len(p.certs) > 0 {
			emptyPolls = 0
		}
		if p.certsComplete && len(p.certs) == 0 {
			var present int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM kv_certificates WHERE target_id = $1 AND missing_since IS NULL", id).Scan(&present); err != nil {
				return fmt.Errorf("inventory: count the stored certificates: %w", err)
			}
			if present == 0 {
				emptyPolls = 0
			} else if emptyPolls == 0 {
				emptyPolls, hold = 1, true
			} else {
				emptyPolls = 0 // the second empty listing in a row is believed
			}
		}
		if p.certsComplete && !hold {
			if removed, err = markMissingCerts(ctx, tx, id, foldedNames(p.certs, func(c kvCert) string { return c.fold }), now); err != nil {
				return err
			}
		}
		sum.MissingCertificates = len(removed)
		if p.keysComplete {
			if sum.MissingKeys, err = markMissingNames(ctx, tx, "kv_keys", id, foldedNames(p.keys, func(k kvKeyItem) string { return k.fold }), now); err != nil {
				return err
			}
		}
		if p.secretsComplete {
			if sum.MissingSecrets, err = markMissingNames(ctx, tx, "kv_secrets", id, foldedNames(p.secrets, func(k kvSecretItem) string { return k.fold }), now); err != nil {
				return err
			}
		}
		if err := s.resolveImports(ctx, tx, id, now, p.certsComplete); err != nil {
			return err
		}

		to, code, cycles := kvPollStatus(t, p)
		sum.Status = to
		f := t.Facts
		if p.keysAsked || p.secretsAsked {
			f.KVMetadataAt = &now
		}
		f.KVAuthFailures, f.KVThrottledCycles, f.KVEmptyPolls = 0, cycles, emptyPolls
		f.KVPoll = &KVPollFacts{At: now, Failures: p.failures, Truncated: p.truncated, DetailsPending: p.detailsPending}
		f.Warnings = p.warnings()
		if hold {
			f.Warnings = append(f.Warnings, providers.Warning{Code: WarnKVListingEmpty, Params: map[string]string{}})
		}
		if sum.VersionConflicts > 0 {
			f.Warnings = append(f.Warnings, providers.Warning{Code: WarnKVVersionConflict,
				Params: map[string]string{"object": kvCertificates, "count": strconv.Itoa(sum.VersionConflicts)}})
		}
		raw, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE targets SET status = $2, last_error_code = $3,
    last_success_at = CASE WHEN $4::boolean THEN $5::timestamptz ELSE last_success_at END,
    last_discovery_at = CASE WHEN $4::boolean THEN $5::timestamptz ELSE last_discovery_at END,
    poll_failures = CASE WHEN $4::boolean THEN 0 ELSE LEAST(poll_failures + 1, $6::integer) END,
    facts = $7, updated_at = $5 WHERE id = $1`, id, to, code, p.certsAnswered, now, maxPollFailures, raw); err != nil {
			return fmt.Errorf("inventory: store the poll's outcome: %w", err)
		}

		// The removals: marked above; the first few are announced.
		var noticeIDs []uuid.UUID
		for i, r := range removed {
			if i < maxRemovedNotices && s.notifier != nil {
				binding := "no"
				if r.bound {
					binding = "yes"
				}
				if err := s.notifier.NotifyAdmins(ctx, tx, TemplateKVCertificateRemoved,
					map[string]string{"target_name": cur.name, "certificate_name": r.name, "binding": binding}); err != nil {
					return fmt.Errorf("inventory: queue the removal email: %w", err)
				}
				noticeIDs = append(noticeIDs, r.id)
			}
		}
		if len(noticeIDs) > 0 {
			if _, err := tx.Exec(ctx, "UPDATE kv_certificates SET removed_notified_at = $2 WHERE id = ANY($1)", noticeIDs, now); err != nil {
				return fmt.Errorf("inventory: record the removal emails: %w", err)
			}
		}
		for i, r := range removed {
			if i >= maxRemovedAudits {
				break
			}
			binding := "no"
			if r.bound {
				binding = "yes"
			}
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("jobs"), Action: "kv.certificate.removed",
				ObjectType: "kv_certificate", ObjectID: r.id.String(), Result: audit.Success, Details: map[string]string{
					"kv_certificate_id": r.id.String(), "certificate_name": r.name, "vault_url": cur.url, "binding": binding}}); err != nil {
				return err
			}
		}
		changed := sum.NewCertificates + sum.NewVersions + sum.NewKeys + sum.NewSecrets + sum.MissingCertificates + sum.MissingKeys + sum.MissingSecrets
		if changed > 0 {
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("jobs"), Action: "target.discovered",
				ObjectType: "target", ObjectID: id.String(), Result: audit.Success, Details: map[string]string{
					"certificate_count": strconv.Itoa(sum.Certificates), "item_count": strconv.Itoa(sum.Keys + sum.Secrets),
					"new_certificate_count": strconv.Itoa(sum.NewCertificates), "new_version_count": strconv.Itoa(sum.NewVersions),
					"missing_count": strconv.Itoa(sum.MissingCertificates + sum.MissingKeys + sum.MissingSecrets),
					"partial":       strconv.FormatBool(len(p.failures) > 0 || len(p.truncated) > 0)}}); err != nil {
				return err
			}
		}
		reason := code
		if to == StatusOK {
			reason = "kv_poll_ok"
		}
		return s.auditStatus(ctx, tx, t, to, reason)
	})
	return sum, err
}

func foldedNames[T any](items []T, fold func(T) string) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = fold(it)
	}
	return out
}

// kvPollStatus is the vault's status after a poll that reached it (the table is in the Task 11
// report): a list that failed other than by throttling makes it degraded with that reason; the
// third throttled cycle in a row degrades it (azure.throttled); one or two throttled cycles change
// nothing; otherwise it is ok and the last error is cleared. A disabled vault stays disabled.
// cycles is the new count of throttled cycles in a row.
func kvPollStatus(t Target, p *preparedKV) (status, code string, cycles int) {
	if p.throttled {
		cycles = min(t.Facts.KVThrottledCycles+1, 1_000_000)
	}
	if t.Status == StatusDisabled {
		return StatusDisabled, t.LastErrorCode, cycles
	}
	for _, f := range p.failures {
		if f.Reason != "azure.throttled" {
			return StatusDegraded, f.Reason, cycles
		}
	}
	switch {
	case cycles >= kvThrottledCycles:
		return StatusDegraded, "azure.throttled", cycles
	case p.throttled:
		return t.Status, t.LastErrorCode, cycles
	}
	return StatusOK, "", cycles
}

const maxPollFailures = 1_000_000

// failure classes of a poll that failed as a whole.
var (
	signInFailures     = []string{"azure.auth_failed", "azure.credentials_expired", "azure.clock_skew", "azure.managed_identity_unavailable"}
	unreachableReasons = []string{"azure.unreachable", "azure.vault_not_found", "azure.tls_untrusted", "azure.address_not_allowed"}
	refusedReasons     = []string{"azure.forbidden", "azure.firewall"}
)

// RecordKVFailure records a poll that failed as a whole (the cause is the provider's error; any
// other error is internal.unexpected, its text never stored). Transitions: a failed sign-in
// (azure.auth_failed, credentials_expired, clock_skew, managed_identity_unavailable) makes the vault
// auth_failed and counts toward the email at the third in a row (once per episode); an unreachable
// vault (unreachable, vault_not_found, tls_untrusted, address_not_allowed) is unreachable; forbidden
// or firewall is degraded; the third throttled cycle in a row is degraded; anything else leaves the
// status and counts. Every failure adds one to poll_failures (bounded), which delays the next poll
// (ScheduleKVPolls), and sets last_error_code. A disabled or deleted vault is left alone.
func (s *Service) RecordKVFailure(ctx context.Context, id uuid.UUID, cause error) error {
	var pe *providers.Error
	if !errors.As(cause, &pe) {
		pe = nil
	}
	failure := sanitizeKVFailure(kvWhole, pe)
	now := s.clock.Now().UTC()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		cur, err := readKVTarget(ctx, tx, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if cur.dropped() != "" {
			return nil
		}
		t, err := getVault(ctx, tx, id, false)
		if err != nil {
			return err
		}
		reason := failure.Reason
		to, auth, cycles := t.Status, 0, 0
		switch {
		case slices.Contains(signInFailures, reason):
			to, auth = StatusAuthFailed, min(t.Facts.KVAuthFailures+1, maxPollFailures)
		case slices.Contains(unreachableReasons, reason):
			to = StatusUnreachable
		case slices.Contains(refusedReasons, reason):
			to = StatusDegraded
		case reason == "azure.throttled":
			cycles = min(t.Facts.KVThrottledCycles+1, maxPollFailures)
			if cycles >= kvThrottledCycles {
				to = StatusDegraded
			}
		}
		f := t.Facts
		f.KVAuthFailures, f.KVThrottledCycles = auth, cycles
		f.KVPoll = &KVPollFacts{At: now, Failures: []KVPollFailure{failure}}
		raw, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE targets SET status = $2, last_error_code = $3, poll_failures = LEAST(poll_failures + 1, $4),
    facts = $5, updated_at = $6 WHERE id = $1`, id, to, reason, maxPollFailures, raw, now); err != nil {
			return fmt.Errorf("inventory: record a failed poll: %w", err)
		}
		if auth == kvAuthNotice && s.notifier != nil {
			if err := s.notifier.NotifyAdmins(ctx, tx, TemplateKVAuthFailed, map[string]string{"target_name": t.Name, "reason": reason}); err != nil {
				return fmt.Errorf("inventory: queue the sign-in email: %w", err)
			}
		}
		return s.auditStatus(ctx, tx, t, to, reason)
	})
}
