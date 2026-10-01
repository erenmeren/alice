package inventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// Host-key statuses (host_keys.status, R37 item 6).
const (
	keyObserved   = "observed"
	keyPinned     = "pinned"
	keySuperseded = "superseded"
	keyRejected   = "rejected"
)

const (
	minReasonRunes = 10
	maxReasonRunes = 500
)

// HostKeyRecord is one row of a target's host-key history. Status is authoritative; SupersededAt
// may be set on an observed row (a replaced key the server presents again).
type HostKeyRecord struct {
	ID              uuid.UUID
	KeyType         string
	Fingerprint     string
	Status          string
	ObservedAt      time.Time
	ConfirmedAt     *time.Time
	ConfirmedByName string
	SupersededAt    *time.Time
}

// VerifyCommand is the command an administrator runs on the server to compare the fingerprint
// (R33 "UI copy-paste fingerprint verification command").
func VerifyCommand(keyType string) string {
	name := "ed25519"
	switch {
	case strings.HasPrefix(keyType, "ecdsa-"):
		name = "ecdsa"
	case keyType == "ssh-rsa" || strings.HasPrefix(keyType, "rsa-"):
		name = "rsa"
	}
	return "ssh-keygen -lf /etc/ssh/ssh_host_" + name + "_key.pub"
}

// HostKeyStore returns the store the SSH dialer pins against (providers.HostKeyStore).
func (s *Service) HostKeyStore() providers.HostKeyStore { return hostKeyStore{s: s} }

type hostKeyStore struct{ s *Service }

// Pinned returns the pinned key of the target or providers.ErrNoPinnedKey.
func (h hostKeyStore) Pinned(ctx context.Context, target uuid.UUID) (providers.HostKey, error) {
	var k providers.HostKey
	err := h.s.pool.QueryRow(ctx, "SELECT key_type, public_key, fingerprint_sha256 FROM host_keys WHERE target_id = $1 AND status = $2",
		target, keyPinned).Scan(&k.Type, &k.PublicKey, &k.Fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return providers.HostKey{}, providers.ErrNoPinnedKey
	}
	if err != nil {
		return providers.HostKey{}, fmt.Errorf("inventory: read pinned host key: %w", err)
	}
	return k, nil
}

// errInconsistentHostKey: the sighting's type or fingerprint is not the one of its public key.
var errInconsistentHostKey = errors.New("inventory: an observed host key's type and fingerprint must be those of its public key")

// checkHostKey makes sure the fingerprint an Administrator will compare names exactly the key
// that a confirmation pins.
func checkHostKey(k providers.HostKey) error {
	if k.Type == "" || k.Fingerprint == "" || len(k.PublicKey) == 0 {
		return errInconsistentHostKey
	}
	pub, err := ssh.ParsePublicKey(k.PublicKey)
	if err != nil || pub.Type() != k.Type || ssh.FingerprintSHA256(pub) != k.Fingerprint {
		return errInconsistentHostKey
	}
	return nil
}

// Observed records a key the server presented that is not pinned; it never pins anything (R37
// item 6). The newest such key is the only candidate an Administrator can confirm; older
// candidates become rejected. Repeated or late reports of the same key update its one row
// (unique per target and fingerprint). Whenever another key is pinned the target is blocked,
// whatever the caller's changed flag says (the store, not the caller, decides what a change is);
// only the transition into host_key_changed is audited and mailed to every Administrator, in the
// transaction that makes it, so however often and however late the change is reported it is
// announced once (F-31, Review Focus 5). A further new key seen while the target is already
// blocked is audited (hostkey.observed) without an email. Every call locks the target row first,
// so concurrent reports serialize. The pinned key is never replaced here.
func (h hostKeyStore) Observed(ctx context.Context, target uuid.UUID, key providers.HostKey, _ bool) error {
	if err := checkHostKey(key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s := h.s
	now := s.clock.Now().UTC()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getTarget(ctx, tx, target, true)
		if err != nil {
			return err
		}
		var old string
		err = tx.QueryRow(ctx, "SELECT fingerprint_sha256 FROM host_keys WHERE target_id = $1 AND status = $2", target, keyPinned).Scan(&old)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inventory: read pinned host key: %w", err)
		}
		if old == key.Fingerprint {
			return nil // the pinned key itself (a late report of a sighting since accepted): nothing to record
		}
		var prev string
		err = tx.QueryRow(ctx, "SELECT status FROM host_keys WHERE target_id = $1 AND fingerprint_sha256 = $2", target, key.Fingerprint).Scan(&prev)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inventory: read host key: %w", err)
		}
		newCandidate := prev != keyObserved
		_, err = tx.Exec(ctx, `INSERT INTO host_keys (id, target_id, key_type, public_key, fingerprint_sha256, status, observed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (target_id, fingerprint_sha256) DO UPDATE SET observed_at = EXCLUDED.observed_at,
    status = CASE WHEN host_keys.status = $8 THEN host_keys.status ELSE EXCLUDED.status END`,
			uuid.Must(uuid.NewV7()), target, key.Type, key.PublicKey, key.Fingerprint, keyObserved, now, keyPinned)
		if err != nil {
			return fmt.Errorf("inventory: record host key: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE host_keys SET status = $3
WHERE target_id = $1 AND status = $4 AND fingerprint_sha256 <> $2`, target, key.Fingerprint, keyRejected, keyObserved); err != nil {
			return fmt.Errorf("inventory: retire older host key candidates: %w", err)
		}
		if old == "" {
			return nil // nothing pinned: a candidate, not a change
		}
		tag, err := tx.Exec(ctx, `UPDATE targets SET status = $2, last_error_code = 'target.host_key_changed', updated_at = $3
WHERE id = $1 AND status <> $2`, target, StatusHostKeyChanged, now)
		if err != nil {
			return fmt.Errorf("inventory: block target: %w", err)
		}
		details := map[string]string{"old_fingerprint": old, "new_fingerprint": key.Fingerprint, "target_name": t.Name}
		if tag.RowsAffected() == 0 {
			if !newCandidate {
				return nil // already blocked and already the candidate: announced before
			}
			// Already blocked (and mailed at the transition): another key is recorded, not mailed.
			_, err = s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("ssh"), Action: "hostkey.observed",
				ObjectType: "target", ObjectID: target.String(), Result: audit.Failure, Details: details})
			return err
		}
		if s.notifier != nil {
			if err := s.notifier.NotifyAdmins(ctx, tx, TemplateHostKeyChanged, map[string]string{
				"target_name": t.Name, "old_fingerprint": old, "new_fingerprint": key.Fingerprint}); err != nil {
				return fmt.Errorf("inventory: queue the host key email: %w", err)
			}
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("ssh"), Action: "hostkey.changed",
			ObjectType: "target", ObjectID: target.String(), Result: audit.Failure, Details: details})
		return err
	})
}

// ListHostKeys returns the host-key history of a live target, newest first. Status is
// authoritative: a key that was superseded and later presented again is a candidate (observed)
// that still carries the time it was superseded (SupersededAt) until it is pinned again.
func (s *Service) ListHostKeys(ctx context.Context, targetID uuid.UUID) ([]HostKeyRecord, error) {
	if _, err := s.GetTarget(ctx, targetID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT h.id, h.key_type, h.fingerprint_sha256, h.status, h.observed_at, h.confirmed_at,
coalesce(u.display_name, ''), h.superseded_at
FROM host_keys h LEFT JOIN users u ON u.id = h.confirmed_by
WHERE h.target_id = $1 ORDER BY h.observed_at DESC, h.id`, targetID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list host keys: %w", err)
	}
	defer rows.Close()
	out := []HostKeyRecord{}
	for rows.Next() {
		var r HostKeyRecord
		if err := rows.Scan(&r.ID, &r.KeyType, &r.Fingerprint, &r.Status, &r.ObservedAt, &r.ConfirmedAt, &r.ConfirmedByName, &r.SupersededAt); err != nil {
			return nil, fmt.Errorf("inventory: read host key: %w", err)
		}
		r.ObservedAt, r.ConfirmedAt, r.SupersededAt = r.ObservedAt.UTC(), utcPtr(r.ConfirmedAt), utcPtr(r.SupersededAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// candidate locks the observed key row an Administrator confirms and checks that it is the key
// the server presented last and that its fingerprint is the one the Administrator saw: a key
// swapped between display and confirmation is never pinned.
func candidate(ctx context.Context, tx pgx.Tx, targetID, keyID uuid.UUID, fingerprint string) (keyType string, err error) {
	var status, fp string
	err = tx.QueryRow(ctx, "SELECT key_type, status, fingerprint_sha256 FROM host_keys WHERE id = $1 AND target_id = $2 FOR UPDATE",
		keyID, targetID).Scan(&keyType, &status, &fp)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrHostKeyStale
	}
	if err != nil {
		return "", fmt.Errorf("inventory: read host key: %w", err)
	}
	if status != keyObserved || fp != strings.TrimSpace(fingerprint) {
		return "", ErrHostKeyStale
	}
	return keyType, nil
}

// pin makes the candidate the target's one pinned key (host_keys_one_pinned) and records who
// confirmed it.
func pin(ctx context.Context, tx pgx.Tx, keyID uuid.UUID, by uuid.UUID, now time.Time) error {
	if _, err := tx.Exec(ctx, "UPDATE host_keys SET status = $2, confirmed_by = $3, confirmed_at = $4, superseded_at = NULL WHERE id = $1",
		keyID, keyPinned, nullableUser(by), now); err != nil {
		return fmt.Errorf("inventory: pin host key: %w", err)
	}
	return nil
}

// ConfirmHostKey pins the key a new target presented, after an Administrator compared its
// fingerprint (F-30). It queues a connection test and returns its job id.
func (s *Service) ConfirmHostKey(ctx context.Context, a Actor, targetID, keyID uuid.UUID, fingerprint string) (uuid.UUID, error) {
	var jobID uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getTarget(ctx, tx, targetID, true)
		if err != nil {
			return err
		}
		var pinnedExists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM host_keys WHERE target_id = $1 AND status = $2)",
			targetID, keyPinned).Scan(&pinnedExists); err != nil {
			return fmt.Errorf("inventory: read pinned host key: %w", err)
		}
		if t.Status != StatusPendingHostKey || pinnedExists {
			return ErrHostKeyState
		}
		keyType, err := candidate(ctx, tx, targetID, keyID, fingerprint)
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		if err := pin(ctx, tx, keyID, a.UserID, now); err != nil {
			return err
		}
		if err := setChecking(ctx, tx, targetID, now); err != nil {
			return err
		}
		if jobID, err = s.enqueueTest(ctx, tx, a, targetID); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "hostkey.pinned", ObjectType: "host_key",
			ObjectID: keyID.String(), Result: audit.Success, Details: map[string]string{
				"fingerprint": strings.TrimSpace(fingerprint), "algorithm": keyType, "target_id": targetID.String()}})
		return err
	})
	return jobID, err
}

// RepinHostKey accepts a changed host key (F-32): an Administrator with a fresh step-up (route
// permission hostkeys.repin) and a reason. The old key stays in the history as superseded; the
// supersede and the pin happen in one transaction, so a target never has two pinned keys.
// keyID may also name the pinned key itself: the Administrator then dismisses the change (the
// server shows its confirmed key again), every outstanding candidate is rejected, nothing is
// superseded, and the change is audited as hostkey.change_dismissed. Either way the target
// resumes work through a new connection test.
func (s *Service) RepinHostKey(ctx context.Context, a Actor, targetID, keyID uuid.UUID, fingerprint, reason string) (uuid.UUID, error) {
	reason = strings.TrimSpace(reason)
	if errs := validateReason(reason); len(errs) > 0 {
		return uuid.Nil, errs
	}
	var jobID uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getTarget(ctx, tx, targetID, true)
		if err != nil {
			return err
		}
		if t.Status != StatusHostKeyChanged {
			return ErrHostKeyState
		}
		now := s.clock.Now().UTC()
		var dismissed bool
		if jobID, dismissed, err = s.dismissChange(ctx, tx, a, targetID, keyID, fingerprint, reason, now); err != nil || dismissed {
			return err
		}
		if _, err := candidate(ctx, tx, targetID, keyID, fingerprint); err != nil {
			return err
		}
		var old string
		err = tx.QueryRow(ctx, `UPDATE host_keys SET status = $3, superseded_at = $2
WHERE target_id = $1 AND status = $4 RETURNING fingerprint_sha256`, targetID, now, keySuperseded, keyPinned).Scan(&old)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inventory: supersede host key: %w", err)
		}
		if err := pin(ctx, tx, keyID, a.UserID, now); err != nil {
			return err
		}
		if err := setChecking(ctx, tx, targetID, now); err != nil {
			return err
		}
		if jobID, err = s.enqueueTest(ctx, tx, a, targetID); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "hostkey.repinned", ObjectType: "host_key",
			ObjectID: keyID.String(), Result: audit.Success, Details: map[string]string{
				"old_fingerprint": old, "new_fingerprint": strings.TrimSpace(fingerprint), "reason": reason, "target_id": targetID.String()}})
		return err
	})
	return jobID, err
}

// dismissChange handles a re-pin of the pinned key itself (see RepinHostKey). dismissed is false
// when keyID is not the pinned row (an ordinary re-pin). The fingerprint must be the pinned one.
func (s *Service) dismissChange(ctx context.Context, tx pgx.Tx, a Actor, targetID, keyID uuid.UUID, fingerprint, reason string,
	now time.Time) (jobID uuid.UUID, dismissed bool, err error) {
	var fp string
	err = tx.QueryRow(ctx, "SELECT fingerprint_sha256 FROM host_keys WHERE id = $1 AND target_id = $2 AND status = $3",
		keyID, targetID, keyPinned).Scan(&fp)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("inventory: read pinned host key: %w", err)
	}
	if fp != strings.TrimSpace(fingerprint) {
		return uuid.Nil, false, ErrHostKeyStale
	}
	if err := rejectCandidates(ctx, tx, targetID); err != nil {
		return uuid.Nil, false, err
	}
	if err := setChecking(ctx, tx, targetID, now); err != nil {
		return uuid.Nil, false, err
	}
	if jobID, err = s.enqueueTest(ctx, tx, a, targetID); err != nil {
		return uuid.Nil, false, err
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "hostkey.change_dismissed", ObjectType: "host_key",
		ObjectID: keyID.String(), Result: audit.Success, Details: map[string]string{
			"old_fingerprint": fp, "new_fingerprint": fp, "reason": reason, "target_id": targetID.String()}})
	if err != nil {
		return uuid.Nil, false, err
	}
	return jobID, true, nil
}

// rejectCandidates marks every outstanding candidate of the target rejected: the server no longer
// presents it, so it can never be confirmed.
func rejectCandidates(ctx context.Context, tx pgx.Tx, targetID uuid.UUID) error {
	if _, err := tx.Exec(ctx, "UPDATE host_keys SET status = $2 WHERE target_id = $1 AND status = $3", targetID, keyRejected, keyObserved); err != nil {
		return fmt.Errorf("inventory: reject host key candidates: %w", err)
	}
	return nil
}

// validateReason: 10 to 500 characters on one line, no control, invisible format or bidi
// characters (as validName), never a PEM block (S-05: people paste secrets into reason fields).
func validateReason(reason string) validate.Errors {
	var errs validate.Errors
	n := utf8.RuneCountInString(reason)
	switch {
	case n < minReasonRunes:
		errs.Add("reason", validate.TooShort, map[string]string{"min": strconv.Itoa(minReasonRunes)})
	case n > maxReasonRunes:
		errs.Add("reason", validate.TooLong, map[string]string{"max": strconv.Itoa(maxReasonRunes)})
	case strings.Contains(reason, "-----BEGIN") || strings.ContainsFunc(reason, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r)
	}):
		errs.Add("reason", validate.Pattern, nil)
	}
	return errs
}

// setChecking moves a target whose key was just pinned to checking until its next connection
// test; the confirmation's own audit row records the transition.
func setChecking(ctx context.Context, tx pgx.Tx, targetID uuid.UUID, now time.Time) error {
	if _, err := tx.Exec(ctx, "UPDATE targets SET status = $3, last_error_code = '', updated_at = $2 WHERE id = $1",
		targetID, now, StatusChecking); err != nil {
		return fmt.Errorf("inventory: update target status: %w", err)
	}
	return nil
}

func (s *Service) enqueueTest(ctx context.Context, tx pgx.Tx, a Actor, targetID uuid.UUID) (uuid.UUID, error) {
	return s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobTestConnection, TargetID: targetID, Payload: map[string]string{},
		Kind: a.jobKind(), CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: "target.test_connection:" + targetID.String()})
}
