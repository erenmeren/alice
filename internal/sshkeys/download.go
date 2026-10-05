package sshkeys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
	"alice/internal/sshkeys/keymat"
)

// DownloadPrivateKey hands out a generated key's private key as an OpenSSH file (spec §13.5, S-09,
// SEC-045; R41 rows 4-5). Order: validation, refusals (audited), the file built outside any
// transaction (the clear PKCS #8 is zeroed before the transaction starts), then the counter and
// the audit row committed together; only then is the file returned. A failed commit zeroes the
// file: no file leaves without its committed audit row. The passphrase is cleared before return on
// every path; it is never stored, logged or audited (only whether one was given). The route
// enforces Administrator, browser session, step-up and the rate limit; the download is allowed in
// lock (row 5).
func (s *Service) DownloadPrivateKey(ctx context.Context, a inventory.Actor, in DownloadInput) (Download, error) {
	defer clear(in.Passphrase)
	protected := in.Passphrase != nil
	errs := inventory.ValidateReason(in.Reason)
	switch {
	case protected && len(in.Passphrase) < keymat.MinPassphrase:
		errs.Add("passphrase", validate.TooShort, map[string]string{"min": strconv.Itoa(keymat.MinPassphrase)})
	case len(in.Passphrase) > keymat.MaxPassphrase:
		errs.Add("passphrase", validate.TooLong, map[string]string{"max": strconv.Itoa(keymat.MaxPassphrase)})
	}
	if len(errs) > 0 {
		return Download{}, errs
	}
	row, err := readKeyRow(ctx, s.pool, in.KeyID)
	if err != nil {
		return Download{}, err
	}
	deny := func(reason string, err error) (Download, error) {
		s.auditDetached(ctx, audit.Event{Actor: a.Audit, Action: "sshkey.private_key_download.denied", ObjectType: "ssh_key",
			ObjectID: in.KeyID.String(), Result: audit.Denied, Details: map[string]string{"ssh_key_id": in.KeyID.String(), "reason": reason}})
		return Download{}, err
	}
	protectedFPs, err := s.ProtectedFingerprints(ctx)
	if err != nil {
		return Download{}, err
	}
	switch {
	case row.isPlatform || slices.Contains(protectedFPs, row.fingerprint):
		return deny(DenyOwnKey, ErrNotManaged)
	case row.privateKeyID == uuid.Nil:
		return deny(DenyNotManaged, ErrNotManaged)
	case row.destroyed:
		return deny(DenyDestroyed, ErrDestroyed)
	}
	file, err := s.buildFile(ctx, row, in.Passphrase)
	if errors.Is(err, ErrDestroyed) {
		return deny(DenyDestroyed, ErrDestroyed)
	}
	if err != nil {
		return Download{}, err
	}
	hold(holdTx, nil)
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(ctx, `UPDATE managed_private_keys SET download_count = download_count + 1, last_downloaded_at = $2
WHERE id = $1 AND destroyed_at IS NULL RETURNING download_count`, row.privateKeyID, s.clock.Now().UTC()).Scan(&n)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDestroyed // destroyed between the read and now
		}
		if err != nil {
			return fmt.Errorf("sshkeys: count the download: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "sshkey.private_key_downloaded", ObjectType: "ssh_key",
			ObjectID: in.KeyID.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": in.KeyID.String(),
				"fingerprint": row.fingerprint, "reason": in.Reason, "protected": strconv.FormatBool(protected),
				"download_count": strconv.Itoa(n)}})
		return err
	})
	if err != nil {
		file.Zero()
		return Download{}, err
	}
	return Download{FileName: fileName(row.label, row.fingerprint), Body: file}, nil
}

// buildFile opens the key's envelope and returns its OpenSSH file (comment: the key's comment).
// The opened PKCS #8 is zeroed before it returns.
func (s *Service) buildFile(ctx context.Context, row keyRow, passphrase []byte) (secrets.Plaintext, error) {
	pt, err := s.openKey(ctx, s.pool, row.privateKeyID)
	if err != nil {
		return secrets.Plaintext{}, err
	}
	defer pt.Zero()
	file, err := keymat.OpenSSHFile(pt, row.comment, passphrase)
	if err != nil {
		return secrets.Plaintext{}, err
	}
	hold(holdFile, file.Bytes())
	return file, nil
}

// fileName is "alice-<slug>-<first 8 hex of SHA-256(fingerprint)>.key" with the slug of
// keymat.Comment (only [a-z0-9._-]), so the header needs no quoting rules.
func fileName(label, fingerprint string) string {
	slug := strings.TrimSuffix(strings.TrimPrefix(keymat.Comment(label, time.Time{}), "alice:"), ":0001-01-01")
	sum := sha256.Sum256([]byte(fingerprint))
	return "alice-" + slug + "-" + hex.EncodeToString(sum[:4]) + ".key"
}
