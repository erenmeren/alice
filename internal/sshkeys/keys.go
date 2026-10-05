package sshkeys

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
	"golang.org/x/text/unicode/norm"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
	"alice/internal/sshkeys/keymat"
)

// maxLabelRunes is ssh_keys_label_length.
const maxLabelRunes = 100

// keyLocation is the AAD of a stored private key: the Phase 4 form inventory uses
// (managed_private_keys/<id>/ciphertext).
func keyLocation(id uuid.UUID) secrets.Location {
	return secrets.Location{Table: "managed_private_keys", RowID: id.String(), Column: "ciphertext"}
}

// validLabel checks a key's label (validName on field label).
func validLabel(raw string) (string, *validate.FieldError) { return validName("label", raw) }

// validName checks a display name as inventory does: 1-100 runes in NFC after trimming, no control
// or format characters (bidirectional overrides, zero-width characters: they could disguise a name
// in the UI and the audit log).
func validName(field, raw string) (string, *validate.FieldError) {
	if !utf8.ValidString(raw) {
		return "", &validate.FieldError{Field: field, Code: validate.Pattern}
	}
	s := norm.NFC.String(strings.TrimSpace(raw))
	switch {
	case s == "":
		return "", &validate.FieldError{Field: field, Code: validate.Required}
	case utf8.RuneCountInString(s) > maxLabelRunes:
		return "", &validate.FieldError{Field: field, Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(maxLabelRunes)}}
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) {
			return "", &validate.FieldError{Field: field, Code: validate.Pattern}
		}
	}
	return s, nil
}

func keyTypeValues() string {
	vs := make([]string, 0, 4)
	for _, t := range keymat.KeyTypes() {
		vs = append(vs, string(t))
	}
	return strings.Join(vs, ", ")
}

// checkGenerate validates a generation request and returns the stored label and the key type.
func checkGenerate(in GenerateInput) (string, keymat.KeyType, validate.Errors) {
	var errs validate.Errors
	label, fe := validLabel(in.Label)
	if fe != nil {
		errs = append(errs, *fe)
	}
	kt := keymat.KeyType(in.KeyType)
	if in.KeyType == "" {
		kt = keymat.Ed25519
	}
	if !kt.Valid() {
		errs.Add("key_type", validate.OneOf, map[string]string{"values": keyTypeValues()})
	}
	return label, kt, errs
}

// Generate creates a key, seals its private key and records it as a managed key (spec §13.5).
// The key is generated outside any transaction; its clear PKCS #8 is zeroed on every path before
// Generate returns. At most MaxGenerations keys are generated at once (ErrGenerateBusy).
func (s *Service) Generate(ctx context.Context, a inventory.Actor, in GenerateInput) (ManagedKey, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return ManagedKey{}, err
	}
	label, kt, errs := checkGenerate(in)
	if len(errs) > 0 {
		return ManagedKey{}, errs
	}
	m, err := s.generate(ctx, kt)
	if err != nil {
		return ManagedKey{}, err
	}
	defer m.PKCS8.Zero()
	return s.storeGenerated(ctx, a, m, label, nil)
}

// generate takes a generation slot and makes the key; the caller zeroes m.PKCS8.
func (s *Service) generate(ctx context.Context, kt keymat.KeyType) (keymat.Material, error) {
	release, ok := acquireGenSlot()
	if !ok {
		return keymat.Material{}, ErrGenerateBusy
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return keymat.Material{}, err
	}
	if !s.randSafe {
		s.randMu.Lock()
		defer s.randMu.Unlock()
	}
	m, err := keymat.Generate(s.rand, kt)
	if err != nil {
		return keymat.Material{}, fmt.Errorf("sshkeys: generate the key: %w", err)
	}
	hold(holdGenerated, m.PKCS8.Bytes())
	return m, nil
}

// storeGenerated seals m and inserts its private key, its ssh_keys row and the audit row in one
// transaction. rotatedFrom links a rotation's new key to the key it replaces (Task 9).
func (s *Service) storeGenerated(ctx context.Context, a inventory.Actor, m keymat.Material, label string, rotatedFrom *uuid.UUID) (ManagedKey, error) {
	var out ManagedKey
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = s.storeGeneratedTx(ctx, tx, a.Audit, a.UserID, m, label, rotatedFrom)
		return err
	})
	return out, err
}

// storeGeneratedTx is storeGenerated in the caller's transaction.
func (s *Service) storeGeneratedTx(ctx context.Context, tx pgx.Tx, actor audit.Actor, by uuid.UUID, m keymat.Material, label string,
	rotatedFrom *uuid.UUID) (ManagedKey, error) {
	now := s.clock.Now().UTC()
	pkID, keyID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	env, err := s.keyring.Seal(keyLocation(pkID), m.PKCS8.Bytes())
	if err != nil {
		return ManagedKey{}, errors.New("sshkeys: the private key cannot be sealed")
	}
	createdBy := nullableUser(by)
	_, err = tx.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek,
    key_version, created_by, created_at) VALUES ($1, 'ssh_key', $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		pkID, m.Algorithm, m.Bits, m.PublicKeySHA256, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, createdBy, now)
	if err != nil {
		return ManagedKey{}, fmt.Errorf("sshkeys: store the private key: %w", err)
	}
	comment := keymat.Comment(label, now)
	sshType, _, _ := strings.Cut(m.PublicKey, " ")
	_, err = tx.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, managed, label, first_seen_at, created_at,
    private_key_id, key_comment, rotated_from, created_by) VALUES ($1, $2, $3, $4, $5, true, $6, $7, $7, $8, $9, $10, $11)`,
		keyID, m.Fingerprint, sshType, m.Bits, m.PublicKey, label, now, pkID, comment, rotatedFrom, createdBy)
	if err != nil {
		return ManagedKey{}, fmt.Errorf("sshkeys: store the key: %w", err)
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "sshkey.generated", ObjectType: "ssh_key", ObjectID: keyID.String(),
		Result: audit.Success, Details: map[string]string{"ssh_key_id": keyID.String(), "fingerprint": m.Fingerprint,
			"algorithm": m.Algorithm, "bits": strconv.Itoa(m.Bits), "label": label}})
	if err != nil {
		return ManagedKey{}, err
	}
	return getManagedKey(ctx, tx, keyID)
}

func nullableUser(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// finishedStatuses are the rotation statuses of a finished run (C2's live-run index).
const finishedStatuses = `('completed', 'aborted', 'needs_attention', 'cancelled')`

const managedKeySelect = `SELECT k.id, k.private_key_id, k.fingerprint_sha256, k.public_key, coalesce(p.algorithm, ''), coalesce(p.bits, 0),
    k.label, k.key_comment, k.created_by, k.created_at, k.retired_at, p.destroyed_at, k.rotated_from, coalesce(p.download_count, 0),
    p.last_downloaded_at,
    (SELECT r.id FROM rotation_policies r WHERE r.ssh_key_id = k.id AND r.deleted_at IS NULL),
    (SELECT o.id FROM rotations o WHERE o.old_ssh_key_id = k.id AND o.status NOT IN ` + finishedStatuses + `)
FROM ssh_keys k LEFT JOIN managed_private_keys p ON p.id = k.private_key_id`

// getManagedKey reads one generated key: ErrNotFound, or ErrNotManaged for a key Alice holds no
// private key for (found on a server, Alice's own key).
func getManagedKey(ctx context.Context, q db.Querier, id uuid.UUID) (ManagedKey, error) {
	var (
		k         ManagedKey
		pkID, by  *uuid.UUID
		algorithm string
	)
	err := q.QueryRow(ctx, managedKeySelect+" WHERE k.id = $1", id).Scan(&k.ID, &pkID, &k.Fingerprint, &k.PublicKey, &algorithm,
		&k.Bits, &k.Label, &k.Comment, &by, &k.CreatedAt, &k.RetiredAt, &k.DestroyedAt, &k.RotatedFrom, &k.DownloadCount,
		&k.LastDownloadedAt, &k.PolicyID, &k.OpenRotationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ManagedKey{}, ErrNotFound
	}
	if err != nil {
		return ManagedKey{}, fmt.Errorf("sshkeys: read the key: %w", err)
	}
	if pkID == nil {
		return ManagedKey{}, ErrNotManaged
	}
	k.PrivateKeyID = *pkID
	if by != nil {
		k.CreatedBy = *by
	}
	k.KeyType = string(keymat.TypeOf(algorithm, k.Bits))
	k.CreatedAt = k.CreatedAt.UTC()
	k.RetiredAt, k.DestroyedAt, k.LastDownloadedAt = utcPtr(k.RetiredAt), utcPtr(k.DestroyedAt), utcPtr(k.LastDownloadedAt)
	return k, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// ManagedKey returns a generated key with its private key's facts, its live policy and its open
// rotation (as old key). ErrNotManaged for a key Alice did not generate; ErrNotFound.
func (s *Service) ManagedKey(ctx context.Context, id uuid.UUID) (ManagedKey, error) {
	return getManagedKey(ctx, s.pool, id)
}
