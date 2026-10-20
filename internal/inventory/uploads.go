package inventory

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/text/unicode/norm"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/certs"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// Private keys held by Alice (spec §7.2, decisions "Secrets protection"). A key uploaded or generated
// for a signing request exists in plaintext only inside the call that seals it: as the caller's
// request strings, the byte copies made here (cleared before return) and certs.Validated's
// PrivateKeyDER (a secrets.Plaintext, zeroed before return). It is stored only as an envelope in
// managed_private_keys.ciphertext, bound to its row by the AAD managed_private_keys/<id>/ciphertext
// (the construction of credentials, platformkey.go). Nothing in this file returns, logs or audits
// key material or a PFX password; errors are fixed sentinels. loadKey is the only place that opens
// a stored key.

// UploadInput is a certificate an administrator brings into Alice: PEM certificate (with its chain)
// and private key, or a PFX file in standard base64 with its password.
type UploadInput struct {
	CertificatePEM string
	PrivateKeyPEM  string
	PFXBase64      string
	PFXPassword    string
	Label          string
	// ServiceID is the service a new certificate goes to (R49); uuid.Nil = the Default service. A certificate Alice
	// already knows keeps its service (design §4.4).
	ServiceID uuid.UUID
}

// maxLabelRunes is certificates.label's bound.
const maxLabelRunes = 100

// maxPFXDecodes bounds the PFX files decoded at once in this process. A shrouded key bag inside an
// encrypted PFX content keeps an iteration count that certs cannot check before decoding (Task 2
// ruling), so a hostile file can pin a core: at most this many cores, and further PFX uploads are
// refused at once with ErrPFXBusy instead of queueing.
const maxPFXDecodes = 2

var pfxSlots = make(chan struct{}, maxPFXDecodes)

// acquirePFXSlot takes a decode slot without waiting. release gives it back and may be called more
// than once.
func acquirePFXSlot() (release func(), ok bool) {
	select {
	case pfxSlots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-pfxSlots }) }, true
	default:
		return nil, false
	}
}

// Upload formats, as audited.
const (
	formatPEM = "pem"
	formatPFX = "pfx"
)

// SQLSTATEs of the certificates_key_check trigger (migration 00006).
const (
	sqlKeyNotTheCertificates = "Z1001"
	sqlKeyAlreadyAttached    = "Z1002"
)

// keyTriggerError maps the key trigger's refusals to their errors.
func keyTriggerError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case sqlKeyNotTheCertificates:
			return ErrKeyMismatch
		case sqlKeyAlreadyAttached:
			return ErrCertificateDuplicate
		}
	}
	return err
}

// refusal maps an error of certs.ValidateUpload or certs.ValidateSigned to the audited reason and
// the error the caller returns. Every certs sentinel has its reason; the error returned is the
// sentinel itself (or certs' fixed-text wrapping of it), except ErrNoKey, which is the field error
// of a missing key (D21). An error certs never returns is reported as an unreadable certificate
// rather than an internal error: the input is what failed.
func refusal(err error) (reason string, out error) {
	for _, m := range []struct {
		sentinel error
		reason   string
	}{
		{certs.ErrTooLarge, "too_large"},
		{certs.ErrKeyMismatch, "key_mismatch"},
		{certs.ErrExpired, "expired"},
		{certs.ErrKeyEncrypted, "key_encrypted"},
		{certs.ErrPFXPassword, "pfx_password"},
		{certs.ErrWeak, "weak"},
		{certs.ErrUnsupportedKey, "unsupported_key"},
		{certs.ErrCSRMismatch, "csr_mismatch"},
		{certs.ErrInvalid, "invalid"},
	} {
		if errors.Is(err, m.sentinel) {
			return m.reason, err
		}
	}
	if errors.Is(err, certs.ErrNoKey) {
		return "validation", validate.Errors{{Field: "private_key_pem", Code: validate.Required}}
	}
	return "invalid", ErrCertificateInvalid
}

// checkLabel normalises a certificate label: NFC, trimmed, at most 100 runes, no control, format
// or bidirectional control characters. "" is allowed.
func checkLabel(raw string) (string, *validate.FieldError) {
	if !utf8.ValidString(raw) {
		return "", &validate.FieldError{Field: "label", Code: validate.Pattern}
	}
	s := norm.NFC.String(strings.TrimSpace(raw))
	if utf8.RuneCountInString(s) > maxLabelRunes {
		return "", &validate.FieldError{Field: "label", Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(maxLabelRunes)}}
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) {
			return "", &validate.FieldError{Field: "label", Code: validate.Pattern}
		}
	}
	return s, nil
}

// rejected describes one refused upload for its audit row.
type rejected struct {
	format        string
	reason        string
	fingerprint   string    // when the certificate was read
	certificateID uuid.UUID // a duplicate's
	csrID         uuid.UUID // a signing request's completion
}

// auditRejection records a refused upload or completion (certificate.upload_rejected) in its own
// transaction: the refused one stored nothing or was rolled back. Like auditLicenseDenial it does
// not depend on the request's context. Details never carry input beyond the certificate's
// fingerprint (public).
func (s *Service) auditRejection(ctx context.Context, a Actor, r rejected) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	d := map[string]string{"reason": r.reason, "format": r.format}
	objectID := ""
	if r.fingerprint != "" {
		d["fingerprint"] = r.fingerprint
	}
	if r.certificateID != uuid.Nil {
		d["certificate_id"] = r.certificateID.String()
		objectID = r.certificateID.String()
	}
	if r.csrID != uuid.Nil {
		d["csr_id"] = r.csrID.String()
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "certificate.upload_rejected", ObjectType: "certificate",
			ObjectID: objectID, Result: audit.Failure, Details: d})
		return err
	})
	if err != nil {
		s.log.Error("could not audit a refused certificate upload", "error_type", fmt.Sprintf("%T", err))
	}
}

// UploadCertificate validates an uploaded certificate with its chain and private key (certs:
// everything is checked before anything is stored) and stores it with the key sealed. A
// certificate Alice knows without a key (found on a server) gets the key attached; one Alice holds
// with its key is refused with ErrCertificateDuplicate, except that an upload of the same
// certificate with a complete chain completes a stored chain that is incomplete (the key is not
// stored again; audited certificate.chain_completed, and the warnings say WarnChainCompleted).
// Every refusal of a read upload, and every PFX attempt whatever its outcome, is audited. It
// returns the certificate and the warnings (not_yet_valid, chain_incomplete,
// chain_certificate_expired, chain_completed), which never block.
func (s *Service) UploadCertificate(ctx context.Context, a Actor, in UploadInput) (Certificate, []string, error) {
	pfxText := strings.TrimSpace(in.PFXBase64)
	format := formatPEM
	if pfxText != "" {
		format = formatPFX
	}
	reject := func(reason string, err error) (Certificate, []string, error) {
		s.auditRejection(ctx, a, rejected{format: format, reason: reason})
		return Certificate{}, nil, err
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		reason := license.DenialReason(err) // locked, lock_due or unverified (AUD-02)
		if reason == "" {
			reason = "locked"
		}
		return reject(reason, err)
	}
	certText, keyText := strings.TrimSpace(in.CertificatePEM), strings.TrimSpace(in.PrivateKeyPEM)
	var errs validate.Errors
	label, fe := checkLabel(in.Label)
	if fe != nil {
		errs = append(errs, *fe)
	}
	switch {
	case pfxText == "" && certText == "" && keyText == "":
		errs.Add("certificate_pem", validate.Required, nil)
		errs.Add("private_key_pem", validate.Required, nil)
		errs.Add("pfx_base64", validate.Required, nil)
	case pfxText != "" && (certText != "" || keyText != ""):
		errs.Add("pfx_base64", validate.Pattern, nil) // either a PFX or PEM fields
	case pfxText == "":
		if certText == "" {
			errs.Add("certificate_pem", validate.Required, nil)
		}
		// The size bound comes first (a huge paste is refused unread), and the scan reads the
		// string itself: a byte copy of a field that may hold a key would never be cleared.
		if len(certText) <= certs.MaxInputSize && certs.ContainsPrivateKey(certText) {
			// The contract has no combined paste: the key belongs in its own field, and a key in
			// the certificate field is never used from there.
			errs.Add("certificate_pem", CodeKeyInCertificate, nil)
		}
		if keyText == "" {
			errs.Add("private_key_pem", validate.Required, nil) // D21: blanks only is no key
		}
	}
	if len(errs) > 0 {
		if format == formatPFX {
			s.auditRejection(ctx, a, rejected{format: format, reason: "validation"})
		}
		return Certificate{}, nil, errs
	}

	var up certs.Upload
	release := func() {}
	if format == formatPFX {
		raw, err := decodePFXText(pfxText)
		defer clear(raw)
		if err != nil {
			reason, out := refusal(err)
			return reject(reason, out)
		}
		var ok bool
		if release, ok = acquirePFXSlot(); !ok {
			return reject("busy", ErrPFXBusy)
		}
		defer release()
		up.PFX, up.PFXPassword = raw, in.PFXPassword
	} else {
		if len(certText) > certs.MaxInputSize || len(keyText) > certs.MaxInputSize {
			return reject("too_large", ErrCertificateTooLarge)
		}
		up.CertificatePEM, up.PrivateKeyPEM = []byte(certText), []byte(keyText)
		defer clear(up.CertificatePEM) // may hold a pasted key (refused above, but the bytes were copied)
		defer clear(up.PrivateKeyPEM)
	}
	v, err := s.validateUpload(up)
	release() // the slot covers the decode only
	if errors.Is(err, errDecoderPanic) {
		s.auditRejection(ctx, a, rejected{format: format, reason: "internal"})
		return Certificate{}, nil, err
	}
	if err != nil {
		reason, out := refusal(err)
		return reject(reason, out)
	}
	defer v.PrivateKeyDER.Zero()
	// What certs matched: the leaf's key is the uploaded key (no second parse of the key).
	info := certs.KeyInfo{Algorithm: v.Algorithm, Bits: v.Bits, PublicKeySHA256: v.PublicKeySHA256}

	var placed placement
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		service, err := authz.ResolveService(ctx, tx, in.ServiceID)
		if err != nil {
			return err
		}
		placed, err = s.placeCertificate(ctx, tx, v.Parsed, v.ChainComplete, true, label, "uploaded", a.UserID, service, func() (uuid.UUID, error) {
			return s.storeKey(ctx, tx, "certificate", v.PrivateKeyDER, info, a.UserID)
		})
		if err != nil {
			return err
		}
		if placed.chainCompleted {
			ev := audit.Event{Actor: a.Audit, ObjectType: "certificate", ObjectID: placed.id.String(), Result: audit.Success,
				Details: map[string]string{"certificate_id": placed.id.String(), "fingerprint": v.Fingerprint, "format": format,
					"chain_length": strconv.Itoa(1 + len(v.Chain)), "issuer": truncRunes(boundText(v.Issuer), maxAuditIssuer)}}
			if label != "" {
				ev.Details["label"] = label
			}
			ev.Action = "certificate.chain_completed"
			_, err = s.audit.Append(ctx, tx, ev)
			return err
		}
		ev := audit.Event{Actor: a.Audit, Action: "certificate.uploaded", ObjectType: "certificate", ObjectID: placed.id.String(),
			Result: audit.Success, Details: map[string]string{"certificate_id": placed.id.String(), "fingerprint": v.Fingerprint,
				"source": "uploaded", "format": format, "algorithm": info.Algorithm, "bits": strconv.Itoa(info.Bits),
				"warnings": strings.Join(heldWarnings(v.Warnings, placed.complete), ",")}}
		if placed.attached {
			ev.Action = "certificate.key_attached"
			delete(ev.Details, "source")
		}
		_, err = s.audit.Append(ctx, tx, ev)
		return err
	})
	if errors.Is(err, ErrCertificateDuplicate) || errors.Is(err, ErrKeyMismatch) {
		reason := "duplicate"
		if errors.Is(err, ErrKeyMismatch) {
			reason = "key_mismatch"
		}
		s.auditRejection(ctx, a, rejected{format: format, reason: reason, fingerprint: v.Fingerprint, certificateID: placed.existing})
		return Certificate{}, nil, err
	}
	if err != nil {
		// Not the upload's fault (the database failed), but the attempt is still on record.
		s.auditRejection(ctx, a, rejected{format: format, reason: "internal", fingerprint: v.Fingerprint})
		return Certificate{}, nil, err
	}
	// A failure to read the committed certificate back reports an error for a stored upload (a
	// retry gets ErrCertificateDuplicate); the audit row is already written.
	c, err := s.GetCertificate(ctx, placed.id)
	if err != nil {
		return Certificate{}, nil, err
	}
	if placed.chainCompleted {
		return c, append(heldWarnings(v.Warnings, true), WarnChainCompleted), nil
	}
	return c, heldWarnings(v.Warnings, placed.complete), nil
}

// maxAuditIssuer bounds the issuer text a chain_completed audit row keeps.
const maxAuditIssuer = 256

// WarnChainCompleted: the upload was a certificate Alice already holds with its key, and its
// complete chain replaced the incomplete one Alice had (nothing else changed; the key was not
// stored again).
const WarnChainCompleted = "chain_completed"

// heldWarnings are an upload's warnings for what Alice holds: chain_incomplete is left out when the
// stored chain is complete (an upload never downgrades it). Never nil. They are not stored with
// the certificate (no column); the audit row of the upload keeps them.
func heldWarnings(warnings []string, complete bool) []string {
	out := []string{}
	for _, w := range warnings {
		if w == "chain_incomplete" && complete {
			continue
		}
		out = append(out, w)
	}
	return out
}

// errDecoderPanic: decoding an upload panicked (a bug in a parser). The upload is refused as an
// internal error; no text of the panic, which may quote input, is kept.
var errDecoderPanic = errors.New("inventory: the uploaded file could not be decoded")

// validateUpload is certs.ValidateUpload (replaceable in tests).
var validateUpload = certs.ValidateUpload

// validateUpload runs the decoder and turns a panic into errDecoderPanic, logged without its value.
func (s *Service) validateUpload(up certs.Upload) (v certs.Validated, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("decoding an uploaded certificate failed", "panic_type", fmt.Sprintf("%T", r))
			v, err = certs.Validated{}, errDecoderPanic
		}
	}()
	return validateUpload(up, s.clock.Now(), s.roots)
}

// decodePFXText decodes a PFX given as standard base64. White space (line breaks of a wrapped
// text, blanks) is ignored; the bound is on the decoded file (certs.MaxInputSize), checked before
// decoding. The caller clears the result, also on error.
func decodePFXText(text string) ([]byte, error) {
	compact := make([]byte, 0, len(text))
	defer func() { clear(compact) }()
	for i := 0; i < len(text); i++ {
		switch c := text[i]; c {
		case ' ', '\t', '\r', '\n', '\f', '\v':
		default:
			compact = append(compact, c)
		}
	}
	if base64.StdEncoding.DecodedLen(len(compact)) > certs.MaxInputSize+2 { // DecodedLen counts the padding as data
		return nil, ErrCertificateTooLarge
	}
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(compact)))
	n, err := base64.StdEncoding.Decode(raw, compact)
	if err != nil {
		clear(raw)
		return nil, ErrCertificateInvalid
	}
	if n > certs.MaxInputSize {
		clear(raw)
		return nil, ErrCertificateTooLarge
	}
	return raw[:n], nil
}

// placement is where placeCertificate put a certificate.
type placement struct {
	id             uuid.UUID
	complete       bool      // the chain Alice now holds for it is complete
	attached       bool      // the key was attached to a certificate Alice knew without one
	chainCompleted bool      // a certificate held with its key got this upload's complete chain
	existing       uuid.UUID // the certificate that already had a key (ErrCertificateDuplicate)
}

// placeCertificate stores the certificate p with a key, in tx. key stores (or names) the key row;
// it is called at most once, and only when the key will be used. The certificate row is found by
// fingerprint and locked:
//   - absent: inserted with source, label, the key, created_by and the owning service (R49; ON CONFLICT DO NOTHING: a scan
//     may insert the same row concurrently; it is then read again and handled as present);
//   - present with a key: ErrCertificateDuplicate, nothing changes (a key is never replaced, and
//     the same certificate's key is the same key); except, when completeChain (an upload), a stored
//     chain that is incomplete is replaced by this one when it is complete (chainCompleted; the key
//     is not stored again: the same leaf has the same public key, so the uploaded key is the held
//     one) — AUD-17 of the independent audit of 2026-10-04;
//   - present without a key (found on a server): the key is attached and the row becomes this
//     upload's: its chain and completeness replace the stored ones whatever they were (a server's
//     file never decides what Alice deploys with a key a person gave, not even a "complete" chain a
//     server forged around a real intermediate's key), and its source becomes source (uploaded or
//     csr; the trigger allows exactly this change); from then on scans never touch the chain. The
//     label is set only when the row has none. Subject, SANs, validity, sightings and created_by are
//     never rewritten.
//
// Only this certificate row is locked, never a target (lock order: target, certificates, locations).
func (s *Service) placeCertificate(ctx context.Context, tx pgx.Tx, p certs.Parsed, complete, completeChain bool, label, source string,
	by, service uuid.UUID, key func() (uuid.UUID, error)) (placement, error) {
	pemChain := p.PEMChain
	if len(pemChain) > maxPEMChain {
		pemChain, complete = leafPEM(p), false
	}
	keyID := uuid.Nil
	useKey := func() (uuid.UUID, error) {
		if keyID == uuid.Nil {
			id, err := key()
			if err != nil {
				return uuid.Nil, err
			}
			keyID = id
		}
		return keyID, nil
	}
	existing, hasKey, stored, err := lockCertificate(ctx, tx, p.Fingerprint)
	if err != nil {
		return placement{}, err
	}
	if existing == uuid.Nil {
		kid, err := useKey()
		if err != nil {
			return placement{}, err
		}
		sans, _ := boundSANs(p.SANs)
		now := s.clock.Now().UTC()
		id := uuid.Must(uuid.NewV7())
		err = tx.QueryRow(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, subject, issuer, serial, sans, not_before, not_after,
    key_algorithm, key_bits, public_key_sha256, pem_chain, chain_complete, self_signed, source, label, private_key_id, first_seen_at, last_seen_at,
    created_by, created_at, service_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $19, $20, $19, $21)
ON CONFLICT (fingerprint_sha256) DO NOTHING
RETURNING id`, id, p.Fingerprint, boundText(p.SubjectCN), boundText(p.Subject), boundText(p.Issuer), boundText(p.Serial), sans,
			p.NotBefore.UTC(), p.NotAfter.UTC(), p.Algorithm, p.Bits, p.PublicKeySHA256, pemChain, complete, p.SelfSigned, source, label, kid,
			now, nullableUser(by), service).Scan(&id)
		switch {
		case err == nil:
			return placement{id: id, complete: complete}, nil
		case !errors.Is(err, pgx.ErrNoRows):
			return placement{}, fmt.Errorf("inventory: store certificate: %w", keyTriggerError(err))
		}
		// A scan inserted it meanwhile (committed: the insert waited for it).
		if existing, hasKey, stored, err = lockCertificate(ctx, tx, p.Fingerprint); err != nil {
			return placement{}, err
		}
		if existing == uuid.Nil {
			return placement{}, errors.New("inventory: the certificate vanished while it was stored")
		}
	}
	if hasKey {
		if completeChain && complete && !stored {
			// A label sent with the completing upload replaces the stored one (an empty one keeps it).
			if _, err := tx.Exec(ctx, `UPDATE certificates SET pem_chain = $2, chain_complete = true,
    label = CASE WHEN $3 <> '' THEN $3 ELSE label END WHERE id = $1`, existing, pemChain, label); err != nil {
				return placement{}, fmt.Errorf("inventory: complete the certificate's chain: %w", err)
			}
			return placement{id: existing, complete: true, chainCompleted: true}, nil
		}
		return placement{existing: existing}, ErrCertificateDuplicate
	}
	kid, err := useKey()
	if err != nil {
		return placement{}, err
	}
	var held bool
	err = tx.QueryRow(ctx, `UPDATE certificates SET private_key_id = $2, label = CASE WHEN label = '' THEN $3 ELSE label END,
    pem_chain = $4, chain_complete = $5, source = CASE WHEN source = 'discovered' THEN $6 ELSE source END
WHERE id = $1 RETURNING chain_complete`, existing, kid, label, pemChain, complete, source).Scan(&held)
	if err != nil {
		if mapped := keyTriggerError(err); errors.Is(mapped, ErrKeyMismatch) || errors.Is(mapped, ErrCertificateDuplicate) {
			return placement{existing: existing}, mapped
		}
		return placement{}, fmt.Errorf("inventory: attach the private key: %w", err)
	}
	return placement{id: existing, attached: true, complete: held}, nil
}

// lockCertificate finds the certificate of a fingerprint and locks it (uuid.Nil when absent), with
// whether it has a key and whether its stored chain is complete. FOR NO KEY UPDATE: the foreign-key
// checks of rows inserted meanwhile that reference the certificate (locations, deployments) take
// KEY SHARE and are not blocked; attaching the key changes the unique private_key_id and takes the
// stronger lock only at that UPDATE.
func lockCertificate(ctx context.Context, tx pgx.Tx, fingerprint string) (id uuid.UUID, hasKey, complete bool, err error) {
	err = tx.QueryRow(ctx, "SELECT id, private_key_id IS NOT NULL, chain_complete FROM certificates WHERE fingerprint_sha256 = $1 FOR NO KEY UPDATE",
		fingerprint).Scan(&id, &hasKey, &complete)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, false, nil
	}
	if err != nil {
		return uuid.Nil, false, false, fmt.Errorf("inventory: read certificate: %w", err)
	}
	return id, hasKey, complete, nil
}

func keyLocation(id uuid.UUID) secrets.Location {
	return secrets.Location{Table: "managed_private_keys", RowID: id.String(), Column: "ciphertext"}
}

// storeKey seals a PKCS#8 key and inserts it as a new managed_private_keys row (append-only for
// the application). der stays the caller's to zero.
func (s *Service) storeKey(ctx context.Context, tx pgx.Tx, ownerType string, der secrets.Plaintext, info certs.KeyInfo, by uuid.UUID) (uuid.UUID, error) {
	id := uuid.Must(uuid.NewV7())
	env, err := s.keyring.Seal(keyLocation(id), der.Bytes())
	if err != nil {
		return uuid.Nil, errors.New("inventory: the private key cannot be sealed")
	}
	_, err = tx.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek,
    key_version, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		id, ownerType, info.Algorithm, info.Bits, info.PublicKeySHA256, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion,
		nullableUser(by), s.clock.Now().UTC())
	if err != nil {
		return uuid.Nil, fmt.Errorf("inventory: store the private key: %w", err)
	}
	return id, nil
}

// loadKey opens a stored private key and returns it as PKCS#8 DER: the only place that unseals one
// (the deployment engine, Task 15, is its only caller). The caller zeroes the result as soon as
// it has used it. It never logs; its errors carry no key material.
func (s *Service) loadKey(ctx context.Context, q db.Querier, id uuid.UUID) (secrets.Plaintext, error) {
	var env secrets.Envelope
	err := q.QueryRow(ctx, "SELECT ciphertext, nonce, wrapped_dek, key_version FROM managed_private_keys WHERE id = $1", id).
		Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return secrets.Plaintext{}, ErrNotFound
	}
	if err != nil {
		return secrets.Plaintext{}, fmt.Errorf("inventory: read the private key: %w", err)
	}
	pt, err := s.keyring.Open(keyLocation(id), env)
	if err != nil {
		return secrets.Plaintext{}, errors.New("inventory: the private key cannot be decrypted with this master key")
	}
	return pt, nil
}
