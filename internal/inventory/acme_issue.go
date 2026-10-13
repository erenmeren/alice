package inventory

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/acme/keygen"
	"alice/internal/audit"
	"alice/internal/certs"
	"alice/internal/platform/db"
	"alice/internal/secrets"
)

// The private key and the issued certificate of an ACME order (plan 2026-10-13 Task 8; amendments A3, A8, A10).
//
// The acme.issue job (Task 10) calls, for one acme_orders row it inserted with state running and kind issue:
//
//	signer, err := s.BeginACMEOrderKey(ctx, tx, orderID, policy) // in the transaction that inserts the order
//	csr, err := keygen.NewCSR(signer, names)
//	chain, err := client.Order(ctx, names, csr, solver, ...)    // outside any transaction
//	issued, err := s.FinishACMEOrder(ctx, orderID, chain)       // or, on any failure:
//	err = s.AbortACMEOrder(ctx, orderID, code)
//
// and, recovering an order a crash interrupted after the CA may have issued, LoadPendingKey(ctx, orderID) gives
// the same signer back (the order URL is in acme_orders.order_url).
//
// The key is generated at the start of the order and sealed at once into the deletable columns
// acme_orders.pending_key_* (AAD acme_orders/<id>/pending_key). FinishACMEOrder moves it, in ONE transaction, into a
// new managed_private_keys row (owner certificate, AAD managed_private_keys/<id>/ciphertext) that the new
// certificates row (source acme) references: certificates_check_key needs both in the same transaction with the
// same public key. The pending columns are NULL afterwards. AbortACMEOrder deletes the pending key. So a key is
// never orphaned, and never lost between the CA's issuance and the commit.
//
// Secret handling (A10): the PKCS#8 DER exists in plaintext only inside the function that seals or opens it and
// is zeroed before it returns (keygen.Key.Zero, secrets.Plaintext.Zero). The crypto.Signer that BeginACMEOrderKey
// and LoadPendingKey return is an *ecdsa.PrivateKey or *rsa.PrivateKey, which Go cannot zero: the caller keeps it
// only for the order function and drops it. Nothing here logs, audits or returns key material; errors are fixed
// sentinels.

// Errors of the ACME order record. None carries a value from the database or the CA.
var (
	// ErrACMEOrderNotRunning: the order is finished, or it is a test run (which has no key).
	ErrACMEOrderNotRunning = errors.New("inventory: the ACME order is not a running issue order")
	// ErrACMEPendingKey: the order has no pending key (FinishACMEOrder, LoadPendingKey) or already has one
	// (BeginACMEOrderKey).
	ErrACMEPendingKey = errors.New("inventory: the ACME order's pending key is missing or already present")
	// ErrACMEChainMismatch: the chain is empty, or its first certificate is not a certificate for the order's
	// key, or it does not hold every name of the order. Nothing is stored.
	ErrACMEChainMismatch = errors.New("inventory: the issued certificate is not the one the order asked for")
	// ErrACMEErrorCode: AbortACMEOrder's code is not a short code ([A-Za-z0-9._-]{1,100}).
	ErrACMEErrorCode = errors.New("inventory: the error code of an ACME order is not valid")
)

// errPendingKeySeal: the pending key cannot be sealed or opened (master key changed, row damaged).
var errPendingKeySeal = errors.New("inventory: the pending key of the ACME order cannot be sealed or opened")

// ACMEIssued is what FinishACMEOrder stored.
type ACMEIssued struct {
	CertificateID uuid.UUID
	Fingerprint   string
	ChainComplete bool // with the provider's CA bundle added to the trusted roots (A3)
	// Reused: the CA returned a certificate Alice already held with its key (an identical chain): that row is
	// the current certificate; no second key row was stored. Its chain was completed when it was incomplete and
	// this one is complete.
	Reused   bool
	Warnings []string // not_yet_valid, chain_incomplete, chain_certificate_expired; never nil
}

// pendingKeyLocation binds a sealed pending key to its order row.
func pendingKeyLocation(orderID uuid.UUID) secrets.Location {
	return secrets.Location{Table: "acme_orders", RowID: orderID.String(), Column: "pending_key"}
}

// sealPendingKey seals key's DER for the order and zeroes the DER (also on error).
func sealPendingKey(k *secrets.Keyring, orderID uuid.UUID, key *keygen.Key) (secrets.Envelope, error) {
	defer key.Zero()
	env, err := k.Seal(pendingKeyLocation(orderID), key.DER.Bytes())
	if err != nil {
		return secrets.Envelope{}, errPendingKeySeal
	}
	return env, nil
}

// openPendingKey opens the order's sealed key and hands it to use; the DER is zeroed when use returns (the
// Signer outlives it, A10).
func openPendingKey(k *secrets.Keyring, orderID uuid.UUID, env secrets.Envelope, use func(*keygen.Key) error) error {
	der, err := k.Open(pendingKeyLocation(orderID), env)
	if err != nil {
		return errPendingKeySeal
	}
	defer der.Zero()
	key, err := keygen.ParsePKCS8(der)
	if err != nil {
		return errPendingKeySeal
	}
	return use(key)
}

// orderKeyState explains why an UPDATE of the order's pending key matched nothing.
func orderKeyState(ctx context.Context, q db.Querier, orderID uuid.UUID) error {
	var state, kind string
	var hasKey bool
	err := q.QueryRow(ctx, "SELECT state, kind, pending_key_ct IS NOT NULL FROM acme_orders WHERE id = $1", orderID).Scan(&state, &kind, &hasKey)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("inventory: read the ACME order: %w", err)
	case state != "running" || kind != "issue":
		return ErrACMEOrderNotRunning
	case hasKey:
		return ErrACMEPendingKey
	}
	return errors.New("inventory: the ACME order changed while its key was stored")
}

// BeginACMEOrderKey generates the private key of a running issue order with the policy (the ACME certificate's
// key_type; keygen.ErrKeyPolicy for another value) and seals it into the order's pending_key_* columns, in tx
// (the transaction that inserted the order, so an order never runs without its key). It returns the key's
// signer for the CSR (keygen.NewCSR) and nothing else; the DER is zeroed before it returns. ErrNotFound,
// ErrACMEOrderNotRunning, ErrACMEPendingKey (the order has a key already: use LoadPendingKey).
func (s *Service) BeginACMEOrderKey(ctx context.Context, tx pgx.Tx, orderID uuid.UUID, policy keygen.KeyPolicy) (crypto.Signer, error) {
	key, err := keygen.Generate(policy)
	if err != nil {
		return nil, err
	}
	env, err := sealPendingKey(s.keyring, orderID, key)
	if err != nil {
		return nil, err
	}
	tag, err := tx.Exec(ctx, `UPDATE acme_orders SET pending_key_ct = $2, pending_key_nonce = $3, pending_key_wrapped_dek = $4,
    pending_key_version = $5
WHERE id = $1 AND state = 'running' AND kind = 'issue' AND pending_key_ct IS NULL`, orderID, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion)
	if err != nil {
		return nil, fmt.Errorf("inventory: store the pending key of the ACME order: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return nil, orderKeyState(ctx, tx, orderID)
	}
	return key.Signer, nil
}

// LoadPendingKey opens the pending key of a running issue order (crash recovery: the order was begun, the
// process stopped before FinishACMEOrder or AbortACMEOrder). ErrNotFound, ErrACMEOrderNotRunning,
// ErrACMEPendingKey (no key: the order cannot be finished, abort it).
func (s *Service) LoadPendingKey(ctx context.Context, orderID uuid.UUID) (crypto.Signer, error) {
	var state, kind string
	var env secrets.Envelope
	var version *int
	err := s.pool.QueryRow(ctx, `SELECT state, kind, pending_key_ct, pending_key_nonce, pending_key_wrapped_dek, pending_key_version
FROM acme_orders WHERE id = $1`, orderID).Scan(&state, &kind, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &version)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("inventory: read the ACME order: %w", err)
	case state != "running" || kind != "issue":
		return nil, ErrACMEOrderNotRunning
	case version == nil:
		return nil, ErrACMEPendingKey
	}
	env.KeyVersion = *version
	var signer crypto.Signer
	err = openPendingKey(s.keyring, orderID, env, func(k *keygen.Key) error {
		signer = k.Signer
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// rootsWith is the trusted roots with the PEM certificates of bundle added (A3: a provider's own CA bundle makes
// its chains complete; the service's roots are not changed). Blocks that do not parse are ignored (the bundle
// was checked when the provider was saved).
func (s *Service) rootsWith(bundle string) *x509.CertPool {
	if strings.TrimSpace(bundle) == "" {
		return s.roots
	}
	pool := s.roots.Clone()
	pool.AppendCertsFromPEM([]byte(bundle))
	return pool
}

// chainPEM encodes a DER chain as CERTIFICATE blocks; ErrCertificateTooLarge beyond what an upload may be.
func chainPEM(chainDER [][]byte) ([]byte, error) {
	var buf bytes.Buffer
	for _, der := range chainDER {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}) // a bytes.Buffer never fails
		if buf.Len() > certs.MaxInputSize {
			return nil, ErrCertificateTooLarge
		}
	}
	return buf.Bytes(), nil
}

// coversNames reports whether the leaf's DNS names hold every ordered name (ASCII, case-insensitive; a wildcard
// name as the same wildcard SAN).
func coversNames(dnsNames, names []string) bool {
	for _, n := range names {
		found := false
		for _, d := range dnsNames {
			if strings.EqualFold(d, n) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// maxAuditNames bounds the names an order's audit row lists.
const maxAuditNames = 1024

// acmeOrderRow is what FinishACMEOrder reads of an order, its ACME certificate and provider.
type acmeOrderRow struct {
	state, kind     string
	certificateID   uuid.UUID // acme_certificates.id
	requestedBy     *uuid.UUID
	env             secrets.Envelope
	version         *int
	names           []string
	keyType, bundle string
}

// FinishACMEOrder stores the chain the CA issued for a running issue order (leaf first, DER, as acme.Client.Order
// returns it), in ONE transaction: the pending key is opened and must be the leaf's key (ErrACMEChainMismatch,
// also when the leaf lacks an ordered name; nothing is stored); the chain is ordered and checked by the upload
// rules (certs.ValidateSigned; a certs refusal is returned as its sentinel) and chain_complete is computed with
// the provider's ca_bundle_pem added to the roots (A3); the key is sealed into a new managed_private_keys row and
// the certificates row is inserted with source acme (placeCertificate, as uploads; a certificate Alice already
// holds with its key is reused, ACMEIssued.Reused); the ACME certificate gets it as current certificate (state
// active, failures 0, no error, next_attempt_at NULL for the planner to set); the order is succeeded with the
// certificate and its pending key NULL; audit acme.order.succeeded (ids, names, fingerprint, algorithm; never
// a key). ErrNotFound, ErrACMEOrderNotRunning, ErrACMEPendingKey, ErrCertificateTooLarge.
func (s *Service) FinishACMEOrder(ctx context.Context, orderID uuid.UUID, chainDER [][]byte) (ACMEIssued, error) {
	if len(chainDER) == 0 || len(chainDER[0]) == 0 {
		return ACMEIssued{}, ErrACMEChainMismatch
	}
	chain, err := chainPEM(chainDER)
	if err != nil {
		return ACMEIssued{}, err
	}
	var out ACMEIssued
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var o acmeOrderRow
		err := tx.QueryRow(ctx, `SELECT o.state, o.kind, o.acme_certificate_id, o.requested_by, o.pending_key_ct, o.pending_key_nonce,
    o.pending_key_wrapped_dek, o.pending_key_version, c.names, c.key_type, p.ca_bundle_pem
FROM acme_orders o JOIN acme_certificates c ON c.id = o.acme_certificate_id JOIN acme_providers p ON p.id = c.provider_id
WHERE o.id = $1 FOR UPDATE OF o, c`, orderID).Scan(&o.state, &o.kind, &o.certificateID, &o.requestedBy, &o.env.Ciphertext, &o.env.Nonce,
			&o.env.WrappedDEK, &o.version, &o.names, &o.keyType, &o.bundle)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return fmt.Errorf("inventory: read the ACME order: %w", err)
		case o.state != "running" || o.kind != "issue":
			return ErrACMEOrderNotRunning
		case o.version == nil:
			return ErrACMEPendingKey
		}
		o.env.KeyVersion = *o.version
		return openPendingKey(s.keyring, orderID, o.env, func(key *keygen.Key) error {
			var err error
			out, err = s.recordIssued(ctx, tx, orderID, o, key, chain, chainDER[0])
			return err
		})
	})
	if err != nil {
		return ACMEIssued{}, err
	}
	return out, nil
}

// recordIssued is FinishACMEOrder's work inside its transaction, with the opened key.
func (s *Service) recordIssued(ctx context.Context, tx pgx.Tx, orderID uuid.UUID, o acmeOrderRow, key *keygen.Key, chain, leafDER []byte) (ACMEIssued, error) {
	info, err := certs.KeyInfoOf(key.DER)
	if err != nil {
		return ACMEIssued{}, errPendingKeySeal
	}
	now := s.clock.Now()
	p, complete, err := certs.ValidateSigned(chain, info, now, s.rootsWith(o.bundle))
	if errors.Is(err, certs.ErrCSRMismatch) {
		return ACMEIssued{}, ErrACMEChainMismatch
	}
	if err != nil {
		_, out := refusal(err)
		return ACMEIssued{}, out
	}
	if !bytes.Equal(p.Leaf.Raw, leafDER) || !coversNames(p.Leaf.DNSNames, o.names) {
		return ACMEIssued{}, ErrACMEChainMismatch
	}
	by := uuid.Nil
	if o.requestedBy != nil {
		by = *o.requestedBy
	}
	placed, err := s.placeCertificate(ctx, tx, p, complete, true, "", "acme", by, func() (uuid.UUID, error) {
		return s.storeKey(ctx, tx, "certificate", key.DER, info, by)
	})
	out := ACMEIssued{CertificateID: placed.id, Fingerprint: p.Fingerprint, ChainComplete: placed.complete}
	switch {
	case errors.Is(err, ErrCertificateDuplicate) && placed.existing != uuid.Nil:
		// The same leaf with its key: the same key (certificates_check_key), stored once.
		out.CertificateID, out.Reused = placed.existing, true
		if err := tx.QueryRow(ctx, "SELECT chain_complete FROM certificates WHERE id = $1", placed.existing).Scan(&out.ChainComplete); err != nil {
			return ACMEIssued{}, fmt.Errorf("inventory: read the held certificate: %w", err)
		}
	case err != nil:
		return ACMEIssued{}, err
	case placed.chainCompleted:
		out.Reused = true
	}
	out.Warnings = signedWarnings(p, out.ChainComplete, o.names, now)
	at := now.UTC()
	if _, err := tx.Exec(ctx, `UPDATE acme_certificates SET current_certificate_id = $2, state = 'active', failures = 0, last_error_code = '',
    last_attempt_at = $3, next_attempt_at = NULL, updated_at = $3 WHERE id = $1`, o.certificateID, out.CertificateID, at); err != nil {
		return ACMEIssued{}, fmt.Errorf("inventory: record the ACME certificate's issuance: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE acme_orders SET state = 'succeeded', finished_at = $2, certificate_id = $3, pending_key_ct = NULL,
    pending_key_nonce = NULL, pending_key_wrapped_dek = NULL, pending_key_version = NULL WHERE id = $1`, orderID, at, out.CertificateID); err != nil {
		return ACMEIssued{}, fmt.Errorf("inventory: finish the ACME order: %w", err)
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "acme.order.succeeded", ObjectType: "acme_certificate",
		ObjectID: o.certificateID.String(), Result: audit.Success, Details: map[string]string{
			"order_id": orderID.String(), "acme_certificate_id": o.certificateID.String(), "certificate_id": out.CertificateID.String(),
			"fingerprint": p.Fingerprint, "names": truncRunes(strings.Join(o.names, ","), maxAuditNames),
			"names_count": strconv.Itoa(len(o.names)), "algorithm": info.Algorithm, "bits": strconv.Itoa(info.Bits),
			"chain_complete": strconv.FormatBool(out.ChainComplete), "reused": strconv.FormatBool(out.Reused),
			"warnings": strings.Join(out.Warnings, ","),
		}})
	if err != nil {
		return ACMEIssued{}, err
	}
	return out, nil
}

// AbortACMEOrder ends a running order as failed with errorCode (a closed-set reason such as an ALC-ACM reason;
// never CA text: ErrACMEErrorCode otherwise) and deletes its pending key (the four columns NULL), in one
// transaction with the audit row acme.order.failed (acme.order.test_failed for a test run; details: ids, kind
// and the code only). Aborting a failed order again only makes sure its key is gone (no second audit row); a
// succeeded order is ErrACMEOrderNotRunning; ErrNotFound. The ACME certificate's failure count and next attempt
// are the caller's (Task 10).
func (s *Service) AbortACMEOrder(ctx context.Context, orderID uuid.UUID, errorCode string) error {
	if !errorCodeRE.MatchString(errorCode) { // acme_orders.error_code's CHECK, without the empty code
		return ErrACMEErrorCode
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var state, kind string
		var acmeCertificateID uuid.UUID
		err := tx.QueryRow(ctx, "SELECT state, kind, acme_certificate_id FROM acme_orders WHERE id = $1 FOR UPDATE", orderID).
			Scan(&state, &kind, &acmeCertificateID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return fmt.Errorf("inventory: read the ACME order: %w", err)
		case state == "succeeded":
			return ErrACMEOrderNotRunning
		case state == "failed":
			// The freeze trigger (Z1017) allows exactly this change of a finished order.
			_, err := tx.Exec(ctx, `UPDATE acme_orders SET pending_key_ct = NULL, pending_key_nonce = NULL, pending_key_wrapped_dek = NULL,
    pending_key_version = NULL WHERE id = $1 AND pending_key_ct IS NOT NULL`, orderID)
			if err != nil {
				return fmt.Errorf("inventory: delete the pending key of the ACME order: %w", err)
			}
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE acme_orders SET state = 'failed', finished_at = $2, error_code = $3, pending_key_ct = NULL,
    pending_key_nonce = NULL, pending_key_wrapped_dek = NULL, pending_key_version = NULL WHERE id = $1`, orderID, s.clock.Now().UTC(), errorCode); err != nil {
			return fmt.Errorf("inventory: fail the ACME order: %w", err)
		}
		// Literal actions: the web's label test reads them from this source (labels in web/src/locales).
		action := "acme.order.failed"
		if kind == "test" {
			action = "acme.order.test_failed"
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: action, ObjectType: "acme_certificate",
			ObjectID: acmeCertificateID.String(), Result: audit.Failure, Details: map[string]string{
				"order_id": orderID.String(), "acme_certificate_id": acmeCertificateID.String(), "kind": kind, "error_code": errorCode,
			}})
		return err
	})
}
