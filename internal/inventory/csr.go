package inventory

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/certs"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// Signing requests (spec §7.3 csr_requests). Alice generates the key (crypto/rand unless
// Config.Rand says otherwise), seals it at once (managed_private_keys, owner csr) and hands out
// the request; the signed certificate completes it and gets that key. A cancelled or never
// completed request keeps its sealed key row (the table is append-only for the application); such
// a key belongs to no certificate, so nothing ever opens it (loadKey is reached only through a
// certificate's private_key_id).

// CSRInput is the input of CreateCSR.
type CSRInput struct {
	CommonName string
	SANs       []string
	KeyType    string // "ecdsa-p256" | "rsa-3072" | "rsa-4096"
}

// CSR is a signing request. It never carries its key.
type CSR struct {
	ID            uuid.UUID
	CommonName    string
	SANs          []string // the request's DNS names: the common name first, then the others once each
	KeyAlgorithm  string
	KeyBits       int
	CSRPEM        string
	Status        string // pending | completed | cancelled
	CertificateID *uuid.UUID
	CreatedAt     time.Time
	FinishedAt    *time.Time
}

// Signing request statuses (csr_requests.status).
const (
	CSRPending   = "pending"
	CSRCompleted = "completed"
	CSRCancelled = "cancelled"
)

const (
	// maxCSRCommonName is csr_requests.common_name's bound (D20; the X.509 ub-common-name).
	maxCSRCommonName = 64
	maxCSRSANs       = 50
	// ListCSRs bounds: every pending request up to maxListedPendingCSRs, then the newest finished.
	maxListedPendingCSRs = 1000
	listedFinishedCSRs   = 50
)

// WarnCSRNameMismatch: the signed certificate does not cover every name of its request (a CA may
// change the names; the completion is accepted and says so).
const WarnCSRNameMismatch = "csr_name_mismatch"

var csrKeyTypes = []string{"ecdsa-p256", "rsa-3072", "rsa-4096"}

// validRequestName is a DNS name a signing request may carry: certs.ValidDNSName (lower-case
// labels, an optional leading "*." over at least two labels) that is not an IP address literal.
func validRequestName(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	return certs.ValidDNSName(s)
}

func checkCSRInput(in CSRInput) (string, []string, validate.Errors) {
	var errs validate.Errors
	cn := foldASCII(strings.TrimSpace(in.CommonName))
	switch {
	case cn == "":
		errs.Add("common_name", validate.Required, nil)
	case len(cn) > maxCSRCommonName:
		errs.Add("common_name", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(maxCSRCommonName)})
	case !validRequestName(cn):
		errs.Add("common_name", validate.Pattern, nil)
	}
	var sans []string
	if len(in.SANs) > maxCSRSANs {
		errs.Add("sans", validate.OutOfRange, map[string]string{"min": "0", "max": strconv.Itoa(maxCSRSANs)})
	} else {
		for _, raw := range in.SANs {
			n := foldASCII(strings.TrimSpace(raw))
			if !validRequestName(n) {
				errs.Add("sans", validate.Pattern, nil)
				break
			}
			sans = append(sans, n)
		}
	}
	if !slices.Contains(csrKeyTypes, in.KeyType) {
		errs.Add("key_type", validate.OneOf, map[string]string{"values": strings.Join(csrKeyTypes, ", ")})
	}
	return cn, sans, errs
}

// requestNames are the DNS names certs.NewCSR puts in a request: the common name, then the others
// once each.
func requestNames(cn string, sans []string) []string {
	out := []string{cn}
	for _, s := range sans {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// CreateCSR generates a key and a signing request for it. The key is sealed in the transaction
// that stores the request and zeroed before return; only the request (public) is returned.
func (s *Service) CreateCSR(ctx context.Context, a Actor, in CSRInput) (CSR, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return CSR{}, err
	}
	cn, sans, errs := checkCSRInput(in)
	if len(errs) > 0 {
		return CSR{}, errs
	}
	csrPEM, key, info, err := func() (string, secrets.Plaintext, certs.KeyInfo, error) {
		s.randMu.Lock()
		defer s.randMu.Unlock()
		return certs.NewCSR(s.rand, certs.CSRRequest{CommonName: cn, SANs: sans, KeyType: in.KeyType})
	}()
	defer key.Zero()
	if err != nil {
		return CSR{}, fmt.Errorf("inventory: create the signing request: %w", err)
	}
	id := uuid.Must(uuid.NewV7())
	var out CSR
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		keyID, err := s.storeKey(ctx, tx, "csr", key, info, a.UserID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO csr_requests (id, private_key_id, common_name, sans, csr_pem, status, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, keyID, cn, requestNames(cn, sans), csrPEM, CSRPending, nullableUser(a.UserID), s.clock.Now().UTC())
		if err != nil {
			return fmt.Errorf("inventory: store the signing request: %w", err)
		}
		if out, err = getCSR(ctx, tx, id, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "csr.created", ObjectType: "csr", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"csr_id": id.String(), "common_name": cn, "algorithm": info.Algorithm,
				"bits": strconv.Itoa(info.Bits)}})
		return err
	})
	if err != nil {
		return CSR{}, err
	}
	return out, nil
}

const csrSelect = `SELECT r.id, r.common_name, r.sans, k.algorithm, k.bits, r.csr_pem, r.status, r.certificate_id, r.created_at, r.finished_at
FROM csr_requests r JOIN managed_private_keys k ON k.id = r.private_key_id`

func scanCSR(row pgx.Row) (CSR, error) {
	var c CSR
	err := row.Scan(&c.ID, &c.CommonName, &c.SANs, &c.KeyAlgorithm, &c.KeyBits, &c.CSRPEM, &c.Status, &c.CertificateID, &c.CreatedAt, &c.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return CSR{}, ErrNotFound
	}
	if err != nil {
		return CSR{}, fmt.Errorf("inventory: read signing request: %w", err)
	}
	c.CreatedAt, c.FinishedAt = c.CreatedAt.UTC(), utcPtr(c.FinishedAt)
	if c.SANs == nil {
		c.SANs = []string{}
	}
	return c, nil
}

// getCSR reads one request; forUpdate locks its row (csr_requests only: FOR UPDATE is denied on
// managed_private_keys).
func getCSR(ctx context.Context, q db.Querier, id uuid.UUID, forUpdate bool) (CSR, error) {
	sql := csrSelect + " WHERE r.id = $1"
	if forUpdate {
		sql += " FOR UPDATE OF r"
	}
	return scanCSR(q.QueryRow(ctx, sql, id))
}

// GetCSR returns one signing request.
func (s *Service) GetCSR(ctx context.Context, id uuid.UUID) (CSR, error) {
	return getCSR(ctx, s.pool, id, false)
}

// ListCSRs returns the pending requests, newest first (at most maxListedPendingCSRs), then the 50
// most recently finished.
func (s *Service) ListCSRs(ctx context.Context) ([]CSR, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.id, r.common_name, r.sans, k.algorithm, k.bits, r.csr_pem, r.status, r.certificate_id, r.created_at,
    r.finished_at
FROM ((SELECT 0 AS grp, created_at AS at, id FROM csr_requests WHERE status = 'pending' ORDER BY created_at DESC, id DESC LIMIT $1)
      UNION ALL
      (SELECT 1, finished_at, id FROM csr_requests WHERE status <> 'pending' ORDER BY finished_at DESC, id DESC LIMIT $2)) sel
JOIN csr_requests r ON r.id = sel.id
JOIN managed_private_keys k ON k.id = r.private_key_id
ORDER BY sel.grp, sel.at DESC, sel.id DESC`, maxListedPendingCSRs, listedFinishedCSRs)
	if err != nil {
		return nil, fmt.Errorf("inventory: list signing requests: %w", err)
	}
	defer rows.Close()
	out := []CSR{}
	for rows.Next() {
		c, err := scanCSR(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// signedWarnings are an upload's warnings for a signed certificate (certs.ValidateSigned reports
// only whether the chain is complete), plus WarnCSRNameMismatch when the certificate's SANs do
// not cover every requested name (the inventory's server-name rule, nameCovered).
func signedWarnings(pemText []byte, p certs.Parsed, complete bool, requested []string, now time.Time) []string {
	out := []string{}
	if now.Before(p.NotBefore) {
		out = append(out, "not_yet_valid")
	}
	if !complete {
		out = append(out, "chain_incomplete")
	}
	if all, err := certs.ParseChainPEM(pemText); err == nil {
		for _, c := range append([]*x509.Certificate{all.Leaf}, all.Chain...) {
			if !bytes.Equal(c.Raw, p.Leaf.Raw) && !now.Before(c.NotAfter) {
				out = append(out, "chain_certificate_expired")
				break
			}
		}
	}
	for _, n := range requested {
		if !nameCovered(p.SANs, n) {
			out = append(out, WarnCSRNameMismatch)
			break
		}
	}
	return out
}

// CompleteCSR stores the certificate a CA signed for a pending request, with the request's key:
// it must carry that key (ErrCSRMismatch) and pass the upload rules (certs.ValidateSigned). The
// certificate is inserted (source csr) or, when Alice knows it without a key, gets the key
// attached; the request is completed in the same transaction. Refusals of the certificate are
// audited (certificate.upload_rejected with the request's id).
func (s *Service) CompleteCSR(ctx context.Context, a Actor, id uuid.UUID, certificatePEM, label string) (Certificate, []string, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Certificate{}, nil, err
	}
	var errs validate.Errors
	label, fe := checkLabel(label)
	if fe != nil {
		errs = append(errs, *fe)
	}
	text := strings.TrimSpace(certificatePEM)
	if text == "" {
		errs.Add("certificate_pem", validate.Required, nil)
	}
	if len(errs) > 0 {
		return Certificate{}, nil, errs
	}
	req, err := s.GetCSR(ctx, id)
	if err != nil {
		return Certificate{}, nil, err
	}
	if req.Status != CSRPending {
		return Certificate{}, nil, ErrCSRNotPending
	}
	reject := func(r rejected, err error) (Certificate, []string, error) {
		r.format, r.csrID = formatPEM, id
		s.auditRejection(ctx, a, r)
		return Certificate{}, nil, err
	}
	if len(text) > certs.MaxInputSize {
		return reject(rejected{reason: "too_large"}, ErrCertificateTooLarge)
	}
	var keyID uuid.UUID
	var info certs.KeyInfo
	err = s.pool.QueryRow(ctx, `SELECT k.id, k.algorithm, k.bits, k.public_key_sha256 FROM csr_requests r
JOIN managed_private_keys k ON k.id = r.private_key_id WHERE r.id = $1`, id).Scan(&keyID, &info.Algorithm, &info.Bits, &info.PublicKeySHA256)
	if err != nil {
		return Certificate{}, nil, fmt.Errorf("inventory: read the signing request's key: %w", err)
	}
	now := s.clock.Now()
	p, complete, err := certs.ValidateSigned([]byte(text), info, now, s.roots)
	if err != nil {
		reason, out := refusal(err)
		return reject(rejected{reason: reason}, out)
	}
	warnings := signedWarnings([]byte(text), p, complete, req.SANs, now)

	var placed placement
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getCSR(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Status != CSRPending {
			return ErrCSRNotPending
		}
		placed, err = s.placeCertificate(ctx, tx, p, complete, label, "csr", a.UserID, func() (uuid.UUID, error) { return keyID, nil })
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE csr_requests SET status = $2, certificate_id = $3, finished_at = $4 WHERE id = $1",
			id, CSRCompleted, placed.id, s.clock.Now().UTC())
		if err != nil {
			return fmt.Errorf("inventory: complete the signing request: %w", err)
		}
		outcome := "created"
		if placed.attached {
			outcome = "key_attached"
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "csr.completed", ObjectType: "csr", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"csr_id": id.String(), "certificate_id": placed.id.String(),
				"fingerprint": p.Fingerprint, "outcome": outcome, "warnings": strings.Join(heldWarnings(warnings, placed.complete), ",")}})
		return err
	})
	switch {
	case errors.Is(err, ErrCertificateDuplicate):
		return reject(rejected{reason: "duplicate", fingerprint: p.Fingerprint, certificateID: placed.existing}, err)
	case errors.Is(err, ErrKeyMismatch):
		return reject(rejected{reason: "key_mismatch", fingerprint: p.Fingerprint}, err)
	case err != nil:
		return Certificate{}, nil, err
	}
	c, err := s.GetCertificate(ctx, placed.id)
	if err != nil {
		return Certificate{}, nil, err
	}
	return c, heldWarnings(warnings, placed.complete), nil
}

// CancelCSR closes a pending request without a certificate. Its key stays sealed and unused.
func (s *Service) CancelCSR(ctx context.Context, a Actor, id uuid.UUID) (CSR, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return CSR{}, err
	}
	var out CSR
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getCSR(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Status != CSRPending {
			return ErrCSRNotPending
		}
		if _, err := tx.Exec(ctx, "UPDATE csr_requests SET status = $2, finished_at = $3 WHERE id = $1", id, CSRCancelled,
			s.clock.Now().UTC()); err != nil {
			return fmt.Errorf("inventory: cancel the signing request: %w", err)
		}
		if out, err = getCSR(ctx, tx, id, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "csr.cancelled", ObjectType: "csr", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"csr_id": id.String()}})
		return err
	})
	if err != nil {
		return CSR{}, err
	}
	return out, nil
}
