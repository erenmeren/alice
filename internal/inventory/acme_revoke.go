package inventory

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/acme"
	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// Revocation of ACME certificates (RFC 8555 section 7.6; owner decision 2026-10-20,
// docs/superpowers/rulings/certificate-revocation.md).
//
// A version of an ACME certificate (a certificates row an order of it produced) is revoked at its CA with the account
// key of the provider's active account (the account that ordered it, or the same account after a key rollover) and an
// RFC 5280 reason a subscriber gives. Revoking is an Administrator's act with a fresh step-up (the API's AcmeManage),
// a licence change (ClassChange), and cannot be undone: the revocation is recorded on the version (time, reason, who),
// the version is never deployed again (RequestDeployment, the planners and the engine refuse it), and when it is the
// current certificate the renewal planner orders a new one at once (renew.Input.Revoked) while automatic renewal is
// on. Deleting an ACME certificate or an inventory entry revokes nothing.

// ErrNotACMEVersion: the certificate is not a version an order of this ACME certificate produced.
var ErrNotACMEVersion = errors.New("inventory: the certificate was not issued for this ACME certificate")

// ACMERevokeInput names the version to revoke (nil: the current certificate) and the reason (an RFC 5280 name:
// acme.RevocationReasonNames).
type ACMERevokeInput struct {
	CertificateID *uuid.UUID
	Reason        string
}

// revocationTarget is what a revocation needs about one version.
type revocationTarget struct {
	acmeCertID, versionID, providerID uuid.UUID
	names                             []string
	fingerprint, serial, pemChain     string
	notAfter                          time.Time
	revoked, current                  bool
}

// readRevocationTarget reads the version of a live ACME certificate (ErrNotFound; ErrACMENotIssued without a current
// certificate when none is named; ErrNotACMEVersion).
func readRevocationTarget(ctx context.Context, q db.Querier, acmeCertID uuid.UUID, version *uuid.UUID) (revocationTarget, error) {
	c, err := getACMECert(ctx, q, acmeCertID, false)
	if err != nil {
		return revocationTarget{}, err
	}
	t := revocationTarget{acmeCertID: c.ID, providerID: c.ProviderID, names: c.Names}
	switch {
	case version != nil:
		t.versionID = *version
	case c.CurrentCertificateID != nil:
		t.versionID = *c.CurrentCertificateID
	default:
		return revocationTarget{}, ErrACMENotIssued
	}
	t.current = c.CurrentCertificateID != nil && *c.CurrentCertificateID == t.versionID
	var ours bool
	err = q.QueryRow(ctx, `SELECT x.fingerprint_sha256, x.serial, x.pem_chain, x.not_after, x.revoked_at IS NOT NULL,
    x.source = 'acme' AND EXISTS (SELECT 1 FROM acme_orders o WHERE o.acme_certificate_id = $2 AND o.certificate_id = x.id AND o.state = 'succeeded')
FROM certificates x WHERE x.id = $1`, t.versionID, acmeCertID).Scan(&t.fingerprint, &t.serial, &t.pemChain, &t.notAfter, &t.revoked, &ours)
	if errors.Is(err, pgx.ErrNoRows) {
		return revocationTarget{}, ErrNotFound
	}
	if err != nil {
		return revocationTarget{}, fmt.Errorf("inventory: read the certificate to revoke: %w", err)
	}
	if !ours {
		return revocationTarget{}, ErrNotACMEVersion
	}
	t.notAfter = t.notAfter.UTC()
	return t, nil
}

// leafDER is the DER of the first certificate of a PEM chain (nil when there is none).
func leafDER(chain string) []byte {
	b, _ := pem.Decode([]byte(chain))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil
	}
	return b.Bytes
}

// revokeAtCA asks the CA of the provider to revoke the version, signed with the provider's active account (no row is
// written). ErrACMEAccountState without an active account, ErrACMERolloverPending during a key change,
// ErrACMESecretUnreadable; a CA failure is an *ACMEError (acmeFailure).
func (s *Service) revokeAtCA(ctx context.Context, t revocationTarget, reason acme.RevocationReason) error {
	p, err := getACMEProvider(ctx, s.pool, t.providerID, false)
	switch {
	case errors.Is(err, ErrNotFound):
		return ErrACMEAccountState
	case err != nil:
		return err
	case p.ActiveAccountID == nil:
		return ErrACMEAccountState
	case p.PendingRollover:
		return ErrACMERolloverPending
	}
	signer, url, err := s.ACMEAccountSigner(ctx, *p.ActiveAccountID)
	if err != nil {
		return err
	}
	client, err := s.acmeClientFor(p, signer, url)
	if err != nil {
		return err
	}
	return acmeFailure(client.Revoke(ctx, leafDER(t.pemChain), reason))
}

// markRevokedTx records a revocation the CA confirmed (once: false when the version was marked already).
func markRevokedTx(ctx context.Context, tx pgx.Tx, version uuid.UUID, reason string, by *uuid.UUID, now time.Time) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE certificates SET revoked_at = $2, revocation_reason = $3, revoked_by = $4 WHERE id = $1 AND revoked_at IS NULL`,
		version, now, reason, by)
	if err != nil {
		return false, fmt.Errorf("inventory: record the revocation: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// revocationDetails are the audit details of a revocation.
func revocationDetails(t revocationTarget, reason string) map[string]string {
	return map[string]string{"acme_certificate_id": t.acmeCertID.String(), "certificate_id": t.versionID.String(), "fingerprint": t.fingerprint,
		"serial": truncRunes(t.serial, 100), "reason": reason, "current": strconv.FormatBool(t.current),
		"names": truncRunes(strings.Join(t.names, ","), maxAuditNames)}
}

// RevokeACMECertificate revokes a version of an ACME certificate at its CA (see the file comment) and returns the
// version as it is now. Order: the reason (validate.Errors); the licence gate (ClassChange: nothing is recorded, the CA
// is not contacted); ErrNotFound, ErrACMENotIssued, ErrNotACMEVersion; ErrCertificateRevoked when it is revoked already;
// ErrCertificateExpired when it has expired (a CA no longer lists an expired certificate); then the CA (an *ACMEError,
// audited acme.certificate.revoke_failed). Success is audited acme.certificate.revoked in the transaction that records
// it. A CA that says the certificate is revoked already ends the same way (the end state asked for).
func (s *Service) RevokeACMECertificate(ctx context.Context, a Actor, acmeCertID uuid.UUID, in ACMERevokeInput) (Certificate, error) {
	reason, ok := acme.ParseRevocationReason(in.Reason)
	if !ok {
		return Certificate{}, validate.Errors{{Field: "reason", Code: validate.OneOf,
			Params: map[string]string{"values": strings.Join(acme.RevocationReasonNames(), ", ")}}}
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Certificate{}, err
	}
	t, err := readRevocationTarget(ctx, s.pool, acmeCertID, in.CertificateID)
	if err != nil {
		return Certificate{}, err
	}
	switch {
	case t.revoked:
		return Certificate{}, ErrCertificateRevoked
	case !s.clock.Now().Before(t.notAfter):
		return Certificate{}, ErrCertificateExpired
	}
	if err := s.revokeAtCA(ctx, t, reason); err != nil {
		s.auditRevokeFailure(ctx, a, t, in.Reason, err)
		return Certificate{}, err
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		marked, err := markRevokedTx(ctx, tx, t.versionID, in.Reason, nullableUser(a.UserID), s.clock.Now().UTC())
		if err != nil || !marked {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.certificate.revoked", ObjectType: "acme_certificate",
			ObjectID: acmeCertID.String(), Result: audit.Success, Details: revocationDetails(t, in.Reason)})
		return err
	})
	if err != nil {
		return Certificate{}, err
	}
	return s.GetCertificate(ctx, t.versionID)
}

// auditRevokeFailure records a refused or failed revocation in its own transaction (detached, like auditDeployDenial).
func (s *Service) auditRevokeFailure(ctx context.Context, a Actor, t revocationTarget, reason string, cause error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	d := revocationDetails(t, reason)
	d["error"] = revokeErrorCode(cause)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.certificate.revoke_failed", ObjectType: "acme_certificate",
			ObjectID: t.acmeCertID.String(), Result: audit.Failure, Details: d})
		return err
	})
	if err != nil {
		s.log.Error("could not audit a failed revocation", "error_type", fmt.Sprintf("%T", err))
	}
}

// revokeErrorCode is the closed code of a revocation failure (an ACME reason, an inventory refusal or unexpected).
func revokeErrorCode(err error) string {
	var ae *ACMEError
	switch {
	case errors.As(err, &ae):
		return ae.Reason
	case errors.Is(err, ErrACMEAccountState):
		return "acme.account_state"
	case errors.Is(err, ErrACMERolloverPending):
		return "acme.rollover_pending"
	case errors.Is(err, ErrACMESecretUnreadable):
		return "acme.secret_unreadable"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return acme.ReasonProviderUnreachable
	}
	return "internal.unexpected"
}
