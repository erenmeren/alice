package inventory

// The scheduled revocation check (R64, D5; Rulings 14 to 20): every unexpired, unrevoked, not self-signed certificate
// Alice holds (any source) and every leaf network discovery found without an inventory row (with its issuer in a chain an
// endpoint presented) is checked at its authority (OCSP, then CRL) by internal/revocation. Each result is recorded in
// revocation_checks with when to check again. A revocation the authority signed marks an inventory certificate revoked
// for good (as an Alice revocation: no deployment again, the R48 rollback guard, an ACME certificate renewed at once) and
// is audited and e-mailed once; a suspension is recorded and e-mailed once per hold, never marked; unknown, unavailable
// and not checkable results are recorded and never acted on. The check is ClassReadOnly (paused in lock) and has a
// switch (settings key revocation.check; absent = on).

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/revocation"
)

// JobRevocationCheck is the periodic task of the check (jobs.RevocationCheck).
const JobRevocationCheck = "revocation.check"

// SettingRevocationCheck is the settings key of the switch.
const SettingRevocationCheck = "revocation.check"

// Limits of a run (R64 Ruling 17).
const (
	revocationBatch     = 200
	revocationPerHost   = 50
	revocationRunBudget = 4 * time.Minute
	revocationPrune     = 1000
	revocationGoodAfter = 24 * time.Hour
	revocationHoldAfter = 6 * time.Hour
	revocationNotAfter  = 7 * 24 * time.Hour // not checkable
	revocationMaxWait   = 24 * time.Hour     // the failures' backoff cap
	revocationEndpoints = 5                  // the endpoints a discovered certificate's e-mail names
)

// RevocationRun is one run of a revocation checker (*revocation.Run).
type RevocationRun interface {
	Check(ctx context.Context, leaf, issuer *x509.Certificate) revocation.Result
}

// RevocationChecker starts runs (*revocation.Checker through RevocationCheckerOf); nil in Config means no checks.
type RevocationChecker interface {
	NewRun(perHost int) RevocationRun
}

// RevocationCheckerOf adapts the revocation package's checker.
func RevocationCheckerOf(c *revocation.Checker) RevocationChecker { return checkerAdapter{c} }

type checkerAdapter struct{ c *revocation.Checker }

func (a checkerAdapter) NewRun(perHost int) RevocationRun { return a.c.NewRun(perHost) }

// RevocationRunReport counts what one run did.
type RevocationRunReport struct{ Checked, Revoked, OnHold, Deferred int }

// RevocationCheck is the last check of a certificate (GetCertificate).
type RevocationCheck struct {
	Status, Method, Reason, ErrorCode string
	RevokedAt                         *time.Time
	CheckedAt, NextCheckAt            time.Time
}

// RevocationSettings is the switch (Version counts the saves, for If-Match).
type RevocationSettings struct {
	Enabled bool
	Version int
}

type revocationSettingValue struct {
	Enabled bool `json:"enabled"`
	Version int  `json:"version"`
}

// The e-mails of a revocation the authority reported (params: certificate_name, fingerprint, revoked_at
// "2006-01-02 15:04 UTC", reason (the RFC 5280 name), method (OCSP or CRL); the discovered one also endpoints).
const (
	TemplateCertificateRevokedByAuthority           = "certificate.revoked_by_authority"
	TemplateCertificateRevokedByAuthorityDiscovered = "certificate.revoked_by_authority_discovered"
	TemplateCertificateOnHoldByAuthority            = "certificate.on_hold_by_authority"
)

// RevocationTemplates lists the revocation check e-mails (render tests).
func RevocationTemplates() []string {
	return []string{TemplateCertificateRevokedByAuthority, TemplateCertificateRevokedByAuthorityDiscovered, TemplateCertificateOnHoldByAuthority}
}

// RevocationSettings reads the switch; an absent row is on (a new installation, R64 Ruling 19).
func (s *Service) RevocationSettings(ctx context.Context) (RevocationSettings, error) {
	return revocationSettings(ctx, s.pool)
}

func revocationSettings(ctx context.Context, q db.Querier) (RevocationSettings, error) {
	v := revocationSettingValue{Enabled: true}
	if _, err := settings.Get(ctx, q, SettingRevocationCheck, &v); err != nil {
		return RevocationSettings{}, err
	}
	return RevocationSettings(v), nil
}

// SaveRevocationSettings switches the check on or off when version is the one read (ErrRevocationSettingsVersion
// otherwise), audited settings.revocation_check_changed.
func (s *Service) SaveRevocationSettings(ctx context.Context, a audit.Actor, version int, enabled bool) (RevocationSettings, error) {
	var out RevocationSettings
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('settings:revocation.check'))"); err != nil {
			return fmt.Errorf("inventory: lock the revocation check setting: %w", err)
		}
		cur, err := revocationSettings(ctx, tx)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return ErrRevocationSettingsVersion
		}
		out = RevocationSettings{Enabled: enabled, Version: cur.Version + 1}
		if err := settings.Set(ctx, tx, SettingRevocationCheck, revocationSettingValue(out), s.clock.Now()); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "settings.revocation_check_changed", ObjectType: "settings",
			ObjectID: SettingRevocationCheck, Result: audit.Success, Details: map[string]string{"enabled": strconv.FormatBool(enabled)}})
		return err
	})
	return out, err
}

// revocationCandidate is a certificate due for a check.
type revocationCandidate struct {
	fingerprint string
	chain       string // the leaf's PEM, then its chain (an inventory certificate's pem_chain; a discovered leaf's PEM)
	issuerPEM   string // a discovered leaf's issuer ("" for an inventory certificate: the issuer is in chain)
	inventory   bool
}

// RunRevocationChecks checks the due certificates once (the revocation.check task). Nothing is asked when the switch is
// off, no checker is configured or the licence gate refuses read-only work.
func (s *Service) RunRevocationChecks(ctx context.Context) (RevocationRunReport, error) {
	var rep RevocationRunReport
	if s.revocation == nil {
		return rep, nil
	}
	set, err := s.RevocationSettings(ctx)
	if err != nil || !set.Enabled {
		return rep, err
	}
	if s.license.Allow(license.ClassReadOnly) != nil {
		return rep, nil
	}
	started := s.clock.Now()
	cands, err := s.revocationCandidates(ctx, started)
	if err != nil {
		return rep, err
	}
	run := s.revocation.NewRun(revocationPerHost)
	for _, c := range cands {
		if ctx.Err() != nil || s.clock.Now().Sub(started) > revocationRunBudget {
			break
		}
		leaf, issuer := revocationPair(c)
		var res revocation.Result
		if leaf == nil {
			res = revocation.Result{Status: revocation.StatusNotCheckable, Code: revocation.CodeNoIssuer}
		} else {
			res = run.Check(ctx, leaf, issuer)
		}
		if res.Status == revocation.StatusDeferred {
			rep.Deferred++
			continue
		}
		rep.Checked++
		if err := s.recordRevocation(ctx, c, res); err != nil {
			return rep, err
		}
		switch res.Status {
		case revocation.StatusRevoked:
			rep.Revoked++
		case revocation.StatusOnHold:
			rep.OnHold++
		}
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM revocation_checks WHERE fingerprint_sha256 IN (SELECT r.fingerprint_sha256 FROM revocation_checks r
WHERE NOT EXISTS (SELECT 1 FROM certificates c WHERE c.fingerprint_sha256 = r.fingerprint_sha256)
  AND NOT EXISTS (SELECT 1 FROM discovery_certificates d WHERE d.fingerprint_sha256 = r.fingerprint_sha256) LIMIT $1)`, revocationPrune)
	if err != nil {
		return rep, fmt.Errorf("inventory: prune the revocation checks: %w", err)
	}
	return rep, nil
}

// revocationCandidates selects the due certificates (one statement, at most revocationBatch, the longest due first).
func (s *Service) revocationCandidates(ctx context.Context, now time.Time) ([]revocationCandidate, error) {
	rows, err := s.pool.Query(ctx, `WITH cand AS (
    SELECT c.fingerprint_sha256 AS fp, c.pem_chain AS chain, '' AS issuer_pem, true AS inv
    FROM certificates c WHERE c.revoked_at IS NULL AND c.not_after > $1 AND NOT c.self_signed
  UNION ALL
    SELECT d.fingerprint_sha256, d.pem, i.pem, false
    FROM discovery_certificates d
    JOIN LATERAL (SELECT ic.pem FROM discovery_endpoints e JOIN discovery_certificates ic ON ic.fingerprint_sha256 = e.chain_fingerprints[1]
                  WHERE e.fingerprint_sha256 = d.fingerprint_sha256 ORDER BY e.last_seen DESC NULLS LAST, e.id LIMIT 1) i ON true
    WHERE d.is_leaf AND NOT d.self_signed AND d.not_after > $1
      AND NOT EXISTS (SELECT 1 FROM certificates c WHERE c.fingerprint_sha256 = d.fingerprint_sha256)
)
SELECT cand.fp, cand.chain, cand.issuer_pem, cand.inv FROM cand
LEFT JOIN revocation_checks r ON r.fingerprint_sha256 = cand.fp
WHERE r.fingerprint_sha256 IS NULL OR (r.next_check_at <= $1 AND r.status <> 'revoked')
ORDER BY coalesce(r.next_check_at, '-infinity'::timestamptz), cand.fp
LIMIT $2`, now, revocationBatch)
	if err != nil {
		return nil, fmt.Errorf("inventory: select the certificates to check for revocation: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (revocationCandidate, error) {
		var c revocationCandidate
		err := row.Scan(&c.fingerprint, &c.chain, &c.issuerPEM, &c.inventory)
		return c, err
	})
}

// revocationPair parses a candidate's leaf and the certificate that signed it: for an inventory certificate the first
// block of its chain after the leaf that signed it, for a discovered leaf the issuer an endpoint presented (nil when none
// did). A leaf that does not parse is nil.
func revocationPair(c revocationCandidate) (leaf, issuer *x509.Certificate) {
	certs := pemCertificates(c.chain + "\n" + c.issuerPEM)
	if len(certs) == 0 {
		return nil, nil
	}
	leaf = certs[0]
	for _, cand := range certs[1:] {
		if leaf.CheckSignatureFrom(cand) == nil {
			return leaf, cand
		}
	}
	return leaf, nil
}

// pemCertificates parses every CERTIFICATE block of a PEM text (a block that does not parse is skipped).
func pemCertificates(text string) []*x509.Certificate {
	var out []*x509.Certificate
	for rest := []byte(text); ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

// revocationBackoff is the wait after the n-th failure in a row: 1, 2, 4 ... hours, at most a day.
func revocationBackoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	return min(time.Hour<<min(n-1, 10), revocationMaxWait)
}

// recordRevocation records one result in its own transaction, and acts on a revocation or a suspension.
func (s *Service) recordRevocation(ctx context.Context, c revocationCandidate, res revocation.Result) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.clock.Now().UTC()
		var prevStatus string
		var prevFailures int
		var prevNotified *time.Time
		err := tx.QueryRow(ctx, "SELECT status, failures, notified_at FROM revocation_checks WHERE fingerprint_sha256 = $1 FOR UPDATE",
			c.fingerprint).Scan(&prevStatus, &prevFailures, &prevNotified)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inventory: read the revocation check: %w", err)
		}
		row := revocationRow{status: string(res.Status), method: res.Method, reason: res.Reason, code: res.Code, notified: prevNotified}
		switch res.Status {
		case revocation.StatusGood:
			row.next = now.Add(revocationGoodAfter)
			if prevStatus == string(revocation.StatusOnHold) {
				row.notified = nil // the hold was lifted: the next one is news
			}
		case revocation.StatusUnknown:
			row.next = now.Add(revocationGoodAfter)
		case revocation.StatusUnavailable:
			row.method, row.failures = "", prevFailures+1
			row.next = now.Add(revocationBackoff(row.failures))
		case revocation.StatusNotCheckable:
			row.method, row.next = "", now.Add(revocationNotAfter)
		case revocation.StatusOnHold:
			at := res.RevokedAt
			row.revokedAt, row.next = &at, now.Add(revocationHoldAfter)
			if prevStatus != string(revocation.StatusOnHold) || prevNotified == nil {
				if err := s.revocationNews(ctx, tx, c, res, TemplateCertificateOnHoldByAuthority, "certificate.revocation_on_hold"); err != nil {
					return err
				}
				row.notified = &now
			}
		case revocation.StatusRevoked:
			at := res.RevokedAt
			row.revokedAt, row.next = &at, now
			if row.reason == "" {
				row.reason = "unspecified"
			}
			if err := s.revokedByAuthority(ctx, tx, c, res, row.reason, prevNotified); err != nil {
				return err
			}
			if prevNotified == nil {
				row.notified = &now
			}
		default:
			return fmt.Errorf("inventory: unknown revocation status %q", res.Status)
		}
		_, err = tx.Exec(ctx, `INSERT INTO revocation_checks (fingerprint_sha256, status, method, revoked_at, reason, error_code, failures, checked_at,
    next_check_at, notified_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (fingerprint_sha256) DO UPDATE SET status = EXCLUDED.status, method = EXCLUDED.method, revoked_at = EXCLUDED.revoked_at,
    reason = EXCLUDED.reason, error_code = EXCLUDED.error_code, failures = EXCLUDED.failures, checked_at = EXCLUDED.checked_at,
    next_check_at = EXCLUDED.next_check_at, notified_at = EXCLUDED.notified_at`, c.fingerprint, row.status, row.method, row.revokedAt, row.reason,
			row.code, row.failures, now, row.next, row.notified)
		if err != nil {
			return fmt.Errorf("inventory: record the revocation check: %w", err)
		}
		return nil
	})
}

type revocationRow struct {
	status, method, reason, code string
	failures                     int
	revokedAt                    *time.Time
	next                         time.Time
	notified                     *time.Time
}

// revokedByAuthority marks an inventory certificate revoked (final; audited certificate.revoked_by_authority) and mails
// the revocation once (notified: already mailed); a discovered leaf is only mailed.
func (s *Service) revokedByAuthority(ctx context.Context, tx pgx.Tx, c revocationCandidate, res revocation.Result, reason string,
	notified *time.Time) error {
	if c.inventory {
		tag, err := tx.Exec(ctx, `UPDATE certificates SET revoked_at = $1, revocation_reason = $2, revocation_seen = $3
WHERE fingerprint_sha256 = $4 AND revoked_at IS NULL`, res.RevokedAt, revocationReasonOf(reason), res.Method, c.fingerprint)
		if err != nil {
			return fmt.Errorf("inventory: mark the certificate revoked by its authority: %w", err)
		}
		if tag.RowsAffected() == 1 {
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: revocationActor, Action: "certificate.revoked_by_authority", ObjectType: "certificate",
				ObjectID: c.fingerprint, Result: audit.Success, Details: map[string]string{"fingerprint": c.fingerprint, "method": res.Method,
					"revoked_at": res.RevokedAt.UTC().Format(time.RFC3339), "reason": reason}}); err != nil {
				return err
			}
		}
	}
	if notified != nil {
		return nil
	}
	template := TemplateCertificateRevokedByAuthority
	if !c.inventory {
		template = TemplateCertificateRevokedByAuthorityDiscovered
	}
	return s.revocationMail(ctx, tx, c, res, reason, template)
}

// revocationReasonOf is the certificates.revocation_reason a reported reason is stored as (certificateHold never is).
func revocationReasonOf(reason string) string {
	if reason == "" || reason == "certificateHold" {
		return "unspecified"
	}
	return reason
}

// revocationActor is the system actor of the check's audit rows.
var revocationActor = audit.SystemActor("revocation")

// revocationNews audits (an inventory certificate only) and mails a suspension.
func (s *Service) revocationNews(ctx context.Context, tx pgx.Tx, c revocationCandidate, res revocation.Result, template, action string) error {
	if c.inventory {
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: revocationActor, Action: action, ObjectType: "certificate", ObjectID: c.fingerprint,
			Result: audit.Success, Details: map[string]string{"fingerprint": c.fingerprint, "method": res.Method,
				"revoked_at": res.RevokedAt.UTC().Format(time.RFC3339)}}); err != nil {
			return err
		}
	}
	return s.revocationMail(ctx, tx, c, res, res.Reason, template)
}

// revocationMail queues a revocation e-mail: an inventory certificate's to its service and the services of the servers
// holding it, a discovered leaf's to the services of the scopes presenting it (the Administrators when none).
func (s *Service) revocationMail(ctx context.Context, tx pgx.Tx, c revocationCandidate, res revocation.Result, reason, template string) error {
	var name string
	var svcs []uuid.UUID
	var err error
	if c.inventory {
		if err = tx.QueryRow(ctx, `SELECT coalesce(nullif(label, ''), nullif(subject_cn, ''), left(fingerprint_sha256, 16)) FROM certificates
WHERE fingerprint_sha256 = $1`, c.fingerprint).Scan(&name); err != nil {
			return fmt.Errorf("inventory: read the certificate's name: %w", err)
		}
		svcs, err = servicesOf(ctx, tx, `SELECT c.service_id FROM certificates c WHERE c.fingerprint_sha256 = $1
UNION ALL
SELECT t.service_id FROM certificate_locations l JOIN certificates c ON c.id = l.certificate_id
JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL WHERE c.fingerprint_sha256 = $1 AND l.missing_since IS NULL`, c.fingerprint)
	} else {
		if err = tx.QueryRow(ctx, `SELECT coalesce(nullif(subject_cn, ''), left(fingerprint_sha256, 16)) FROM discovery_certificates
WHERE fingerprint_sha256 = $1`, c.fingerprint).Scan(&name); err != nil {
			return fmt.Errorf("inventory: read the discovered certificate's name: %w", err)
		}
		svcs, err = servicesOf(ctx, tx, `SELECT sc.service_id FROM discovery_endpoints e JOIN discovery_scopes sc ON sc.id = e.scope_id
WHERE e.fingerprint_sha256 = $1`, c.fingerprint)
	}
	if err != nil {
		return err
	}
	method := map[string]string{"ocsp": "OCSP", "crl": "CRL"}[res.Method]
	params := map[string]string{"certificate_name": truncRunes(strings.TrimSpace(name), 200), "fingerprint": c.fingerprint,
		"revoked_at": res.RevokedAt.UTC().Format("2006-01-02 15:04") + " UTC", "reason": reason, "method": method}
	if !c.inventory {
		eps, err := discoveredEndpoints(ctx, tx, c.fingerprint)
		if err != nil {
			return err
		}
		params["endpoints"] = eps
	}
	return s.notifier.NotifyServices(ctx, tx, svcs, template, params)
}

// discoveredEndpoints names at most revocationEndpoints address:port values presenting a discovered leaf, then "…".
func discoveredEndpoints(ctx context.Context, tx pgx.Tx, fp string) (string, error) {
	rows, err := tx.Query(ctx, `SELECT CASE WHEN family(address) = 6 THEN '[' || host(address) || ']' ELSE host(address) END || ':' || port
FROM discovery_endpoints WHERE fingerprint_sha256 = $1 ORDER BY address, port LIMIT $2`, fp, revocationEndpoints+1)
	if err != nil {
		return "", fmt.Errorf("inventory: read the endpoints presenting the certificate: %w", err)
	}
	eps, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", fmt.Errorf("inventory: read the endpoints presenting the certificate: %w", err)
	}
	if len(eps) > revocationEndpoints {
		eps = append(eps[:revocationEndpoints], "…")
	}
	return strings.Join(eps, ", "), nil
}

// revocationCheckOf reads a certificate's last check (nil when never checked).
func revocationCheckOf(ctx context.Context, q db.Querier, fingerprint string) (*RevocationCheck, error) {
	var rc RevocationCheck
	err := q.QueryRow(ctx, `SELECT status, method, reason, error_code, revoked_at, checked_at, next_check_at FROM revocation_checks
WHERE fingerprint_sha256 = $1`, fingerprint).Scan(&rc.Status, &rc.Method, &rc.Reason, &rc.ErrorCode, &rc.RevokedAt, &rc.CheckedAt, &rc.NextCheckAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read the certificate's revocation check: %w", err)
	}
	rc.RevokedAt, rc.CheckedAt, rc.NextCheckAt = utcPtr(rc.RevokedAt), rc.CheckedAt.UTC(), rc.NextCheckAt.UTC()
	return &rc, nil
}
