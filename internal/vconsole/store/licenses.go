package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"alice/internal/vconsole/audit"
)

// LicenseRow is one issued license as the list shows it (the signed file is fetched separately).
type LicenseRow struct {
	LicenseID, Customer, Installation, KeyID, SignedBy, Replaces string
	IssuedAt, ValidFrom, ValidUntil                              time.Time
	Targets                                                      int
	RevokedAt                                                    *time.Time
}

// ListLicenses returns licenses ordered by valid_until ascending. endingWithinDays 0 means all;
// otherwise only licenses that are not revoked and end by now+days: those ending before now are
// included only when includeEnded is true.
func ListLicenses(ctx context.Context, q audit.Q, now time.Time, endingWithinDays int, includeEnded bool) ([]LicenseRow, error) {
	rows, err := q.Query(ctx, `SELECT l.license_id, c.name, l.installation, l.key_id, l.signed_by, l.replaces,
			l.issued_at, l.valid_from, l.valid_until, l.targets, l.revoked_at
		FROM licenses l JOIN customers c ON c.id = l.customer_id
		WHERE $2 = 0 OR (l.revoked_at IS NULL
			AND l.valid_until <= $1::timestamptz + make_interval(days => $2)
			AND ($3 OR l.valid_until >= $1::timestamptz))
		ORDER BY l.valid_until, l.license_id`, now, endingWithinDays, includeEnded)
	if err != nil {
		return nil, fmt.Errorf("store: list licenses: %w", err)
	}
	defer rows.Close()
	var out []LicenseRow
	for rows.Next() {
		var r LicenseRow
		if err := rows.Scan(&r.LicenseID, &r.Customer, &r.Installation, &r.KeyID, &r.SignedBy, &r.Replaces,
			&r.IssuedAt, &r.ValidFrom, &r.ValidUntil, &r.Targets, &r.RevokedAt); err != nil {
			return nil, fmt.Errorf("store: list licenses: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListCustomers returns all customers, sorted by name without regard to case.
func ListCustomers(ctx context.Context, q audit.Q) ([]Customer, error) {
	rows, err := q.Query(ctx, `SELECT id, name, contact, notes, created_by, created_at FROM customers
		ORDER BY lower(name), id`)
	if err != nil {
		return nil, fmt.Errorf("store: list customers: %w", err)
	}
	defer rows.Close()
	var out []Customer
	for rows.Next() {
		var c Customer
		if err := rows.Scan(&c.ID, &c.Name, &c.Contact, &c.Notes, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: list customers: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Renewal is what the "Renew" form is prefilled with: the old license's customer and installation,
// and the targets and features of the request it was issued from.
type Renewal struct {
	LicenseID    string
	CustomerID   int64
	Customer     string
	Installation string
	Targets      int
	Features     []string
	ValidUntil   time.Time
	RevokedAt    *time.Time
}

// GetLicenseForRenewal reads one license for the renew form. Features come from the original
// request (licenses.request_id), not from the signed file, so nothing is parsed here. An unknown ID
// is ErrNotFound; a revoked license is returned with RevokedAt set, for the caller to refuse.
func GetLicenseForRenewal(ctx context.Context, q audit.Q, licenseID string) (Renewal, error) {
	var r Renewal
	err := q.QueryRow(ctx, `SELECT l.license_id, l.customer_id, c.name, l.installation, r.targets, r.features,
			l.valid_until, l.revoked_at
		FROM licenses l
		JOIN customers c ON c.id = l.customer_id
		JOIN license_requests r ON r.id = l.request_id
		WHERE l.license_id = $1`, licenseID).Scan(&r.LicenseID, &r.CustomerID, &r.Customer, &r.Installation,
		&r.Targets, &r.Features, &r.ValidUntil, &r.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Renewal{}, fmt.Errorf("%w: license %s", ErrNotFound, licenseID)
	}
	if err != nil {
		return Renewal{}, fmt.Errorf("store: read license for renewal: %w", err)
	}
	return r, nil
}

// MaxReasonLen is the longest revoke reason, in characters.
const MaxReasonLen = 200

// checkReason refuses an empty reason, one over MaxReasonLen characters, invalid UTF-8, and any
// control (line breaks included), format (bidi, zero width) or line/paragraph separator character:
// the reason ends up in the audit log and in terminal output, so it must be one honest line.
func checkReason(reason string) error {
	if !utf8.ValidString(reason) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidReason)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: a reason is required", ErrInvalidReason)
	}
	if utf8.RuneCountInString(reason) > MaxReasonLen {
		return fmt.Errorf("%w: longer than %d characters", ErrInvalidReason, MaxReasonLen)
	}
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return fmt.Errorf("%w: control or formatting characters are not allowed", ErrInvalidReason)
		}
	}
	return nil
}

// RevokeLicense marks a license revoked at now and records the reason in the license.revoke audit
// row. The reason travels to the audit trigger in the transaction-local setting vendor.reason, so
// the setting and the UPDATE must share one transaction, so q must be able to begin one: a pool or
// a single connection gets a transaction of its own, and a transaction (pgx.Tx) gets a savepoint
// inside the caller's transaction (the setting then lasts until the caller's transaction ends).
// Any other q is refused with an error, because the reason would be lost.
// ErrNotFound for an unknown license, ErrAlreadyRevoked when revoked_at is already set; a
// permission error (42501) passes through, only vendor_owner may revoke.
func RevokeLicense(ctx context.Context, q audit.Q, licenseID, reason string, now time.Time) error {
	if err := checkReason(reason); err != nil {
		return err
	}
	b, ok := q.(interface {
		Begin(ctx context.Context) (pgx.Tx, error)
	})
	if !ok {
		return fmt.Errorf("store: revoke license: %T cannot begin a transaction", q)
	}
	return pgx.BeginFunc(ctx, b, func(tx pgx.Tx) error { return revokeIn(ctx, tx, licenseID, reason, now) })
}

func revokeIn(ctx context.Context, q audit.Q, licenseID, reason string, now time.Time) error {
	if _, err := q.Exec(ctx, `SELECT set_config('vendor.reason', $1, true)`, reason); err != nil {
		return fmt.Errorf("store: revoke license: %w", err)
	}
	tag, err := q.Exec(ctx, `UPDATE licenses SET revoked_at = $2 WHERE license_id = $1 AND revoked_at IS NULL`,
		licenseID, now)
	if err != nil {
		return fmt.Errorf("store: revoke license: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var revoked *time.Time
	err = q.QueryRow(ctx, `SELECT revoked_at FROM licenses WHERE license_id = $1`, licenseID).Scan(&revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: license %s", ErrNotFound, licenseID)
	}
	if err != nil {
		return fmt.Errorf("store: revoke license: %w", err)
	}
	return fmt.Errorf("%w: %s", ErrAlreadyRevoked, licenseID)
}
