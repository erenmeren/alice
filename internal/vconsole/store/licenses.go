package store

import (
	"context"
	"fmt"
	"time"

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
