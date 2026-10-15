// Package store reads and writes vendor customers and license requests. The database writes the audit
// row of every change itself (triggers), so nothing here has to remember to.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/text/unicode/norm"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/db"
	"alice/internal/vconsole/audit"
)

// Errors.
var (
	ErrDuplicateCustomer = errors.New("store: a customer with this name already exists")
	ErrNotFound          = errors.New("store: not found")
)

// InvalidError means the request itself is wrong (not the database): the message is meant for the person
// who typed it.
type InvalidError struct{ Err error }

func (e *InvalidError) Error() string {
	return "store: the request cannot become a license: " + e.Err.Error()
}
func (e *InvalidError) Unwrap() error { return e.Err }

// Customer is a company that buys licenses.
type Customer struct {
	ID        int64
	Name      string
	Contact   string
	Notes     string
	CreatedBy string
	CreatedAt time.Time
}

// NewCustomer is what a sales person enters.
type NewCustomer struct{ Name, Contact, Notes string }

// AddCustomer creates a customer. The name is NFC-normalized and trimmed, and compared without
// regard to case, so the same company typed twice is one customer.
func AddCustomer(ctx context.Context, q audit.Q, c NewCustomer) (int64, error) {
	name := strings.TrimSpace(norm.NFC.String(c.Name))
	var id int64
	err := q.QueryRow(ctx, `INSERT INTO customers (name, contact, notes) VALUES ($1, $2, $3) RETURNING id`,
		name, strings.TrimSpace(c.Contact), strings.TrimSpace(c.Notes)).Scan(&id)
	if db.IsUniqueViolationOn(err, "customers_name_key") {
		return 0, ErrDuplicateCustomer
	}
	if err != nil {
		return 0, fmt.Errorf("store: add customer: %w", err)
	}
	return id, nil
}

// NewRequest is a license a sales person asks for.
type NewRequest struct {
	CustomerID   int64
	Installation string   // as typed; stored in canonical form
	Targets      int      // 1..100000
	From         string   // "" = today; "2026-10-01" or RFC 3339
	Months       int      // 0 = 12
	Features     []string // empty entries are dropped
	Replaces     string   // license ID a correction replaces
}

// Request is a stored request.
type Request struct {
	ID       int64
	Customer string // the customer's name
	NewRequest
	Status      string
	RequestedBy string
	RequestedAt time.Time
}

func normalizedFeatures(in []string) []string {
	out := []string{}
	for _, f := range in {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// AddRequest validates the request by building the payload it would produce (so a request that
// could never be signed is refused now, not at signing time) and stores it.
func AddRequest(ctx context.Context, q audit.Q, r NewRequest, now time.Time) (int64, error) {
	var name string
	if err := q.QueryRow(ctx, `SELECT name FROM customers WHERE id = $1`, r.CustomerID).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("%w: customer %d", ErrNotFound, r.CustomerID)
		}
		return 0, fmt.Errorf("store: read customer: %w", err)
	}
	if _, err := issuer.BuildPayload(issuer.Request{
		Installation: r.Installation, Customer: name, Targets: r.Targets, From: r.From,
		Months: r.Months, Features: r.Features, Replaces: r.Replaces,
	}, now); err != nil {
		return 0, &InvalidError{Err: err}
	}
	inst, err := license.ParseInstallationID(r.Installation)
	if err != nil {
		return 0, err
	}
	months := r.Months
	if months == 0 {
		months = 12
	}
	var id int64
	err = q.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, valid_from, months, features, replaces)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		r.CustomerID, inst, r.Targets, strings.TrimSpace(r.From), months, normalizedFeatures(r.Features),
		strings.TrimSpace(r.Replaces)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: add request: %w", err)
	}
	return id, nil
}

const requestColumns = `r.id, c.name, r.customer_id, r.installation, r.targets, r.valid_from, r.months, r.features,
	r.replaces, r.status, r.requested_by, r.requested_at`

func scanRequest(row pgx.Row) (Request, error) {
	var r Request
	err := row.Scan(&r.ID, &r.Customer, &r.CustomerID, &r.Installation, &r.Targets, &r.From, &r.Months, &r.Features,
		&r.Replaces, &r.Status, &r.RequestedBy, &r.RequestedAt)
	return r, err
}

// GetRequest returns one request.
func GetRequest(ctx context.Context, q audit.Q, id int64) (Request, error) {
	r, err := scanRequest(q.QueryRow(ctx, `SELECT `+requestColumns+` FROM license_requests r
		JOIN customers c ON c.id = r.customer_id WHERE r.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	return r, err
}

// ListRequests returns requests, oldest first. An empty status means all.
func ListRequests(ctx context.Context, q audit.Q, status string) ([]Request, error) {
	rows, err := q.Query(ctx, `SELECT `+requestColumns+` FROM license_requests r
		JOIN customers c ON c.id = r.customer_id WHERE $1 = '' OR r.status = $1 ORDER BY r.requested_at, r.id`, status)
	if err != nil {
		return nil, fmt.Errorf("store: list requests: %w", err)
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list requests: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RequestHash is the SHA-256 (hex) of the content a signer approves: customer name, canonical
// installation ID, targets, start, months, features and the license it replaces. A JSON array
// keeps the fields apart. It is recomputed from the database row at signing time, so a request
// that changed after the signer looked at it is noticed.
func RequestHash(r Request) string {
	feats := r.Features
	if feats == nil {
		feats = []string{}
	}
	raw, _ := json.Marshal([]any{r.Customer, r.Installation, r.Targets, r.From, r.Months, feats, r.Replaces})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// CancelRequest closes an open request. A sales login may cancel only its own (row-level security);
// ErrNotFound covers a missing, already closed or someone else's request.
func CancelRequest(ctx context.Context, q audit.Q, id int64) error {
	tag, err := q.Exec(ctx, `UPDATE license_requests SET status = 'cancelled' WHERE id = $1 AND status = 'open'`, id)
	if err != nil {
		return fmt.Errorf("store: cancel request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: no open request %d that you may cancel", ErrNotFound, id)
	}
	return nil
}

// LicenseFile returns the signed file of an issued license, byte for byte as it was issued.
func LicenseFile(ctx context.Context, q audit.Q, licenseID string) ([]byte, error) {
	var raw []byte
	err := q.QueryRow(ctx, `SELECT file FROM licenses WHERE license_id = $1`, licenseID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: license %s", ErrNotFound, licenseID)
	}
	if err != nil {
		return nil, fmt.Errorf("store: read license: %w", err)
	}
	return raw, nil
}
