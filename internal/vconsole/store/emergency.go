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

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/vconsole/audit"
)

// Emergency extensions (docs/superpowers/rulings/vendor-emergency-extension.md).
const (
	DefaultEmergencyDays = 14
	MaxEmergencyDays     = issuer.MaxEmergencyDays
)

// Errors of emergency extensions. Both reach the person wrapped in an InvalidError.
var (
	// ErrExtensionNotNeeded: a license of the installation that is valid on the extension's start
	// day already runs at least as long; in Alice the extension (the later start) would hide it.
	ErrExtensionNotNeeded = errors.New("this installation already has a license that runs at least as long as the extension would")
	// ErrStartsBeforeExtension: a license starting before a running extension must replace it,
	// or Alice keeps the extension (the later start) in force until it ends.
	ErrStartsBeforeExtension = errors.New("the license starts before an emergency extension of this installation")
	// ErrAlreadyExtended: one emergency extension per lapse (owner decision 2026-10-20). An extension is
	// not extended again, and a license with an open or issued extension gets no second one; the next
	// step is a regular license.
	ErrAlreadyExtended = errors.New("this lapse already has an emergency extension; issue a regular license instead")
)

// EmergencyBasis is what an extension carries over: the installation's latest license that is not
// revoked, with the targets and features of the request it was issued from.
type EmergencyBasis struct {
	LicenseID    string
	CustomerID   int64
	Customer     string
	Installation string
	Targets      int
	Features     []string
	ValidUntil   time.Time
}

// GetEmergencyBasis finds the installation of licenseID and returns its latest license that is not
// revoked (latest end, then latest issue). An unknown or revoked licenseID is ErrNotFound, so the
// link of a revoked license extends nothing.
func GetEmergencyBasis(ctx context.Context, q audit.Q, licenseID string) (EmergencyBasis, error) {
	var b EmergencyBasis
	err := q.QueryRow(ctx, `SELECT l.license_id, l.customer_id, c.name, l.installation, r.targets, r.features, l.valid_until
		FROM licenses l
		JOIN customers c ON c.id = l.customer_id
		JOIN license_requests r ON r.id = l.request_id
		WHERE l.revoked_at IS NULL AND l.installation = (
			SELECT o.installation FROM licenses o WHERE o.license_id = $1 AND o.revoked_at IS NULL)
		ORDER BY l.valid_until DESC, l.issued_at DESC, l.license_id DESC
		LIMIT 1`, licenseID).Scan(&b.LicenseID, &b.CustomerID, &b.Customer, &b.Installation, &b.Targets, &b.Features,
		&b.ValidUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return EmergencyBasis{}, fmt.Errorf("%w: license %s", ErrNotFound, licenseID)
	}
	if err != nil {
		return EmergencyBasis{}, fmt.Errorf("store: read license for an emergency extension: %w", err)
	}
	return b, nil
}

// NewEmergency is an emergency extension a sales person asks for.
type NewEmergency struct {
	LicenseID string // any license of the installation; the latest one is carried over
	Days      int    // 0 = DefaultEmergencyDays; at most MaxEmergencyDays
	Reason    string // required: one line, at most MaxReasonLen characters
}

// checkEmergencyReason is checkReason with a message for the request form.
func checkEmergencyReason(reason string) error {
	switch {
	case !utf8.ValidString(reason) || strings.TrimSpace(reason) == "":
		return errors.New("a reason is required")
	case utf8.RuneCountInString(reason) > MaxReasonLen:
		return fmt.Errorf("the reason must be at most %d characters", MaxReasonLen)
	}
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return errors.New("the reason must be one line of plain text")
		}
	}
	return nil
}

// AddEmergencyRequest stores an emergency extension request for the installation of e.LicenseID,
// carrying over customer, installation, targets and features of its latest license. Nothing of the
// carried-over content comes from the caller. It is refused (InvalidError) when the term or reason
// is wrong or when a license already covers the extension (ErrExtensionNotNeeded), as of now; the
// signer's Issue checks again at signing time.
func AddEmergencyRequest(ctx context.Context, q audit.Q, e NewEmergency, now time.Time) (int64, error) {
	days := e.Days
	if days == 0 {
		days = DefaultEmergencyDays
	}
	if days < 1 || days > MaxEmergencyDays {
		return 0, &InvalidError{Err: fmt.Errorf("an emergency extension lasts 1 to %d days", MaxEmergencyDays)}
	}
	if err := checkEmergencyReason(e.Reason); err != nil {
		return 0, &InvalidError{Err: err}
	}
	b, err := GetEmergencyBasis(ctx, q, e.LicenseID)
	if err != nil {
		return 0, err
	}
	p, err := issuer.BuildPayload(issuer.Request{Installation: b.Installation, Customer: b.Customer, Targets: b.Targets,
		Features: b.Features, Days: days}, now)
	if err != nil {
		return 0, &InvalidError{Err: err}
	}
	if err := CheckExtensionAllowed(ctx, q, b.LicenseID, 0); err != nil {
		return 0, err
	}
	if err := CheckEmergencyNeeded(ctx, q, p); err != nil {
		return 0, err
	}
	var id int64
	err = q.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, months, features, kind, days,
			reason, extends)
		VALUES ($1, $2, $3, NULL, $4, 'emergency', $5, $6, $7) RETURNING id`,
		b.CustomerID, b.Installation, b.Targets, normalizedFeatures(b.Features), days, strings.TrimSpace(e.Reason),
		b.LicenseID).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: add emergency request: %w", err)
	}
	return id, nil
}

// CheckExtensionAllowed refuses a second emergency extension of the same lapse (ErrAlreadyExtended):
// when the license to carry over, licenseID, was itself issued from an emergency request, or when
// another emergency request extending it is signed with a license that is not revoked, or, for a new
// request (self = 0), is open. When request self is signed, open rivals do not count: the first one
// signed wins and the others are refused at their signing. Revoking an extension therefore allows a
// new one in its place.
func CheckExtensionAllowed(ctx context.Context, q audit.Q, licenseID string, self int64) error {
	var extension, taken bool
	err := q.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM licenses l JOIN license_requests r ON r.id = l.request_id
				WHERE l.license_id = $1 AND r.kind = 'emergency'),
			EXISTS (SELECT 1 FROM license_requests r
				WHERE r.kind = 'emergency' AND r.extends = $1 AND r.id <> $2 AND ((r.status = 'open' AND $2 = 0)
					OR (r.status = 'signed' AND EXISTS (SELECT 1 FROM licenses l
						WHERE l.request_id = r.id AND l.revoked_at IS NULL))))`, licenseID, self).Scan(&extension, &taken)
	if err != nil {
		return fmt.Errorf("store: check the license's emergency extensions: %w", err)
	}
	switch {
	case extension:
		return &InvalidError{Err: fmt.Errorf("%w (%s is an emergency extension)", ErrAlreadyExtended, licenseID)}
	case taken:
		return &InvalidError{Err: fmt.Errorf("%w (%s already has one, requested or issued)", ErrAlreadyExtended, licenseID)}
	}
	return nil
}

// CheckEmergencyNeeded refuses an extension payload p when a license of its installation that is
// not revoked and is valid on p's start day ends on or after p ends (ErrExtensionNotNeeded).
func CheckEmergencyNeeded(ctx context.Context, q audit.Q, p license.Payload) error {
	var id string
	var until time.Time
	err := q.QueryRow(ctx, `SELECT license_id, valid_until FROM licenses
		WHERE installation = $1 AND revoked_at IS NULL AND valid_from <= $2 AND valid_until >= $3
		ORDER BY valid_until DESC, license_id LIMIT 1`, p.InstallationID, p.ValidFrom, p.ValidUntil).Scan(&id, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: check the installation's licenses: %w", err)
	}
	return &InvalidError{Err: fmt.Errorf("%w (%s ends %s, the extension would end %s); no extension is needed",
		ErrExtensionNotNeeded, id, until.UTC().Format("2006-01-02"), p.ValidUntil.UTC().Format("2006-01-02"))}
}

// CheckStartsBeforeExtension refuses a license payload p that starts before an emergency
// extension of its installation (not revoked) and does not replace it: Alice would keep the
// extension, the later start, in force until it ends. The fix is in the message.
func CheckStartsBeforeExtension(ctx context.Context, q audit.Q, p license.Payload) error {
	var id string
	var from time.Time
	err := q.QueryRow(ctx, `SELECT l.license_id, l.valid_from FROM licenses l
		JOIN license_requests r ON r.id = l.request_id
		WHERE r.kind = 'emergency' AND l.installation = $1 AND l.revoked_at IS NULL
		  AND l.valid_from > $2 AND l.license_id <> $3
		ORDER BY l.valid_from, l.license_id LIMIT 1`, p.InstallationID, p.ValidFrom, p.Replaces).Scan(&id, &from)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: check the installation's emergency extensions: %w", err)
	}
	return &InvalidError{Err: fmt.Errorf("%w (%s, from %s): start on or after %s, or replace %s", ErrStartsBeforeExtension,
		id, from.UTC().Format("2006-01-02"), from.UTC().Format("2006-01-02"), id)}
}
