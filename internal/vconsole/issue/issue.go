// Package issue turns an open license request into a signed license in one database transaction:
// lock the request, check it is still what the signer saw, apply the correction rules, sign,
// record the license and close the request (the database writes the audit rows). If any step fails nothing is
// recorded.
package issue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/db"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/store"
)

// Errors. They mirror the refusals of licensectl's ledger.
var (
	ErrNotOpen            = errors.New("issue: the request is not open")
	ErrRequestChanged     = errors.New("issue: the request changed after it was shown; look at it again")
	ErrUnknownReplaced    = errors.New("issue: the license named by the request is not recorded")
	ErrOtherInstallation  = errors.New("issue: the replaced license is for another installation")
	ErrShortensTerm       = errors.New("issue: the correction ends earlier than the license it replaces; set Shorten if that is intended")
	ErrDuplicateLicenseID = errors.New("issue: a license with this ID was already issued")
	// ErrNotConfirmed is what a Confirm hook returns when the operator answers no.
	ErrNotConfirmed = errors.New("issue: the signer did not confirm the license; nothing was signed")
	// ErrOutcomeUnknown: every write succeeded but the commit did not report back (a lost
	// connection, a cancel during COMMIT). The license may or may not be recorded.
	ErrOutcomeUnknown = errors.New("issue: the database did not confirm the commit; the license may or may not be recorded")
	// ErrSignedBytesChanged: the signed file's payload is not the one whose signed-bytes digest
	// the operator confirmed. Nothing is recorded.
	ErrSignedBytesChanged = errors.New("issue: the signed license is not the one that was confirmed (its signed bytes differ); nothing was recorded")
)

// Params selects the request and what the signer saw.
type Params struct {
	RequestID    int64
	ExpectedHash string // store.RequestHash of the request as the signer saw it
	LicenseID    string // "" = LIC-<year>-<6 random digits>
	Shorten      bool   // allow a correction to end earlier than the license it replaces
	// Confirm, when set, is shown the payload exactly as it will be signed and the SHA-256 (hex)
	// of the bytes the signer receives, after the correction rules passed and before the signer
	// is called (so before any PIN prompt). A non-nil error aborts the issue and nothing is
	// recorded; the request stays open. After signing, the signed file's signed bytes must have
	// this digest (ErrSignedBytesChanged otherwise, nothing recorded). It runs inside the transaction: the request row stays
	// locked while the operator reads, so the caller must bound how long it waits.
	Confirm func(p license.Payload, signedSHA256 string) error
}

// Result is the issued license.
type Result struct {
	LicenseID  string
	File       []byte
	KeyID      string
	FileSHA256 string
	ValidUntil time.Time
}

// Issue signs the request with s. pool must act as a signer login.
func Issue(ctx context.Context, pool *pgxpool.Pool, s sign.Signer, p Params, now time.Time) (Result, error) {
	var res Result
	written := false
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		// Lock the row so two signers cannot both issue from one request.
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM license_requests WHERE id = $1 FOR UPDATE`, p.RequestID).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("issue: lock request: %w", err)
		}
		if status != "open" {
			return ErrNotOpen
		}
		req, err := store.GetRequest(ctx, tx, p.RequestID)
		if err != nil {
			return err
		}
		if store.RequestHash(req) != p.ExpectedHash {
			return ErrRequestChanged
		}
		payload, err := issuer.BuildPayload(issuer.Request{
			Installation: req.Installation, Customer: req.Customer, Targets: req.Targets, From: req.From,
			Months: req.Months, Features: req.Features, Replaces: req.Replaces, LicenseID: p.LicenseID,
		}, now)
		if err != nil {
			return fmt.Errorf("issue: the request can no longer become a license (%w); cancel it and make a new request", err)
		}
		if err := checkCorrection(ctx, tx, payload, p.Shorten); err != nil {
			return err
		}
		confirmed := ""
		if p.Confirm != nil {
			// The signers sign the normalized payload; the operator confirms exactly that.
			payload = issuer.NormalizePayload(payload)
			_, sum, err := sign.PayloadDigest(payload)
			if err != nil {
				return fmt.Errorf("issue: the request can no longer become a license (%w); cancel it and make a new request", err)
			}
			if err := p.Confirm(payload, sum); err != nil {
				if errors.Is(err, ErrNotConfirmed) {
					return err
				}
				return fmt.Errorf("issue: confirm: %w", err)
			}
			confirmed = sum
		}
		raw, err := s.Issue(ctx, payload)
		if err != nil {
			return fmt.Errorf("issue: sign: %w", err)
		}
		// Never record a file the product would not accept.
		signedFile, err := sign.Verify(raw, s)
		if err != nil {
			return fmt.Errorf("issue: the signed file does not verify: %w", err)
		}
		// Never record a license other than the one the operator confirmed. This catches a signer
		// that signed another payload than it was handed; it cannot catch malware that controls
		// the signer computer, which can show one license and send its own to the card.
		if confirmed != "" {
			got := sha256.Sum256(license.SignedBytes(signedFile.Payload))
			if hex.EncodeToString(got[:]) != confirmed {
				return ErrSignedBytesChanged
			}
		}
		sum := sha256.Sum256(raw)
		res = Result{LicenseID: payload.LicenseID, File: raw, KeyID: s.KeyID(), FileSHA256: hex.EncodeToString(sum[:]),
			ValidUntil: payload.ValidUntil}
		_, err = tx.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
			valid_from, valid_until, targets, replaces, file, file_sha256)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			payload.LicenseID, req.ID, req.CustomerID, payload.InstallationID, s.KeyID(), payload.IssuedAt,
			payload.ValidFrom, payload.ValidUntil, payload.MaxTargets, payload.Replaces, raw, res.FileSHA256)
		if db.IsUniqueViolationOn(err, "licenses_pkey") {
			return ErrDuplicateLicenseID
		}
		if err != nil {
			return fmt.Errorf("issue: record license: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE license_requests SET status = 'signed' WHERE id = $1`, req.ID); err != nil {
			return fmt.Errorf("issue: close request: %w", err)
		}
		written = true
		return nil
	})
	if err != nil && written {
		return Result{}, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
	}
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// checkCorrection applies the rules licensectl's ledger applies to a license that replaces another.
func checkCorrection(ctx context.Context, q audit.Q, p license.Payload, shorten bool) error {
	if p.Replaces == "" {
		return nil
	}
	var inst string
	var until time.Time
	err := q.QueryRow(ctx, `SELECT installation, valid_until FROM licenses WHERE license_id = $1`, p.Replaces).Scan(&inst, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnknownReplaced
	}
	if err != nil {
		return fmt.Errorf("issue: read replaced license: %w", err)
	}
	if inst != p.InstallationID {
		return ErrOtherInstallation
	}
	if p.ValidUntil.Before(until) && !shorten {
		return ErrShortensTerm
	}
	return nil
}
