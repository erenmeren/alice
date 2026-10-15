package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"alice/internal/license"
	"alice/internal/vconsole/audit"
)

// clockSkew is how far a license's signed issued_at may lie after the check time before it is
// reported: the signer machine's clock and the checking machine's clock may differ a little.
const clockSkew = 5 * time.Minute

// LicenseProblem is one finding of VerifyLicenses. Problem is a short fixed sentence: it never
// carries file bytes, payload values or an installation ID, so the report can go to a terminal,
// a ticket or a message without leaking customer data.
type LicenseProblem struct {
	LicenseID string
	Problem   string
}

// VerifyLicenses re-checks every stored license after a restore (or at any time), so a damaged
// or edited database is noticed before a wrong file is sent to a customer again. For each row,
// in license ID order, it checks:
//
//  1. sha256(file) equals file_sha256;
//  2. the file verifies with the product's own license.Check against ks: format, signature, a
//     key ID that ks knows, a valid payload. A revoked key is judged the way the product judges
//     it, at the license's own signed issued_at, not at now: a license issued before the key's
//     revoked_from stays valid, one issued at or after it (or any license of a key revoked
//     without a date) is a problem;
//  3. the signed payload agrees with the row: license ID, installation, key ID, issued_at,
//     valid_from, valid_until, targets and replaces. The customer name is not compared: the
//     payload holds the name at issue time and customer names may be corrected later.
//
// now is only used to report a license whose signed issued_at lies more than clockSkew after
// the check time (a clock error at issue, or a file that did not come from this console's
// normal path). An empty key set is an error: every file would be reported as signed by an
// unknown key, which hides real findings.
//
// It returns every problem, never stopping at the first, and the number of licenses checked.
// q must be allowed to read licenses.file (the owner, signer and sales logins and the web
// service can read license files; the notifier cannot, on purpose). err is only a database error.
func VerifyLicenses(ctx context.Context, q audit.Q, ks license.KeySet, now time.Time) (checked int, problems []LicenseProblem, err error) {
	if ks.Len() == 0 {
		return 0, nil, errors.New("store: verify licenses: the key set is empty")
	}
	rows, err := q.Query(ctx, `SELECT license_id, installation, key_id, issued_at, valid_from, valid_until,
			targets, replaces, file, file_sha256
		FROM licenses ORDER BY license_id`)
	if err != nil {
		return 0, nil, fmt.Errorf("store: verify licenses: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r storedLicense
		if err := rows.Scan(&r.LicenseID, &r.Installation, &r.KeyID, &r.IssuedAt, &r.ValidFrom, &r.ValidUntil,
			&r.Targets, &r.Replaces, &r.File, &r.FileSHA256); err != nil {
			return 0, nil, fmt.Errorf("store: verify licenses: %w", err)
		}
		checked++
		for _, p := range r.problems(ks, now) {
			problems = append(problems, LicenseProblem{LicenseID: r.LicenseID, Problem: p})
		}
	}
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("store: verify licenses: %w", err)
	}
	return checked, problems, nil
}

type storedLicense struct {
	LicenseID, Installation, KeyID, Replaces, FileSHA256 string
	IssuedAt, ValidFrom, ValidUntil                      time.Time
	Targets                                              int
	File                                                 []byte
}

// problems lists what is wrong with one stored license, as fixed sentences.
func (r storedLicense) problems(ks license.KeySet, now time.Time) []string {
	if len(r.File) == 0 {
		return []string{"the stored file is empty"}
	}
	var out []string
	sum := sha256.Sum256(r.File)
	if hex.EncodeToString(sum[:]) != r.FileSHA256 {
		out = append(out, "file_sha256 does not match the stored file")
	}
	f, err := license.Check(r.File, ks)
	if err != nil {
		// The payload of a file that does not verify is not trusted, so it is not compared.
		return append(out, checkProblem(err))
	}
	p := f.Payload
	for _, m := range []struct {
		differs bool
		column  string
	}{
		{p.LicenseID != r.LicenseID, "license ID"},
		{p.InstallationID != r.Installation, "installation"},
		{f.KeyID != r.KeyID, "key_id"},
		{!p.IssuedAt.Equal(r.IssuedAt), "issued_at"},
		{!p.ValidFrom.Equal(r.ValidFrom), "valid_from"},
		{!p.ValidUntil.Equal(r.ValidUntil), "valid_until"},
		{p.MaxTargets != r.Targets, "targets"},
		{p.Replaces != r.Replaces, "replaces"},
	} {
		if m.differs {
			out = append(out, "the row's "+m.column+" differs from the signed file")
		}
	}
	if p.IssuedAt.After(now.Add(clockSkew)) {
		out = append(out, "the signed issued_at is after the check time")
	}
	return out
}

// checkProblem names why license.Check refused a file. Only fixed texts and the product's own
// problem codes are used: the product's error messages for some cases quote parts of
// installation IDs.
func checkProblem(err error) string {
	var inv *license.InvalidError
	switch {
	case errors.Is(err, license.ErrUnknownKey):
		return "the file is signed by a key that is not in the key set"
	case errors.Is(err, license.ErrRevokedKey):
		return "the file is signed by a key that is revoked for its issue date"
	case errors.Is(err, license.ErrUnsupportedFormat):
		return "the file is in a newer format than this build reads"
	case errors.As(err, &inv):
		return "the file does not verify (" + inv.Problem + ")"
	default:
		return "the file does not verify"
	}
}
