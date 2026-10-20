//go:build integration

package issue_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/issue"
	"alice/internal/vconsole/sign"
	"alice/internal/vconsole/store"
)

const day = 24 * time.Hour

// lapsed records a license for a new installation that ended three days before now, issued from
// a request with 7 targets and two features, and returns the installation ID.
func (e env) lapsed(t *testing.T, id string) string {
	t.Helper()
	ctx := context.Background()
	inst := license.NewInstallationID()
	var reqID int64
	require.NoError(t, e.d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, features, status)
		VALUES ($1, $2, 7, '{audit,sso}', 'signed') RETURNING id`, e.cust, inst).Scan(&reqID))
	_, err := e.d.Owner.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256)
		VALUES ($1, $2, $3, $4, 'vk-2026-01', $5, $5, $6, 7, 'x', 'sha')`, id, reqID, e.cust, inst, now.Add(-368*day), now.Add(-3*day))
	require.NoError(t, err)
	return inst
}

func (e env) emergency(t *testing.T, licenseID string, days int) (int64, string) {
	t.Helper()
	ctx := context.Background()
	id, err := store.AddEmergencyRequest(ctx, e.sales, store.NewEmergency{LicenseID: licenseID, Days: days,
		Reason: "Renewal PO delayed"}, now)
	require.NoError(t, err)
	r, err := store.GetRequest(ctx, e.signer, id)
	require.NoError(t, err)
	return id, store.RequestHash(r)
}

func TestIssueEmergencyExtension(t *testing.T) {
	e := setup(t, "em1")
	ctx := context.Background()
	inst := e.lapsed(t, "LIC-2025-000001")
	id, hash := e.emergency(t, "LIC-2025-000001", 14)

	signAt := now.Add(2 * time.Hour) // the signer acts later the same day
	var confirmed license.Payload
	res, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash,
		Confirm: func(p license.Payload, _ string) error { confirmed = p; return nil }}, signAt)
	require.NoError(t, err)

	f, err := sign.Verify(res.File, e.key)
	require.NoError(t, err)
	p := f.Payload
	assert.Equal(t, confirmed, p, "the signer confirmed exactly what was signed")
	day0 := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	assert.True(t, p.ValidFrom.Equal(day0), "from the start of the signing day (UTC)")
	assert.True(t, p.ValidUntil.Equal(day0.Add(14*day)))
	assert.Equal(t, inst, p.InstallationID)
	assert.Equal(t, "Acme Ltd", p.Customer)
	assert.Equal(t, 7, p.MaxTargets)
	assert.Equal(t, []string{"audit", "sso"}, p.Features)
	assert.Empty(t, p.Replaces, "an ordinary license, not a correction")
	assert.Equal(t, license.FormatVersion, p.Format, "the signed format is unchanged")

	var details []byte
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT details FROM audit WHERE action = 'license.issue' AND subject = $1`,
		res.LicenseID).Scan(&details))
	var got map[string]any
	require.NoError(t, json.Unmarshal(details, &got))
	assert.Equal(t, "emergency", got["kind"])
	assert.EqualValues(t, 14, got["days"])

	var title, body string
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT title, body FROM notifications WHERE kind = 'license.issued' AND subject = $1`,
		res.LicenseID).Scan(&title, &body))
	assert.Equal(t, "Emergency extension issued: Acme Ltd ("+res.LicenseID+")", title)
	assert.Contains(t, body, "Emergency extension: 14 days\nReason: Renewal PO delayed\n")

	var status string
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT status FROM license_requests WHERE id = $1`, id).Scan(&status))
	assert.Equal(t, "signed", status)
	require.NoError(t, audit.Check(ctx, e.d.Owner))

	rows, err := store.ListLicenses(ctx, e.sales, signAt, 0, false)
	require.NoError(t, err)
	for _, r := range rows {
		assert.Equal(t, r.LicenseID == res.LicenseID, r.Emergency, r.LicenseID)
	}
}

// What was true when the extension was asked for is checked again when it is signed.
func TestIssueEmergencyRechecksAtSigningTime(t *testing.T) {
	e := setup(t, "em2")
	ctx := context.Background()

	t.Run("a license now covers it", func(t *testing.T) {
		inst := e.lapsed(t, "LIC-2025-000010")
		id, hash := e.emergency(t, "LIC-2025-000010", 14)
		renewal, rhash := e.request(t, inst, 7, "")
		_, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: renewal, ExpectedHash: rhash}, now)
		require.NoError(t, err)

		_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
		assert.ErrorIs(t, err, store.ErrExtensionNotNeeded)
		var status string
		require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT status FROM license_requests WHERE id = $1`, id).Scan(&status))
		assert.Equal(t, "open", status, "nothing recorded; the request stays open to be cancelled")
	})

	t.Run("the carried-over license was revoked", func(t *testing.T) {
		e.lapsed(t, "LIC-2025-000020")
		id, hash := e.emergency(t, "LIC-2025-000020", 14)
		require.NoError(t, store.RevokeLicense(ctx, e.d.Owner, "LIC-2025-000020", "issued in error", now))
		_, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: id, ExpectedHash: hash}, now)
		assert.ErrorIs(t, err, issue.ErrExtendedRevoked)
	})
}

// A normal license that starts before an extension and does not replace it is refused at signing
// time too (the extension may have been issued after the request was made).
func TestIssueRefusesALicenseStartingBeforeAnExtension(t *testing.T) {
	e := setup(t, "em3")
	ctx := context.Background()
	inst := e.lapsed(t, "LIC-2025-000030")
	// The backdated renewal is asked for first (a correction of the lapsed license)...
	backdated, err := store.AddRequest(ctx, e.sales, store.NewRequest{CustomerID: e.cust, Installation: inst, Targets: 7,
		From: now.Add(-3 * day).Format("2006-01-02"), Months: 12, Replaces: "LIC-2025-000030"}, now)
	require.NoError(t, err)
	r, err := store.GetRequest(ctx, e.signer, backdated)
	require.NoError(t, err)
	// ...then the extension is issued.
	ext, ehash := e.emergency(t, "LIC-2025-000030", 14)
	extRes, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: ext, ExpectedHash: ehash}, now)
	require.NoError(t, err)

	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: backdated, ExpectedHash: store.RequestHash(r)}, now)
	assert.ErrorIs(t, err, store.ErrStartsBeforeExtension)
	assert.ErrorContains(t, err, extRes.LicenseID)
}

// One extension per lapse holds at signing too: a second request for the same lapse (made before the
// rule, or racing the first) is refused once the first is issued.
func TestIssueRefusesASecondExtensionOfTheSameLapse(t *testing.T) {
	e := setup(t, "em-once")
	ctx := context.Background()
	inst := e.lapsed(t, "LIC-2025-000009")
	first, hash := e.emergency(t, "LIC-2025-000009", 14)
	var second int64
	require.NoError(t, e.d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets, features,
		kind, months, days, reason, extends) VALUES ($1, $2, 7, '{audit,sso}', 'emergency', NULL, 7, 'again', 'LIC-2025-000009')
		RETURNING id`, e.cust, inst).Scan(&second))

	_, err := issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: first, ExpectedHash: hash}, now)
	require.NoError(t, err)
	r, err := store.GetRequest(ctx, e.signer, second)
	require.NoError(t, err)
	_, err = issue.Issue(ctx, e.signer, e.key, issue.Params{RequestID: second, ExpectedHash: store.RequestHash(r)}, now)
	assert.ErrorIs(t, err, store.ErrAlreadyExtended)
}
