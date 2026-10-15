//go:build integration

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
	"alice/internal/vconsole/audit"
	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/vpgtest"
)

const revDay = 24 * time.Hour

// revokeEnv has a database with one customer and the given licenses (all valid, ending in 30 days).
func revokeEnv(t *testing.T, ids ...string) *vpgtest.DB {
	t.Helper()
	d := vpgtest.New(t)
	sales := d.As(t, "vendor_sales", "t_rev_sales")
	cid, err := store.AddCustomer(context.Background(), sales, store.NewCustomer{Name: "Rev Ltd"})
	require.NoError(t, err)
	for _, id := range ids {
		seedLicense(t, d, cid, id, now.Add(30*revDay), false)
	}
	return d
}

type revokeAudit struct {
	actor   string
	details string
}

func revokeAudits(t *testing.T, d *vpgtest.DB, licenseID string) []revokeAudit {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(),
		`SELECT actor, details::text FROM audit WHERE action = 'license.revoke' AND subject = $1 ORDER BY seq`, licenseID)
	require.NoError(t, err)
	defer rows.Close()
	var out []revokeAudit
	for rows.Next() {
		var a revokeAudit
		require.NoError(t, rows.Scan(&a.actor, &a.details))
		out = append(out, a)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestRevokeSetsTimeAndAuditsTheReason(t *testing.T) {
	d := revokeEnv(t, "L-1")
	owner := d.As(t, "vendor_owner", "t_rev_owner")
	ctx := context.Background()

	require.NoError(t, store.RevokeLicense(ctx, owner, "L-1", "customer closed the account", now))

	var at time.Time
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT revoked_at FROM licenses WHERE license_id = 'L-1'`).Scan(&at))
	assert.True(t, at.Equal(now))
	as := revokeAudits(t, d, "L-1")
	require.Len(t, as, 1)
	assert.Equal(t, "t_rev_owner", as[0].actor)
	assert.Contains(t, as[0].details, `"reason": "customer closed the account"`)
	assert.NoError(t, audit.Check(ctx, d.Owner))
}

func TestRevokeInsideACallerTransaction(t *testing.T) {
	d := revokeEnv(t, "L-1")
	owner := d.As(t, "vendor_owner", "t_rev_owner")
	ctx := context.Background()
	require.NoError(t, db.InTx(ctx, owner, func(tx pgx.Tx) error {
		return store.RevokeLicense(ctx, tx, "L-1", "key leaked", now)
	}))
	as := revokeAudits(t, d, "L-1")
	require.Len(t, as, 1)
	assert.Contains(t, as[0].details, `"reason": "key leaked"`)
}

func TestReasonDoesNotLeakIntoOtherTransactions(t *testing.T) {
	d := revokeEnv(t, "L-1", "L-2")
	owner := d.As(t, "vendor_owner", "t_rev_owner")
	ctx := context.Background()
	require.NoError(t, store.RevokeLicense(ctx, owner, "L-1", "first reason", now))
	// A plain update on the same pool (no reason set) keeps the old details.
	_, err := owner.Exec(ctx, `UPDATE licenses SET revoked_at = $1 WHERE license_id = 'L-2'`, now)
	require.NoError(t, err)
	as := revokeAudits(t, d, "L-2")
	require.Len(t, as, 1)
	assert.NotContains(t, as[0].details, "reason")
}

func TestRevokeTwiceIsRefused(t *testing.T) {
	d := revokeEnv(t, "L-1")
	owner := d.As(t, "vendor_owner", "t_rev_owner")
	ctx := context.Background()
	require.NoError(t, store.RevokeLicense(ctx, owner, "L-1", "first", now))
	err := store.RevokeLicense(ctx, owner, "L-1", "second", now.Add(time.Hour))
	assert.ErrorIs(t, err, store.ErrAlreadyRevoked)
	var at time.Time
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT revoked_at FROM licenses WHERE license_id = 'L-1'`).Scan(&at))
	assert.True(t, at.Equal(now), "the first time stays")
	assert.Len(t, revokeAudits(t, d, "L-1"), 1)
}

func TestRevokeUnknownIsNotFound(t *testing.T) {
	d := revokeEnv(t, "L-1")
	owner := d.As(t, "vendor_owner", "t_rev_owner")
	err := store.RevokeLicense(context.Background(), owner, "L-nope", "why", now)
	assert.ErrorIs(t, err, store.ErrNotFound)
	assert.NotErrorIs(t, err, store.ErrAlreadyRevoked)
	assert.Empty(t, revokeAudits(t, d, "L-nope"))
}

func TestSignerAndSalesCannotRevoke(t *testing.T) {
	d := revokeEnv(t, "L-1")
	for group, login := range map[string]string{"vendor_signer": "t_rev_signer", "vendor_sales": "t_rev_sales2"} {
		p := d.As(t, group, login)
		err := store.RevokeLicense(context.Background(), p, "L-1", "why", now)
		var pe *pgconn.PgError
		require.True(t, errors.As(err, &pe), "%s: %v", group, err)
		assert.Equal(t, "42501", pe.Code, group)
	}
	var revoked bool
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		`SELECT revoked_at IS NOT NULL FROM licenses WHERE license_id = 'L-1'`).Scan(&revoked))
	assert.False(t, revoked)
	assert.Empty(t, revokeAudits(t, d, "L-1"))
}

func TestRevokedLicenseDisappearsFromEndingList(t *testing.T) {
	d := revokeEnv(t, "L-1", "L-2")
	owner := d.As(t, "vendor_owner", "t_rev_owner")
	notifier := d.As(t, "vendor_notifier", "t_rev_notifier")
	ctx := context.Background()
	_, err := d.Owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('owner_email', 'boss@example.com')
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`)
	require.NoError(t, err)

	require.NoError(t, store.RevokeLicense(ctx, owner, "L-1", "refund", now))

	rows, err := store.ListLicenses(ctx, owner, now, 60, false)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "L-2", rows[0].LicenseID)
	all, err := store.ListLicenses(ctx, owner, now, 0, false)
	require.NoError(t, err)
	require.Len(t, all, 2)
	for _, r := range all {
		assert.Equal(t, r.LicenseID == "L-1", r.RevokedAt != nil)
	}

	n, err := notify.CreateReminders(ctx, notifier, now, "https://console.example.com")
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the license that is still valid gets a reminder")
	var c int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM reminders WHERE license_id = 'L-1'`).Scan(&c))
	assert.Zero(t, c)
}

func TestReasonRules(t *testing.T) {
	d := revokeEnv(t, "L-1")
	owner := d.As(t, "vendor_owner", "t_rev_owner")
	ctx := context.Background()
	bad := map[string]string{
		"empty":      "",
		"blank":      "   ",
		"too long":   strings.Repeat("a", 201),
		"LF":         "one\ntwo",
		"CR":         "one\rtwo",
		"CRLF":       "one\r\ntwo",
		"NUL":        "a\x00b",
		"tab":        "a\tb",
		"escape":     "a\x1b[31mb",
		"DEL":        "a\x7fb",
		"C1":         "a\u0085b",
		"RLO":        "a\u202eb",
		"isolate":    "a\u2066b",
		"zero width": "a\u200bb",
		"line sep":   "a b",
		"bad utf8":   "a\xffb",
	}
	for name, reason := range bad {
		err := store.RevokeLicense(ctx, owner, "L-1", reason, now)
		assert.ErrorIs(t, err, store.ErrInvalidReason, name)
	}
	var revoked bool
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM licenses WHERE license_id = 'L-1'`).Scan(&revoked))
	assert.False(t, revoked, "nothing changed")

	// 200 characters (multi-byte included) are fine.
	require.NoError(t, store.RevokeLicense(ctx, owner, "L-1", strings.Repeat("ä", 200), now))
}

func TestDatabaseSanitizesTheReasonItself(t *testing.T) {
	d := revokeEnv(t, "L-1")
	owner := d.As(t, "vendor_owner", "t_rev_owner")
	ctx := context.Background()
	// A caller that skips the Go checks: the trigger still makes one short line.
	require.NoError(t, db.InTx(ctx, owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('vendor.reason', $1, true)`,
			"line1\nline2\u202e"+strings.Repeat("x", 300)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE licenses SET revoked_at = $1 WHERE license_id = 'L-1'`, now)
		return err
	}))
	as := revokeAudits(t, d, "L-1")
	require.Len(t, as, 1)
	var reason string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT details->>'reason' FROM audit WHERE action = 'license.revoke'`).Scan(&reason))
	assert.Equal(t, 200, len([]rune(reason)))
	assert.True(t, strings.HasPrefix(reason, "line1 line2 "), reason)
	assert.NotContains(t, reason, "\n")
	assert.NotContains(t, reason, "\u202e")
}

func TestRevokeKeepsTheFileAndOtherColumns(t *testing.T) {
	d := revokeEnv(t, "L-1")
	owner := d.As(t, "vendor_owner", "t_rev_owner")
	ctx := context.Background()
	require.NoError(t, store.RevokeLicense(ctx, owner, "L-1", "why", now))
	var file, sha string
	var targets int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT file::text, file_sha256, targets FROM licenses WHERE license_id = 'L-1'`).Scan(&file, &sha, &targets))
	assert.Equal(t, "sha", sha)
	assert.Equal(t, 5, targets)

	// The guard still forbids every other column, with or without a reason.
	_, err := owner.Exec(ctx, `UPDATE licenses SET targets = 99 WHERE license_id = 'L-1'`)
	require.Error(t, err)
}
