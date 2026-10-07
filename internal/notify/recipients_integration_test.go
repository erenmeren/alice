//go:build integration

package notify_test

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

func recipientsOfOneEmail(t *testing.T, h harness) []string {
	t.Helper()
	_, err := h.d.Owner.Exec(context.Background(), `DELETE FROM notifications_outbox`)
	require.NoError(t, err)
	queue(t, h.d, h.clk, "license.locked")
	rows, err := h.d.Owner.Query(context.Background(), `SELECT to_address || ':' || locale FROM notifications_outbox`)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	sort.Strings(got)
	return got
}

// R42 row 6: one recipients setting decides every email Alice sends to Administrators.
func TestRecipientsSettingDecidesEveryEmail(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	addUser(t, h.d, "ada", "admin", "ada@example.com", "tr", false)
	addUser(t, h.d, "op", "operator", "op@example.com", "en", false)
	assert.Equal(t, []string{"ada@example.com:tr"}, recipientsOfOneEmail(t, h), "default: every Administrator")
	def, err := h.s.Recipients(ctx)
	require.NoError(t, err)
	assert.Equal(t, notify.Recipients{Administrators: true}, def)

	r, err := h.s.SaveRecipients(ctx, h.who, 0, notify.Recipients{Administrators: true, Addresses: []notify.Address{
		{Email: "noc@example.com", Locale: "en"}, {Email: "ADA@example.com", Locale: "en"}}})
	require.NoError(t, err)
	assert.Equal(t, 1, r.Version)
	assert.Equal(t, []string{"ada@example.com:tr", "noc@example.com:en"}, recipientsOfOneEmail(t, h),
		"an address that is an Administrator's gets one email, in the Administrator's language")

	_, err = h.s.SaveRecipients(ctx, h.who, 1, notify.Recipients{Addresses: []notify.Address{{Email: "noc@example.com", Locale: "tr"}}})
	require.NoError(t, err)
	assert.Equal(t, []string{"noc@example.com:tr"}, recipientsOfOneEmail(t, h))

	for _, bad := range []notify.Recipients{
		{},
		{Addresses: []notify.Address{{Email: "not an address", Locale: "en"}}},
		{Addresses: []notify.Address{{Email: "a@example.com", Locale: "de"}}},
		{Addresses: []notify.Address{{Email: "a@example.com", Locale: "en"}, {Email: "A@example.com", Locale: "tr"}}},
		{Administrators: true, Addresses: make([]notify.Address, notify.MaxExtraRecipients+1)},
	} {
		_, err := h.s.SaveRecipients(ctx, h.who, 2, bad)
		var v validate.Errors
		assert.True(t, errors.As(err, &v), "%+v: %v", bad, err)
	}
	_, err = h.s.SaveRecipients(ctx, h.who, 1, notify.Recipients{Administrators: true})
	assert.ErrorIs(t, err, notify.ErrVersion)
	assert.Equal(t, 2, countAudit(t, h.d, "settings.recipients_changed"))
}

// S-4: the audit row names the addresses and is written with the change.
func TestRecipientsChangeAuditNamesTheAddresses(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	_, err := h.s.SaveRecipients(ctx, h.who, 0, notify.Recipients{Administrators: false, Addresses: []notify.Address{
		{Email: "noc@example.com", Locale: "en"}, {Email: "ops@example.org", Locale: "tr"}}})
	require.NoError(t, err)
	var admins, addrs, count string
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT details->>'administrators', details->>'addresses', details->>'address_count'
FROM audit_log WHERE action = 'settings.recipients_changed'`).Scan(&admins, &addrs, &count))
	assert.Equal(t, "false", admins)
	assert.Equal(t, "noc@example.com, ops@example.org", addrs)
	assert.Equal(t, "2", count)

	// A rejected change leaves neither the setting nor an audit row.
	_, err = h.s.SaveRecipients(ctx, h.who, 5, notify.Recipients{Administrators: true})
	require.ErrorIs(t, err, notify.ErrVersion)
	assert.Equal(t, 1, countAudit(t, h.d, "settings.recipients_changed"))
}

func TestSaveGeneralValidates(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	g, err := h.s.SaveGeneral(ctx, h.who, 0, settings.General{PublicURL: "https://alice.example.com/", RetiredKeyRetentionDays: 90})
	require.NoError(t, err)
	assert.Equal(t, "https://alice.example.com", g.PublicURL, "a trailing slash is dropped")
	assert.Equal(t, 1, g.Version)
	stored, err := settings.GetGeneral(ctx, h.d.App)
	require.NoError(t, err)
	assert.Equal(t, g, stored)
	got, err := h.s.General(ctx)
	require.NoError(t, err)
	assert.Equal(t, g, got)
	for _, bad := range []settings.General{
		{PublicURL: "http://alice.example.com", RetiredKeyRetentionDays: 30},
		{PublicURL: "https://alice.example.com/app", RetiredKeyRetentionDays: 30},
		{PublicURL: "https://a@alice.example.com", RetiredKeyRetentionDays: 30},
		{PublicURL: "https://alice.example.com?x", RetiredKeyRetentionDays: 30},
		{PublicURL: "https://alice.example.com#", RetiredKeyRetentionDays: 30},
		{PublicURL: "https://", RetiredKeyRetentionDays: 30},
		{PublicURL: "https://bad host", RetiredKeyRetentionDays: 30},
		{PublicURL: "", RetiredKeyRetentionDays: 0},
		{PublicURL: "", RetiredKeyRetentionDays: 3651},
	} {
		_, err := h.s.SaveGeneral(ctx, h.who, 1, bad)
		var v validate.Errors
		assert.True(t, errors.As(err, &v), "%+v", bad)
	}
	_, err = h.s.SaveGeneral(ctx, h.who, 0, settings.General{RetiredKeyRetentionDays: 30})
	assert.ErrorIs(t, err, notify.ErrVersion)
	_, err = h.s.SaveGeneral(ctx, h.who, 1, settings.General{PublicURL: "https://alice.example.com:9443", RetiredKeyRetentionDays: 30})
	require.NoError(t, err)
	assert.Equal(t, 2, countAudit(t, h.d, "settings.general_changed"))
}
