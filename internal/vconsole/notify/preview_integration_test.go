//go:build integration

package notify_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/vpgtest"
)

// A dry run must say "due" exactly when the real run creates a summary, including for odd marks.
func TestPreviewAndWeeklySummaryAgreeOnWhetherASummaryIsDue(t *testing.T) {
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	mark := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	for i, c := range []struct {
		name, last string // "" means no mark at all
		due        bool
	}{
		{"no mark", "", true},
		{"8 days ago", mark(-8 * 24 * time.Hour), true},
		{"6 days ago", mark(-6 * 24 * time.Hour), false},
		{"30 minutes in the future", mark(30 * time.Minute), false},
		{"2 hours in the future", mark(2 * time.Hour), true},
		{"unparseable", "last tuesday", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := vpgtest.New(t)
			p := d.As(t, "vendor_notifier", fmt.Sprintf("t_pv%d_notifier", i))
			if c.last != "" {
				setSetting(t, d, "last_summary_at", c.last)
			}
			pre, err := notify.PreviewRun(context.Background(), p, now)
			require.NoError(t, err)
			sent, err := notify.WeeklySummary(context.Background(), p, now)
			require.NoError(t, err)
			assert.Equal(t, c.due, sent, "real run")
			assert.Equal(t, sent, pre.Summary, "the dry run agrees with the real run")
		})
	}
}

// The dry run lists exactly the notices the real run then creates, and writes nothing itself.
func TestPreviewListsTheNoticesTheRunCreates(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_pv_all_notifier")
	now := summaryNow
	addWebUser(t, d, "ayse", "sales")
	addWebUser(t, d, "boss", "owner")
	seedLicense(t, d, lic{id: "LIC-P1", customer: "A", requestedBy: "web:ayse", validUntil: now.Add(25 * day)})
	seedLicense(t, d, lic{id: "LIC-P2", customer: "B", requestedBy: "web:boss", validUntil: now.Add(70 * day)})
	seedIssued(t, d, "LIC-NIGHT", "Night Co", "sig_a", ist(t, 2026, 10, 12, 23, 30, 0))
	before := countNotices(t, d)

	pre, err := notify.PreviewRun(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, before, countNotices(t, d), "the dry run writes nothing")
	assert.Empty(t, reminderRows(t, d, "LIC-P1"))
	assert.Equal(t, 2, pre.Reminders)
	assert.True(t, pre.Summary)
	var preKeys []string
	for _, n := range pre.Notices {
		preKeys = append(preKeys, n.DedupeKey)
	}
	assert.ElementsMatch(t, []string{"ending:LIC-P1:30", "ending:LIC-P1:30:ayse", "ending:LIC-P2:90",
		"summary:2026-10-15", "unusual:2026-10-15"}, preKeys)

	_, err = notify.CreateReminders(ctx, p, now)
	require.NoError(t, err)
	_, err = notify.WeeklySummary(ctx, p, now)
	require.NoError(t, err)
	var realKeys []string
	for _, kind := range []string{"license.ending", "summary.weekly", "activity.unusual"} {
		for _, n := range notices(t, d, kind) {
			realKeys = append(realKeys, n.DedupeKey)
		}
	}
	assert.ElementsMatch(t, preKeys, realKeys)
	for _, n := range pre.Notices {
		if n.Kind == "summary.weekly" {
			assert.Equal(t, notices(t, d, "summary.weekly")[0].Body, n.Body, "the same body")
		}
	}
}
