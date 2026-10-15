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

// A dry run must say "due" exactly when the real run sends a summary, including for odd marks.
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
