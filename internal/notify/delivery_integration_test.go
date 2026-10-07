//go:build integration

package notify_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/testutil/fakesmtp"
	"alice/internal/testutil/pgtest"
)

func senderFor(t *testing.T, h harness, src notify.MailerSource) *notify.Sender {
	t.Helper()
	return &notify.Sender{Pool: h.d.App, Source: src, Catalog: mustCatalog(t), Clock: h.clk, Log: slog.New(slog.DiscardHandler)}
}

// drainUntilQuiet advances the fake clock to the next due row and drains, up to n times.
func drainUntilQuiet(t *testing.T, d *pgtest.DB, s *notify.Sender, clk *clock.Fake, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		var next *time.Time
		require.NoError(t, d.Owner.QueryRow(context.Background(),
			`SELECT min(next_attempt_at) FROM notifications_outbox WHERE status = 'pending'`).Scan(&next))
		if next == nil {
			return
		}
		if next.After(clk.Now()) {
			clk.Set(*next)
		}
		_, err := s.Drain(context.Background())
		require.NoError(t, err)
	}
}

// F-60: a message is retried with backoff (30 s doubling, at most 1 hour) until 24 hours after it was queued.
func TestRetriesLastTwentyFourHours(t *testing.T) {
	h := newHarness(t, nil)
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	fail := &fakeMailer{fail: 1 << 30}
	s := &notify.Sender{Pool: h.d.App, Mailer: fail, Catalog: mustCatalog(t), Clock: h.clk, Log: slog.New(slog.DiscardHandler)}
	queue(t, h.d, h.clk, "license.locked")
	start := h.clk.Now()
	drainUntilQuiet(t, h.d, s, h.clk, 100)
	assert.Equal(t, map[string]int{"failed": 1}, statuses(t, h.d))
	var attempts int
	require.NoError(t, h.d.Owner.QueryRow(context.Background(), `SELECT attempts FROM notifications_outbox`).Scan(&attempts))
	assert.GreaterOrEqual(t, h.clk.Now().Sub(start), notify.GiveUpAfter)
	assert.Less(t, h.clk.Now().Sub(start), notify.GiveUpAfter+time.Hour)
	assert.Equal(t, attempts, fail.calls, "every attempt was one send")
	assert.InDelta(t, 30, attempts, 4, "about 30 attempts over a day")
}

// F-60, owner step 4: SMTP down → retries, "failing" after three failed attempts; back up → each message once.
func TestF60OutageDeliversOnceAndRaisesFailing(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	in := input(srv, nil)
	in.Username, in.CAPEM = "", string(srv.CertPEM())
	_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	s := senderFor(t, h, h.s)
	srv.Down()
	queue(t, h.d, h.clk, "license.locked")
	queue(t, h.d, h.clk, "license.grace")
	drainUntilQuiet(t, h.d, s, h.clk, 2)
	d, err := h.s.Delivery(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, d.ConsecutiveFailures, notify.FailingAfter)
	assert.True(t, d.Failing())
	assert.Equal(t, "smtp.connect", d.LastFailureCode)
	assert.Equal(t, 2, d.Pending)
	require.NoError(t, srv.Up())
	drainUntilQuiet(t, h.d, s, h.clk, 20)
	assert.Equal(t, map[string]int{"sent": 2}, statuses(t, h.d))
	assert.Len(t, srv.Messages(), 2, "exactly once each")
	d, err = h.s.Delivery(ctx)
	require.NoError(t, err)
	assert.False(t, d.Failing())
	require.NotNil(t, d.LastSuccessAt)
}

// F-61: one refused recipient does not stop the others.
func TestF61PerRecipient(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	addUser(t, h.d, "bob", "admin", "bob@example.com", "tr", false)
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	srv.RejectRecipient("bob@example.com")
	in := input(srv, nil)
	in.Username, in.CAPEM = "", string(srv.CertPEM())
	_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	queue(t, h.d, h.clk, "license.locked")
	_, err = senderFor(t, h, h.s).Drain(ctx)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"sent": 1, "pending": 1}, statuses(t, h.d))
	var code string
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT last_error_code FROM notifications_outbox WHERE to_address = 'bob@example.com'`).Scan(&code))
	assert.Equal(t, "smtp.rejected", code)
	require.Len(t, srv.Messages(), 1)
	assert.Equal(t, []string{"ada@example.com"}, srv.Messages()[0].To)
}

// S-9: parallel drains count every failure; the delivery state is one UPDATE, not a read-modify-write.
func TestDeliveryCountIsExactUnderParallelDrains(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	for i := range 12 {
		n := string(rune('a' + i))
		addUser(t, h.d, "admin"+n, "admin", "admin"+n+"@example.com", "en", false)
	}
	queue(t, h.d, h.clk, "license.locked")
	s := &notify.Sender{Pool: h.d.App, Mailer: &fakeMailer{fail: 1 << 30}, Catalog: mustCatalog(t), Clock: h.clk, Log: slog.New(slog.DiscardHandler)}
	done := make(chan error, 4)
	for range 4 {
		go func() { _, err := s.Drain(ctx); done <- err }()
	}
	for range 4 {
		require.NoError(t, <-done)
	}
	d, err := h.s.Delivery(ctx)
	require.NoError(t, err)
	assert.Equal(t, 12, d.ConsecutiveFailures, "no lost increment")
	assert.Equal(t, 12, d.Pending)
	assert.Equal(t, "smtp.connect", d.LastFailureCode)
}

// Skipped rows (no SMTP) change no delivery state; the zero state reads as not failing.
func TestSkippedRowsLeaveTheDeliveryStateAlone(t *testing.T) {
	h := newHarness(t, nil)
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	queue(t, h.d, h.clk, "license.locked")
	_, err := senderFor(t, h, h.s).Drain(context.Background())
	require.NoError(t, err)
	d, err := h.s.Delivery(context.Background())
	require.NoError(t, err)
	assert.False(t, d.Failing())
	assert.Zero(t, d.ConsecutiveFailures)
	assert.Nil(t, d.LastSuccessAt)
}

// Failed24h counts rows that gave up recently.
func TestDeliveryCountsFailedRows(t *testing.T) {
	h := newHarness(t, nil)
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	s := &notify.Sender{Pool: h.d.App, Mailer: &fakeMailer{fail: 1 << 30}, Catalog: mustCatalog(t), Clock: h.clk, Log: slog.New(slog.DiscardHandler)}
	queue(t, h.d, h.clk, "license.locked")
	drainUntilQuiet(t, h.d, s, h.clk, 100)
	d, err := h.s.Delivery(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, d.Failed24h)
	assert.Zero(t, d.Pending)
}
