//go:build integration

package notify_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/testutil/pgtest"
	"alice/locales"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

func addUser(t *testing.T, d *pgtest.DB, username, role, email, locale string, disabled bool) {
	t.Helper()
	var disabledAt *time.Time
	if disabled {
		now := time.Now()
		disabledAt = &now
	}
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO users (id, username, display_name, email, password_hash, role, locale, disabled_at, created_at, updated_at)
VALUES ($1, $2::text, $2::text, $3, '$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA', $4, $5, $6, now(), now())`,
		uuid.Must(uuid.NewV7()), username, email, role, locale, disabledAt)
	require.NoError(t, err)
}

func queue(t *testing.T, d *pgtest.DB, clk clock.Clock, template string) {
	t.Helper()
	require.NoError(t, db.InTx(context.Background(), d.App, func(tx pgx.Tx) error {
		return notify.AdminNotifier{Clock: clk}.NotifyAdmins(context.Background(), tx, template,
			map[string]string{"installation_id": "ALICE-X", "ends_at": "2027-10-01 00:00 UTC"})
	}))
}

func statuses(t *testing.T, d *pgtest.DB) map[string]int {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), "SELECT status, count(*) FROM notifications_outbox GROUP BY status")
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		require.NoError(t, rows.Scan(&s, &n))
		out[s] = n
	}
	return out
}

type fakeMailer struct {
	mu    sync.Mutex
	fail  int // fail this many sends first
	sent  map[string]int
	calls int
}

func (f *fakeMailer) Send(_ context.Context, m notify.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail > 0 {
		f.fail--
		return notify.ErrSMTPConnect
	}
	if f.sent == nil {
		f.sent = map[string]int{}
	}
	f.sent[m.To+"|"+m.Subject]++
	return nil
}

func sender(t *testing.T, d *pgtest.DB, clk clock.Clock, m notify.Mailer) *notify.Sender {
	t.Helper()
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	return &notify.Sender{Pool: d.App, Mailer: m, Catalog: cat, Clock: clk, Log: slog.New(slog.DiscardHandler)}
}

var start = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func TestNotifyAdminsQueuesOneEmailPerEnabledAdminWithAnAddress(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "tr", false)
	addUser(t, d, "noemail", "admin", "", "en", false)
	addUser(t, d, "gone", "admin", "gone@example.com", "en", true)
	addUser(t, d, "otto", "operator", "otto@example.com", "en", false)
	queue(t, d, clk, license.TemplateExpiryWarning)

	var to, locale, tpl string
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		"SELECT to_address, locale, template_key FROM notifications_outbox").Scan(&to, &locale, &tpl))
	assert.Equal(t, "ayse@example.com", to)
	assert.Equal(t, "tr", locale)
	assert.Equal(t, license.TemplateExpiryWarning, tpl)
	assert.Equal(t, map[string]int{"pending": 1}, statuses(t, d))

	err := db.InTx(context.Background(), d.App, func(tx pgx.Tx) error {
		return notify.AdminNotifier{Clock: clk}.NotifyAdmins(context.Background(), tx, "Bad Template", nil)
	})
	assert.Error(t, err)
}

// L-18: without SMTP nothing fails; the email is recorded as skipped.
func TestDrainWithoutSMTPSkips(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, d, clk, license.TemplateGrace)
	n, err := sender(t, d, clk, nil).Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, map[string]int{"skipped_no_smtp": 1}, statuses(t, d))
}

// F-60 in its Phase 2 form: retries with backoff, then delivered exactly once.
func TestDrainRetriesWithBackoff(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, d, clk, license.TemplateLocked)
	m := &fakeMailer{fail: 2}
	s := sender(t, d, clk, m)

	_, err := s.Drain(context.Background())
	require.NoError(t, err)
	var attempts int
	var next time.Time
	var code string
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		"SELECT attempts, next_attempt_at, last_error_code FROM notifications_outbox").Scan(&attempts, &next, &code))
	assert.Equal(t, 1, attempts)
	assert.True(t, next.Equal(start.Add(30*time.Second)))
	assert.Equal(t, "smtp.connect", code)

	n, err := s.Drain(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "not due yet")
	clk.Advance(30 * time.Second)
	_, err = s.Drain(context.Background())
	require.NoError(t, err)
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT next_attempt_at FROM notifications_outbox").Scan(&next))
	assert.True(t, next.Equal(start.Add(90*time.Second)), "the second retry waits twice as long")
	clk.Advance(time.Minute)
	_, err = s.Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"sent": 1}, statuses(t, d))
	assert.Len(t, m.sent, 1)
}

// The retries span about 2 hours; the log says "retried" only when the email will be retried
// and says so when Alice gives up (B5).
func TestDrainGivesUpAfterMaxAttempts(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, d, clk, license.TemplateLocked)
	s := sender(t, d, clk, &fakeMailer{fail: 1000})
	var logs bytes.Buffer
	s.Log = slog.New(slog.NewTextHandler(&logs, nil))
	for range notify.MaxAttempts {
		_, err := s.Drain(context.Background())
		require.NoError(t, err)
		var next time.Time
		require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT next_attempt_at FROM notifications_outbox").Scan(&next))
		if statuses(t, d)["pending"] == 1 {
			clk.Set(next) // the next attempt as early as allowed
		}
	}
	assert.Equal(t, map[string]int{"failed": 1}, statuses(t, d))
	span := clk.Now().Sub(start)
	assert.True(t, span > 115*time.Minute && span < 125*time.Minute, "first to last attempt: %s", span)

	assert.Equal(t, notify.MaxAttempts-1, strings.Count(logs.String(), "it will be retried"))
	assert.Equal(t, 1, strings.Count(logs.String(), "email not sent after "+strconv.Itoa(notify.MaxAttempts)+" attempts; giving up"))
	assert.Equal(t, notify.MaxAttempts-1, strings.Count(logs.String(), "level=WARN"))
	assert.Equal(t, 1, strings.Count(logs.String(), "level=ERROR"))
}

// Two drains at once (for example during an update) never send an email twice.
func TestConcurrentDrainsSendEachEmailOnce(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	for i := range 5 {
		addUser(t, d, "admin"+string(rune('a'+i)), "admin", "admin"+string(rune('a'+i))+"@example.com", "en", false)
	}
	for _, tpl := range license.Templates() {
		queue(t, d, clk, tpl)
	}
	m := &fakeMailer{}
	s := sender(t, d, clk, m)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Drain(context.Background())
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, 30, m.calls, "6 templates x 5 admins")
	for k, n := range m.sent {
		assert.Equal(t, 1, n, k)
	}
	assert.Equal(t, map[string]int{"sent": 30}, statuses(t, d))
}
