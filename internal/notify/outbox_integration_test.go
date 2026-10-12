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

// Retries last until GiveUpAfter; the log says "retried" only when the email will be retried and says so when Alice
// gives up (B5).
func TestDrainGivesUpAfterGiveUpAfter(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, d, clk, license.TemplateLocked)
	s := sender(t, d, clk, &fakeMailer{fail: 1 << 30})
	var logs bytes.Buffer
	s.Log = slog.New(slog.NewTextHandler(&logs, nil))
	drainUntilQuiet(t, d, s, clk, 100)
	assert.Equal(t, map[string]int{"failed": 1}, statuses(t, d))
	assert.GreaterOrEqual(t, clk.Now().Sub(start), notify.GiveUpAfter)
	var attempts int
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT attempts FROM notifications_outbox").Scan(&attempts))

	assert.Equal(t, attempts-1, strings.Count(logs.String(), "it will be retried"))
	assert.Equal(t, 1, strings.Count(logs.String(), "email not sent after "+strconv.Itoa(attempts)+" attempts; giving up"))
	assert.Equal(t, attempts-1, strings.Count(logs.String(), "level=WARN"))
	assert.Equal(t, 1, strings.Count(logs.String(), "level=ERROR"))
	assert.Equal(t, 1, strings.Count(logs.String(), "event=notify.gave_up"))
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

// probeMailer checks, while it "sends", that the e-mail's row is neither locked nor holding a pooled connection, and
// that another drain does not pick the row up meanwhile.
type probeMailer struct {
	t      *testing.T
	d      *pgtest.DB
	other  *notify.Sender
	calls  int
	locked error
	inUse  int32
	again  int
}

func (p *probeMailer) Send(ctx context.Context, _ notify.Message) error {
	p.calls++
	tx, err := p.d.Owner.Begin(ctx)
	require.NoError(p.t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, p.locked = tx.Exec(ctx, `SELECT id FROM notifications_outbox FOR UPDATE NOWAIT`)
	p.inUse = p.d.App.Stat().AcquiredConns()
	if p.other != nil {
		p.again, err = p.other.Drain(ctx)
		require.NoError(p.t, err)
	}
	return nil
}

// Review L-6: the SMTP exchange runs outside any database transaction. The row is leased first (it is not due while
// it is being sent), so a failed commit after the server accepted the message cannot roll the row back to a due
// "pending" and send it again at the next drain, and no pooled connection waits on the mail server.
func TestDrainSendsOutsideTheTransaction(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, d, clk, license.TemplateLocked)
	m := &probeMailer{t: t, d: d}
	s := sender(t, d, clk, m)
	m.other = sender(t, d, clk, &fakeMailer{})
	n, err := s.Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, m.calls)
	assert.NoError(t, m.locked, "no row lock is held during the send")
	assert.Zero(t, m.inUse, "no pooled connection is held during the send")
	assert.Zero(t, m.again, "a second drain does not take a row that is being sent")
	assert.Equal(t, map[string]int{"sent": 1}, statuses(t, d))
	var attempts int
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT attempts FROM notifications_outbox").Scan(&attempts))
	assert.Equal(t, 1, attempts)
}

type hookMailer struct{ hook func() error }

func (h hookMailer) Send(context.Context, notify.Message) error { return h.hook() }

// A send that outlives its lease (a stalled mail server) does not overwrite the outcome of the drain that took the
// row after the lease ended: the outcome is fenced on the attempt count.
func TestAnOutcomeAfterTheLeaseIsDropped(t *testing.T) {
	for _, slowErr := range []error{nil, notify.ErrSMTPConnect} {
		d := pgtest.New(t)
		clk := clock.NewFake(start)
		addUser(t, d, "ayse", "admin", "ayse@example.com", "en", false)
		queue(t, d, clk, license.TemplateLocked)
		fast := &fakeMailer{}
		slow := sender(t, d, clk, hookMailer{hook: func() error {
			clk.Advance(3 * time.Minute) // past the lease
			n, err := sender(t, d, clk, fast).Drain(context.Background())
			require.NoError(t, err)
			require.Equal(t, 1, n, "the row is due again once the lease ended")
			return slowErr
		}})
		_, err := slow.Drain(context.Background())
		require.NoError(t, err)
		assert.Equal(t, map[string]int{"sent": 1}, statuses(t, d), "%v", slowErr)
		var attempts int
		var code string
		require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT attempts, last_error_code FROM notifications_outbox").Scan(&attempts, &code))
		assert.Equal(t, 2, attempts)
		assert.Empty(t, code, "the later drain's success is kept")
	}
}
