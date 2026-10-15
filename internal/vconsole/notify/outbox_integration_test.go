//go:build integration

package notify_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/mail"
	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

// fakeSender records every message it is asked to send. fail decides, per message, whether the
// send fails and with which error; delay widens the window in which two runs overlap.
type fakeSender struct {
	mu    sync.Mutex
	sent  []mail.Message
	tries int
	fail  func(m mail.Message) error
	delay time.Duration
}

func (f *fakeSender) Send(ctx context.Context, m mail.Message, _ time.Time) error {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tries++
	if f.fail != nil {
		if err := f.fail(m); err != nil {
			return err
		}
	}
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeSender) messages() []mail.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mail.Message(nil), f.sent...)
}

func (f *fakeSender) attempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tries
}

// testNow is a fixed instant at microsecond precision, so it round-trips through timestamptz.
func testNow() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// seed inserts one outbox row through the owner pool, due at due.
func seed(t *testing.T, d *vpgtest.DB, to []string, subject string, due time.Time) int64 {
	t.Helper()
	if to == nil {
		to = []string{}
	}
	var id int64
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		`INSERT INTO mail_outbox (kind, to_addrs, subject, body, next_attempt_at) VALUES ('test', $1, $2, 'body of '||$2, $3) RETURNING id`,
		to, subject, due).Scan(&id))
	return id
}

type row struct {
	SentAt, FailedAt *time.Time
	Attempts         int
	LastError        string
	NextAttemptAt    time.Time
	To               []string
}

func load(t *testing.T, p *pgxpool.Pool, id int64) row {
	t.Helper()
	var r row
	require.NoError(t, p.QueryRow(context.Background(),
		`SELECT sent_at, failed_at, attempts, last_error, next_attempt_at, to_addrs FROM mail_outbox WHERE id = $1`, id).
		Scan(&r.SentAt, &r.FailedAt, &r.Attempts, &r.LastError, &r.NextAttemptAt, &r.To))
	return r
}

const from = "Vendor Console <console@example.com>"

func TestPendingMessageIsSentOnceAndMarked(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := d.As(t, "vendor_notifier", "t_o1_notifier")
	now := testNow()
	id := seed(t, d, []string{"boss@example.com"}, "hello", now.Add(-time.Minute))
	f := &fakeSender{}

	res, err := notify.SendPending(ctx, p, f, from, now)
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{Sent: 1}, res)
	msgs := f.messages()
	require.Len(t, msgs, 1)
	assert.Equal(t, mail.Message{From: from, To: []string{"boss@example.com"}, Subject: "hello", Body: "body of hello"}, msgs[0])
	r := load(t, d.Owner, id)
	require.NotNil(t, r.SentAt)
	assert.True(t, r.SentAt.Equal(now))
	assert.Nil(t, r.FailedAt)

	res, err = notify.SendPending(ctx, p, f, from, now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{}, res)
	assert.Len(t, f.messages(), 1)
}

func TestEnqueueAsNotifierIsDueAtOnce(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := d.As(t, "vendor_notifier", "t_o2_notifier")
	id, err := notify.Enqueue(ctx, p, "reminder", []string{"a@example.com", "b@example.com"}, "Expiry soon", "text")
	require.NoError(t, err)
	assert.Positive(t, id)
	_, err = notify.Enqueue(ctx, p, "reminder", []string{"a@example.com"}, "bad\r\nBcc: x@example.com", "text")
	require.Error(t, err)

	f := &fakeSender{}
	res, err := notify.SendPending(ctx, p, f, from, testNow().Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, 1, res.Sent)
	require.Len(t, f.messages(), 1)
	assert.Equal(t, []string{"a@example.com", "b@example.com"}, f.messages()[0].To)
}

func TestTwoConcurrentRunsSendEachMessageOnce(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p1 := d.As(t, "vendor_notifier", "t_o3_notifier_a")
	p2 := d.As(t, "vendor_notifier", "t_o3_notifier_b")
	now := testNow()
	for i := range 20 {
		seed(t, d, []string{"boss@example.com"}, fmt.Sprintf("m%02d", i), now.Add(-time.Minute))
	}
	f := &fakeSender{delay: 5 * time.Millisecond}

	var wg sync.WaitGroup
	results := make([]notify.SendResult, 2)
	errs := make([]error, 2)
	for i, p := range []*pgxpool.Pool{p1, p2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = notify.SendPending(ctx, p, f, from, now)
		}()
	}
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	seen := map[string]int{}
	for _, m := range f.messages() {
		seen[m.Subject]++
	}
	assert.Len(t, seen, 20)
	for s, n := range seen {
		assert.Equal(t, 1, n, "message %s sent %d times", s, n)
	}
	assert.Equal(t, 20, results[0].Sent+results[1].Sent)
	var unsent int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM mail_outbox WHERE sent_at IS NULL`).Scan(&unsent))
	assert.Zero(t, unsent)
}

func TestFailureRecordsAttemptAndBacksOff(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := d.As(t, "vendor_notifier", "t_o4_notifier")
	now := testNow()
	id := seed(t, d, []string{"boss@example.com"}, "hello", now.Add(-time.Minute))
	f := &fakeSender{fail: func(mail.Message) error { return errors.New("smtp: 451 try later") }}

	res, err := notify.SendPending(ctx, p, f, from, now)
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{Retry: 1}, res)
	r := load(t, d.Owner, id)
	assert.Equal(t, 1, r.Attempts)
	assert.Equal(t, "smtp: 451 try later", r.LastError)
	assert.True(t, r.NextAttemptAt.Equal(now.Add(2*time.Minute)), "next attempt %v", r.NextAttemptAt)
	assert.Nil(t, r.SentAt)
	assert.Nil(t, r.FailedAt)

	res, err = notify.SendPending(ctx, p, f, from, now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{}, res)
	assert.Equal(t, 1, f.attempts())

	f.fail = nil
	res, err = notify.SendPending(ctx, p, f, from, now.Add(2*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{Sent: 1}, res)
	assert.NotNil(t, load(t, d.Owner, id).SentAt)
}

func TestBackoffIsCappedAtSixHours(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := d.As(t, "vendor_notifier", "t_o5_notifier")
	now := testNow()
	id := seed(t, d, []string{"boss@example.com"}, "hello", now.Add(-time.Minute))
	_, err := d.Owner.Exec(ctx, `UPDATE mail_outbox SET attempts = 8 WHERE id = $1`, id)
	require.NoError(t, err)
	f := &fakeSender{fail: func(mail.Message) error { return errors.New("down") }}

	_, err = notify.SendPending(ctx, p, f, from, now)
	require.NoError(t, err)
	r := load(t, d.Owner, id)
	assert.Equal(t, 9, r.Attempts)
	assert.True(t, r.NextAttemptAt.Equal(now.Add(6*time.Hour)), "next attempt %v", r.NextAttemptAt) // 2^9 min > 6 h
}

func TestMessageFailsAfterMaxAttempts(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := d.As(t, "vendor_notifier", "t_o6_notifier")
	now := testNow()
	id := seed(t, d, []string{"boss@example.com"}, "hello", now.Add(-time.Minute))
	f := &fakeSender{fail: func(mail.Message) error { return errors.New("550 rejected") }}

	for i := 1; i <= notify.MaxAttempts; i++ {
		res, err := notify.SendPending(ctx, p, f, from, now)
		require.NoError(t, err)
		r := load(t, d.Owner, id)
		assert.Equal(t, i, r.Attempts)
		if i < notify.MaxAttempts {
			assert.Equal(t, notify.SendResult{Retry: 1}, res, "run %d", i)
			assert.Nil(t, r.FailedAt, "run %d", i)
		} else {
			assert.Equal(t, notify.SendResult{Failed: 1}, res, "run %d", i)
			require.NotNil(t, r.FailedAt)
			assert.True(t, r.FailedAt.Equal(now))
		}
		now = now.Add(7 * time.Hour) // past any backoff
	}
	assert.Equal(t, notify.MaxAttempts, f.attempts())

	res, err := notify.SendPending(ctx, p, f, from, now.Add(24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{}, res)
	assert.Equal(t, notify.MaxAttempts, f.attempts())
}

func TestWaitingMessageGetsTheOwnerAddressOnceSet(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := d.As(t, "vendor_notifier", "t_o7_notifier")
	now := testNow()
	id := seed(t, d, nil, "issued", now.Add(-time.Minute))
	f := &fakeSender{}

	n, err := notify.ResolveEmptyRecipients(ctx, p)
	require.NoError(t, err)
	assert.Zero(t, n, "no owner address yet")
	res, err := notify.SendPending(ctx, p, f, from, now)
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{Waiting: 1}, res)
	assert.Empty(t, f.messages())
	r := load(t, d.Owner, id)
	assert.Zero(t, r.Attempts)
	assert.Empty(t, r.LastError)

	_, err = d.Owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('owner_email', 'boss@example.com')`)
	require.NoError(t, err)
	n, err = notify.ResolveEmptyRecipients(ctx, p)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	res, err = notify.SendPending(ctx, p, f, from, now)
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{Sent: 1}, res)
	require.Len(t, f.messages(), 1)
	assert.Equal(t, []string{"boss@example.com"}, f.messages()[0].To)

	n, err = notify.ResolveEmptyRecipients(ctx, p)
	require.NoError(t, err)
	assert.Zero(t, n)
}

func TestOneBadMessageDoesNotBlockTheOthers(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := d.As(t, "vendor_notifier", "t_o8_notifier")
	now := testNow()
	a := seed(t, d, []string{"a@example.com"}, "first", now.Add(-time.Minute))
	b := seed(t, d, []string{"bad@example.com"}, "second", now.Add(-time.Minute))
	c := seed(t, d, []string{"c@example.com"}, "third", now.Add(-time.Minute))
	f := &fakeSender{fail: func(m mail.Message) error {
		if m.To[0] == "bad@example.com" {
			return errors.New("550 no such user")
		}
		return nil
	}}

	res, err := notify.SendPending(ctx, p, f, from, now)
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{Sent: 2, Retry: 1}, res)
	assert.NotNil(t, load(t, d.Owner, a).SentAt)
	assert.Nil(t, load(t, d.Owner, b).SentAt)
	assert.Equal(t, 1, load(t, d.Owner, b).Attempts)
	assert.NotNil(t, load(t, d.Owner, c).SentAt)
}

func TestLastErrorIsTruncated(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := d.As(t, "vendor_notifier", "t_o9_notifier")
	now := testNow()
	id := seed(t, d, []string{"boss@example.com"}, "hello", now.Add(-time.Minute))
	long := strings.Repeat("ş", 1000) // two bytes per rune: a byte cut would split one
	f := &fakeSender{fail: func(mail.Message) error { return errors.New(long) }}

	_, err := notify.SendPending(ctx, p, f, from, now)
	require.NoError(t, err)
	r := load(t, d.Owner, id)
	assert.True(t, utf8.ValidString(r.LastError))
	assert.Equal(t, 300, utf8.RuneCountInString(r.LastError))
	assert.True(t, strings.HasPrefix(long, r.LastError))
}

func TestNotDueMessageIsLeftAlone(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := d.As(t, "vendor_notifier", "t_o10_notifier")
	now := testNow()
	seed(t, d, []string{"boss@example.com"}, "later", now.Add(time.Minute))
	f := &fakeSender{}
	res, err := notify.SendPending(ctx, p, f, from, now)
	require.NoError(t, err)
	assert.Equal(t, notify.SendResult{}, res)
	assert.Zero(t, f.attempts())
}
