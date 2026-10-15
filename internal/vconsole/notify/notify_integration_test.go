//go:build integration

package notify_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/notify"
	"alice/internal/vconsole/vpgtest"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

// testNow is a fixed instant at microsecond precision, so it round-trips through timestamptz.
func testNow() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

func notifier(t *testing.T, d *vpgtest.DB, login string) *pgxpool.Pool {
	t.Helper()
	return d.As(t, "vendor_notifier", login)
}

// notice is one row of the notifications table.
type notice struct {
	ID        int64
	Kind      string
	Severity  string
	Title     string
	Body      string
	Audience  string
	Target    *string
	Subject   string
	DedupeKey string
}

// notices returns the notifications of one kind, oldest first, read through the owner pool (the
// issuance trigger writes license.issued rows for every seeded license too).
func notices(t *testing.T, d *vpgtest.DB, kind string) []notice {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), `SELECT id, kind, severity, title, body, audience, target_user, subject, dedupe_key
		FROM notifications WHERE kind = $1 ORDER BY id`, kind)
	require.NoError(t, err)
	defer rows.Close()
	var out []notice
	for rows.Next() {
		var n notice
		require.NoError(t, rows.Scan(&n.ID, &n.Kind, &n.Severity, &n.Title, &n.Body, &n.Audience, &n.Target, &n.Subject, &n.DedupeKey))
		out = append(out, n)
	}
	require.NoError(t, rows.Err())
	return out
}

func countNotices(t *testing.T, d *vpgtest.DB) int {
	t.Helper()
	var n int
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM notifications`).Scan(&n))
	return n
}

func sampleNotice(key string) notify.Notice {
	return notify.Notice{Kind: "test.kind", Severity: notify.SeverityInfo, Title: "A title", Body: "A body.\n",
		Audience: notify.AudienceOwner, Subject: "LIC-1", DedupeKey: key}
}

func TestNotifyIsIdempotentOnTheDedupeKey(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_n1_notifier")

	created, err := notify.Notify(ctx, p, sampleNotice("test:1"))
	require.NoError(t, err)
	assert.True(t, created)
	other := sampleNotice("test:1")
	other.Title = "A different title"
	created, err = notify.Notify(ctx, p, other)
	require.NoError(t, err)
	assert.False(t, created, "the same key creates nothing, whatever the rest says")
	created, err = notify.Notify(ctx, p, sampleNotice("test:2"))
	require.NoError(t, err)
	assert.True(t, created)

	ns := notices(t, d, "test.kind")
	require.Len(t, ns, 2)
	assert.Equal(t, "A title", ns[0].Title)
	assert.Equal(t, "owner", ns[0].Audience)
	assert.Nil(t, ns[0].Target)
	assert.Equal(t, "LIC-1", ns[0].Subject)
	assert.Equal(t, "test:1", ns[0].DedupeKey)
}

func TestConcurrentNotifyCreatesOneRow(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p1 := notifier(t, d, "t_n2_notifier_a")
	p2 := notifier(t, d, "t_n2_notifier_b")
	var wg sync.WaitGroup
	created := make([]bool, 8)
	errs := make([]error, 8)
	for i := range 8 {
		p := p1
		if i%2 == 1 {
			p = p2
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			created[i], errs[i] = notify.Notify(ctx, p, sampleNotice("test:race"))
		}()
	}
	wg.Wait()
	n := 0
	for i := range 8 {
		require.NoError(t, errs[i])
		if created[i] {
			n++
		}
	}
	assert.Equal(t, 1, n)
	assert.Len(t, notices(t, d, "test.kind"), 1)
}

func TestNotifyCleansTheTitleAndCutsTheBody(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_n3_notifier")

	n := sampleNotice("test:clean")
	n.Title = "Evil\r\nline\u2028two\u2029three\u202e\x1b[0m" + strings.Repeat("ş", 300)
	n.Subject = "LIC\n" + strings.Repeat("x", 100)
	n.Body = strings.Repeat("ğ", 5000) + "\x00"
	created, err := notify.Notify(ctx, p, n)
	require.NoError(t, err)
	require.True(t, created)

	ns := notices(t, d, "test.kind")
	require.Len(t, ns, 1)
	assert.Equal(t, 200, utf8.RuneCountInString(ns[0].Title))
	assert.True(t, strings.HasPrefix(ns[0].Title, "Evil line two three [0m"), ns[0].Title)
	assert.Equal(t, 64, utf8.RuneCountInString(ns[0].Subject))
	assert.True(t, strings.HasPrefix(ns[0].Subject, "LIC x"))
	assert.Equal(t, 4000, utf8.RuneCountInString(ns[0].Body))
	assert.True(t, strings.HasSuffix(ns[0].Body, "ğ... (truncated)"))
	assert.True(t, utf8.ValidString(ns[0].Body))

	// A body of exactly 4000 characters is kept as it is.
	n = sampleNotice("test:exact")
	n.Body = strings.Repeat("ğ", 4000)
	_, err = notify.Notify(ctx, p, n)
	require.NoError(t, err)
	ns = notices(t, d, "test.kind")
	require.Len(t, ns, 2)
	assert.Equal(t, n.Body, ns[1].Body)
}

func TestNotifyRefusesInvalidNotices(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_n4_notifier")
	for name, mod := range map[string]func(*notify.Notice){
		"empty kind":           func(n *notify.Notice) { n.Kind = "" },
		"long kind":            func(n *notify.Notice) { n.Kind = strings.Repeat("k", 41) },
		"bad severity":         func(n *notify.Notice) { n.Severity = "critical" },
		"bad audience":         func(n *notify.Notice) { n.Audience = "everyone" },
		"owner with target":    func(n *notify.Notice) { n.Target = "ayse" },
		"sales with target":    func(n *notify.Notice) { n.Audience, n.Target = notify.AudienceSales, "ayse" },
		"user without target":  func(n *notify.Notice) { n.Audience = notify.AudienceUser },
		"user with bad target": func(n *notify.Notice) { n.Audience, n.Target = notify.AudienceUser, "ay se" },
		"empty title":          func(n *notify.Notice) { n.Title = "\r\n\u202e" },
		"empty dedupe key":     func(n *notify.Notice) { n.DedupeKey = "" },
		"long dedupe key":      func(n *notify.Notice) { n.DedupeKey = strings.Repeat("d", 201) },
	} {
		n := sampleNotice("test:bad")
		mod(&n)
		created, err := notify.Notify(ctx, p, n)
		require.Error(t, err, name)
		assert.False(t, created, name)
	}
	assert.Empty(t, notices(t, d, "test.kind"))

	n := sampleNotice("test:user")
	n.Audience, n.Target = notify.AudienceUser, "Ayse.K"
	created, err := notify.Notify(ctx, p, n)
	require.NoError(t, err)
	assert.True(t, created)
	ns := notices(t, d, "test.kind")
	require.Len(t, ns, 1)
	require.NotNil(t, ns[0].Target)
	assert.Equal(t, "Ayse.K", *ns[0].Target)
}

// The notifier cannot set created_at, so the rows are aged through the superuser pool.
func TestPruneKeepsUnreadAndRecent(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	p := notifier(t, d, "t_n5_notifier")
	// The database never prunes anything younger than 180 days by its own clock, so the test's
	// now is the real time.
	now := testNow()
	for _, k := range []string{"old-read", "old-unread", "edge-read", "new-read"} {
		_, err := notify.Notify(ctx, p, sampleNotice("test:"+k))
		require.NoError(t, err)
	}
	age := map[string]time.Time{
		"test:old-read":   now.Add(-181 * day),
		"test:old-unread": now.Add(-400 * day),
		"test:edge-read":  now.Add(-180 * day), // exactly at the cutoff: kept
		"test:new-read":   now.Add(-10 * day),
	}
	for k, at := range age {
		_, err := d.Owner.Exec(ctx, `UPDATE notifications SET created_at = $2 WHERE dedupe_key = $1`, k, at)
		require.NoError(t, err)
	}
	var uid int64
	require.NoError(t, d.Owner.QueryRow(ctx, `INSERT INTO web_users (name, role) VALUES ('boss', 'owner') RETURNING id`).Scan(&uid))
	_, err := d.Owner.Exec(ctx, `INSERT INTO notification_reads (notification_id, user_id)
		SELECT id, $1 FROM notifications WHERE dedupe_key IN ('test:old-read', 'test:edge-read', 'test:new-read')`, uid)
	require.NoError(t, err)

	n, err := notify.Prune(ctx, p, now)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	var left []string
	for _, x := range notices(t, d, "test.kind") {
		left = append(left, x.DedupeKey)
	}
	assert.ElementsMatch(t, []string{"test:old-unread", "test:edge-read", "test:new-read"}, left)
	var reads int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM notification_reads`).Scan(&reads))
	assert.Equal(t, 2, reads, "the pruned notification's read row went with it")

	n, err = notify.Prune(ctx, p, now)
	require.NoError(t, err)
	assert.Zero(t, n)
	// A clock far ahead does not prune read notifications the database knows are recent. (The edge
	// row may go now: by the database's clock, a little later than now, it has passed 180 days.)
	_, err = notify.Prune(ctx, p, now.Add(3*365*day))
	require.NoError(t, err)
	left = nil
	for _, x := range notices(t, d, "test.kind") {
		left = append(left, x.DedupeKey)
	}
	assert.Contains(t, left, "test:new-read")
	assert.Contains(t, left, "test:old-unread")
}
