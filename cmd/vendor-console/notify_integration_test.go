//go:build integration

package main

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
	"alice/internal/vconsole/vpgtest"
)

// notifyEnv is one fresh database and logins for each role the commands care about.
type notifyEnv struct {
	t    *testing.T
	d    *vpgtest.DB
	urls map[string]string // login kind -> database URL
}

func newNotifyEnv(t *testing.T, prefix string) *notifyEnv {
	t.Helper()
	d := vpgtest.New(t)
	e := &notifyEnv{t: t, d: d, urls: map[string]string{"super": d.OwnerURL}}
	for kind, group := range map[string]string{"owner": "vendor_owner", "sales": "vendor_sales", "notifier": "vendor_notifier"} {
		login := prefix + "_" + kind
		_ = d.As(t, group, login)
		u, err := url.Parse(d.OwnerURL)
		require.NoError(t, err)
		u.User = url.UserPassword(login, vpgtest.AsPassword)
		e.urls[kind] = u.String()
	}
	return e
}

// do runs the CLI as the given login kind and checks that no output names a database URL or the
// test logins' password.
func (e *notifyEnv) do(kind string, clk clock.Clock, args ...string) (string, string, int) {
	env := map[string]string{"VENDOR_DATABASE_URL": e.urls[kind]}
	ask := func(string) ([]byte, error) { return []byte(words), nil }
	var out, errOut bytes.Buffer
	code := run(args, func(k string) string { return env[k] }, &out, &errOut, ask, clk)
	all := out.String() + errOut.String()
	assert.NotContains(e.t, all, vpgtest.AsPassword, "%q", args)
	assert.NotContains(e.t, all, "postgres://", "%q", args)
	assert.NotContains(e.t, all, "postgresql://", "%q", args)
	return out.String(), errOut.String(), code
}

func (e *notifyEnv) count(table string) int {
	var n int
	require.NoError(e.t, e.d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n))
	return n
}

func (e *notifyEnv) exec(sql string, args ...any) {
	e.t.Helper()
	_, err := e.d.Owner.Exec(context.Background(), sql, args...)
	require.NoError(e.t, err)
}

// issueOne issues a 12-month license as the superuser login at clk's time and returns its ID.
func (e *notifyEnv) issueOne(clk clock.Clock, customer string) string {
	t := e.t
	t.Helper()
	dir := t.TempDir()
	priv, _, err := issuer.GenerateKey("vk-2026-01", []byte(words), issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1})
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, priv, 0o600))
	out, se, code := e.do("super", clk, "customer", "add", "--name", customer)
	require.Equal(t, 0, code, se)
	cust := regexp.MustCompile(`\d+`).FindString(out)
	out, se, code = e.do("super", clk, "request", "add", "--customer", cust, "--installation", license.NewInstallationID(), "--targets", "5")
	require.Equal(t, 0, code, se)
	reqID := regexp.MustCompile(`\d+`).FindString(out)
	out, se, code = e.do("super", clk, "request", "show", reqID)
	require.Equal(t, 0, code, se)
	hash := regexp.MustCompile(`[0-9a-f]{64}`).FindString(out)
	out, se, code = e.do("super", clk, "issue", "--request", reqID, "--hash", hash, "--key", keyPath, "--out", filepath.Join(dir, "l.alicelic"))
	require.Equal(t, 0, code, se)
	id := regexp.MustCompile(`LIC-\d+-\d+`).FindString(out)
	require.NotEmpty(t, id, out)
	return id
}

// settingsSnapshot returns every setting as "key=value", ordered by key.
func (e *notifyEnv) settingsSnapshot() []string {
	return e.strings(`SELECT key || '=' || value FROM vendor_settings ORDER BY key`)
}

// notifications returns every notification as "kind|audience|target|dedupe key", ordered by id.
func (e *notifyEnv) notifications() []string {
	return e.strings(`SELECT concat_ws('|', kind, audience, coalesce(target_user, ''), dedupe_key) FROM notifications ORDER BY id`)
}

func (e *notifyEnv) strings(query string) []string {
	e.t.Helper()
	rows, err := e.d.Owner.Query(context.Background(), query)
	require.NoError(e.t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(e.t, err)
	return out
}

func TestSettingsAsOwnerAndNotAsSales(t *testing.T) {
	e := newNotifyEnv(t, "t_cs")
	clk := clock.Real{}
	out, se, code := e.do("owner", clk, "settings", "show")
	require.Equal(t, 0, code, se)
	assert.Equal(t, "timezone         (not set)\nlast_summary_at  (not set)\n", out)

	_, se, code = e.do("owner", clk, "settings", "set", "timezone", "Europe/Berlin")
	require.Equal(t, 0, code, se)
	_, se, code = e.do("owner", clk, "settings", "set", "timezone", "Asia/Tokyo")
	require.Equal(t, 0, code, se)
	e.exec(`INSERT INTO vendor_settings (key, value) VALUES ('last_summary_at', '2026-10-12T06:00:00Z')`)
	out, se, code = e.do("owner", clk, "settings", "show")
	require.Equal(t, 0, code, se)
	assert.Equal(t, "timezone         Asia/Tokyo\nlast_summary_at  2026-10-12T06:00:00Z\n", out)

	// The removed key is refused before the database, as any unknown key.
	_, se, code = e.do("owner", clk, "settings", "set", "owner_email", "boss@example.com")
	assert.Equal(t, 2, code)
	assert.Contains(t, se, "allowed keys: timezone")

	for _, args := range [][]string{
		{"settings", "set", "timezone", "UTC"},
		{"settings", "show"},
	} {
		out, se, code := e.do("sales", clk, args...)
		assert.Equal(t, 1, code, args)
		assert.Contains(t, se, "permission denied", args)
		assert.Contains(t, se, "owner login", args)
		assert.Empty(t, out, args)
	}
	var n int
	require.NoError(t, e.d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM audit WHERE action = 'settings.set'
		AND actor = 't_cs_owner'`).Scan(&n))
	assert.Equal(t, 2, n, "every settings change is audited")
}

func TestNotifyRunCreatesTheNotificationsOnce(t *testing.T) {
	e := newNotifyEnv(t, "t_cn")
	t0 := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	fake := clock.NewFake(t0)
	_, se, code := e.do("owner", fake, "web-user", "add", "boss", "--owner")
	require.Equal(t, 0, code, se)
	id := e.issueOne(fake, "Acme Ltd")
	require.Equal(t, []string{"license.issued|owner||issued:" + id}, e.notifications(), "the database wrote the issuance notice")
	fake.Advance(345 * 24 * time.Hour) // 20 days before the 12-month license ends

	// A dry run changes nothing.
	tables := []string{"notifications", "notification_reads", "reminders", "vendor_settings", "audit"}
	before := map[string]int{}
	for _, tbl := range tables {
		before[tbl] = e.count(tbl)
	}
	settingsBefore, notesBefore := e.settingsSnapshot(), e.notifications()
	out, se, code := e.do("notifier", fake, "notify", "run", "--dry-run")
	require.Equal(t, 0, code, se)
	assert.Empty(t, se, "an owner exists: no warning")
	assert.Equal(t, "dry run, nothing changed\nreminders: 1 to create\nweekly summary: due\npruned: not run (dry run)\n", out)
	for tbl, n := range before {
		assert.Equal(t, n, e.count(tbl), "dry run wrote to %s", tbl)
	}
	assert.Equal(t, settingsBefore, e.settingsSnapshot(), "dry run changed a setting")
	assert.Equal(t, notesBefore, e.notifications(), "dry run changed a notification")

	// The real run agrees with the dry run.
	out, se, code = e.do("notifier", fake, "notify", "run")
	require.Equal(t, 0, code, se)
	assert.Empty(t, se)
	assert.Equal(t, "reminders: 1 created\nweekly summary: created\npruned: 0\n", out)
	notes := e.notifications()
	require.Len(t, notes, 3, notes)
	assert.Equal(t, "license.ending|owner||ending:"+id+":30", notes[1])
	assert.Equal(t, "summary.weekly|owner||summary:"+fake.Now().UTC().Format("2006-01-02"), notes[2])
	assert.Equal(t, []string{"30", "60", "90"}, e.strings(`SELECT days_before::text FROM reminders ORDER BY days_before`),
		"the passed thresholds are recorded, only the nearest one notifies")
	var mark string
	require.NoError(t, e.d.Owner.QueryRow(context.Background(), `SELECT value FROM vendor_settings WHERE key = 'last_summary_at'`).Scan(&mark))
	assert.Equal(t, fake.Now().UTC().Format("2006-01-02T15:04:05Z"), mark)

	// The second run, and its dry run, find nothing to do.
	out, se, code = e.do("notifier", fake, "notify", "run", "--dry-run")
	require.Equal(t, 0, code, se)
	assert.Contains(t, out, "reminders: 0 to create\nweekly summary: not due\n")
	out, se, code = e.do("notifier", fake, "notify", "run")
	require.Equal(t, 0, code, se)
	assert.Equal(t, "reminders: 0 created\nweekly summary: not due\npruned: 0\n", out)
	assert.Len(t, e.notifications(), 3)
}

func TestNotifyRunPrunesOldReadNotifications(t *testing.T) {
	e := newNotifyEnv(t, "t_cp")
	_, se, code := e.do("owner", clock.Real{}, "web-user", "add", "boss", "--owner")
	require.Equal(t, 0, code, se)
	// A summary was made yesterday, so the run creates nothing and only prunes.
	e.exec(`INSERT INTO vendor_settings (key, value) VALUES ('last_summary_at', $1)`,
		time.Now().UTC().Add(-24*time.Hour).Format(time.RFC3339))
	for i, key := range []string{"old-read", "old-unread", "new-read"} {
		age := "200 days"
		if i == 2 {
			age = "10 days"
		}
		e.exec(`INSERT INTO notifications (kind, title, audience, dedupe_key, created_at)
			VALUES ('test', 't', 'owner', $1, now() - $2::interval)`, key, age)
	}
	e.exec(`INSERT INTO notification_reads (notification_id, user_id)
		SELECT n.id, w.id FROM notifications n, web_users w WHERE n.dedupe_key IN ('old-read', 'new-read')`)

	out, se, code := e.do("notifier", clock.Real{}, "notify", "run")
	require.Equal(t, 0, code, se)
	assert.Equal(t, "reminders: 0 created\nweekly summary: not due\npruned: 1\n", out)
	assert.Equal(t, []string{"test|owner||old-unread", "test|owner||new-read"}, e.notifications())
}

func TestNotifyRunWarnsWhenNoOwnerCanReadTheNotifications(t *testing.T) {
	e := newNotifyEnv(t, "t_cw")
	clk := clock.Real{}
	check := func(wantWarning bool, why string) {
		t.Helper()
		for _, args := range [][]string{{"notify", "run"}, {"notify", "run", "--dry-run"}} {
			out, se, code := e.do("notifier", clk, args...)
			assert.Equal(t, 0, code, "%s %q: %s", why, args, se)
			assert.NotEmpty(t, out, why)
			if wantWarning {
				assert.Equal(t, noOwnerWarning+"\n", se, "%s %q", why, args)
			} else {
				assert.Empty(t, se, "%s %q", why, args)
			}
		}
	}
	check(true, "no web user")
	_, se, code := e.do("owner", clk, "web-user", "add", "ayse")
	require.Equal(t, 0, code, se)
	check(true, "only a sales user")
	_, se, code = e.do("owner", clk, "web-user", "add", "boss", "--owner")
	require.Equal(t, 0, code, se)
	check(false, "an enabled owner")
	_, se, code = e.do("owner", clk, "web-user", "disable", "boss")
	require.Equal(t, 0, code, se)
	check(true, "the owner is disabled")
}

// The owner check is advice: when it cannot read web_users it says so and the run goes on.
func TestTheOwnerCheckNeverFailsTheRun(t *testing.T) {
	e := newNotifyEnv(t, "t_co")
	ctx := context.Background()
	for _, kind := range []string{"sales", "notifier"} {
		pool := e.d.As(t, map[string]string{"sales": "vendor_sales", "notifier": "vendor_notifier"}[kind], "t_co_check_"+kind)
		if kind == "notifier" {
			e.exec(`REVOKE SELECT (role) ON web_users FROM vendor_notifier`)
		}
		var out, errOut bytes.Buffer
		c := &cli{out: &out, err: &errOut}
		c.warnIfNoOwner(ctx, pool)
		assert.Empty(t, out.String(), kind)
		assert.True(t, strings.HasPrefix(errOut.String(), "warning: could not check for an owner web user: "), "%s: %s", kind, errOut.String())
		assert.Contains(t, errOut.String(), "permission denied", kind)
	}
}

func TestNotifyRunNeedsANotifierLogin(t *testing.T) {
	e := newNotifyEnv(t, "t_cl")
	for _, kind := range []string{"owner", "sales"} {
		for _, args := range [][]string{{"notify", "run"}, {"notify", "run", "--dry-run"}} {
			out, se, code := e.do(kind, clock.Real{}, args...)
			assert.Equal(t, 1, code, kind, args)
			assert.Contains(t, se, "vendor_notifier", kind)
			assert.NotContains(t, se, "warning", kind)
			assert.Empty(t, out, kind)
		}
	}
	assert.Zero(t, e.count("notifications"))
	assert.Zero(t, e.count("vendor_settings"))
}

// A step that fails must not keep the others from running; the run ends with exit 1 so the
// timer shows the failure. The failure is a privilege taken from the notifier in this database.
func TestNotifyRunGoesOnWhenAStepFails(t *testing.T) {
	t.Run("reminders", func(t *testing.T) {
		e := newNotifyEnv(t, "t_cf")
		fake := clock.NewFake(time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC))
		id := e.issueOne(fake, "Beta Ltd")
		e.exec(`REVOKE INSERT ON reminders FROM vendor_notifier`)
		fake.Advance(345 * 24 * time.Hour)

		out, se, code := e.do("notifier", fake, "notify", "run")
		assert.Equal(t, 1, code)
		assert.Contains(t, se, "permission denied")
		assert.Contains(t, se, id)
		assert.Equal(t, "reminders: 0 created\nweekly summary: created\npruned: 0\n", out, "the summary and the prune still ran")
		assert.Zero(t, e.count("reminders"))
		assert.Len(t, e.strings(`SELECT kind FROM notifications WHERE kind = 'summary.weekly'`), 1)
	})
	t.Run("prune", func(t *testing.T) {
		e := newNotifyEnv(t, "t_cg")
		e.exec(`REVOKE EXECUTE ON FUNCTION notify_prune(timestamptz) FROM vendor_notifier`)
		out, se, code := e.do("notifier", clock.Real{}, "notify", "run")
		assert.Equal(t, 1, code)
		assert.Contains(t, se, "notify: prune")
		assert.Equal(t, "reminders: 0 created\nweekly summary: created\npruned: 0\n", out)
		assert.Len(t, e.strings(`SELECT kind FROM notifications WHERE kind = 'summary.weekly'`), 1)
	})
}
