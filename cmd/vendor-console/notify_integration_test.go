//go:build integration

package main

import (
	"bytes"
	"context"
	"io"
	"mime/quotedprintable"
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
	"alice/internal/vconsole/mail/mailtest"
	"alice/internal/vconsole/vpgtest"
)

const smtpPassword = "smtp-pw-never-printed" //nolint:gosec // G101: a throw-away test password

// notifyEnv is one fresh database, an SMTP server and logins for each role the commands care about.
type notifyEnv struct {
	t    *testing.T
	d    *vpgtest.DB
	smtp *mailtest.Server
	urls map[string]string // login kind -> database URL
}

func newNotifyEnv(t *testing.T, prefix string) *notifyEnv {
	t.Helper()
	d := vpgtest.New(t)
	e := &notifyEnv{t: t, d: d, smtp: mailtest.Start(t, mailtest.Options{}), urls: map[string]string{"super": d.OwnerURL}}
	for kind, group := range map[string]string{"owner": "vendor_owner", "sales": "vendor_sales", "notifier": "vendor_notifier"} {
		login := prefix + "_" + kind
		_ = d.As(t, group, login)
		u, err := url.Parse(d.OwnerURL)
		require.NoError(t, err)
		u.User = url.UserPassword(login, vpgtest.AsPassword)
		e.urls[kind] = u.String()
	}
	old := smtpRootCAs
	smtpRootCAs = e.smtp.CertPool()
	t.Cleanup(func() { smtpRootCAs = old })
	return e
}

// do runs the CLI as the given login kind, with the SMTP settings of the test server.
func (e *notifyEnv) do(kind string, clk clock.Clock, args ...string) (string, string, int) {
	env := map[string]string{
		"VENDOR_DATABASE_URL":  e.urls[kind],
		"VENDOR_SMTP_ADDR":     e.smtp.Addr(),
		"VENDOR_SMTP_FROM":     "Vendor Console <console@vendor.example>",
		"VENDOR_SMTP_USER":     "console",
		"VENDOR_SMTP_PASSWORD": smtpPassword,
	}
	ask := func(string) ([]byte, error) { return []byte(words), nil }
	var out, errOut bytes.Buffer
	code := run(args, func(k string) string { return env[k] }, &out, &errOut, ask, clk)
	assert.NotContains(e.t, out.String()+errOut.String(), smtpPassword)
	return out.String(), errOut.String(), code
}

func (e *notifyEnv) count(table string) int {
	var n int
	require.NoError(e.t, e.d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n))
	return n
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

// outboxSnapshot returns the state of every outbox row (recipients, attempts, timestamps), ordered by id.
func (e *notifyEnv) outboxSnapshot() []string {
	return e.strings(`SELECT concat_ws('|', id, array_to_string(to_addrs, ','), attempts, last_error, sent_at, failed_at,
		next_attempt_at) FROM mail_outbox ORDER BY id`)
}

func (e *notifyEnv) strings(query string) []string {
	e.t.Helper()
	rows, err := e.d.Owner.Query(context.Background(), query)
	require.NoError(e.t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(e.t, err)
	return out
}

func subjects(msgs []mailtest.Message) []string {
	var out []string
	for _, m := range msgs {
		for _, l := range strings.Split(string(m.Data), "\r\n") {
			if s, ok := strings.CutPrefix(l, "Subject: "); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// bodies decodes the quoted-printable bodies of msgs and joins them.
func bodies(t *testing.T, msgs []mailtest.Message) string {
	t.Helper()
	var b strings.Builder
	for _, m := range msgs {
		_, body, ok := strings.Cut(string(m.Data), "\r\n\r\n")
		require.True(t, ok)
		dec, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
		require.NoError(t, err)
		b.Write(dec)
	}
	return b.String()
}

func TestSettingsAsOwnerAndNotAsSales(t *testing.T) {
	e := newNotifyEnv(t, "t_cs")
	clk := clock.Real{}
	_, se, code := e.do("owner", clk, "settings", "set", "owner_email", "boss@example.com")
	require.Equal(t, 0, code, se)
	_, se, code = e.do("owner", clk, "settings", "set", "timezone", "Europe/Berlin")
	require.Equal(t, 0, code, se)
	_, se, code = e.do("owner", clk, "settings", "set", "owner_email", "new.boss@example.com")
	require.Equal(t, 0, code, se)
	out, se, code := e.do("owner", clk, "settings", "show")
	require.Equal(t, 0, code, se)
	assert.Regexp(t, `owner_email\s+new\.boss@example\.com`, out)
	assert.Regexp(t, `timezone\s+Europe/Berlin`, out)

	for _, args := range [][]string{
		{"settings", "set", "owner_email", "sales@example.com"},
		{"settings", "set", "timezone", "UTC"},
		{"settings", "show"},
		{"web-user", "set-email", "ayse", "ayse@example.com"},
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
	assert.Equal(t, 3, n, "every settings change is audited")
}

func TestWebUserSetEmail(t *testing.T) {
	e := newNotifyEnv(t, "t_ce")
	clk := clock.Real{}
	_, se, code := e.do("owner", clk, "web-user", "add", "ayse")
	require.Equal(t, 0, code, se)
	_, se, code = e.do("owner", clk, "web-user", "set-email", "AYSE", "ayse@example.com")
	require.Equal(t, 0, code, se)
	var email string
	require.NoError(t, e.d.Owner.QueryRow(context.Background(), `SELECT email FROM web_users WHERE name = 'ayse'`).Scan(&email))
	assert.Equal(t, "ayse@example.com", email)
	_, se, code = e.do("owner", clk, "web-user", "set-email", "nobody", "x@example.com")
	assert.Equal(t, 1, code)
	assert.Contains(t, se, "not found")
	_, se, code = e.do("owner", clk, "web-user", "set-email", "ayse", "")
	require.Equal(t, 0, code, se)
	require.NoError(t, e.d.Owner.QueryRow(context.Background(), `SELECT email FROM web_users WHERE name = 'ayse'`).Scan(&email))
	assert.Empty(t, email)
}

func TestNotifyRunSendsIssuanceReminderAndSummaryOnce(t *testing.T) {
	e := newNotifyEnv(t, "t_cn")
	t0 := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	fake := clock.NewFake(t0)
	_, se, code := e.do("owner", fake, "settings", "set", "owner_email", "boss@example.com")
	require.Equal(t, 0, code, se)
	id := e.issueOne(fake, "Acme Ltd")
	fake.Advance(345 * 24 * time.Hour) // 20 days before the 12-month license ends

	// A dry run changes nothing and sends nothing.
	before := map[string]int{}
	for _, tbl := range []string{"mail_outbox", "reminders", "vendor_settings", "audit"} {
		before[tbl] = e.count(tbl)
	}
	settingsBefore := e.settingsSnapshot()
	outboxBefore := e.outboxSnapshot()
	out, se, code := e.do("notifier", fake, "notify", "run", "--dry-run", "--base-url", "https://licenses.example.com")
	require.Equal(t, 0, code, se)
	assert.Contains(t, out, "reminders to create: 1")
	assert.Contains(t, out, "weekly summary: due")
	assert.Contains(t, out, "mail to send: 1 already queued")
	for tbl, n := range before {
		assert.Equal(t, n, e.count(tbl), "dry run wrote to %s", tbl)
	}
	assert.Equal(t, settingsBefore, e.settingsSnapshot(), "dry run changed a setting")
	assert.Equal(t, outboxBefore, e.outboxSnapshot(), "dry run changed an outbox row")
	assert.Empty(t, e.smtp.Messages())

	out, se, code = e.do("notifier", fake, "notify", "run", "--base-url", "https://licenses.example.com")
	require.Equal(t, 0, code, se)
	assert.Contains(t, out, "reminders created: 1")
	assert.Contains(t, out, "weekly summary: created")
	assert.Contains(t, out, "mail: sent 3,")
	msgs := e.smtp.Messages()
	require.Len(t, msgs, 3)
	subj := strings.Join(subjects(msgs), "\n")
	assert.Contains(t, subj, "License issued: Acme Ltd ("+id+")")
	assert.Contains(t, subj, "License ending in 30 days: Acme Ltd")
	assert.Contains(t, subj, "Weekly summary:")
	for _, m := range msgs {
		assert.Equal(t, []string{"boss@example.com"}, m.To)
		assert.Equal(t, "console@vendor.example", m.From)
	}
	assert.Contains(t, bodies(t, msgs), "https://licenses.example.com/requests/new?renew="+id)
	auths := e.smtp.Auths()
	require.NotEmpty(t, auths)
	for _, a := range auths {
		assert.True(t, a.TLS, "credentials only over TLS")
	}

	// The second run finds nothing to do.
	out, se, code = e.do("notifier", fake, "notify", "run", "--base-url", "https://licenses.example.com")
	require.Equal(t, 0, code, se)
	assert.Contains(t, out, "reminders created: 0")
	assert.Contains(t, out, "weekly summary: not due")
	assert.Contains(t, out, "mail: sent 0,")
	assert.Len(t, e.smtp.Messages(), 3)
}

func TestNotifyRunNeedsANotifierLogin(t *testing.T) {
	e := newNotifyEnv(t, "t_cl")
	for _, kind := range []string{"owner", "sales"} {
		for _, args := range [][]string{{"notify", "run"}, {"notify", "run", "--dry-run"}} {
			out, se, code := e.do(kind, clock.Real{}, args...)
			assert.Equal(t, 1, code, kind, args)
			assert.Contains(t, se, "vendor_notifier", kind)
			assert.Empty(t, out, kind)
		}
	}
	assert.Zero(t, e.count("mail_outbox"))
}

// A reminder step that fails must not keep the issuance mail from going out; the run still ends
// with exit 1 so the timer shows the failure.
func TestNotifyRunSendsEvenWhenRemindersFail(t *testing.T) {
	e := newNotifyEnv(t, "t_cf")
	t0 := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	fake := clock.NewFake(t0)
	id := e.issueOne(fake, "Beta Ltd") // before the owner address exists: the mail waits
	_, se, code := e.do("owner", fake, "settings", "set", "owner_email", "boss@example.com")
	require.Equal(t, 0, code, se)
	ctx := context.Background()
	_, err := e.d.Owner.Exec(ctx, `CREATE FUNCTION t_break() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'reminders are broken'; END $$`)
	require.NoError(t, err)
	_, err = e.d.Owner.Exec(ctx, `CREATE TRIGGER t_break BEFORE INSERT ON reminders FOR EACH ROW EXECUTE FUNCTION t_break()`)
	require.NoError(t, err)
	fake.Advance(345 * 24 * time.Hour)

	out, se, code := e.do("notifier", fake, "notify", "run")
	assert.Equal(t, 1, code)
	assert.Contains(t, se, "reminders are broken")
	assert.Contains(t, se, id)
	assert.Contains(t, out, "recipients filled: 1")
	assert.Contains(t, out, "reminders created: 0")
	assert.Contains(t, out, "mail: sent 2,", "the issuance mail and the summary still go out")
	assert.Contains(t, strings.Join(subjects(e.smtp.Messages()), "\n"), "License issued: Beta Ltd")
}

func TestNotifyRunExitsOneWhenAMessageFails(t *testing.T) {
	e := newNotifyEnv(t, "t_cx")
	ctx := context.Background()
	// The run's clock is a little ahead of the database's, so the seeded message is due.
	now := time.Now().UTC().Add(time.Minute)
	// A summary went out yesterday, so this run sends none and the bad message is the only mail.
	_, err := e.d.Owner.Exec(ctx, `INSERT INTO vendor_settings (key, value) VALUES ('last_summary_at', $1)`,
		now.Add(-24*time.Hour).Format(time.RFC3339))
	require.NoError(t, err)
	// An address the outbox stores but the sender can never use: it fails at once, not in 14 hours.
	_, err = e.d.Owner.Exec(ctx, `INSERT INTO mail_outbox (kind, to_addrs, subject, body) VALUES ('test', '{not an address}', 's', 'b')`)
	require.NoError(t, err)
	out, se, code := e.do("notifier", clock.NewFake(now), "notify", "run")
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "weekly summary: not due")
	assert.Contains(t, out, "mail: sent 0, to retry 0, failed 1,")
	assert.Equal(t, 1, e.count("mail_outbox"), "no summary was created")
	assert.Contains(t, se, "marked failed")
	var failed int
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT count(*) FROM mail_outbox WHERE failed_at IS NOT NULL AND attempts = 1`).Scan(&failed))
	assert.Equal(t, 1, failed)
}
