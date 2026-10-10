//go:build integration

package notify_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/i18n"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
	"alice/internal/testutil/fakesmtp"
	"alice/internal/testutil/pgtest"
	"alice/locales"
)

const canary = "CANARY-smtp-0b7c"

type harness struct {
	d   *pgtest.DB
	s   *notify.Settings
	clk *clock.Fake
	who audit.Actor
}

func newHarness(t *testing.T, fallback notify.Mailer) harness {
	t.Helper()
	d := pgtest.New(t)
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := notify.NewSettings(notify.SettingsConfig{Pool: d.App, Keyring: k, Audit: audit.New(clk), Clock: clk,
		Catalog: cat, Fallback: fallback})
	return harness{d: d, s: s, clk: clk, who: audit.Actor{Type: audit.ActorUser, Name: "ada"}}
}

func input(srv *fakesmtp.Server, password *secrets.Plaintext) notify.SMTPInput {
	host, port := srv.Addr()
	return notify.SMTPInput{Host: host, Port: port, TLSMode: notify.TLSModeSTARTTLS, From: "alice@example.com",
		Username: "mailer", Password: password}
}

func pw(v string) *secrets.Plaintext { p := secrets.NewPlaintext([]byte(v)); return &p }

func TestSaveSMTPValidatesAndVersions(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	_, ok, err := h.s.SMTP(ctx)
	require.NoError(t, err)
	assert.False(t, ok)
	bad := input(srv, pw(canary))
	bad.Host, bad.Port, bad.TLSMode, bad.From = "a b", 0, "plain", "not-an-address"
	_, err = h.s.SaveSMTP(ctx, h.who, 0, bad)
	var verrs validate.Errors
	require.True(t, errors.As(err, &verrs), "%v", err)
	fields := map[string]bool{}
	for _, f := range verrs {
		fields[f.Field] = true
	}
	assert.Equal(t, map[string]bool{"host": true, "port": true, "tls_mode": true, "from": true}, fields)
	got, err := h.s.SaveSMTP(ctx, h.who, 0, input(srv, pw(canary)))
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version)
	assert.True(t, got.HasPassword)
	_, err = h.s.SaveSMTP(ctx, h.who, 0, input(srv, nil))
	assert.ErrorIs(t, err, notify.ErrVersion, "If-Match of a stale version")
	got, err = h.s.SaveSMTP(ctx, h.who, 1, input(srv, nil))
	require.NoError(t, err)
	assert.True(t, got.HasPassword, "nil keeps the password")
	empty := secrets.NewPlaintext(nil)
	in := input(srv, &empty)
	in.Username = ""
	got, err = h.s.SaveSMTP(ctx, h.who, 2, in)
	require.NoError(t, err)
	assert.False(t, got.HasPassword, "an empty password removes it")
	require.NoError(t, h.s.DeleteSMTP(ctx, h.who, 3))
	_, ok, err = h.s.SMTP(ctx)
	require.NoError(t, err)
	assert.False(t, ok)
}

// Final review minor 11: a stored password is not reused for another server. A new host or port without the password is
// a 422 on the password field and changes nothing; with the password it saves; the same server keeps the stored one.
func TestStoredPasswordIsNotSentToAnotherServer(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	_, err := h.s.SaveSMTP(ctx, h.who, 0, input(srv, pw(canary)))
	require.NoError(t, err)
	for _, move := range []func(*notify.SMTPInput){
		func(in *notify.SMTPInput) { in.Host = "mail.attacker.example" },
		func(in *notify.SMTPInput) { in.Port++ },
	} {
		in := input(srv, nil)
		move(&in)
		_, err = h.s.SaveSMTP(ctx, h.who, 1, in)
		var verrs validate.Errors
		require.True(t, errors.As(err, &verrs), "%v", err)
		require.Len(t, verrs, 1)
		assert.Equal(t, "password", verrs[0].Field)
		assert.Equal(t, validate.Required, verrs[0].Code)
	}
	cur, ok, err := h.s.SMTP(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 1, cur.Version, "a refused save changes nothing")
	host, _ := srv.Addr()
	assert.Equal(t, host, cur.Host)

	got, err := h.s.SaveSMTP(ctx, h.who, 1, input(srv, nil))
	require.NoError(t, err, "the same server keeps the stored password")
	assert.True(t, got.HasPassword)
	moved := input(srv, pw("new-"+canary))
	moved.Host = "mail.example.net"
	got, err = h.s.SaveSMTP(ctx, h.who, 2, moved)
	require.NoError(t, err, "a new server with its password")
	assert.True(t, got.HasPassword)
	noAuth := input(srv, nil)
	noAuth.Host, noAuth.Username = "relay.example.net", ""
	_, err = h.s.SaveSMTP(ctx, h.who, 3, noAuth)
	require.NoError(t, err, "a new server without authentication needs no password")
}

// Review Focus 3, S-04: the password is only an envelope; no settings value, audit row or error holds it.
func TestSMTPPasswordIsAnEnvelope(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{Username: "mailer", Password: "right"})
	in := input(srv, pw(canary))
	in.CAPEM = string(srv.CertPEM()) // the certificate verifies, so the test reaches AUTH
	_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	var dump string
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT coalesce(string_agg(value::text, ' '), '') FROM settings`).Scan(&dump))
	assert.NotContains(t, dump, canary)
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log`).Scan(&dump))
	assert.NotContains(t, dump, canary)
	assert.Contains(t, dump, `"auth_changed": "true"`)
	var ct []byte
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT ciphertext FROM setting_secrets WHERE key = 'notify.smtp.password'`).Scan(&ct))
	assert.NotContains(t, string(ct), canary)
	// F-63 and Review Focus 3: a refused password is reported without the password or the server's text.
	err = h.s.TestMail(ctx, h.who, "ops@example.com", "en")
	assert.ErrorIs(t, err, notify.ErrSMTPAuth)
	assert.NotContains(t, err.Error(), canary)
	assert.NotContains(t, err.Error(), "535")
}

func TestTestMailSendsThroughTheSettingsAndTheTrust(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{Username: "mailer", Password: canary})
	_, err := h.s.SaveSMTP(ctx, h.who, 0, input(srv, pw(canary)))
	require.NoError(t, err)

	// F-62: the first test sees an untrusted certificate and remembers it for an hour.
	err = h.s.TestMail(ctx, h.who, "ops@example.com", "tr")
	var ce *notify.CertError
	require.True(t, errors.As(err, &ce))
	assert.Equal(t, srv.Fingerprint(), ce.Cert.Fingerprint)
	_, err = h.s.Trust(ctx, h.who, 1, strings.Repeat("ab", 32))
	assert.ErrorIs(t, err, notify.ErrCertNotSeen, "only the certificate Alice saw can be trusted")
	got, err := h.s.Trust(ctx, h.who, 1, srv.Fingerprint())
	require.NoError(t, err)
	require.NotNil(t, got.Trusted)
	assert.Equal(t, "ada", got.Trusted.TrustedBy)

	require.NoError(t, h.s.TestMail(ctx, h.who, "ops@example.com", "tr"))
	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	assert.Equal(t, "Alice test e-postası", msgs[0].Subject, "rendered in the requested language")
	assert.True(t, msgs[0].Authed)

	// Changing the host or port drops the pin (it belongs to that server); it needs the password again.
	in := input(srv, pw(canary))
	in.Port++
	got, err = h.s.SaveSMTP(ctx, h.who, got.Version, in)
	require.NoError(t, err)
	assert.Nil(t, got.Trusted)

	// A certificate seen more than an hour ago cannot be trusted any more.
	in.Port--
	got, err = h.s.SaveSMTP(ctx, h.who, got.Version, in)
	require.NoError(t, err)
	require.Error(t, h.s.TestMail(ctx, h.who, "ops@example.com", "en"))
	h.clk.Advance(notify.SeenCertValidFor + time.Second)
	_, err = h.s.Trust(ctx, h.who, got.Version, srv.Fingerprint())
	assert.ErrorIs(t, err, notify.ErrCertNotSeen)
	assert.Equal(t, 3, countAudit(t, h.d, "settings.smtp_tested"), "one row per test mail")
}

// S-6: the certificate a failed test saw belongs to the host and port it was seen on.
func TestSeenCertificateIsBoundToHostAndPort(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	got, err := h.s.SaveSMTP(ctx, h.who, 0, input(srv, pw(canary)))
	require.NoError(t, err)
	var ce *notify.CertError
	require.True(t, errors.As(h.s.TestMail(ctx, h.who, "ops@example.com", "en"), &ce))

	// The host changes (same server by another name), within the hour: the seen record is gone.
	in := input(srv, pw(canary))
	in.Host = "localhost"
	got, err = h.s.SaveSMTP(ctx, h.who, got.Version, in)
	require.NoError(t, err)
	_, err = h.s.Trust(ctx, h.who, got.Version, srv.Fingerprint())
	assert.ErrorIs(t, err, notify.ErrCertNotSeen, "a certificate seen on another host:port is not trusted for this one")

	// A seen record that names another host:port is refused even when it is still stored (tampered row).
	_, err = h.d.Owner.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('notify.smtp_seen_cert',
jsonb_build_object('fingerprint', $1::text, 'subject', 'x', 'not_after', '2030-01-01T00:00:00Z', 'seen_at', $2::text,
'host', 'elsewhere.example.com', 'port', 587), now()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		srv.Fingerprint(), h.clk.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)
	_, err = h.s.Trust(ctx, h.who, got.Version, srv.Fingerprint())
	assert.ErrorIs(t, err, notify.ErrCertNotSeen)
}

// SEC-037: an administrator's CA bundle verifies a private certificate without a pin.
func TestCABundleTrustsAPrivateCA(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	in := input(srv, nil)
	in.Username, in.CAPEM = "", string(srv.CertPEM())
	_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	require.NoError(t, h.s.TestMail(ctx, h.who, "ops@example.com", "en"))
	in.CAPEM = "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	_, err = h.s.SaveSMTP(ctx, h.who, 1, in)
	require.Error(t, err, "only CERTIFICATE blocks")
	assert.Contains(t, err.Error(), "ca_pem")
}

func TestMailerSourceFallsBackWhenNotConfigured(t *testing.T) {
	fb := &fakeMailer{}
	h := newHarness(t, fb)
	m, release, err := h.s.Mailer(context.Background())
	require.NoError(t, err)
	defer release()
	assert.Same(t, fb, m, "the e2e mailbox (or nil in release) while no mail settings exist")
	h2 := newHarness(t, nil)
	m, release2, err := h2.s.Mailer(context.Background())
	require.NoError(t, err)
	defer release2()
	assert.Nil(t, m, "release without settings: skipped_no_smtp (L-18)")
}

func TestImportEnvOnce(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	files := map[string][]byte{"/run/secrets/smtp": []byte(canary + "\n")}
	read := func(p string) ([]byte, error) { return files[p], nil }
	cfg := config.SMTP{Host: "smtp.example.com", Port: 587, From: "alice@example.com", Username: "mailer",
		PasswordFile: "/run/secrets/smtp", TLSMode: "starttls"}
	done, err := h.s.ImportEnv(ctx, cfg, read)
	require.NoError(t, err)
	assert.True(t, done)
	got, ok, err := h.s.SMTP(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "smtp.example.com", got.Host)
	assert.True(t, got.HasPassword)
	assert.Equal(t, 1, countAudit(t, h.d, "settings.smtp_imported"))
	cfg.Host = "other.example.com"
	done, err = h.s.ImportEnv(ctx, cfg, read)
	require.NoError(t, err)
	assert.False(t, done, "settings exist: the environment is ignored")
	done, err = h.s.ImportEnv(ctx, config.SMTP{}, read)
	require.NoError(t, err)
	assert.False(t, done)
}

// S-12: deleting the mail settings is not undone by the variables that are still set.
func TestImportEnvDoesNotReimportAfterDelete(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	read := func(string) ([]byte, error) { return []byte(canary), nil }
	cfg := config.SMTP{Host: "smtp.example.com", Port: 587, From: "alice@example.com", Username: "mailer",
		PasswordFile: "/run/secrets/smtp", TLSMode: "starttls"}
	done, err := h.s.ImportEnv(ctx, cfg, read)
	require.NoError(t, err)
	require.True(t, done)
	require.NoError(t, h.s.DeleteSMTP(ctx, h.who, 1))
	done, err = h.s.ImportEnv(ctx, cfg, read)
	require.NoError(t, err)
	assert.False(t, done, "the tombstone blocks the re-import")
	_, ok, err := h.s.SMTP(ctx)
	require.NoError(t, err)
	assert.False(t, ok)
	var n int
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT count(*) FROM setting_secrets`).Scan(&n))
	assert.Zero(t, n, "the password was not stored again")
	assert.Equal(t, 1, countAudit(t, h.d, "settings.smtp_imported"))

	// An Administrator saving the settings again makes the tombstone moot; a second delete tombstones again.
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	got, err := h.s.SaveSMTP(ctx, h.who, 0, input(srv, pw(canary)))
	require.NoError(t, err)
	require.NoError(t, h.s.DeleteSMTP(ctx, h.who, got.Version))
	done, err = h.s.ImportEnv(ctx, cfg, read)
	require.NoError(t, err)
	assert.False(t, done)
}

func countAudit(t *testing.T, d *pgtest.DB, action string) int {
	t.Helper()
	var n int
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n))
	return n
}
