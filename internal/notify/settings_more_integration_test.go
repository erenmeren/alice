//go:build integration

package notify_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/i18n"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
	"alice/internal/testutil/fakesmtp"
	"alice/internal/testutil/pgtest"
	"alice/locales"
)

func fieldsOf(t *testing.T, err error) map[string]string {
	t.Helper()
	var verrs validate.Errors
	require.True(t, errors.As(err, &verrs), "%v", err)
	out := map[string]string{}
	for _, f := range verrs {
		out[f.Field] = f.Code
	}
	return out
}

func TestSaveSMTPFieldRules(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	save := func(mut func(*notify.SMTPInput)) error {
		in := input(srv, pw(canary))
		mut(&in)
		_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
		return err
	}
	cert := string(srv.CertPEM())
	cases := []struct {
		name string
		mut  func(*notify.SMTPInput)
		want map[string]string
	}{
		{"empty host", func(in *notify.SMTPInput) { in.Host = "" }, map[string]string{"host": validate.Required}},
		{"long host", func(in *notify.SMTPInput) { in.Host = strings.Repeat("a", 254) }, map[string]string{"host": validate.TooLong}},
		{"slash in host", func(in *notify.SMTPInput) { in.Host = "a/b" }, map[string]string{"host": validate.Pattern}},
		{"port high", func(in *notify.SMTPInput) { in.Port = 70000 }, map[string]string{"port": validate.OutOfRange}},
		{"empty tls mode", func(in *notify.SMTPInput) { in.TLSMode = "" }, map[string]string{"tls_mode": validate.OneOf}},
		{"empty from", func(in *notify.SMTPInput) { in.From = "" }, map[string]string{"from": validate.Email}},
		{"long from", func(in *notify.SMTPInput) { in.From = strings.Repeat("a", 250) + "@example.com" }, map[string]string{"from": validate.Email}},
		{"long username", func(in *notify.SMTPInput) { in.Username = strings.Repeat("u", 256) }, map[string]string{"username": validate.TooLong}},
		{"control in username", func(in *notify.SMTPInput) { in.Username = "a\nb" }, map[string]string{"username": validate.Pattern}},
		{"long password", func(in *notify.SMTPInput) { in.Password = pw(strings.Repeat("p", 1025)) }, map[string]string{"password": validate.TooLong}},
		{"username without password", func(in *notify.SMTPInput) { in.Password = nil }, map[string]string{"password": validate.Required}},
		{"empty password with username", func(in *notify.SMTPInput) { e := secrets.NewPlaintext(nil); in.Password = &e }, map[string]string{"password": validate.Required}},
		{"ca too long", func(in *notify.SMTPInput) { in.CAPEM = strings.Repeat("x", 65*1024) }, map[string]string{"ca_pem": validate.TooLong}},
		{"ca garbage", func(in *notify.SMTPInput) { in.CAPEM = "not pem" }, map[string]string{"ca_pem": validate.Pattern}},
		{"ca trailing text", func(in *notify.SMTPInput) { in.CAPEM = cert + "tail" }, map[string]string{"ca_pem": validate.Pattern}},
		{"ca bad certificate", func(in *notify.SMTPInput) {
			in.CAPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		}, map[string]string{"ca_pem": validate.Pattern}},
		{"ca 21 certificates", func(in *notify.SMTPInput) { in.CAPEM = strings.Repeat(cert, 21) }, map[string]string{"ca_pem": validate.TooLong}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, fieldsOf(t, save(c.mut)))
		})
	}
	_, ok, err := h.s.SMTP(ctx)
	require.NoError(t, err)
	assert.False(t, ok, "nothing was stored")
	require.NoError(t, save(func(in *notify.SMTPInput) { in.CAPEM = strings.Repeat(cert, 20) }), "20 certificates are fine")
}

func TestOperationsWithoutSettingsOrWithAStaleVersion(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	assert.ErrorIs(t, h.s.TestMail(ctx, h.who, "ops@example.com", "en"), notify.ErrNotConfigured)
	assert.Equal(t, map[string]string{"to": validate.Email}, fieldsOf(t, h.s.TestMail(ctx, h.who, "nope", "en")))
	assert.Equal(t, map[string]string{"fingerprint": validate.Pattern}, fieldsOf(t, errOf(h.s.Trust(ctx, h.who, 0, "XYZ"))))
	assert.ErrorIs(t, errOf(h.s.Trust(ctx, h.who, 0, strings.Repeat("ab", 32))), notify.ErrNotConfigured)
	assert.ErrorIs(t, errOf(h.s.Untrust(ctx, h.who, 0)), notify.ErrNotConfigured)
	assert.ErrorIs(t, h.s.DeleteSMTP(ctx, h.who, 0), notify.ErrNotConfigured)

	srv := fakesmtp.Start(t, fakesmtp.Options{})
	_, err := h.s.SaveSMTP(ctx, h.who, 0, input(srv, pw(canary)))
	require.NoError(t, err)
	assert.ErrorIs(t, errOf(h.s.Trust(ctx, h.who, 0, strings.Repeat("ab", 32))), notify.ErrVersion)
	assert.ErrorIs(t, errOf(h.s.Untrust(ctx, h.who, 0)), notify.ErrVersion)
	assert.ErrorIs(t, h.s.DeleteSMTP(ctx, h.who, 0), notify.ErrVersion)
}

func errOf(_ notify.SMTPSettings, err error) error { return err }

func TestUntrustDropsThePin(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	in := input(srv, nil)
	in.Username = ""
	_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	var ce *notify.CertError
	require.True(t, errors.As(h.s.TestMail(ctx, h.who, "ops@example.com", "en"), &ce))
	got, err := h.s.Trust(ctx, h.who, 1, srv.Fingerprint())
	require.NoError(t, err)
	_, err = h.s.Trust(ctx, h.who, got.Version, srv.Fingerprint())
	assert.ErrorIs(t, err, notify.ErrCertNotSeen, "a trust request is single-use")
	got, err = h.s.Untrust(ctx, h.who, got.Version)
	require.NoError(t, err)
	assert.Nil(t, got.Trusted)
	assert.Equal(t, 3, got.Version)
	assert.Equal(t, 1, countAudit(t, h.d, "settings.smtp_untrusted"))
	assert.Equal(t, 1, countAudit(t, h.d, "settings.smtp_trusted"))
	assert.Error(t, h.s.TestMail(ctx, h.who, "ops@example.com", "en"), "the certificate is untrusted again")
}

func TestSettingsDialIsUsed(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	called := false
	s := notify.NewSettings(notify.SettingsConfig{Pool: h.d.App, Keyring: mustKeyring(t), Audit: audit.New(h.clk), Clock: h.clk,
		Catalog: mustCatalog(t), Dial: func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, errors.New("down")
		}})
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	in := input(srv, nil)
	in.Username = ""
	_, err := s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	assert.ErrorIs(t, s.TestMail(ctx, h.who, "ops@example.com", "en"), notify.ErrSMTPConnect)
	assert.True(t, called)
}

func mustKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	return k
}

func mustCatalog(t *testing.T) *i18n.Catalog {
	t.Helper()
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	return cat
}

type sourceFunc func(ctx context.Context) (notify.Mailer, func(), error)

func (f sourceFunc) Mailer(ctx context.Context) (notify.Mailer, func(), error) { return f(ctx) }

// The sender takes the mailer of the current settings at every drain, and releases it.
func TestSenderUsesTheMailerSource(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	clk := clock.NewFake(start)
	addUser(t, h.d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, h.d, clk, license.TemplateGrace)

	// No settings and no fallback: the row is skipped (L-18).
	snd := &notify.Sender{Pool: h.d.App, Source: h.s, Catalog: mustCatalog(t), Clock: clk, Log: slog.New(slog.DiscardHandler)}
	n, err := snd.Drain(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, map[string]int{"skipped_no_smtp": 1}, statuses(t, h.d))

	// With settings (the CA verifies the server), the next row is delivered through them.
	srv := fakesmtp.Start(t, fakesmtp.Options{Username: "mailer", Password: canary})
	in := input(srv, pw(canary))
	in.CAPEM = string(srv.CertPEM())
	_, err = h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	queue(t, h.d, clk, license.TemplateGrace)
	n, err = snd.Drain(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	require.Len(t, srv.Messages(), 1)
	assert.True(t, srv.Messages()[0].Authed)
	assert.Equal(t, map[string]int{"skipped_no_smtp": 1, "sent": 1}, statuses(t, h.d))
}

func TestSenderSourceErrorClaimsNothing(t *testing.T) {
	h := newHarness(t, nil)
	clk := clock.NewFake(start)
	addUser(t, h.d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, h.d, clk, license.TemplateGrace)
	boom := errors.New("boom")
	snd := &notify.Sender{Pool: h.d.App, Catalog: mustCatalog(t), Clock: clk, Log: slog.New(slog.DiscardHandler),
		Source: sourceFunc(func(context.Context) (notify.Mailer, func(), error) { return nil, func() {}, boom })}
	n, err := snd.Drain(context.Background())
	assert.ErrorIs(t, err, boom)
	assert.Zero(t, n)
	assert.Equal(t, map[string]int{"pending": 1}, statuses(t, h.d))
}

func TestMailerReleaseZeroesThePassword(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	_, err := h.s.SaveSMTP(ctx, h.who, 0, input(srv, pw(canary)))
	require.NoError(t, err)
	m, release, err := h.s.Mailer(ctx)
	require.NoError(t, err)
	require.NotNil(t, m)
	release()
}

func TestImportEnvEdges(t *testing.T) {
	var logs bytes.Buffer
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	s := notify.NewSettings(notify.SettingsConfig{Pool: d.App, Keyring: mustKeyring(t), Audit: audit.New(clk), Clock: clk,
		Catalog: mustCatalog(t), Log: slog.New(slog.NewTextHandler(&logs, nil))})
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	files := map[string][]byte{"/pw": []byte(canary + "\r\n"), "/ca": srv.CertPEM(), "/empty": nil}
	read := func(p string) ([]byte, error) {
		b, ok := files[p]
		if !ok {
			return nil, errors.New("no such file")
		}
		return append([]byte(nil), b...), nil
	}
	base := config.SMTP{Host: "smtp.example.com", Port: 587, From: "alice@example.com", Username: "mailer"}

	bad := base
	bad.PasswordFile = "/missing"
	_, err := s.ImportEnv(ctx, bad, read)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), canary)
	bad = base
	bad.CAFile = "/missing"
	_, err = s.ImportEnv(ctx, bad, read)
	require.Error(t, err)
	bad = base
	bad.Port = 0
	_, err = s.ImportEnv(ctx, bad, read)
	assert.Equal(t, map[string]string{"port": validate.OutOfRange}, fieldsOf(t, err))
	_, ok, err := s.SMTP(ctx)
	require.NoError(t, err)
	assert.False(t, ok, "a failed import stores nothing")

	good := base
	good.PasswordFile, good.CAFile = "/pw", "/ca"
	done, err := s.ImportEnv(ctx, good, read)
	require.NoError(t, err)
	assert.True(t, done)
	got, ok, err := s.SMTP(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, notify.TLSModeSTARTTLS, got.TLSMode, "an empty mode is STARTTLS")
	assert.NotEmpty(t, got.CAPEM)
	p, found, err := mustKeyring(t).GetSetting(ctx, d.App, "notify.smtp.password")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, canary, string(p.Bytes()), "one trailing line ending is trimmed")
	done, err = s.ImportEnv(ctx, good, read)
	require.NoError(t, err)
	assert.False(t, done)
	assert.Contains(t, logs.String(), "ALICE_SMTP_* is set")
	assert.NotContains(t, logs.String(), canary)
}
