package notify_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/testutil/fakesmtp"
)

func smtpConfigFor(s *fakesmtp.Server) notify.SMTPConfig {
	host, port := s.Addr()
	return notify.SMTPConfig{Host: host, Port: port, From: "alice@example.com", TLSMode: "starttls"}
}

// F-62: an untrusted certificate is refused with its fingerprint; a pin accepts exactly that certificate.
func TestF62UntrustedCertificateAndThePin(t *testing.T) {
	s := fakesmtp.Start(t, fakesmtp.Options{})
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	m, err := notify.NewSMTPMailer(smtpConfigFor(s), clk)
	require.NoError(t, err)
	err = m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"})
	var ce *notify.CertError
	require.True(t, errors.As(err, &ce), "%v", err)
	assert.Equal(t, s.Fingerprint(), ce.Cert.Fingerprint)
	assert.Contains(t, ce.Cert.Subject, "127.0.0.1")
	assert.ErrorIs(t, err, notify.ErrSMTPUntrusted)
	assert.ErrorIs(t, err, notify.ErrSMTPTLS)
	assert.Equal(t, "smtp.untrusted", notify.ErrorCode(err))
	assert.Empty(t, s.Messages())

	cfg := smtpConfigFor(s)
	cfg.Pin = s.Fingerprint()
	m, err = notify.NewSMTPMailer(cfg, clk)
	require.NoError(t, err)
	require.NoError(t, m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"}))
	assert.Len(t, s.Messages(), 1)

	cfg.Pin = "00" + s.Fingerprint()[2:]
	m, err = notify.NewSMTPMailer(cfg, clk)
	require.NoError(t, err)
	err = m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"})
	require.True(t, errors.As(err, &ce), "a pin that does not match is an untrusted certificate, with the one served")
	assert.Equal(t, s.Fingerprint(), ce.Cert.Fingerprint)
	assert.Len(t, s.Messages(), 1, "nothing was sent")
}

// A-14: an SMTP host on a refused address is never dialled.
func TestAddressRefused(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	m, err := notify.NewSMTPMailer(notify.SMTPConfig{Host: "169.254.169.254", Port: 587, From: "alice@example.com"}, clk)
	require.NoError(t, err)
	err = m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"})
	assert.ErrorIs(t, err, notify.ErrAddressRefused)
	assert.Equal(t, "smtp.address_refused", notify.ErrorCode(err))
}

// The implicit-TLS path reports the certificate and honours the pin too.
func TestImplicitTLSUntrustedAndPinned(t *testing.T) {
	s := fakesmtp.Start(t, fakesmtp.Options{Implicit: true})
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	cfg := smtpConfigFor(s)
	cfg.TLSMode = "tls"
	m, err := notify.NewSMTPMailer(cfg, clk)
	require.NoError(t, err)
	msg := notify.Message{To: "ops@example.com", Subject: "s", Body: "b"}
	err = m.Send(context.Background(), msg)
	var ce *notify.CertError
	require.True(t, errors.As(err, &ce), "%v", err)
	assert.Equal(t, s.Fingerprint(), ce.Cert.Fingerprint)
	assert.NotContains(t, ce.Error(), s.Fingerprint(), "the error text carries no server data")
	cfg.Pin = s.Fingerprint()
	m, err = notify.NewSMTPMailer(cfg, clk)
	require.NoError(t, err)
	require.NoError(t, m.Send(context.Background(), msg))
	assert.Len(t, s.Messages(), 1)
}

// A handshake that fails for another reason than the certificate is a plain TLS failure.
func TestTLSFailureWithoutACertificateProblem(t *testing.T) {
	s := fakesmtp.Start(t, fakesmtp.Options{}) // speaks plain SMTP, the client wants implicit TLS
	cfg := smtpConfigFor(s)
	cfg.TLSMode = "tls"
	m, err := notify.NewSMTPMailer(cfg, clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)))
	require.NoError(t, err)
	err = m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPTLS)
	assert.NotErrorIs(t, err, notify.ErrSMTPUntrusted)
	assert.Equal(t, "smtp.tls", notify.ErrorCode(err))
}

// The configured dialer replaces the default one.
func TestCustomDialer(t *testing.T) {
	cfg := notify.SMTPConfig{Host: "mail.example.com", Port: 587, From: "alice@example.com",
		Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("down") }}
	m, err := notify.NewSMTPMailer(cfg, clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)))
	require.NoError(t, err)
	err = m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"})
	assert.ErrorIs(t, err, notify.ErrSMTPConnect)
}
