package notify_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/secrets"
)

const smtpPassword = "s3cret-smtp-pw"

type fakeMessage struct {
	from, to, data string
	secure, authed bool
}

// fakeSMTP is a minimal SMTP server: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA, QUIT.
type fakeSMTP struct {
	ln         net.Listener
	tlsConfig  *tls.Config
	pool       *x509.CertPool
	noStartTLS bool
	implicit   bool
	rejectRcpt bool

	mu       sync.Mutex
	messages []fakeMessage
	authSeen bool
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func newFakeSMTP(t *testing.T, opts ...func(*fakeSMTP)) *fakeSMTP {
	t.Helper()
	cert, pool := selfSigned(t)
	f := &fakeSMTP{tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, pool: pool}
	for _, o := range opts {
		o(f)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	if f.implicit {
		ln = tls.NewListener(ln, f.tlsConfig)
	}
	f.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.session(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) got() []fakeMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeMessage(nil), f.messages...)
}

func (f *fakeSMTP) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	tp := textproto.NewConn(c)
	secure, authed := f.implicit, false
	var from, to string
	_ = tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		switch verb := strings.Fields(line + " x")[0]; verb {
		case "EHLO", "HELO":
			_ = tp.PrintfLine("250-fake greets you")
			if !f.noStartTLS && !secure {
				_ = tp.PrintfLine("250-STARTTLS")
			}
			_ = tp.PrintfLine("250 AUTH PLAIN")
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(c, f.tlsConfig)
			if tc.Handshake() != nil {
				return
			}
			c, tp, secure = tc, textproto.NewConn(tc), true
		case "AUTH":
			f.mu.Lock()
			f.authSeen = true
			f.mu.Unlock()
			parts := strings.Fields(line)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			fields := strings.Split(string(raw), "\x00")
			if len(fields) == 3 && fields[1] == "alice" && fields[2] == smtpPassword {
				authed = true
				_ = tp.PrintfLine("235 ok")
			} else {
				_ = tp.PrintfLine("535 bad credentials")
			}
		case "MAIL":
			from = line
			_ = tp.PrintfLine("250 ok")
		case "RCPT":
			if f.rejectRcpt {
				_ = tp.PrintfLine("550 no such user")
				continue
			}
			to = line
			_ = tp.PrintfLine("250 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go on")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.messages = append(f.messages, fakeMessage{from: from, to: to, data: string(data), secure: secure, authed: authed})
			f.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("250 ok")
		}
	}
}

var mailClock = clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))

func mailer(t *testing.T, f *fakeSMTP, change func(*notify.SMTPConfig)) *notify.SMTPMailer {
	t.Helper()
	c := notify.SMTPConfig{
		Host: "127.0.0.1", Port: f.port(), From: "Alice <alice@example.com>", Username: "alice",
		Password: secrets.NewPlaintext([]byte(smtpPassword)), RootCAs: f.pool,
	}
	if change != nil {
		change(&c)
	}
	m, err := notify.NewSMTPMailer(c, mailClock)
	require.NoError(t, err)
	return m
}

func send(m *notify.SMTPMailer, msg notify.Message) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.Send(ctx, msg)
}

func TestSMTPMailerSendsOverSTARTTLSWithAuth(t *testing.T) {
	f := newFakeSMTP(t)
	err := send(mailer(t, f, nil), notify.Message{To: "ada@example.com", Subject: "Lisans uyarısı", Body: "Merhaba\nİkinci satır"})
	require.NoError(t, err)
	got := f.got()
	require.Len(t, got, 1)
	assert.True(t, got[0].secure, "the message travels only after STARTTLS")
	assert.True(t, got[0].authed)
	assert.Contains(t, got[0].to, "ada@example.com")
	assert.Contains(t, got[0].data, "Subject: =?utf-8?q?Lisans_uyar=C4=B1s=C4=B1?=")
	assert.Contains(t, got[0].data, "Content-Transfer-Encoding: base64")
	// The fake reads DATA with textproto's dot reader, which turns CRLF into LF.
	body := strings.SplitN(got[0].data, "\n\n", 2)[1]
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\n", ""))
	require.NoError(t, err)
	assert.Equal(t, "Merhaba\r\nİkinci satır", string(decoded))
}

func TestSMTPMailerImplicitTLS(t *testing.T) {
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.implicit = true })
	require.NoError(t, send(mailer(t, f, func(c *notify.SMTPConfig) { c.TLSMode = "tls" }), notify.Message{To: "ada@example.com", Subject: "s", Body: "b"}))
	require.Len(t, f.got(), 1)
	assert.True(t, f.got()[0].secure)
}

// No plaintext fallback: without STARTTLS nothing is sent and the password never leaves.
func TestSMTPMailerRequiresTLS(t *testing.T) {
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.noStartTLS = true })
	err := send(mailer(t, f, nil), notify.Message{To: "ada@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPTLS)
	assert.Equal(t, "smtp.tls", notify.ErrorCode(err))
	assert.Empty(t, f.got())
	f.mu.Lock()
	assert.False(t, f.authSeen, "credentials are never sent unencrypted")
	f.mu.Unlock()
}

func TestSMTPMailerRejectsAnUntrustedCertificate(t *testing.T) {
	f := newFakeSMTP(t)
	err := send(mailer(t, f, func(c *notify.SMTPConfig) { c.RootCAs = x509.NewCertPool() }), notify.Message{To: "ada@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPTLS)
	assert.Empty(t, f.got())
}

func TestSMTPMailerFailures(t *testing.T) {
	f := newFakeSMTP(t)
	err := send(mailer(t, f, func(c *notify.SMTPConfig) { c.Password = secrets.NewPlaintext([]byte("wrong-smtp-pw")) }),
		notify.Message{To: "ada@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPAuth)
	assert.NotContains(t, err.Error(), "wrong-smtp-pw")

	r := newFakeSMTP(t, func(f *fakeSMTP) { f.rejectRcpt = true })
	err = send(mailer(t, r, nil), notify.Message{To: "nobody@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPRejected)

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := closed.Addr().(*net.TCPAddr).Port
	require.NoError(t, closed.Close())
	err = send(mailer(t, f, func(c *notify.SMTPConfig) { c.Port = port }), notify.Message{To: "ada@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPConnect)
}

// Header injection through a subject is impossible.
func TestSMTPMailerKeepsTheSubjectOnOneLine(t *testing.T) {
	f := newFakeSMTP(t)
	require.NoError(t, send(mailer(t, f, nil), notify.Message{To: "ada@example.com", Subject: "Hi\r\nBcc: evil@example.com", Body: "b"}))
	for _, line := range strings.Split(f.got()[0].data, "\n") {
		assert.False(t, strings.HasPrefix(line, "Bcc:"), line)
	}
}

func TestNewSMTPMailerValidatesItsConfiguration(t *testing.T) {
	good := notify.SMTPConfig{Host: "mail.example.com", Port: 587, From: "alice@example.com"}
	_, err := notify.NewSMTPMailer(good, mailClock)
	require.NoError(t, err)
	for name, change := range map[string]func(*notify.SMTPConfig){
		"no host":    func(c *notify.SMTPConfig) { c.Host = "" },
		"bad host":   func(c *notify.SMTPConfig) { c.Host = "mail example" },
		"port 0":     func(c *notify.SMTPConfig) { c.Port = 0 },
		"port 70000": func(c *notify.SMTPConfig) { c.Port = 70000 },
		"bad sender": func(c *notify.SMTPConfig) { c.From = "not an address" },
		"plain mode": func(c *notify.SMTPConfig) { c.TLSMode = "none" },
	} {
		c := good
		change(&c)
		_, err := notify.NewSMTPMailer(c, mailClock)
		assert.Error(t, err, name)
	}
}
