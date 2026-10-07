package fakesmtp

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"net/textproto"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const raw = "From: <alice@example.com>\r\nTo: <ops@example.com>\r\nSubject: =?utf-8?q?S=C3=BCre_doldu?=\r\n" +
	"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
	"U8O8cmUgZG9sZHU6IHd3dy5leGFtcGxlLnRlc3QK\r\n"

func send(t *testing.T, s *Server, auth smtp.Auth, to string) error {
	t.Helper()
	host, port := s.Addr()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(s.CertPEM()))
	c, err := smtp.Dial(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := c.StartTLS(&tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail("alice@example.com"); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(raw)); err != nil {
		return err
	}
	return w.Close()
}

// codeOf is the SMTP reply code of err, or 0 when err is nil or not a reply.
func codeOf(err error) int {
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code
	}
	return 0
}

func TestStoresDecodedMessagesOverSTARTTLS(t *testing.T) {
	s := Start(t, Options{})
	require.NoError(t, send(t, s, nil, "ops@example.com"))
	msgs := s.Messages()
	require.Len(t, msgs, 1)
	assert.Equal(t, "alice@example.com", msgs[0].From)
	assert.Equal(t, []string{"ops@example.com"}, msgs[0].To)
	assert.Equal(t, "Süre doldu", msgs[0].Subject)
	assert.Equal(t, "Süre doldu: www.example.test\n", msgs[0].Body)
	assert.True(t, msgs[0].Secure)
	assert.Regexp(t, `^[0-9a-f]{64}$`, s.Fingerprint())
	s.Clear()
	assert.Empty(t, s.Messages())
}

func TestRequiresAuthWhenConfigured(t *testing.T) {
	s := Start(t, Options{Username: "mailer", Password: "pw-1"})
	host, _ := s.Addr()
	assert.Equal(t, 530, codeOf(send(t, s, nil, "ops@example.com")), "MAIL without AUTH")
	assert.Equal(t, 535, codeOf(send(t, s, smtp.PlainAuth("", "mailer", "wrong", host), "ops@example.com")))
	require.NoError(t, send(t, s, smtp.PlainAuth("", "mailer", "pw-1", host), "ops@example.com"))
	assert.True(t, s.Messages()[0].Authed)
}

func TestFaultSwitches(t *testing.T) {
	s := Start(t, Options{})
	s.RejectRecipient("bad@example.com")
	assert.Equal(t, 550, codeOf(send(t, s, nil, "bad@example.com")))
	require.NoError(t, send(t, s, nil, "ops@example.com"))
	s.Down()
	assert.Error(t, send(t, s, nil, "ops@example.com"), "connections are refused while down")
	require.NoError(t, s.Up())
	require.NoError(t, send(t, s, nil, "ops@example.com"))
	assert.Len(t, s.Messages(), 2)
}

func TestMailHogAPI(t *testing.T) {
	s := Start(t, Options{})
	require.NoError(t, send(t, s, nil, "ops@example.com"))
	h := s.Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v2/messages", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var got struct {
		Total int `json:"total"`
		Items []struct {
			From    struct{ Mailbox, Domain string }
			Content struct {
				Headers map[string][]string
				Body    string
			}
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, 1, got.Total)
	assert.Equal(t, "alice", got.Items[0].From.Mailbox)
	assert.Equal(t, []string{"Süre doldu"}, got.Items[0].Content.Headers["Subject"])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/messages", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, s.Messages())
}

func TestImplicitTLSStoresSecureMessages(t *testing.T) {
	s := Start(t, Options{Implicit: true})
	host, port := s.Addr()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(s.CertPEM()))
	conn, err := tls.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	c, err := smtp.NewClient(conn, host)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.Mail("alice@example.com"))
	require.NoError(t, c.Rcpt("ops@example.com"))
	w, err := c.Data()
	require.NoError(t, err)
	_, err = w.Write([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Len(t, s.Messages(), 1)
	assert.True(t, s.Messages()[0].Secure)
	plain, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	require.NoError(t, err)
	defer func() { _ = plain.Close() }()
	require.NoError(t, plain.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	_, err = textproto.NewReader(bufio.NewReader(plain)).ReadLine()
	assert.Error(t, err, "a plaintext client gets no SMTP banner from an implicit-TLS listener")
}

func TestNoStartTLSOffersNoUpgradeAndNoAuthInTheClear(t *testing.T) {
	s := Start(t, Options{NoStartTLS: true, Username: "mailer", Password: "pw-1"})
	assert.Equal(t, 503, codeOf(send(t, s, nil, "ops@example.com")), "STARTTLS is refused")

	host, port := s.Addr()
	conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	require.NoError(t, err)
	tp := textproto.NewConn(conn)
	defer func() { _ = tp.Close() }()
	_, _, err = tp.ReadResponse(220)
	require.NoError(t, err)
	require.NoError(t, tp.PrintfLine("EHLO test"))
	_, msg, err := tp.ReadResponse(250)
	require.NoError(t, err)
	assert.NotContains(t, msg, "STARTTLS")
	assert.NotContains(t, msg, "AUTH", "AUTH is offered only inside TLS")
	require.NoError(t, tp.PrintfLine("AUTH PLAIN %s", base64.StdEncoding.EncodeToString([]byte("\x00mailer\x00pw-1"))))
	code, _, err := tp.ReadResponse(0)
	if err != nil {
		var te *textproto.Error
		require.ErrorAs(t, err, &te)
		code = te.Code
	}
	assert.Equal(t, 535, code, "the right password in the clear is still refused")
	assert.Empty(t, s.Messages())
}
