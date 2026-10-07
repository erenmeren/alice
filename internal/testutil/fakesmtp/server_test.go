package fakesmtp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strconv"
	"testing"

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
	assert.Error(t, send(t, s, nil, "ops@example.com"), "MAIL without AUTH")
	assert.Error(t, send(t, s, smtp.PlainAuth("", "mailer", "wrong", host), "ops@example.com"))
	require.NoError(t, send(t, s, smtp.PlainAuth("", "mailer", "pw-1", host), "ops@example.com"))
	assert.True(t, s.Messages()[0].Authed)
}

func TestFaultSwitches(t *testing.T) {
	s := Start(t, Options{})
	s.RejectRecipient("bad@example.com")
	assert.Error(t, send(t, s, nil, "bad@example.com"))
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
