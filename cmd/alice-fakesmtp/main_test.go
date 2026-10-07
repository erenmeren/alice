package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type running struct {
	smtpAddr, apiAddr string
	stopped           chan error
	cancel            context.CancelFunc
	logs              *bytes.Buffer
}

func start(t *testing.T) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{stopped: make(chan error, 1), cancel: cancel, logs: &bytes.Buffer{}}
	ready := make(chan struct{})
	cfg := serveConfig{Listen: "127.0.0.1:0", API: "127.0.0.1:0", Hostname: "fakesmtp", ready: func(s, a string) {
		r.smtpAddr, r.apiAddr = s, a
		close(ready)
	}}
	go func() { r.stopped <- serve(ctx, cfg, slog.New(slog.NewTextHandler(r.logs, nil))) }()
	select {
	case <-ready:
	case err := <-r.stopped:
		t.Fatalf("serve stopped: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not start")
	}
	t.Cleanup(func() { cancel() })
	return r
}

func (r *running) ctl(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"ctl", "--api", r.apiAddr}, args...), &out, &errb)
	return out.String(), errb.String(), code
}

func (r *running) ctlOK(t *testing.T, args ...string) string {
	t.Helper()
	out, errs, code := r.ctl(t, args...)
	require.Equal(t, 0, code, errs)
	return out
}

func sendMail(addr, user, pass, to string) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := c.StartTLS(&tls.Config{ServerName: "fakesmtp", MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}); err != nil { //nolint:gosec // G402: the fake's self-signed certificate; this test only needs the encrypted channel
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	if err := c.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
		return err
	}
	if err := c.Mail("alice@example.test"); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, "Subject: hello\r\nFrom: alice@example.test\r\nTo: "+to+"\r\n\r\nbody text\r\n"); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func TestServeRefusesANonLoopbackAdminAddress(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:8025", ":8025", "localhost:8025", "10.0.0.1:8025", "[::ffff:127.0.0.1]:8025", "127.0.0.1", "127.0.0.1:99999"} {
		var errb bytes.Buffer
		code := run(context.Background(), []string{"serve", "--listen", "127.0.0.1:0", "--api", bad}, io.Discard, &errb)
		assert.Equal(t, 2, code, bad)
		assert.Contains(t, errb.String(), "loopback", bad)
	}
	var errb bytes.Buffer
	assert.Equal(t, 2, run(context.Background(), []string{"ctl", "--api", "10.0.0.1:8025", "ping"}, io.Discard, &errb))
	assert.Contains(t, errb.String(), "loopback")
}

func TestCtlRoundTrip(t *testing.T) {
	r := start(t)
	assert.Equal(t, "ok\n", r.ctlOK(t, "ping"))

	var creds struct{ Username, Password string }
	require.NoError(t, json.Unmarshal([]byte(r.ctlOK(t, "credentials")), &creds))
	assert.Equal(t, "mailer", creds.Username)
	assert.GreaterOrEqual(t, len(creds.Password), 40)
	var fp struct{ Fingerprint string }
	require.NoError(t, json.Unmarshal([]byte(r.ctlOK(t, "fingerprint")), &fp))
	assert.Regexp(t, `^[0-9a-f]{64}$`, fp.Fingerprint)

	require.Error(t, sendMail(r.smtpAddr, "mailer", "wrong", "ada@example.test"), "a wrong password is refused")
	require.NoError(t, sendMail(r.smtpAddr, creds.Username, creds.Password, "ada@example.test"))
	var list struct {
		Total int
		Items []struct {
			Content struct {
				Body    string
				Headers map[string][]string
			}
		}
	}
	require.NoError(t, json.Unmarshal([]byte(r.ctlOK(t, "messages")), &list))
	require.Equal(t, 1, list.Total)
	assert.Equal(t, []string{"hello"}, list.Items[0].Content.Headers["Subject"])
	assert.Contains(t, list.Items[0].Content.Body, "body text")

	assert.JSONEq(t, `{"ok": true}`, r.ctlOK(t, "clear"))
	require.NoError(t, json.Unmarshal([]byte(r.ctlOK(t, "messages")), &list))
	assert.Equal(t, 0, list.Total)

	assert.JSONEq(t, `{"ok": true}`, r.ctlOK(t, "reject", "bad@example.test"))
	require.Error(t, sendMail(r.smtpAddr, creds.Username, creds.Password, "bad@example.test"))
	require.NoError(t, sendMail(r.smtpAddr, creds.Username, creds.Password, "ada@example.test"))
	assert.JSONEq(t, `{"ok": true}`, r.ctlOK(t, "reject"))
	require.NoError(t, sendMail(r.smtpAddr, creds.Username, creds.Password, "bad@example.test"))

	assert.JSONEq(t, `{"ok": true}`, r.ctlOK(t, "down"))
	_, err := net.DialTimeout("tcp", r.smtpAddr, time.Second)
	require.Error(t, err, "down refuses connections")
	assert.Equal(t, "ok\n", r.ctlOK(t, "ping"), "the API still answers")
	assert.JSONEq(t, `{"ok": true}`, r.ctlOK(t, "up"))
	c, err := net.DialTimeout("tcp", r.smtpAddr, time.Second)
	require.NoError(t, err, "up accepts them again")
	_ = c.Close()

	assert.NotContains(t, r.logs.String(), creds.Password, "the password is never logged")
	r.cancel()
	require.NoError(t, <-r.stopped, "SIGTERM-style cancellation stops cleanly")
}

func TestCtlErrors(t *testing.T) {
	r := start(t)
	for _, tc := range [][]string{{}, {"nope"}, {"ping", "extra"}, {"reject", "a", "b"}} {
		_, errs, code := r.ctl(t, tc...)
		assert.NotEqual(t, 0, code, tc)
		assert.NotEmpty(t, errs)
	}
	assert.Equal(t, 2, run(context.Background(), nil, io.Discard, io.Discard))
	assert.Equal(t, 2, run(context.Background(), []string{"bogus"}, io.Discard, io.Discard))
	assert.Equal(t, 2, run(context.Background(), []string{"serve", "extra"}, io.Discard, io.Discard))
	assert.Equal(t, 2, run(context.Background(), []string{"serve", "--nope"}, io.Discard, io.Discard))
	assert.Equal(t, 2, run(context.Background(), []string{"ctl", "--nope"}, io.Discard, io.Discard))
	// No server at the address.
	var errb bytes.Buffer
	code := run(context.Background(), []string{"ctl", "--api", "127.0.0.1:1", "ping"}, io.Discard, &errb)
	assert.Equal(t, 1, code)
	assert.True(t, strings.Contains(errb.String(), "does not answer"))
	// A listen address already taken fails serve with exit 1.
	assert.Equal(t, 1, run(context.Background(), []string{"serve", "--listen", r.smtpAddr, "--api", "127.0.0.1:0"}, io.Discard, io.Discard))
	assert.Equal(t, 1, run(context.Background(), []string{"serve", "--listen", "127.0.0.1:0", "--api", r.apiAddr}, io.Discard, io.Discard))
}

func TestRejectNeedsAJSONBody(t *testing.T) {
	r := start(t)
	resp, err := (&tlsFreeClient{}).post("http://" + r.apiAddr + "/ctl/reject")
	require.NoError(t, err)
	assert.Equal(t, 400, resp)
}

type tlsFreeClient struct{}

func (*tlsFreeClient) post(u string) (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, u, strings.NewReader("not json"))
	if err != nil {
		return 0, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = res.Body.Close() }()
	return res.StatusCode, nil
}
