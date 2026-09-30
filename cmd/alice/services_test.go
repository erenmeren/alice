//go:build !e2e

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/version"
)

// implicitTLSServer is a one-connection-at-a-time SMTP server on 127.0.0.1 with implicit
// TLS. It accepts AUTH PLAIN only for wantAuth ("\x00user\x00password").
func implicitTLSServer(t *testing.T, wantAuth string) (port int, caPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test smtp"},
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			smtpSession(c, wantAuth)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func smtpSession(c net.Conn, wantAuth string) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	reply := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	reply("220 test ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			reply("250-test\r\n250 AUTH PLAIN")
		case strings.HasPrefix(cmd, "AUTH PLAIN "):
			got, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(cmd, "AUTH PLAIN "))
			if string(got) != wantAuth {
				reply("535 authentication failed")
				continue
			}
			reply("235 ok")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
			reply("250 ok")
		case cmd == "DATA":
			reply("354 go on")
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
			}
			reply("250 queued")
		case cmd == "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 not implemented")
		}
	}
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}

func smtpConfig(t *testing.T, vars map[string]string) config.Config {
	t.Helper()
	cfg, err := config.Load(env(vars))
	require.NoError(t, err)
	return cfg
}

func sendTestMail(t *testing.T, m notify.Mailer) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.Send(ctx, notify.Message{To: "admin@example.com", Subject: "test", Body: "hello"})
}

// ALICE_SMTP_CA_FILE is trusted for the mail server's certificate, and the password file is
// read without its trailing newline.
func TestNewMailerUsesCAFileAndPasswordFile(t *testing.T) {
	port, caPEM := implicitTLSServer(t, "\x00alice\x00s3cret pw")
	vars := map[string]string{
		"ALICE_SMTP_HOST": "127.0.0.1", "ALICE_SMTP_PORT": strconv.Itoa(port), "ALICE_SMTP_TLS": "tls",
		"ALICE_SMTP_FROM": "alice@example.com", "ALICE_SMTP_USERNAME": "alice",
		"ALICE_SMTP_PASSWORD_FILE": writeFile(t, "pw", []byte("s3cret pw\r\n")),
	}

	withoutCA, err := newMailer(smtpConfig(t, vars), clock.Real{})
	require.NoError(t, err)
	assert.ErrorIs(t, sendTestMail(t, withoutCA), notify.ErrSMTPTLS, "the private CA is not a system root")

	vars["ALICE_SMTP_CA_FILE"] = writeFile(t, "ca.pem", caPEM)
	withCA, err := newMailer(smtpConfig(t, vars), clock.Real{})
	require.NoError(t, err)
	assert.NoError(t, sendTestMail(t, withCA))
}

func TestNewMailerConfigurationErrors(t *testing.T) {
	m, err := newMailer(smtpConfig(t, nil), clock.Real{})
	require.NoError(t, err)
	assert.Nil(t, m, "no SMTP host: the sender records emails as skipped")

	base := map[string]string{"ALICE_SMTP_HOST": "mail.example.com", "ALICE_SMTP_FROM": "alice@example.com"}
	with := func(k, v string) map[string]string {
		out := map[string]string{}
		for bk, bv := range base {
			out[bk] = bv
		}
		out[k] = v
		return out
	}
	withAuth := func(pwFile string) map[string]string {
		out := with("ALICE_SMTP_PASSWORD_FILE", pwFile)
		out["ALICE_SMTP_USERNAME"] = "alice"
		return out
	}
	missing := filepath.Join(t.TempDir(), "missing")
	for name, tc := range map[string]struct {
		vars map[string]string
		want string
	}{
		"password file missing": {withAuth(missing), "read ALICE_SMTP_PASSWORD_FILE " + missing},
		"CA file missing":       {with("ALICE_SMTP_CA_FILE", missing), "read ALICE_SMTP_CA_FILE " + missing},
		"CA file not PEM":       {with("ALICE_SMTP_CA_FILE", writeFile(t, "ca.pem", []byte("not a certificate"))), "holds no PEM certificate"},
		"sender not an address": {with("ALICE_SMTP_FROM", "alice.example.com"), "sender address is not valid"},
	} {
		_, err := newMailer(smtpConfig(t, tc.vars), clock.Real{})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), tc.want, name)
	}
}

// The build time set at link time is the floor of the license clock; a development build
// has none.
func TestBuildTime(t *testing.T) {
	saved := version.BuildTime
	t.Cleanup(func() { version.BuildTime = saved })
	version.BuildTime = "unknown"
	assert.True(t, buildTime().IsZero())
	version.BuildTime = "2026-09-30T12:00:00Z"
	assert.Equal(t, time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC), buildTime())
}
