//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// startTLS serves leaf on 127.0.0.1 and returns the port; sni receives the server name of each
// handshake.
func startTLS(t *testing.T, leaf pki.Leaf, sni chan<- string) string {
	t.Helper()
	cert, err := tls.X509KeyPair(leaf.FullchainPEM, leaf.KeyPEM)
	require.NoError(t, err)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			if sni != nil {
				sni <- h.ServerName
			}
			return nil, nil
		}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

func TestTLSProbeReportsTheServedLeaf(t *testing.T) {
	f := newFixture(t)
	f.s.euid = func() int { return 1000 } // runs without sudo
	ca := pki.NewCA("Probe", pki.ECDSA256, testNow)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	sni := make(chan string, 4)
	port := startTLS(t, leaf, sni)
	code, m := f.run("tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", "www.example.test", "--key-type", "any")
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), m["leaf_sha256"])
	assert.Equal(t, float64(2), m["chain_length"])
	assert.Equal(t, leaf.Cert.NotAfter.UTC().Format(time.RFC3339), m["not_after"])
	assert.Equal(t, "www.example.test", <-sni)
	code, m = f.run("tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", helperproto.NoSNI, "--key-type", "ecdsa")
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "", <-sni, "_ sends no server name")
	assert.Empty(t, f.loggedLines(), "an unprivileged probe writes no log line")
}

func TestTLSProbeFailures(t *testing.T) {
	f := newFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	require.NoError(t, ln.Close())
	code, m := f.run("tls-probe", "--addr", "127.0.0.1", "--port", closedPort, "--sni", "a.example.test", "--key-type", "any")
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeProbeFailed, m["code"])

	// A plain TCP server that never speaks TLS: the handshake fails (or times out) and is reported.
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = plain.Close() })
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
			_ = c.Close()
		}
	}()
	port := strconv.Itoa(plain.Addr().(*net.TCPAddr).Port)
	code, m = f.run("tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", "a.example.test", "--key-type", "any")
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeProbeFailed, m["code"])

	// RSA requested from an ECDSA-only server: no common suite.
	leaf := pki.NewCA("Probe", pki.ECDSA256, testNow).Issue(pki.Opts{CommonName: "a.example.test"}, testNow)
	port = startTLS(t, leaf, nil)
	code, m = f.run("tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", "a.example.test", "--key-type", "rsa")
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeProbeFailed, m["code"])
}

func TestTLSProbeIsBounded(t *testing.T) {
	f := newFixture(t)
	var dialed string
	f.s.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = network + " " + addr
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		go func() { // a server that reads the hello and never answers
			buf := make([]byte, 4096)
			for {
				if _, err := server.Read(buf); err != nil {
					return
				}
			}
		}()
		return client, nil
	}
	old := probeTimeout
	probeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { probeTimeout = old })
	start := time.Now()
	code, m := f.run("tls-probe", "--addr", "::1", "--port", "8443", "--sni", "a.example.test", "--key-type", "any")
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeProbeFailed, m["code"])
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Equal(t, "tcp [::1]:8443", dialed)

	f.s.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	code, _ = f.run("tls-probe", "--addr", "10.0.0.1", "--port", "443", "--sni", "a.example.test", "--key-type", "any")
	assert.Equal(t, helperproto.ExitFailed, code)
}

// Requirement 10: the argument vector is fixed (count, order, flags) and every value validated.
func TestTLSProbeArguments(t *testing.T) {
	f := newFixture(t)
	f.s.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("nothing is dialed for a refused vector")
		return nil, nil
	}
	ok := []string{"--addr", "127.0.0.1", "--port", "443", "--sni", "a.b", "--key-type", "any"}
	for _, tc := range []struct {
		args []string
		code string
	}{
		{nil, helperproto.CodeUsage},
		{ok[:7], helperproto.CodeUsage},
		{ok[:6], helperproto.CodeUsage},
		{append(append([]string{}, ok...), "--extra"), helperproto.CodeUsage},
		{append(append([]string{}, ok...), "--sni", "c.d"), helperproto.CodeUsage},
		{[]string{"--port", "443", "--addr", "127.0.0.1", "--sni", "a.b", "--key-type", "any"}, helperproto.CodeUsage},
		{[]string{"--addr", "127.0.0.1", "--port", "443", "--key-type", "any", "--sni", "a.b"}, helperproto.CodeUsage},
		{[]string{"--addr", "127.0.0.1", "--addr", "127.0.0.1", "--sni", "a.b", "--key-type", "any"}, helperproto.CodeUsage},
		{[]string{"--addr=127.0.0.1", "--port", "443", "--sni", "a.b", "--key-type", "any", "x"}, helperproto.CodeUsage},
		{[]string{"--addr", "localhost", "--port", "443", "--sni", "a.b", "--key-type", "any"}, helperproto.CodeInvalidArgument},
		{[]string{"--addr", "127.000.0.1", "--port", "443", "--sni", "a.b", "--key-type", "any"}, helperproto.CodeInvalidArgument},
		{[]string{"--addr", "fe80::1%eth0", "--port", "443", "--sni", "a.b", "--key-type", "any"}, helperproto.CodeInvalidArgument},
		{[]string{"--addr", "127.0.0.1", "--port", "0", "--sni", "a.b", "--key-type", "any"}, helperproto.CodeInvalidArgument},
		{[]string{"--addr", "127.0.0.1", "--port", "65536", "--sni", "a.b", "--key-type", "any"}, helperproto.CodeInvalidArgument},
		{[]string{"--addr", "127.0.0.1", "--port", "443", "--sni", "A.B", "--key-type", "any"}, helperproto.CodeInvalidArgument},
		{[]string{"--addr", "127.0.0.1", "--port", "443", "--sni", "10.0.0.1", "--key-type", "any"}, helperproto.CodeInvalidArgument},
		{[]string{"--addr", "127.0.0.1", "--port", "443", "--sni", "", "--key-type", "any"}, helperproto.CodeInvalidArgument},
		{[]string{"--addr", "127.0.0.1", "--port", "443", "--sni", "a.b", "--key-type", "dsa"}, helperproto.CodeInvalidArgument},
	} {
		code, m := f.run(append([]string{"tls-probe"}, tc.args...)...)
		assert.Equal(t, helperproto.ExitRefused, code, "%v", tc.args)
		assert.Equal(t, tc.code, m["code"], "%v", tc.args)
	}
}
