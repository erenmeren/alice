package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakefleet"
)

type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func noEnv(string) string { return "" }

func TestParseServeDefaults(t *testing.T) {
	cfg, err := parseServe(nil, noEnv, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0", cfg.Bind)
	assert.Equal(t, "fleet.alice-e2e.test", cfg.Domain)
	assert.Equal(t, "127.0.0.1:9092", cfg.Ctl)
	assert.Equal(t, fakefleet.AllKinds, cfg.Kinds)
	assert.Equal(t, fakefleet.DefaultPorts, cfg.Ports)
	assert.Equal(t, time.Second, cfg.SlowLorisInterval)
	assert.Equal(t, 443, cfg.Ports[fakefleet.KindValid])
}

func TestParseServeFlagsAndEnvironment(t *testing.T) {
	env := map[string]string{"FAKEFLEET_BIND": "10.89.0.10", "FAKEFLEET_KINDS": "valid,expired", "FAKEFLEET_PORTS": "valid=8443"}
	cfg, err := parseServe(nil, func(k string) string { return env[k] }, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Equal(t, "10.89.0.10", cfg.Bind)
	assert.Equal(t, []fakefleet.Kind{fakefleet.KindValid, fakefleet.KindExpired}, cfg.Kinds)
	assert.Equal(t, 8443, cfg.Ports[fakefleet.KindValid])
	assert.Equal(t, 9401, cfg.Ports[fakefleet.KindExpired], "the other ports keep their defaults")

	cfg, err = parseServe([]string{"--bind", "127.0.0.1", "--kinds", "all", "--ports", "tls10=0, tls12=0", "--domain", "fleet.example.test",
		"--ctl", "127.0.0.1:0", "--slowloris-interval", "50ms"}, func(k string) string { return env[k] }, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", cfg.Bind, "a flag wins over the environment")
	assert.Equal(t, fakefleet.AllKinds, cfg.Kinds)
	assert.Equal(t, 0, cfg.Ports[fakefleet.KindTLS10])
	assert.Equal(t, 0, cfg.Ports[fakefleet.KindTLS12])
	assert.Equal(t, "fleet.example.test", cfg.Domain)
	assert.Equal(t, 50*time.Millisecond, cfg.SlowLorisInterval)

	for name, args := range map[string][]string{
		"unknown kind":     {"--kinds", "valid,bogus"},
		"empty kinds":      {"--kinds", ""},
		"bad port":         {"--ports", "valid=70000"},
		"bad port syntax":  {"--ports", "valid"},
		"unknown port":     {"--ports", "bogus=1"},
		"bad bind":         {"--bind", "fleet.example.test"},
		"ctl not loopback": {"--ctl", "0.0.0.0:9092"},
		"ctl a name":       {"--ctl", "localhost:9092"},
		"bad interval":     {"--slowloris-interval", "0s"},
		"extra argument":   {"extra"},
		"unknown flag":     {"--nope"},
		"same port twice":  {"--ports", "valid=9401"},
	} {
		_, err := parseServe(args, noEnv, &bytes.Buffer{})
		assert.Error(t, err, name)
	}
	_, err = parseServe(nil, func(k string) string { return map[string]string{"FAKEFLEET_SLOWLORIS_INTERVAL": "soon"}[k] }, &bytes.Buffer{})
	assert.Error(t, err, "a bad environment value")
}

func TestCheckLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:9092", "127.1.2.3:1", "[::1]:9092"} {
		assert.NoError(t, checkLoopback(ok), ok)
	}
	for _, bad := range []string{"0.0.0.0:9092", "10.89.0.10:9092", "localhost:9092", "[::ffff:127.0.0.1]:9092", "127.0.0.1", "127.0.0.1:x", "[fe80::1%lo]:1", ":9092"} {
		assert.Error(t, checkLoopback(bad), bad)
	}
	assert.NoError(t, boundLoopback(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}))
	assert.Error(t, boundLoopback(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}))
}

type stack struct {
	ctl  string
	info fakefleet.Info
	logs *logBuffer
}

func startStack(t *testing.T, kinds []fakefleet.Kind) *stack {
	t.Helper()
	ports := map[fakefleet.Kind]int{}
	for _, k := range kinds {
		ports[k] = 0
	}
	st := &stack{logs: &logBuffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	cfg := serveConfig{Bind: "127.0.0.1", Domain: "fleet.example.test", Ctl: "127.0.0.1:0", Kinds: kinds, Ports: ports,
		SlowLorisInterval: time.Second,
		ready: func(info fakefleet.Info, ctl string) {
			st.info, st.ctl = info, ctl
			close(ready)
		}}
	go func() { done <- serve(ctx, cfg, slog.New(slog.NewTextHandler(st.logs, nil))) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("serve ended before it was ready: %v", err)
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("serve was not ready")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(20 * time.Second):
			t.Error("serve did not stop")
		}
	})
	return st
}

func ctl(t *testing.T, st *stack, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"ctl", "--ctl", st.ctl}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func TestServeAndCtl(t *testing.T) {
	st := startStack(t, []fakefleet.Kind{fakefleet.KindValid, fakefleet.KindPlainText})
	require.Len(t, st.info.Servers, 2)
	assert.Contains(t, st.logs.String(), "alice-fakefleet is serving")
	assert.NotContains(t, st.logs.String(), "PRIVATE KEY")

	code, out, _ := ctl(t, st, "ping")
	assert.Equal(t, 0, code)
	assert.JSONEq(t, `{"ok":true}`, out)

	code, out, _ = ctl(t, st, "fleet")
	require.Equal(t, 0, code)
	var info fakefleet.Info
	require.NoError(t, json.Unmarshal([]byte(out), &info))
	assert.Equal(t, st.info, info)
	assert.Equal(t, "valid.fleet.example.test", info.Servers[0].Host)

	code, out, _ = ctl(t, st, "ca")
	require.Equal(t, 0, code)
	blk, _ := pem.Decode([]byte(out))
	require.NotNil(t, blk)

	addr := info.Servers[0].Addr
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "probe.fleet.example.test", InsecureSkipVerify: true}) //nolint:gosec // G402: the test reads the presented chain
	require.NoError(t, err)
	require.NoError(t, c.Close())

	code, out, _ = ctl(t, st, "log", "--settle")
	require.Equal(t, 0, code)
	var log []fakefleet.Access
	require.NoError(t, json.Unmarshal([]byte(out), &log))
	require.Len(t, log, 1)
	assert.Equal(t, "probe.fleet.example.test", log[0].SNI)
	assert.True(t, log[0].Handshake)

	code, out, _ = ctl(t, st, "counters")
	require.Equal(t, 0, code)
	assert.Contains(t, out, `"valid":1`)

	code, _, _ = ctl(t, st, "clear-log")
	assert.Equal(t, 0, code)
	_, out, _ = ctl(t, st, "log")
	assert.Equal(t, "[]", strings.TrimSpace(out))

	code, _, errOut := ctl(t, st, "nope")
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "unknown command")
	code, _, errOut = ctl(t, st, "ping", "extra")
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "takes no argument")
	code, _, errOut = ctl(t, st, "log", "--bogus")
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "takes no argument")
}

func TestCtlRefusesANonLoopbackAddressAndReportsAnAbsentFake(t *testing.T) {
	var out, errb bytes.Buffer
	assert.Equal(t, 2, run(context.Background(), []string{"ctl", "--ctl", "10.89.0.10:9092", "ping"}, &out, &errb))
	assert.Contains(t, errb.String(), "loopback")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	errb.Reset()
	assert.Equal(t, 1, run(context.Background(), []string{"ctl", "--ctl", addr, "ping"}, &out, &errb))
	assert.Contains(t, errb.String(), "does not answer")
}

func TestCtlReportsAnErrorAnswer(t *testing.T) {
	st := startStack(t, []fakefleet.Kind{fakefleet.KindValid})
	// A path the control API does not serve stands for any refusal.
	var out, errb bytes.Buffer
	code := ctlRequest(context.Background(), st.ctl, "GET", "/nope", "nope", &out, &errb)
	assert.Equal(t, 1, code)
	assert.Contains(t, errb.String(), "404")
}

func TestRunUsage(t *testing.T) {
	var out, errb bytes.Buffer
	assert.Equal(t, 2, run(context.Background(), nil, &out, &errb))
	assert.Contains(t, errb.String(), "Usage: alice-fakefleet")
	errb.Reset()
	assert.Equal(t, 2, run(context.Background(), []string{"bogus"}, &out, &errb))
	errb.Reset()
	assert.Equal(t, 2, run(context.Background(), []string{"serve", "--kinds", "bogus"}, &out, &errb))
	assert.Contains(t, errb.String(), "bogus")
	errb.Reset()
	assert.Equal(t, 2, run(context.Background(), []string{"ctl"}, &out, &errb))
	errb.Reset()
	assert.Equal(t, 2, run(context.Background(), []string{"ctl", "--bogus"}, &out, &errb))
}

func TestServeFailsWhenAPortIsTaken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := serveConfig{Bind: "127.0.0.1", Domain: "fleet.example.test", Ctl: "127.0.0.1:0", Kinds: []fakefleet.Kind{fakefleet.KindValid},
		Ports: map[fakefleet.Kind]int{fakefleet.KindValid: port}, SlowLorisInterval: time.Second}
	assert.Error(t, serve(context.Background(), cfg, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	cfg.Ports[fakefleet.KindValid] = 0
	cfg.Ctl = ln.Addr().String()
	assert.Error(t, serve(context.Background(), cfg, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))), "the control address is taken")

	var errb bytes.Buffer
	assert.Equal(t, 1, run(context.Background(), []string{"serve", "--bind", "127.0.0.1", "--kinds", "valid", "--ports", "valid=" + strconv.Itoa(port)},
		&bytes.Buffer{}, &errb))
	assert.Contains(t, errb.String(), "alice-fakefleet stopped")
}

// An answer over the size limit fails instead of being cut silently.
func TestCtlRefusesAnOversizedAnswer(t *testing.T) {
	defer func(old int64) { maxCtlBody = old }(maxCtlBody)
	maxCtlBody = 10
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 11)))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	var out, errb bytes.Buffer
	assert.Equal(t, 1, ctlRequest(context.Background(), addr, http.MethodGet, "/log", "log", &out, &errb))
	assert.Empty(t, out.String())
	assert.Contains(t, errb.String(), "larger than")
	out.Reset()
	maxCtlBody = 11
	assert.Equal(t, 0, ctlRequest(context.Background(), addr, http.MethodGet, "/log", "log", &out, &errb))
	assert.Equal(t, strings.Repeat("x", 11), out.String(), "exactly the limit passes")
}
