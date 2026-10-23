package winhelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

var testNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// run calls Run and returns the exit code and the raw answer, after checking it is one JSON line.
func run(t *testing.T, h Host, args ...string) (int, []byte) {
	t.Helper()
	var out bytes.Buffer
	code := Run(context.Background(), h, args, strings.NewReader(""), &out)
	oneLine(t, out.Bytes())
	return code, out.Bytes()
}

func oneLine(t *testing.T, b []byte) {
	t.Helper()
	if len(b) == 0 || b[len(b)-1] != '\n' || bytes.Count(b, []byte("\n")) != 1 {
		t.Fatalf("answer is not exactly one line: %q", b)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("answer is not JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("trailing data after the answer: %q", b)
	}
}

func wantError(t *testing.T, code int, out []byte, wantExit int, wantCode string) {
	t.Helper()
	var e winproto.ErrorResponse
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatal(err)
	}
	if code != wantExit || e.OK || e.Code != wantCode {
		t.Fatalf("got exit %d %+v, want exit %d %s", code, e, wantExit, wantCode)
	}
}

func TestRunVersion(t *testing.T) {
	h := &fakeHost{}
	code, out := run(t, h, "version")
	if code != 0 || string(out) != `{"ok":true,"helper":"0.3.0","protocol":1}`+"\n" {
		t.Fatalf("got %d %q", code, out)
	}
	code, out = run(t, h, "version", "x")
	wantError(t, code, out, 2, "USAGE")
}

func TestRunRefusesUnknownAndEmpty(t *testing.T) {
	h := &fakeHost{}
	code, out := run(t, h)
	wantError(t, code, out, 2, "USAGE")
	for _, sub := range []string{"rdp-deploy", "ssh", "nope"} {
		code, out = run(t, h, sub)
		wantError(t, code, out, 2, "UNKNOWN_SUBCOMMAND")
	}
	if h.calls.Load() != 0 {
		t.Fatal("the host was called")
	}
}

func TestRunForcedSplitsTheOriginalCommand(t *testing.T) {
	h := &fakeHost{}
	var out bytes.Buffer
	if code := RunForced(context.Background(), h, "version", nil, &out); code != 0 || !strings.Contains(out.String(), `"protocol":1`) {
		t.Fatalf("got %d %q", code, out.String())
	}
	for _, line := range []string{"version && whoami", "", "version\x00", "version  x", "version\n"} {
		out.Reset()
		code := RunForced(context.Background(), h, line, nil, &out)
		oneLine(t, out.Bytes())
		wantError(t, code, out.Bytes(), 2, "INVALID_ARGUMENT")
	}
	if h.calls.Load() != 0 {
		t.Fatal("the host was called")
	}
}

func TestElevationGate(t *testing.T) {
	h := &fakeHost{elevated: false}
	code, out := run(t, h, "iis-dump")
	wantError(t, code, out, 2, "NOT_ELEVATED")
	if h.calls.Load() != 1 { // only Elevated
		t.Fatalf("host reads after a refused gate: %d calls", h.calls.Load())
	}
	for _, args := range [][]string{{"version"}, {"win-facts"}} {
		if code, out := run(t, h, args...); code != 0 {
			t.Fatalf("%v: %d %s", args, code, out)
		}
	}
	h.elevatedErr = errors.New("token")
	code, out = run(t, h, "iis-dump")
	wantError(t, code, out, 4, "IO_ERROR")
	// An elevated token reaches the dump handler.
	h = &fakeHost{elevated: true, appcmd: []byte(`<appcmd/>`)}
	code, out = run(t, h, "iis-dump")
	if code != 0 {
		t.Fatalf("%d %s", code, out)
	}
	var r winproto.IISDumpResponse
	if err := json.Unmarshal(out, &r); err != nil || !r.OK {
		t.Fatal(err, string(out))
	}
	// iis-dump takes no arguments.
	code, out = run(t, h, "iis-dump", "extra")
	wantError(t, code, out, 2, "USAGE")
}

func TestWinFacts(t *testing.T) {
	h := &fakeHost{elevated: true,
		os:     OSFacts{Build: "20348", Product: "Windows Server 2022 Datacenter", InstallationType: "Server Core", OpenSSHVersion: "OpenSSH_for_Windows_9.5"},
		iis:    winproto.IISFacts{Installed: true, Version: "10.0", SharedConfig: true, CCSEnabled: true, CCSPath: `\\fs\ccs`, AutoCertRebind: true},
		stores: []string{"My", "WebHosting", "\x1b[31m", ""}}
	code, out := run(t, h, "win-facts")
	var r winproto.WinFactsResponse
	if err := json.Unmarshal(out, &r); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	if !r.OK || !r.Elevated || r.OSBuild != "20348" || r.OSProduct != "Windows Server 2022 Datacenter" || r.InstallationType != "Server Core" ||
		r.OpenSSHVersion != "OpenSSH_for_Windows_9.5" || !r.IIS.Installed || r.IIS.Version != "10.0" || !r.IIS.SharedConfig ||
		!r.IIS.CCSEnabled || r.IIS.CCSPath != `\\fs\ccs` || !r.IIS.AutoCertRebind {
		t.Fatalf("%+v", r)
	}
	if strings.Join(r.Stores, ",") != "My,WebHosting,[31m" {
		t.Fatalf("stores %q", r.Stores)
	}
	h.elevated = false
	_, out = run(t, h, "win-facts")
	_ = json.Unmarshal(out, &r)
	if r.Elevated {
		t.Fatal("elevated must be false")
	}
	if code, out := run(t, h, "win-facts", "x"); code != 2 {
		t.Fatalf("%d %s", code, out)
	}
}

func TestWinFactsCleansText(t *testing.T) {
	h := &fakeHost{os: OSFacts{Product: strings.Repeat("é", 300) + "x", Build: "1\x1b[2J\u202e2\xff", InstallationType: "\u2066Server\u2069"}}
	_, out := run(t, h, "win-facts")
	var r winproto.WinFactsResponse
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(r.OSProduct)); n != winproto.MaxText {
		t.Fatalf("product has %d runes", n)
	}
	if r.OSBuild != "1[2J2" || r.InstallationType != "Server" {
		t.Fatalf("build %q type %q", r.OSBuild, r.InstallationType)
	}
}

func TestWinFactsStoresAreBounded(t *testing.T) {
	var many []string
	for i := 0; i < 100; i++ {
		many = append(many, "S"+strconv.Itoa(i))
	}
	_, out := run(t, &fakeHost{stores: many}, "win-facts")
	var r winproto.WinFactsResponse
	_ = json.Unmarshal(out, &r)
	if len(r.Stores) != maxStores {
		t.Fatalf("%d stores", len(r.Stores))
	}
}

func TestWinFactsWithoutIIS(t *testing.T) {
	h := &fakeHost{iisErr: ErrIISNotInstalled, iis: winproto.IISFacts{Installed: true, Version: "stale"}}
	code, out := run(t, h, "win-facts")
	var r winproto.WinFactsResponse
	if err := json.Unmarshal(out, &r); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	if r.IIS != (winproto.IISFacts{}) || !r.OK {
		t.Fatalf("%+v", r.IIS)
	}
	if !strings.Contains(string(out), `"stores":[]`) {
		t.Fatalf("stores must be an empty list: %s", out)
	}
}

func TestWinFactsHostErrors(t *testing.T) {
	boom := errors.New("secret OS text C:\\x")
	for name, h := range map[string]*fakeHost{
		"token":  {elevatedErr: boom},
		"os":     {osErr: boom},
		"iis":    {iisErr: boom},
		"stores": {storesErr: boom},
	} {
		code, out := run(t, h, "win-facts")
		wantError(t, code, out, 4, "IO_ERROR")
		if strings.Contains(string(out), "secret") {
			t.Fatalf("%s: OS text leaked: %s", name, out)
		}
	}
}

// tlsServer serves two certificates by SNI name on 127.0.0.1 and returns the port.
func tlsServer(t *testing.T) (port string, leaves map[string]pki.Leaf) {
	t.Helper()
	ca := pki.NewCA("Winhelper Test", pki.ECDSA256, testNow)
	leaves = map[string]pki.Leaf{}
	pairs := map[string]*tls.Certificate{}
	for _, name := range []string{"www.example.test", "api.example.test"} {
		l := ca.Issue(pki.Opts{CommonName: name, SANs: []string{name}}, testNow)
		leaves[name] = l
		pairs[name] = &tls.Certificate{Certificate: [][]byte{l.Cert.Raw, ca.Intermediate.Raw}, PrivateKey: l.Key}
	}
	cfg := &tls.Config{
		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c, ok := pairs[ch.ServerName]; ok {
				return c, nil
			}
			return pairs["www.example.test"], nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
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
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, leaves
}

func TestTLSProbe(t *testing.T) {
	port, leaves := tlsServer(t)
	h := &fakeHost{}
	for sni, l := range leaves {
		code, out := run(t, h, "tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", sni, "--key-type", "any")
		var r winproto.TLSProbeResponse
		if err := json.Unmarshal(out, &r); err != nil || code != 0 {
			t.Fatal(code, err, string(out))
		}
		sum := sha256.Sum256(l.Cert.Raw)
		if !r.OK || r.LeafSHA256 != hex.EncodeToString(sum[:]) || r.ChainLength != 2 || r.NotAfter != l.Cert.NotAfter.UTC().Format(time.RFC3339) {
			t.Fatalf("%s: %+v", sni, r)
		}
		ders, ok := helperproto.DecodeProbeChain(r.Chain)
		if !ok || len(ders) != 2 || !bytes.Equal(ders[0], l.Cert.Raw) {
			t.Fatalf("%s: chain %v", sni, ok)
		}
	}
	// No SNI: the default certificate.
	code, _ := run(t, h, "tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", "_", "--key-type", "ecdsa")
	if code != 0 {
		t.Fatal(code)
	}
}

func TestTLSProbeRefusals(t *testing.T) {
	h := &fakeHost{}
	good := []string{"tls-probe", "--addr", "127.0.0.1", "--port", "443", "--sni", "_", "--key-type", "any"}
	code, out := run(t, h, "tls-probe", "--addr", "127.0.0.1")
	wantError(t, code, out, 2, "USAGE")
	swapped := append([]string{}, good...)
	swapped[1], swapped[3] = "--port", "--addr"
	code, out = run(t, h, swapped...)
	wantError(t, code, out, 2, "USAGE")
	for _, bad := range []struct {
		idx int
		v   string
	}{{2, "10.0.0.300"}, {4, "99999"}, {6, "UPPER.example"}, {8, "dsa"}} {
		args := append([]string{}, good...)
		args[bad.idx] = bad.v
		code, out = run(t, h, args...)
		wantError(t, code, out, 2, "INVALID_ARGUMENT")
	}
	if h.calls.Load() != 0 {
		t.Fatal("the host dialled")
	}
}

func TestTLSProbeFailures(t *testing.T) {
	// A refused dial.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	code, out := run(t, &fakeHost{}, "tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", "_", "--key-type", "any")
	wantError(t, code, out, 4, "PROBE_FAILED")
	// An injected dial error.
	code, out = run(t, &fakeHost{dialErr: errors.New("x")}, "tls-probe", "--addr", "127.0.0.1", "--port", "1", "--sni", "_", "--key-type", "any")
	wantError(t, code, out, 4, "PROBE_FAILED")
	// A plain TCP server that is not TLS: the handshake fails.
	old := probeTimeout
	probeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { probeTimeout = old })
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			_ = c.Close()
		}
	}()
	_, port, _ = net.SplitHostPort(plain.Addr().String())
	code, out = run(t, &fakeHost{}, "tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", "_", "--key-type", "any")
	wantError(t, code, out, 4, "PROBE_FAILED")
}

func TestBudgetEndsTheCall(t *testing.T) {
	old := commandBudget
	commandBudget = 50 * time.Millisecond
	t.Cleanup(func() { commandBudget = old })
	h := &fakeHost{block: true}
	start := time.Now()
	code, out := run(t, h, "win-facts")
	wantError(t, code, out, 4, "IO_ERROR")
	if time.Since(start) > time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}

func TestBudgetEndsTheDump(t *testing.T) {
	old := commandBudget
	commandBudget = 50 * time.Millisecond
	t.Cleanup(func() { commandBudget = old })
	h := &fakeHost{elevated: true, bindingBlock: true}
	start := time.Now()
	code, out := run(t, h, "iis-dump")
	wantError(t, code, out, 4, "IO_ERROR")
	if time.Since(start) > time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}

func TestReplyEncodeFailure(t *testing.T) {
	var out bytes.Buffer
	if code := reply(&out, make(chan int), nil); code != 0 {
		t.Fatal(code)
	}
	oneLine(t, out.Bytes())
	if !strings.Contains(out.String(), "IO_ERROR") {
		t.Fatal(out.String())
	}
	out.Reset()
	if code := reply(&out, nil, errors.New("plain")); code != 4 || !strings.Contains(out.String(), "IO_ERROR") {
		t.Fatal(code, out.String())
	}
}
