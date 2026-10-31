// Command alice-fakewindows is the emulated Windows server of the e2e stack (compose service fakewindows on the
// internal backend network) for the Windows journey (web/e2e/windows.spec.ts, R60). It is a test tool: it is built
// into the e2e fake Windows image only and never ships (internal/archtest lists it in testOnlyDirs). It wraps
// internal/providers/windows/wintest: the fixed demo host of wintest.Demo (Windows Server 2022 Datacenter with IIS
// 10.0, three IIS sites, four http.sys entries, a CCS folder, an RDP listener), whose helper answers run the helper's
// own code (winhelper), behind an SSH server that behaves like Windows OpenSSH (every session after the first on one
// connection sees the first session's command, design 2026-10-21 §8).
//
//	alice-fakewindows serve [--listen ADDR] [--tls-bind IP] [--ctl ADDR]
//	alice-fakewindows ctl [--ctl ADDR] ping | hostkey | endpoints | prepare | stale-tls-on | stale-tls-off | ccs-password | rdp-self-signed |
//	  winrm-account | winrm-fingerprint
//
// serve generates a fresh Ed25519 host key and the demo host's test CA and certificates when it starts (nothing is
// stored in the repository or the image), listens for SSH on --listen and serves the demo's TLS bindings on --tls-bind
// at their own ports (443, 8443, 5986, 9444) and its RDP listener at 3389 (the RDP negotiation, then TLS; W6 Ruling 25);
// "IP:0" gives random ports, for tests. No client key is authorized until
// "ctl prepare" reads the Windows setup script Alice shows on its standard input and authorizes the key of its one
// $AuthorizedKey = '...' line (the counterpart of the SSH target's alice-e2e-prepare); a later prepare replaces it.
// The helper's write subcommands (iis-deploy, iis-restore, iis-status, iis-fence; R61) run on the model too, its state
// files (journal, binding records, imports) in memory: a restart is a fresh demo host. "ctl stale-tls-on" makes every
// listener keep serving what it served before the next bind (a website that did not take the change, W2 Ruling 23)
// until "ctl stale-tls-off", so a deployment's verification fails and is rolled back; the demo's CCS files (W5) go
// stale with them, and so does its RDP listener (W6). The demo's Centralized Certificate Store (C:\CCS, two files) is encrypted with a password made at
// start, which "ctl ccs-password" prints on its standard output (never logged). "ctl rdp-self-signed" deletes the RDP
// listener's value, as someone outside Alice would, so it serves its self-signed certificate again (an e2e journey's
// start, W6 Ruling 25).
// The 5986 record is the demo's WinRM listener (R71 Rulings 20 and 23): WS-Man's WinRS subset over its TLS, behind an
// NTLMv2 check of one account, running the helper's forced entry like the SSH server. No account signs in until "ctl
// winrm-account" reads "<user> <password>" on its standard input (never an argument, never logged); "ctl
// winrm-fingerprint" prints the listener's SPKI fingerprint as Alice shows it. 9444 is the IIS binding the WinRM
// journey deploys to.
// The control API has no authentication beyond its address: it listens on loopback only (serve refuses any other
// address), ctl talks to loopback only, and it runs inside the container ("docker compose exec -T fakewindows
// /alice-fakewindows ctl prepare < script").
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
)

const (
	defaultListen  = ":22"
	defaultTLSBind = "0.0.0.0"
	defaultCtl     = "127.0.0.1:9093"
	// maxScript is the largest setup script ctl prepare takes (Alice's is about 20 KiB).
	maxScript = 1 << 20
	// maxAccountLine is the longest "<user> <password>" line ctl winrm-account takes.
	maxAccountLine = 512
)

// maxCtlBody is the largest control answer ctl prints (a variable for tests).
var maxCtlBody int64 = 1 << 20

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `Usage: alice-fakewindows <command>

Commands:
  serve [--listen ADDR] [--tls-bind IP] [--ctl ADDR]
        Run the emulated Windows server: SSH on --listen (default :22), the demo's TLS bindings and RDP listener
        on --tls-bind (default 0.0.0.0, at their own ports; IP:0 for random ports), the control API on --ctl
        (default 127.0.0.1:9093, loopback only).
  ctl [--ctl ADDR] <command>
        Drive a running server (answer on stdout, errors on stderr, exit 1 on failure):
        ping | hostkey (the SHA256 fingerprint of the host key) | endpoints (the TLS and RDP listeners) |
        prepare (stdin: Alice's Windows setup script; authorizes the key of its $AuthorizedKey line) |
        stale-tls-on (the listeners keep serving what they served before the next bind, CCS file or RDP write) |
        stale-tls-off | ccs-password (the demo's CCS private-key password) |
        rdp-self-signed (the RDP listener's value deleted: it serves its self-signed certificate again) |
        winrm-account (stdin: one line "<user> <password>"; the WinRM listener's account) |
        winrm-fingerprint (the SHA256 fingerprint of the WinRM listener's SubjectPublicKeyInfo)
`

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		cfg, err := parseServe(args[1:], stderr)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "alice-fakewindows serve: %v\n", err)
			return 2
		}
		log := slog.New(slog.NewTextHandler(stderr, nil))
		if err := serve(ctx, cfg, log); err != nil {
			log.Error("alice-fakewindows stopped", "error", err.Error())
			return 1
		}
		return 0
	case "ctl":
		return runCtl(ctx, args[1:], stdin, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "alice-fakewindows: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// ---- serve ----

type serveConfig struct {
	Listen  string
	TLSBind string
	Ctl     string
	// ready, when set, is called once everything listens (tests).
	ready func(sshAddr, ctl string, hostKey ssh.PublicKey)
}

func parseServe(args []string, stderr io.Writer) (serveConfig, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := serveConfig{}
	fs.StringVar(&cfg.Listen, "listen", defaultListen, "address of the SSH server")
	fs.StringVar(&cfg.TLSBind, "tls-bind", defaultTLSBind, "IP address of the TLS bindings (IP:0 for random ports)")
	fs.StringVar(&cfg.Ctl, "ctl", defaultCtl, "address of the control API (loopback only)")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}
	if fs.NArg() != 0 {
		return serveConfig{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		return serveConfig{}, fmt.Errorf("--listen %q is not an address with a port", cfg.Listen)
	}
	ip := cfg.TLSBind
	if h, p, err := net.SplitHostPort(cfg.TLSBind); err == nil {
		if p != "0" {
			return serveConfig{}, fmt.Errorf("--tls-bind %q: the bindings listen on their own ports, or on random ones with :0", cfg.TLSBind)
		}
		ip = h
	}
	if a, err := netip.ParseAddr(ip); err != nil || a.Zone() != "" {
		return serveConfig{}, fmt.Errorf("--tls-bind %q is not an IP address", cfg.TLSBind)
	}
	if err := checkLoopback(cfg.Ctl); err != nil {
		return serveConfig{}, fmt.Errorf("--ctl: %w", err)
	}
	return cfg, nil
}

// serve runs the emulated server until ctx ends. It logs addresses and the host key's fingerprint, never a key.
func serve(ctx context.Context, cfg serveConfig, log *slog.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops the TLS listeners
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return err
	}
	m, err := wintest.Demo(clock.Real{}.Now())
	if err != nil {
		return err
	}
	if err := m.Serve(ctx, cfg.TLSBind); err != nil {
		return fmt.Errorf("serve the TLS bindings on %s: %w", cfg.TLSBind, err)
	}
	sshSrv, err := linuxsshtest.Listen(cfg.Listen, signer, m.Handler())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	defer sshSrv.Close()
	sshSrv.StickyFirstCommand() // Windows OpenSSH (W0); no client can sign in before ctl prepare
	ctlLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Ctl)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Ctl, err)
	}
	if err := boundLoopback(ctlLn.Addr()); err != nil {
		_ = ctlLn.Close()
		return err
	}
	c := &control{ssh: sshSrv, model: m, fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}
	srv := &http.Server{Handler: c.handler(), ReadHeaderTimeout: 10 * time.Second}
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(ctlLn) }()
	host, port := sshSrv.Addr()
	sshAddr := net.JoinHostPort(host, strconv.Itoa(port))
	attrs := []any{"ssh", sshAddr, "ctl", ctlLn.Addr().String(), "host_key", c.fingerprint}
	for p, addr := range c.endpoints(ctx) {
		attrs = append(attrs, "tls_"+p, addr)
	}
	log.Info("alice-fakewindows is serving", attrs...)
	if cfg.ready != nil {
		cfg.ready(sshAddr, ctlLn.Addr().String(), signer.PublicKey())
	}
	select {
	case err = <-errs:
	case <-ctx.Done():
		err = nil
	}
	shutdown, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	_ = srv.Shutdown(shutdown)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// control is the loopback control API of a running server.
type control struct {
	ssh         *linuxsshtest.Server
	model       *wintest.Model
	fingerprint string
}

func (c *control) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /hostkey", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, c.fingerprint+"\n")
	})
	mux.HandleFunc("GET /endpoints", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, c.endpoints(r.Context()))
	})
	mux.HandleFunc("POST /prepare", func(w http.ResponseWriter, r *http.Request) {
		script, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxScript))
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "the script is larger than " + strconv.Itoa(maxScript) + " bytes"})
			return
		}
		key, err := authorizedKeyOf(script)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		c.ssh.Authorize(key)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	// A website that does not take a change (Ruling 23): while on, every listener keeps serving what it served before
	// the next bind, so a deployment's verification fails and the provider's iis-restore rolls it back.
	// The CCS files go stale with them (F15 route (b) modelled), so a CCS deployment is rolled back to its backup, and
	// so does the RDP listener (W6 Ruling 25): an RDP deployment is rolled back to the previous certificate.
	mux.HandleFunc("POST /stale-tls-on", func(w http.ResponseWriter, _ *http.Request) {
		c.model.StaleTLS(true)
		c.model.ServeStaleCCS(true)
		c.model.ServeStaleRDP(true)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /stale-tls-off", func(w http.ResponseWriter, _ *http.Request) {
		c.model.StaleTLS(false)
		c.model.ServeStaleCCS(false)
		c.model.ServeStaleRDP(false)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	// The RDP listener back on its self-signed certificate (W6 Ruling 25): its value deleted, as someone outside Alice
	// would, so every run of the e2e journey starts where a fresh demo host does.
	mux.HandleFunc("POST /rdp-self-signed", func(w http.ResponseWriter, _ *http.Request) {
		c.model.SetRDPThumbprint("")
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	// The demo's CCS password (W5 Ruling 25), made at start: the answer only, never logged.
	mux.HandleFunc("GET /ccs-password", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, c.model.CCSPassword()+"\n")
	})
	// The WinRM listener's one account (R71 Ruling 23), from one "<user> <password>" line; the password is never logged
	// or echoed.
	mux.HandleFunc("POST /winrm-account", func(w http.ResponseWriter, r *http.Request) {
		line, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAccountLine))
		user, password, ok := accountOf(line)
		if err != nil || !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": `stdin must be one line "<user> <password>" of printable ASCII`})
			return
		}
		c.model.SetWinRMAccount(user, password)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /winrm-fingerprint", func(w http.ResponseWriter, _ *http.Request) {
		spki, ok := c.model.WinRMSPKI()
		if !ok {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "the WinRM listener serves no certificate"})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, providers.TLSIdentity(spki).Fingerprint+"\n")
	})
	return mux
}

// accountOf reads one "<user> <password>" line (one trailing line end allowed): two fields of printable ASCII without
// a space.
func accountOf(b []byte) (user, password string, ok bool) {
	line := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	user, password, _ = strings.Cut(line, " ")
	for _, f := range []string{user, password} {
		if f == "" || strings.IndexFunc(f, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
			return "", "", false
		}
	}
	return user, password, true
}

// endpoints maps each TLS binding port of the demo host, and the RDP listener's port, to the address its listener has.
func (c *control) endpoints(ctx context.Context) map[string]string {
	bindings, _ := c.model.Host().SSLBindings(ctx)
	ports := make([]int, 0, len(bindings)+1)
	for _, b := range bindings {
		ports = append(ports, b.Port)
	}
	if l, _ := c.model.Host().RDPListener(ctx); l.Present {
		ports = append(ports, l.Port)
	}
	out := map[string]string{}
	for _, p := range ports {
		if ep := c.model.Endpoint(p); ep != "" {
			out[strconv.Itoa(p)] = ep
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// keyLinePrefix starts the line of the Windows setup script that holds Alice's administrators_authorized_keys line
// (internal/providers/windows/setup.go).
const keyLinePrefix = "$AuthorizedKey ="

// forcedCommandOption is the command= option the key line must carry: the installed helper's forced-command entry.
const forcedCommandOption = `command="\"` + winproto.HelperPath + `\" ssh"`

// authorizedKeyOf finds the one $AuthorizedKey = '<line>' assignment of a setup script and parses its line as
// administrators_authorized_keys does (options, then the key). Any other count of such lines is refused.
func authorizedKeyOf(script []byte) (ssh.PublicKey, error) {
	var found []string
	for _, line := range strings.Split(string(script), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, keyLinePrefix) {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("the script has %d lines %s '...', not exactly one", len(found), keyLinePrefix)
	}
	value := strings.TrimSpace(strings.TrimPrefix(found[0], keyLinePrefix))
	if len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' {
		return nil, fmt.Errorf("the line %s is not a single-quoted string", keyLinePrefix)
	}
	key, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(value[1 : len(value)-1]))
	if err != nil {
		return nil, fmt.Errorf("the line %s holds no public key: %w", keyLinePrefix, err)
	}
	// The line must confine the key to the helper itself (final review C1): administrators_authorized_keys is read
	// for every administrator account, so a line without the forced command would open a shell on all of them.
	if !slices.Contains(opts, forcedCommandOption) {
		return nil, fmt.Errorf("the line %s does not force %s", keyLinePrefix, forcedCommandOption)
	}
	return key, nil
}

// checkLoopback accepts only a literal loopback IP (127.0.0.0/8 or ::1, no zone, no IPv4-mapped form) with a port.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	bad := fmt.Errorf("%q must be a loopback IP address with a port (127.0.0.1:9093)", addr)
	if err != nil || host == "" {
		return bad
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return bad
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsLoopback() {
		return bad
	}
	return nil
}

// boundLoopback checks the address a listener really bound.
func boundLoopback(a net.Addr) error {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil || ap.Addr().Zone() != "" || ap.Addr().Is4In6() || !ap.Addr().IsLoopback() {
		return fmt.Errorf("the control listener is bound to %s, not a loopback address", a)
	}
	return nil
}

// ---- ctl ----

var ctlCommands = map[string][2]string{
	"ping":      {http.MethodGet, "/ping"},
	"hostkey":   {http.MethodGet, "/hostkey"},
	"endpoints": {http.MethodGet, "/endpoints"},
	"prepare":   {http.MethodPost, "/prepare"},
	// stale-tls-on / stale-tls-off: the listeners keep serving what they served before the next bind (Ruling 23).
	"stale-tls-on":  {http.MethodPost, "/stale-tls-on"},
	"stale-tls-off": {http.MethodPost, "/stale-tls-off"},
	// ccs-password: the demo's CCS private-key password, on stdout only.
	"ccs-password": {http.MethodGet, "/ccs-password"},
	// rdp-self-signed: the RDP listener's value deleted, so it serves its self-signed certificate again (W6).
	"rdp-self-signed": {http.MethodPost, "/rdp-self-signed"},
	// winrm-account: stdin's "<user> <password>" becomes the WinRM listener's account (R71).
	"winrm-account": {http.MethodPost, "/winrm-account"},
	// winrm-fingerprint: the WinRM listener's SPKI fingerprint, as Alice shows it.
	"winrm-fingerprint": {http.MethodGet, "/winrm-fingerprint"},
}

func runCtl(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("ctl", defaultCtl, "address of the control API (loopback only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	name := fs.Arg(0)
	cmd, ok := ctlCommands[name]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl: unknown command %q (%s)\n", name, strings.Join(slices.Sorted(maps.Keys(ctlCommands)), ", "))
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl %s: takes no argument but %q\n", name, strings.Join(fs.Args()[1:], " "))
		return 2
	}
	if err := checkLoopback(*addr); err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl: the control address %v\n", err)
		return 2
	}
	var body []byte
	if name == "prepare" {
		b, err := io.ReadAll(io.LimitReader(stdin, maxScript+1))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl prepare: read the script: %v\n", err)
			return 1
		}
		if len(b) > maxScript {
			_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl prepare: the script is larger than %d bytes\n", maxScript)
			return 1
		}
		body = b
	}
	if name == "winrm-account" {
		b, err := io.ReadAll(io.LimitReader(stdin, maxAccountLine+1))
		if err != nil || len(b) > maxAccountLine {
			_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl winrm-account: stdin must be one line of at most %d bytes\n", maxAccountLine)
			return 1
		}
		body = b
	}
	return ctlRequest(ctx, *addr, cmd[0], cmd[1], name, body, stdout, stderr)
}

// ctlRequest sends one request to the loopback control API and copies the answer to stdout.
func ctlRequest(ctx context.Context, addr, method, path, name string, body []byte, stdout, stderr io.Writer) int {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, "http://"+addr+path, bytes.NewReader(body))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl: %v\n", err)
		return 1
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req) //nolint:gosec // G704: the address was checked to be loopback
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl: the server does not answer at %s: %v\n", addr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxCtlBody+1))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl: %v\n", err)
		return 1
	}
	if int64(len(answer)) > maxCtlBody {
		_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl %s: the answer is larger than %d bytes\n", name, maxCtlBody)
		return 1
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(answer, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		_, _ = fmt.Fprintf(stderr, "alice-fakewindows ctl %s: %s\n", name, e.Error)
		return 1
	}
	_, _ = stdout.Write(answer)
	return 0
}
