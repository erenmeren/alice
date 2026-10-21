// Command alice-fakeacme is the fake ACME certificate authority that runs in the e2e stack (compose
// service fakeacme, network alias acme.test.alice) for the ACME journeys. It is a test tool: it is
// built into the e2e fake ACME image only and never ships (internal/archtest lists it in
// testOnlyDirs). It wraps internal/testutil/fakeacme, the fake the Go suites use in process; that
// package's comment documents the protocol it speaks and the DNS hook contract (POST /hook with a
// bearer token and an HMAC signature) Alice's DNS-01 webhook solver calls.
//
//	alice-fakeacme serve [--listen :443] [--admin 127.0.0.1:9091] [--ca-out FILE] [--base-url URL]
//	                     [--require-eab] [--alternates N] [--dns-providers]
//	alice-fakeacme ctl [--admin ADDR] COMMAND [ARGS]
//
// serve generates a TLS CA, a TLS certificate for the base URL's host, an issuing CA chain, the
// external account binding credentials and the hook secret when it starts (nothing of it is stored in
// the repository or in the image), writes the TLS CA to --ca-out for Alice to trust, serves the ACME
// directory and the hook on --listen over TLS and an admin API on --admin. The admin API has no
// authentication beyond its address: it listens on loopback only (serve refuses any other address),
// ctl talks to loopback only, and it runs inside the container ("docker compose exec fakeacme
// /alice-fakeacme ctl ..."). The EAB HMAC key and the hook secret are printed by "ctl credentials"
// and never written to the log. --dns-providers also serves the fake Cloudflare and Route 53 APIs (dns.go) on the
// same listener; "ctl dns-providers" prints their credentials and records.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"alice/internal/testutil/fakeacme"
)

const (
	defaultListen = ":443"
	defaultAdmin  = "127.0.0.1:9091"
	maxAdminBody  = 1 << 20
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `Usage: alice-fakeacme <command>

Commands:
  serve [--listen ADDR] [--admin ADDR] [--ca-out FILE] [--base-url URL] [--require-eab] [--alternates N] [--dns-providers]
        Run the fake: the ACME directory and the DNS hook over TLS on --listen (default :443), the admin
        API on --admin (default 127.0.0.1:9091, loopback only), the TLS CA written to --ca-out. With
        --dns-providers also the fake Cloudflare and Route 53 APIs for api.cloudflare.com,
        route53.amazonaws.com and sts.amazonaws.com (their CAs are added to --ca-out).
  ctl [--admin ADDR] <command> [args]
        Drive a running fake (JSON on stdout, errors on stderr, exit 1 on failure):
        ping | credentials | ca | reset | counters | requests | clear-requests | dns-providers
        fault set ENDPOINT KIND [--times N] [--retry-after SECONDS] [--delay DURATION] | fault clear
          kinds: badNonce rateLimited serverInternal slow giant; endpoint * = all
        dns set NAME VALUE | dns clear [NAME [VALUE]] | dns list
        http-target NAME HOST:PORT|off
        eab on|off | lifetime DURATION | stuck on|off | reject IDENTIFIER|clear
        validation-fail http-01|dns-01 on|off | challenges TYPE[,TYPE] | processing-polls N
        ari default | ari window START END | ari relative BEFORE [LENGTH]
        ari certificate SERIAL START END   (one certificate's window, SERIAL in hex) | replacements
        advertise FIELD [URL|off]   (replace a URL the CA hands out; no URL restores it)
        clock RFC3339|real
`

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return runServe(ctx, args[1:], stderr)
	case "ctl":
		return runCtl(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "alice-fakeacme: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// ---- serve ----

type serveConfig struct {
	Listen     string // the ACME host, TLS
	Admin      string // the admin API, plain HTTP, loopback only
	CAOut      string // where the TLS CA is written ("" = nowhere)
	BaseURL    string
	RequireEAB bool
	Alternates int
	// DNSProviders also serves the fake DNS providers (dns.go).
	DNSProviders bool
	// ready, when set, is called with the bound addresses once everything listens (tests).
	ready func(listen, admin string)
}

func runServe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := serveConfig{}
	fs.StringVar(&cfg.Listen, "listen", defaultListen, "address of the ACME host (TLS)")
	fs.StringVar(&cfg.Admin, "admin", defaultAdmin, "address of the admin API (loopback only)")
	fs.StringVar(&cfg.CAOut, "ca-out", "", "file the TLS CA certificate is written to")
	fs.StringVar(&cfg.BaseURL, "base-url", fakeacme.DefaultBaseURL, "public base URL of the CA")
	fs.BoolVar(&cfg.RequireEAB, "require-eab", false, "require an external account binding")
	fs.IntVar(&cfg.Alternates, "alternates", 0, "alternate certificate chains to offer")
	fs.BoolVar(&cfg.DNSProviders, "dns-providers", false, "also serve the fake Cloudflare and Route 53 APIs")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "alice-fakeacme serve: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	if err := serve(ctx, cfg, log); err != nil {
		log.Error("alice-fakeacme stopped", "error", err.Error())
		if strings.Contains(err.Error(), "loopback") {
			return 2
		}
		return 1
	}
	return 0
}

// serve runs the fake until ctx ends. It logs addresses and never a secret or a key.
func serve(ctx context.Context, cfg serveConfig, log *slog.Logger) error {
	if err := checkLoopback(cfg.Admin); err != nil {
		return fmt.Errorf("admin address: %w", err)
	}
	if cfg.Alternates < 0 || cfg.Alternates > 5 {
		return errors.New("alternates must be from 0 to 5")
	}
	if u, err := url.Parse(cfg.BaseURL); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil {
		return errors.New("base-url must be an https URL with a host and no path")
	}
	f, err := fakeacme.New(fakeacme.Options{BaseURL: cfg.BaseURL, RequireEAB: cfg.RequireEAB, Alternates: cfg.Alternates})
	if err != nil {
		return err
	}
	defer f.Close()
	handler, adminHandler, tlsConf, caPEM := f.Handler(), f.AdminHandler(), f.TLSConfig(), f.CAPEM()
	if cfg.DNSProviders {
		d, err := newDNSFakes(f)
		if err != nil {
			return err
		}
		defer d.Close()
		handler, adminHandler, tlsConf = d.handler(handler), d.admin(adminHandler), d.tlsConfig(tlsConf)
		caPEM = append(append([]byte{}, caPEM...), d.caPEM()...)
	}

	lc := &net.ListenConfig{}
	tlsLn, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	adminLn, err := lc.Listen(ctx, "tcp", cfg.Admin)
	if err != nil {
		_ = tlsLn.Close()
		return fmt.Errorf("listen on %s: %w", cfg.Admin, err)
	}
	if err := boundLoopback(adminLn.Addr()); err != nil {
		_ = tlsLn.Close()
		_ = adminLn.Close()
		return err
	}
	if cfg.CAOut != "" {
		if err := writeCA(cfg.CAOut, caPEM); err != nil {
			_ = tlsLn.Close()
			_ = adminLn.Close()
			return err
		}
	}
	acmeSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	admin := &http.Server{Handler: adminHandler, ReadHeaderTimeout: 10 * time.Second}
	errs := make(chan error, 2)
	go func() { errs <- acmeSrv.Serve(tls.NewListener(tlsLn, tlsConf)) }()
	go func() { errs <- admin.Serve(adminLn) }()
	log.Info("alice-fakeacme is serving", "acme", tlsLn.Addr().String(), "admin", adminLn.Addr().String(),
		"directory", f.DirectoryURL(), "ca_out", cfg.CAOut)
	if cfg.ready != nil {
		cfg.ready(tlsLn.Addr().String(), adminLn.Addr().String())
	}

	select {
	case err = <-errs:
	case <-ctx.Done():
		err = nil
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = acmeSrv.Shutdown(shutdown)
	_ = admin.Shutdown(shutdown)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// writeCA writes the TLS CA certificate (public) for Alice, another user in another container, to read:
// the directory is made 0755 and the file 0644, replaced atomically so a reader never sees a part.
func writeCA(path string, pem []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: a public CA's directory, read by Alice's user (UID 10001)
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, pem, 0o644); err != nil { //nolint:gosec // G306: a public CA certificate, read by Alice's user (UID 10001)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o644); err != nil { //nolint:gosec // G302: same: the file must be readable whatever the umask
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// checkLoopback accepts only a literal loopback IP (127.0.0.0/8 or ::1, no zone, no IPv4-mapped form)
// with a port: no host name, not even localhost, whose answer could change.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	bad := fmt.Errorf("%q must be a loopback IP address with a port (127.0.0.1:9091)", addr)
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
		return fmt.Errorf("the admin listener is bound to %s, not a loopback address", a)
	}
	return nil
}

// ---- ctl ----

// ctlCommand maps a ctl command to an admin request: its positionals (min, max), the flags it takes
// (true = takes a value) and the request it sends.
type ctlCommand struct {
	min, max int
	flags    map[string]bool
	request  func(pos []string, flags map[string]string) (method, path string, q url.Values)
}

type form = url.Values

func get(path string) ctlCommand  { return fixed(http.MethodGet, path) }
func post(path string) ctlCommand { return fixed(http.MethodPost, path) }

func fixed(method, path string) ctlCommand {
	return ctlCommand{request: func([]string, map[string]string) (string, string, url.Values) { return method, path, nil }}
}

// withPos is a POST with n positionals mapped to the named query parameters.
func withPos(path string, names ...string) ctlCommand {
	return ctlCommand{min: len(names), max: len(names), request: func(pos []string, _ map[string]string) (string, string, url.Values) {
		q := form{}
		for i, n := range names {
			q.Set(n, pos[i])
		}
		return http.MethodPost, path, q
	}}
}

func onOff(v string) string { return map[string]string{"on": "true", "off": "false"}[v] }

var ctlCommands = map[string]ctlCommand{
	"ping":           get("/ping"),
	"credentials":    get("/credentials"),
	"dns-providers":  get("/dns-providers"),
	"ca":             get("/ca"),
	"reset":          post("/reset"),
	"counters":       get("/counters"),
	"requests":       get("/requests"),
	"clear-requests": post("/requests/clear"),
	"fault set": {min: 2, max: 2, flags: map[string]bool{"times": true, "retry-after": true, "delay": true},
		request: func(pos []string, fl map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/fault", form{"endpoint": {pos[0]}, "kind": {pos[1]}, "times": {fl["times"]}, "retry_after": {fl["retry-after"]}, "delay": {fl["delay"]}}
		}},
	"fault clear": post("/unfault"),
	"dns set":     withPos("/dns", "name", "value"),
	"dns clear": {max: 2, request: func(pos []string, _ map[string]string) (string, string, url.Values) {
		q := form{}
		if len(pos) > 0 {
			q.Set("name", pos[0])
		}
		if len(pos) > 1 {
			q.Set("value", pos[1])
		}
		return http.MethodPost, "/dns/clear", q
	}},
	"dns list":    get("/dns"),
	"http-target": withPos("/http-target", "name", "addr"),
	"eab": {min: 1, max: 1, request: func(pos []string, _ map[string]string) (string, string, url.Values) {
		return http.MethodPost, "/eab", form{"required": {onOff(pos[0])}}
	}},
	"lifetime": withPos("/lifetime", "duration"),
	"stuck": {min: 1, max: 1, request: func(pos []string, _ map[string]string) (string, string, url.Values) {
		return http.MethodPost, "/stuck", form{"on": {onOff(pos[0])}}
	}},
	"reject": {min: 1, max: 1, request: rejectRequest},
	"validation-fail": {min: 2, max: 2, request: func(pos []string, _ map[string]string) (string, string, url.Values) {
		return http.MethodPost, "/validation-fail", form{"type": {pos[0]}, "on": {onOff(pos[1])}}
	}},
	"challenges":       withPos("/challenges", "types"),
	"processing-polls": withPos("/processing-polls", "n"),
	"ari default": {request: func([]string, map[string]string) (string, string, url.Values) {
		return http.MethodPost, "/ari", form{"default": {"true"}}
	}},
	"ari window":      withPos("/ari", "start", "end"),
	"ari certificate": withPos("/ari", "serial", "start", "end"),
	"replacements":    get("/replacements"),
	"ari relative": {min: 1, max: 2, request: func(pos []string, _ map[string]string) (string, string, url.Values) {
		q := form{"before": {pos[0]}}
		if len(pos) > 1 {
			q.Set("length", pos[1])
		}
		return http.MethodPost, "/ari", q
	}},
	"advertise": {min: 1, max: 2, request: func(pos []string, _ map[string]string) (string, string, url.Values) {
		q := form{"field": {pos[0]}}
		if len(pos) > 1 {
			q.Set("url", pos[1])
		}
		return http.MethodPost, "/advertise", q
	}},
	"clock": withPos("/clock", "time"),
}

func rejectRequest(pos []string, _ map[string]string) (string, string, url.Values) {
	if pos[0] == "clear" {
		return http.MethodPost, "/reject/clear", nil
	}
	return http.MethodPost, "/reject", form{"identifier": {pos[0]}}
}

// lookup finds a command by one or two words and returns the arguments left.
func lookup(args []string) (name string, cmd ctlCommand, rest []string, ok bool) {
	if len(args) >= 2 {
		if c, found := ctlCommands[args[0]+" "+args[1]]; found {
			return args[0] + " " + args[1], c, args[2:], true
		}
	}
	c, found := ctlCommands[args[0]]
	return args[0], c, args[1:], found
}

// parseCtl splits arguments into positionals and --flags (a value flag takes the next argument).
func parseCtl(cmd ctlCommand, args []string) (pos []string, flags map[string]string, err error) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, isFlag := strings.CutPrefix(a, "--")
		if !isFlag {
			pos = append(pos, a)
			continue
		}
		takesValue, known := cmd.flags[name]
		switch {
		case !known:
			return nil, nil, fmt.Errorf("unknown flag --%s", name)
		case !takesValue:
			flags[name] = "true"
		case i+1 >= len(args):
			return nil, nil, fmt.Errorf("--%s needs a value", name)
		default:
			i++
			flags[name] = args[i]
		}
	}
	if len(pos) < cmd.min || len(pos) > cmd.max {
		return nil, nil, errors.New("wrong number of arguments")
	}
	return pos, flags, nil
}

func runCtl(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	adminAddr := fs.String("admin", defaultAdmin, "address of the admin API (loopback only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	name, cmd, rest, found := lookup(fs.Args())
	if !found {
		_, _ = fmt.Fprintf(stderr, "alice-fakeacme ctl: unknown command %q\n\n%s", fs.Arg(0), usage)
		return 2
	}
	if err := checkLoopback(*adminAddr); err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeacme ctl: the admin address %v\n", err)
		return 2
	}
	pos, flags, err := parseCtl(cmd, rest)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeacme ctl %s: %v\n", name, err)
		return 1
	}
	method, path, q := cmd.request(pos, flags)
	target := url.URL{Scheme: "http", Host: *adminAddr, Path: path}
	if q != nil {
		for k, v := range q {
			if len(v) == 1 && v[0] == "" {
				delete(q, k) // an absent flag is no parameter
			}
		}
		target.RawQuery = q.Encode()
	}
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, target.String(), nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeacme ctl: %v\n", err)
		return 1
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req) //nolint:gosec // G704: the address was checked to be loopback above
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeacme ctl: the fake does not answer at %s: %v\n", *adminAddr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAdminBody))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeacme ctl: %v\n", err)
		return 1
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		_, _ = fmt.Fprintf(stderr, "alice-fakeacme ctl %s: %s\n", name, e.Error)
		return 1
	}
	_, _ = stdout.Write(body)
	return 0
}
