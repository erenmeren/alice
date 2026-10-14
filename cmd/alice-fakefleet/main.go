// Command alice-fakefleet is the fleet of hostile and ordinary TLS servers that runs in the e2e stack
// (compose service fakefleet on the dedicated network "fleet", fixed address 10.89.0.10, a name per
// server kind under fleet.alice-e2e.test) for the network discovery journeys. It is a test tool: it
// is built into the e2e fake fleet image only and never ships (internal/archtest lists it in
// testOnlyDirs). It wraps internal/testutil/fakefleet, the fleet the Go suites run in process; that
// package documents every server kind.
//
//	alice-fakefleet serve [--bind IP] [--kinds all|KIND,...] [--ports KIND=PORT,...] [--domain NAME]
//	                      [--ctl ADDR] [--slowloris-interval DURATION]
//	alice-fakefleet ctl [--ctl ADDR] COMMAND
//
// serve generates its CA and every certificate when it starts (nothing is stored in the repository
// or the image) and serves each kind on --bind at its port (fakefleet.DefaultPorts unless --ports
// says otherwise). Each flag can also come from the environment (FAKEFLEET_BIND, FAKEFLEET_KINDS,
// FAKEFLEET_PORTS, FAKEFLEET_DOMAIN, FAKEFLEET_CTL, FAKEFLEET_SLOWLORIS_INTERVAL); a flag wins. The
// control API has no authentication beyond its address: it listens on loopback only (serve refuses
// any other address), ctl talks to loopback only, and it runs inside the container ("docker compose
// exec fakefleet /alice-fakefleet ctl log --settle").
package main

import (
	"context"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"alice/internal/testutil/fakefleet"
)

const (
	defaultBind   = "0.0.0.0"
	defaultDomain = "fleet.alice-e2e.test"
	defaultCtl    = "127.0.0.1:9092"
	maxCtlBody    = 16 << 20
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `Usage: alice-fakefleet <command>

Commands:
  serve [--bind IP] [--kinds all|KIND,...] [--ports KIND=PORT,...] [--domain NAME] [--ctl ADDR]
        [--slowloris-interval DURATION]
        Run the fleet: every kind on --bind (default 0.0.0.0) at its port, the control API on --ctl
        (default 127.0.0.1:9092, loopback only). Environment: FAKEFLEET_<FLAG> (a flag wins).
        Kinds: valid expired not-yet-valid self-signed wrong-order missing-intermediate sni tls10 tls12
        tls13 rsa-kex sha1 slow-loris giant-chain huge-chain reset plaintext many-sni malformed
  ctl [--ctl ADDR] <command>
        Drive a running fleet (JSON on stdout, errors on stderr, exit 1 on failure):
        ping | fleet | ca | log [--settle] | clear-log | counters
`

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		cfg, err := parseServe(args[1:], os.Getenv, stderr)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "alice-fakefleet serve: %v\n", err)
			return 2
		}
		log := slog.New(slog.NewTextHandler(stderr, nil))
		if err := serve(ctx, cfg, log); err != nil {
			log.Error("alice-fakefleet stopped", "error", err.Error())
			return 1
		}
		return 0
	case "ctl":
		return runCtl(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "alice-fakefleet: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// ---- serve ----

type serveConfig struct {
	Bind              string
	Kinds             []fakefleet.Kind
	Ports             map[fakefleet.Kind]int
	Domain            string
	Ctl               string
	SlowLorisInterval time.Duration
	// ready, when set, is called once everything listens (tests).
	ready func(info fakefleet.Info, ctl string)
}

// parseServe reads serve's flags; every flag defaults to its FAKEFLEET_ environment variable, then to
// the built-in default.
func parseServe(args []string, getenv func(string) string, stderr io.Writer) (serveConfig, error) {
	envOr := func(name, def string) string {
		if v := getenv("FAKEFLEET_" + name); v != "" {
			return v
		}
		return def
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bind := fs.String("bind", envOr("BIND", defaultBind), "IP address every server listens on")
	kinds := fs.String("kinds", envOr("KINDS", "all"), "kinds to serve: all or a comma-separated list")
	ports := fs.String("ports", envOr("PORTS", ""), "port overrides: KIND=PORT,... (0 = any free port)")
	domain := fs.String("domain", envOr("DOMAIN", defaultDomain), "DNS suffix of the servers' names")
	ctlAddr := fs.String("ctl", envOr("CTL", defaultCtl), "address of the control API (loopback only)")
	intervalText := envOr("SLOWLORIS_INTERVAL", "1s")
	interval, err := time.ParseDuration(intervalText)
	if err != nil {
		return serveConfig{}, fmt.Errorf("FAKEFLEET_SLOWLORIS_INTERVAL: %w", err)
	}
	fs.DurationVar(&interval, "slowloris-interval", interval, "how often the slow-loris server writes its next byte")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}
	if fs.NArg() != 0 {
		return serveConfig{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	cfg := serveConfig{Bind: *bind, Domain: *domain, Ctl: *ctlAddr, SlowLorisInterval: interval, Ports: map[fakefleet.Kind]int{}}
	if ip, err := netip.ParseAddr(cfg.Bind); err != nil || ip.Zone() != "" {
		return serveConfig{}, fmt.Errorf("--bind %q is not an IP address", cfg.Bind)
	}
	if err := checkLoopback(cfg.Ctl); err != nil {
		return serveConfig{}, fmt.Errorf("--ctl: %w", err)
	}
	if interval <= 0 {
		return serveConfig{}, errors.New("--slowloris-interval must be positive")
	}
	if cfg.Kinds, err = parseKinds(*kinds); err != nil {
		return serveConfig{}, err
	}
	for k, p := range fakefleet.DefaultPorts {
		cfg.Ports[k] = p
	}
	if err := parsePorts(*ports, cfg.Ports); err != nil {
		return serveConfig{}, err
	}
	used := map[int]fakefleet.Kind{}
	for _, k := range cfg.Kinds {
		p := cfg.Ports[k]
		if other, dup := used[p]; dup && p != 0 {
			return serveConfig{}, fmt.Errorf("--ports: %s and %s both on port %d", other, k, p)
		}
		used[p] = k
	}
	return cfg, nil
}

func parseKinds(s string) ([]fakefleet.Kind, error) {
	if s == "all" {
		return fakefleet.AllKinds, nil
	}
	var out []fakefleet.Kind
	for _, part := range strings.Split(s, ",") {
		k := fakefleet.Kind(strings.TrimSpace(part))
		if _, ok := fakefleet.DefaultPorts[k]; !ok {
			return nil, fmt.Errorf("--kinds: unknown kind %q", k)
		}
		out = append(out, k)
	}
	return out, nil
}

func parsePorts(s string, into map[fakefleet.Kind]int) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		name, port, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return fmt.Errorf("--ports: %q is not KIND=PORT", part)
		}
		k := fakefleet.Kind(name)
		if _, known := fakefleet.DefaultPorts[k]; !known {
			return fmt.Errorf("--ports: unknown kind %q", name)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("--ports: %q is not a port", port)
		}
		into[k] = n
	}
	return nil
}

// serve runs the fleet until ctx ends. It logs addresses and never a key.
func serve(ctx context.Context, cfg serveConfig, log *slog.Logger) error {
	listen := map[fakefleet.Kind]string{}
	for _, k := range cfg.Kinds {
		listen[k] = net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Ports[k]))
	}
	f, err := fakefleet.New(fakefleet.Options{Kinds: cfg.Kinds, Listen: listen, Bind: cfg.Bind, Domain: cfg.Domain,
		SlowLorisInterval: cfg.SlowLorisInterval})
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	ctlLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Ctl)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Ctl, err)
	}
	if err := boundLoopback(ctlLn.Addr()); err != nil {
		_ = ctlLn.Close()
		return err
	}
	srv := &http.Server{Handler: f.ControlHandler(), ReadHeaderTimeout: 10 * time.Second}
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(ctlLn) }()
	info := f.Info()
	attrs := []any{"ctl", ctlLn.Addr().String(), "domain", info.Domain}
	for _, s := range info.Servers {
		attrs = append(attrs, string(s.Kind), s.Addr)
	}
	log.Info("alice-fakefleet is serving", attrs...)
	if cfg.ready != nil {
		cfg.ready(info, ctlLn.Addr().String())
	}
	select {
	case err = <-errs:
	case <-ctx.Done():
		err = nil
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// checkLoopback accepts only a literal loopback IP (127.0.0.0/8 or ::1, no zone, no IPv4-mapped form)
// with a port: no host name, not even localhost, whose answer could change.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	bad := fmt.Errorf("%q must be a loopback IP address with a port (127.0.0.1:9092)", addr)
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
	"fleet":     {http.MethodGet, "/fleet"},
	"ca":        {http.MethodGet, "/ca"},
	"log":       {http.MethodGet, "/log"},
	"clear-log": {http.MethodPost, "/log/clear"},
	"counters":  {http.MethodGet, "/counters"},
}

func runCtl(ctx context.Context, args []string, stdout, stderr io.Writer) int {
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
	name, rest := fs.Arg(0), fs.Args()[1:]
	cmd, ok := ctlCommands[name]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "alice-fakefleet ctl: unknown command %q\n\n%s", name, usage)
		return 2
	}
	path := cmd[1]
	switch {
	case name == "log" && len(rest) == 1 && rest[0] == "--settle":
		path += "?" + url.Values{"settle": {"1"}}.Encode()
	case len(rest) != 0:
		_, _ = fmt.Fprintf(stderr, "alice-fakefleet ctl %s: takes no argument but %q\n", name, strings.Join(rest, " "))
		return 2
	}
	if err := checkLoopback(*addr); err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakefleet ctl: the control address %v\n", err)
		return 2
	}
	return ctlRequest(ctx, *addr, cmd[0], path, name, stdout, stderr)
}

// ctlRequest sends one request to the loopback control API and copies the answer to stdout.
func ctlRequest(ctx context.Context, addr, method, path, name string, stdout, stderr io.Writer) int {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, "http://"+addr+path, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakefleet ctl: %v\n", err)
		return 1
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req) //nolint:gosec // G704: the address was checked to be loopback
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakefleet ctl: the fleet does not answer at %s: %v\n", addr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCtlBody))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakefleet ctl: %v\n", err)
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
		_, _ = fmt.Fprintf(stderr, "alice-fakefleet ctl %s: %s\n", name, e.Error)
		return 1
	}
	_, _ = stdout.Write(body)
	return 0
}
