// Command alice-fakesmtp is the fake SMTP server that runs in the e2e stack (compose service fakesmtp) for
// the Phase 7 journeys. It is a test tool: it is built into the e2e fake SMTP image only and never ships
// (internal/archtest lists it in testOnlyDirs). It wraps internal/testutil/fakesmtp, the fake the Go suites
// use in process.
//
//	alice-fakesmtp serve [--listen :2525] [--api 127.0.0.1:8025] [--hostname fakesmtp]
//	alice-fakesmtp ctl [--api ADDR] COMMAND [ARGS]
//
// serve generates a self-signed certificate for --hostname and an AUTH PLAIN password when it starts
// (nothing of it is stored in the repository or the image), accepts mail on --listen (STARTTLS) and serves
// a MailHog-compatible message API plus the control routes on --api. The API has no authentication beyond
// its address: it listens on loopback only (serve refuses any other address), ctl talks to loopback only,
// and it runs inside the container ("docker compose exec fakesmtp /alice-fakesmtp ctl ..."). The password
// is printed by "ctl credentials" and never written to the log.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

	"alice/internal/testutil/fakesmtp"
)

const (
	defaultListen   = ":2525"
	defaultAPI      = "127.0.0.1:8025"
	defaultHostname = "fakesmtp"
	smtpUsername    = "mailer"
	maxAdminBody    = 1 << 20
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `Usage: alice-fakesmtp <command>

Commands:
  serve [--listen ADDR] [--api ADDR] [--hostname NAME]
        Run the fake: SMTP with STARTTLS and AUTH PLAIN on --listen (default :2525), the message API and
        the control routes on --api (default 127.0.0.1:8025, loopback only).
  ctl [--api ADDR] <command> [args]
        Drive a running fake (JSON on stdout, errors on stderr, exit 1 on failure):
        ping | credentials | fingerprint | messages | clear | down | up | reject [ADDRESS]
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
		_, _ = fmt.Fprintf(stderr, "alice-fakesmtp: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

type serveConfig struct {
	Listen   string
	API      string
	Hostname string
	// ready, when set, is called with the bound addresses once everything listens (tests).
	ready func(smtp, api string)
}

func runServe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := serveConfig{}
	fs.StringVar(&cfg.Listen, "listen", defaultListen, "address of the SMTP server")
	fs.StringVar(&cfg.API, "api", defaultAPI, "address of the message and control API (loopback only)")
	fs.StringVar(&cfg.Hostname, "hostname", defaultHostname, "the certificate's DNS name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "alice-fakesmtp serve: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	if err := serve(ctx, cfg, log); err != nil {
		log.Error("alice-fakesmtp stopped", "error", err.Error())
		if errors.Is(err, errNotLoopback) {
			return 2
		}
		return 1
	}
	return 0
}

// serve runs the fake until ctx ends. It logs addresses and never the password or the certificate.
func serve(ctx context.Context, cfg serveConfig, log *slog.Logger) error {
	if err := checkLoopback(cfg.API); err != nil {
		return fmt.Errorf("api address: %w", err)
	}
	pw := make([]byte, 32)
	if _, err := rand.Read(pw); err != nil {
		return err
	}
	password := base64.RawURLEncoding.EncodeToString(pw)
	s, err := fakesmtp.New(fakesmtp.Options{Hostname: cfg.Hostname, Username: smtpUsername, Password: password})
	if err != nil {
		return err
	}
	apiLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.API)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.API, err)
	}
	if err := boundLoopback(apiLn.Addr()); err != nil {
		_ = apiLn.Close()
		return err
	}
	if err := s.Listen(cfg.Listen); err != nil {
		_ = apiLn.Close()
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	defer s.Close()
	api := &http.Server{Handler: adminHandler(s, smtpUsername, password), ReadHeaderTimeout: 10 * time.Second}
	errs := make(chan error, 1)
	go func() { errs <- api.Serve(apiLn) }()
	host, port := s.Addr()
	smtpAddr := net.JoinHostPort(host, strconv.Itoa(port))
	log.Info("alice-fakesmtp is serving", "smtp", smtpAddr, "api", apiLn.Addr().String(), "hostname", cfg.Hostname)
	if cfg.ready != nil {
		cfg.ready(smtpAddr, apiLn.Addr().String())
	}
	select {
	case err = <-errs:
	case <-ctx.Done():
		err = nil
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = api.Shutdown(shutdown)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// adminHandler is the MailHog-compatible API of the fake plus the control routes under /ctl.
func adminHandler(s *fakesmtp.Server, username, password string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", s.Handler())
	mux.HandleFunc("GET /ctl/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /ctl/credentials", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"username": username, "password": password})
	})
	mux.HandleFunc("GET /ctl/fingerprint", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"fingerprint": s.Fingerprint()})
	})
	mux.HandleFunc("POST /ctl/down", func(w http.ResponseWriter, _ *http.Request) {
		s.Down()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /ctl/up", func(w http.ResponseWriter, _ *http.Request) {
		if err := s.Up(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /ctl/reject", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Address string `json:"address"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the body must be {\"address\": ...}"})
			return
		}
		s.RejectRecipient(in.Address)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	return mux
}

var errNotLoopback = errors.New("not a loopback address")

// checkLoopback accepts only a literal loopback IP (127.0.0.0/8 or ::1, no zone, no IPv4-mapped form)
// with a port: no host name, not even localhost, whose answer could change.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	bad := fmt.Errorf("%w: %q must be a loopback IP address with a port (127.0.0.1:8025)", errNotLoopback, addr)
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
		return fmt.Errorf("%w: the API listener is bound to %s", errNotLoopback, a)
	}
	return nil
}

// ---- ctl ----

type ctlRequest struct {
	method, path string
	body         any // JSON body, nil for none
}

// ctlCommands maps a ctl command to its request; max is the number of positional arguments it takes.
var ctlCommands = map[string]struct {
	usage string
	max   int
	build func(pos []string) ctlRequest
}{
	"ping":        {"ping", 0, func([]string) ctlRequest { return ctlRequest{method: http.MethodGet, path: "/ctl/ping"} }},
	"credentials": {"credentials", 0, func([]string) ctlRequest { return ctlRequest{method: http.MethodGet, path: "/ctl/credentials"} }},
	"fingerprint": {"fingerprint", 0, func([]string) ctlRequest { return ctlRequest{method: http.MethodGet, path: "/ctl/fingerprint"} }},
	"messages":    {"messages", 0, func([]string) ctlRequest { return ctlRequest{method: http.MethodGet, path: "/api/v2/messages"} }},
	"clear":       {"clear", 0, func([]string) ctlRequest { return ctlRequest{method: http.MethodDelete, path: "/api/v1/messages"} }},
	"down":        {"down", 0, func([]string) ctlRequest { return ctlRequest{method: http.MethodPost, path: "/ctl/down"} }},
	"up":          {"up", 0, func([]string) ctlRequest { return ctlRequest{method: http.MethodPost, path: "/ctl/up"} }},
	"reject": {"reject [ADDRESS]", 1, func(pos []string) ctlRequest {
		addr := ""
		if len(pos) == 1 {
			addr = pos[0]
		}
		return ctlRequest{method: http.MethodPost, path: "/ctl/reject", body: map[string]string{"address": addr}}
	}},
}

func runCtl(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apiAddr := fs.String("api", defaultAPI, "address of the API (loopback only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	name := fs.Arg(0)
	cmd, found := ctlCommands[name]
	if !found {
		_, _ = fmt.Fprintf(stderr, "alice-fakesmtp ctl: unknown command %q\n\n%s", name, usage)
		return 2
	}
	if err := checkLoopback(*apiAddr); err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakesmtp ctl: the API address %v\n", err)
		return 2
	}
	pos := fs.Args()[1:]
	if len(pos) > cmd.max {
		_, _ = fmt.Fprintf(stderr, "alice-fakesmtp ctl: too many arguments\nusage: ctl %s\n", cmd.usage)
		return 1
	}
	cr := cmd.build(pos)
	var rdr io.Reader
	if cr.body != nil {
		raw, err := json.Marshal(cr.body)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "alice-fakesmtp ctl: %v\n", err)
			return 1
		}
		rdr = strings.NewReader(string(raw))
	}
	target := url.URL{Scheme: "http", Host: *apiAddr, Path: cr.path}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, cr.method, target.String(), rdr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakesmtp ctl: %v\n", err)
		return 1
	}
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req) //nolint:gosec // G704: the address was checked to be loopback above
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakesmtp ctl: the fake does not answer at %s: %v\n", *apiAddr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAdminBody))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakesmtp ctl: %v\n", err)
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
		_, _ = fmt.Fprintf(stderr, "alice-fakesmtp ctl %s: %s\n", name, e.Error)
		return 1
	}
	if len(body) == 0 {
		body = []byte("{\"ok\": true}\n")
	}
	_, _ = stdout.Write(body)
	return 0
}
