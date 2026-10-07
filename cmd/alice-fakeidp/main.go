// Command alice-fakeidp is the fake OpenID Connect provider that runs in the e2e stack (compose service
// fakeidp) for the Phase 7 SSO journeys. It is a test tool: it is built into the e2e fake IdP image only and
// never ships (internal/archtest lists it in testOnlyDirs). It wraps internal/testutil/fakeidp, the fake the
// Go suites use in process.
//
//	alice-fakeidp serve [--listen :9444] [--host idp.alice-e2e.test] [--admin 127.0.0.1:9091] [--redirect-prefix PREFIX]
//	alice-fakeidp ctl [--admin ADDR] COMMAND [ARGS]
//
// serve generates a CA, a TLS certificate for --host, signing keys and the client secret when it starts
// (nothing of it is stored in the repository or the image), serves the provider over TLS on --listen and an
// admin API on --admin. The admin API has no authentication beyond its address: it listens on loopback only
// (serve refuses any other address), ctl talks to loopback only, and it runs inside the container ("docker
// compose exec fakeidp /alice-fakeidp ctl ..."). The client secret is printed by "ctl credentials" and never
// written to the log.
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

	"alice/internal/testutil/fakeidp"
)

const (
	defaultListen = ":9444"
	defaultHost   = "idp.alice-e2e.test"
	defaultAdmin  = "127.0.0.1:9091"
	maxAdminBody  = 1 << 20
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `Usage: alice-fakeidp <command>

Commands:
  serve [--listen ADDR] [--host NAME] [--admin ADDR] [--redirect-prefix PREFIX]
        Run the fake: the provider over TLS on --listen (default :9444) as https://NAME:PORT, the admin API
        on --admin (default 127.0.0.1:9091, loopback only). Redirect URIs starting with PREFIX are allowed.
  ctl [--admin ADDR] <command> [args]
        Drive a running fake (JSON on stdout, errors on stderr, exit 1 on failure):
        ping | credentials | ca (the CA certificate, PEM) | down | up
        next-user [--sub S] [--username U] [--name N] [--email E] [--groups a,b]
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
		_, _ = fmt.Fprintf(stderr, "alice-fakeidp: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

type serveConfig struct {
	Listen         string
	Host           string
	Admin          string
	RedirectPrefix string
	// ready, when set, is called with the bound addresses once everything listens (tests).
	ready func(idp, admin string)
}

func runServe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := serveConfig{}
	fs.StringVar(&cfg.Listen, "listen", defaultListen, "address of the provider (TLS)")
	fs.StringVar(&cfg.Host, "host", defaultHost, "the TLS name and the issuer host")
	fs.StringVar(&cfg.Admin, "admin", defaultAdmin, "address of the admin API (loopback only)")
	fs.StringVar(&cfg.RedirectPrefix, "redirect-prefix", "", "redirect URIs starting with this are allowed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "alice-fakeidp serve: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	if err := serve(ctx, cfg, log); err != nil {
		log.Error("alice-fakeidp stopped", "error", err.Error())
		if errors.Is(err, errNotLoopback) {
			return 2
		}
		return 1
	}
	return 0
}

// serve runs the fake until ctx ends. It logs addresses and never the client secret or a key.
func serve(ctx context.Context, cfg serveConfig, log *slog.Logger) error {
	if err := checkLoopback(cfg.Admin); err != nil {
		return fmt.Errorf("admin address: %w", err)
	}
	s, err := fakeidp.New(fakeidp.Options{Host: cfg.Host})
	if err != nil {
		return err
	}
	if cfg.RedirectPrefix != "" {
		s.RegisterRedirectPrefix(cfg.RedirectPrefix)
	}
	adminLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Admin)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Admin, err)
	}
	if err := boundLoopback(adminLn.Addr()); err != nil {
		_ = adminLn.Close()
		return err
	}
	if err := s.Listen(cfg.Listen); err != nil {
		_ = adminLn.Close()
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	defer s.Close()
	admin := &http.Server{Handler: adminHandler(s), ReadHeaderTimeout: 10 * time.Second}
	errs := make(chan error, 1)
	go func() { errs <- admin.Serve(adminLn) }()
	log.Info("alice-fakeidp is serving", "issuer", s.Issuer(), "admin", adminLn.Addr().String(), "client_id", s.ClientID())
	if cfg.ready != nil {
		cfg.ready(s.Issuer(), adminLn.Addr().String())
	}
	select {
	case err = <-errs:
	case <-ctx.Done():
		err = nil
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = admin.Shutdown(shutdown)
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

// nextUser is the body of POST /ctl/next-user.
type nextUser struct {
	Subject  string   `json:"sub"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}

func adminHandler(s *fakeidp.Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ctl/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /ctl/credentials", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"issuer": s.Issuer(), "client_id": s.ClientID(), "client_secret": s.ClientSecret()})
	})
	mux.HandleFunc("GET /ctl/ca", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(s.CAPEM())
	})
	mux.HandleFunc("POST /ctl/next-user", func(w http.ResponseWriter, r *http.Request) {
		var in nextUser
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || in.Subject == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the body must be {\"sub\": ..., \"username\": ..., \"name\": ..., \"email\": ..., \"groups\": [...]} with a sub"})
			return
		}
		s.NextLogin(fakeidp.Login{Subject: in.Subject, Username: in.Username, Name: in.Name, Email: in.Email, Groups: in.Groups})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /ctl/down", func(w http.ResponseWriter, _ *http.Request) {
		s.Down()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /ctl/up", func(w http.ResponseWriter, _ *http.Request) {
		s.Up()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	return mux
}

var errNotLoopback = errors.New("not a loopback address")

// checkLoopback accepts only a literal loopback IP (127.0.0.0/8 or ::1, no zone, no IPv4-mapped form)
// with a port: no host name, not even localhost, whose answer could change.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	bad := fmt.Errorf("%w: %q must be a loopback IP address with a port (127.0.0.1:9091)", errNotLoopback, addr)
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
		return fmt.Errorf("%w: the admin listener is bound to %s", errNotLoopback, a)
	}
	return nil
}

// ---- ctl ----

type ctlRequest struct {
	method, path string
	body         any // JSON body, nil for none
}

func get(path string) ctlRequest  { return ctlRequest{method: http.MethodGet, path: path} }
func post(path string) ctlRequest { return ctlRequest{method: http.MethodPost, path: path} }

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
	name, rest := fs.Arg(0), fs.Args()[1:]
	var cr ctlRequest
	switch name {
	case "ping", "credentials", "ca", "down", "up":
		if len(rest) != 0 {
			_, _ = fmt.Fprintf(stderr, "alice-fakeidp ctl: %s takes no arguments\n", name)
			return 1
		}
		switch name {
		case "ping", "credentials", "ca":
			cr = get("/ctl/" + name)
		default:
			cr = post("/ctl/" + name)
		}
	case "next-user":
		nf := flag.NewFlagSet("next-user", flag.ContinueOnError)
		nf.SetOutput(stderr)
		var u nextUser
		var groups string
		nf.StringVar(&u.Subject, "sub", "", "the subject (required)")
		nf.StringVar(&u.Username, "username", "", "preferred_username")
		nf.StringVar(&u.Name, "name", "", "the display name")
		nf.StringVar(&u.Email, "email", "", "the e-mail address")
		nf.StringVar(&groups, "groups", "", "comma-separated group values")
		if err := nf.Parse(rest); err != nil {
			return 2
		}
		if u.Subject == "" || nf.NArg() != 0 {
			_, _ = fmt.Fprint(stderr, "alice-fakeidp ctl: usage: ctl next-user --sub S [--username U] [--name N] [--email E] [--groups a,b]\n")
			return 1
		}
		if groups != "" {
			u.Groups = strings.Split(groups, ",")
		}
		cr = post("/ctl/next-user")
		cr.body = u
	default:
		_, _ = fmt.Fprintf(stderr, "alice-fakeidp ctl: unknown command %q\n\n%s", name, usage)
		return 2
	}
	if err := checkLoopback(*adminAddr); err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeidp ctl: the admin address %v\n", err)
		return 2
	}
	var rdr io.Reader
	if cr.body != nil {
		raw, err := json.Marshal(cr.body)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "alice-fakeidp ctl: %v\n", err)
			return 1
		}
		rdr = strings.NewReader(string(raw))
	}
	target := url.URL{Scheme: "http", Host: *adminAddr, Path: cr.path}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, cr.method, target.String(), rdr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeidp ctl: %v\n", err)
		return 1
	}
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req) //nolint:gosec // G704: the address was checked to be loopback above
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeidp ctl: the fake does not answer at %s: %v\n", *adminAddr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAdminBody))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeidp ctl: %v\n", err)
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
		_, _ = fmt.Fprintf(stderr, "alice-fakeidp ctl %s: %s\n", name, e.Error)
		return 1
	}
	_, _ = stdout.Write(body)
	return 0
}
