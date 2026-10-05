// Command alice-fakeazure is the fake of Microsoft Entra ID and Azure Key Vault that runs in the e2e
// stack (compose service fakeazure) for the Phase 5 journeys. It is a test tool: it is built into the
// e2e fake Azure image only and never ships (internal/archtest lists it in testOnlyDirs). It wraps
// internal/testutil/fakekv, the fake the Go suites use in process.
//
//	alice-fakeazure serve [--listen :443] [--admin 127.0.0.1:9090] [--ca-out FILE] [--vault-name NAME]
//	alice-fakeazure ctl [--admin ADDR] COMMAND [ARGS]
//
// serve generates a CA, a TLS certificate for login.microsoftonline.com and <vault>.vault.azure.net, a
// tenant, an application and its client secret when it starts (nothing of it is stored in the
// repository or in the image), writes the CA to --ca-out for Alice to trust, seeds the vault, serves the
// Azure hosts on --listen and an admin API on --admin. The admin API has no authentication beyond
// its address: it listens on loopback only (serve refuses any other address), ctl talks to loopback
// only, and it runs inside the container ("docker compose exec fakeazure /alice-fakeazure ctl ...").
// The client secret is printed by "ctl credentials" and never written to the log.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"alice/internal/testutil/fakekv"
)

const (
	defaultListen = ":443"
	defaultAdmin  = "127.0.0.1:9090"
	vaultName     = "alice-e2e"
	loginHost     = "login.microsoftonline.com"
	maxAdminBody  = 1 << 16
)

var (
	nameRE    = regexp.MustCompile(`^[0-9a-zA-Z-]{1,127}$`)
	versionRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// actions are the data actions revoke-role and grant-role know (fakekv's own list).
	actions = []string{"certificates/list", "certificates/get", "certificates/import", "keys/list", "keys/get", "secrets/list", "secrets/get"}
	roles   = []string{fakekv.RoleReader, fakekv.RoleSecretsUser, fakekv.RoleCertificatesOfficer}
	// throttled are the vault routes "throttle" answers 429 for.
	throttled = []string{"/certificates", "/keys", "/secrets"}
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `Usage: alice-fakeazure <command>

Commands:
  serve [--listen ADDR] [--admin ADDR] [--ca-out FILE] [--vault-name NAME]
        Run the fake: the Azure hosts over TLS on --listen (default :443), the admin API on --admin
        (default 127.0.0.1:9090, loopback only), the CA written to --ca-out.
  ctl [--admin ADDR] <command> [args]
        Drive a running fake (JSON on stdout, errors on stderr, exit 1 on failure):
        ping | credentials | reset
        renew NAME | leaf NAME [--version V] | add-cert NAME [--cn CN] [--exportable true|false]
        set-exportable NAME true|false | disable-version NAME [--version V] | enable-version NAME [--version V]
        delete NAME | recover NAME
        revoke-role ACTION | grant-role ACTION | set-roles [ROLE...] | grant-all
        fault PATH STATUS [--retry-after SECONDS] [--times N] | throttle [--retry-after SECONDS] | unfault
        firewall ADDRESS|off | expire-secret on|off
        requests [--authenticated] | clear-requests
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
		_, _ = fmt.Fprintf(stderr, "alice-fakeazure: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// ---- serve ----

type serveConfig struct {
	Listen    string // the Azure hosts, TLS
	Admin     string // the admin API, plain HTTP, loopback only
	CAOut     string // where the CA is written ("" = nowhere)
	VaultName string
	// ready, when set, is called with the bound addresses once everything listens (tests).
	ready func(listen, admin string)
}

func runServe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := serveConfig{}
	fs.StringVar(&cfg.Listen, "listen", defaultListen, "address of the Azure hosts (TLS)")
	fs.StringVar(&cfg.Admin, "admin", defaultAdmin, "address of the admin API (loopback only)")
	fs.StringVar(&cfg.CAOut, "ca-out", "", "file the CA certificate is written to")
	fs.StringVar(&cfg.VaultName, "vault-name", vaultName, "name of the vault (<name>.vault.azure.net)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "alice-fakeazure serve: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	if err := serve(ctx, cfg, log); err != nil {
		log.Error("alice-fakeazure stopped", "error", err.Error())
		if strings.Contains(err.Error(), "loopback") {
			return 2
		}
		return 1
	}
	return 0
}

// serve runs the fake until ctx ends. It logs addresses and never a secret, token or certificate.
func serve(ctx context.Context, cfg serveConfig, log *slog.Logger) error {
	if err := checkLoopback(cfg.Admin); err != nil {
		return fmt.Errorf("admin address: %w", err)
	}
	f, err := newFake(cfg.VaultName)
	if err != nil {
		return err
	}
	defer f.close()

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
	if cfg.CAOut != "" {
		if err := writeCA(cfg.CAOut, f.s.CAPEM()); err != nil {
			_ = tlsLn.Close()
			_ = adminLn.Close()
			return err
		}
	}
	azure := &http.Server{Handler: f.s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	admin := &http.Server{Handler: adminHandler(f), ReadHeaderTimeout: 10 * time.Second}
	errs := make(chan error, 2)
	go func() { errs <- azure.Serve(tls.NewListener(tlsLn, f.s.TLSConfig())) }()
	go func() { errs <- admin.Serve(adminLn) }()
	log.Info("alice-fakeazure is serving", "azure", tlsLn.Addr().String(), "admin", adminLn.Addr().String(),
		"vault", f.s.VaultURL(), "ca_out", cfg.CAOut)
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
	_ = azure.Shutdown(shutdown)
	_ = admin.Shutdown(shutdown)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// writeCA writes the CA certificate (public) for Alice, another user in another container, to read:
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

// checkLoopback accepts only "localhost:port" or a loopback IP literal with a port.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	bad := fmt.Errorf("%q must be a loopback address with a port (127.0.0.1:9090)", addr)
	if err != nil || host == "" {
		return bad
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return bad
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return bad
	}
	return nil
}

// ---- the fake and its seed ----

// fake is the fakekv server with the state the admin API keeps beside it.
type fake struct {
	s *fakekv.Server

	mu    sync.Mutex
	stops []func() // FailAll faults set by throttle and fault (unfault removes them)
}

func newFake(name string) (*fake, error) {
	if name == "" {
		name = vaultName
	}
	s, err := fakekv.NewServer(fakekv.Options{VaultName: name, Model: "rbac"})
	if err != nil {
		return nil, err
	}
	f := &fake{s: s}
	f.seed()
	return f, nil
}

func (f *fake) close() { f.s.Close() }

// seed fills an empty vault with what the journeys expect: web-cert (ECDSA, www.example.test,
// exportable), monitor-only (not exportable), the key signing-key (RSA 2048) and the secret
// db-password. newFake and reset both call it, so a reset leaves the vault as a start does.
func (f *fake) seed() {
	f.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", SANs: []string{"www.example.test"}, Exportable: true})
	f.s.AddCertificate("monitor-only", fakekv.CertOptions{CommonName: "monitor.example.test", SANs: []string{"monitor.example.test"}, Exportable: false})
	f.s.AddKey("signing-key", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
	f.s.AddSecret("db-password", "text/plain")
}

// reset returns the fake to its seeded state with a new client secret, keeping the CA, the listeners
// and the tenant and client IDs (fakekv.Server.Reset): the CA file Alice trusts stays right.
func (f *fake) reset() {
	f.mu.Lock()
	f.stops = nil
	f.mu.Unlock()
	f.s.Reset()
	f.seed()
}

// ---- the admin API ----

type adminError struct {
	status int
	msg    string
}

func (e *adminError) Error() string { return e.msg }

func bad(format string, args ...any) *adminError {
	return &adminError{status: http.StatusBadRequest, msg: fmt.Sprintf(format, args...)}
}

func notFound(format string, args ...any) *adminError {
	return &adminError{status: http.StatusNotFound, msg: fmt.Sprintf(format, args...)}
}

// adminHandler is the admin API. Every route answers one JSON object; a caller that is not loopback
// gets 403 (the listener is loopback already: defence in depth).
func adminHandler(f *fake) http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, fn func(r *http.Request) (any, *adminError)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			out, aerr := fn(r)
			if aerr != nil {
				writeJSON(w, aerr.status, map[string]string{"error": aerr.msg})
				return
			}
			writeJSON(w, http.StatusOK, out)
		})
	}
	ok := map[string]bool{"ok": true}

	route("GET /ping", func(*http.Request) (any, *adminError) { return ok, nil })
	route("GET /credentials", func(*http.Request) (any, *adminError) { return f.credentials(), nil })
	route("POST /reset", func(*http.Request) (any, *adminError) { f.reset(); return f.credentials(), nil })

	route("POST /certs/{name}/renew", func(r *http.Request) (any, *adminError) {
		name, aerr := f.certName(r)
		if aerr != nil {
			return nil, aerr
		}
		return map[string]string{"version": f.s.Renew(name)}, nil
	})
	route("GET /certs/{name}/leaf", func(r *http.Request) (any, *adminError) {
		name, aerr := f.certName(r)
		if aerr != nil {
			return nil, aerr
		}
		ver, aerr := f.versionOf(name, r.URL.Query().Get("version"), false)
		if aerr != nil {
			return nil, aerr
		}
		leaf := f.s.Leaf(name, ver)
		if leaf == nil {
			return nil, notFound("no such certificate version")
		}
		sum := sha256.Sum256(leaf.Raw)
		return map[string]string{"fingerprint": hex.EncodeToString(sum[:]), "version": ver}, nil
	})
	route("POST /certs/{name}/add", func(r *http.Request) (any, *adminError) {
		name := r.PathValue("name")
		if !nameRE.MatchString(name) {
			return nil, bad("%q is not a valid object name", name)
		}
		if f.s.Versions(name) != nil {
			return nil, bad("a certificate named %s exists", name)
		}
		q := r.URL.Query()
		cn := q.Get("cn")
		if cn == "" {
			cn = name + ".example.test"
		}
		exportable, aerr := boolOf(q.Get("exportable"), true)
		if aerr != nil {
			return nil, aerr
		}
		ver := f.s.AddCertificate(name, fakekv.CertOptions{CommonName: cn, SANs: []string{cn}, Exportable: exportable})
		return map[string]string{"version": ver}, nil
	})
	route("POST /certs/{name}/exportable", func(r *http.Request) (any, *adminError) {
		name, aerr := f.certName(r)
		if aerr != nil {
			return nil, aerr
		}
		v := r.URL.Query().Get("value")
		on, aerr := boolOf(v, false)
		if aerr != nil || v == "" {
			return nil, bad("value must be true or false")
		}
		f.s.SetExportable(name, on)
		return ok, nil
	})
	for _, enable := range []bool{false, true} {
		verb := "disable"
		if enable {
			verb = "enable"
		}
		route("POST /certs/{name}/"+verb, func(r *http.Request) (any, *adminError) {
			name, aerr := f.certName(r)
			if aerr != nil {
				return nil, aerr
			}
			ver, aerr := f.versionOf(name, r.URL.Query().Get("version"), true)
			if aerr != nil {
				return nil, aerr
			}
			if enable {
				f.s.EnableVersion(name, ver)
			} else {
				f.s.DisableVersion(name, ver)
			}
			return map[string]string{"version": ver}, nil
		})
	}
	route("POST /certs/{name}/delete", func(r *http.Request) (any, *adminError) {
		name, aerr := f.certName(r)
		if aerr != nil {
			return nil, aerr
		}
		f.s.DeleteCertificate(name)
		return ok, nil
	})
	route("POST /certs/{name}/recover", func(r *http.Request) (any, *adminError) {
		name, aerr := f.certName(r)
		if aerr != nil {
			return nil, aerr
		}
		f.s.RecoverCertificate(name)
		return ok, nil
	})

	route("POST /roles/revoke", func(r *http.Request) (any, *adminError) {
		a, aerr := actionOf(r)
		if aerr != nil {
			return nil, aerr
		}
		f.s.RevokeRole(a)
		return ok, nil
	})
	route("POST /roles/grant", func(r *http.Request) (any, *adminError) {
		a, aerr := actionOf(r)
		if aerr != nil {
			return nil, aerr
		}
		f.s.GrantRole(a)
		return ok, nil
	})
	route("POST /roles/set", func(r *http.Request) (any, *adminError) {
		given := r.URL.Query()["role"]
		for _, g := range given {
			if !contains(roles, g) {
				return nil, bad("unknown role %q (known: %s)", g, strings.Join(roles, ", "))
			}
		}
		f.s.SetRoles(given...)
		return ok, nil
	})
	route("POST /roles/grant-all", func(*http.Request) (any, *adminError) { f.s.GrantAllRoles(); return ok, nil })

	route("POST /fault", func(r *http.Request) (any, *adminError) {
		q := r.URL.Query()
		path := q.Get("path")
		if !strings.HasPrefix(path, "/") {
			return nil, bad("path must start with /")
		}
		status, err := strconv.Atoi(q.Get("status"))
		if err != nil || status < 400 || status > 599 {
			return nil, bad("status must be a number from 400 to 599")
		}
		ra, aerr := retryAfterOf(q.Get("retry_after"))
		if aerr != nil {
			return nil, aerr
		}
		times := 0
		if v := q.Get("times"); v != "" {
			if times, err = strconv.Atoi(v); err != nil || times < 0 || times > 100 {
				return nil, bad("times must be a number from 0 to 100 (0 = until unfault)")
			}
		}
		fault := fakekv.Fault{Status: status, RetryAfter: ra}
		if times == 0 {
			f.addStop(f.s.FailAll(path, fault))
		}
		for range times {
			f.s.FailNext(path, fault)
		}
		return ok, nil
	})
	route("POST /throttle", func(r *http.Request) (any, *adminError) {
		ra, aerr := retryAfterOf(r.URL.Query().Get("retry_after"))
		if aerr != nil {
			return nil, aerr
		}
		if ra == "" {
			ra = "7"
		}
		for _, p := range throttled {
			f.addStop(f.s.FailAll(p, fakekv.Fault{Status: http.StatusTooManyRequests, RetryAfter: ra}))
		}
		return ok, nil
	})
	route("POST /unfault", func(*http.Request) (any, *adminError) { f.unfault(); return ok, nil })
	route("POST /firewall", func(r *http.Request) (any, *adminError) {
		addr := r.URL.Query().Get("address")
		if addr == "off" {
			addr = ""
		} else if _, err := netip.ParseAddr(addr); err != nil {
			return nil, bad("address must be an IP address or off")
		}
		f.s.Firewall(addr)
		return ok, nil
	})
	route("POST /expire-secret", func(r *http.Request) (any, *adminError) {
		switch r.URL.Query().Get("on") {
		case "true":
			f.s.ExpireSecret()
		case "false":
			f.s.RestoreSecret()
		default:
			return nil, bad("expire-secret takes on or off")
		}
		return ok, nil
	})

	route("GET /requests", func(r *http.Request) (any, *adminError) {
		onlyAuth := r.URL.Query().Get("authenticated") == "true"
		vault := strings.TrimPrefix(f.s.VaultURL(), "https://")
		var count, login, vaultN int
		for _, req := range f.s.Requests() {
			if onlyAuth && !req.HadAuth {
				continue
			}
			count++
			switch req.Host {
			case loginHost:
				login++
			case vault:
				vaultN++
			}
		}
		return map[string]int{"count": count, "login": login, "vault": vaultN}, nil
	})
	route("POST /requests/clear", func(*http.Request) (any, *adminError) { f.s.ClearRequests(); return ok, nil })

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !ap.Addr().Unmap().IsLoopback() {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "the admin API answers loopback callers only"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
		mux.ServeHTTP(w, r)
	})
}

func (f *fake) credentials() map[string]string {
	return map[string]string{"tenant_id": f.s.TenantID(), "client_id": f.s.ClientID(), "client_secret": f.s.Secret(), "vault_url": f.s.VaultURL()}
}

func (f *fake) addStop(stop func()) {
	f.mu.Lock()
	f.stops = append(f.stops, stop)
	f.mu.Unlock()
}

func (f *fake) unfault() {
	f.mu.Lock()
	stops := f.stops
	f.stops = nil
	f.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

// certName validates the {name} of a route and that the certificate exists (the fake panics on an
// unknown name: the admin API never reaches that).
func (f *fake) certName(r *http.Request) (string, *adminError) {
	name := r.PathValue("name")
	if !nameRE.MatchString(name) {
		return "", bad("%q is not a valid object name", name)
	}
	if f.s.Versions(name) == nil {
		return "", notFound("no certificate named %s", name)
	}
	return name, nil
}

// versionOf validates a version ID of a certificate; empty is the newest (or, for leaf, "" = the
// current one, which fakekv reads as the newest enabled).
func (f *fake) versionOf(name, v string, newestWhenEmpty bool) (string, *adminError) {
	all := f.s.Versions(name)
	if v == "" {
		if newestWhenEmpty && len(all) > 0 {
			return all[len(all)-1], nil
		}
		return "", nil
	}
	if !versionRE.MatchString(v) || !contains(all, v) {
		return "", notFound("no such version of %s", name)
	}
	return v, nil
}

func actionOf(r *http.Request) (string, *adminError) {
	a := r.URL.Query().Get("action")
	if !contains(actions, a) {
		return "", bad("unknown action %q (known: %s)", a, strings.Join(actions, ", "))
	}
	return a, nil
}

func retryAfterOf(v string) (string, *adminError) {
	if v == "" {
		return "", nil
	}
	if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 3600 {
		return "", bad("retry-after must be a number of seconds from 0 to 3600")
	}
	return v, nil
}

func boolOf(v string, def bool) (bool, *adminError) {
	switch v {
	case "":
		return def, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, bad("%q is not true or false", v)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- ctl ----

// ctlCommand maps a ctl command to an admin request: its positionals (min, max), the flags it takes
// (true = takes a value) and the request it sends.
type ctlCommand struct {
	usage    string
	min, max int
	flags    map[string]bool
	request  func(pos []string, flags map[string]string) (method, path string, q url.Values)
}

var ctlCommands = map[string]ctlCommand{
	"ping":        {usage: "ping", request: simple(http.MethodGet, "/ping")},
	"credentials": {usage: "credentials", request: simple(http.MethodGet, "/credentials")},
	"reset":       {usage: "reset", request: simple(http.MethodPost, "/reset")},
	"renew":       {usage: "renew NAME", min: 1, max: 1, request: onCert(http.MethodPost, "renew")},
	"leaf": {usage: "leaf NAME [--version V]", min: 1, max: 1, flags: map[string]bool{"version": true},
		request: func(pos []string, fl map[string]string) (string, string, url.Values) {
			return http.MethodGet, "/certs/" + url.PathEscape(pos[0]) + "/leaf", url.Values{"version": {fl["version"]}}
		}},
	"add-cert": {usage: "add-cert NAME [--cn CN] [--exportable true|false]", min: 1, max: 1, flags: map[string]bool{"cn": true, "exportable": true},
		request: func(pos []string, fl map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/certs/" + url.PathEscape(pos[0]) + "/add", url.Values{"cn": {fl["cn"]}, "exportable": {fl["exportable"]}}
		}},
	"set-exportable": {usage: "set-exportable NAME true|false", min: 2, max: 2,
		request: func(pos []string, _ map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/certs/" + url.PathEscape(pos[0]) + "/exportable", url.Values{"value": {pos[1]}}
		}},
	"disable-version": {usage: "disable-version NAME [--version V]", min: 1, max: 1, flags: map[string]bool{"version": true}, request: onVersion("disable")},
	"enable-version":  {usage: "enable-version NAME [--version V]", min: 1, max: 1, flags: map[string]bool{"version": true}, request: onVersion("enable")},
	"delete":          {usage: "delete NAME", min: 1, max: 1, request: onCert(http.MethodPost, "delete")},
	"recover":         {usage: "recover NAME", min: 1, max: 1, request: onCert(http.MethodPost, "recover")},
	"revoke-role": {usage: "revoke-role ACTION", min: 1, max: 1,
		request: func(pos []string, _ map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/roles/revoke", url.Values{"action": {pos[0]}}
		}},
	"grant-role": {usage: "grant-role ACTION", min: 1, max: 1,
		request: func(pos []string, _ map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/roles/grant", url.Values{"action": {pos[0]}}
		}},
	"set-roles": {usage: "set-roles [ROLE...]", max: 3,
		request: func(pos []string, _ map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/roles/set", url.Values{"role": pos}
		}},
	"grant-all": {usage: "grant-all", request: simple(http.MethodPost, "/roles/grant-all")},
	"fault": {usage: "fault PATH STATUS [--retry-after SECONDS] [--times N]", min: 2, max: 2, flags: map[string]bool{"retry-after": true, "times": true},
		request: func(pos []string, fl map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/fault", url.Values{"path": {pos[0]}, "status": {pos[1]}, "retry_after": {fl["retry-after"]}, "times": {fl["times"]}}
		}},
	"throttle": {usage: "throttle [--retry-after SECONDS]", flags: map[string]bool{"retry-after": true},
		request: func(_ []string, fl map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/throttle", url.Values{"retry_after": {fl["retry-after"]}}
		}},
	"unfault": {usage: "unfault", request: simple(http.MethodPost, "/unfault")},
	"firewall": {usage: "firewall ADDRESS|off", min: 1, max: 1,
		request: func(pos []string, _ map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/firewall", url.Values{"address": {pos[0]}}
		}},
	"expire-secret": {usage: "expire-secret on|off", min: 1, max: 1,
		request: func(pos []string, _ map[string]string) (string, string, url.Values) {
			return http.MethodPost, "/expire-secret", url.Values{"on": {map[string]string{"on": "true", "off": "false"}[pos[0]]}}
		}},
	"requests": {usage: "requests [--authenticated]", flags: map[string]bool{"authenticated": false},
		request: func(_ []string, fl map[string]string) (string, string, url.Values) {
			return http.MethodGet, "/requests", url.Values{"authenticated": {strconv.FormatBool(fl["authenticated"] != "")}}
		}},
	"clear-requests": {usage: "clear-requests", request: simple(http.MethodPost, "/requests/clear")},
}

func simple(method, path string) func([]string, map[string]string) (string, string, url.Values) {
	return func([]string, map[string]string) (string, string, url.Values) { return method, path, nil }
}

func onCert(method, verb string) func([]string, map[string]string) (string, string, url.Values) {
	return func(pos []string, _ map[string]string) (string, string, url.Values) {
		return method, "/certs/" + url.PathEscape(pos[0]) + "/" + verb, nil
	}
}

func onVersion(verb string) func([]string, map[string]string) (string, string, url.Values) {
	return func(pos []string, fl map[string]string) (string, string, url.Values) {
		return http.MethodPost, "/certs/" + url.PathEscape(pos[0]) + "/" + verb, url.Values{"version": {fl["version"]}}
	}
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
	name := fs.Arg(0)
	cmd, found := ctlCommands[name]
	if !found {
		_, _ = fmt.Fprintf(stderr, "alice-fakeazure ctl: unknown command %q\n\n%s", name, usage)
		return 2
	}
	if err := checkLoopback(*adminAddr); err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeazure ctl: the admin address %v\n", err)
		return 2
	}
	pos, flags, err := parseCtl(cmd, fs.Args()[1:])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeazure ctl: %v\nusage: ctl %s\n", err, cmd.usage)
		return 1
	}
	method, path, q := cmd.request(pos, flags)
	target := url.URL{Scheme: "http", Host: *adminAddr, Path: path}
	if q != nil {
		target.RawQuery = q.Encode()
	}
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, target.String(), nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeazure ctl: %v\n", err)
		return 1
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req) //nolint:gosec // G704: the address was checked to be loopback above
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeazure ctl: the fake does not answer at %s: %v\n", *adminAddr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAdminBody))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "alice-fakeazure ctl: %v\n", err)
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
		_, _ = fmt.Fprintf(stderr, "alice-fakeazure ctl %s: %s\n", name, e.Error)
		return 1
	}
	_, _ = stdout.Write(body)
	return 0
}
