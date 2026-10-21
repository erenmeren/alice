package lestaging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"alice/internal/acme/solver"
	"alice/internal/acme/solver/dns01"
	"alice/internal/acme/solver/http01"
	"alice/internal/secrets"
)

// DNSParams is what a DNS-01 provider is built from.
type DNSParams struct {
	// Domain is the base name of the order (the wildcard shares its record name).
	Domain string
	// Getenv reads the provider's own ALICE_LE_DNS_* variables.
	Getenv func(string) string
	// Out is the report's writer (the manual provider prints its instructions there).
	Out io.Writer
}

// DNSProvider builds the DNS-01 solver of a run. The solver must clean up exactly the value it presented (the
// contract of internal/acme/solver).
type DNSProvider func(p DNSParams) (solver.Solver, error)

var (
	dnsMu        sync.Mutex
	dnsProviders = map[string]DNSProvider{"hook": hookProvider, "manual": manualProvider}
)

// RegisterDNSProvider is the extension point for Alice's built-in DNS providers (R57): each one registers the
// solver.Solver it builds under its name (ALICE_LE_DNS_PROVIDER=<name>), reading its credentials from its own
// ALICE_LE_DNS_<NAME>_* variables through DNSParams.Getenv. Call it from an init function of a file of this package.
// It panics on an empty or duplicate name.
func RegisterDNSProvider(name string, p DNSProvider) {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	if name == "" || p == nil || dnsProviders[name] != nil {
		panic("lestaging: DNS provider " + name + " is empty or registered twice")
	}
	dnsProviders[name] = p
}

// DNSProviders lists the registered providers.
func DNSProviders() []string {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	out := make([]string, 0, len(dnsProviders))
	for n := range dnsProviders {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func dnsProvider(name string) (DNSProvider, bool) {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	p, ok := dnsProviders[name]
	return p, ok
}

// hookProvider is Alice's DNS hook (internal/acme/solver/dns01, the wire contract of the admin guide).
func hookProvider(p DNSParams) (solver.Solver, error) {
	get := func(k string) string { return strings.TrimSpace(p.Getenv(k)) }
	cfg := dns01.Config{URL: get(EnvDNSHookURL), AllowedSuffixes: []string{p.Domain}}
	secret := get(EnvDNSHookSecret)
	if cfg.URL == "" || secret == "" {
		return nil, fmt.Errorf("lestaging: the hook needs %s and %s", EnvDNSHookURL, EnvDNSHookSecret)
	}
	cfg.Secret = secrets.NewPlaintext([]byte(secret))
	if f := get(EnvDNSHookCAFile); f != "" {
		b, err := os.ReadFile(f) //nolint:gosec // a file the person named
		if err != nil {
			return nil, fmt.Errorf("lestaging: %s: %w", EnvDNSHookCAFile, err)
		}
		cfg.CABundlePEM = string(b)
	}
	wait, err := durationEnv(p.Getenv, EnvDNSWait, dns01.DefaultPropagationWait)
	if err != nil {
		return nil, err
	}
	if wait == 0 {
		wait = -1 // dns01: a negative wait is none, zero the default
	}
	cfg.PropagationWait = wait
	if cfg.PollTimeout, err = durationEnv(p.Getenv, EnvDNSPollTimeout, dns01.DefaultPollTimeout); err != nil {
		return nil, err
	}
	s, err := dns01.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("lestaging: the DNS hook settings: %w", err)
	}
	return s, nil
}

// manualProvider prints the TXT record for a person to add, then waits until a resolver sees it.
func manualProvider(p DNSParams) (solver.Solver, error) {
	wait, err := durationEnv(p.Getenv, EnvDNSManualWait, DefaultManualTimeout)
	if err != nil {
		return nil, err
	}
	r := net.DefaultResolver
	if addr := strings.TrimSpace(p.Getenv(EnvDNSResolver)); addr != "" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("lestaging: %s must be host:port, for example 1.1.1.1:53", EnvDNSResolver)
		}
		d := &net.Dialer{Timeout: 5 * time.Second}
		r = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}}
	}
	return &manualSolver{out: p.Out, timeout: wait, interval: 10 * time.Second, lookup: r.LookupTXT, sleep: sleepCtx}, nil
}

// ErrRecordNotVisible is the manual provider's failure: the TXT value never appeared.
var ErrRecordNotVisible = errors.New("lestaging: the TXT record did not become visible in time")

type manualSolver struct {
	out      io.Writer
	timeout  time.Duration
	interval time.Duration
	lookup   func(ctx context.Context, name string) ([]string, error)
	sleep    func(context.Context, time.Duration) error
}

func (*manualSolver) Types() []string { return []string{solver.DNS01} }

func (m *manualSolver) Present(ctx context.Context, ch solver.Challenge) error {
	_, _ = fmt.Fprintf(m.out, "\n  ACTION: add this TXT record now (keep any other value of the same name):\n"+
		"          %s.  TXT  \"%s\"\n  waiting up to %s for it to be visible ...\n", ch.DNSName, ch.DNSValue, m.timeout)
	deadline := time.Duration(0)
	for {
		vals, _ := m.lookup(ctx, ch.DNSName)
		if slices.Contains(vals, ch.DNSValue) {
			_, _ = fmt.Fprintf(m.out, "  seen %s; asking the CA to check\n", ch.DNSName)
			return nil
		}
		if deadline >= m.timeout {
			return ErrRecordNotVisible
		}
		if err := m.sleep(ctx, m.interval); err != nil {
			return err
		}
		deadline += m.interval
	}
}

func (m *manualSolver) CleanUp(_ context.Context, ch solver.Challenge) error {
	_, _ = fmt.Fprintf(m.out, "  ACTION: you may remove the TXT record %s with value \"%s\" now\n", ch.DNSName, ch.DNSValue)
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// listenPublisher is the HTTP-01 publisher of a host without a web server: it serves the token files itself.
type listenPublisher struct {
	mu     sync.Mutex
	tokens map[string][]byte
	srv    *http.Server
	ln     net.Listener
}

func newListenPublisher(addr string) (*listenPublisher, error) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("lestaging: cannot listen on %s for HTTP-01 (port 80 needs root or "+
			"net.ipv4.ip_unprivileged_port_start; or set %s): %w", addr, EnvHTTP01Webroot, err)
	}
	p := &listenPublisher{tokens: map[string][]byte{}, ln: ln}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

// Addr is the listener's address.
func (p *listenPublisher) Addr() string { return p.ln.Addr().String() }

func (p *listenPublisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.URL.Path, solver.HTTPPathPrefix)
	p.mu.Lock()
	body, found := p.tokens[tok]
	p.mu.Unlock()
	if r.Method != http.MethodGet || !ok || !found {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(body)
}

func (p *listenPublisher) PublishHTTP01Token(_ context.Context, token string, keyAuth []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[token] = append([]byte(nil), keyAuth...)
	return nil
}

func (p *listenPublisher) RemoveHTTP01Token(_ context.Context, token string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.tokens[token]
	delete(p.tokens, token)
	return ok, nil
}

func (p *listenPublisher) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.srv.Shutdown(ctx)
}

// webrootPublisher writes the token files below the document root of a web server that already answers on port
// 80: <root>/.well-known/acme-challenge/<token> (the certbot webroot layout).
type webrootPublisher struct{ dir string }

func newWebrootPublisher(root string) (*webrootPublisher, error) {
	dir := filepath.Join(root, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // the web server must read it
		return nil, fmt.Errorf("lestaging: %s: %w", EnvHTTP01Webroot, err)
	}
	return &webrootPublisher{dir: dir}, nil
}

func (p *webrootPublisher) PublishHTTP01Token(_ context.Context, token string, keyAuth []byte) error {
	return os.WriteFile(filepath.Join(p.dir, filepath.Base(token)), keyAuth, 0o644) //nolint:gosec // public by design
}

func (p *webrootPublisher) RemoveHTTP01Token(_ context.Context, token string) (bool, error) {
	err := os.Remove(filepath.Join(p.dir, filepath.Base(token)))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (*webrootPublisher) Close() error { return nil }

type publisher interface {
	http01.Publisher
	Close() error
}

// buildSolver makes the run's solver and what closes it.
func (r *Runner) buildSolver() (solver.Solver, func(), error) {
	if r.cfg.Challenge == solver.DNS01 {
		p, ok := dnsProvider(r.cfg.DNSProvider)
		if !ok {
			return nil, nil, fmt.Errorf("lestaging: unknown DNS provider %q", r.cfg.DNSProvider)
		}
		getenv := r.cfg.Getenv
		if getenv == nil {
			getenv = func(string) string { return "" }
		}
		s, err := p(DNSParams{Domain: r.cfg.Domain, Getenv: getenv, Out: r.out})
		return s, func() {}, err
	}
	var (
		pub publisher
		err error
	)
	if r.cfg.HTTP01Webroot != "" {
		pub, err = newWebrootPublisher(r.cfg.HTTP01Webroot)
	} else {
		var lp *listenPublisher
		lp, err = newListenPublisher(r.cfg.HTTP01Listen)
		if err == nil {
			pub = lp
			if r.onListen != nil {
				r.onListen(lp.Addr())
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}
	s, err := http01.New(http01.Config{Publisher: pub, AllowedSuffixes: []string{r.cfg.Domain}})
	if err != nil {
		_ = pub.Close()
		return nil, nil, err
	}
	if r.http01Seam != nil {
		r.http01Seam(s)
	}
	return s, func() { _ = pub.Close() }, nil
}
