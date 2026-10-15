// Command vendor-web is the sales web page of the vendor console (design spec
// 2026-10-15-vendor-console-design.md). It holds no signing key and connects to PostgreSQL as the
// vendor_web login. It never ships to customers; the alice binary must not link it.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/vconsole/store"
	"alice/internal/vconsole/web"
)

const (
	dbEnv     = "VENDOR_WEB_DATABASE_URL"
	originEnv = "VENDOR_WEB_ORIGIN"
	rpidEnv   = "VENDOR_WEB_RPID"
)

const usage = `Usage: vendor-web [--listen :8443] [--tls-cert FILE --tls-key FILE]
                  [--trusted-proxy CIDR]...

--trusted-proxy CIDR (repeatable): reverse proxy range whose X-Forwarded-For is believed for the
rate limit; without it every client behind a proxy shares the proxy's limit.

Environment:
  VENDOR_WEB_DATABASE_URL  PostgreSQL connection string of the vendor_web login (sslmode=verify-full
                           unless the database is on this computer)
  VENDOR_WEB_ORIGIN        public address, e.g. https://licenses.example.com (http only for localhost)
  VENDOR_WEB_RPID          passkey domain (default: the host of the origin)
`

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// config is a validated configuration.
type config struct {
	dbURL, origin, rpid string
	listen              string
	certFile, keyFile   string
	cert                *tls.Certificate // loaded from certFile and keyFile; nil for plain http
	trustedProxies      []netip.Prefix
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run validates the configuration and then starts the server through serve. Every configuration
// error ends with exit code 2 before any socket or database connection is opened.
func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "vendor-web: "+format+"\n", a...)
		return 2
	}
	fs := flag.NewFlagSet("vendor-web", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = fmt.Fprint(stderr, usage) }
	listen := fs.String("listen", ":8443", "address to listen on")
	certFile := fs.String("tls-cert", "", "TLS certificate file (with --tls-key)")
	keyFile := fs.String("tls-key", "", "TLS key file (with --tls-cert)")
	var proxies stringList
	fs.Var(&proxies, "trusted-proxy", "reverse proxy CIDR whose X-Forwarded-For is trusted for the rate limit (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		return fail("unexpected argument %q", fs.Arg(0))
	}
	if (*certFile == "") != (*keyFile == "") {
		if *certFile == "" {
			return fail("--tls-key needs --tls-cert too")
		}
		return fail("--tls-cert needs --tls-key too")
	}
	trusted, err := web.ParseTrustedProxies(proxies)
	if err != nil {
		return fail("--trusted-proxy: %v", err)
	}
	c := config{trustedProxies: trusted, dbURL: getenv(dbEnv), origin: getenv(originEnv), rpid: getenv(rpidEnv),
		listen: *listen, certFile: *certFile, keyFile: *keyFile}
	if c.dbURL == "" {
		return fail("set %s to the PostgreSQL connection string", dbEnv)
	}
	if err := store.RequireTLSVerification(c.dbURL, dbEnv); err != nil {
		return fail("%v", err)
	}
	if c.origin == "" {
		return fail("set %s to the public address, e.g. https://licenses.example.com", originEnv)
	}
	if c.rpid == "" {
		u, err := url.Parse(c.origin)
		if err != nil || u.Hostname() == "" {
			return fail("%s %q is not a valid address", originEnv, c.origin)
		}
		c.rpid = u.Hostname()
	}
	// Validate origin and RP ID now; the pool is not needed for that.
	if _, err := web.New(web.Config{RPID: c.rpid, Origin: c.origin, TrustedProxies: c.trustedProxies}); err != nil {
		return fail("%v", err)
	}
	if c.certFile != "" {
		// Load the pair now so a bad file is a configuration error. The library's error names
		// the problem, never the file contents.
		cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			return fail("cannot load the TLS certificate and key (--tls-cert %s, --tls-key %s): %v", c.certFile, c.keyFile, err)
		}
		c.cert = &cert
	} else if !httpOrigin(c.origin) {
		_, _ = fmt.Fprintln(stderr, "vendor-web: note: serving plain http; the https origin must be terminated by a proxy in front")
	}
	return serve(c, stdout, stderr)
}

func httpOrigin(origin string) bool {
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "http"
}

// serve is replaced in tests.
var serve = serveReal

func serveReal(c config, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	openCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	pool, err := db.Open(openCtx, c.dbURL)
	cancel()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "vendor-web: %v\n", err) // db.Open errors never include the URL
		return 1
	}
	defer pool.Close()
	srv, err := web.New(web.Config{Pool: pool, RPID: c.rpid, Origin: c.origin, Clock: clock.Real{}, TrustedProxies: c.trustedProxies})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "vendor-web: %v\n", err)
		return 2
	}
	hs := &http.Server{
		Addr:              c.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if c.cert != nil {
		hs.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*c.cert}, MinVersion: tls.VersionTLS12}
	}
	// Listen first, so "listening on" is printed only once the port is ours.
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", c.listen)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "vendor-web: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "vendor-web: listening on %s for %s\n", ln.Addr(), c.origin)
	errc := make(chan error, 1)
	go func() {
		if c.cert != nil {
			errc <- hs.ServeTLS(ln, "", "") // the certificate is in TLSConfig
		} else {
			errc <- hs.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		_, _ = fmt.Fprintf(stderr, "vendor-web: %v\n", err)
		return 1
	case <-ctx.Done():
	}
	stop() // restore default signal handling: a second Ctrl-C ends the process at once
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		_, _ = fmt.Fprintf(stderr, "vendor-web: shutdown: %v\n", err)
		return 1
	}
	return 0
}
