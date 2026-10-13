// Package transport is the only outbound HTTP client of ACME and DNS hooks: TLS 1.2+, system roots plus an
// optional CA bundle, every connection through netaddr, no environment proxy, no redirect, no keep-alive, https
// only (checked for every request URL, including URLs a CA returns), and answers cut at MaxResponseBytes.
//
// Callers must treat every non-2xx and every 3xx answer as a failure (redirects are returned, never followed),
// and must never log a url.Error raw: it carries the full request URL including the query string.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"alice/internal/platform/netaddr"
)

const (
	// MaxResponseBytes is the largest answer body one response may have.
	MaxResponseBytes = 1 << 20
	// Timeout is the budget of one whole exchange.
	Timeout = 30 * time.Second
)

var (
	// ErrCABundle is a CA bundle without a usable certificate (mapped to ALC-ACM-0013 by the caller).
	ErrCABundle = errors.New("acme transport: the CA bundle has no certificate")
	// ErrURLRefused is a request URL that is not plain https without credentials.
	ErrURLRefused = errors.New("acme transport: only https URLs without credentials are allowed")
	// ErrTooLarge is an answer body over MaxResponseBytes.
	ErrTooLarge = errors.New("acme transport: the answer is too large")
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// New builds the client. caPEM may be empty; otherwise its certificates are added to the system roots. There is
// no exported way to replace the dialer or the budget: every connection goes through netaddr.
func New(caPEM string) (*http.Client, error) { return build(caPEM, nil, nil, 0) }

// NewWithRoots is New with base instead of the system roots (nil means the system roots): the e2e build's trust
// of its fake CA (cmd/alice acmeRoots). base is not changed: caPEM is added to a copy.
func NewWithRoots(caPEM string, base *x509.CertPool) (*http.Client, error) {
	return build(caPEM, base, nil, 0)
}

// build is New with the test seams: dial (nil means netaddr) and budget (zero means Timeout).
func build(caPEM string, base *x509.CertPool, dial dialFunc, budget time.Duration) (*http.Client, error) {
	var roots *x509.CertPool
	if base != nil {
		roots = base.Clone()
	} else if sys, err := x509.SystemCertPool(); err == nil && sys != nil {
		roots = sys
	} else {
		roots = x509.NewCertPool()
	}
	if caPEM != "" && !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, ErrCABundle
	}
	if budget <= 0 {
		budget = Timeout
	}
	if dial == nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netaddr.DialContext(ctx, &net.Dialer{Timeout: budget}, network, addr)
		}
	}
	tr := &http.Transport{DialContext: dial, Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSHandshakeTimeout: budget, ResponseHeaderTimeout: budget, MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	return &http.Client{
		Transport:     roundTripper{next: tr},
		Timeout:       budget,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

type roundTripper struct{ next http.RoundTripper }

func (r roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Host == "" {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, ErrURLRefused
	}
	res, err := r.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	res.Body = &limitedBody{r: io.LimitReader(res.Body, MaxResponseBytes+1), c: res.Body}
	return res, nil
}

type limitedBody struct {
	r io.Reader
	c io.Closer
	n int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += int64(n)
	if b.n > MaxResponseBytes {
		return 0, ErrTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.c.Close() }
