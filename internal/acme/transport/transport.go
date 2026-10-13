// Package transport is the only outbound HTTP client of ACME and DNS hooks: TLS 1.2+, system roots plus an
// optional CA bundle, every connection through netaddr, no environment proxy, no redirect, no keep-alive, https
// only (checked for every request URL, including URLs a CA returns), and answers cut at MaxResponseBytes.
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

// Options tunes a client; the zero value is the production setting.
type Options struct {
	// Dial replaces the netaddr dialer (tests only).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Timeout replaces the overall budget (tests only); zero means Timeout.
	Timeout time.Duration
}

// New builds the client. caPEM may be empty; otherwise its certificates are added to the system roots.
func New(caPEM string, o Options) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caPEM != "" && !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, ErrCABundle
	}
	budget := o.Timeout
	if budget <= 0 {
		budget = Timeout
	}
	dial := o.Dial
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
