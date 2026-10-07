package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"

	"alice/internal/platform/netaddr"
)

var (
	errTooLarge = errors.New("oidc: the identity provider's answer is too large")
	errCABundle = errors.New("oidc: the CA bundle has no certificate")
)

// httpClient is the client of one provider (SEC-013, A-14, R42 row 11): TLS 1.2+, the system roots plus the
// provider's CA bundle, every connection through netaddr, no proxy, no redirect, a 10-second budget, and answers cut
// at MaxResponseBytes.
func (s *Service) httpClient(caPEM string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caPEM != "" && !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errCABundle
	}
	dial := s.dial
	if dial == nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netaddr.DialContext(ctx, &net.Dialer{Timeout: HTTPTimeout}, network, addr)
		}
	}
	tr := &http.Transport{DialContext: dial, Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: HTTPTimeout,
		ResponseHeaderTimeout: HTTPTimeout, MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	return limitedClient(&http.Client{Transport: tr, Timeout: HTTPTimeout}), nil
}

// limitedClient refuses redirects and bounds every answer body.
func limitedClient(c *http.Client) *http.Client {
	next := c.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	out := *c
	out.Transport = limitTransport{next: next}
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &out
}

type limitTransport struct{ next http.RoundTripper }

func (l limitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := l.next.RoundTrip(r)
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
		return 0, errTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.c.Close() }
