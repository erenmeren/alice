package dnsapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"alice/internal/acme"
	"alice/internal/platform/netaddr"
)

// Limits of one provider exchange.
const (
	// MaxResponseBytes is the largest answer body Alice reads from a DNS provider.
	MaxResponseBytes = 1 << 20
	// RequestTimeout is the budget of one exchange.
	RequestTimeout = 30 * time.Second
	// UserAgent is sent with every request.
	UserAgent = "alice-acme/1"
)

var (
	// ErrHostNotAllowed is the cause of a request to a host the provider's client may not reach.
	ErrHostNotAllowed = errors.New("dnsapi: request to a host this provider may not reach")
	// ErrTooLarge is an answer body over MaxResponseBytes.
	ErrTooLarge = errors.New("dnsapi: the answer is too large")
	// ErrMapNeedsRoots refuses an address mapping without explicit roots (a mapped dial never trusts the system roots).
	ErrMapNeedsRoots = errors.New("dnsapi: an address mapping needs explicit roots")
)

// HTTPOptions configures NewHTTPClient.
type HTTPOptions struct {
	// Hosts are the only host names the client sends a request to (port 443, https).
	Hosts []string
	// Roots replaces the system roots when set (the e2e build's trust of its fake services; nil in a release build).
	Roots *x509.CertPool
	// MapAddr, when set, changes the "host:port" a connection goes to (the in-process fakes of the tests). The
	// mapped address still passes the netaddr rule, the request still names its real host, and the TLS handshake
	// still verifies that name, against Roots, which must then be set.
	MapAddr func(hostport string) string
}

// testMapAddr is the address mapping of the integration seam (seam_integration.go); nil in every other build.
var testMapAddr atomic.Pointer[func(string) string]

// TestMappedAddr is the integration seam's mapping of hostport (hostport itself when no mapping is set, which is
// always the case outside integration builds). Only a transport that cannot use NewHTTPClient calls it: the Azure
// managed identity's metadata endpoint, which the netaddr rule refuses by design.
func TestMappedAddr(hostport string) string {
	if f := testMapAddr.Load(); f != nil {
		return (*f)(hostport)
	}
	return hostport
}

// NewHTTPClient builds the client of one provider: https to its fixed hosts on port 443 only, TLS 1.2 or later,
// every connection through netaddr, no environment proxy, no redirect, answers cut at MaxResponseBytes and one
// RequestTimeout per exchange.
func NewHTTPClient(o HTTPOptions) (*http.Client, error) {
	mapAddr := o.MapAddr
	if mapAddr == nil {
		if f := testMapAddr.Load(); f != nil {
			mapAddr = *f
		}
	}
	if mapAddr != nil && o.Roots == nil {
		return nil, ErrMapNeedsRoots
	}
	roots := o.Roots
	if roots == nil {
		sys, err := x509.SystemCertPool()
		if err != nil || sys == nil {
			sys = x509.NewCertPool()
		}
		roots = sys
	}
	allowed := make(map[string]bool, len(o.Hosts))
	for _, h := range o.Hosts {
		allowed[asciiLower(h)] = true
	}
	dialer := &net.Dialer{Timeout: RequestTimeout}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if mapAddr != nil {
				addr = mapAddr(addr)
			}
			return netaddr.DialContext(ctx, dialer, network, addr)
		},
		ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSHandshakeTimeout: RequestTimeout,
		ResponseHeaderTimeout: RequestTimeout, MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
	}
	return &http.Client{
		Transport:     guard{next: tr, allowed: allowed},
		Timeout:       RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

type guard struct {
	next    http.RoundTripper
	allowed map[string]bool
}

func (g guard) RoundTrip(req *http.Request) (*http.Response, error) {
	u := req.URL
	port := u.Port()
	if u.Scheme != "https" || u.User != nil || !g.allowed[asciiLower(u.Hostname())] || (port != "" && port != "443") ||
		(req.Host != "" && asciiLower(req.Host) != asciiLower(u.Host)) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, ErrHostNotAllowed
	}
	res, err := g.next.RoundTrip(req)
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

// Do sends req with client and returns the answer's status and body (at most MaxResponseBytes). A request that got
// no answer is acme.DNSProviderError(identifier, 0, true) (a dead ctx is ctx.Err()); the error never carries the
// request URL (a *url.Error does) or the answer. A redirect is answered as its status: the caller refuses it.
func Do(ctx context.Context, client *http.Client, req *http.Request, identifier string) (int, http.Header, []byte, error) {
	req = req.WithContext(ctx)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	res, err := client.Do(req) //nolint:gosec // G704: the client's guard admits the provider's fixed hosts only
	if err != nil {
		if ce := ctx.Err(); ce != nil {
			return 0, nil, nil, ce
		}
		return 0, nil, nil, acme.DNSProviderError(identifier, 0, !errors.Is(err, ErrHostNotAllowed))
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		if ce := ctx.Err(); ce != nil {
			return 0, nil, nil, ce
		}
		return 0, nil, nil, acme.DNSProviderError(identifier, res.StatusCode, !errors.Is(err, ErrTooLarge))
	}
	return res.StatusCode, res.Header, body, nil
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
