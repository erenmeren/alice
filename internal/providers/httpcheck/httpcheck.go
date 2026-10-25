// Package httpcheck is the canary's HTTPS application check (R65, design
// docs/superpowers/specs/2026-10-24-canary-deployment-design.md §9.3, §20.1): one GET from Alice to a managed server,
// through the deployed certificate, whose status is compared with the expected ones.
//
// The address dialed is always the caller's (the location's verification address or its server's host, never the
// policy's host name), through netaddr.DialContext: the SEC-065 rule on the connected address. The TLS handshake trusts
// nothing and compares the served leaf with the deployed one before a single request byte is sent; chain trust is the
// TLS baseline's job. No proxy, no redirects, no cookies, no credentials, keep-alives off, a 16 KiB header cap, a
// 64 KiB body read cap and one timeout for the whole request. The response body is never kept.
package httpcheck

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
)

// The reasons of a failed check (UI texts, design §17.2).
const (
	ReasonHTTPStatus  = "canary.http_status"
	ReasonServedOther = "canary.served_other"
	ReasonUnreachable = "canary.unreachable"
	ReasonNotAllowed  = "canary.not_allowed"
	ReasonTimeout     = "canary.timeout"
	ReasonProtocol    = "canary.protocol"
)

// Bounds of one check (design §9.3).
const (
	MaxHeaderBytes   = 16 << 10
	MaxBodyBytes     = 64 << 10
	maxDialTimeout   = 5 * time.Second
	defaultTimeout   = 5 * time.Second
	defaultStatusOK  = http.StatusOK
	defaultUserAgent = "Alice-canary"
)

// Request is one check: where to connect (Address, Port), what to name (ServerName: the TLS server name and the Host
// header, "" for none and then Host is Address), what to ask (Path, the request target with its query) and what passes
// (ExpectStatus, nil = 200; the served leaf's SHA-256 must be ExpectLeafSHA256). Timeout bounds the whole request
// (zero = 5 s).
type Request struct {
	Address          string
	Port             int
	ServerName       string
	Path             string
	ExpectStatus     []int
	Timeout          time.Duration
	ExpectLeafSHA256 string
	UserAgent        string
}

// Result is the outcome of one check: OK, or the Reason it failed; the status when a response arrived, the time the
// check took and the SHA-256 of the leaf served when a handshake completed.
type Result struct {
	OK           bool
	Reason       string
	HTTPStatus   int
	LatencyMS    int
	ServedSHA256 string
}

// Checker runs one check (the canary job's seam).
type Checker interface {
	Check(ctx context.Context, r Request) Result
}

// HTTPChecker is the Checker of the product. Clock measures the latency (nil = the real clock); Resolver resolves an
// Address that is a name (nil = the system's; tests set it). The address rule applies to whatever it answers.
type HTTPChecker struct {
	Clock    clock.Clock
	Resolver *net.Resolver
}

var _ Checker = HTTPChecker{}

var errServedOther = errors.New("httpcheck: the served certificate is not the deployed one")

// Check runs r. It never panics and never answers OK without a response whose status is expected, served through the
// expected leaf.
func (c HTTPChecker) Check(ctx context.Context, r Request) Result {
	clk := c.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	start := clk.Now()
	res := c.check(ctx, r)
	res.LatencyMS = max(0, int(clk.Now().Sub(start)/time.Millisecond))
	return res
}

func (c HTTPChecker) check(ctx context.Context, r Request) Result {
	var res Result
	if r.Port < 1 || r.Port > 65535 {
		res.Reason = ReasonUnreachable
		return res
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var served atomic.Value // string: the leaf's SHA-256 once a handshake presented one
	var connected atomic.Bool
	target := net.JoinHostPort(r.Address, strconv.Itoa(r.Port))
	tr := &http.Transport{
		Proxy: nil, // never the environment's: the destination is a managed server (decision 13)
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := netaddr.DialContext(ctx, &net.Dialer{Timeout: min(timeout, maxDialTimeout), Resolver: c.Resolver}, "tcp", target)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{
				ServerName:             r.ServerName,
				InsecureSkipVerify:     true, //nolint:gosec // the leaf is compared below; chain trust is the TLS baseline's job (design §9.3)
				MinVersion:             tls.VersionTLS12,
				NextProtos:             []string{"http/1.1"},
				SessionTicketsDisabled: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errServedOther
					}
					sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
					got := hex.EncodeToString(sum[:])
					served.Store(got)
					if !strings.EqualFold(got, r.ExpectLeafSHA256) {
						return errServedOther
					}
					return nil
				},
			})
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			connected.Store(true)
			return tc, nil
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: MaxHeaderBytes,
		ForceAttemptHTTP2:      false,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	hreq, err := newRequest(ctx, r)
	if err != nil {
		res.Reason = ReasonProtocol
		return res
	}
	resp, err := client.Do(hreq)
	if s, ok := served.Load().(string); ok {
		res.ServedSHA256 = s
	}
	if err != nil {
		res.Reason = classify(ctx, err, connected.Load())
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	res.HTTPStatus = resp.StatusCode
	if res.Reason = readBody(ctx, resp.Body); res.Reason != "" {
		return res
	}
	expect := r.ExpectStatus
	if len(expect) == 0 {
		expect = []int{defaultStatusOK}
	}
	if !slices.Contains(expect, resp.StatusCode) {
		res.Reason = ReasonHTTPStatus
		return res
	}
	res.OK = true
	return res
}

// readBody reads at most MaxBodyBytes of the body and discards it; it answers the failure's reason ("" for none). A
// deadline that ended the body is a timeout even when the read reports a clean end: the transport may close the
// connection under the read (seen on CI with a slow-loris server); a check that outlived its timeout never passes.
func readBody(ctx context.Context, body io.Reader) string {
	if _, err := io.Copy(io.Discard, io.LimitReader(body, MaxBodyBytes)); err != nil {
		return classify(ctx, err, true)
	}
	if ctx.Err() != nil {
		return ReasonTimeout
	}
	return ""
}

// newRequest builds the GET: the target exactly as given, Host the server name (or the address), no credentials.
func newRequest(ctx context.Context, r Request) (*http.Request, error) {
	u, err := url.ParseRequestURI(r.Path)
	if err != nil || !strings.HasPrefix(r.Path, "/") {
		return nil, errors.New("httpcheck: not a request target")
	}
	host := r.ServerName
	if host == "" {
		host = r.Address
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	u.Scheme, u.Host = "https", host
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	hreq.Host = host
	hreq.Close = true
	ua := r.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	hreq.Header.Set("User-Agent", ua)
	hreq.Header.Set("Accept", "*/*")
	return hreq, nil
}

// classify names the reason of a failed request: the address rule, the leaf compare, the timeout (the context's or a
// network one), a failure before the TLS connection was up (unreachable) or after it (protocol).
func classify(ctx context.Context, err error, connected bool) string {
	var ne net.Error
	switch {
	case errors.Is(err, netaddr.ErrNotAllowed):
		return ReasonNotAllowed
	case errors.Is(err, errServedOther):
		return ReasonServedOther
	case ctx.Err() != nil, errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ReasonTimeout
	case !connected:
		return ReasonUnreachable
	}
	return ReasonProtocol
}
