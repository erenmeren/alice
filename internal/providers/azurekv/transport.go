package azurekv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"alice/internal/platform/azureid"
	"alice/internal/platform/netaddr"
)

var (
	errHostNotAllowed = errors.New("azurekv: request to a host this session may not reach")
	errRedirect       = errors.New("azurekv: Azure answered with a redirect")
	errBodyTooLarge   = errors.New("azurekv: Azure's answer is larger than Alice reads")
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// guardedTransport is the transport of one class of Azure traffic (R40 row 8, SEC-065, A-14, ruling
// S1): https to the hosts it was built for on port 443, the connect-time address rule, no redirect,
// no environment proxy, bounded bodies. A session builds two: the identity one (the Entra login
// host only) and the vault one (the session's own vault host only), so a token endpoint never
// receives vault traffic and a vault never makes Alice send its token or secret to the login host.
type guardedTransport struct {
	allowed map[string]bool // "host:443"
	tr      *http.Transport
	client  *http.Client
	// dialOverride replaces the dial in tests only (a DNS answer that cannot be had offline).
	dialOverride dialFunc
}

func newGuardedTransport(hosts []string, roots *x509.CertPool, dialAddr func(string) string) *guardedTransport {
	g := &guardedTransport{allowed: make(map[string]bool, len(hosts))}
	for _, h := range hosts {
		g.allowed[foldASCII(h)+":443"] = true
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	g.tr = &http.Transport{
		Proxy: nil, // never the environment's proxy (R40 row 7)
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if g.dialOverride != nil {
				return g.dialOverride(ctx, network, addr)
			}
			if dialAddr != nil {
				addr = dialAddr(addr)
			}
			return netaddr.DialContext(ctx, dialer, network, addr)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  TryTimeout,
		MaxResponseHeaderBytes: MaxHeaderBytes,
		ForceAttemptHTTP2:      true,
		MaxIdleConnsPerHost:    VaultConcurrency,
		IdleConnTimeout:        90 * time.Second,
	}
	g.client = &http.Client{Transport: g.tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return g
}

// Do implements policy.Transporter.
func (g *guardedTransport) Do(req *http.Request) (*http.Response, error) {
	st := wireOf(req.Context())
	st.begin(foldASCII(req.URL.Hostname()))
	if req.URL.Scheme != "https" || req.URL.User != nil || !g.allowed[hostPort(req.URL, "443")] ||
		(req.Host != "" && foldASCII(req.Host) != foldASCII(req.URL.Host)) {
		st.fail(wireHostNotAllowed)
		return nil, errHostNotAllowed
	}
	resp, err := g.client.Do(req) //nolint:gosec // G704: the host was checked against the session's allow-list above
	return finish(req, st, resp, err)
}

// CloseIdleConnections drops what the transport keeps open.
func (g *guardedTransport) CloseIdleConnections() { g.tr.CloseIdleConnections() }

// finish is the common tail of both transports: record, refuse redirects, cap the body.
func finish(req *http.Request, st *wireState, resp *http.Response, err error) (*http.Response, error) {
	if err != nil {
		if cerr := req.Context().Err(); cerr != nil {
			st.failCtx(cerr)
		} else {
			st.fail(kindOf(err))
		}
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		_ = resp.Body.Close()
		st.fail(wireRedirect)
		return nil, errRedirect
	}
	st.answered(resp.StatusCode, ownChallenge(resp.StatusCode, resp.Header))
	resp.Body = &cappedBody{rc: resp.Body, left: MaxBody, st: st}
	return resp, nil
}

// hostPort is the URL's folded host and port (def when the URL names none).
func hostPort(u *url.URL, def string) string {
	port := u.Port()
	if port == "" {
		port = def
	}
	return foldASCII(u.Hostname()) + ":" + port
}

// foldASCII lowercases ASCII letters only (strings.ToLower is banned in this repository).
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// imdsTransport is the managed identity's transport: http to 169.254.169.254:80 and nothing else.
// It is the single exception to the address rule (R40 row 4, ruling S11): its dialer accepts that
// one address, checked before any mapping, and it is used by no other code path.
type imdsTransport struct {
	tr     *http.Transport
	client *http.Client
}

func newIMDSTransport(dialAddr func(string) string) *imdsTransport {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	t := &imdsTransport{}
	t.tr = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != azureid.IMDSAddr {
				return nil, errHostNotAllowed
			}
			if dialAddr != nil {
				addr = dialAddr(addr)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ResponseHeaderTimeout:  TryTimeout,
		MaxResponseHeaderBytes: MaxHeaderBytes,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        30 * time.Second,
	}
	t.client = &http.Client{Transport: t.tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return t
}

// Do implements policy.Transporter.
func (t *imdsTransport) Do(req *http.Request) (*http.Response, error) {
	st := wireOf(req.Context())
	st.begin(foldASCII(req.URL.Hostname()))
	if req.URL.Scheme != "http" || req.URL.User != nil || hostPort(req.URL, "80") != azureid.IMDSAddr ||
		(req.Host != "" && foldASCII(req.Host) != foldASCII(req.URL.Host)) {
		st.fail(wireHostNotAllowed)
		return nil, errHostNotAllowed
	}
	resp, err := t.client.Do(req) //nolint:gosec // G704: scheme, host and port are pinned to the metadata endpoint above and in the dialer
	return finish(req, st, resp, err)
}

// CloseIdleConnections drops what the transport keeps open.
func (t *imdsTransport) CloseIdleConnections() { t.tr.CloseIdleConnections() }

// cappedBody reads at most MaxBody bytes and records how reading ended.
type cappedBody struct {
	rc   io.ReadCloser
	left int64
	st   *wireState
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.rc.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		c.st.fail(wireBodyTooLarge)
		return 0, errBodyTooLarge
	}
	if err != nil && !errors.Is(err, io.EOF) {
		c.st.fail(wireBodyRead)
	}
	return n, err
}

func (c *cappedBody) Close() error { return c.rc.Close() }
