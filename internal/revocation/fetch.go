package revocation

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"alice/internal/platform/netaddr"
)

// usableURL applies the URL rule (R64 Ruling 17): http or https, no user info, a host, and the scheme's own port.
func usableURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Hostname() == "" || strings.Contains(u.Host, "%") {
		return nil, false
	}
	switch port := u.Port(); u.Scheme {
	case "http":
		return u, port == "" || port == "80"
	case "https":
		return u, port == "" || port == "443"
	}
	return nil, false
}

// guardedDialer connects through netaddr's connect-time check (coordinator ruling C1), which also refuses loopback and
// unspecified addresses here: Alice's own host is never an authority's responder. resolver nil is the system's.
func guardedDialer(resolver *net.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: exchangeTimeout, Resolver: resolver}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return netaddr.DialContextExcept(ctx, d, network, addr, func(a netip.Addr) bool { return a.IsLoopback() || a.IsUnspecified() })
	}
}

// tlsConfig is TLS 1.2 or later with the system's roots.
func tlsConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }

// codeDeferred marks a request the run's budget for its host did not allow (not a code of a result).
const codeDeferred = "deferred"

// fetch makes one request of the run: it counts against the host's budget, and answers the body (at most limit bytes)
// or the closed code of the failure.
func (r *Run) fetch(ctx context.Context, method string, u *url.URL, body []byte, limit int64) ([]byte, string) {
	host := strings.Map(asciiLower, u.Hostname()) // one budget per host, whatever its case
	if r.spent[host] >= r.perHost {
		return nil, codeDeferred
	}
	r.spent[host]++
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, CodeUnreachable
	}
	req.Header.Set("User-Agent", userAgent)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/ocsp-request")
	}
	resp, err := r.c.client.Do(req)
	if err != nil {
		if errors.Is(err, netaddr.ErrNotAllowed) {
			return nil, CodeAddressRefused
		}
		return nil, CodeUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, CodeUnreachable // a redirect too: never followed
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	switch {
	case err != nil:
		return nil, CodeUnreachable
	case int64(len(data)) > limit:
		return nil, CodeTooLarge
	}
	return data, ""
}

// failed is the result of a fetch that answered code.
func failed(code string) Result {
	if code == codeDeferred {
		return Result{Status: StatusDeferred}
	}
	return Result{Status: StatusUnavailable, Code: code}
}

// asciiLower folds an ASCII upper-case letter (a host name's case does not matter; no other letter is touched).
func asciiLower(r rune) rune {
	if 'A' <= r && r <= 'Z' {
		return r + 'a' - 'A'
	}
	return r
}
