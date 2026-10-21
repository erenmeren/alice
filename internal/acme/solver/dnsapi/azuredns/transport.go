package azuredns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"alice/internal/acme/solver/dnsapi"
	"alice/internal/platform/azureid"
)

// errIMDSOnly is a request of the managed identity's transport to anything but the metadata endpoint.
var errIMDSOnly = errors.New("azuredns: the managed identity reaches the metadata endpoint only")

// imdsTransport is the managed identity's transport: http to 169.254.169.254:80 and nothing else. It is the one
// exception to the netaddr rule (the address is link-local by design): its dialer accepts that one address, checked
// before any mapping, and no other code path uses it. No proxy, no redirect, bounded headers and body.
type imdsTransport struct {
	client *http.Client
}

func newIMDSTransport(mapAddr func(string) string) *imdsTransport {
	if mapAddr == nil {
		mapAddr = dnsapi.TestMappedAddr // the integration seam's mapping; the address itself in every other build
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != azureid.IMDSAddr {
				return nil, errIMDSOnly
			}
			return dialer.DialContext(ctx, network, mapAddr(addr))
		},
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  dnsapi.RequestTimeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &imdsTransport{client: &http.Client{
		Transport:     tr,
		Timeout:       dnsapi.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Do implements policy.Transporter.
func (t *imdsTransport) Do(req *http.Request) (*http.Response, error) {
	u := req.URL
	port := u.Port()
	if port == "" {
		port = "80"
	}
	if u.Scheme != "http" || u.User != nil || foldASCII(u.Hostname())+":"+port != azureid.IMDSAddr ||
		(req.Host != "" && foldASCII(req.Host) != foldASCII(u.Host)) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errIMDSOnly
	}
	res, err := t.client.Do(req) //nolint:gosec // G704: scheme, host and port are pinned to the metadata endpoint above and in the dialer
	if err != nil {
		return nil, err
	}
	res.Body = &cappedBody{rc: res.Body, left: dnsapi.MaxResponseBytes}
	return res, nil
}

type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.rc.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return 0, dnsapi.ErrTooLarge
	}
	return n, err
}

func (c *cappedBody) Close() error { return c.rc.Close() }
