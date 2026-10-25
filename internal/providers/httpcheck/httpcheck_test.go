package httpcheck_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr/netaddrtest"
	"alice/internal/providers/httpcheck"
)

// Ports of this package's local servers: each is the port the system chose when its server started (listen), so no
// fixed port meets another process's connection on CI (a fixed port in the ephemeral range collided once, R65).
var (
	portMain      int
	portRedirect  int
	portOther     int
	portHeaders   int
	portSilent    int
	portSlow      int
	portHuge      int
	portBigHeader int
	portPlain     int
	portProxy     int
	portRefused   int
)

// listen opens a listener on 127.0.0.1 at a port the system chooses and records the port in *port.
func listen(t *testing.T, port *int) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	*port = ln.Addr().(*net.TCPAddr).Port
	return ln
}

// closedPort records a port nothing listens on (one the system just gave out and took back).
func closedPort(t *testing.T, port *int) {
	t.Helper()
	require.NoError(t, listen(t, port).Close())
}

type leaf struct {
	cert tls.Certificate
	hash string
}

func newLeaf(t *testing.T, name string) leaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	sum := sha256.Sum256(der)
	return leaf{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hash: hex.EncodeToString(sum[:])}
}

// seen is what one server recorded.
type seen struct {
	mu       sync.Mutex
	sni      []string
	requests []*http.Request
}

func (s *seen) addSNI(n string) { s.mu.Lock(); s.sni = append(s.sni, n); s.mu.Unlock() }
func (s *seen) add(r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r)
	s.mu.Unlock()
}
func (s *seen) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.requests) }

// serveTLS starts an HTTPS server on 127.0.0.1 (its port in *port) with the leaf and the handler; it records SNI and requests.
func serveTLS(t *testing.T, port *int, l leaf, h http.HandlerFunc) *seen {
	t.Helper()
	s := &seen{}
	ln := listen(t, port)
	cfg := &tls.Config{Certificates: []tls.Certificate{l.cert}, MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { s.addSNI(hello.ServerName); return nil, nil }}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r.Clone(context.Background()))
		h(w, r)
	}), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

func checker() httpcheck.HTTPChecker { return httpcheck.HTTPChecker{Clock: clock.Real{}} }

func req(port int, l leaf) httpcheck.Request {
	return httpcheck.Request{Address: "127.0.0.1", Port: port, ServerName: "app.example.test", Path: "/healthz",
		ExpectStatus: []int{200}, Timeout: 2 * time.Second, ExpectLeafSHA256: l.hash, UserAgent: "Alice-canary/test"}
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

// CAN-12: a pass, a status not expected, a redirect never followed.
func TestCheckPasses(t *testing.T) {
	l := newLeaf(t, "app.example.test")
	serveTLS(t, &portMain, l, status(http.StatusOK))
	res := checker().Check(context.Background(), req(portMain, l))
	assert.True(t, res.OK, "%+v", res)
	assert.Empty(t, res.Reason)
	assert.Equal(t, 200, res.HTTPStatus)
	assert.GreaterOrEqual(t, res.LatencyMS, 0)
	assert.Equal(t, l.hash, res.ServedSHA256)

	// The fingerprint compare ignores case; a nil clock is the real one; no statuses means 200.
	r := req(portMain, l)
	r.ExpectLeafSHA256 = strings.Map(func(c rune) rune {
		if 'a' <= c && c <= 'f' {
			return c - 'a' + 'A'
		}
		return c
	}, l.hash)
	r.ExpectStatus = nil
	r.Timeout = 0
	res = httpcheck.HTTPChecker{}.Check(context.Background(), r)
	assert.True(t, res.OK, "%+v", res)
}

func TestCheckStatusNotExpected(t *testing.T) {
	l := newLeaf(t, "app.example.test")
	serveTLS(t, &portMain, l, status(http.StatusServiceUnavailable))
	res := checker().Check(context.Background(), req(portMain, l))
	assert.False(t, res.OK)
	assert.Equal(t, httpcheck.ReasonHTTPStatus, res.Reason)
	assert.Equal(t, 503, res.HTTPStatus)
	assert.Equal(t, l.hash, res.ServedSHA256)
}

func TestCheckDoesNotFollowRedirects(t *testing.T) {
	l := newLeaf(t, "app.example.test")
	second := serveTLS(t, &portRedirect, l, status(http.StatusOK))
	serveTLS(t, &portMain, l, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1:"+strconv.Itoa(portRedirect)+"/elsewhere", http.StatusFound)
	})
	res := checker().Check(context.Background(), req(portMain, l))
	assert.False(t, res.OK)
	assert.Equal(t, httpcheck.ReasonHTTPStatus, res.Reason)
	assert.Equal(t, 302, res.HTTPStatus)
	r := req(portMain, l)
	r.ExpectStatus = []int{200, 302}
	res = checker().Check(context.Background(), r)
	assert.True(t, res.OK, "%+v", res)
	assert.Zero(t, second.count(), "the redirect target saw no request")
}

// CAN-13: the served leaf is compared before any request byte is sent.
func TestCheckComparesTheServedLeaf(t *testing.T) {
	served, expected := newLeaf(t, "app.example.test"), newLeaf(t, "app.example.test")
	s := serveTLS(t, &portOther, served, status(http.StatusOK))
	res := checker().Check(context.Background(), req(portOther, expected))
	assert.False(t, res.OK)
	assert.Equal(t, httpcheck.ReasonServedOther, res.Reason)
	assert.Equal(t, served.hash, res.ServedSHA256)
	assert.Zero(t, res.HTTPStatus)
	assert.Zero(t, s.count(), "handshake only: no HTTP request")
}

// CAN-13: what is sent: SNI and Host are the server name, GET, the exact target, no credentials.
func TestCheckSendsTheServerNameAndHost(t *testing.T) {
	l := newLeaf(t, "app.example.test")
	s := serveTLS(t, &portHeaders, l, status(http.StatusNoContent))
	r := req(portHeaders, l)
	r.Path = "/health/deep?probe=1&x=%2F"
	r.ExpectStatus = []int{204}
	res := checker().Check(context.Background(), r)
	require.True(t, res.OK, "%+v", res)
	require.Equal(t, 1, s.count())
	got := s.requests[0]
	assert.Equal(t, []string{"app.example.test"}, s.sni)
	assert.Equal(t, "app.example.test", got.Host)
	assert.Equal(t, http.MethodGet, got.Method)
	assert.Equal(t, "/health/deep?probe=1&x=%2F", got.RequestURI)
	assert.Equal(t, "HTTP/1.1", got.Proto)
	assert.Equal(t, "Alice-canary/test", got.Header.Get("User-Agent"))
	assert.Equal(t, "*/*", got.Header.Get("Accept"))
	assert.Empty(t, got.Header.Get("Cookie"))
	assert.Empty(t, got.Header.Get("Authorization"))
	assert.Empty(t, got.Header.Get("Accept-Encoding"))
	assert.True(t, got.Close, "Connection: close")

	// No server name: no SNI, and Host is the dialed address.
	r.ServerName = ""
	res = checker().Check(context.Background(), r)
	require.True(t, res.OK, "%+v", res)
	assert.Equal(t, "", s.sni[1])
	assert.Equal(t, "127.0.0.1", s.requests[1].Host)
}

// CAN-14 (Review Focus 2): the server name is never resolved; only the address is dialed.
func TestCheckNeverDialsTheHostName(t *testing.T) {
	l := newLeaf(t, "metadata.invalid")
	s := serveTLS(t, &portMain, l, status(http.StatusOK))
	var lookups atomic.Int32
	res := httpcheck.HTTPChecker{Clock: clock.Real{}, Resolver: netaddrtest.Resolver(func(string) []netip.Addr {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}
	})}.Check(context.Background(), httpcheck.Request{Address: "127.0.0.1", Port: portMain, ServerName: "metadata.invalid",
		Path: "/", Timeout: 2 * time.Second, ExpectLeafSHA256: l.hash})
	assert.True(t, res.OK, "%+v", res)
	assert.Zero(t, lookups.Load(), "no lookup of the server name")
	assert.Equal(t, []string{"metadata.invalid"}, s.sni)
}

// CAN-14: the SEC-065 address rule refuses link-local, by address and through a name.
func TestCheckRefusesLinkLocal(t *testing.T) {
	l := newLeaf(t, "app.example.test")
	res := checker().Check(context.Background(), httpcheck.Request{Address: "169.254.169.254", Port: 443, Path: "/",
		Timeout: time.Second, ExpectLeafSHA256: l.hash})
	assert.False(t, res.OK)
	assert.Equal(t, httpcheck.ReasonNotAllowed, res.Reason)

	res = httpcheck.HTTPChecker{Clock: clock.Real{}, Resolver: netaddrtest.Resolver(func(name string) []netip.Addr {
		if name == "web.example.test" {
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}
		}
		return nil
	})}.Check(context.Background(), httpcheck.Request{Address: "web.example.test", Port: 443, Path: "/", Timeout: time.Second,
		ExpectLeafSHA256: l.hash})
	assert.False(t, res.OK)
	assert.Equal(t, httpcheck.ReasonNotAllowed, res.Reason)
}

// CAN-14: environment proxies are never used (the destination is a managed server, decision 13).
func TestCheckIgnoresEnvironmentProxies(t *testing.T) {
	l := newLeaf(t, "app.example.test")
	serveTLS(t, &portMain, l, status(http.StatusOK))
	ln := listen(t, &portProxy)
	t.Cleanup(func() { _ = ln.Close() })
	var proxied atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			proxied.Add(1)
			_ = c.Close()
		}
	}()
	proxy := "http://127.0.0.1:" + strconv.Itoa(portProxy)
	t.Setenv("HTTPS_PROXY", proxy)
	t.Setenv("https_proxy", proxy)
	t.Setenv("HTTP_PROXY", proxy)
	t.Setenv("NO_PROXY", "")
	res := checker().Check(context.Background(), req(portMain, l))
	assert.True(t, res.OK, "%+v", res)
	assert.Zero(t, proxied.Load())
}

// CAN-15: timeouts, caps and failures to connect.
func TestCheckTimeouts(t *testing.T) {
	l := newLeaf(t, "app.example.test")

	t.Run("accepts and never answers", func(t *testing.T) {
		ln := listen(t, &portSilent)
		t.Cleanup(func() { _ = ln.Close() })
		var conns []net.Conn
		var mu sync.Mutex
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
			}
		}()
		t.Cleanup(func() {
			mu.Lock()
			defer mu.Unlock()
			for _, c := range conns {
				_ = c.Close()
			}
		})
		r := req(portSilent, l)
		r.Timeout = time.Second
		start := time.Now()
		res := checker().Check(context.Background(), r)
		assert.Equal(t, httpcheck.ReasonTimeout, res.Reason, "%+v", res)
		assert.Less(t, time.Since(start), r.Timeout+time.Second)
	})

	t.Run("slow-loris body", func(t *testing.T) {
		serveTLS(t, &portSlow, l, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			f := w.(http.Flusher)
			for range 30 {
				if _, err := w.Write([]byte("x")); err != nil {
					return
				}
				f.Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(time.Second / 4):
				}
			}
		})
		r := req(portSlow, l)
		r.Timeout = time.Second
		start := time.Now()
		res := checker().Check(context.Background(), r)
		assert.Equal(t, httpcheck.ReasonTimeout, res.Reason, "%+v", res)
		assert.Equal(t, 200, res.HTTPStatus)
		assert.Less(t, time.Since(start), r.Timeout+time.Second)
	})

	t.Run("huge body is cut after 64 KiB", func(t *testing.T) {
		var wrote atomic.Int64
		var finished atomic.Bool
		serveTLS(t, &portHuge, l, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			chunk := make([]byte, 32<<10)
			for range 320 { // 10 MiB
				n, err := w.Write(chunk)
				wrote.Add(int64(n))
				if err != nil {
					return
				}
			}
			finished.Store(true)
		})
		res := checker().Check(context.Background(), req(portHuge, l))
		assert.True(t, res.OK, "%+v", res)
		assert.Eventually(t, func() bool { return !finished.Load() && wrote.Load() < 10<<20 }, 2*time.Second, 50*time.Millisecond)
	})

	t.Run("headers over 16 KiB", func(t *testing.T) {
		serveTLS(t, &portBigHeader, l, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Big", strings.Repeat("a", 20<<10))
			w.WriteHeader(http.StatusOK)
		})
		res := checker().Check(context.Background(), req(portBigHeader, l))
		assert.Equal(t, httpcheck.ReasonProtocol, res.Reason, "%+v", res)
		assert.Equal(t, l.hash, res.ServedSHA256)
	})

	t.Run("plaintext listener", func(t *testing.T) {
		ln := listen(t, &portPlain)
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					_, _ = bufio.NewReader(c).ReadByte()
					_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
					_ = c.Close()
				}()
			}
		}()
		res := checker().Check(context.Background(), req(portPlain, l))
		assert.Equal(t, httpcheck.ReasonUnreachable, res.Reason, "%+v", res)
	})

	closedPort(t, &portRefused)
	t.Run("refused port", func(t *testing.T) {
		res := checker().Check(context.Background(), req(portRefused, l))
		assert.Equal(t, httpcheck.ReasonUnreachable, res.Reason, "%+v", res)
	})

	t.Run("port out of range", func(t *testing.T) {
		res := checker().Check(context.Background(), req(0, l))
		assert.Equal(t, httpcheck.ReasonUnreachable, res.Reason, "%+v", res)
	})

	t.Run("a cancelled context is a timeout", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res := checker().Check(ctx, req(portRefused, l))
		assert.Equal(t, httpcheck.ReasonTimeout, res.Reason, "%+v", res)
	})
}

// The malformed response of a TLS server that is not HTTP is a protocol failure.
func TestCheckMalformedResponse(t *testing.T) {
	l := newLeaf(t, "app.example.test")
	ln := tls.NewListener(listen(t, &portMain), &tls.Config{Certificates: []tls.Certificate{l.cert}, MinVersion: tls.VersionTLS12})
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = bufio.NewReader(c).ReadString('\n')
				_, _ = io.WriteString(c, "SSH-2.0-not-http\r\n\r\n")
			}()
		}
	}()
	res := checker().Check(context.Background(), req(portMain, l))
	assert.Equal(t, httpcheck.ReasonProtocol, res.Reason, "%+v", res)
}

// A target that is not origin-form is never sent; an IPv6 address without a server name is bracketed in Host.
func TestCheckRequestForm(t *testing.T) {
	l := newLeaf(t, "app.example.test")
	for _, p := range []string{"healthz", "", "*"} {
		r := req(portRefused, l)
		r.Path = p
		res := checker().Check(context.Background(), r)
		assert.Equal(t, httpcheck.ReasonProtocol, res.Reason, "%q", p)
	}
	r := req(portRefused, l)
	r.Address, r.ServerName = "::1", ""
	res := checker().Check(context.Background(), r)
	assert.Equal(t, httpcheck.ReasonUnreachable, res.Reason, "%+v", res)
}
