// Package fakefleet is a fleet of hostile and ordinary TLS servers for the network discovery tests
// (plan 2026-10-13-network-discovery, design decision 8 and amendment A6). Each server kind listens
// on its own address and keeps an access log of every connection it accepted (remote address, SNI,
// times, bytes read and written, whether the TLS handshake completed, and the application bytes the
// client sent after it), so a test can prove which endpoints a scan dialed and which it never did,
// and that the probe sent no application byte.
//
// It is a test helper (internal/archtest testOnlyDirs) and imports internal/testutil/pki only. No
// release binary links it: cmd/alice-fakefleet wraps it for the e2e stack.
//
// Determinism: WaitIdle returns only once every connection made before the call has been accepted,
// logged and finished (it pushes a sentinel connection through each listener's FIFO accept queue), so
// a test never sleeps. A handler that sees its client leave stops at once and writes nothing more;
// no TLS server writes anything after its handshake (not even close_notify: the TCP connection is
// closed under it). Every connection lives at most Options.IdleTimeout, and every byte budget
// (slow-loris, giant chain, log) is bounded on the fake's side.
package fakefleet

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/testutil/pki"
)

// wall is the real clock: log times and network deadlines are real time, whatever Options.Now says.
var wall clock.Clock = clock.Real{}

// lowerASCII lower-cases the ASCII letters of a DNS name (SNI names are ASCII; no locale applies).
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Kind names a server behaviour.
type Kind string

// Server kinds.
const (
	KindValid               Kind = "valid"                // leaf + intermediate of the fleet CA, TLS 1.2-1.3
	KindExpired             Kind = "expired"              // leaf expired a day before Now
	KindNotYetValid         Kind = "not-yet-valid"        // leaf valid from a day after Now
	KindSelfSigned          Kind = "self-signed"          // a self-signed leaf alone
	KindWrongOrder          Kind = "wrong-order"          // leaf, root, intermediate
	KindMissingIntermediate Kind = "missing-intermediate" // the leaf alone
	KindSNI                 Kind = "sni"                  // a certificate per SNI name, a default one otherwise
	KindTLS10               Kind = "tls10"                // TLS 1.0 only
	KindTLS12               Kind = "tls12"                // TLS 1.2 only
	KindTLS13               Kind = "tls13"                // TLS 1.3 only
	KindRSAKeyExchange      Kind = "rsa-kex"              // TLS 1.2, RSA key exchange suites only (RSA leaf)
	KindSHA1                Kind = "sha1"                 // leaf signed with SHA-1 by a legacy RSA intermediate
	KindSlowLoris           Kind = "slow-loris"           // reads the hello, then trickles one byte per interval
	KindGiantChain          Kind = "giant-chain"          // ServerHello, then a Certificate message claiming 16 MiB
	KindHugeChain           Kind = "huge-chain"           // a real chain of HugeChainCerts certificates (TLS 1.2)
	KindReset               Kind = "reset"                // reads the hello, then resets the connection
	KindPlainText           Kind = "plaintext"            // not TLS: writes a text banner and closes
	KindManySNI             Kind = "many-sni"             // ManySNINames names, each with its own certificate
	KindMalformed           Kind = "malformed"            // a leaf with a negative serial number, served raw (TLS 1.2)
)

// AllKinds lists every kind in a stable order (the order of Fleet.Servers).
var AllKinds = []Kind{KindValid, KindExpired, KindNotYetValid, KindSelfSigned, KindWrongOrder, KindMissingIntermediate,
	KindSNI, KindTLS10, KindTLS12, KindTLS13, KindRSAKeyExchange, KindSHA1, KindSlowLoris, KindGiantChain, KindHugeChain,
	KindReset, KindPlainText, KindManySNI, KindMalformed}

// DefaultPorts are the fixed ports cmd/alice-fakefleet serves each kind on (one address, one port per kind).
var DefaultPorts = map[Kind]int{
	KindValid: 443, KindExpired: 9401, KindNotYetValid: 9402, KindSelfSigned: 9403, KindWrongOrder: 9404,
	KindMissingIntermediate: 9405, KindSNI: 9406, KindTLS10: 9407, KindTLS12: 9408, KindTLS13: 9409,
	KindRSAKeyExchange: 9410, KindSHA1: 9411, KindSlowLoris: 9412, KindGiantChain: 9413, KindHugeChain: 9414,
	KindReset: 9415, KindPlainText: 9416, KindManySNI: 9417, KindMalformed: 9418,
}

// DefaultDomain is the DNS suffix of the servers' names when Options.Domain is empty.
const DefaultDomain = "fleet.test"

// PlainTextBanner is what the plaintext server writes.
const PlainTextBanner = "220 fakefleet plain text service, not TLS\r\n"

// Options configure a fleet. The zero value serves every kind on 127.0.0.1 with real-time certificates.
type Options struct {
	Kinds  []Kind          // nil: AllKinds
	Listen map[Kind]string // a kind's listen address; missing: Bind with port 0
	Bind   string          // default "127.0.0.1"
	Domain string          // server names are <kind>.<Domain>; default DefaultDomain
	Now    time.Time       // the certificates' reference time; default time.Now()

	IdleTimeout       time.Duration // the longest life of any connection; default 30s
	SlowLorisInterval time.Duration // default 1s
	GiantBytes        int64         // Certificate message body the giant server sends at most; default 100 MiB
	HugeChainCerts    int           // default 10,000
	ManySNINames      int           // default 256
	MaxConns          int           // open connections per server, more are closed at once; default 128
	MaxChainConns     int           // the same for giant-chain and huge-chain (megabytes per connection); default 8
	MaxLog            int           // access log entries kept, later ones are counted in Dropped; default 100,000
}

const (
	defaultGiantBytes = 100 << 20
	maxManySNI        = 4096
	maxHugeChain      = 30000
)

func (o *Options) defaults() error {
	if o.Kinds == nil {
		o.Kinds = AllKinds
	}
	seen := map[Kind]bool{}
	for _, k := range o.Kinds {
		if _, ok := DefaultPorts[k]; !ok {
			return fmt.Errorf("fakefleet: unknown kind %q", k)
		}
		if seen[k] {
			return fmt.Errorf("fakefleet: kind %q twice", k)
		}
		seen[k] = true
	}
	for k := range o.Listen {
		if !seen[k] {
			return fmt.Errorf("fakefleet: a listen address for %q, which is not served", k)
		}
	}
	if o.Bind == "" {
		o.Bind = "127.0.0.1"
	}
	if o.Domain == "" {
		o.Domain = DefaultDomain
	}
	if !validDomain(o.Domain) {
		return fmt.Errorf("fakefleet: %q is not a DNS name", o.Domain)
	}
	if o.Now.IsZero() {
		o.Now = wall.Now()
	}
	setDefault(&o.IdleTimeout, 30*time.Second)
	setDefault(&o.SlowLorisInterval, time.Second)
	setDefault(&o.GiantBytes, defaultGiantBytes)
	setDefault(&o.HugeChainCerts, 10000)
	setDefault(&o.ManySNINames, 256)
	setDefault(&o.MaxConns, 128)
	setDefault(&o.MaxChainConns, 8)
	setDefault(&o.MaxLog, 100000)
	switch {
	case o.GiantBytes < 0:
		return errors.New("fakefleet: GiantBytes must not be negative")
	case o.HugeChainCerts < 2 || o.HugeChainCerts > maxHugeChain:
		return fmt.Errorf("fakefleet: HugeChainCerts must be from 2 to %d", maxHugeChain)
	case o.ManySNINames < 1 || o.ManySNINames > maxManySNI:
		return fmt.Errorf("fakefleet: ManySNINames must be from 1 to %d", maxManySNI)
	}
	return nil
}

func setDefault[T int | int64 | time.Duration](v *T, d T) {
	if *v == 0 {
		*v = d
	}
}

func validDomain(d string) bool {
	if len(d) > 200 {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// Fleet is a running set of servers.
type Fleet struct {
	o       Options
	ca      *pki.CA
	servers []*Server
	byKind  map[Kind]*Server

	closing chan struct{}
	ctx     context.Context // ends with Close: handshakes stop
	cancel  context.CancelFunc
	wg      sync.WaitGroup // accept loops and connection handlers

	mu        sync.Mutex
	closed    bool
	log       []*access
	dropped   int64
	conns     map[*access]net.Conn
	sentinels map[string]bool // local addresses of WaitIdle's connections, until accepted
	active    int
	changed   chan struct{} // closed and replaced whenever the log grows or a connection ends

	appBytes atomic.Int64
}

// Server is one listener of the fleet.
type Server struct {
	f        *Fleet
	kind     Kind
	host     string
	ln       net.Listener
	addr     string
	material *material
	accepted atomic.Int64
	open     atomic.Int64
}

// New builds the certificates and starts every listener. On error nothing is left listening.
func New(o Options) (*Fleet, error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	f := &Fleet{o: o, byKind: map[Kind]*Server{}, closing: make(chan struct{}), conns: map[*access]net.Conn{},
		sentinels: map[string]bool{}, changed: make(chan struct{})}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.ca = pki.NewCA("Fakefleet", pki.ECDSA256, o.Now)
	mats := newMaterials(f.ca, o)
	for _, k := range o.Kinds {
		addr, ok := o.Listen[k]
		if !ok {
			addr = net.JoinHostPort(o.Bind, "0")
		}
		ln, err := (&net.ListenConfig{}).Listen(f.ctx, "tcp", addr)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("fakefleet: %s: %w", k, err)
		}
		s := &Server{f: f, kind: k, host: hostOf(k, o.Domain), ln: ln, addr: ln.Addr().String()}
		s.material, err = mats.build(k, s.host)
		if err != nil {
			_ = ln.Close()
			_ = f.Close()
			return nil, err
		}
		f.servers = append(f.servers, s)
		f.byKind[k] = s
	}
	for _, s := range f.servers {
		f.wg.Add(1)
		go s.acceptLoop()
	}
	return f, nil
}

func hostOf(k Kind, domain string) string { return string(k) + "." + domain }

// Close stops every listener, closes every open connection and waits for every handler. It is
// idempotent.
func (f *Fleet) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	close(f.closing)
	f.cancel()
	for _, c := range f.conns {
		_ = c.Close()
	}
	f.mu.Unlock()
	for _, s := range f.servers {
		_ = s.ln.Close()
	}
	f.wg.Wait()
	return nil
}

// Servers returns the servers in the order of AllKinds.
func (f *Fleet) Servers() []*Server { return slices.Clone(f.servers) }

// Server returns the server of a kind, or nil.
func (f *Fleet) Server(k Kind) *Server { return f.byKind[k] }

// Addr returns the listen address of a kind ("" when the fleet does not serve it).
func (f *Fleet) Addr(k Kind) string {
	if s := f.byKind[k]; s != nil {
		return s.addr
	}
	return ""
}

// Domain is the DNS suffix of the servers' names.
func (f *Fleet) Domain() string { return f.o.Domain }

// CA is the fleet's root and intermediate.
func (f *Fleet) CA() *pki.CA { return f.ca }

// Root is the fleet's root certificate.
func (f *Fleet) Root() *x509.Certificate { return f.ca.Root }

// RootPEM is the fleet's root certificate in PEM.
func (f *Fleet) RootPEM() []byte { return f.ca.RootPEM }

// AppBytesAfterHandshake is the number of application bytes all clients sent after a completed
// handshake. A discovery probe must keep it at zero. Each connection is read for at most 1 MiB and then
// closed, so above that the counter is a floor, not an exact count.
func (f *Fleet) AppBytesAfterHandshake() int64 { return f.appBytes.Load() }

// Dropped is the number of connections not kept in the log because it was full.
func (f *Fleet) Dropped() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropped
}

// Kind is the server's kind.
func (s *Server) Kind() Kind { return s.kind }

// Addr is the address the server listens on.
func (s *Server) Addr() string { return s.addr }

// Host is the server's DNS name (<kind>.<domain>), its default certificate's name.
func (s *Server) Host() string { return s.host }

// Chain is the DER chain the server presents by default (nil for servers that present none).
func (s *Server) Chain() [][]byte { return cloneChain(s.material.chain) }

// SNINames lists the names with a certificate of their own (sni and many-sni), sorted.
func (s *Server) SNINames() []string { return slices.Clone(s.material.names) }

// ChainFor is the chain presented for one SNI name, nil when the name has none of its own.
func (s *Server) ChainFor(name string) [][]byte {
	if c, ok := s.material.bySNI[lowerASCII(name)]; ok {
		return cloneChain(c.Certificate)
	}
	return nil
}

// Accepted is the number of connections the server accepted since the last ClearLog (exact even
// when the log is full).
func (s *Server) Accepted() int64 { return s.accepted.Load() }

// Log returns the server's access log entries.
func (s *Server) Log() []Access {
	var out []Access
	for _, a := range s.f.Log() {
		if a.Kind == s.kind {
			out = append(out, a)
		}
	}
	return out
}

func cloneChain(c [][]byte) [][]byte {
	if c == nil {
		return nil
	}
	out := make([][]byte, len(c))
	for i, d := range c {
		out[i] = slices.Clone(d)
	}
	return out
}

// Info describes a fleet for the control endpoint.
type Info struct {
	Domain  string       `json:"domain"`
	Servers []ServerInfo `json:"servers"`
}

// ServerInfo describes one server.
type ServerInfo struct {
	Kind        Kind     `json:"kind"`
	Addr        string   `json:"addr"`
	Host        string   `json:"host"`
	SNINames    int      `json:"sni_names"`
	ChainSHA256 []string `json:"chain_sha256"`
}

// Info returns the fleet's description.
func (f *Fleet) Info() Info {
	out := Info{Domain: f.o.Domain}
	for _, s := range f.servers {
		si := ServerInfo{Kind: s.kind, Addr: s.addr, Host: s.host, SNINames: len(s.material.names)}
		for _, d := range s.material.chain {
			si.ChainSHA256 = append(si.ChainSHA256, fingerprint(d))
		}
		out.Servers = append(out.Servers, si)
	}
	return out
}

// Counters are the fleet's counters.
type Counters struct {
	Accepted               map[Kind]int64 `json:"accepted"`
	AppBytesAfterHandshake int64          `json:"app_bytes_after_handshake"`
	Active                 int            `json:"active"`
	Dropped                int64          `json:"dropped"`
}

// Counters returns the counters.
func (f *Fleet) Counters() Counters {
	c := Counters{Accepted: map[Kind]int64{}, AppBytesAfterHandshake: f.appBytes.Load()}
	for _, s := range f.servers {
		c.Accepted[s.kind] = s.accepted.Load()
	}
	f.mu.Lock()
	c.Active, c.Dropped = f.active, f.dropped
	f.mu.Unlock()
	return c
}

// ClearLog empties the log and resets the counters (open connections keep being served, and are
// not logged again).
func (f *Fleet) ClearLog() {
	f.mu.Lock()
	f.log, f.dropped = nil, 0
	f.mu.Unlock()
	f.appBytes.Store(0)
	for _, s := range f.servers {
		s.accepted.Store(0)
	}
}

// WaitIdle returns once every connection made to the fleet before the call has been accepted,
// logged and finished. It pushes one sentinel connection through each listener (connections are
// accepted in order, so once the sentinel is accepted every earlier one is) and then waits for
// every handler; sentinels are never logged or counted.
func (f *Fleet) WaitIdle(ctx context.Context) error {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if !closed {
		for _, s := range f.servers {
			if err := s.settle(ctx); err != nil {
				return err
			}
		}
	}
	for {
		f.mu.Lock()
		if f.active == 0 {
			f.mu.Unlock()
			return nil
		}
		ch := f.changed
		f.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// settle dials the server from an address registered before the connection exists, and waits until
// the accept loop has taken that connection (and closed it unlogged).
func (s *Server) settle(ctx context.Context) error {
	ap, err := netip.ParseAddrPort(s.addr)
	if err != nil {
		return fmt.Errorf("fakefleet: settle %s: %w", s.kind, err)
	}
	ip := ap.Addr().Unmap()
	if ip.IsUnspecified() {
		ip = netip.IPv6Loopback()
		if ap.Addr().Is4() {
			ip = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		}
	}
	var local string
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var bindErr error
		if err := rc.Control(func(fd uintptr) { local, bindErr = s.f.bindSentinel(int(fd), ip) }); err != nil {
			return err
		}
		return bindErr
	}}
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, ap.Port()).String())
	if err != nil {
		s.f.dropSentinel(local)
		return fmt.Errorf("fakefleet: settle %s: %w", s.kind, err)
	}
	defer func() { _ = c.Close() }()
	for {
		s.f.mu.Lock()
		taken := !s.f.sentinels[local]
		ch := s.f.changed
		closed := s.f.closed
		s.f.mu.Unlock()
		if taken || closed {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			s.f.dropSentinel(local)
			return ctx.Err()
		}
	}
}

// bindSentinel binds a socket to an ephemeral port of ip and registers the address as a sentinel's
// before the socket connects, so the accept loop recognises the connection whenever it takes it.
func (f *Fleet) bindSentinel(fd int, ip netip.Addr) (string, error) {
	var sa syscall.Sockaddr
	if ip.Is4() {
		sa = &syscall.SockaddrInet4{Addr: ip.As4()}
	} else {
		sa = &syscall.SockaddrInet6{Addr: ip.As16()}
	}
	if err := syscall.Bind(fd, sa); err != nil {
		return "", err
	}
	got, err := syscall.Getsockname(fd)
	if err != nil {
		return "", err
	}
	var port int
	switch g := got.(type) {
	case *syscall.SockaddrInet4:
		port = g.Port
	case *syscall.SockaddrInet6:
		port = g.Port
	}
	local := netip.AddrPortFrom(ip, uint16(port)).String() //nolint:gosec // G115: a port fits
	f.mu.Lock()
	f.sentinels[local] = true
	f.mu.Unlock()
	return local, nil
}

func (f *Fleet) dropSentinel(local string) {
	f.mu.Lock()
	delete(f.sentinels, local)
	f.mu.Unlock()
}
