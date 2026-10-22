package wintest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"alice/internal/providers/windows/winproto"
)

var errNoCertificate = errors.New("wintest: http.sys has no usable certificate for this connection")

// handshakeTimeout bounds one client's handshake.
const handshakeTimeout = 10 * time.Second

// selectLocked is http.sys's choice for a connection to ip:port with the given SNI (""): a hostnameport
// entry for (SNI, port), else an ipport entry for (ip, port), else the wildcard 0.0.0.0:port (and
// [::]:port); a ccs entry alone serves nothing.
func (m *Model) selectLocked(ip string, port int, sni string) (*winproto.SSLBinding, error) {
	addr, _ := netip.ParseAddr(ip)
	addr = addr.Unmap()
	var pick *winproto.SSLBinding
	find := func(match func(b *winproto.SSLBinding) bool) bool {
		for i := range m.bindings {
			if m.bindings[i].Port == port && match(&m.bindings[i]) {
				pick = &m.bindings[i]
				return true
			}
		}
		return false
	}
	ipport := func(want netip.Addr) func(b *winproto.SSLBinding) bool {
		return func(b *winproto.SSLBinding) bool {
			a, err := netip.ParseAddr(b.IP)
			return b.Type == winproto.BindingIPPort && err == nil && a.Unmap() == want
		}
	}
	switch {
	case sni != "" && find(func(b *winproto.SSLBinding) bool {
		return b.Type == winproto.BindingHostnamePort && fold(b.Host) == fold(sni)
	}):
	case addr.IsValid() && find(ipport(addr)):
	case find(ipport(netip.IPv4Unspecified())):
	case find(ipport(netip.IPv6Unspecified())):
	default:
		return nil, errNoCertificate
	}
	return pick, nil
}

// servedEntry is schannel's cache of one record (W0 F5): the chain built when the record was last
// written (built at the first handshake for a record the model was given, or after a reboot), and,
// with StaleTLS, the certificate the listener kept serving across a write (Ruling 23).
type servedEntry struct {
	chain  []*x509.Certificate
	pinned *tls.Certificate
}

// usableLocked is the certificate a record names when it is in its store with a key SYSTEM can use;
// else a handshake fails (design §11 "key unusable").
func (m *Model) usableLocked(b *winproto.SSLBinding) (*certEntry, error) {
	if b.CertSHA1 == "" {
		return nil, errNoCertificate
	}
	e := m.certLocked(b.Store, b.CertSHA1)
	if e == nil || e.key == nil || (e.usable != nil && !*e.usable) {
		return nil, errNoCertificate
	}
	return e, nil
}

// presentedLocked is the TLS certificate a handshake for a record sends: what a stale listener kept,
// else the leaf and the chain schannel cached for the record (built now when there is none).
func (m *Model) presentedLocked(b *winproto.SSLBinding) (*tls.Certificate, error) {
	k := keyOf(*b)
	s := m.served[k]
	if s != nil && s.pinned != nil {
		return s.pinned, nil
	}
	e, err := m.usableLocked(b)
	if err != nil {
		return nil, err
	}
	if s == nil {
		s = &servedEntry{chain: m.chainLocked(e.leaf)}
		m.served[k] = s
	}
	c := &tls.Certificate{Certificate: [][]byte{e.leaf.Raw}, PrivateKey: e.key}
	for _, x := range s.chain {
		c.Certificate = append(c.Certificate, x.Raw)
	}
	return c, nil
}

// Served is what a TLS handshake to ip:port with the given SNI shows: the SHA-256 of the leaf (lower
// case hex) and the number of certificates presented. ok is false when the handshake fails.
func (m *Model) Served(ip string, port int, sni string) (leafSHA256 string, chainLength int, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := m.selectLocked(ip, port, sni)
	if err != nil {
		return "", 0, false
	}
	c, err := m.presentedLocked(b)
	if err != nil {
		return "", 0, false
	}
	sum := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(sum[:]), len(c.Certificate), true
}

// Endpoint is the real address of the listener for a binding port ("" when none): tests listen on
// random ports.
func (m *Model) Endpoint(port int) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.endpoints[port]
}

// Serve starts one TLS listener per distinct binding port on bind and returns once they listen; they
// stop when ctx ends. A bind of "host" listens on the binding ports themselves (the container: 0.0.0.0);
// "host:0" on a random port per binding port (tests: 127.0.0.1:0), found with Endpoint. Bindings added
// later are served by the listeners that exist; a new port needs another Serve.
func (m *Model) Serve(ctx context.Context, bind string) error {
	hostName, random := bind, false
	if h, p, err := net.SplitHostPort(bind); err == nil {
		if p != "0" {
			return fmt.Errorf("wintest: bind %q: the port is 0 or absent", bind)
		}
		hostName, random = h, true
	}
	m.mu.Lock()
	var ports []int
	for _, b := range m.bindings {
		if !slices.Contains(ports, b.Port) {
			ports = append(ports, b.Port)
		}
	}
	m.mu.Unlock()
	slices.Sort(ports)

	var lns []net.Listener
	closeAll := func() {
		for _, l := range lns {
			_ = l.Close()
		}
	}
	for _, port := range ports {
		listenPort := port
		if random {
			listenPort = 0
		}
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(hostName, strconv.Itoa(listenPort)))
		if err != nil {
			closeAll()
			return err
		}
		lns = append(lns, ln)
		m.mu.Lock()
		m.endpoints[port] = ln.Addr().String()
		m.mu.Unlock()
	}
	for i, ln := range lns {
		m.serving.Add(1)
		go m.accept(ctx, ln, ports[i])
	}
	return nil
}

// accept serves one listener until ctx ends.
func (m *Model) accept(ctx context.Context, ln net.Listener, port int) {
	defer m.serving.Done()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			m.mu.Lock()
			defer m.mu.Unlock()
			ip := ""
			if a, ok := hi.Conn.LocalAddr().(*net.TCPAddr); ok {
				ip = a.IP.String()
			}
			if meant, ok := m.intents[hi.Conn.RemoteAddr().String()]; ok {
				ip = meant
			}
			b, err := m.selectLocked(ip, port, hi.ServerName)
			if err != nil {
				return nil, err
			}
			return m.presentedLocked(b)
		},
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		m.serving.Add(1)
		go func() {
			defer m.serving.Done()
			defer func() { _ = c.Close() }()
			hctx, stop := context.WithTimeout(ctx, handshakeTimeout)
			defer stop()
			_ = tls.Server(c, cfg).HandshakeContext(hctx)
		}()
	}
}
