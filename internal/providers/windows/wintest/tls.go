package wintest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

var errNoCertificate = errors.New("wintest: http.sys has no usable certificate for this connection")

// handshakeTimeout bounds one client's handshake.
const handshakeTimeout = 10 * time.Second

// selectLocked is http.sys's choice for a connection to ip:port with the given SNI (""): a hostnameport
// entry for (SNI, port), else the ccs entry of the port when CCS is on and there is an SNI (an explicit
// hostnameport entry comes first, F17), else an ipport entry for (ip, port), else the wildcard
// 0.0.0.0:port (and [::]:port). Without CCS or an SNI a ccs entry serves nothing.
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
	case sni != "" && m.iis.CCSEnabled && find(func(b *winproto.SSLBinding) bool { return b.Type == winproto.BindingCCS }):
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

// certificateLocked is what a handshake to ip:port with the given SNI presents: the record http.sys
// selects, and for a ccs record the file of the CCS folder (ccsPresentedLocked).
func (m *Model) certificateLocked(ip string, port int, sni string) (*tls.Certificate, error) {
	b, err := m.selectLocked(ip, port, sni)
	if err != nil {
		return nil, err
	}
	if b.Type == winproto.BindingCCS {
		return m.ccsPresentedLocked(sni)
	}
	return m.presentedLocked(b)
}

// ccsPresentedLocked is IIS's CCS lookup for an SNI host (F17 as measured, ruling W5-13): <host>.pfx, else
// the nearest _.<suffix>.pfx of a suffix at any depth that keeps at least two labels (never the wildcard's
// own parent), compared without case, in the folder the registry names now. The order between two wildcard
// files is not measured (nearest first here).
// A file the helper replaced or restored is served as it was until RefreshCCSRecords (F15, pinLocked).
// The file is opened with the store's password; one it does not open serves nothing (F16). The chain is
// the file's intermediates (F18 as modelled).
func (m *Model) ccsPresentedLocked(sni string) (*tls.Certificate, error) {
	host := fold(sni)
	names := []string{host + ".pfx"}
	for rest := host; ; {
		_, suffix, ok := strings.Cut(rest, ".")
		if !ok || !strings.Contains(suffix, ".") {
			break
		}
		names = append(names, "_."+suffix+".pfx")
		rest = suffix
	}
	d := m.ccsDirs[folderKey(m.iis.CCSPath)]
	for _, n := range names {
		f := d[n]
		if f == nil {
			continue
		}
		data := f.data
		if p, ok := m.ccsPinned[n]; ok {
			data = p
		}
		leaf, chain, key, err := pki.OpenPFXKey(data, []byte(m.ccsPassword))
		if err != nil {
			return nil, errNoCertificate
		}
		return &tls.Certificate{Certificate: append([][]byte{leaf}, chain...), PrivateKey: key}, nil
	}
	return nil, errNoCertificate
}

// Served is what a TLS handshake to ip:port with the given SNI shows: the SHA-256 of the leaf (lower
// case hex) and the number of certificates presented. ok is false when the handshake fails.
func (m *Model) Served(ip string, port int, sni string) (leafSHA256 string, chainLength int, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.certificateLocked(ip, port, sni)
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
	rdpPort := 0 // a binding on the listener's port wins: http.sys holds it
	if c := m.rdpCfg; c.Present && c.Port > 0 && !slices.Contains(ports, c.Port) {
		rdpPort = c.Port
		ports = append(ports, rdpPort)
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
		m.mu.Lock()
		winrm := m.winrmPortLocked(ports[i])
		m.mu.Unlock()
		if winrm { // the WinRM record's port serves WS-Man over its TLS (R71 Ruling 20)
			go m.serveWinRM(ctx, ln, m.listenerTLS(ports[i], false))
			continue
		}
		go m.accept(ctx, ln, ports[i], ports[i] == rdpPort)
	}
	return nil
}

// accept serves one listener until ctx ends: http.sys's TLS, or with rdp the RDP listener's negotiation
// before its TLS.
func (m *Model) accept(ctx context.Context, ln net.Listener, port int, rdp bool) {
	defer m.serving.Done()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	cfg := m.listenerTLS(port, rdp)
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
			if dl, _ := hctx.Deadline(); rdp && !m.rdpNegotiate(c, dl) {
				return
			}
			_ = tls.Server(c, cfg).HandshakeContext(hctx)
		}()
	}
}

// listenerTLS is the TLS of a listener's port: what http.sys selects for the address the client reached (or the
// helper meant), or with rdp what the RDP listener presents.
func (m *Model) listenerTLS(port int, rdp bool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if rdp {
				return m.rdpCertLocked()
			}
			ip := ""
			if a, ok := hi.Conn.LocalAddr().(*net.TCPAddr); ok {
				ip = a.IP.String()
			}
			if meant, ok := m.intents[hi.Conn.RemoteAddr().String()]; ok {
				ip = meant
			}
			return m.certificateLocked(ip, port, hi.ServerName)
		},
	}
}

// maxRDPRequest bounds the client's Connection Request TPKT (a cookie included).
const maxRDPRequest = 256

// rdpNegotiate reads the client's X.224 Connection Request and answers the listener's Connection
// Confirm (rdpConfirmLocked); true when TLS follows. A listener turned off, or bytes that are no
// Connection Request, are closed unanswered. The negotiation shares the handshake's deadline.
func (m *Model) rdpNegotiate(c net.Conn, deadline time.Time) bool {
	_ = c.SetDeadline(deadline)
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	m.mu.Lock()
	on := m.rdpCfg.Present && m.rdpCfg.Enabled
	m.mu.Unlock()
	if !on {
		return false
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return false
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if hdr[0] != 3 || n < 11 || n > maxRDPRequest {
		return false
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(c, body); err != nil || body[1] != 0xe0 { // X.224 CR
		return false
	}
	var requested uint32
	// shortcut: a Connection Request without RDP_NEG_REQ is answered as requested=0 (a failure), where
	// Windows answers a plain confirm; no Alice client sends one, model it when a test needs it.
	if len(body) >= 7+8 && body[len(body)-8] == 0x01 { // RDP_NEG_REQ ends the request
		requested = binary.LittleEndian.Uint32(body[len(body)-4:])
	}
	m.mu.Lock()
	answer, tlsNext := m.rdpConfirmLocked(requested)
	m.mu.Unlock()
	_, err := c.Write(answer)
	return err == nil && tlsNext
}

// rdpConfirmLocked is the listener's answer to requestedProtocols (F22 as measured, mirroring Windows):
// security layer 0 is SSL_NOT_ALLOWED_BY_SERVER (2); HYBRID whenever asked for, with NLA on or off; else
// with NLA on HYBRID_REQUIRED_BY_SERVER (5), without SSL when asked for, else SSL_REQUIRED_BY_SERVER (1).
// shortcut: layer 1 with a client that asks for standard RDP security only is answered as layer 2 (no
// client of Alice's asks so); model it when a test needs it.
func (m *Model) rdpConfirmLocked(requested uint32) (answer []byte, tlsNext bool) {
	c := m.rdpCfg
	switch {
	case c.SecurityLayer == 0:
		return helperproto.RDPFailure(2), false
	case requested&helperproto.RDPProtocolHybrid != 0:
		return helperproto.RDPConfirm(helperproto.RDPProtocolHybrid), true
	case c.NLA:
		return helperproto.RDPFailure(5), false
	case requested&helperproto.RDPProtocolSSL != 0:
		return helperproto.RDPConfirm(helperproto.RDPProtocolSSL), true
	}
	return helperproto.RDPFailure(1), false
}

// rdpCertLocked is what the RDP listener's TLS presents (Ruling 4): what a stale listener kept (a
// certificate, or the failure it had), else the
// certificate the value names in My, or while it is absent the single certificate of Remote Desktop,
// with the chain Windows builds. A certificate without its key, or whose key NETWORK SERVICE cannot read,
// fails the handshake (F21 modelled).
// shortcut: Windows makes a new self-signed certificate when Remote Desktop holds none; the model fails.
func (m *Model) rdpCertLocked() (*tls.Certificate, error) {
	if m.rdpPinSet {
		if m.rdpPinned == nil {
			return nil, errNoCertificate
		}
		return m.rdpPinned, nil
	}
	storeName := "My"
	var e *certEntry
	if m.rdp != "" {
		e = m.certLocked(storeName, m.rdp)
	} else if s := m.stores[fold(winproto.RDPStoreSelfSigned)]; s != nil && len(s.certs) == 1 {
		storeName, e = winproto.RDPStoreSelfSigned, s.certs[0]
	}
	if e == nil || e.key == nil || !m.nsRead[keyID(storeName, e.sha1)] {
		return nil, errNoCertificate
	}
	c := &tls.Certificate{Certificate: [][]byte{e.leaf.Raw}, PrivateKey: e.key}
	for _, x := range m.chainLocked(e.leaf) {
		c.Certificate = append(c.Certificate, x.Raw)
	}
	return c, nil
}
