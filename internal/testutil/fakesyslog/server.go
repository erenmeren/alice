// Package fakesyslog is a syslog receiver for tests: RFC 5425/6587 octet-counted frames over TLS (with a server
// certificate issued at start by a test CA from internal/testutil/pki) or plain TCP, and RFC 5426 datagrams over UDP
// on the same port number. It stores the message text of each frame and can go down and come back on the same port.
package fakesyslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/testutil/pki"
)

// maxFrame bounds one frame; a longer length closes the connection.
const maxFrame = 64 << 10

// Options choose the listeners: TLS or plain TCP always, and UDP on the same port when asked.
type Options struct {
	TLS bool
	UDP bool
}

// Server is the fake receiver.
type Server struct {
	opts   Options
	tlsCfg *tls.Config
	caPEM  []byte

	mu       sync.Mutex
	addr     string
	ln       net.Listener
	udp      net.PacketConn
	conns    map[net.Conn]struct{}
	messages []string
}

// Start listens on a free loopback port; t.Cleanup stops the server.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	s := &Server{opts: o, conns: map[net.Conn]struct{}{}}
	if o.TLS {
		now := clock.Real{}.Now()
		ca := pki.NewCA("fakesyslog", pki.ECDSA256, now)
		leaf := ca.Issue(pki.Opts{CommonName: "127.0.0.1", SANs: []string{"127.0.0.1", "localhost"}}, now)
		s.caPEM = ca.RootPEM
		s.tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.Cert.Raw, ca.Intermediate.Raw}, PrivateKey: leaf.Key, Leaf: leaf.Cert}}}
	}
	var err error
	for range 20 { // a UDP port of the same number can be taken by someone else: try another TCP port
		if err = s.listen("127.0.0.1:0"); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Down)
	return s
}

func (s *Server) listen(addr string) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	var pc net.PacketConn
	if s.opts.UDP {
		if pc, err = lc.ListenPacket(context.Background(), "udp", ln.Addr().String()); err != nil {
			_ = ln.Close()
			return err
		}
	}
	if s.tlsCfg != nil {
		ln = tls.NewListener(ln, s.tlsCfg)
	}
	s.mu.Lock()
	s.ln, s.udp, s.addr = ln, pc, ln.Addr().String()
	s.mu.Unlock()
	go s.accept(ln)
	if pc != nil {
		go s.datagrams(pc)
	}
	return nil
}

func (s *Server) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go s.session(c)
	}
}

func (s *Server) datagrams(pc net.PacketConn) {
	buf := make([]byte, maxFrame)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		s.store(string(buf[:n]))
	}
}

// session reads "<length> <message>" frames until the peer closes or sends a malformed frame.
func (s *Server) session(c net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		_ = c.Close()
	}()
	r := bufio.NewReader(c)
	for {
		_ = c.SetReadDeadline(clock.Real{}.Now().Add(time.Minute))
		n, ok := frameLength(r)
		if !ok {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(r, msg); err != nil {
			return
		}
		s.store(string(msg))
	}
}

// frameLength reads the "<digits> " prefix of a frame; anything else (a TLS hello on a plain port, say) ends the session.
func frameLength(r *bufio.Reader) (int, bool) {
	n, digits := 0, 0
	for {
		b, err := r.ReadByte()
		switch {
		case err != nil:
			return 0, false
		case b == ' ' && digits > 0:
			return n, n >= 1
		case b < '0' || b > '9' || digits == 6:
			return 0, false
		}
		n, digits = n*10+int(b-'0'), digits+1
		if n > maxFrame {
			return 0, false
		}
	}
}

func (s *Server) store(m string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, m)
}

// Addr is the "127.0.0.1:<port>" address of the listeners.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// CAPEM is the root certificate of the CA that issued the TLS server certificate (nil without TLS).
func (s *Server) CAPEM() []byte { return s.caPEM }

// Messages returns a copy of the received messages in arrival order.
func (s *Server) Messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.messages...)
}

// Clear forgets the received messages.
func (s *Server) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = nil
}

// Down closes the listeners and every open connection: new connections are refused until Up.
func (s *Server) Down() {
	s.mu.Lock()
	ln, pc := s.ln, s.udp
	s.ln, s.udp = nil, nil
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if pc != nil {
		_ = pc.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

// Up listens again on the previous port.
func (s *Server) Up() error {
	s.mu.Lock()
	addr, up := s.addr, s.ln != nil
	s.mu.Unlock()
	if up {
		return nil
	}
	return s.listen(addr)
}
