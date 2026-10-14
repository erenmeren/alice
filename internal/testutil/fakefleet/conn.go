package fakefleet

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Access is one access log entry: a connection a server accepted.
type Access struct {
	Kind         Kind      `json:"kind"`
	Local        string    `json:"local"`  // the server address the client reached (not the listen address)
	Remote       string    `json:"remote"` // the client's address
	SNI          string    `json:"sni"`    // the server name of the ClientHello ("" when none or not TLS)
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"` // zero while open
	BytesRead    int64     `json:"bytes_read"`
	BytesWritten int64     `json:"bytes_written"`
	Handshake    bool      `json:"handshake"` // the TLS handshake completed
	AppBytes     int64     `json:"app_bytes"` // application bytes received after the handshake (at most 1 MiB is read: a floor above that)
	Closed       bool      `json:"closed"`
	Overflow     bool      `json:"overflow"` // closed at once: the server had MaxConns open connections
}

// access is the live entry; the counters change while the connection runs.
type access struct {
	kind          Kind
	local, remote string
	start         time.Time
	overflow      bool

	read, written, app atomic.Int64
	handshake          atomic.Bool

	// under Fleet.mu
	sni    string
	end    time.Time
	closed bool
}

func (a *access) snapshot() Access {
	return Access{Kind: a.kind, Local: a.local, Remote: a.remote, SNI: a.sni, Start: a.start, End: a.end,
		BytesRead: a.read.Load(), BytesWritten: a.written.Load(), Handshake: a.handshake.Load(), AppBytes: a.app.Load(),
		Closed: a.closed, Overflow: a.overflow}
}

// Log returns every kept access log entry in accept order.
func (f *Fleet) Log() []Access {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Access, 0, len(f.log))
	for _, a := range f.log {
		out = append(out, a.snapshot())
	}
	return out
}

// signal wakes WaitIdle and settle. Called with f.mu held.
func (f *Fleet) signal() {
	close(f.changed)
	f.changed = make(chan struct{})
}

func (s *Server) acceptLoop() {
	defer s.f.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.f.closing:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		s.accept(c)
	}
}

// accept logs a connection (synchronously, so the log keeps accept order) and starts its handler.
func (s *Server) accept(c net.Conn) {
	f := s.f
	remote := c.RemoteAddr().String()
	f.mu.Lock()
	if f.sentinels[remote] {
		delete(f.sentinels, remote)
		f.signal()
		f.mu.Unlock()
		_ = c.Close()
		return
	}
	if f.closed {
		f.mu.Unlock()
		_ = c.Close()
		return
	}
	a := &access{kind: s.kind, local: c.LocalAddr().String(), remote: remote, start: wall.Now(),
		overflow: s.open.Load() >= int64(s.maxConns())}
	s.accepted.Add(1)
	if len(f.log) < f.o.MaxLog {
		f.log = append(f.log, a)
	} else {
		f.dropped++
	}
	if a.overflow {
		a.end, a.closed = wall.Now(), true
		f.signal()
		f.mu.Unlock()
		_ = c.Close()
		return
	}
	f.conns[a] = c
	f.active++
	s.open.Add(1)
	f.signal()
	f.mu.Unlock()
	f.wg.Add(1)
	go s.serve(c, a)
}

// maxConns is the server's open connection limit: the chain servers, which send megabytes per
// connection, have their own small one.
func (s *Server) maxConns() int {
	if s.kind == KindGiantChain || s.kind == KindHugeChain {
		return s.f.o.MaxChainConns
	}
	return s.f.o.MaxConns
}

// finish closes the connection and marks the entry closed.
func (s *Server) finish(c net.Conn, a *access) {
	_ = c.Close()
	f := s.f
	s.open.Add(-1)
	f.mu.Lock()
	delete(f.conns, a)
	a.end, a.closed = wall.Now(), true
	f.active--
	f.signal()
	f.mu.Unlock()
	f.wg.Done()
}

// countConn counts the bytes read and written on the wire.
type countConn struct {
	net.Conn
	a *access
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.a.read.Add(int64(n))
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.a.written.Add(int64(n))
	return n, err
}

// prefixConn replays bytes already read before reading on.
type prefixConn struct {
	net.Conn
	buf []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (s *Server) serve(raw net.Conn, a *access) {
	var helpers sync.WaitGroup
	defer func() {
		_ = raw.Close()
		helpers.Wait() // the entry is final once nothing reads or writes any more
		s.finish(raw, a)
	}()
	_ = raw.SetDeadline(wall.Now().Add(s.f.o.IdleTimeout))
	c := &countConn{Conn: raw, a: a}
	if s.kind == KindPlainText {
		s.plainText(c, &helpers)
		return
	}
	first, hello := readHello(c)
	s.f.mu.Lock()
	a.sni = hello.serverName
	s.f.mu.Unlock()
	if len(first) == 0 {
		return // the client left (or sent nothing before the deadline)
	}
	switch s.kind {
	case KindSlowLoris:
		s.slowLoris(c, &helpers)
	case KindGiantChain:
		s.giantChain(c, hello, &helpers)
	case KindReset:
		if tc, ok := raw.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // Close sends a reset
		}
	default:
		s.serveTLS(&prefixConn{Conn: c, buf: first}, a)
	}
}

// appCounter counts the application bytes received after the handshake.
type appCounter struct {
	a *access
	f *Fleet
}

func (w appCounter) Write(p []byte) (int, error) {
	w.a.app.Add(int64(len(p)))
	w.f.appBytes.Add(int64(len(p)))
	return len(p), nil
}

// maxAppBytes is how much a TLS server reads after the handshake before it stops reading and closes:
// an AppBytes of 1 MiB therefore means "at least 1 MiB" (the counter is a floor above it).
const maxAppBytes = 1 << 20

// serveTLS runs the handshake, then only reads (counting what arrives) until the client leaves. It
// never writes after the handshake: the TCP connection is closed under the TLS one, so not even a
// close_notify alert is sent.
func (s *Server) serveTLS(c net.Conn, a *access) {
	tc := tls.Server(c, s.material.tls)
	if err := tc.HandshakeContext(s.f.ctx); err != nil {
		return
	}
	a.handshake.Store(true)
	_, _ = io.Copy(appCounter{a: a, f: s.f}, io.LimitReader(tc, maxAppBytes))
}

// untilGone reads (and discards) until the client closes or the connection fails, then closes gone.
func untilGone(c net.Conn, helpers *sync.WaitGroup) <-chan struct{} {
	gone := make(chan struct{})
	helpers.Add(1)
	go func() {
		defer helpers.Done()
		defer close(gone)
		_, _ = io.Copy(io.Discard, io.LimitReader(c, maxAppBytes))
	}()
	return gone
}

// slowLorisPayload is what the slow-loris server trickles: the start of a handshake record that never ends.
var slowLorisPayload = []byte{22, 3, 3, 0x40, 0, 2, 0, 0x3f, 0xfc, 3, 3}

func (s *Server) slowLoris(c net.Conn, helpers *sync.WaitGroup) {
	gone := untilGone(c, helpers)
	t := time.NewTicker(s.f.o.SlowLorisInterval)
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-gone:
			return
		case <-s.f.closing:
			return
		case <-t.C:
		}
		b := slowLorisPayload[i%len(slowLorisPayload) : i%len(slowLorisPayload)+1]
		if _, err := c.Write(b); err != nil {
			return
		}
	}
}

// plainText writes its banner, then reads (for the log) until the client leaves, the connection's
// IdleTimeout passes or the fleet closes. Closing only after the client did means no unread byte is
// left behind, so the client never sees a reset.
func (s *Server) plainText(c net.Conn, helpers *sync.WaitGroup) {
	if _, err := io.WriteString(c, PlainTextBanner); err != nil {
		return
	}
	select {
	case <-untilGone(c, helpers):
	case <-s.f.closing:
	}
}

const recordMax = 16384

// giantChain answers a TLS 1.2 ServerHello and a Certificate message whose header claims the protocol
// maximum (2^24-1 bytes; TLS cannot frame a 100 MB message), then streams zero bytes of it, at most
// GiantBytes, in full-size records from one reused buffer, until the client leaves.
func (s *Server) giantChain(c net.Conn, h clientHello, helpers *sync.WaitGroup) {
	suite, ok := pickTLS12Suite(h.suites)
	if !ok {
		return
	}
	gone := untilGone(c, helpers)
	var random [32]byte
	_, _ = rand.Read(random[:])
	sh := []byte{2, 0, 0, 38, 3, 3}
	sh = append(sh, random[:]...)
	sh = append(sh, 0)                            // no session id
	sh = binary.BigEndian.AppendUint16(sh, suite) // the suite
	sh = append(sh, 0)                            // no compression
	first := append(sh, 11, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc)
	if _, err := c.Write(record(22, first)); err != nil {
		return
	}
	left := s.f.o.GiantBytes - 3               // the certificate_list length counts in the body
	rec := record(22, make([]byte, recordMax)) // one full record of zeros, written again and again
	for left > 0 {
		select {
		case <-gone:
			return
		case <-s.f.closing:
			return
		default:
		}
		n := min(int64(recordMax), left)
		if n < recordMax { // the last, partial record: only its length changes
			binary.BigEndian.PutUint16(rec[3:5], uint16(n)) //nolint:gosec // G115: n < recordMax
		}
		if _, err := c.Write(rec[:5+n]); err != nil {
			return
		}
		left -= n
	}
}

func record(typ byte, body []byte) []byte {
	out := make([]byte, 0, 5+len(body))
	out = append(out, typ, 3, 3)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body))) //nolint:gosec // G115: callers pass at most recordMax bytes
	return append(out, body...)
}

// pickTLS12Suite picks a TLS 1.2 suite the client offered.
func pickTLS12Suite(offered []uint16) (uint16, bool) {
	for _, want := range []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256} {
		for _, o := range offered {
			if o == want {
				return o, true
			}
		}
	}
	return 0, false
}
