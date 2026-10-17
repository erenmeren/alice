package fakesyslog

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func frame(msgs ...string) []byte {
	var b []byte
	for _, m := range msgs {
		b = fmt.Appendf(b, "%d %s", len(m), m)
	}
	return b
}

func eventually(t *testing.T, s *Server, n int) []string {
	t.Helper()
	require.Eventually(t, func() bool { return len(s.Messages()) >= n }, 5*time.Second, 10*time.Millisecond)
	return s.Messages()
}

func TestTLSReceiverParsesOctetCountedMessages(t *testing.T) {
	s := Start(t, Options{TLS: true})
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(s.CAPEM()))
	conn, err := tls.Dial("tcp", s.Addr(), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	// "é" is two bytes: the frame length counts octets, not runes.
	payload := frame("<37>1 one", "<36>1 two with spaces é")
	_, err = conn.Write(payload[:5]) // a frame split across writes
	require.NoError(t, err)
	_, err = conn.Write(payload[5:])
	require.NoError(t, err)
	assert.Equal(t, []string{"<37>1 one", "<36>1 two with spaces é"}, eventually(t, s, 2))
}

func TestTLSReceiverRefusesAnUntrustingClient(t *testing.T) {
	s := Start(t, Options{TLS: true})
	_, err := tls.Dial("tcp", s.Addr(), &tls.Config{ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	require.Error(t, err)
	var unknown x509.UnknownAuthorityError
	assert.ErrorAs(t, err, &unknown)
}

func TestPlainTCPAndUDP(t *testing.T) {
	s := Start(t, Options{UDP: true})
	c, err := net.Dial("tcp", s.Addr())
	require.NoError(t, err)
	_, err = c.Write(frame("<37>1 tcp"))
	require.NoError(t, err)
	require.NoError(t, c.Close())
	assert.Equal(t, []string{"<37>1 tcp"}, eventually(t, s, 1))

	u, err := net.Dial("udp", s.Addr())
	require.NoError(t, err)
	_, err = u.Write([]byte("<37>1 udp datagram"))
	require.NoError(t, err)
	require.NoError(t, u.Close())
	assert.Equal(t, []string{"<37>1 tcp", "<37>1 udp datagram"}, eventually(t, s, 2))
}

func TestNoUDPListenerUnlessAsked(t *testing.T) {
	s := Start(t, Options{})
	assert.Nil(t, s.udp)
}

func TestMalformedFrameDropsTheConnection(t *testing.T) {
	s := Start(t, Options{})
	c, err := net.Dial("tcp", s.Addr())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	_, err = c.Write([]byte("abc <37>1 x"))
	require.NoError(t, err)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Read(make([]byte, 1))
	require.Error(t, err, "the server closes the connection")
	assert.Empty(t, s.Messages())
}

func TestDownRefusesAndUpListensOnTheSamePort(t *testing.T) {
	s := Start(t, Options{UDP: true})
	addr := s.Addr()
	live, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	s.Down()
	s.Down() // idempotent
	_, err = net.DialTimeout("tcp", addr, time.Second)
	require.Error(t, err)
	_ = live.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = live.Read(make([]byte, 1))
	require.Error(t, err, "Down also closes open connections")
	_ = live.Close()

	require.NoError(t, s.Up())
	require.NoError(t, s.Up()) // idempotent
	assert.Equal(t, addr, s.Addr())
	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	_, err = c.Write(frame("<37>1 after up"))
	require.NoError(t, err)
	require.NoError(t, c.Close())
	assert.Equal(t, []string{"<37>1 after up"}, eventually(t, s, 1))
	s.Clear()
	assert.Empty(t, s.Messages())
}

// The goroutines below are driven synchronously: their exit paths (listener closed, peer gone, bad frame) otherwise
// run on a scheduler-dependent goroutine that may not get to execute before the test binary exits, which made the
// package's statement coverage vary between a fast machine and a loaded CI runner.

func TestAcceptReturnsWhenTheListenerIsClosed(t *testing.T) {
	s := &Server{conns: map[net.Conn]struct{}{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, ln.Close())
	s.accept(ln) // returns on the Accept error instead of blocking
	assert.Empty(t, s.conns)
}

func TestDatagramsReturnWhenTheSocketIsClosed(t *testing.T) {
	s := &Server{}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, pc.Close())
	s.datagrams(pc)
	assert.Empty(t, s.Messages())
}

func TestSessionEnds(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want []string
	}{
		"clean close":               {"", nil},
		"truncated body":            {"10 short", nil},
		"truncated after a message": {"2 ok5 abc", []string{"ok"}},
		"non digit":                 {"x", nil},
		"leading space":             {" 1 a", nil},
		"zero length":               {"0 ", nil},
		"too many digits":           {"1234567 a", nil},
		"over the frame bound":      {"65537 a", nil},
	} {
		t.Run(name, func(t *testing.T) {
			s := &Server{conns: map[net.Conn]struct{}{}}
			srv, cli := net.Pipe()
			s.conns[srv] = struct{}{}
			done := make(chan struct{})
			go func() { s.session(srv); close(done) }()
			go func() { _, _ = cli.Write([]byte(tc.in)); _ = cli.Close() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("session did not end")
			}
			assert.Equal(t, tc.want, s.Messages())
			assert.Empty(t, s.conns, "the session unregisters its connection")
		})
	}
}

func TestListenFailures(t *testing.T) {
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = hold.Close() }()
	s := &Server{conns: map[net.Conn]struct{}{}}
	require.Error(t, s.listen(hold.Addr().String()), "TCP port taken")

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()
	s = &Server{opts: Options{UDP: true}, conns: map[net.Conn]struct{}{}}
	require.Error(t, s.listen(pc.LocalAddr().String()), "UDP port taken: the TCP listener is released again")
	assert.Nil(t, s.ln)
}
