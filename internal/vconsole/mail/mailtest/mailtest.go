// Package mailtest is a small in-process SMTP server for tests only; no non-test code imports
// it. It speaks just enough ESMTP for the vendor console's sender: EHLO, STARTTLS with a
// throw-away self-signed certificate made at start, AUTH PLAIN, MAIL, RCPT and DATA (with
// dot-unstuffing). It records every accepted message and every set of AUTH credentials it was
// shown, and can misbehave on request (no STARTTLS, silence, refusing RCPT or AUTH, echoing
// what the client sent back in error replies).
package mailtest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// Options switch on the server's misbehaviours. The zero value is a well-behaved server that
// offers STARTTLS and accepts any AUTH PLAIN.
type Options struct {
	// NoSTARTTLS stops the server from advertising STARTTLS (AUTH PLAIN is still advertised, so
	// a test can check the client does not send credentials over plain text).
	NoSTARTTLS bool
	// ImplicitTLS makes the server start TLS right after accepting, as on port 465.
	ImplicitTLS bool
	// Silent accepts connections and never says anything.
	Silent bool
	// RejectRCPT answers every RCPT with 550.
	RejectRCPT bool
	// FailAuth answers every AUTH with 535 (the credentials are still recorded).
	FailAuth bool
	// Echo makes every error reply repeat the command line and the last decoded AUTH
	// credentials, like a careless server would; it proves the client keeps them out of errors.
	Echo bool
}

// Message is one message the server accepted.
type Message struct {
	From string   // envelope sender
	To   []string // envelope recipients
	Data []byte   // DATA content after dot-unstuffing, CRLF line endings
}

// Credentials are what a client presented with AUTH PLAIN.
type Credentials struct {
	Identity string
	User     string
	Password string
	TLS      bool // whether the connection was encrypted when AUTH was sent
}

// Server is a running test SMTP server on 127.0.0.1.
type Server struct {
	opts Options
	ln   net.Listener
	tls  *tls.Config
	pool *x509.CertPool

	mu    sync.Mutex
	msgs  []Message
	auths []Credentials
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

// TB is the part of testing.TB that Start uses. The package does not import testing so that
// the release-build rule (no test code in non-test files) holds for it too.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// Start runs a server until the test ends.
func Start(t TB, o Options) *Server {
	t.Helper()
	cert, pool, err := selfSigned()
	if err != nil {
		t.Fatalf("mailtest: certificate: %v", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mailtest: listen: %v", err)
	}
	s := &Server{
		opts:  o,
		ln:    ln,
		tls:   &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		pool:  pool,
		conns: map[net.Conn]struct{}{},
	}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// Addr is the server's host:port.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// CertPool trusts the server's throw-away certificate (valid for 127.0.0.1 and localhost).
func (s *Server) CertPool() *x509.CertPool { return s.pool }

// Messages returns a copy of the accepted messages.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.msgs...)
}

// Auths returns a copy of every set of AUTH credentials presented.
func (s *Server) Auths() []Credentials {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Credentials(nil), s.auths...)
}

// Close stops the server and drops open connections. It is safe to call more than once.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				_ = c.Close()
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
			}()
			s.handle(c)
		}()
	}
}

type session struct {
	s        *Server
	conn     net.Conn
	r        *bufio.Reader
	w        *bufio.Writer
	tls      bool
	from     string
	to       []string
	lastAuth string
}

func (s *Server) handle(c net.Conn) {
	if s.opts.Silent {
		// Read and discard until the client or Close hangs up; never answer.
		buf := make([]byte, 512)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}
	ss := &session{s: s, conn: c}
	if s.opts.ImplicitTLS {
		tc := tls.Server(c, s.tls)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			return
		}
		ss.conn, ss.tls = tc, true
	}
	ss.reset()
	ss.reply("220 mailtest ESMTP")
	for {
		line, err := ss.readLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch {
		case strings.EqualFold(verb, "EHLO"), strings.EqualFold(verb, "HELO"):
			ss.reply("250-mailtest")
			if !ss.tls && !s.opts.NoSTARTTLS {
				ss.reply("250-STARTTLS")
			}
			ss.reply("250-AUTH PLAIN")
			ss.reply("250 8BITMIME")
		case strings.EqualFold(verb, "STARTTLS"):
			if ss.tls || s.opts.NoSTARTTLS {
				ss.fail("502 5.5.1 STARTTLS not available", line)
				continue
			}
			ss.reply("220 2.0.0 ready to start TLS")
			tc := tls.Server(ss.conn, s.tls)
			if err := tc.HandshakeContext(context.Background()); err != nil {
				return
			}
			ss.conn, ss.tls = tc, true
			ss.reset()
		case strings.EqualFold(verb, "AUTH"):
			ss.auth(line, arg)
		case strings.EqualFold(verb, "MAIL"):
			ss.from = pathArg(arg, "FROM:")
			ss.to = nil
			ss.reply("250 2.1.0 ok")
		case strings.EqualFold(verb, "RCPT"):
			if s.opts.RejectRCPT {
				ss.fail("550 5.1.1 recipient refused", line)
				continue
			}
			ss.to = append(ss.to, pathArg(arg, "TO:"))
			ss.reply("250 2.1.5 ok")
		case strings.EqualFold(verb, "DATA"):
			ss.data()
		case strings.EqualFold(verb, "RSET"), strings.EqualFold(verb, "NOOP"):
			ss.reply("250 2.0.0 ok")
		case strings.EqualFold(verb, "QUIT"):
			ss.reply("221 2.0.0 bye")
			return
		default:
			ss.fail("502 5.5.2 command not recognised", line)
		}
	}
}

func (ss *session) reset() {
	ss.r = bufio.NewReader(ss.conn)
	ss.w = bufio.NewWriter(ss.conn)
}

func (ss *session) readLine() (string, error) {
	l, err := ss.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(l, "\r\n"), nil
}

func (ss *session) reply(l string) {
	_, _ = ss.w.WriteString(l + "\r\n")
	_ = ss.w.Flush()
}

// fail sends an error reply; in Echo mode it repeats what the client said, credentials too.
func (ss *session) fail(l, said string) {
	if ss.s.opts.Echo {
		l += " (you said: " + said + "; auth: " + ss.lastAuth + ")"
	}
	ss.reply(l)
}

func (ss *session) auth(line, arg string) {
	mech, initial, _ := strings.Cut(arg, " ")
	if !strings.EqualFold(mech, "PLAIN") {
		ss.fail("504 5.5.4 mechanism not supported", line)
		return
	}
	if initial == "" {
		ss.reply("334 ")
		l, err := ss.readLine()
		if err != nil {
			return
		}
		initial = l
	}
	raw, err := base64.StdEncoding.DecodeString(initial)
	parts := strings.Split(string(raw), "\x00")
	if err != nil || len(parts) != 3 {
		ss.fail("501 5.5.2 bad AUTH PLAIN response", line)
		return
	}
	ss.s.mu.Lock()
	ss.s.auths = append(ss.s.auths, Credentials{Identity: parts[0], User: parts[1], Password: parts[2], TLS: ss.tls})
	ss.s.mu.Unlock()
	ss.lastAuth = strings.Join(parts, " ")
	if ss.s.opts.FailAuth {
		ss.fail("535 5.7.8 authentication failed", line)
		return
	}
	ss.reply("235 2.7.0 authenticated")
}

func (ss *session) data() {
	ss.reply("354 end with <CRLF>.<CRLF>")
	var b strings.Builder
	for {
		l, err := ss.readLine()
		if err != nil {
			return
		}
		if l == "." {
			break
		}
		// RFC 5321 section 4.5.2: a leading dot was doubled by the client.
		l = strings.TrimPrefix(l, ".")
		b.WriteString(l + "\r\n")
	}
	ss.s.mu.Lock()
	ss.s.msgs = append(ss.s.msgs, Message{From: ss.from, To: ss.to, Data: []byte(b.String())})
	ss.s.mu.Unlock()
	ss.to = nil
	ss.reply("250 2.0.0 queued")
}

// pathArg pulls the address out of "FROM:<a@b> SIZE=1" style arguments.
func pathArg(arg, prefix string) string {
	if len(arg) >= len(prefix) && strings.EqualFold(arg[:len(prefix)], prefix) {
		arg = arg[len(prefix):]
	}
	arg, _, _ = strings.Cut(strings.TrimSpace(arg), " ")
	return strings.TrimSuffix(strings.TrimPrefix(arg, "<"), ">")
}

// selfSigned makes a throw-away certificate. The validity window is fixed and wide so the
// package needs no clock.
func selfSigned() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mailtest"},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool, nil
}
