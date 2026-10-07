// Package fakesmtp is an SMTP server for tests (spec §22.1; §26.9 "MailHog-compatible"): STARTTLS (or implicit TLS)
// with a self-signed certificate generated when it starts, optional AUTH PLAIN, a message store with decoded subject
// and body, fault switches (down, a refused recipient) and a MailHog-compatible HTTP API. It is the Go suites' fake
// and the engine of cmd/alice-fakesmtp (the e2e container). It holds no secret of Alice's.
package fakesmtp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"alice/internal/platform/clock"
)

// Options configure the server.
type Options struct {
	Implicit   bool
	NoStartTLS bool
	Username   string
	Password   string
	Hostname   string
}

// Message is one accepted message.
type Message struct {
	From    string
	To      []string
	Subject string
	Body    string
	Raw     string
	Secure  bool
	Authed  bool
}

// Server is the fake.
type Server struct {
	opts    Options
	tlsCfg  *tls.Config
	certDER []byte

	mu       sync.Mutex
	ln       net.Listener
	addr     string
	messages []Message
	reject   string
}

// New generates the certificate. It does not listen yet.
func New(o Options) (*Server, error) {
	if o.Hostname == "" {
		o.Hostname = "127.0.0.1"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := clock.Real{}.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: o.Hostname},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(o.Hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{o.Hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &Server{opts: o, certDER: der, tlsCfg: &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}, nil
}

// Start is New and Listen on a free loopback port; t.Cleanup closes it.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Listen accepts connections on addr.
func (s *Server) Listen(addr string) error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	if s.opts.Implicit {
		ln = tls.NewListener(ln, s.tlsCfg)
	}
	s.mu.Lock()
	s.ln, s.addr = ln, ln.Addr().String()
	s.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.session(c)
		}
	}()
	return nil
}

// Addr is the listening address.
func (s *Server) Addr() (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	host, port, _ := net.SplitHostPort(s.addr)
	p, _ := strconv.Atoi(port)
	return host, p
}

// CertPEM is the server certificate.
func (s *Server) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.certDER})
}

// Fingerprint is the lower-case hex SHA-256 of the certificate's DER.
func (s *Server) Fingerprint() string {
	sum := sha256.Sum256(s.certDER)
	return hex.EncodeToString(sum[:])
}

// Messages returns a copy of the stored messages.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

// Clear forgets every stored message.
func (s *Server) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = nil
}

// Down closes the listener: new connections are refused until Up.
func (s *Server) Down() {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

// Up listens again on the previous address.
func (s *Server) Up() error {
	s.mu.Lock()
	addr, up := s.addr, s.ln != nil
	s.mu.Unlock()
	if up {
		return nil
	}
	return s.Listen(addr)
}

// RejectRecipient makes RCPT TO addr answer 550; "" clears.
func (s *Server) RejectRecipient(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reject = addr
}

// Close stops the server.
func (s *Server) Close() { s.Down() }

func addrOf(arg string) string {
	_, v, _ := strings.Cut(arg, ":")
	return strings.Trim(strings.TrimSpace(v), "<>")
}

func (s *Server) session(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(clock.Real{}.Now().Add(time.Minute))
	tp := textproto.NewConn(conn)
	reply := func(format string, args ...any) { _ = tp.PrintfLine(format, args...) }
	secure, authed := s.opts.Implicit, false
	var from string
	var to []string
	reply("220 fakesmtp ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		is := func(v string) bool { return strings.EqualFold(verb, v) }
		switch {
		case is("EHLO"), is("HELO"):
			lines := []string{"fakesmtp greets you"}
			if !secure && !s.opts.NoStartTLS {
				lines = append(lines, "STARTTLS")
			}
			if secure && s.opts.Username != "" {
				lines = append(lines, "AUTH PLAIN")
			}
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				reply("250%s%s", sep, l)
			}
		case is("STARTTLS"):
			if secure || s.opts.NoStartTLS {
				reply("503 5.5.1 TLS not available")
				continue
			}
			reply("220 2.0.0 ready")
			tc := tls.Server(conn, s.tlsCfg)
			if err := tc.HandshakeContext(context.Background()); err != nil {
				return
			}
			conn, tp, secure = tc, textproto.NewConn(tc), true
		case is("AUTH"):
			mech, payload, _ := strings.Cut(arg, " ")
			raw, err := base64.StdEncoding.DecodeString(payload)
			parts := strings.Split(string(raw), "\x00")
			if !strings.EqualFold(mech, "PLAIN") || !secure || err != nil || len(parts) != 3 ||
				parts[1] != s.opts.Username || parts[2] != s.opts.Password {
				reply("535 5.7.8 authentication failed")
				continue
			}
			authed = true
			reply("235 2.7.0 authenticated")
		case is("MAIL"):
			if s.opts.Username != "" && !authed {
				reply("530 5.7.0 authentication required")
				continue
			}
			from, to = addrOf(arg), nil
			reply("250 2.1.0 ok")
		case is("RCPT"):
			rcpt := addrOf(arg)
			s.mu.Lock()
			rejected := s.reject != "" && strings.EqualFold(rcpt, s.reject)
			s.mu.Unlock()
			if rejected {
				reply("550 5.1.1 mailbox unavailable")
				continue
			}
			to = append(to, rcpt)
			reply("250 2.1.5 ok")
		case is("DATA"):
			if from == "" || len(to) == 0 {
				reply("503 5.5.1 need MAIL and RCPT")
				continue
			}
			reply("354 go ahead")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			s.store(from, to, data, secure, authed)
			from, to = "", nil
			reply("250 2.0.0 queued")
		case is("RSET"):
			from, to = "", nil
			reply("250 2.0.0 ok")
		case is("NOOP"):
			reply("250 2.0.0 ok")
		case is("QUIT"):
			reply("221 2.0.0 bye")
			return
		default:
			reply("502 5.5.2 unknown command")
		}
	}
}

func (s *Server) store(from string, to []string, data []byte, secure, authed bool) {
	m := Message{From: from, To: to, Raw: string(data), Secure: secure, Authed: authed}
	if msg, err := mail.ReadMessage(bytes.NewReader(data)); err == nil {
		if subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject")); err == nil {
			m.Subject = subject
		}
		body, _ := io.ReadAll(msg.Body)
		if strings.EqualFold(msg.Header.Get("Content-Transfer-Encoding"), "base64") {
			if dec, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), "")); err == nil {
				body = dec
			}
		}
		m.Body = strings.ReplaceAll(string(body), "\r\n", "\n")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, m)
}
