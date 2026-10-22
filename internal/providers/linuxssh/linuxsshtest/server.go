// Package linuxsshtest provides an in-process SSH server and an alice-helper emulator for the
// tests of the linuxssh provider and of the packages that use it. It is never linked into the
// alice binary (only test files import it).
package linuxsshtest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Response is what the server answers to one exec request.
type Response struct {
	Stdout []byte
	Stderr []byte
	// Exit is the exit status; a negative value closes the channel without an exit status.
	Exit int
	// Signal, when set, ends the command with an exit-signal request (a killed helper) instead of an
	// exit status.
	Signal string
	// Delay is waited before answering (a slow host, F-39). The wait ends early when the client
	// closes the connection.
	Delay time.Duration
	// Hangup closes the whole SSH connection instead of answering (a dropped connection, F-08):
	// the client sees a transport error, not an exit status.
	Hangup bool
	// StallReadLoop answers with a malformed exit-status (a payload shorter than 4 bytes) and then
	// more channel requests than x/crypto/ssh buffers, and holds the channel open (final review
	// A2-I1): the client's session stops reading its requests, the connection's read loop blocks on
	// a full Go channel, and closing the socket can no longer wake it.
	StallReadLoop bool
}

// Handler answers one command line; stdin is everything the client sent before closing its input.
type Handler func(cmd string, stdin []byte) Response

// Server is an SSH server on 127.0.0.1 that accepts one authorized client key, records every
// authentication attempt and every exec command line, and answers commands with a Handler.
type Server struct {
	ln   net.Listener
	done chan struct{}
	wg   sync.WaitGroup

	mu         sync.Mutex
	signers    []ssh.Signer
	authorized []byte
	handler    Handler
	attempts   int
	commands   []string
	sessionIDs [][]byte
	conns      map[net.Conn]struct{}
	accepted   int
	noPubkey   bool
	noAuth     bool
	hangGlobal bool
	holdOpens  bool
	maxAuth    int // SetMaxAuthTries
	loginCheck func(user string, key ssh.PublicKey) bool
	stall      bool
	sticky     bool
	closeOnce  sync.Once
}

// StallHandshake makes the server accept TCP connections from now on and say nothing: the client
// waits for the SSH version banner until it gives up or closes the connection.
func (s *Server) StallHandshake() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stall = true
}

// OpenConnections is the number of TCP connections currently open on the server side (a closed
// client connection leaves this count once the server noticed).
func (s *Server) OpenConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Connections is the number of TCP connections the server accepted (every dial, whether or not
// it got as far as authentication).
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// HangGlobalRequests makes the server leave global requests (OpenSSH's keepalive probe)
// unanswered on connections opened from now on.
func (s *Server) HangGlobalRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hangGlobal = true
}

// HoldChannelOpens makes the server leave every channel open from now on unanswered (neither
// confirmed nor refused), on every connection: the client's new session waits for an answer that
// never comes while the connection stays up.
func (s *Server) HoldChannelOpens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.holdOpens = true
}

// SetMaxAuthTries sets x/crypto's MaxAuthTries for connections from now on: after n failed
// attempts the server disconnects with "too many authentication failures" (as OpenSSH's
// MaxAuthTries does).
func (s *Server) SetMaxAuthTries(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxAuth = n
}

// DisablePublicKeyAuth makes the server offer password authentication only (never accepted).
func (s *Server) DisablePublicKeyAuth() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noPubkey = true
}

// AcceptNoAuth makes the server accept every client without authentication.
func (s *Server) AcceptNoAuth() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noAuth = true
}

// NewServer starts a server on 127.0.0.1 with a random Ed25519 host key. It stops when the test ends.
func NewServer(t testing.TB, h Handler) *Server {
	t.Helper()
	s, err := Listen("127.0.0.1:0", NewHostKey(t), h)
	if err != nil {
		t.Fatalf("linuxsshtest: listen: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// Listen starts a server on addr with the given host key. Close stops it. NewServer is Listen on a
// random loopback port with a random host key; a test tool that runs outside a test (the e2e fake
// of a host) uses Listen with its own address and key.
func Listen(addr string, hostKey ssh.Signer, h Handler) (*Server, error) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{
		ln:      ln,
		done:    make(chan struct{}),
		signers: []ssh.Signer{hostKey},
		handler: h,
		conns:   map[net.Conn]struct{}{},
	}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Close stops the server and drops its connections. It may be called more than once.
func (s *Server) Close() {
	s.closeOnce.Do(s.stop)
}

// StickyFirstCommand models Windows OpenSSH (design 2026-10-21 §8, phase W0): every exec session
// after the first on one connection is handed the FIRST session's command line (its standard input
// stays its own). Commands still records what the client actually sent. Off by default.
func (s *Server) StickyFirstCommand() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sticky = true
}

func (s *Server) stop() {
	close(s.done)
	_ = s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Addr returns the address clients dial.
func (s *Server) Addr() (host string, port int) {
	a := s.ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// HostKey returns the first host key the server offers.
func (s *Server) HostKey() ssh.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signers[0].PublicKey()
}

// SetHostKey makes the next connections see another host key (a reinstalled server or a MITM, F-31).
// A reinstalled server drops every open connection, so pooled connections cannot hide the change.
func (s *Server) SetHostKey(k ssh.Signer) {
	s.SetHostKeyAlgorithms(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}

// SetHostKeyAlgorithms makes the server offer exactly these host keys from the next connection on.
func (s *Server) SetHostKeyAlgorithms(signers ...ssh.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signers = append([]ssh.Signer(nil), signers...)
}

// Authorize sets the one client key the server accepts.
func (s *Server) Authorize(k ssh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorized = k.Marshal()
}

// AuthAttempts counts public-key authentication callbacks over all connections.
func (s *Server) AuthAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

// Commands returns every exec command line received, in order.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

// SessionIDs returns the SSH session identifier (the key-exchange hash) of every connection that
// completed its handshake, so leak tests can look for session material in Alice's output.
func (s *Server) SessionIDs() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, 0, len(s.sessionIDs))
	for _, id := range s.sessionIDs {
		out = append(out, append([]byte(nil), id...))
	}
	return out
}

// SetHandler replaces the command handler.
func (s *Server) SetHandler(h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = h
}

// NewHostKey returns a random Ed25519 signer.
func NewHostKey(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("linuxsshtest: ed25519 key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("linuxsshtest: signer: %v", err)
	}
	return s
}

// NewECDSAHostKey returns a random ECDSA P-256 signer.
func NewECDSAHostKey(t testing.TB) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("linuxsshtest: ecdsa key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("linuxsshtest: signer: %v", err)
	}
	return s
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
		s.accepted++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(c)
		}()
	}
}

// SetLoginCheck makes the server also accept a public key that check accepts for the user (the
// one key of Authorize keeps working as before).
func (s *Server) SetLoginCheck(check func(user string, key ssh.PublicKey) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loginCheck = check
}

func (s *Server) checkKey(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	s.attempts++
	ok := s.authorized != nil && bytes.Equal(key.Marshal(), s.authorized)
	check := s.loginCheck
	s.mu.Unlock()
	if ok {
		return &ssh.Permissions{}, nil
	}
	// The check runs outside s.mu: an emulator takes its own lock.
	if check != nil && check(meta.User(), key) {
		return &ssh.Permissions{}, nil
	}
	return nil, errors.New("linuxsshtest: key not authorized")
}

func (s *Server) handleConn(c net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		_ = c.Close()
	}()
	cfg := &ssh.ServerConfig{PublicKeyCallback: s.checkKey}
	s.mu.Lock()
	for _, k := range s.signers {
		cfg.AddHostKey(k)
	}
	if s.noPubkey {
		cfg.PublicKeyCallback = nil
		cfg.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, errors.New("linuxsshtest: password not accepted")
		}
	}
	cfg.NoClientAuth = s.noAuth
	cfg.MaxAuthTries = s.maxAuth
	hang := s.hangGlobal
	stall := s.stall
	s.mu.Unlock()
	if stall {
		_, _ = io.Copy(io.Discard, c) // returns when the client closes
		return
	}
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.sessionIDs = append(s.sessionIDs, append([]byte(nil), sc.SessionID()...))
	s.mu.Unlock()
	if hang {
		go func() {
			for range reqs { // never replied: the client's probe waits until it gives up
			}
		}()
	} else {
		go ssh.DiscardRequests(reqs)
	}
	closed := make(chan struct{})
	go func() {
		_ = sc.Wait()
		close(closed)
	}()
	var sessions sync.WaitGroup
	first := &firstCommand{}
	for nc := range chans {
		s.mu.Lock()
		hold := s.holdOpens
		s.mu.Unlock()
		if hold {
			continue // never answered: the open stays pending until the connection closes
		}
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			s.serveSession(ch, creqs, closed, sc, first)
		}()
	}
	sessions.Wait()
}

// firstCommand is the first exec line of one connection (StickyFirstCommand).
type firstCommand struct {
	mu   sync.Mutex
	line string
	set  bool
}

// resolve returns the line the handler is called with: the first line of the connection.
func (f *firstCommand) resolve(line string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.set {
		f.line, f.set = line, true
	}
	return f.line
}

func (s *Server) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, closed <-chan struct{}, conn ssh.Conn, first *firstCommand) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		var p struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			_ = req.Reply(false, nil)
			continue
		}
		_ = req.Reply(true, nil)
		s.mu.Lock()
		s.commands = append(s.commands, p.Command)
		h := s.handler
		sticky := s.sticky
		s.mu.Unlock()
		line := p.Command
		if sticky {
			line = first.resolve(p.Command)
		}
		stdin, err := io.ReadAll(ch)
		if err != nil {
			return
		}
		resp := Response{Stderr: []byte("sh: command not found\n"), Exit: 127}
		if h != nil {
			resp = h(line, stdin)
		}
		if resp.Hangup {
			_ = conn.Close()
			return
		}
		if resp.Delay > 0 {
			select {
			case <-time.After(resp.Delay):
			case <-closed:
				return
			case <-s.done:
				return
			}
		}
		_, _ = ch.Write(resp.Stdout)
		_, _ = ch.Stderr().Write(resp.Stderr)
		if resp.StallReadLoop {
			_, _ = ch.SendRequest("exit-status", false, []byte{0})
			for range 32 {
				_, _ = ch.SendRequest("keepalive@openssh.com", false, nil)
			}
			select {
			case <-closed:
			case <-s.done:
			}
			return
		}
		if resp.Signal != "" {
			sig := struct {
				Signal     string
				CoreDumped bool
				Error      string
				Lang       string
			}{Signal: resp.Signal}
			_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(sig))
		} else if resp.Exit >= 0 {
			status := struct{ Status uint32 }{uint32(resp.Exit)} //nolint:gosec // G115: test exit codes are small non-negative numbers
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(status))
		}
		return
	}
}
