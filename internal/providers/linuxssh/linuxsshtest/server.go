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
	noPubkey   bool
	noAuth     bool
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

// NewServer starts a server with a random Ed25519 host key. It stops when the test ends.
func NewServer(t testing.TB, h Handler) *Server {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("linuxsshtest: listen: %v", err)
	}
	s := &Server{
		ln:      ln,
		done:    make(chan struct{}),
		signers: []ssh.Signer{NewHostKey(t)},
		handler: h,
		conns:   map[net.Conn]struct{}{},
	}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.stop)
	return s
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
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(c)
		}()
	}
}

func (s *Server) checkKey(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.authorized != nil && bytes.Equal(key.Marshal(), s.authorized) {
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
	s.mu.Unlock()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.sessionIDs = append(s.sessionIDs, append([]byte(nil), sc.SessionID()...))
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	closed := make(chan struct{})
	go func() {
		_ = sc.Wait()
		close(closed)
	}()
	var sessions sync.WaitGroup
	for nc := range chans {
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
			s.serveSession(ch, creqs, closed)
		}()
	}
	sessions.Wait()
}

func (s *Server) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, closed <-chan struct{}) {
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
		s.mu.Unlock()
		stdin, err := io.ReadAll(ch)
		if err != nil {
			return
		}
		resp := Response{Stderr: []byte("sh: command not found\n"), Exit: 127}
		if h != nil {
			resp = h(p.Command, stdin)
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
