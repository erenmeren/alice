package linuxsshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// dialClient connects to s with a fresh authorized client key.
func dialClient(t *testing.T, s *Server) *ssh.Client {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s.Authorize(signer.PublicKey())
	host, port := s.Addr()
	c, err := ssh.Dial("tcp", host+":"+strconv.Itoa(port), &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(s.HostKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func runOn(t *testing.T, c *ssh.Client, cmd, stdin string) string {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	sess.Stdin = strings.NewReader(stdin)
	out, err := sess.Output(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// echoHandler answers the command line it was called with, then the stdin.
func echoHandler(cmd string, stdin []byte) Response {
	return Response{Stdout: []byte(cmd + "|" + string(stdin))}
}

func TestStickyFirstCommandRepeatsTheFirstLine(t *testing.T) {
	s := NewServer(t, echoHandler)
	s.StickyFirstCommand()
	c := dialClient(t, s)
	if got := runOn(t, c, "version", "a"); got != "version|a" {
		t.Fatalf("first session: %q", got)
	}
	if got := runOn(t, c, "win-facts", "b"); got != "version|b" {
		t.Fatalf("second session must see the first line with its own stdin: %q", got)
	}
	if got := s.Commands(); len(got) != 2 || got[0] != "version" || got[1] != "win-facts" {
		t.Fatalf("Commands keeps what the client sent: %v", got)
	}
	// Another connection starts again with its own first line.
	c2 := dialClient(t, s)
	if got := runOn(t, c2, "iis-dump", ""); got != "iis-dump|" {
		t.Fatalf("new connection: %q", got)
	}
}

func TestWithoutStickyEverySessionSeesItsOwnLine(t *testing.T) {
	s := NewServer(t, echoHandler)
	c := dialClient(t, s)
	if a, b := runOn(t, c, "version", ""), runOn(t, c, "win-facts", ""); a != "version|" || b != "win-facts|" {
		t.Fatalf("%q %q", a, b)
	}
}

func TestListenTakesAnAddressAndAKeyAndCloses(t *testing.T) {
	key := NewHostKey(t)
	s, err := Listen("127.0.0.1:0", key, echoHandler)
	if err != nil {
		t.Fatal(err)
	}
	if string(s.HostKey().Marshal()) != string(key.PublicKey().Marshal()) {
		t.Fatal("Listen must use the host key it is given")
	}
	c := dialClient(t, s)
	if got := runOn(t, c, "version", ""); got != "version|" {
		t.Fatalf("%q", got)
	}
	s.Close()
	s.Close() // idempotent
	if _, err := Listen("256.0.0.1:0", key, echoHandler); err == nil {
		t.Fatal("a bad address must be an error")
	}
}
