package netaddr_test

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
	"alice/internal/platform/netaddr/netaddrtest"
)

// Every address form Alice may meet at connect time, with the verdict of the one rule shared with
// target validation (SEC-065, AUD-25 a).
func TestAllowedEveryAddressForm(t *testing.T) {
	for a, want := range map[string]bool{
		// Loopback and private addresses are managed servers (the product allows them when a target
		// is added; the e2e stack and the tests use them).
		"127.0.0.1": true, "127.1.2.3": true, "::1": true, "10.0.0.5": true, "172.16.0.1": true, "192.168.1.1": true,
		"100.64.0.1": true, "fc00::1": true, "fd12:3456::1": true, "192.0.2.10": true, "2001:db8::1": true,
		"::ffff:127.0.0.1": true, "::ffff:10.0.0.5": true,
		// Link-local, the cloud metadata address and its IPv6 forms.
		"169.254.169.254": false, "169.254.0.1": false, "fe80::1": false, "::ffff:169.254.169.254": false,
		"64:ff9b::a9fe:a9fe": false, "2002:a9fe:a9fe::1": false, "fd00:ec2::254": false,
		"64:ff9b:1:a9fe:a9:fea9:fe00:0": false, "64:ff9b:1::a9fe:a9fe": false,
		// NAT64 and 6to4 forms of a server address are servers.
		"64:ff9b::a00:5": true, "2002:a00:5::1": true, "64:ff9b:1::a00:5": true,
		// Multicast, unspecified, broadcast (0.0.0.0 and :: reach the host's own services).
		"224.0.0.1": false, "239.255.255.250": false, "ff02::1": false, "ff05::2": false, "0.0.0.0": false, "::": false,
		"::ffff:0.0.0.0": false, "255.255.255.255": false, "::ffff:255.255.255.255": false, "64:ff9b::ffff:ffff": false,
		"64:ff9b::": false, "2002::1": false,
		// A zone never names a managed server: target validation refuses it as typed, and a resolver
		// never returns one from DNS.
		"fe80::1%eth0": false, "2001:db8::1%eth0": false, "::1%lo": false,
	} {
		assert.Equal(t, want, netaddr.Allowed(netip.MustParseAddr(a)), a)
	}
	assert.False(t, netaddr.Allowed(netip.Addr{}), "the zero Addr")
}

func TestControl(t *testing.T) {
	assert.ErrorIs(t, netaddr.Control("tcp4", "169.254.169.254:22", nil), netaddr.ErrNotAllowed)
	assert.ErrorIs(t, netaddr.Control("tcp6", "[fe80::1%eth0]:22", nil), netaddr.ErrNotAllowed)
	assert.ErrorIs(t, netaddr.Control("tcp6", "[::ffff:169.254.169.254]:22", nil), netaddr.ErrNotAllowed)
	assert.NoError(t, netaddr.Control("tcp4", "127.0.0.1:22", nil))
	assert.NoError(t, netaddr.Control("tcp6", "[2001:db8::1]:22", nil))
	assert.ErrorIs(t, netaddr.Control("tcp", "not an address", nil), netaddr.ErrNotAllowed, "unparsable: refused")
}

// counter is a listener on 127.0.0.1 that counts the connections it accepted.
type counter struct {
	ln       net.Listener
	accepted atomic.Int64
}

func listen(t *testing.T) *counter {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	c := &counter{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.accepted.Add(1)
			_ = conn.Close()
		}
	}()
	return c
}

func (c *counter) port() string { return strconv.Itoa(c.ln.Addr().(*net.TCPAddr).Port) }

// settled waits until the listener accepted want connections and checks that no other arrives.
func (c *counter) settled(t *testing.T, want int64) {
	t.Helper()
	require.Eventually(t, func() bool { return c.accepted.Load() >= want }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, want, c.accepted.Load())
}

// table resolves every name from a fixed table (nil: no such name).
func table(m map[string][]string) *net.Resolver {
	return netaddrtest.Resolver(func(name string) []netip.Addr {
		var out []netip.Addr
		for _, s := range m[name] {
			out = append(out, netip.MustParseAddr(s))
		}
		return out
	})
}

func dial(r *net.Resolver, address string) (net.Conn, error) {
	return netaddr.DialContext(context.Background(), &net.Dialer{Timeout: 5 * time.Second, Resolver: r}, "tcp", address)
}

// AUD-25 (a): the address a name resolves to is checked on the socket Alice is about to connect,
// after resolution, so the checked address is the connected one: no second lookup, DNS rebinding
// included. 0.0.0.0 is the sharpest case: on Linux a connection to it reaches the host's own
// loopback listeners.
func TestDialContextChecksTheResolvedAddress(t *testing.T) {
	srv := listen(t)
	r := table(map[string][]string{
		"server.alice.test":   {"127.0.0.1"},
		"rebound.alice.test":  {"0.0.0.0"},
		"metadata.alice.test": {"169.254.169.254"},
		"mixed.alice.test":    {"0.0.0.0", "127.0.0.1"},
	})

	_, err := dial(r, "rebound.alice.test:"+srv.port())
	require.ErrorIs(t, err, netaddr.ErrNotAllowed)
	_, err = dial(r, "metadata.alice.test:"+srv.port())
	require.ErrorIs(t, err, netaddr.ErrNotAllowed)
	_, err = dial(nil, "169.254.169.254:"+srv.port())
	require.ErrorIs(t, err, netaddr.ErrNotAllowed, "a literal is checked the same way")
	_, err = dial(nil, "[::ffff:0.0.0.0]:"+srv.port())
	require.ErrorIs(t, err, netaddr.ErrNotAllowed, "the IPv4-mapped form too")

	c, err := dial(r, "server.alice.test:"+srv.port())
	require.NoError(t, err)
	_ = c.Close()
	srv.settled(t, 1) // only the allowed name reached the listener

	// Every candidate of a name is checked: the refused one is never connected, an allowed one is.
	c, err = dial(r, "mixed.alice.test:"+srv.port())
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", c.RemoteAddr().(*net.TCPAddr).IP.String())
	_ = c.Close()
	srv.settled(t, 2)

	// Control: without the check, the refused address does reach the listener on this host (the
	// test above is meaningful).
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", "0.0.0.0:"+srv.port())
	require.NoError(t, err)
	_ = raw.Close()
	srv.settled(t, 3)
}

// When no candidate connects and one was refused, the refusal is the answer whatever the order of
// the records: the name resolves to an address Alice does not connect to (fix DNS), which a refused
// or timed-out allowed address must not hide.
func TestDialContextReportsARefusalAmongFailures(t *testing.T) {
	srv := listen(t)
	closed := srv.port()
	require.NoError(t, srv.ln.Close())
	for _, order := range [][]string{{"0.0.0.0", "127.0.0.1"}, {"127.0.0.1", "0.0.0.0"}, {"169.254.169.254", "::1"}} {
		_, err := dial(table(map[string][]string{"down.alice.test": order}), "down.alice.test:"+closed)
		require.ErrorIs(t, err, netaddr.ErrNotAllowed, "%v", order)
	}
	_, err := dial(table(map[string][]string{"down.alice.test": {"127.0.0.1"}}), "down.alice.test:"+closed)
	require.Error(t, err)
	assert.NotErrorIs(t, err, netaddr.ErrNotAllowed, "a plain refused connection stays what it is")
	_, err = dial(table(nil), "missing.alice.test:"+closed)
	require.Error(t, err)
	assert.NotErrorIs(t, err, netaddr.ErrNotAllowed, "a name that does not resolve is not a refusal")
}
