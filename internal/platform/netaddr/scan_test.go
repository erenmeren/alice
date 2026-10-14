package netaddr_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/netaddr/netaddrtest"
)

// The address inputs of the table test: Alice's own interface addresses, its default gateway, the
// database host the DSN names, an Admin global exclusion and a scope exclusion.
var (
	ownAddrs  = []string{"10.1.2.3", "fd12::3", "fe80::3"}
	gateways  = []string{"10.1.2.1", "fd12::1"}
	dbAddrs   = []string{"10.1.2.50", "fd12::50"}
	globalEx  = []string{"10.9.0.0/16", "fd12:9::/32"}
	scopeEx   = []string{"10.8.0.0/24", "10.7.7.7/32"}
	everyAddr = []string{"0.0.0.0/0", "::/0"}
)

func addrs(t *testing.T, ss []string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func prefixes(t *testing.T, ss []string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// inputs is a ScanPolicyInputs whose every system source is a stub: no real interface, route
// table or DNS server is read.
func inputs(t *testing.T, allowed []string) netaddr.ScanPolicyInputs {
	t.Helper()
	return netaddr.ScanPolicyInputs{
		AllowedNetworks:  prefixes(t, allowed),
		GlobalExclusions: prefixes(t, globalEx),
		ScopeExclusions:  prefixes(t, scopeEx),
		DatabaseURL:      "postgres://alice_app:secret@db.alice.test:5432/alice?sslmode=verify-full",
		InterfaceAddrs:   func() ([]netip.Addr, error) { return addrs(t, ownAddrs), nil },
		DefaultGateways:  func() ([]netip.Addr, error) { return addrs(t, gateways), nil },
		LookupHost: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "db.alice.test" {
				return addrs(t, dbAddrs), nil
			}
			return nil, errors.New("no such host")
		},
	}
}

func policy(t *testing.T, allowed []string) netaddr.ScanPolicy {
	t.Helper()
	p, err := netaddr.NewScanPolicy(context.Background(), inputs(t, allowed))
	require.NoError(t, err)
	return p
}

// Review Focus 1: every spelling of an address discovery must never connect to, with the Admin
// allowlist opened to everything so that each refusal stands on its own rule.
func TestScanPolicyEverySpelling(t *testing.T) {
	p := policy(t, everyAddr)
	for a, want := range map[string]bool{
		// Loopback, in every form that reaches it.
		"127.0.0.1": false, "127.1.2.3": false, "127.255.255.254": false, "::1": false,
		"::ffff:127.0.0.1": false, "64:ff9b::7f00:1": false, "2002:7f00:1::": false, "2002:7f00:1::1": false,
		// Unspecified (reaches the host's own services on Linux).
		"0.0.0.0": false, "::": false, "::ffff:0.0.0.0": false, "64:ff9b::": false,
		// Link-local, the cloud metadata address and its IPv6 forms.
		"169.254.169.254": false, "169.254.0.1": false, "fe80::1": false, "fe80::a9fe:a9fe": false,
		"::ffff:169.254.169.254": false, "64:ff9b::a9fe:a9fe": false, "2002:a9fe:a9fe::1": false, "fd00:ec2::254": false,
		// Multicast.
		"224.0.0.1": false, "239.255.255.250": false, "ff02::1": false, "ff05::2": false, "::ffff:224.0.0.1": false,
		// Reserved: this network, 240/4, broadcast, IETF protocol assignments, the old 6to4 relay
		// anycast, the IPv6 discard prefix and the IETF protocol range of 2001::/23.
		"0.1.2.3": false, "240.0.0.1": false, "255.255.255.255": false, "192.0.0.8": false, "192.88.99.1": false,
		"100::1": false, "2001:1::1": false, "2001:2::1": false, "2001:10::1": false,
		// Cloud metadata services that are not link-local: GCP over IPv6, Azure WireServer.
		"fd20:ce::254": false, "168.63.129.16": false, "::ffff:168.63.129.16": false, "64:ff9b::a83f:8110": false,
		"168.63.129.17": true, "fd20:ce::255": true,
		// CGNAT, benchmarking, documentation.
		"100.64.0.1": false, "100.127.255.254": false, "::ffff:100.64.0.1": false, "64:ff9b::6440:1": false,
		"198.18.0.1": false, "198.19.255.254": false, "2002:c612:1::1": false,
		"192.0.2.10": false, "198.51.100.1": false, "203.0.113.5": false, "2001:db8::1": false, "3fff::1": false,
		// Teredo (its embedded server and client addresses are a relay's and a NATed client's), also
		// when its obfuscated client address is loopback.
		"2001::1": false, "2001:0:4136:e378:8000:63bf:3fff:fdd2": false, "2001:0:a00:1::80ff:fffe": false,
		// The local-use NAT64 range: the embedded IPv4 address cannot be located, so nothing in it is scanned.
		"64:ff9b:1::a01:204": false, "64:ff9b:1:a01:2:400::": false,
		// IPv4-compatible and IPv4-translated forms.
		"::a01:204": false, "::127.0.0.1": false, "::ffff:0:a01:204": false,
		// Alice's own interface addresses, in every form that embeds them.
		"10.1.2.3": false, "::ffff:10.1.2.3": false, "64:ff9b::a01:203": false, "2002:a01:203::1": false, "fd12::3": false,
		// The default gateway.
		"10.1.2.1": false, "::ffff:10.1.2.1": false, "64:ff9b::a01:201": false, "fd12::1": false,
		// The database host the DSN names (resolved).
		"10.1.2.50": false, "fd12::50": false, "2002:a01:232::": false,
		// The Admin's global exclusions and the scope's exclusions.
		"10.9.1.1": false, "64:ff9b::a09:101": false, "fd12:9::1": false, "10.8.0.7": false, "10.7.7.7": false,
		// Zones never name a scanned host.
		"fd12::4%eth0": false, "fe80::1%eth0": false,
		// Allowed: neighbours of every excluded address, private and public addresses, and NAT64 and
		// 6to4 forms of an allowed IPv4 address.
		"10.1.2.4": true, "10.1.2.2": true, "10.1.2.51": true, "10.8.1.7": true, "10.7.7.8": true, "10.10.0.1": true,
		"172.16.0.1": true, "192.168.1.10": true, "8.8.8.8": true, "100.63.255.255": true, "100.128.0.0": true,
		"198.17.255.255": true, "198.20.0.0": true, "::ffff:10.1.2.4": true, "64:ff9b::a01:204": true,
		"2002:a01:204::1": true, "fd12::4": true, "2a00:1450:4001::1": true, "2001:200::1": true,
	} {
		err := p.CheckScan(netip.MustParseAddr(a))
		if want {
			assert.NoError(t, err, a)
		} else {
			assert.ErrorIs(t, err, netaddr.ErrScanRefused, a)
		}
	}
	assert.ErrorIs(t, p.CheckScan(netip.Addr{}), netaddr.ErrScanRefused, "the zero Addr")
}

// AllowedForScan is the built-in part only (what a scope may never name, whatever the settings):
// a strict subset of Allowed.
func TestAllowedForScanIsStricterThanAllowed(t *testing.T) {
	for a, want := range map[string]bool{
		"127.0.0.1": false, "::1": false, "0.0.0.0": false, "169.254.169.254": false, "fd00:ec2::254": false,
		"100.64.0.1": false, "198.18.0.1": false, "192.0.2.1": false, "2001:db8::1": false, "64:ff9b::7f00:1": false,
		"2002:7f00:1::": false, "2001::1": false, "::ffff:127.0.0.1": false, "64:ff9b:1::a00:5": false,
		"10.0.0.5": true, "::ffff:10.0.0.5": true, "64:ff9b::a00:5": true, "2002:a00:5::1": true, "fd12::1": true,
	} {
		addr := netip.MustParseAddr(a)
		assert.Equal(t, want, netaddr.AllowedForScan(addr), a)
		if netaddr.AllowedForScan(addr) {
			assert.True(t, netaddr.Allowed(addr), "%s: allowed for scan but not Allowed", a)
		}
	}
	assert.False(t, netaddr.AllowedForScan(netip.Addr{}))
}

// ScanBuiltins is a copy of the built-in list: every address of it is refused, and changing the copy
// changes nothing.
func TestScanBuiltins(t *testing.T) {
	bs := netaddr.ScanBuiltins()
	require.Contains(t, bs, netip.MustParsePrefix("127.0.0.0/8"))
	require.Contains(t, bs, netip.MustParsePrefix("fd00:ec2::254/128"))
	for _, p := range bs {
		assert.False(t, netaddr.AllowedForScan(p.Addr()), p)
	}
	bs[0] = netip.MustParsePrefix("10.0.0.0/8")
	assert.NotEqual(t, bs[0], netaddr.ScanBuiltins()[0])
}

// FuzzAllowedForScan: no address is allowed for scanning that Allowed refuses, and the verdict of
// the 4in6 form is that of the IPv4 address.
func FuzzAllowedForScan(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "::1", "64:ff9b::7f00:1", "2002:7f00:1::", "2001::1", "10.0.0.5"} {
		a := netip.MustParseAddr(s).As16()
		f.Add(a[:])
	}
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte{168, 63, 129, 16})
	f.Fuzz(func(t *testing.T, b []byte) {
		var a netip.Addr
		if len(b) == 4 {
			a = netip.AddrFrom4([4]byte(b))
		} else {
			var a16 [16]byte
			copy(a16[:], b)
			a = netip.AddrFrom16(a16)
		}
		if netaddr.AllowedForScan(a) && !netaddr.Allowed(a) {
			t.Fatalf("%s allowed for scan but not Allowed", a)
		}
		if a.Is4In6() && netaddr.AllowedForScan(a) != netaddr.AllowedForScan(a.Unmap()) {
			t.Fatalf("%s: mapped and plain verdicts differ", a)
		}
	})
}

// The Admin's allowed networks are a positive allowlist: empty means nothing may be scanned, and a
// set list admits only addresses inside it (exclusions and built-ins still win).
func TestScanPolicyAllowedNetworks(t *testing.T) {
	empty := policy(t, nil)
	for _, a := range []string{"10.1.2.4", "8.8.8.8", "fd12::4", "::ffff:10.1.2.4"} {
		assert.ErrorIs(t, empty.CheckScan(netip.MustParseAddr(a)), netaddr.ErrScanRefused, "empty allowlist: %s", a)
	}

	set := policy(t, []string{"10.0.0.0/8", "fd12::/16", "::ffff:192.168.7.0/120", "127.0.0.0/8", "192.0.2.0/24"})
	for a, want := range map[string]bool{
		"10.1.2.4": true, "::ffff:10.1.2.4": true, "fd12::4": true, "192.168.7.9": true,
		"192.168.1.1": false, "8.8.8.8": false, "fd13::1": false, "172.16.0.1": false,
		"64:ff9b::a01:204": false,                                       // the dialed address is outside the list even though it embeds an inside one
		"10.9.1.1":         false, "10.1.2.3": false, "10.8.0.7": false, // exclusions and own addresses still win
		"127.0.0.1": false, "192.0.2.1": false, // built-ins cannot be allow-listed
	} {
		err := set.CheckScan(netip.MustParseAddr(a))
		if want {
			assert.NoError(t, err, a)
		} else {
			assert.ErrorIs(t, err, netaddr.ErrScanRefused, a)
		}
	}

	// An allow-listed NAT64 or 6to4 prefix opens only the IPv4 addresses that are allow-listed too.
	xlat := policy(t, []string{"64:ff9b::/96", "2002::/16", "10.0.0.0/8"})
	for a, want := range map[string]bool{
		"64:ff9b::a01:204": true, "2002:a01:204::1": true,
		"64:ff9b::808:808": false, "2002:808:808::1": false, "64:ff9b::c0a8:101": false,
	} {
		err := xlat.CheckScan(netip.MustParseAddr(a))
		if want {
			assert.NoError(t, err, a)
		} else {
			assert.ErrorIs(t, err, netaddr.ErrScanRefused, a)
		}
	}
}

func TestNewScanPolicyRefusesBadInputs(t *testing.T) {
	ctx := context.Background()
	bad := func(edit func(*netaddr.ScanPolicyInputs)) error {
		in := inputs(t, everyAddr)
		edit(&in)
		_, err := netaddr.NewScanPolicy(ctx, in)
		return err
	}
	require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) { in.AllowedNetworks = []netip.Prefix{{}} }), "invalid allowed network")
	require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) { in.GlobalExclusions = []netip.Prefix{{}} }), "invalid global exclusion")
	require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) { in.ScopeExclusions = []netip.Prefix{{}} }), "invalid scope exclusion")
	require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) { in.DatabaseURL = "" }), "no database URL")
	err := bad(func(in *netaddr.ScanPolicyInputs) { in.DatabaseURL = "postgres://u:hunter2@[::1" })
	require.Error(t, err, "unparsable database URL")
	for _, mapped := range []string{"::ffff:0:0/95", "::ffff:0:0/80", "::ffff:10.0.0.0/64"} {
		pfx := netip.MustParsePrefix(mapped)
		require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) { in.AllowedNetworks = []netip.Prefix{pfx} }), "allowed %s", mapped)
		require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) { in.GlobalExclusions = []netip.Prefix{pfx} }), "global %s", mapped)
		require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) { in.ScopeExclusions = []netip.Prefix{pfx} }), "scope %s", mapped)
	}
	require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) {
		in.LookupHost = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	}), "a database host that resolves to no address: fail closed")
	assert.NotContains(t, err.Error(), "hunter2", "the error never carries the DSN")
	require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) { in.DatabaseURL = "postgres://u@nowhere.alice.test/db" }),
		"a database host that does not resolve: the policy cannot be built")
	require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) {
		in.InterfaceAddrs = func() ([]netip.Addr, error) { return nil, errors.New("netlink") }
	}), "own addresses unreadable")
	require.Error(t, bad(func(in *netaddr.ScanPolicyInputs) {
		in.DefaultGateways = func() ([]netip.Addr, error) { return nil, errors.New("no /proc") }
	}), "gateway unreadable")
}

// The database hosts come from the DSN as pgx reads it: URL and key/value forms, several hosts, IP
// literals (no lookup) and Unix sockets (no address).
func TestScanPolicyDatabaseHosts(t *testing.T) {
	for dsn, refused := range map[string][]string{
		"host=db1.alice.test,10.4.4.4 port=5432,5433 user=u dbname=d": {"10.1.2.50", "10.4.4.4"},
		"postgres://u@[fd12::77]:5432/d":                              {"fd12::77"},
		"host=/run/postgresql user=u dbname=d":                        {},
	} {
		in := inputs(t, everyAddr)
		in.DatabaseURL = dsn
		var looked []string
		in.LookupHost = func(_ context.Context, host string) ([]netip.Addr, error) {
			looked = append(looked, host)
			return addrs(t, []string{"10.1.2.50"}), nil
		}
		p, err := netaddr.NewScanPolicy(context.Background(), in)
		require.NoError(t, err, dsn)
		for _, a := range refused {
			assert.ErrorIs(t, p.CheckScan(netip.MustParseAddr(a)), netaddr.ErrScanRefused, "%s: %s", dsn, a)
		}
		assert.NoError(t, p.CheckScan(netip.MustParseAddr("10.4.4.5")), dsn)
		for _, h := range looked {
			assert.False(t, strings.HasPrefix(h, "/"), "a socket path is never looked up")
			_, perr := netip.ParseAddr(h)
			assert.Error(t, perr, "an IP literal is never looked up")
		}
	}
}

// Own interface addresses and the gateway are re-read while a scan runs: an address added after
// the policy was built is refused once the refresh interval passed, and a read failure refuses
// everything until a read succeeds again (fail closed).
func TestScanPolicyRereadsOwnAddresses(t *testing.T) {
	var mu sync.Mutex
	own := []string{"10.1.2.3"}
	var fail bool
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	in := inputs(t, everyAddr)
	in.InterfaceAddrs = func() ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return nil, errors.New("netlink")
		}
		return addrs(t, own), nil
	}
	in.RefreshEvery = time.Second
	in.Clock = clk
	p, err := netaddr.NewScanPolicy(context.Background(), in)
	require.NoError(t, err)
	fresh := netip.MustParseAddr("10.1.2.99")
	require.NoError(t, p.CheckScan(fresh))

	mu.Lock()
	own = append(own, "10.1.2.99")
	mu.Unlock()
	require.NoError(t, p.CheckScan(fresh), "within the interval the last read stands")
	clk.Advance(time.Second)
	require.ErrorIs(t, p.CheckScan(fresh), netaddr.ErrScanRefused, "re-read: the new own address is refused")

	mu.Lock()
	fail = true
	mu.Unlock()
	clk.Advance(time.Second)
	require.ErrorIs(t, p.CheckScan(netip.MustParseAddr("10.1.2.4")), netaddr.ErrScanRefused, "read failure: fail closed")
	mu.Lock()
	fail = false
	mu.Unlock()
	clk.Advance(time.Second)
	require.NoError(t, p.CheckScan(netip.MustParseAddr("10.1.2.4")), "recovered")
}

// The system sources: on Linux the interface list holds the loopback address and the route files
// parse (their content depends on the host).
func TestScanPolicySystemSources(t *testing.T) {
	in := netaddr.ScanPolicyInputs{AllowedNetworks: prefixes(t, everyAddr), DatabaseURL: "host=/run/postgresql user=u"}
	p, err := netaddr.NewScanPolicy(context.Background(), in)
	require.NoError(t, err)
	assert.ErrorIs(t, p.CheckScan(netip.MustParseAddr("127.0.0.1")), netaddr.ErrScanRefused)

	in.DatabaseURL = "postgres://u@localhost/d" // resolved by the system resolver (/etc/hosts)
	_, err = netaddr.NewScanPolicy(context.Background(), in)
	require.NoError(t, err)
}

func TestScanControlParsesStrictly(t *testing.T) {
	ctl := netaddr.ScanControl(policy(t, everyAddr))
	require.NoError(t, ctl("tcp4", "10.1.2.4:443", nil))
	require.NoError(t, ctl("tcp6", "[fd12::4]:443", nil))
	// Decimal, octal, hex and short IPv4 spellings, zones and garbage never reach a connect: the net
	// package hands Control the canonical form, and anything else is refused as unreadable.
	for _, a := range []string{"2130706433:443", "0177.0.0.1:443", "0x7f.0.0.1:443", "127.1:443", "017.1.2.4:443",
		"[fd12::4%eth0]:443", "10.1.2.4", "not an address", "", "[::ffff:127.0.0.1]:443", "127.0.0.1:443"} {
		assert.ErrorIs(t, ctl("tcp", a, nil), netaddr.ErrScanRefused, a)
	}
	assert.ErrorIs(t, netaddr.ScanControl(nil)("tcp4", "10.1.2.4:443", nil), netaddr.ErrScanRefused, "no policy: nothing is scanned")
}

// openPolicy allows every valid address: the control of the dial-counting test (proves that the
// listener does accept the connection the scan policy refuses).
type openPolicy struct{}

func (openPolicy) CheckScan(netip.Addr) error { return nil }

func scanDial(p netaddr.ScanPolicy, r *net.Resolver, address string) (net.Conn, error) {
	return netaddr.ScanDialContext(context.Background(), p, &net.Dialer{Timeout: 5 * time.Second, Resolver: r}, "tcp", address)
}

// Review Focus 2: an excluded address is refused at connect time, before the socket connects,
// proven by a listener that counts what it accepted. Loopback is refused even when the Admin
// allow-lists 127.0.0.0/8.
func TestScanControlRefusesBeforeConnect(t *testing.T) {
	srv := listen(t)
	p := policy(t, []string{"127.0.0.0/8", "0.0.0.0/0", "::/0"})
	r := table(map[string][]string{"loop.alice.test": {"127.0.0.1"}, "any.alice.test": {"0.0.0.0", "::1"}})
	for _, a := range []string{"127.0.0.1:" + srv.port(), "[::ffff:127.0.0.1]:" + srv.port(), "0.0.0.0:" + srv.port(),
		"loop.alice.test:" + srv.port(), "any.alice.test:" + srv.port()} {
		_, err := scanDial(p, r, a)
		require.ErrorIs(t, err, netaddr.ErrScanRefused, a)
	}
	// A dialer with its own ControlContext: ScanDialContext replaces it, the policy still decides.
	d := &net.Dialer{Timeout: 5 * time.Second, ControlContext: func(context.Context, string, string, syscall.RawConn) error { return nil }}
	_, err := netaddr.ScanDialContext(context.Background(), p, d, "tcp", "127.0.0.1:"+srv.port())
	require.ErrorIs(t, err, netaddr.ErrScanRefused)
	// And as a plain Dialer.Control hook.
	_, err = (&net.Dialer{Timeout: 5 * time.Second, Control: netaddr.ScanControl(p)}).DialContext(context.Background(), "tcp", "127.0.0.1:"+srv.port())
	require.ErrorIs(t, err, netaddr.ErrScanRefused)
	srv.settled(t, 0)

	// Control: an open policy reaches the same listener (the refusal above is what kept it away).
	c, err := scanDial(openPolicy{}, r, "loop.alice.test:"+srv.port())
	require.NoError(t, err)
	_ = c.Close()
	srv.settled(t, 1)
}

// A name that resolves to both an allowed public address and an excluded one: every candidate is
// checked at connect time, the excluded one is never connected; and a name that rebinds between
// the check and the dial is checked again on the socket (the address checked is the one connected).
func TestScanControlNameWithPublicAndExcludedAddresses(t *testing.T) {
	srv := listen(t)
	p := policy(t, everyAddr)
	errStub := errors.New("stub: an allowed address would connect here")
	var mu sync.Mutex
	checked := map[string]error{}
	ctl := netaddr.ScanControl(p)
	d := &net.Dialer{Timeout: 5 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		err := ctl(network, address, c)
		mu.Lock()
		checked[address] = err
		mu.Unlock()
		if err == nil {
			return errStub // never touch the network for the public address
		}
		return err
	}}
	for _, order := range [][]string{{"93.184.216.34", "127.0.0.1"}, {"127.0.0.1", "93.184.216.34"}} {
		clear(checked)
		d.Resolver = table(map[string][]string{"both.alice.test": order})
		_, err := d.DialContext(context.Background(), "tcp", "both.alice.test:"+srv.port())
		require.Error(t, err)
		mu.Lock()
		assert.NoError(t, checked["93.184.216.34:"+srv.port()], "%v: the public address passes", order)
		assert.ErrorIs(t, checked["127.0.0.1:"+srv.port()], netaddr.ErrScanRefused, "%v: the excluded one is refused", order)
		mu.Unlock()
	}

	// Rebinding: the name answers a public address to whoever looks first (a pre-check), then loopback.
	var rebound atomic.Bool
	rebind := netaddrtest.Resolver(func(name string) []netip.Addr {
		switch {
		case name != "rebind.alice.test":
			return nil
		case rebound.Load():
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		default:
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}
		}
	})
	pre, err := rebind.LookupNetIP(context.Background(), "ip", "rebind.alice.test")
	require.NoError(t, err)
	require.NotEmpty(t, pre)
	for _, a := range pre {
		require.NoError(t, p.CheckScan(a), "the pre-check sees only the public address")
	}
	rebound.Store(true)
	_, err = scanDial(p, rebind, "rebind.alice.test:"+srv.port())
	require.ErrorIs(t, err, netaddr.ErrScanRefused, "the dial checks the rebound address")
	srv.settled(t, 0)
}
