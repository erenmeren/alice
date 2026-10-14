package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
	"alice/internal/testutil/scanpolicy"
)

// stubResolver answers from a table; a name it does not know does not resolve.
type stubResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	asked   []string
	block   bool // wait for the context instead of answering
	budgets []time.Duration
}

func (r *stubResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.asked = append(r.asked, host)
	if dl, ok := ctx.Deadline(); ok {
		r.budgets = append(r.budgets, time.Until(dl))
	}
	r.mu.Unlock()
	if network != "ip" {
		return nil, errors.New("unexpected network " + network)
	}
	if r.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	as, ok := r.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return as, nil
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func lab() Rules {
	return Rules{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2a00:1450::/112")}}
}

func keys(es []Endpoint) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Address.String() + " " + strconv.Itoa(int(e.Port)) + " sni=" + e.SNI + " host=" + e.Host
	}
	return out
}

func TestExpandLiteralScope(t *testing.T) {
	s := scope("10.0.0.0/30", "10.0.0.2", "::ffff:10.0.0.9")
	s.Ports = []int{443, 8443}
	x, err := Expand(context.Background(), s, ExpandInputs{Rules: lab(), Policy: scanpolicy.Permissive()})
	require.NoError(t, err)
	require.Equal(t, []string{
		"10.0.0.0 443 sni= host=", "10.0.0.0 8443 sni= host=", "10.0.0.1 443 sni= host=", "10.0.0.1 8443 sni= host=",
		"10.0.0.2 443 sni= host=", "10.0.0.2 8443 sni= host=", "10.0.0.3 443 sni= host=", "10.0.0.3 8443 sni= host=",
		"10.0.0.9 443 sni= host=", "10.0.0.9 8443 sni= host=",
	}, keys(x.Dial), "an IP-literal scope: one SNI-less handshake per address and port, overlap counted once")
	require.Empty(t, x.Excluded)
	require.Equal(t, 5, x.Addresses)
	require.Equal(t, 10, x.Endpoints)
}

func TestExpandSNINames(t *testing.T) {
	s := scope("10.0.0.1")
	s.SNINames = []string{"a.example", "b.example"}
	x, err := Expand(context.Background(), s, ExpandInputs{Rules: lab(), Policy: scanpolicy.Permissive()})
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.1 443 sni=a.example host=", "10.0.0.1 443 sni=b.example host="}, keys(x.Dial))
}

func TestExpandHostnames(t *testing.T) {
	r := &stubResolver{answers: map[string][]netip.Addr{
		"www.example.com":  addrs("10.0.0.7", "::ffff:10.0.0.8", "10.0.0.7"),
		"mail.example.com": addrs("10.0.0.7"),
		"gone.example.com": {},
	}}
	s := scope("www.example.com", "10.0.0.7", "mail.example.com", "nx.example.com", "gone.example.com")
	s.SNINames = []string{"www.example.com"}
	x, err := Expand(context.Background(), s, ExpandInputs{Rules: lab(), Policy: scanpolicy.Permissive(), Resolver: r})
	require.NoError(t, err)
	require.Equal(t, []string{
		"10.0.0.7 443 sni=www.example.com host=",
		"10.0.0.8 443 sni=www.example.com host=www.example.com",
		"10.0.0.7 443 sni=mail.example.com host=mail.example.com",
	}, keys(x.Dial), "each resolved address is its own endpoint, the name its SNI and host; the literal's equal (address, port, SNI) comes first")
	require.Equal(t, []string{"nx.example.com", "gone.example.com"}, x.Unresolved)
	require.Equal(t, 2, x.Addresses)
	require.ElementsMatch(t, []string{"www.example.com", "mail.example.com", "nx.example.com", "gone.example.com"}, r.asked,
		"every name is resolved exactly once")
	require.Len(t, r.budgets, 4, "every lookup has a deadline")
	for _, b := range r.budgets {
		require.LessOrEqual(t, b, ResolveTimeout)
		require.Greater(t, b, ResolveTimeout-time.Second)
	}
}

func TestExpandAtMostEightAddressesPerName(t *testing.T) {
	var many []netip.Addr
	for i := range 12 {
		many = append(many, netip.AddrFrom4([4]byte{10, 0, 1, byte(i)}))
	}
	r := &stubResolver{answers: map[string][]netip.Addr{"big.example": many}}
	x, err := Expand(context.Background(), scope("big.example"), ExpandInputs{Rules: lab(), Policy: scanpolicy.Permissive(), Resolver: r})
	require.NoError(t, err)
	require.Len(t, x.Dial, MaxAddressesPerName)
	require.Equal(t, "10.0.1.0", x.Dial[0].Address.String())
}

func TestExpandResolveTimeout(t *testing.T) {
	r := &stubResolver{block: true}
	x, err := Expand(context.Background(), scope("slow.example", "10.0.0.1"),
		ExpandInputs{Rules: lab(), Policy: scanpolicy.Permissive(), Resolver: r, ResolveTimeout: 50 * time.Millisecond})
	require.NoError(t, err)
	require.Equal(t, []string{"slow.example"}, x.Unresolved, "a lookup that times out leaves its name unresolved, not the scan failed")
	require.Len(t, x.Dial, 1)
}

// TestExpandRebindingName: a name that resolves to a public and to excluded addresses (loopback, the
// metadata address, Alice's own address in the policy, an Admin exclusion, outside the allowed
// networks) keeps the public one and records every other as excluded: never dialable.
func TestExpandRebindingName(t *testing.T) {
	r := &stubResolver{answers: map[string][]netip.Addr{
		"evil.example": addrs("127.0.0.1", "10.0.0.9", "169.254.169.254", "::ffff:127.0.0.1", "10.0.0.66", "10.9.0.1", "192.168.1.1",
			"64:ff9b::7f00:1"),
	}}
	rules := lab()
	rules.GlobalExclusions = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}
	pol := scanpolicy.Permissive(netip.MustParsePrefix("10.0.0.66/32"))
	x, err := Expand(context.Background(), scope("evil.example"), ExpandInputs{Rules: rules, Policy: pol, Resolver: r})
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.9 443 sni=evil.example host=evil.example"}, keys(x.Dial))
	require.Equal(t, []string{
		"127.0.0.1 443 sni=evil.example host=evil.example",
		"169.254.169.254 443 sni=evil.example host=evil.example",
		"10.0.0.66 443 sni=evil.example host=evil.example",
		"10.9.0.1 443 sni=evil.example host=evil.example",
		"192.168.1.1 443 sni=evil.example host=evil.example",
		"64:ff9b::7f00:1 443 sni=evil.example host=evil.example",
	}, keys(x.Excluded), "the mapped loopback is the same address as 127.0.0.1")
	for _, e := range x.Excluded {
		require.Equal(t, StateExcluded, e.State())
		require.Equal(t, ErrorCodePolicy, e.ErrorCode())
	}
	require.Empty(t, x.Dial[0].State())
	require.Empty(t, x.Dial[0].ErrorCode())
	require.Equal(t, 7, x.Addresses)
}

func TestExpandExclusionsAreSubtracted(t *testing.T) {
	rules := lab()
	rules.GlobalExclusions = []netip.Prefix{netip.MustParsePrefix("10.0.0.6/31")}
	s := scope("10.0.0.0/29")
	s.Exclusions = []string{"10.0.0.0/30"}
	pol := scanpolicy.Permissive(netip.MustParsePrefix("10.0.0.5/32"))
	x, err := Expand(context.Background(), s, ExpandInputs{Rules: rules, Policy: pol})
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.4 443 sni= host="}, keys(x.Dial))
	require.Equal(t, []string{"10.0.0.5 443 sni= host="}, keys(x.Excluded), "a policy refusal is recorded, an exclusion removed")
	require.Equal(t, 2, x.Addresses)
	require.Equal(t, 2, x.Endpoints)
}

func TestExpandBuiltinsInsideARange(t *testing.T) {
	s := scope("192.0.0.0/22")
	x, err := Expand(context.Background(), s, ExpandInputs{Rules: everywhere, Policy: scanpolicy.Permissive()})
	require.NoError(t, err)
	require.Len(t, x.Dial, 512)
	require.Len(t, x.Excluded, 512)
	for _, e := range x.Excluded {
		require.False(t, netaddr.AllowedForScan(e.Address))
	}
}

// TestExcludedAddressesAreNeverReturnedDialable: whatever the scope, the dial list holds only
// addresses the policy, the built-in rule, the allowed networks and every exclusion accept, and no
// excluded endpoint is also in it.
func TestExcludedAddressesAreNeverReturnedDialable(t *testing.T) {
	r := &stubResolver{answers: map[string][]netip.Addr{
		"a.example": addrs("10.0.0.1", "127.0.0.1", "10.0.3.3"),
		"b.example": addrs("10.0.2.200", "::1", "fe80::1", "2a00:1450::5", "2a00:1451::5", "64:ff9b::a00:101"),
	}}
	rules := Rules{
		AllowedNetworks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/22"), netip.MustParsePrefix("2a00:1450::/112")},
		GlobalExclusions: []netip.Prefix{netip.MustParsePrefix("10.0.2.128/25")},
	}
	s := scope("10.0.0.0/23", "10.0.2.0/24", "a.example", "b.example", "2a00:1450::/120")
	s.Exclusions = []string{"10.0.1.0/28"}
	s.Ports = []int{443, 636}
	except := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/27"), netip.MustParsePrefix("2a00:1450::5/128")}
	pol := scanpolicy.Permissive(except...)
	x, err := Expand(context.Background(), s, ExpandInputs{Rules: rules, Policy: pol, Resolver: r})
	require.NoError(t, err)
	require.NotEmpty(t, x.Dial)
	require.NotEmpty(t, x.Excluded)
	excl := append(append([]netip.Prefix{}, rules.GlobalExclusions...), netip.MustParsePrefix("10.0.1.0/28"))
	dial := map[netip.Addr]bool{}
	for _, e := range x.Dial {
		dial[e.Address] = true
		require.NoError(t, pol.CheckScan(e.Address))
		require.True(t, netaddr.AllowedForScan(e.Address), e.Address)
		require.True(t, inPrefixes(e.Address, rules.AllowedNetworks), e.Address)
		require.False(t, inPrefixes(e.Address, excl), e.Address)
		require.False(t, inPrefixes(e.Address, except), e.Address)
	}
	for _, e := range x.Excluded {
		require.False(t, dial[e.Address], "excluded %s is also dialable", e.Address)
	}
	for _, a := range addrs("127.0.0.1", "::1", "fe80::1", "2a00:1450::5", "2a00:1451::5", "64:ff9b::a00:101", "10.0.2.200", "10.0.0.1") {
		require.False(t, dial[a], a)
	}
	require.True(t, dial[netip.MustParseAddr("10.0.3.3")], "the allowed address of a.example stays")
	require.Equal(t, len(x.Dial)+len(x.Excluded), x.Endpoints)
}

func TestExpandFailsClosed(t *testing.T) {
	pol := scanpolicy.Permissive()
	_, err := Expand(context.Background(), scope("10.0.0.1"), ExpandInputs{Policy: pol})
	require.ErrorIs(t, err, ErrNotAllowed, "no allowed networks: nothing may be scanned")
	_, err = Expand(context.Background(), scope("10.0.0.1"), ExpandInputs{Rules: lab()})
	require.Error(t, err, "no policy")
	_, err = Expand(context.Background(), scope("www.example.com"), ExpandInputs{Rules: lab(), Policy: pol})
	require.Error(t, err, "a host name and no resolver")
	_, err = Expand(context.Background(), scope("192.168.0.1"), ExpandInputs{Rules: lab(), Policy: pol})
	require.ErrorIs(t, err, ErrNotAllowed, "an entry outside the allowed networks is refused again at expansion")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Expand(ctx, scope("www.example.com"), ExpandInputs{Rules: lab(), Policy: pol, Resolver: &stubResolver{}})
	require.ErrorIs(t, err, context.Canceled)
}

func TestExpandCapsCountResolvedAddresses(t *testing.T) {
	answers := map[string][]netip.Addr{}
	s := scope("10.0.0.0/21", "10.0.8.0/22")
	for i := range 200 {
		name := "h" + strconv.Itoa(i) + ".example"
		s.Entries = append(s.Entries, name)
		for j := range 8 {
			answers[name] = append(answers[name], netip.AddrFrom4([4]byte{10, 1, byte(i), byte(j)}))
		}
	}
	r := &stubResolver{answers: answers}
	_, err := Expand(context.Background(), s, ExpandInputs{Rules: lab(), Policy: scanpolicy.Permissive(), Resolver: r})
	require.ErrorIs(t, err, ErrTooLarge, "3,072 literal + 1,600 resolved addresses")

	s.Entries = s.Entries[2:]
	s.Ports = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	_, err = Expand(context.Background(), s, ExpandInputs{Rules: lab(), Policy: scanpolicy.Permissive(), Resolver: r})
	require.ErrorIs(t, err, ErrTooLarge, "1,600 resolved addresses x 13 ports = 20,800 endpoints")
	s.Ports = s.Ports[:12]
	x, err := Expand(context.Background(), s, ExpandInputs{Rules: lab(), Policy: scanpolicy.Permissive(), Resolver: r})
	require.NoError(t, err)
	require.Equal(t, 19200, x.Endpoints)
}

func TestSystemResolverIsTheDefault(t *testing.T) {
	require.Equal(t, net.DefaultResolver, SystemResolver)
}
