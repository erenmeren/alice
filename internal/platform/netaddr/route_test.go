package netaddr

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const routeV4 = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0100A8C0	0003	0	0	600	00000000	0	0	0
eth1	00000000	FE01010A	0003	0	0	700	00000000	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
wlan0	0000A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
blackhole	00000000	00000000	0001	0	0	900	00000000	0	0	0
short	00000000
bad	00000000	zz00A8C0	0003	0	0	600	00000000	0	0	0
`

const routeV6 = `fd000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00200200       lo
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd120000000000000000000000000001 00000400 00000001 00000000 00000003     eth1
00000000000000000000000000000000 00 00000000000000000000000000000000 00 zz120000000000000000000000000001 00000400 00000001 00000000 00000003     eth1
00000000000000000000000000000000 00
`

func TestParseRoutes(t *testing.T) {
	v4 := parseIPv4Gateways(routeV4)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("10.1.1.254")}, v4)
	v6 := parseIPv6Gateways(routeV6)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fd12::1")}, v6)
}

func TestReadGateways(t *testing.T) {
	dir := t.TempDir()
	v4, v6 := filepath.Join(dir, "route"), filepath.Join(dir, "ipv6_route")
	require.NoError(t, os.WriteFile(v4, []byte(routeV4), 0o600))
	require.NoError(t, os.WriteFile(v6, []byte(routeV6), 0o600))
	got, err := readGateways(v4, v6)
	require.NoError(t, err)
	assert.Len(t, got, 4)

	// No IPv6 route table (IPv6 disabled): the IPv4 gateways stand.
	got, err = readGateways(v4, filepath.Join(dir, "missing"))
	require.NoError(t, err)
	assert.Len(t, got, 2)

	// No IPv4 route table: the policy cannot know its gateway, so it is not built (fail closed).
	_, err = readGateways(filepath.Join(dir, "missing"), v6)
	require.Error(t, err)
	// An IPv6 table that exists but cannot be read is an error too.
	_, err = readGateways(v4, dir)
	require.Error(t, err)

	// The host's own tables parse.
	_, err = systemGateways()
	require.NoError(t, err)
}

// FuzzParseRoutes: the route table parsers never panic and return only valid, zone-free addresses
// of their family.
func FuzzParseRoutes(f *testing.F) {
	f.Add(routeV4)
	f.Add(routeV6)
	f.Add("x\t00000000\tFFFFFFFF")
	f.Fuzz(func(t *testing.T, s string) {
		for _, a := range parseIPv4Gateways(s) {
			if !a.Is4() || a.IsUnspecified() {
				t.Fatalf("bad IPv4 gateway %s from %q", a, s)
			}
		}
		for _, a := range parseIPv6Gateways(s) {
			if !a.Is6() || a.Zone() != "" || a.IsUnspecified() {
				t.Fatalf("bad IPv6 gateway %s from %q", a, s)
			}
		}
	})
}
