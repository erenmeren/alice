package netaddr

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// The Linux route tables the scan policy reads Alice's default gateways from.
const (
	procRouteV4 = "/proc/net/route"
	procRouteV6 = "/proc/net/ipv6_route"
)

func systemGateways() ([]netip.Addr, error) { return readGateways(procRouteV4, procRouteV6) }

// readGateways returns the default gateways of the IPv4 table v4 (required) and the IPv6 table v6
// (optional: absent when IPv6 is disabled).
func readGateways(v4, v6 string) ([]netip.Addr, error) {
	b, err := os.ReadFile(v4) //nolint:gosec // G304: a fixed /proc path (a temporary file in tests)
	if err != nil {
		return nil, err
	}
	out := parseIPv4Gateways(string(b))
	b, err = os.ReadFile(v6) //nolint:gosec // G304: as above
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return out, nil
	case err != nil:
		return nil, err
	}
	return append(out, parseIPv6Gateways(string(b))...), nil
}

// parseIPv4Gateways reads /proc/net/route: the gateway of every default route (destination and mask
// 0), which the kernel prints as the hexadecimal of the in-memory network-order word.
func parseIPv4Gateways(s string) []netip.Addr {
	var out []netip.Addr
	for line := range strings.SplitSeq(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" || len(f[2]) != 8 {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		var b [4]byte
		binary.NativeEndian.PutUint32(b[:], uint32(v))
		out = append(out, netip.AddrFrom4(b))
	}
	return out
}

// parseIPv6Gateways reads /proc/net/ipv6_route: the next hop of every default route (destination
// ::/0) that has one.
func parseIPv6Gateways(s string) []netip.Addr {
	var out []netip.Addr
	for line := range strings.SplitSeq(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "00000000000000000000000000000000" || f[1] != "00" || len(f[4]) != 32 {
			continue
		}
		b, err := hex.DecodeString(f[4])
		if err != nil {
			continue
		}
		a := netip.AddrFrom16([16]byte(b))
		if a.IsUnspecified() {
			continue
		}
		out = append(out, a)
	}
	return out
}
