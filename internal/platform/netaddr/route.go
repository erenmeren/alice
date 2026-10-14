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

// rtfGateway is the kernel's RTF_GATEWAY route flag: the route goes through a gateway.
const rtfGateway = 0x2

// viaGateway reports whether a route is a default route or its hexadecimal flags field has RTF_GATEWAY.
func viaGateway(field string, isDefault bool) bool {
	flags, err := strconv.ParseUint(field, 16, 32)
	return isDefault || (err == nil && flags&rtfGateway != 0)
}

// parseIPv4Gateways reads /proc/net/route: the non-zero gateway of every default route (destination
// and mask 0) and of every other route through a gateway (RTF_GATEWAY). The kernel prints an address
// as the hexadecimal of the in-memory network-order word.
func parseIPv4Gateways(s string) []netip.Addr {
	var out []netip.Addr
	for line := range strings.SplitSeq(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || len(f[2]) != 8 || !viaGateway(f[3], f[1] == "00000000" && f[7] == "00000000") {
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

// parseIPv6Gateways reads /proc/net/ipv6_route: the non-zero next hop of every default route
// (destination ::/0) and of every other route through a gateway (RTF_GATEWAY, the ninth field).
func parseIPv6Gateways(s string) []netip.Addr {
	var out []netip.Addr
	for line := range strings.SplitSeq(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || len(f[4]) != 32 {
			continue
		}
		isDefault := f[0] == "00000000000000000000000000000000" && f[1] == "00"
		if !isDefault && (len(f) < 9 || !viaGateway(f[8], false)) {
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
