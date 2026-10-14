// Package netaddr is the address rule of SEC-065, shared by target validation (what an
// administrator types) and every connection Alice opens to a managed server (the address a name
// resolves to when Alice connects, AUD-25 a). One rule, so the two can never drift.
package netaddr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
)

var (
	nat64Prefix  = netip.MustParsePrefix("64:ff9b::/96")   // RFC 6052 well-known prefix
	nat64Local   = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215 local-use prefix
	sixToFour    = netip.MustParsePrefix("2002::/16")      // RFC 3056
	awsIMDSv6    = netip.MustParseAddr("fd00:ec2::254")    // AWS instance metadata over IPv6
	ipv4Broadcst = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	v4Compatible = netip.MustParsePrefix("::/96")           // RFC 4291 IPv4-compatible (deprecated)
	v4Translated = netip.MustParsePrefix("::ffff:0:0:0/96") // RFC 2765 SIIT IPv4-translated
	teredo       = netip.MustParsePrefix("2001::/32")       // RFC 4380
	thisNetwork  = netip.MustParsePrefix("0.0.0.0/8")       // RFC 1122 "this network"
	reservedV4   = netip.MustParsePrefix("240.0.0.0/4")     // RFC 1112 reserved (and broadcast)
	ipv6Loopback = netip.IPv6Loopback()
)

// Allowed reports whether a may be a managed server's address. Refused: link-local (including the
// cloud metadata address 169.254.169.254, SEC-065, and its IPv6 forms: IPv4-mapped, NAT64
// 64:ff9b::/96 and the local-use NAT64 range 64:ff9b:1::/48, 6to4 2002::/16 and AWS's
// fd00:ec2::254), multicast, unspecified (0.0.0.0 and :: reach the host's own services), the
// IPv4 "this network" range 0.0.0.0/8 and the reserved 240.0.0.0/4 (broadcast included), also when
// embedded in NAT64 or 6to4; the IPv6 forms that only carry an IPv4 address to a host, never route to
// a server, or tunnel to a destination Alice cannot see: IPv4-compatible ::/96 (but ::1, loopback),
// IPv4-translated ::ffff:0:0:0/96 and Teredo 2001::/32 (refused as a whole: its embedded addresses
// are a relay's and a client's behind NAT, never a managed server's); an address with a zone (target
// validation refuses one as typed, and DNS never returns one) and the zero Addr. Loopback and
// private addresses are allowed.
func Allowed(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	u := a.Unmap()
	if notAServer(u) || reserved(u) || u == awsIMDSv6 || localNAT64ToNonServer(u) {
		return false
	}
	if u.Is6() && u != ipv6Loopback && (v4Compatible.Contains(u) || v4Translated.Contains(u) || teredo.Contains(u)) {
		return false
	}
	if u.Is6() {
		b := u.As16()
		var embedded netip.Addr
		switch {
		case nat64Prefix.Contains(u):
			embedded = netip.AddrFrom4([4]byte(b[12:16]))
		case sixToFour.Contains(u):
			embedded = netip.AddrFrom4([4]byte(b[2:6]))
		}
		if embedded.IsValid() && (notAServer(embedded) || reserved(embedded)) {
			return false
		}
	}
	return true
}

// reserved reports the IPv4 ranges that never hold a server: 0.0.0.0/8 and 240.0.0.0/4. Not part of
// notAServer: localNAT64ToNonServer's shorter forms read zero bits of every /96 address as 0.x.x.x.
func reserved(u netip.Addr) bool {
	return thisNetwork.Contains(u) || reservedV4.Contains(u)
}

// localNAT64ToNonServer reports whether u lies in the local-use NAT64 range 64:ff9b:1::/48 and
// translates to an address that is never a managed server. Alice cannot know the prefix length an
// operator chose inside the range, so the IPv4 address is read at every RFC 6052 position a prefix
// of /48, /56, /64 or /96 places it: the last 32 bits like the well-known prefix (also refused when
// unspecified), and the three shorter forms, which skip the u-octet (bits 64-71) and are refused
// for link-local, multicast and broadcast (their zero bits read as 0.0.0.0 in every /96 address).
func localNAT64ToNonServer(u netip.Addr) bool {
	if !u.Is6() || !nat64Local.Contains(u) {
		return false
	}
	b := u.As16()
	if last := netip.AddrFrom4([4]byte(b[12:16])); notAServer(last) || reserved(last) {
		return true
	}
	for _, v4 := range [][4]byte{{b[6], b[7], b[9], b[10]}, {b[7], b[9], b[10], b[11]}, {b[9], b[10], b[11], b[12]}} {
		if e := netip.AddrFrom4(v4); !e.IsUnspecified() && notAServer(e) {
			return true
		}
	}
	return false
}

func notAServer(u netip.Addr) bool {
	return u.IsLinkLocalUnicast() || u.IsLinkLocalMulticast() || u.IsInterfaceLocalMulticast() ||
		u.IsMulticast() || u.IsUnspecified() || u == ipv4Broadcst
}

// ErrNotAllowed is the error of a connection refused because its address is not Allowed.
var ErrNotAllowed = errors.New("netaddr: the address is not one of a managed server")

// Control is a net.Dialer.Control function: it refuses a connection to an address Allowed refuses.
// The net package calls it for every candidate address of a dial, after name resolution, on the
// socket that is about to connect and before anything is sent: the checked address is the
// connected one (DNS names and rebinding included). An address it cannot read is refused.
func Control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrNotAllowed, address)
	}
	if !Allowed(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrNotAllowed, ap.Addr())
	}
	return nil
}

// DialContext connects like d.DialContext with Control checking every candidate address (d's own
// Control and ControlContext are replaced; d is not changed). A name with several addresses
// connects to the first allowed one that answers; refused ones are never connected. When nothing
// connected and at least one candidate was refused, the error matches ErrNotAllowed whatever the
// order of the records and the failures of the others: the name resolves to an address Alice does
// not connect to, which an allowed address that is down must not hide.
func DialContext(ctx context.Context, d *net.Dialer, network, address string) (net.Conn, error) {
	return guardedDial(ctx, d, network, address, Control, ErrNotAllowed)
}

// guardedDial dials through a copy of d whose only control hook is check; when the dial failed and
// check refused a candidate, the error matches refusedErr.
func guardedDial(ctx context.Context, d *net.Dialer, network, address string,
	check func(network, address string, c syscall.RawConn) error, refusedErr error,
) (net.Conn, error) {
	var refused atomic.Bool
	nd := *d
	nd.ControlContext = nil
	nd.Control = func(network, address string, c syscall.RawConn) error {
		err := check(network, address, c)
		if err != nil {
			refused.Store(true)
		}
		return err
	}
	conn, err := nd.DialContext(ctx, network, address)
	if err != nil && refused.Load() && !errors.Is(err, refusedErr) {
		err = fmt.Errorf("%w (another address failed: %w)", refusedErr, err)
	}
	return conn, err
}
