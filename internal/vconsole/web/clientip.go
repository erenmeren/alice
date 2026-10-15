package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses the --trusted-proxy values: CIDR ranges, or bare addresses (a
// single host). Empty values and the all-addresses ranges are refused: trusting everyone would
// let any client choose its own rate limit key.
func ParseTrustedProxies(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, errors.New("trusted proxy: empty value")
		}
		var p netip.Prefix
		if strings.Contains(s, "/") {
			var err error
			if p, err = netip.ParsePrefix(s); err != nil {
				return nil, fmt.Errorf("trusted proxy %q: not a CIDR range", s)
			}
		} else {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: not an address or CIDR range", s)
			}
			if a.Zone() != "" {
				return nil, fmt.Errorf("trusted proxy %q: zones are not allowed", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		a := p.Addr()
		// Store IPv4-mapped ranges as IPv4, since peers are compared after Unmap.
		if a.Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("trusted proxy %q: range too wide", s)
			}
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("trusted proxy %q: trusting every address is refused", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientAddr is the address of the client of a request: the TCP peer, unless the peer is a
// trusted proxy, in which case the right-most X-Forwarded-For entry that is not itself trusted.
// Entries further left are client-controlled and never chosen over it. An unparsable remote
// gives the zero address. The result has no zone and no IPv4-mapping.
func clientAddr(remote string, xff []string, trusted []netip.Prefix) netip.Addr {
	peer := parseRemote(remote)
	if !peer.IsValid() || len(trusted) == 0 || !inAny(peer, trusted) {
		return peer
	}
	var entries []string
	for _, line := range xff {
		entries = append(entries, strings.Split(line, ",")...)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(entries[i]))
		if err != nil {
			continue
		}
		a = a.Unmap().WithZone("")
		if !inAny(a, trusted) {
			return a
		}
	}
	return peer
}

func parseRemote(remote string) netip.Addr {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

// limiterKey is the rate limit bucket of a request. An IPv6 client is keyed by its /64 prefix,
// since one host usually holds a whole /64; an unparsable address shares the zero-address bucket.
func (s *Server) limiterKey(r *http.Request) netip.Addr {
	a := clientAddr(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), s.cfg.TrustedProxies)
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().Addr()
	}
	return a
}
