package discovery

import (
	"net/netip"
	"strings"
	"testing"
)

// FuzzParseEntry: no input panics; an accepted entry is canonical (it parses again to itself), a
// host name is one the database stores and never an IP literal, and a range is masked, zone-free,
// never IPv4-mapped and within the size limits.
func FuzzParseEntry(f *testing.F) {
	for _, s := range []string{"10.0.0.5", "10.0.0.0/24", "::ffff:10.0.0.0/120", "2a00:1450::/120", "fe80::1%eth0", "2130706433",
		"0x7f.1", "0177.0.0.1", "www.example.com", "bücher.example", "xn--bcher-kva.example", "a..b", "10.0.0.5/24", "１２７.０.０.１",
		"example.com.", "10.0.0.0/8", "::/0", "a\r\nb"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		e, err := ParseEntry(in)
		if err != nil {
			if _, ok := err.(*Error); !ok { //nolint:errorlint // the parser returns *Error itself, never a wrapped one
				t.Fatalf("ParseEntry(%q) returned a %T", in, err)
			}
			return
		}
		again, err := ParseEntry(e.String())
		if err != nil || again != e {
			t.Fatalf("ParseEntry(%q) = %v; its canonical form %q parses to %v, %v", in, e, e.String(), again, err)
		}
		switch e.Kind {
		case KindHost:
			checkName(t, e.Host)
		case KindAddress, KindRange:
			p := e.Prefix
			if p != p.Masked() || p.Addr().Zone() != "" || p.Addr().Is4In6() {
				t.Fatalf("ParseEntry(%q) = %v: not canonical", in, p)
			}
			if size := uint64(1) << (p.Addr().BitLen() - p.Bits()); size > MaxAddresses {
				t.Fatalf("ParseEntry(%q) = %v: %d addresses", in, p, size)
			}
			if (e.Kind == KindAddress) != p.IsSingleIP() {
				t.Fatalf("ParseEntry(%q): kind %v for %v", in, e.Kind, p)
			}
		default:
			t.Fatalf("ParseEntry(%q): kind %v", in, e.Kind)
		}
	})
}

// FuzzCanonicalHostname: an accepted name (a scope host name or an SNI name) is canonical, fits the
// database CHECK and is never an IP literal or an IPv4 spelling a resolver would read as an address.
func FuzzCanonicalHostname(f *testing.F) {
	for _, s := range []string{"www.example.com", "WWW.Example.COM.", "2130706433", "0x7f.1", "0177.0.0.1", "127.1", "::1",
		"xn--bcher-kva.example", "xn--zz.example", "bücher.example", "a_b", "-a", strings.Repeat("a", 64), "①.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		n, err := CanonicalHostname(in)
		if err != nil {
			return
		}
		checkName(t, n)
		again, err := CanonicalHostname(n)
		if err != nil || again != n {
			t.Fatalf("CanonicalHostname(%q) = %q, which canonicalises to %q, %v", in, n, again, err)
		}
	})
}

func checkName(t *testing.T, n string) {
	t.Helper()
	if !dbName.MatchString(n) || len(n) > MaxNameLen {
		t.Fatalf("name %q does not fit the database CHECK", n)
	}
	if _, err := netip.ParseAddr(n); err == nil {
		t.Fatalf("name %q is an IP literal", n)
	}
	last := n[strings.LastIndexByte(n, '.')+1:]
	if last[0] < 'a' || last[0] > 'z' {
		t.Fatalf("name %q ends in a label a resolver may read as a number", n)
	}
}
