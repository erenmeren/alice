package discovery

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"alice/internal/platform/netaddr"
	"alice/internal/testutil/scanpolicy"
)

// FuzzParseEntry: no input panics; an accepted entry is canonical (it parses again to itself), a
// host name is one the database stores and never an IP literal, and a range is masked, zone-free,
// never IPv4-mapped and within the size limits.
func FuzzParseEntry(f *testing.F) {
	for _, s := range []string{"10.0.0.5", "10.0.0.0/24", "::ffff:10.0.0.0/120", "2a00:1450::/120", "fe80::1%eth0", "2130706433",
		"0x7f.1", "0177.0.0.1", "www.example.com", "bücher.example", "xn--bcher-kva.example", "a..b", "10.0.0.5/24", "１２７.０.０.１",
		"example.com.", "10.0.0.0/8", "::/0", "a\r\nb", "0.0.0.0/0", "::ffff:0.0.0.0/96", "10.0.0.1/32"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if x, err := ParseExclusion(in); err == nil {
			if x != x.Masked() || x.Addr().Zone() != "" || x.Addr().Is4In6() {
				t.Fatalf("ParseExclusion(%q) = %v: not canonical", in, x)
			}
			if again, err := ParseExclusion(Entry{Kind: kindOf(x), Prefix: x}.String()); err != nil || again != x {
				t.Fatalf("ParseExclusion(%q) = %v does not parse again: %v, %v", in, x, again, err)
			}
		} else if _, ok := err.(*Error); !ok { //nolint:errorlint // the parser returns *Error itself
			t.Fatalf("ParseExclusion(%q) returned a %T", in, err)
		}
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

// FuzzExpand: whatever the scope, the rules, the resolver's answers and the policy, every endpoint of
// the dial list passes the built-in rule, the allowed networks, every exclusion and the policy, and
// no address is both dialable and excluded.
func FuzzExpand(f *testing.F) {
	f.Add("10.0.0.0/28,a.example,127.0.0.1,192.0.0.0/22", "10.0.0.0/8,192.0.0.0/16", "10.0.0.4/30", "10.0.0.8",
		"10.0.0.9,127.0.0.1,::ffff:10.0.0.10,169.254.169.254,64:ff9b::7f00:1", "10.0.0.1/32")
	f.Add("b.example,2a00:1450::/124", "2a00:1450::/112,::/0", "", "", "2a00:1450::3,fe80::1,::1,2002:7f00:1::", "")
	f.Add("10.1.0.0/24", "0.0.0.0/0", "10.1.0.0/25", "10.1.0.128/26", "", "10.1.0.200/29")
	f.Fuzz(func(t *testing.T, entries, allowed, global, scopeExcl, answers, except string) {
		split := func(s string) []string {
			if s == "" {
				return nil
			}
			return strings.Split(s, ",")
		}
		prefixes := func(s string) []netip.Prefix {
			var out []netip.Prefix
			for _, e := range split(s) {
				if p, err := ParseExclusion(e); err == nil {
					out = append(out, p)
				}
			}
			return out
		}
		var as []netip.Addr
		for _, a := range split(answers) {
			if ad, err := netip.ParseAddr(a); err == nil {
				as = append(as, ad)
			}
		}
		res := &fuzzResolver{answers: as}
		rules := Rules{AllowedNetworks: prefixes(allowed), GlobalExclusions: prefixes(global)}
		exceptions := prefixes(except)
		pol := scanpolicy.Permissive(exceptions...)
		s := Scope{Name: "fuzz", Entries: split(entries), Ports: []int{443, 8443}, Exclusions: split(scopeExcl)}
		x, err := Expand(context.Background(), s, ExpandInputs{Rules: rules, Policy: pol, Resolver: res})
		if err != nil {
			return
		}
		excl := append(append([]netip.Prefix(nil), rules.GlobalExclusions...), prefixes(scopeExcl)...)
		dial := map[netip.Addr]bool{}
		for _, e := range x.Dial {
			a := e.Address
			dial[a] = true
			if !netaddr.AllowedForScan(a) || !inAny(a, rules.AllowedNetworks) || inAny(a, excl) || inAny(a, exceptions) || pol.CheckScan(a) != nil {
				t.Fatalf("%s is dialable", a)
			}
			if e.State() != "" || e.ErrorCode() != "" {
				t.Fatalf("dialable %s has state %q", a, e.State())
			}
		}
		for _, e := range x.Excluded {
			if dial[e.Address] {
				t.Fatalf("%s is dialable and excluded", e.Address)
			}
			if e.State() != StateExcluded || e.ErrorCode() != ErrorCodePolicy {
				t.Fatalf("excluded %s has state %q", e.Address, e.State())
			}
		}
		if len(x.Dial)+len(x.Excluded) != x.Endpoints || x.Endpoints > MaxEndpoints || x.Addresses > MaxAddresses {
			t.Fatalf("counts %d+%d != %d or over the limits (%d addresses)", len(x.Dial), len(x.Excluded), x.Endpoints, x.Addresses)
		}
	})
}

// fuzzResolver answers every name with the same addresses.
type fuzzResolver struct{ answers []netip.Addr }

func (r *fuzzResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.answers, nil
}

// inAny is the obvious check, independent of the package's sorted prefix sets.
func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) || p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}
