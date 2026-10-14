package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"alice/internal/platform/netaddr"
)

const (
	// ResolveTimeout bounds the lookup of one host name when a scan starts (amendment A3).
	ResolveTimeout = 5 * time.Second
	// ResolveBudget bounds the lookups of one expansion together.
	ResolveBudget = 60 * time.Second
	// MaxAddressesPerName is how many of a name's addresses a scan probes (the first ones the
	// resolver returns, IPv4-mapped forms unmapped, duplicates once).
	MaxAddressesPerName = 8
	// resolveWorkers is how many names are looked up at once.
	resolveWorkers = 8

	// StateExcluded and ErrorCodePolicy are the discovery_endpoints state and last_error_code of an
	// endpoint the policy refused: it is recorded and never dialed.
	StateExcluded   = "excluded"
	ErrorCodePolicy = "policy"
)

// Resolver looks up a host name; *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// SystemResolver is the production resolver: the system's, nothing else (air-gap rule).
var SystemResolver Resolver = net.DefaultResolver

// Endpoint is one combination a scan probes: an address, a port and the SNI name sent ("" = none).
// Host is the scope's host name the address was resolved from ("" for an address or range entry).
type Endpoint struct {
	Address netip.Addr
	Port    uint16
	SNI     string
	Host    string

	excluded bool
}

// State is StateExcluded for an endpoint the policy refused, "" for one a scan dials.
func (e Endpoint) State() string {
	if e.excluded {
		return StateExcluded
	}
	return ""
}

// ErrorCode is ErrorCodePolicy for an excluded endpoint, "" otherwise.
func (e Endpoint) ErrorCode() string {
	if e.excluded {
		return ErrorCodePolicy
	}
	return ""
}

// ExpandInputs are what an expansion is checked against. Policy is the scan's netaddr.ScanPolicy
// (production: netaddr.NewScanPolicy, built per scan; it also holds the rules, so every address is
// checked twice, here and at connect time). Resolver looks up the host names (production:
// SystemResolver). ResolveTimeout bounds each lookup (zero: ResolveTimeout), ResolveBudget all of
// them together (zero: ResolveBudget).
type ExpandInputs struct {
	Rules
	Policy         netaddr.ScanPolicy
	Resolver       Resolver
	ResolveTimeout time.Duration
	ResolveBudget  time.Duration
}

// Expansion is a scope expanded for one scan. Dial holds the only endpoints a scan may connect to;
// Excluded those the rule refused (recorded as excluded, never dialed); Unresolved the host names
// that did not resolve (or resolved to no usable address), in entry order. Addresses counts the
// distinct addresses of both lists, Endpoints both lists.
type Expansion struct {
	Dial       []Endpoint
	Excluded   []Endpoint
	Unresolved []string
	Addresses  int
	Endpoints  int
}

// Expand validates s again (scan time: the rules may have changed since it was saved) and expands
// it. The addresses of address and range entries that the scope's or the global exclusions cover are
// removed; every other address, and every address a host name resolves to (each name looked up
// once), is an endpoint that is dialable only when the built-in rule (netaddr.AllowedForScan), the
// allowed networks, the exclusions and the policy all accept it, and excluded otherwise. The limits
// are applied again to the resolved addresses before any endpoint is built. Fails closed: no allowed
// networks, no policy, or host names and no resolver is an error, and so is a cancelled ctx.
func Expand(ctx context.Context, s Scope, in ExpandInputs) (*Expansion, error) {
	c, err := compile(s, in.Rules)
	if err != nil {
		return nil, err
	}
	if in.Policy == nil {
		return nil, errors.New("discovery: no scan policy")
	}
	if len(c.hosts) > 0 && in.Resolver == nil {
		return nil, errors.New("discovery: no resolver for the host names")
	}
	timeout := in.ResolveTimeout
	if timeout <= 0 {
		timeout = ResolveTimeout
	}
	budget := in.ResolveBudget
	if budget <= 0 {
		budget = ResolveBudget
	}
	resolved := resolveAll(ctx, in.Resolver, c.hosts, timeout, budget)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	excluded := newPrefixSet(in.GlobalExclusions, c.exclusions)
	allowed := newPrefixSet(in.AllowedNetworks)
	var literal []netip.Addr
	for _, p := range c.ranges {
		a := p.Addr()
		for n := prefixSize(p); n > 0; n-- {
			if !excluded.contains(a) {
				literal = append(literal, a)
			}
			a = a.Next()
		}
	}
	distinct := make(map[netip.Addr]bool, len(literal))
	for _, a := range literal {
		distinct[a] = true
	}
	perName := 0
	x := &Expansion{}
	for i, as := range resolved {
		if len(as) == 0 {
			x.Unresolved = append(x.Unresolved, c.hosts[i])
		}
		perName += len(as)
		for _, a := range as {
			distinct[a] = true
		}
	}
	if len(distinct) > MaxAddresses {
		return nil, fail(ErrTooLarge, "entries", -1, "", fmt.Sprintf("the scope's names resolve to %d addresses in all; at most %d", len(distinct), MaxAddresses))
	}
	if eps := c.endpoints(len(literal), perName); eps > MaxEndpoints {
		return nil, fail(ErrTooLarge, "entries", -1, "", fmt.Sprintf("the scope covers %d endpoints once its names are resolved; at most %d", eps, MaxEndpoints))
	}
	x.Addresses = len(distinct)

	verdicts := make(map[netip.Addr]bool, len(distinct))
	dialable := func(a netip.Addr) bool {
		ok, seen := verdicts[a]
		if !seen {
			ok = netaddr.AllowedForScan(a) && allowed.contains(a) && !excluded.contains(a) && in.Policy.CheckScan(a) == nil
			verdicts[a] = ok
		}
		return ok
	}
	type key struct {
		a    netip.Addr
		port uint16
		sni  string
	}
	done := make(map[key]bool)
	add := func(e Endpoint) {
		k := key{e.Address, e.Port, e.SNI}
		if done[k] {
			return
		}
		done[k] = true
		if dialable(e.Address) {
			x.Dial = append(x.Dial, e)
			return
		}
		e.excluded = true
		x.Excluded = append(x.Excluded, e)
	}
	snis := c.sni
	if len(snis) == 0 {
		snis = []string{""} // an IP-literal scope without SNI names: one handshake without SNI
	}
	for _, a := range literal {
		for _, port := range c.ports {
			for _, sni := range snis {
				add(Endpoint{Address: a, Port: port, SNI: sni})
			}
		}
	}
	for i, as := range resolved {
		for _, a := range as {
			for _, port := range c.ports {
				add(Endpoint{Address: a, Port: port, SNI: c.hosts[i], Host: c.hosts[i]})
			}
		}
	}
	x.Endpoints = len(x.Dial) + len(x.Excluded)
	return x, nil
}

// resolveAll looks every name up once, a few at a time, each with its own deadline and all within
// budget. A name that does not resolve, or is not looked up before the budget runs out, has no
// addresses. Addresses are unmapped; zoned or invalid ones (no resolver returns
// them for a name) are dropped; at most MaxAddressesPerName are kept per name.
func resolveAll(ctx context.Context, r Resolver, hosts []string, timeout, budget time.Duration) [][]netip.Addr {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	out := make([][]netip.Addr, len(hosts))
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(resolveWorkers, len(hosts)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				out[i] = lookup(ctx, r, hosts[i], timeout)
			}
		}()
	}
feed:
	for i := range hosts {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	return out
}

func lookup(ctx context.Context, r Resolver, host string, timeout time.Duration) []netip.Addr {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	as, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range as {
		a = a.Unmap()
		if !a.IsValid() || a.Zone() != "" || containsAddr(out, a) {
			continue
		}
		out = append(out, a)
		if len(out) == MaxAddressesPerName {
			break
		}
	}
	return out
}

func containsAddr(as []netip.Addr, a netip.Addr) bool {
	for _, b := range as {
		if a == b {
			return true
		}
	}
	return false
}
