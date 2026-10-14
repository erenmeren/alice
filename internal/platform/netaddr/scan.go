package netaddr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/platform/clock"
)

// Network certificate discovery (plan 2026-10-13, amendment A2) connects to addresses an Admin listed
// in a scan scope. Its rule is stricter than Allowed: a scan may never reach Alice itself, its
// network's infrastructure or anything outside what the Admin explicitly allowed.

// ErrScanRefused is the error of a scan connection the scan policy refuses.
var ErrScanRefused = errors.New("netaddr: the address may not be scanned")

// ScanPolicy decides, at connect time, whether discovery may connect to an address. Production uses
// NewScanPolicy, built per scan; tests inject a permissive policy from internal/testutil/scanpolicy.
type ScanPolicy interface {
	// CheckScan returns nil when a may be scanned, otherwise an error matching ErrScanRefused.
	CheckScan(a netip.Addr) error
}

// DefaultScanRefresh is how long one reading of Alice's own interface addresses and default gateways
// stands before a check reads them again.
const DefaultScanRefresh = 2 * time.Second

// scanBuiltins never hold a host discovery may scan, whatever the settings: loopback, unspecified,
// link-local (the cloud metadata address included), multicast, reserved and special-purpose ranges,
// CGNAT, benchmarking and documentation ranges, the AWS IPv6 metadata address, and the IPv6 forms
// whose embedded IPv4 address Alice cannot locate or check: the local-use NAT64 range (its prefix
// length is the operator's choice), IPv4-compatible and IPv4-translated addresses, and the IETF
// protocol range 2001::/23, Teredo included (refused as a whole: its embedded addresses are a
// relay's and a NATed client's).
var scanBuiltins = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fe80::/10", "ff00::/8", "100::/64", "2001::/23", "2001:db8::/32", "3fff::/20",
		"fd00:ec2::254/128", "64:ff9b:1::/48", "::/96", "::ffff:0:0:0/96",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// scanCandidates returns the addresses a connection to u reaches or names: u itself and the IPv4
// address the well-known NAT64 prefix or 6to4 embed. u is unmapped and valid.
func scanCandidates(u netip.Addr) []netip.Addr {
	out := []netip.Addr{u}
	if u.Is6() {
		b := u.As16()
		switch {
		case nat64Prefix.Contains(u):
			out = append(out, netip.AddrFrom4([4]byte(b[12:16])))
		case sixToFour.Contains(u):
			out = append(out, netip.AddrFrom4([4]byte(b[2:6])))
		}
	}
	return out
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// AllowedForScan reports whether a passes the built-in part of the scan rule: Allowed accepts it
// and neither a nor the IPv4 address it embeds lies in a built-in scan exclusion. It is the check a
// scope entry gets when it is saved; the full rule (Alice's own addresses, gateway, database host,
// Admin exclusions and allowed networks) is the policy of NewScanPolicy.
func AllowedForScan(a netip.Addr) bool {
	if !Allowed(a) {
		return false
	}
	for _, c := range scanCandidates(a.Unmap()) {
		if inAny(c, scanBuiltins) {
			return false
		}
	}
	return true
}

// ScanPolicyInputs are the inputs of NewScanPolicy. The function fields are seams: nil means the
// system source.
type ScanPolicyInputs struct {
	// AllowedNetworks is the Admin's allowlist (setting discovery.allowed_networks): an address
	// outside every one of them is refused, and an empty list refuses everything.
	AllowedNetworks []netip.Prefix
	// GlobalExclusions are the Admin's global exclusions; ScopeExclusions are the scanned scope's.
	GlobalExclusions []netip.Prefix
	ScopeExclusions  []netip.Prefix
	// DatabaseURL is Alice's database DSN (URL or key/value form, as pgx reads it): every host it
	// names is resolved once and refused. Required.
	DatabaseURL string
	// InterfaceAddrs lists Alice's own interface addresses (nil: net.InterfaceAddrs).
	InterfaceAddrs func() ([]netip.Addr, error)
	// DefaultGateways lists the default gateways (nil: /proc/net/route and /proc/net/ipv6_route).
	DefaultGateways func() ([]netip.Addr, error)
	// LookupHost resolves a database host name (nil: the system resolver).
	LookupHost func(ctx context.Context, host string) ([]netip.Addr, error)
	// RefreshEvery is how long one reading of the interface addresses and gateways stands (zero:
	// DefaultScanRefresh). Clock measures that interval (nil: clock.Real; monotonic, so a wall clock
	// change never keeps a reading alive).
	RefreshEvery time.Duration
	Clock        clock.Monotonic
}

// scanPolicy is the production ScanPolicy.
type scanPolicy struct {
	allowed  []netip.Prefix
	excluded []netip.Prefix
	database map[netip.Addr]bool
	ifaces   func() ([]netip.Addr, error)
	gateways func() ([]netip.Addr, error)
	every    time.Duration
	clock    clock.Monotonic

	mu     sync.Mutex
	host   map[netip.Addr]bool // own interface addresses and default gateways, unmapped
	readAt time.Duration
	errRd  error
}

// NewScanPolicy builds the scan policy of one scan. It reads Alice's own interface addresses and
// default gateways (and reads them again while the scan runs, every RefreshEvery) and resolves the
// database hosts once. Any source that cannot be read fails the build: a policy that does not know
// what to protect is never built. A later failed re-read refuses every address until a read succeeds.
func NewScanPolicy(ctx context.Context, in ScanPolicyInputs) (ScanPolicy, error) {
	p := &scanPolicy{ifaces: in.InterfaceAddrs, gateways: in.DefaultGateways, every: in.RefreshEvery, clock: in.Clock,
		database: map[netip.Addr]bool{}}
	var err error
	if p.allowed, err = canonicalPrefixes("allowed network", in.AllowedNetworks); err != nil {
		return nil, err
	}
	global, err := canonicalPrefixes("global exclusion", in.GlobalExclusions)
	if err != nil {
		return nil, err
	}
	scope, err := canonicalPrefixes("scope exclusion", in.ScopeExclusions)
	if err != nil {
		return nil, err
	}
	p.excluded = append(global, scope...)
	if p.ifaces == nil {
		p.ifaces = systemInterfaceAddrs
	}
	if p.gateways == nil {
		p.gateways = systemGateways
	}
	if p.every <= 0 {
		p.every = DefaultScanRefresh
	}
	if p.clock == nil {
		p.clock = clock.Real{}
	}
	db, err := databaseAddrs(ctx, in.DatabaseURL, in.LookupHost)
	if err != nil {
		return nil, err
	}
	for _, a := range db {
		p.database[a.Unmap()] = true
	}
	if _, err := p.hostAddrs(); err != nil {
		return nil, err
	}
	return p, nil
}

// canonicalPrefixes masks every prefix and turns an IPv4-mapped prefix into its IPv4 one.
func canonicalPrefixes(what string, in []netip.Prefix) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() || p.Addr().Zone() != "" {
			return nil, fmt.Errorf("netaddr: invalid %s %q", what, p)
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// hostAddrs returns Alice's own addresses and gateways, read again when the last reading is older
// than the refresh interval. A failed reading is the answer until the next one.
func (p *scanPolicy) hostAddrs() (map[netip.Addr]bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock.Elapsed()
	if p.host != nil || p.errRd != nil {
		if now-p.readAt < p.every {
			return p.host, p.errRd
		}
	}
	p.readAt = now
	p.host, p.errRd = nil, nil
	own, err := p.ifaces()
	if err != nil {
		p.errRd = fmt.Errorf("netaddr: Alice's own addresses cannot be read: %w", err)
		return nil, p.errRd
	}
	gws, err := p.gateways()
	if err != nil {
		p.errRd = fmt.Errorf("netaddr: the default gateway cannot be read: %w", err)
		return nil, p.errRd
	}
	host := make(map[netip.Addr]bool, len(own)+len(gws))
	for _, list := range [][]netip.Addr{own, gws} {
		for _, a := range list {
			host[a.WithZone("").Unmap()] = true
		}
	}
	p.host = host
	return host, nil
}

func refuse(a netip.Addr, why string) error { return fmt.Errorf("%w: %s (%s)", ErrScanRefused, a, why) }

// CheckScan applies the whole rule: built-ins, the database hosts, Alice's own addresses and
// gateways, the Admin's and the scope's exclusions (each also against the IPv4 address a NAT64 or
// 6to4 address embeds), then the Admin's allowlist (against the address connected).
func (p *scanPolicy) CheckScan(a netip.Addr) error {
	if !a.IsValid() || a.Zone() != "" || !AllowedForScan(a) {
		return refuse(a, "never scanned")
	}
	host, err := p.hostAddrs()
	if err != nil {
		return fmt.Errorf("%w: %s (%w)", ErrScanRefused, a, err)
	}
	u := a.Unmap()
	for _, c := range scanCandidates(u) {
		switch {
		case p.database[c]:
			return refuse(a, "Alice's database host")
		case host[c]:
			return refuse(a, "Alice's own address or default gateway")
		case inAny(c, p.excluded) || inAny(netip.AddrFrom16(c.As16()), p.excluded):
			return refuse(a, "excluded")
		}
	}
	if !inAny(u, p.allowed) {
		return refuse(a, "outside the allowed scan networks")
	}
	return nil
}

// databaseAddrs resolves every TCP host the DSN names (Unix socket paths name no address).
func databaseAddrs(ctx context.Context, dsn string, lookup func(context.Context, string) ([]netip.Addr, error)) ([]netip.Addr, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("netaddr: the scan policy needs the database URL")
	}
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("netaddr: the database URL cannot be parsed") // never the DSN: it may carry a password
	}
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	hosts := []string{cfg.Host}
	for _, fb := range cfg.Fallbacks {
		hosts = append(hosts, fb.Host)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var out []netip.Addr
	seen := map[string]bool{}
	for _, h := range hosts {
		if seen[h] || h == "" || strings.HasPrefix(h, "/") {
			continue
		}
		seen[h] = true
		if a, err := netip.ParseAddr(h); err == nil {
			out = append(out, a)
			continue
		}
		as, err := lookup(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("netaddr: the database host %q does not resolve: %w", h, err)
		}
		out = append(out, as...)
	}
	return out, nil
}

func systemInterfaceAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if na, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, na.Unmap())
		}
	}
	return out, nil
}

// ScanControl is a net.Dialer.Control function that applies policy to every candidate address of a
// dial, after name resolution, on the socket about to connect and before anything is sent (DNS
// names and rebinding included). An address it cannot read, and every address when policy is nil,
// is refused. A net.Dialer's ControlContext takes precedence over Control: use ScanDialContext.
func ScanControl(policy ScanPolicy) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: %q", ErrScanRefused, address)
		}
		if policy == nil {
			return refuse(ap.Addr(), "no scan policy")
		}
		return policy.CheckScan(ap.Addr())
	}
}

// ScanDialContext connects like d.DialContext with ScanControl(policy) checking every candidate
// address (d's own Control and ControlContext are replaced; d is not changed). When nothing
// connected and a candidate was refused, the error matches ErrScanRefused.
func ScanDialContext(ctx context.Context, policy ScanPolicy, d *net.Dialer, network, address string) (net.Conn, error) {
	return guardedDial(ctx, d, network, address, ScanControl(policy), ErrScanRefused)
}
