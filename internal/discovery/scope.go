// Package discovery is network certificate discovery (plan 2026-10-13-network-discovery): the scan
// scopes an Administrator defines, their validation and expansion into endpoints, the scanner and
// the ingestion of what the endpoints present.
//
// This file is the scope model and its validation, shared by the API (save time, the live size
// preview) and the scanner (scan time). Nothing here resolves a name or opens a connection.
package discovery

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"alice/internal/platform/netaddr"
	"alice/internal/platform/validate"
)

// The limits of a scope (design decision 1; migration 00014 mirrors them).
const (
	MaxEntries     = 256   // entries of a scope
	MaxPorts       = 16    // ports of a scope
	MaxPortList    = 1024  // elements of a port list before de-duplication (a longer one is refused unread)
	MaxSNINames    = 256   // SNI names of a scope
	MaxExclusions  = 256   // exclusions of a scope, and entries of the allowed networks or global exclusions settings
	MaxAddresses   = 4096  // addresses of a scope (a /20), host names' addresses included
	MaxEndpoints   = 20000 // address x port x SNI combinations of one scan
	MaxEntryLen    = 255   // characters of one entry or exclusion as stored
	MaxNameLen     = 253   // characters of a host or SNI name
	MaxScopeName   = 100   // characters of a scope's name
	MinIPv4Bits    = 20    // the widest IPv4 range of an entry
	MinIPv6Bits    = 120   // the widest IPv6 range of an entry
	MaxRate        = 100   // new connections per second
	MaxConcurrency = 64    // workers of one scan
	MaxSchedule    = 168   // hours between scheduled scans

	DefaultRate        = 20
	DefaultConcurrency = 32
)

// The kinds of refusal. Each maps to one API code (internal/api/errors.go): ErrTooLarge ALC-DSC-0001,
// ErrNotAllowed ALC-DSC-0002, ErrInvalid ALC-DSC-0003, ErrSchedule ALC-DSC-0009. Every error of this
// file is an *Error that unwraps to one of them.
var (
	ErrTooLarge   = errors.New("discovery: the scope is too large")
	ErrNotAllowed = errors.New("discovery: the entry may not be scanned")
	ErrInvalid    = errors.New("discovery: the entry is not valid")
	ErrSchedule   = errors.New("discovery: the schedule is not valid")
)

// Error is a refusal of one field (the scope's JSON and column name) and, for a list, one element
// (Index; -1 for the field as a whole). Value is the element as given (an Administrator's own input,
// never an address a name resolved to).
type Error struct {
	Kind   error
	Field  string
	Index  int
	Value  string
	Detail string
}

func (e *Error) Error() string {
	s := e.Kind.Error() + ": " + e.Field
	if e.Index >= 0 {
		s += "[" + strconv.Itoa(e.Index) + "] " + strconv.Quote(e.Value)
	}
	return s + ": " + e.Detail
}

func (e *Error) Unwrap() error { return e.Kind }

func fail(kind error, field string, index int, value, detail string) *Error {
	return &Error{Kind: kind, Field: field, Index: index, Value: value, Detail: detail}
}

// EntryKind is what an entry names.
type EntryKind int

const (
	KindAddress EntryKind = iota + 1 // one IP address
	KindRange                        // a CIDR range of more than one address
	KindHost                         // a host name, resolved when a scan starts
)

// Entry is one parsed scope entry. Prefix is set for an address (a /32 or /128) and a range (masked,
// IPv4-mapped forms turned into IPv4); Host for a host name (canonical: lower case, A-labels, no
// trailing dot).
type Entry struct {
	Kind   EntryKind
	Prefix netip.Prefix
	Host   string
}

// String is the canonical form a scope stores: an address without a length, a range, or a name.
func (e Entry) String() string {
	switch e.Kind {
	case KindAddress:
		return e.Prefix.Addr().String()
	case KindRange:
		return e.Prefix.String()
	}
	return e.Host
}

// prefixSize is the number of addresses of p (capped at 2^62: only exclusions are that wide, and
// their sizes are never added up).
func prefixSize(p netip.Prefix) int {
	return 1 << min(p.Addr().BitLen()-p.Bits(), 62)
}

// ParseEntry parses one scope entry: an IP address, a CIDR range (IPv4 at most a /20, IPv6 at most a
// /120) or a host name (CanonicalHostname). An IPv4-mapped address or range is its IPv4 form. Refused
// as invalid: anything with surrounding or inner white space or control characters, a zone, a range
// with host bits set (10.0.0.5/24 is ambiguous: the address or its network?), an IPv4-mapped range
// shorter than /96 (it mixes the two families), and every other IPv4 spelling (decimal 2130706433,
// octal 0177.0.0.1, hex 0x7f.1, short 127.1): netip accepts only the dotted-decimal form, and the
// host name rule refuses a name whose last label does not start with a letter.
func ParseEntry(s string) (Entry, error) {
	p, isIP, err := parseIPOrPrefix("entries", s)
	if err != nil {
		return Entry{}, err
	}
	if !isIP {
		h, err := hostname("entries", s)
		if err != nil {
			return Entry{}, err
		}
		return Entry{Kind: KindHost, Host: h}, nil
	}
	minBits := MinIPv4Bits
	if p.Addr().Is6() {
		minBits = MinIPv6Bits
	}
	if p.Bits() < minBits {
		return Entry{}, fail(ErrTooLarge, "entries", 0, s, fmt.Sprintf("a range may be at most a /%d", minBits))
	}
	if p.IsSingleIP() {
		return Entry{Kind: KindAddress, Prefix: p}, nil
	}
	return Entry{Kind: KindRange, Prefix: p}, nil
}

// ParseExclusion parses one exclusion (of a scope, or of the global exclusions and allowed networks
// settings): an IP address or a CIDR range of any size, with the address rules of ParseEntry. A host
// name is refused: an exclusion is enforced on the address a connection goes to.
func ParseExclusion(s string) (netip.Prefix, error) {
	p, isIP, err := parseIPOrPrefix("exclusions", s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !isIP {
		return netip.Prefix{}, fail(ErrInvalid, "exclusions", 0, s, "an exclusion is an IP address or a network range, not a host name")
	}
	return p, nil
}

// ParseNetworks parses a settings list (discovery.allowed_networks, discovery.exclusions) with
// ParseExclusion. Any element that does not parse fails the whole list: a caller that cannot read
// the allowed networks scans nothing.
func ParseNetworks(list []string) ([]netip.Prefix, error) {
	if len(list) > MaxExclusions {
		return nil, fail(ErrTooLarge, "networks", -1, "", fmt.Sprintf("at most %d networks", MaxExclusions))
	}
	out := make([]netip.Prefix, 0, len(list))
	for i, s := range list {
		p, err := ParseExclusion(s)
		if err != nil {
			e := err.(*Error) //nolint:errorlint,forcetypeassert // ParseExclusion returns *Error itself
			e.Field, e.Index = "networks", i
			return nil, e
		}
		out = append(out, p)
	}
	return out, nil
}

// parseIPOrPrefix parses s as an address or a CIDR range when it looks like one (isIP), refusing
// what no part of Alice should read as either. A string that is neither is returned with isIP false
// for the host name rule.
func parseIPOrPrefix(field, s string) (p netip.Prefix, isIP bool, err error) {
	if s == "" || len(s) > MaxEntryLen {
		return p, false, fail(ErrInvalid, field, 0, s, fmt.Sprintf("an entry has 1 to %d characters", MaxEntryLen))
	}
	if strings.ContainsAny(s, "/%:") || (s[0] >= '0' && s[0] <= '9' && strings.Trim(s, "0123456789.") == "") {
		isIP = true // an address, a range, an IPv6 or zoned form, or digits and dots: never a host name
	}
	if !isIP {
		return p, false, nil
	}
	if strings.Contains(s, "%") {
		return p, true, fail(ErrInvalid, field, 0, s, "an address with a zone (%) is not accepted")
	}
	if addr, perr := netip.ParseAddr(s); perr == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), true, nil
	}
	pp, perr := netip.ParsePrefix(s)
	if perr != nil {
		return p, true, fail(ErrInvalid, field, 0, s, "not an IP address (10.0.0.5) or a network range (10.0.0.0/24)")
	}
	if pp != pp.Masked() {
		return p, true, fail(ErrInvalid, field, 0, s, "the range has host bits set; did you mean "+pp.Masked().String()+"?")
	}
	if pp.Addr().Is4In6() {
		// At least /96 here: every ::ffff: address has bits 80-95 set, so a shorter mapped range has
		// host bits set and was refused above (it would mix IPv4 and IPv6 space).
		pp = netip.PrefixFrom(pp.Addr().Unmap(), pp.Bits()-96)
	}
	return pp, true, nil
}

// CanonicalHostname validates a host name (a scope entry) or an SNI name (amendment A3) and returns
// its canonical form: ASCII lower case, internationalised labels as IDNA A-labels (xn--), one
// trailing dot removed. Refused: an IP literal of either family, white space, control characters
// and every character outside letters, digits, hyphen and dot (no wildcard, no underscore, no
// port); an empty label; a label longer than 63 characters or starting or ending with a hyphen; a
// name longer than 253 characters; an xn-- label that is not valid Punycode; and a name whose last
// label does not start with a letter, so that no IPv4 spelling a resolver accepts (2130706433,
// 0x7f.1, 0177.0.0.1, 127.1) is ever a name.
func CanonicalHostname(s string) (string, error) { return hostname("sni_names", s) }

func hostname(field, s string) (string, error) {
	bad := func(detail string) (string, error) { return "", fail(ErrInvalid, field, 0, s, detail) }
	if s == "" {
		return bad(fmt.Sprintf("a name has 1 to %d characters", MaxNameLen))
	}
	if len(s) > MaxEntryLen {
		return bad(fmt.Sprintf("an entry has at most %d characters", MaxEntryLen))
	}
	if !utf8.ValidString(s) {
		return bad("not valid UTF-8")
	}
	n := asciiLower(s)
	if !isASCII(n) {
		// The IDNA2008 registration rules, without the UTS #46 lookup mapping: a character the mapping
		// would silently drop or fold (a zero-width space, a full-width digit, a circled one) is refused,
		// so the name scanned is the name shown. The ASCII rules below then apply to the A-labels.
		a, err := idna.Registration.ToASCII(n)
		if err != nil || !isASCII(a) {
			return bad("not a valid internationalised name; give it in lower case or in its A-label (xn--) form")
		}
		n = a
	}
	n = strings.TrimSuffix(n, ".")
	if n == "" || len(n) > MaxNameLen {
		return bad(fmt.Sprintf("a name has 1 to %d characters", MaxNameLen))
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return bad("an IP address is not a name")
	}
	labels := strings.Split(n, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return bad("each part of a name between dots has 1 to 63 characters")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return bad("a part of a name starts or ends with a hyphen")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return bad("a name has only letters, digits, hyphens and dots")
			}
		}
		if strings.HasPrefix(l, "xn--") {
			u, err := idna.Registration.ToUnicode(l)
			if err != nil {
				return bad("the xn-- part is not a valid internationalised label")
			}
			if back, err := idna.Registration.ToASCII(u); err != nil || back != l {
				return bad("the xn-- part is not a valid internationalised label")
			}
		}
	}
	if last := labels[len(labels)-1]; last[0] < 'a' || last[0] > 'z' {
		return bad("the last part of a name starts with a letter (a number there reads as an IP address)")
	}
	return n, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// asciiLower lower-cases ASCII letters only (strings.ToLower would apply Unicode case rules).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// Schedule is a scope's optional schedule: a scan every Hours hours (0: none), optionally only inside
// a daily window from WindowStart to WindowEnd ("HH:MM", 24-hour; a window may cross midnight) in
// TimeZone (an IANA name; empty is UTC). The binary embeds the zone database (time/tzdata in
// cmd/alice), so validation does not depend on the image.
type Schedule struct {
	Hours       int
	WindowStart string
	WindowEnd   string
	TimeZone    string
}

// Scope is a scan scope as the API receives it and the database stores it (discovery_scopes).
type Scope struct {
	Name          string
	Entries       []string
	Ports         []int
	SNINames      []string
	Exclusions    []string
	Enabled       bool
	Schedule      Schedule
	AlertOnExpiry bool
	RatePerSec    int // 0: DefaultRate
	Concurrency   int // 0: DefaultConcurrency
}

// Rules are the Administrator's settings a scope is checked against: the allowed scan networks (an
// empty list allows nothing) and the global exclusions.
type Rules struct {
	AllowedNetworks  []netip.Prefix
	GlobalExclusions []netip.Prefix
}

// compiled is a validated scope.
type compiled struct {
	scope      Scope
	ranges     []netip.Prefix // address and range entries, de-duplicated and without the ones inside another
	hosts      []string       // host name entries, de-duplicated, in order
	exclusions []netip.Prefix // the scope's own exclusions
	sni        []string
	ports      []uint16
	addresses  int // addresses of ranges
}

// Validate checks a scope against the limits and the rules and returns it canonical: entries,
// exclusions and SNI names in their canonical forms and de-duplicated (first occurrence kept), ports
// de-duplicated, defaults filled in. The first refusal is returned (an *Error). Checks, in order:
// the name; the counts of every list; every entry's syntax and size; the scope's size arithmetic
// (before any address is enumerated); then whether every entry may be scanned.
func Validate(s Scope, r Rules) (Scope, error) {
	c, err := compile(s, r)
	if err != nil {
		return Scope{}, err
	}
	return c.scope, nil
}

func compile(s Scope, r Rules) (*compiled, error) {
	name := strings.TrimSpace(s.Name)
	if name == "" || utf8.RuneCountInString(s.Name) > MaxScopeName || !validate.StorableText(s.Name) || strings.ContainsFunc(s.Name, isControl) {
		return nil, fail(ErrInvalid, "name", -1, "", fmt.Sprintf("a name has 1 to %d characters", MaxScopeName))
	}
	if len(s.Entries) == 0 {
		return nil, fail(ErrInvalid, "entries", -1, "", "a scope has at least one entry")
	}
	if len(s.Entries) > MaxEntries {
		return nil, fail(ErrTooLarge, "entries", -1, "", fmt.Sprintf("at most %d entries", MaxEntries))
	}
	if len(s.SNINames) > MaxSNINames {
		return nil, fail(ErrTooLarge, "sni_names", -1, "", fmt.Sprintf("at most %d server names", MaxSNINames))
	}
	if len(s.Exclusions) > MaxExclusions {
		return nil, fail(ErrTooLarge, "exclusions", -1, "", fmt.Sprintf("at most %d exclusions", MaxExclusions))
	}
	c := &compiled{}
	out := s

	ports, err := checkPorts(s.Ports)
	if err != nil {
		return nil, err
	}
	out.Ports = make([]int, len(ports))
	for i, p := range ports {
		out.Ports[i] = int(p)
	}
	c.ports = ports

	out.SNINames = nil
	for i, n := range s.SNINames {
		h, err := hostname("sni_names", n)
		if err != nil {
			err.(*Error).Index = i //nolint:errorlint,forcetypeassert // hostname returns *Error itself
			return nil, err
		}
		if !slices.Contains(out.SNINames, h) {
			out.SNINames = append(out.SNINames, h)
		}
	}
	c.sni = out.SNINames

	out.Exclusions = nil
	for i, x := range s.Exclusions {
		p, err := ParseExclusion(x)
		if err != nil {
			err.(*Error).Index = i //nolint:errorlint,forcetypeassert // ParseExclusion returns *Error itself
			return nil, err
		}
		if !slices.Contains(c.exclusions, p) {
			c.exclusions = append(c.exclusions, p)
			out.Exclusions = append(out.Exclusions, Entry{Kind: kindOf(p), Prefix: p}.String())
		}
	}

	out.Entries = nil
	var prefixes []netip.Prefix
	var prefixIndex []int
	for i, raw := range s.Entries {
		e, err := ParseEntry(raw)
		if err != nil {
			err.(*Error).Index = i //nolint:errorlint,forcetypeassert // ParseEntry returns *Error itself
			return nil, err
		}
		str := e.String()
		if slices.Contains(out.Entries, str) {
			continue
		}
		out.Entries = append(out.Entries, str)
		if e.Kind == KindHost {
			c.hosts = append(c.hosts, e.Host)
		} else {
			prefixes = append(prefixes, e.Prefix)
			prefixIndex = append(prefixIndex, i)
		}
	}
	c.ranges = outermost(prefixes)
	for _, p := range c.ranges {
		c.addresses += prefixSize(p)
	}

	if err := c.checkSize(); err != nil {
		return nil, err
	}
	if out.RatePerSec == 0 {
		out.RatePerSec = DefaultRate
	}
	if out.RatePerSec < 1 || out.RatePerSec > MaxRate {
		return nil, fail(ErrInvalid, "rate_per_sec", -1, "", fmt.Sprintf("1 to %d connections per second", MaxRate))
	}
	if out.Concurrency == 0 {
		out.Concurrency = DefaultConcurrency
	}
	if out.Concurrency < 1 || out.Concurrency > MaxConcurrency {
		return nil, fail(ErrInvalid, "concurrency", -1, "", fmt.Sprintf("1 to %d workers", MaxConcurrency))
	}
	if out.Schedule, err = checkSchedule(s.Schedule); err != nil {
		return nil, err
	}

	// Whether the entries may be scanned: the size checks above bound this walk to MaxAddresses
	// addresses per entry.
	if len(r.AllowedNetworks) == 0 {
		return nil, fail(ErrNotAllowed, "entries", 0, s.Entries[0], "no allowed scan networks are set: nothing may be scanned")
	}
	allowed := newPrefixSet(r.AllowedNetworks)
	blocked := newPrefixSet(r.GlobalExclusions, c.exclusions, netaddr.ScanBuiltins())
	for k, p := range prefixes {
		if err := checkAllowed(p, allowed, blocked); err != "" {
			i := prefixIndex[k]
			return nil, fail(ErrNotAllowed, "entries", i, s.Entries[i], err)
		}
	}
	c.scope = out
	return c, nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

func kindOf(p netip.Prefix) EntryKind {
	if p.IsSingleIP() {
		return KindAddress
	}
	return KindRange
}

func checkPorts(in []int) ([]uint16, error) {
	if len(in) == 0 {
		return nil, fail(ErrInvalid, "ports", -1, "", "a scope has at least one port")
	}
	tooMany := fail(ErrTooLarge, "ports", -1, "", fmt.Sprintf("at most %d ports", MaxPorts))
	if len(in) > MaxPortList {
		return nil, tooMany
	}
	var seen [65536 / 64]uint64
	var out []uint16
	for i, p := range in {
		if p < 1 || p > 65535 {
			return nil, fail(ErrInvalid, "ports", i, strconv.Itoa(p), "a port is a number from 1 to 65535")
		}
		if seen[p/64]&(1<<(p%64)) != 0 {
			continue
		}
		seen[p/64] |= 1 << (p % 64)
		if out = append(out, uint16(p)); len(out) > MaxPorts {
			return nil, tooMany
		}
	}
	return out, nil
}

// outermost returns the prefixes that no other one contains, sorted by address (two CIDR ranges
// either nest or do not overlap), so the result is disjoint and its sizes add up to the addresses
// the prefixes cover. Sorted by address and then widest first, a prefix inside an earlier one is
// inside the last one kept: one pass after the sort.
func outermost(ps []netip.Prefix) prefixSet {
	sorted := slices.Clone(ps)
	slices.SortFunc(sorted, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	var out prefixSet
	for _, p := range sorted {
		if n := len(out); n > 0 && out[n-1].Bits() <= p.Bits() && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// prefixSet is a set of disjoint prefixes sorted by address (outermost's result): membership is a
// binary search, not a walk over every prefix.
type prefixSet []netip.Prefix

// newPrefixSet merges prefix lists into a set; each prefix is masked and an IPv4-mapped one of at
// least 96 bits becomes its IPv4 form (the addresses checked are unmapped).
func newPrefixSet(lists ...[]netip.Prefix) prefixSet {
	var all []netip.Prefix
	for _, l := range lists {
		for _, p := range l {
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			all = append(all, p.Masked())
		}
	}
	return outermost(all)
}

// find returns the prefix of the set that holds a.
func (s prefixSet) find(a netip.Addr) (netip.Prefix, bool) {
	i, _ := slices.BinarySearchFunc(s, a, func(p netip.Prefix, a netip.Addr) int {
		if p.Addr().Compare(a) <= 0 {
			return -1
		}
		return 1
	}) // i: the first prefix starting after a
	if i == 0 || !s[i-1].Contains(a) {
		return netip.Prefix{}, false
	}
	return s[i-1], true
}

func (s prefixSet) contains(a netip.Addr) bool {
	_, ok := s.find(a)
	return ok
}

// covers reports whether every address of p is in the set: one prefix of the set holds p, or the
// prefixes of the set inside p add up to it.
func (s prefixSet) covers(p netip.Prefix) bool {
	if q, ok := s.find(p.Addr()); ok && q.Bits() <= p.Bits() {
		return true
	}
	i, _ := slices.BinarySearchFunc(s, p.Addr(), func(q netip.Prefix, a netip.Addr) int { return q.Addr().Compare(a) })
	n := 0
	for ; i < len(s) && p.Contains(s[i].Addr()); i++ {
		n += prefixSize(s[i])
	}
	return n == prefixSize(p)
}

// lastAddr is the highest address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As16()
	off := 0
	if p.Addr().Is4() {
		off = 96
	}
	for i := off + p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a := netip.AddrFrom16(b)
	if p.Addr().Is4() {
		return a.Unmap()
	}
	return a
}

// checkSize applies the scope limits to the counts alone: addresses (a host name counts as one, its
// resolved addresses are counted again at expansion) and endpoints. Nothing is enumerated.
func (c *compiled) checkSize() error {
	addrs := c.addresses + len(c.hosts)
	if addrs > MaxAddresses {
		return fail(ErrTooLarge, "entries", -1, "", fmt.Sprintf("the scope covers %d addresses; at most %d", addrs, MaxAddresses))
	}
	if eps := c.endpoints(c.addresses, len(c.hosts)); eps > MaxEndpoints {
		return fail(ErrTooLarge, "entries", -1, "", fmt.Sprintf("the scope covers %d endpoints (address x port x server name); at most %d", eps, MaxEndpoints))
	}
	return nil
}

// endpoints counts address x port x SNI: a literal address is probed once per SNI name (once with
// none when the scope lists none), a host name's address once, with the name as SNI.
func (c *compiled) endpoints(literal, resolved int) int {
	return literal*len(c.ports)*max(1, len(c.sni)) + resolved*len(c.ports)
}

// checkAllowed refuses an address or range that is not entirely inside the allowed networks (set
// arithmetic), or whose every address the built-in rule or an exclusion refuses. blocked holds the
// exclusions and the built-in exclusions: the walk jumps over each of its prefixes at once and stops
// at the first scannable address. A range only partly refused stays: its refused addresses are
// excluded at expansion (and listed in the preview).
func checkAllowed(p netip.Prefix, allowed, blocked prefixSet) string {
	if !allowed.covers(p) {
		return "outside the allowed scan networks"
	}
	for a := p.Addr(); a.IsValid() && p.Contains(a); {
		if q, ok := blocked.find(a); ok {
			a = lastAddr(q).Next()
			continue
		}
		if netaddr.AllowedForScan(a) {
			return ""
		}
		a = a.Next()
	}
	return "an address Alice never scans, or excluded"
}

func checkSchedule(s Schedule) (Schedule, error) {
	if s.Hours < 0 || s.Hours > MaxSchedule {
		return s, fail(ErrSchedule, "schedule_hours", -1, "", fmt.Sprintf("every 1 to %d hours", MaxSchedule))
	}
	if s.TimeZone == "" {
		s.TimeZone = "UTC"
	}
	if !zoneName(s.TimeZone) {
		return s, fail(ErrSchedule, "window_tz", -1, s.TimeZone, "not an IANA time zone name (for example UTC or Europe/Istanbul)")
	}
	if (s.WindowStart == "") != (s.WindowEnd == "") {
		return s, fail(ErrSchedule, "window", -1, "", "a window has a start and an end")
	}
	if s.WindowStart == "" {
		return s, nil
	}
	if s.Hours == 0 {
		return s, fail(ErrSchedule, "window", -1, "", "a window narrows a schedule; set the interval first")
	}
	start, ok1 := timeOfDay(s.WindowStart)
	end, ok2 := timeOfDay(s.WindowEnd)
	if !ok1 || !ok2 {
		return s, fail(ErrSchedule, "window", -1, "", "a window is two times of day, HH:MM")
	}
	if start == end {
		return s, fail(ErrSchedule, "window", -1, "", "the window starts and ends at the same time")
	}
	return s, nil
}

// zoneName accepts an IANA zone the database CHECK accepts too ("Local" names the host's zone,
// not a choice, and is refused like ALICE_TZ refuses it).
func zoneName(z string) bool {
	if len(z) > 64 || z == "Local" || strings.Trim(z, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+/-") != "" {
		return false
	}
	_, err := time.LoadLocation(z)
	return err == nil
}

// timeOfDay parses "HH:MM" (two digits each, 00:00 to 23:59) into minutes after midnight.
func timeOfDay(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	h, err1 := strconv.Atoi(s[:2])
	m, err2 := strconv.Atoi(s[3:])
	if err1 != nil || err2 != nil || s[0] == '+' || s[3] == '+' || s[0] == '-' || s[3] == '-' || h > 23 || m > 59 || h < 0 || m < 0 {
		return 0, false
	}
	return h*60 + m, true
}

// Preview is the size of a scope as the scope form shows it while it is typed (design decision 7):
// no name is resolved and nothing is dialed. Addresses are the addresses the address and range
// entries cover (overlaps once); ExcludedAddresses those of them the scope's own and the global
// exclusions remove; Endpoints counts every host name as one address (a name may resolve to up to
// MaxAddressesPerName). BuiltinExclusions are the built-in exclusions the ranges overlap: their
// addresses are never scanned.
type Preview struct {
	Addresses         int
	ExcludedAddresses int
	Hostnames         int
	Ports             int
	SNINames          int
	Endpoints         int
	BuiltinExclusions []netip.Prefix
}

// PreviewScope validates s like Validate and returns its size.
func PreviewScope(s Scope, r Rules) (Preview, error) {
	c, err := compile(s, r)
	if err != nil {
		return Preview{}, err
	}
	p := Preview{
		Addresses: c.addresses, Hostnames: len(c.hosts), Ports: len(c.ports), SNINames: len(c.sni),
		Endpoints:         c.endpoints(c.addresses, len(c.hosts)),
		ExcludedAddresses: overlap(c.ranges, outermost(append(slices.Clone(r.GlobalExclusions), c.exclusions...))),
		BuiltinExclusions: []netip.Prefix{},
	}
	for _, b := range netaddr.ScanBuiltins() {
		for _, rg := range c.ranges {
			if rg.Overlaps(b) {
				p.BuiltinExclusions = append(p.BuiltinExclusions, b)
				break
			}
		}
	}
	return p, nil
}

// overlap counts the addresses two disjoint prefix sets share: prefixes nest or do not overlap, so
// each overlapping pair contributes the smaller one.
func overlap(a, b []netip.Prefix) int {
	var n int
	for _, x := range a {
		for _, y := range b {
			if !x.Overlaps(y) {
				continue
			}
			if x.Bits() >= y.Bits() {
				n += prefixSize(x)
			} else {
				n += prefixSize(y)
			}
		}
	}
	return n
}
