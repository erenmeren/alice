package discovery

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
)

// everywhere allows every address the built-in rule lets through, so each refusal of a test stands
// on its own rule.
var everywhere = Rules{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}

// dbName is the discovery_name_ok CHECK of migration 00014: a stored host or SNI name must pass it.
var dbName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func scope(entries ...string) Scope {
	return Scope{Name: "lab", Entries: entries, Ports: []int{443}}
}

func TestParseEntryAccepts(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61) // 63*3 + 61 + 3 dots = 253
	for in, want := range map[string]struct {
		kind EntryKind
		out  string
	}{
		"10.0.0.5":                {KindAddress, "10.0.0.5"},
		"10.0.0.0/24":             {KindRange, "10.0.0.0/24"},
		"10.0.0.0/20":             {KindRange, "10.0.0.0/20"},
		"10.0.0.5/32":             {KindAddress, "10.0.0.5"},
		"::ffff:10.0.0.5":         {KindAddress, "10.0.0.5"},
		"::ffff:10.0.0.0/120":     {KindRange, "10.0.0.0/24"},
		"::ffff:10.0.0.5/128":     {KindAddress, "10.0.0.5"},
		"2a00:1450::1":            {KindAddress, "2a00:1450::1"},
		"2A00:1450:0::1":          {KindAddress, "2a00:1450::1"},
		"2a00:1450::/120":         {KindRange, "2a00:1450::/120"},
		"2a00:1450::1/128":        {KindAddress, "2a00:1450::1"},
		"www.Example.COM":         {KindHost, "www.example.com"},
		"example.com.":            {KindHost, "example.com"},
		"intranet":                {KindHost, "intranet"},
		"1.example.com":           {KindHost, "1.example.com"},
		"a-b.c1":                  {KindHost, "a-b.c1"},
		"bücher.example":          {KindHost, "xn--bcher-kva.example"},
		"Bücher.Example":          {KindHost, "xn--bcher-kva.example"},
		"xn--bcher-kva.example":   {KindHost, "xn--bcher-kva.example"},
		label63 + ".example":      {KindHost, label63 + ".example"},
		name253:                   {KindHost, name253},
		"0x7f.example":            {KindHost, "0x7f.example"},
		"2130706433.example.com":  {KindHost, "2130706433.example.com"},
		"mail.xn--bcher-kva.test": {KindHost, "mail.xn--bcher-kva.test"},
	} {
		t.Run(in, func(t *testing.T) {
			e, err := ParseEntry(in)
			require.NoError(t, err)
			require.Equal(t, want.kind, e.Kind)
			require.Equal(t, want.out, e.String())
			again, err := ParseEntry(e.String())
			require.NoError(t, err, "the canonical form parses again")
			require.Equal(t, e, again)
			if e.Kind == KindHost {
				require.Regexp(t, dbName, e.Host)
			}
		})
	}
}

func TestParseEntryRefuses(t *testing.T) {
	invalid := []string{
		"", " ", " 10.0.0.1", "10.0.0.1 ", "10.0.0.1\n", "10.0.0.5/24", "10.0.0/24", "010.0.0.1", "10.0.0.256",
		"10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/", "/24", "10.0.0.0/24/24", "10.0.0.0/024",
		// decimal, octal, hex and short IPv4 spellings are neither addresses nor host names
		"2130706433", "0x7f.1", "0177.0.0.1", "0x7f000001", "0x7f.0.0.1", "127.1", "1.2.3", "017.1.2.4", "0x7f",
		"1.2.3.4.5", "example.123", "example.0x7f", "１２７.０.０.１",
		// zones and mapped prefixes that mix IPv4 and IPv6
		"fe80::1%eth0", "fe80::%eth0/120", "::ffff:10.0.0.0/64", "::ffff:0:0/95",
		// host name syntax (A3)
		"a..b", ".example.com", "example.com..", "-a.com", "a-.com", "a_b.com", "exa mple.com", "a\r\nb.com", "a\x00.com",
		"a\tb.com", "http://x.com", "x.com:443", "[::1]", "*.example.com", "user@example.com", "a/b.com",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 126) + "ab", "xn--zz.example", "xn--.example", "\xff.com",
		"①.com", "ex\u200bample.com", strings.Repeat("a", 256),
	}
	for _, in := range invalid {
		t.Run(strconv.Quote(in), func(t *testing.T) {
			_, err := ParseEntry(in)
			require.ErrorIs(t, err, ErrInvalid)
			var de *Error
			require.ErrorAs(t, err, &de)
		})
	}
	for _, in := range []string{"10.0.0.0/8", "10.0.0.0/19", "0.0.0.0/0", "2a00:1450::/119", "::/0", "::ffff:10.0.0.0/115"} {
		t.Run(in, func(t *testing.T) {
			_, err := ParseEntry(in)
			require.ErrorIs(t, err, ErrTooLarge)
		})
	}
}

func TestCanonicalHostname(t *testing.T) {
	for _, in := range []string{"10.0.0.1", "::1", "::ffff:127.0.0.1", "2130706433", "0x7f.1", "0177.0.0.1", "", "a b", "a\nb"} {
		_, err := CanonicalHostname(in)
		require.ErrorIs(t, err, ErrInvalid, in)
	}
	got, err := CanonicalHostname("WWW.Example.org")
	require.NoError(t, err)
	require.Equal(t, "www.example.org", got)
}

func TestParseExclusion(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1": "10.0.0.1/32", "10.0.0.0/8": "10.0.0.0/8", "::ffff:10.0.0.0/104": "10.0.0.0/8", "2a00::/16": "2a00::/16",
		"0.0.0.0/0": "0.0.0.0/0",
	} {
		p, err := ParseExclusion(in)
		require.NoError(t, err, in)
		require.Equal(t, want, p.String(), in)
	}
	for _, in := range []string{"", "example.com", "10.0.0.1/24", "fe80::1%eth0", "2130706433", "::ffff:0:0/80", "10.0.0.0/33"} {
		_, err := ParseExclusion(in)
		require.ErrorIs(t, err, ErrInvalid, in)
	}
	ps, err := ParseNetworks([]string{"10.0.0.0/8", "192.168.1.0/24"})
	require.NoError(t, err)
	require.Len(t, ps, 2)
	_, err = ParseNetworks([]string{"10.0.0.0/8", "nope"})
	require.ErrorIs(t, err, ErrInvalid)
	_, err = ParseNetworks(make([]string, 257))
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestValidateNormalises(t *testing.T) {
	s := Scope{
		Name:       "  ",
		Entries:    []string{"10.0.0.1", "::ffff:10.0.0.1", "10.0.0.1", "WWW.example.com", "www.example.com."},
		Ports:      []int{443, 8443, 443, 443},
		SNINames:   []string{"A.example", "a.example"},
		Exclusions: []string{"::ffff:10.0.0.9", "10.0.0.9"},
	}
	_, err := Validate(s, everywhere)
	require.ErrorIs(t, err, ErrInvalid, "a blank name")
	s.Name = "Lab"
	got, err := Validate(s, everywhere)
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.1", "www.example.com"}, got.Entries)
	require.Equal(t, []int{443, 8443}, got.Ports, "ports are de-duplicated")
	require.Equal(t, []string{"a.example"}, got.SNINames)
	require.Equal(t, []string{"10.0.0.9"}, got.Exclusions)
	require.Equal(t, DefaultRate, got.RatePerSec)
	require.Equal(t, DefaultConcurrency, got.Concurrency)
	require.Equal(t, "UTC", got.Schedule.TimeZone)
}

func TestValidateFieldErrors(t *testing.T) {
	many := func(n int, f func(i int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	ports17 := make([]int, 17)
	for i := range ports17 {
		ports17[i] = 1000 + i
	}
	for name, tc := range map[string]struct {
		mut   func(*Scope)
		want  error
		field string
	}{
		"no entries": {func(s *Scope) { s.Entries = nil }, ErrInvalid, "entries"},
		"257 entries": {func(s *Scope) {
			s.Entries = many(257, func(i int) string { return "h" + strconv.Itoa(i) + ".example" })
		}, ErrTooLarge, "entries"},
		"bad entry":  {func(s *Scope) { s.Entries = []string{"10.0.0.1", "0x7f.1"} }, ErrInvalid, "entries"},
		"no ports":   {func(s *Scope) { s.Ports = nil }, ErrInvalid, "ports"},
		"port 0":     {func(s *Scope) { s.Ports = []int{0} }, ErrInvalid, "ports"},
		"port 65536": {func(s *Scope) { s.Ports = []int{443, 65536} }, ErrInvalid, "ports"},
		"17 ports":   {func(s *Scope) { s.Ports = ports17 }, ErrTooLarge, "ports"},
		"257 sni": {func(s *Scope) {
			s.SNINames = many(257, func(i int) string { return "s" + strconv.Itoa(i) + ".example" })
		}, ErrTooLarge, "sni_names"},
		"sni ip literal": {func(s *Scope) { s.SNINames = []string{"10.0.0.1"} }, ErrInvalid, "sni_names"},
		"sni v6 literal": {func(s *Scope) { s.SNINames = []string{"::1"} }, ErrInvalid, "sni_names"},
		"sni decimal ip": {func(s *Scope) { s.SNINames = []string{"2130706433"} }, ErrInvalid, "sni_names"},
		"sni crlf":       {func(s *Scope) { s.SNINames = []string{"a.example\r\nX: y"} }, ErrInvalid, "sni_names"},
		"257 exclusions": {func(s *Scope) {
			s.Exclusions = many(257, func(i int) string { return "10.1.0." + strconv.Itoa(i%250) })
		}, ErrTooLarge, "exclusions"},
		"host exclusion":   {func(s *Scope) { s.Exclusions = []string{"example.com"} }, ErrInvalid, "exclusions"},
		"rate 101":         {func(s *Scope) { s.RatePerSec = 101 }, ErrInvalid, "rate_per_sec"},
		"rate -1":          {func(s *Scope) { s.RatePerSec = -1 }, ErrInvalid, "rate_per_sec"},
		"concurrency 65":   {func(s *Scope) { s.Concurrency = 65 }, ErrInvalid, "concurrency"},
		"name 101":         {func(s *Scope) { s.Name = strings.Repeat("n", 101) }, ErrInvalid, "name"},
		"name nul":         {func(s *Scope) { s.Name = "a\x00b" }, ErrInvalid, "name"},
		"name bad utf8":    {func(s *Scope) { s.Name = "a\xffb" }, ErrInvalid, "name"},
		"hours 169":        {func(s *Scope) { s.Schedule.Hours = 169 }, ErrSchedule, "schedule_hours"},
		"hours -1":         {func(s *Scope) { s.Schedule.Hours = -1 }, ErrSchedule, "schedule_hours"},
		"window, no hours": {func(s *Scope) { s.Schedule = Schedule{WindowStart: "01:00", WindowEnd: "02:00"} }, ErrSchedule, "window"},
		"start only":       {func(s *Scope) { s.Schedule = Schedule{Hours: 1, WindowStart: "01:00"} }, ErrSchedule, "window"},
		"end only":         {func(s *Scope) { s.Schedule = Schedule{Hours: 1, WindowEnd: "01:00"} }, ErrSchedule, "window"},
		"empty window":     {func(s *Scope) { s.Schedule = Schedule{Hours: 1, WindowStart: "01:00", WindowEnd: "01:00"} }, ErrSchedule, "window"},
		"24:00":            {func(s *Scope) { s.Schedule = Schedule{Hours: 1, WindowStart: "24:00", WindowEnd: "01:00"} }, ErrSchedule, "window"},
		"9:00":             {func(s *Scope) { s.Schedule = Schedule{Hours: 1, WindowStart: "9:00", WindowEnd: "10:00"} }, ErrSchedule, "window"},
		"09:60":            {func(s *Scope) { s.Schedule = Schedule{Hours: 1, WindowStart: "09:00", WindowEnd: "09:60"} }, ErrSchedule, "window"},
		"seconds":          {func(s *Scope) { s.Schedule = Schedule{Hours: 1, WindowStart: "09:00:00", WindowEnd: "10:00"} }, ErrSchedule, "window"},
		"zone Local":       {func(s *Scope) { s.Schedule = Schedule{Hours: 1, TimeZone: "Local"} }, ErrSchedule, "window_tz"},
		"zone unknown":     {func(s *Scope) { s.Schedule = Schedule{Hours: 1, TimeZone: "Mars/Olympus_Mons"} }, ErrSchedule, "window_tz"},
		"zone path":        {func(s *Scope) { s.Schedule = Schedule{Hours: 1, TimeZone: "../../etc/passwd"} }, ErrSchedule, "window_tz"},
		"zone long":        {func(s *Scope) { s.Schedule = Schedule{Hours: 1, TimeZone: strings.Repeat("A", 65)} }, ErrSchedule, "window_tz"},
	} {
		t.Run(name, func(t *testing.T) {
			s := scope("10.0.0.0/24")
			tc.mut(&s)
			_, err := Validate(s, everywhere)
			require.ErrorIs(t, err, tc.want)
			var de *Error
			require.ErrorAs(t, err, &de)
			require.Equal(t, tc.field, de.Field)
			require.NotEmpty(t, de.Error())
		})
	}
}

func TestValidateScheduleAccepts(t *testing.T) {
	for _, sch := range []Schedule{
		{}, {Hours: 1}, {Hours: 168}, {Hours: 24, WindowStart: "22:00", WindowEnd: "02:00", TimeZone: "Europe/Istanbul"},
		{Hours: 6, WindowStart: "00:00", WindowEnd: "23:59", TimeZone: "UTC"}, {Hours: 2, TimeZone: "America/Argentina/Buenos_Aires"},
	} {
		s := scope("10.0.0.0/24")
		s.Schedule = sch
		got, err := Validate(s, everywhere)
		require.NoError(t, err, "%+v", sch)
		require.NotEmpty(t, got.Schedule.TimeZone)
	}
}

func TestValidateEntryNotAllowed(t *testing.T) {
	lab := Rules{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("2a00:1450::/112")}}
	refused := map[string]Rules{
		"192.168.1.1":      lab,
		"10.1.0.0/24":      lab,
		"10.0.255.0/23":    lab, // sic: 10.0.254.0/23 is the masked form; see the valid one below
		"2a00:1451::1":     lab,
		"127.0.0.1":        everywhere,
		"::1":              everywhere,
		"::ffff:127.0.0.1": everywhere,
		"64:ff9b::7f00:1":  everywhere,
		"2002:7f00:1::":    everywhere,
		"169.254.169.254":  everywhere,
		"0.0.0.0":          everywhere,
		"100.64.0.0/24":    everywhere,
		"fd00:ec2::254":    everywhere,
		"2001:db8::/120":   everywhere,
		"224.0.0.0/24":     everywhere,
		"10.9.0.0/24":      {AllowedNetworks: everywhere.AllowedNetworks, GlobalExclusions: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}},
		"www.example.com":  {},
		"10.0.0.1":         {},
	}
	for entry, rules := range refused {
		t.Run(entry, func(t *testing.T) {
			_, err := Validate(scope(entry), rules)
			if entry == "10.0.255.0/23" {
				require.ErrorIs(t, err, ErrInvalid, "host bits set")
				return
			}
			require.ErrorIs(t, err, ErrNotAllowed)
			var de *Error
			require.ErrorAs(t, err, &de)
			require.Equal(t, "entries", de.Field)
			require.Equal(t, 0, de.Index)
		})
	}
	partial := Rules{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
	_, err := Validate(scope("10.0.0.0/23"), partial)
	require.ErrorIs(t, err, ErrNotAllowed, "an entry partly outside the allowed networks")
	two := Rules{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.1.0/24")}}
	_, err = Validate(scope("10.0.0.0/23"), two)
	require.NoError(t, err, "an entry covered by two allowed networks")
	for _, ok := range []string{"10.0.254.0/23", "2a00:1450::/120", "www.example.com"} {
		_, err := Validate(scope(ok), lab)
		require.NoError(t, err, ok)
	}
	s := scope("10.0.0.0/24")
	s.Exclusions = []string{"10.0.0.0/24"}
	_, err = Validate(s, lab)
	require.ErrorIs(t, err, ErrNotAllowed, "an entry its own exclusions remove entirely")
	_, err = Validate(scope("192.0.0.0/22"), everywhere)
	require.NoError(t, err, "partly built-in: the built-in addresses are excluded at expansion")
}

func TestPreview(t *testing.T) {
	s := scope("10.0.0.0/22")
	s.Ports = []int{443, 8443}
	p, err := PreviewScope(s, everywhere)
	require.NoError(t, err)
	require.Equal(t, Preview{Addresses: 1024, Ports: 2, Endpoints: 2048, BuiltinExclusions: []netip.Prefix{}}, p)

	s.SNINames = []string{"a.example", "b.example", "c.example"}
	s.Entries = append(s.Entries, "www.example.com", "mail.example.com")
	p, err = PreviewScope(s, everywhere)
	require.NoError(t, err)
	require.Equal(t, 1024, p.Addresses)
	require.Equal(t, 2, p.Hostnames)
	require.Equal(t, 3, p.SNINames)
	require.Equal(t, 1024*2*3+2*2, p.Endpoints, "a host name is its own SNI and counts one address in the preview")

	over := scope("10.0.0.0/24", "10.0.0.128/25", "10.0.0.200", "10.0.1.0/24", "::ffff:10.0.1.200", "10.0.0.200")
	over.Exclusions = []string{"10.0.0.0/26", "10.0.1.255", "10.5.0.0/16"}
	over.Ports = []int{443}
	p, err = PreviewScope(over, Rules{AllowedNetworks: everywhere.AllowedNetworks, GlobalExclusions: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/25")}})
	require.NoError(t, err)
	require.Equal(t, 512, p.Addresses, "overlapping and duplicate entries count once")
	require.Equal(t, 64+1+128, p.ExcludedAddresses)

	p, err = PreviewScope(scope("192.0.0.0/22"), everywhere)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24")}, p.BuiltinExclusions)

	_, err = PreviewScope(scope("10.0.0.0/8"), everywhere)
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestCapsAreArithmetic(t *testing.T) {
	// A hostile /8 is refused before anything is expanded.
	allocs := testing.AllocsPerRun(10, func() {
		_, err := PreviewScope(scope("10.0.0.0/8"), everywhere)
		if !errors.Is(err, ErrTooLarge) {
			panic(err)
		}
	})
	require.Less(t, allocs, 100.0)

	// 256 distinct /20s: one million addresses, refused by the sum, not by expanding them.
	var entries []string
	for i := range 256 {
		entries = append(entries, "10."+strconv.Itoa(i)+".0.0/20")
	}
	allocs = testing.AllocsPerRun(5, func() {
		_, err := Validate(scope(entries...), everywhere)
		if !errors.Is(err, ErrTooLarge) {
			panic(err)
		}
	})
	require.Less(t, allocs, 20000.0, "far less than one allocation per address")

	for name, tc := range map[string]struct {
		entries []string
		ports   int
		sni     int
		want    error
	}{
		"one /20, 4 ports":               {[]string{"10.0.0.0/20"}, 4, 0, nil},
		"one /20, 5 ports":               {[]string{"10.0.0.0/20"}, 5, 0, ErrTooLarge},
		"a /20 and one more":             {[]string{"10.0.0.0/20", "10.0.16.1"}, 1, 0, ErrTooLarge},
		"a /20 and a host name":          {[]string{"10.0.0.0/20", "www.example.com"}, 1, 0, ErrTooLarge},
		"a /20 and an address inside":    {[]string{"10.0.0.0/20", "10.0.0.1"}, 1, 0, nil},
		"one address, 256 SNI x 16":      {[]string{"10.0.0.1"}, 16, 256, nil},
		"five addresses, 256 SNI x 16":   {[]string{"10.0.0.0/30", "10.0.0.4"}, 16, 256, ErrTooLarge},
		"a /24, 78 SNI":                  {[]string{"10.0.0.0/24"}, 1, 78, nil},
		"a /24, 79 SNI":                  {[]string{"10.0.0.0/24"}, 1, 79, ErrTooLarge},
		"an IPv6 /120 x 16 ports":        {[]string{"2a00:1450::/120"}, 16, 0, nil},
		"256 names x 16 ports x 256 SNI": {nil, 16, 256, nil},
	} {
		t.Run(name, func(t *testing.T) {
			s := scope(tc.entries...)
			if tc.entries == nil {
				for i := range 256 {
					s.Entries = append(s.Entries, "h"+strconv.Itoa(i)+".example")
				}
			}
			s.Ports = nil
			for i := range tc.ports {
				s.Ports = append(s.Ports, 1000+i)
			}
			for i := range tc.sni {
				s.SNINames = append(s.SNINames, "s"+strconv.Itoa(i)+".example")
			}
			_, err := Validate(s, everywhere)
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// Review fix 1: a hostile port list is refused by its length before any element is read, and the
// loop stops at the 17th distinct port (shape, not wall clock: an invalid port placed after the
// bound would be reported if the list were read that far).
func TestPortsAreBounded(t *testing.T) {
	huge := make([]int, 70000)
	for i := range huge {
		huge[i] = i%65535 + 1
	}
	huge[0] = 0 // invalid, but never read
	s := scope("10.0.0.1")
	s.Ports = huge
	_, err := Validate(s, everywhere)
	require.ErrorIs(t, err, ErrTooLarge, "refused by its length, before element 0 is read")
	var de *Error
	require.ErrorAs(t, err, &de)
	require.Equal(t, "ports", de.Field)
	require.Equal(t, -1, de.Index)

	distinct := make([]int, MaxPortList)
	for i := range distinct {
		distinct[i] = i + 1
	}
	distinct[MaxPorts+1] = 70000 // invalid, after the 17th distinct port: never read
	s.Ports = distinct
	_, err = Validate(s, everywhere)
	require.ErrorIs(t, err, ErrTooLarge, "refused at the 17th distinct port")

	dups := make([]int, MaxPortList)
	for i := range dups {
		dups[i] = 443 + i%2
	}
	s.Ports = dups
	got, err := Validate(s, everywhere)
	require.NoError(t, err)
	require.Equal(t, []int{443, 444}, got.Ports)
	dups[MaxPortList-1] = 0
	_, err = Validate(s, everywhere)
	require.ErrorIs(t, err, ErrInvalid, "a list within the bound is read to the end")
	s.Ports = append(dups[:MaxPortList:MaxPortList], 443)
	_, err = Validate(s, everywhere)
	require.ErrorIs(t, err, ErrTooLarge, "more than MaxPortList elements, even duplicates")
}

// Review fix 3: the scannable walk jumps over whole excluded prefixes instead of visiting their
// addresses, and "inside the allowed networks" is set arithmetic. Counted, not timed: a /20 whose
// only free address is its last one, behind 12 exclusions, takes 13 steps (a per-address walk 4,096).
func TestCheckAllowedIsNotQuadratic(t *testing.T) {
	var allowedList []netip.Prefix
	a := netip.MustParseAddr("10.0.0.0")
	for range 4096 {
		allowedList = append(allowedList, netip.PrefixFrom(a, 32))
		a = a.Next()
	}
	rand.New(rand.NewPCG(1, 2)).Shuffle(len(allowedList), func(i, j int) {
		allowedList[i], allowedList[j] = allowedList[j], allowedList[i]
	})
	var excl []netip.Prefix // 10.0.0.0/21, 10.0.8.0/22, ..., 10.0.15.254/32: all but 10.0.15.255
	off := uint32(0)
	for bits := 21; bits <= 32; bits++ {
		excl = append(excl, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(off >> 8), byte(off)}), bits))
		off += 1 << (32 - bits)
	}
	require.Len(t, excl, 12)
	allowed := newPrefixSet(allowedList)
	blocked := newPrefixSet(excl, netaddr.ScanBuiltins())

	refusal, steps := checkAllowed(netip.MustParsePrefix("10.0.0.0/20"), allowed, blocked)
	require.Empty(t, refusal)
	require.Equal(t, 13, steps, "12 jumps and the free address")
	refusal, steps = checkAllowed(netip.MustParsePrefix("10.0.0.0/21"), allowed, blocked)
	require.NotEmpty(t, refusal)
	require.Equal(t, 1, steps, "one jump over the whole entry")
	refusal, steps = checkAllowed(netip.MustParsePrefix("10.0.16.0/24"), allowed, blocked)
	require.Equal(t, "outside the allowed scan networks", refusal)
	require.Zero(t, steps)
	refusal, _ = checkAllowed(netip.MustParsePrefix("10.0.15.0/24"), newPrefixSet(allowedList[:100]), blocked)
	require.Equal(t, "outside the allowed scan networks", refusal, "partly outside")

	// 256 nested entries inside the /20: at most 13 steps each, and the verdicts through Validate.
	var entries []string
	for bits := 20; bits <= 27; bits++ {
		for i := range 1 << (bits - 20) {
			o := uint32(i) << (32 - bits)
			entries = append(entries, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(o >> 8), byte(o)}), bits).String())
		}
	}
	entries = append(entries, "10.0.15.240/28")
	require.Len(t, entries, 256)
	total, free := 0, 0
	for _, e := range entries {
		r, n := checkAllowed(netip.MustParsePrefix(e), allowed, blocked)
		require.LessOrEqual(t, n, 13, e)
		total += n
		if r == "" {
			free++
		}
	}
	require.LessOrEqual(t, total, 256*13)
	require.Equal(t, 9, free, "the entries holding 10.0.15.255")
	rules := Rules{AllowedNetworks: allowedList, GlobalExclusions: excl}
	_, err := Validate(scope(entries...), rules)
	require.ErrorIs(t, err, ErrNotAllowed)
	var de *Error
	require.ErrorAs(t, err, &de)
	require.Equal(t, "10.0.0.0/21", de.Value, "the first entirely excluded entry")
}

// Review fix 4: the length refusals say the limit they apply.
func TestLengthMessages(t *testing.T) {
	_, err := CanonicalHostname(strings.Repeat("a", 300))
	require.ErrorContains(t, err, "255")
	_, err = CanonicalHostname(strings.Repeat("a.", 127) + "b")
	require.ErrorContains(t, err, "253")
	_, err = CanonicalHostname("")
	require.ErrorContains(t, err, "253")
}

func TestPrefixSet(t *testing.T) {
	mp := func(ss ...string) []netip.Prefix {
		out := make([]netip.Prefix, len(ss))
		for i, s := range ss {
			out[i] = netip.MustParsePrefix(s)
		}
		return out
	}
	set := newPrefixSet(mp("::ffff:10.0.0.0/104", "10.1.2.3/16", "2a00::/120", "2a00::80/121", "10.0.5.0/24"), mp("2a01::/127", "2a01::2/127"))
	require.Equal(t, mp("10.0.0.0/8", "2a00::/120", "2a01::/127", "2a01::2/127"), []netip.Prefix(set),
		"mapped prefixes unmapped, masked, nested ones dropped, sorted")
	require.True(t, set.contains(netip.MustParseAddr("10.200.0.1")))
	require.False(t, set.contains(netip.MustParseAddr("11.0.0.0")))
	require.False(t, set.contains(netip.MustParseAddr("0.0.0.1")))
	require.True(t, set.covers(netip.MustParsePrefix("10.9.0.0/20")))
	require.True(t, set.covers(netip.MustParsePrefix("2a01::/126")), "two prefixes add up")
	require.False(t, set.covers(netip.MustParsePrefix("2a01::/125")))
	require.False(t, set.covers(netip.MustParsePrefix("2a00::100/120")))
	require.Equal(t, "10.0.0.255", lastAddr(netip.MustParsePrefix("10.0.0.0/24")).String())
	require.Equal(t, "2a00::ff", lastAddr(netip.MustParsePrefix("2a00::/120")).String())
	require.Equal(t, "255.255.255.255", lastAddr(netip.MustParsePrefix("0.0.0.0/0")).String())
	_, err := Validate(scope("10.0.0.0/24"), Rules{AllowedNetworks: mp("::ffff:10.0.0.0/120")})
	require.NoError(t, err, "a mapped allowed network allows its IPv4 addresses")
	// A range at the very top of the address space ends the walk without wrapping.
	_, err = Validate(scope("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00/120"), everywhere)
	require.ErrorIs(t, err, ErrNotAllowed)
}
