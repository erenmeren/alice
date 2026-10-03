package inventory

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"alice/internal/platform/validate"
)

// Validation codes added by this package (texts in locales/common, validation.*).
const (
	CodeHostPort       = "validation.host_port"        // a port typed into the address field
	CodeHostNotAllowed = "validation.host_not_allowed" // link-local, multicast, unspecified, broadcast
	CodeHostASCII      = "validation.host_ascii"       // non-ASCII host name: type the xn-- form or the IP address
)

// typeValues are the parameters of a refused target type.
func typeValues() map[string]string { return map[string]string{"values": TypeLinux + ", " + TypeNginx} }

const (
	maxNameRunes = 100
	maxHostLen   = 253
)

// usernameRE is SEC-062's OS user name rule. It equals helperproto.ValidUser (inventory may not
// import the linuxssh packages, §5.4); a test in Task 16 compares the two.
var usernameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// labelRE is one RFC 1123 host name label (ASCII letters, digits, inner hyphens).
var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// foldASCII lowercases ASCII letters only (strings.ToLower is banned: Turkish İ/ı).
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func hostProblem(code string, params map[string]string) *validate.FieldError {
	return &validate.FieldError{Field: "host", Code: code, Params: params}
}

// NormalizeHost turns what a person typed into the stored host (Review Focus 2): surrounding
// space and one trailing dot are dropped, ASCII is lowercased, an IPv6 literal may be written in
// brackets and is stored without them. A port, scheme, path, user part, zone, non-ASCII name or
// a link-local, multicast, unspecified or broadcast address (SEC-065) is refused with the reason.
func NormalizeHost(raw string) (string, *validate.FieldError) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", hostProblem(validate.Required, nil)
	}
	if strings.ContainsAny(s, "/@\\%") {
		return "", hostProblem(validate.Pattern, nil)
	}
	if strings.HasPrefix(s, "[") {
		inner, ok := strings.CutSuffix(strings.TrimPrefix(s, "["), "]")
		a, err := netip.ParseAddr(inner)
		if !ok || err != nil || !a.Is6() || a.Zone() != "" {
			return "", hostProblem(validate.Pattern, nil)
		}
		return checkAddr(a)
	}
	// One trailing dot is dropped from addresses as from names ("10.0.0.5." is 10.0.0.5).
	if a, err := netip.ParseAddr(strings.TrimSuffix(s, ".")); err == nil {
		if a.Zone() != "" {
			return "", hostProblem(validate.Pattern, nil)
		}
		return checkAddr(a)
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		if _, err := strconv.Atoi(s[i+1:]); err == nil && strings.Count(s, ":") == 1 {
			return "", hostProblem(CodeHostPort, nil)
		}
		return "", hostProblem(validate.Pattern, nil)
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return "", hostProblem(CodeHostASCII, nil)
		}
	}
	s = strings.TrimSuffix(foldASCII(s), ".")
	if len(s) > maxHostLen {
		return "", hostProblem(validate.TooLong, map[string]string{"max": strconv.Itoa(maxHostLen)})
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if !labelRE.MatchString(label) {
			return "", hostProblem(validate.Pattern, nil)
		}
	}
	if numericLabelRE.MatchString(labels[len(labels)-1]) {
		return "", hostProblem(validate.Pattern, nil)
	}
	return s, nil
}

// numericLabelRE is a last label that makes a name read as a number (WHATWG "ends in a
// number"): resolvers built on inet_aton take 2852039166, 0251.0376.0251.0376 or 0xa9fea9fe
// for 169.254.169.254, which would slip past checkAddr. No real host name ends like this.
var numericLabelRE = regexp.MustCompile(`^([0-9]+|0x[0-9a-f]*)$`)

var (
	nat64Prefix  = netip.MustParsePrefix("64:ff9b::/96")   // RFC 6052 well-known prefix
	nat64Local   = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215 local-use prefix
	sixToFour    = netip.MustParsePrefix("2002::/16")      // RFC 3056
	awsIMDSv6    = netip.MustParseAddr("fd00:ec2::254")    // AWS instance metadata over IPv6
	ipv4Broadcst = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

// checkAddr refuses addresses that are never a managed server: link-local (including the cloud
// metadata address 169.254.169.254, SEC-065, and its IPv6 forms: IPv4-mapped, NAT64 64:ff9b::/96
// and the local-use NAT64 range 64:ff9b:1::/48, 6to4 2002::/16 and AWS's fd00:ec2::254),
// multicast, unspecified and the IPv4 broadcast address. Loopback and private addresses are
// allowed.
func checkAddr(a netip.Addr) (string, *validate.FieldError) {
	u := a.Unmap()
	if notAServer(u) || u == awsIMDSv6 || localNAT64ToNonServer(u) {
		return "", hostProblem(CodeHostNotAllowed, nil)
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
		if embedded.IsValid() && notAServer(embedded) {
			return "", hostProblem(CodeHostNotAllowed, nil)
		}
	}
	return u.String(), nil
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
	if notAServer(netip.AddrFrom4([4]byte(b[12:16]))) {
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

// validName checks a display name: 1..100 characters in NFC, no control or format characters
// (bidirectional overrides, zero-width characters, soft hyphens, BOM: they could disguise a name
// in the UI and the audit log). The stored form is NFC, so two spellings of one name are equal.
func validName(field, raw string) (string, *validate.FieldError) {
	if !utf8.ValidString(raw) {
		return "", &validate.FieldError{Field: field, Code: validate.Pattern}
	}
	s := norm.NFC.String(strings.TrimSpace(raw))
	switch {
	case s == "":
		return "", &validate.FieldError{Field: field, Code: validate.Required}
	case utf8.RuneCountInString(s) > maxNameRunes:
		return "", &validate.FieldError{Field: field, Code: validate.TooLong, Params: map[string]string{"max": strconv.Itoa(maxNameRunes)}}
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) {
			return "", &validate.FieldError{Field: field, Code: validate.Pattern}
		}
	}
	return s, nil
}

// validateNewTarget normalizes and checks a new target; it returns the stored form.
func validateNewTarget(in NewTarget) (NewTarget, validate.Errors) {
	var errs validate.Errors
	out := in
	if name, fe := validName("name", in.Name); fe != nil {
		errs = append(errs, *fe)
	} else {
		out.Name = name
	}
	if in.Type != TypeLinux && in.Type != TypeNginx {
		errs.Add("type", validate.OneOf, typeValues())
	}
	if host, fe := NormalizeHost(in.Host); fe != nil {
		errs = append(errs, *fe)
	} else {
		out.Host = host
	}
	switch {
	case in.Port == 0:
		out.Port = defaultSSHPort
	case in.Port < 1 || in.Port > 65535:
		errs.Add("port", validate.OutOfRange, map[string]string{"min": "1", "max": "65535"})
	}
	out.Username = strings.TrimSpace(in.Username)
	if out.Username == "" {
		out.Username = ServiceUser
	} else if !usernameRE.MatchString(out.Username) {
		errs.Add("username", validate.Pattern, nil)
	}
	return out, errs
}
