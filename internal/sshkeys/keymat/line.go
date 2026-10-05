package keymat

import (
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxSlug = 40

// Comment is the comment of a line Alice adds (spec §13.4): "alice:<slug>:<yyyy-mm-dd>", the slug
// made of the label's ASCII letters (lower case), digits, '.' and '_', other runs folded to one '-'.
func Comment(label string, day time.Time) string {
	var b strings.Builder
	dash := false
	for _, r := range label {
		if b.Len() >= maxSlug {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_':
			b.WriteRune(r)
			dash = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "key"
	}
	return "alice:" + slug + ":" + day.UTC().Format("2006-01-02")
}

// validComment: 1-100 printable ASCII characters without a space (ssh_keys.key_comment).
func validComment(c string) bool {
	if c == "" || len(c) > 100 {
		return false
	}
	for i := 0; i < len(c); i++ {
		if c[i] < '!' || c[i] > '~' {
			return false
		}
	}
	return true
}

// FromOption validates a comma-separated list of IP addresses and networks (host bits zero, no
// zone, at most MaxFromEntries) and returns the option text `from="…"` in canonical form.
func FromOption(list string) (string, error) {
	parts := strings.Split(list, ",")
	if strings.TrimSpace(list) == "" || len(parts) > MaxFromEntries {
		return "", ErrFromOption
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if pfx, err := netip.ParsePrefix(p); err == nil && pfx == pfx.Masked() && pfx.Addr().Zone() == "" {
			out = append(out, pfx.String())
			continue
		}
		if a, err := netip.ParseAddr(p); err == nil && a.Zone() == "" {
			out = append(out, a.String())
			continue
		}
		return "", ErrFromOption
	}
	return `from="` + strings.Join(out, ",") + `"`, nil
}

// Line builds "[options ]<type> <base64> <comment>" and refuses anything that is not exactly one
// plain key line: a line break or NUL anywhere, a key that does not parse, a comment that is not
// validComment, options ssh.ParseAuthorizedKey does not accept, or a certificate authority.
func Line(options, publicKey, comment string) (string, error) {
	if strings.ContainsAny(options+publicKey+comment, "\r\n\x00") || !validComment(comment) {
		return "", ErrLine
	}
	pk, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil || len(rest) != 0 {
		return "", ErrLine
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + comment
	if options != "" {
		line = options + " " + line
	}
	got, gotComment, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(rest) != 0 || gotComment != comment || ssh.FingerprintSHA256(got) != ssh.FingerprintSHA256(pk) {
		return "", ErrLine
	}
	for _, o := range opts {
		if strings.EqualFold(o, "cert-authority") {
			return "", ErrLine
		}
	}
	return line, nil
}

// HasFromOption reports whether an option list (as stored for a location) holds from=.
func HasFromOption(options string) bool {
	for _, o := range splitOptions(options) {
		if len(o) >= 5 && strings.EqualFold(o[:5], "from=") {
			return true
		}
	}
	return false
}

// splitOptions splits an option list on commas outside double quotes (a backslash escapes the
// next character inside quotes, as sshd reads it).
func splitOptions(s string) []string {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if quoted {
				i++
			}
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}
