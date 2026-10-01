// Package sshdconf reads OpenSSH server settings from "sshd -T" output (or sshd_config text) and
// expands AuthorizedKeysFile tokens (spec §13.2). It is pure and uses only the standard library:
// the static alice-helper binary imports it to compute the only authorized_keys paths it touches.
package sshdconf

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultAuthorizedKeysFile is OpenSSH's default AuthorizedKeysFile.
var DefaultAuthorizedKeysFile = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}

// MaxConfigSize bounds the parsed text.
const MaxConfigSize = 1 << 20

var (
	// ErrTooLarge means the configuration text is larger than MaxConfigSize.
	ErrTooLarge = errors.New("sshdconf: configuration too large")
	// ErrInvalidPattern means an AuthorizedKeysFile pattern cannot be expanded safely.
	ErrInvalidPattern = errors.New("sshdconf: invalid AuthorizedKeysFile pattern")
)

// Config holds the settings Alice needs. Empty strings mean "not set"; Parse fills the
// OpenSSH defaults for AuthorizedKeysFile and AuthorizedKeysCommand.
type Config struct {
	AuthorizedKeysFile        []string
	AuthorizedKeysCommand     string // "none" when unset
	AuthorizedKeysCommandUser string
	AuthorizedPrincipalsFile  string
	TrustedUserCAKeys         string
	PubkeyAuthentication      string
	PasswordAuthentication    string
	PermitRootLogin           string
	StrictModes               string
	HostKeys                  []string
}

// Parse reads "keyword value…" lines. Keywords are case-insensitive, "=" may separate keyword
// and value, '#' starts a comment line, double quotes group a value. Like sshd, the first value of
// a keyword wins (hostkey accumulates). Parsing stops at the first Match block: its values apply
// only to some connections, and "sshd -T" without "-C" prints none.
func Parse(data []byte) (Config, error) {
	if len(data) > MaxConfigSize {
		return Config{}, ErrTooLarge
	}
	var c Config
	seen := map[string]bool{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		kw, rest := splitKeyword(line)
		kw = foldASCII(kw)
		if kw == "match" {
			break
		}
		vals := fields(rest)
		if len(vals) == 0 {
			continue
		}
		if kw == "hostkey" {
			c.HostKeys = append(c.HostKeys, vals...)
			continue
		}
		if seen[kw] {
			continue
		}
		seen[kw] = true
		one := strings.Join(vals, " ")
		switch kw {
		case "authorizedkeysfile":
			if len(vals) == 1 && foldASCII(vals[0]) == "none" {
				c.AuthorizedKeysFile = []string{}
			} else {
				c.AuthorizedKeysFile = vals
			}
		case "authorizedkeyscommand":
			c.AuthorizedKeysCommand = one
		case "authorizedkeyscommanduser":
			c.AuthorizedKeysCommandUser = one
		case "authorizedprincipalsfile":
			c.AuthorizedPrincipalsFile = one
		case "trustedusercakeys":
			c.TrustedUserCAKeys = one
		case "pubkeyauthentication":
			c.PubkeyAuthentication = one
		case "passwordauthentication":
			c.PasswordAuthentication = one
		case "permitrootlogin":
			c.PermitRootLogin = one
		case "strictmodes":
			c.StrictModes = one
		}
	}
	if c.AuthorizedKeysFile == nil {
		c.AuthorizedKeysFile = append([]string(nil), DefaultAuthorizedKeysFile...)
	}
	if c.AuthorizedKeysCommand == "" {
		c.AuthorizedKeysCommand = "none"
	}
	return c, nil
}

// splitKeyword splits "Keyword value", "Keyword=value" and "Keyword = value".
func splitKeyword(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	rest := strings.TrimLeft(line[i:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	return line[:i], strings.TrimSpace(rest)
}

// fields splits on spaces and tabs; double quotes group (an unterminated quote runs to the end).
// Backslash escapes are not handled: this reader only serves the fallback path of plain sshd_config
// text, while the helper normally parses "sshd -T" output.
func fields(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			have = true
		case (c == ' ' || c == '\t') && !inQuote:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

// foldASCII lowercases ASCII letters only (strings.ToLower is banned: Turkish casing, and
// sshd keywords are ASCII).
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Expand turns an AuthorizedKeysFile pattern into a path for one user: %h is the home directory,
// %u the user name, %U the numeric user ID, %% a percent sign; a relative result is relative to
// the home directory. A pattern or an expansion that contains NUL or a line break, an unknown
// token, a ".." path element or a result that is not absolute is refused with ErrInvalidPattern.
func Expand(pattern, user, home string, uid int) (string, error) {
	if pattern == "" || strings.ContainsAny(pattern+user+home, "\x00\n\r") {
		return "", ErrInvalidPattern
	}
	if user == "" || strings.Contains(user, "/") || !strings.HasPrefix(home, "/") {
		return "", ErrInvalidPattern
	}
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(pattern) {
			return "", fmt.Errorf("%w: trailing %%", ErrInvalidPattern)
		}
		i++
		switch pattern[i] {
		case '%':
			b.WriteByte('%')
		case 'h':
			b.WriteString(home)
		case 'u':
			b.WriteString(user)
		case 'U':
			b.WriteString(strconv.Itoa(uid))
		default:
			return "", fmt.Errorf("%w: unknown token %%%c", ErrInvalidPattern, pattern[i])
		}
	}
	p := b.String()
	if !strings.HasPrefix(p, "/") {
		p = home + "/" + p
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: the path contains a .. element", ErrInvalidPattern)
		}
	}
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%w: the path is not absolute", ErrInvalidPattern)
	}
	return p, nil
}
