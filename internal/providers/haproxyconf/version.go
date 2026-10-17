package haproxyconf

import (
	"bytes"
)

// ParseV reads the version from the output of "haproxy -v" (Ruling 3): the <v> of a first line
// "HAProxy version <v> " (or "HA-Proxy version <v> ", the spelling before 1.9), where <v> is 1
// to 40 characters of [A-Za-z0-9.+-]. Anything else, including any CR in the output (HAProxy
// writes LF line ends only) or an output over MaxInput, gives "".
func ParseV(out []byte) string {
	if len(out) > MaxInput || bytes.IndexByte(out, '\r') >= 0 {
		return ""
	}
	first, _, _ := bytes.Cut(out, []byte("\n"))
	rest, ok := bytes.CutPrefix(first, []byte("HAProxy version "))
	if !ok {
		if rest, ok = bytes.CutPrefix(first, []byte("HA-Proxy version ")); !ok {
			return ""
		}
	}
	v, _, ok := bytes.Cut(rest, []byte(" "))
	if !ok || !validVersion(v) {
		return ""
	}
	return string(v)
}

// validVersion is nginx's version rule: 1 to 40 characters of [A-Za-z0-9.+-].
func validVersion(v []byte) bool {
	if len(v) == 0 || len(v) > 40 {
		return false
	}
	for _, c := range v {
		if !isDigit(c) && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '.' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

// minorAtLeast says whether version, read as "<major>.<minor>" followed by anything, is at
// least major.minor. known is false when version does not start that way (or a number has more
// than 9 digits): the caller then treats the version-dependent case as uncertain.
func minorAtLeast(version string, major, minor int) (yes, known bool) {
	vMajor, rest, ok := leadingNumber(version)
	if !ok || rest == "" || rest[0] != '.' {
		return false, false
	}
	vMinor, _, ok := leadingNumber(rest[1:])
	if !ok {
		return false, false
	}
	if vMajor != major {
		return vMajor > major, true
	}
	return vMinor >= minor, true
}

// leadingNumber reads the decimal number at the start of s (1 to 9 digits).
func leadingNumber(s string) (n int, rest string, ok bool) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	if i == 0 || i > 9 {
		return 0, s, false
	}
	for _, c := range []byte(s[:i]) {
		n = n*10 + int(c-'0')
	}
	return n, s[i:], true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
