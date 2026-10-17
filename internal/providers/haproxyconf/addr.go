package haproxyconf

import (
	"strings"
	"unicode/utf8"
)

// Listen is one address a bind listens on: Addr is "" for any address, Port is 1-65535.
type Listen struct {
	Addr string
	Port int
}

// maxHost is the longest host an address may name (a DNS name's limit).
const maxHost = 253

// listenPrefixes are the address families stripped from an entry: they name an IP socket.
var listenPrefixes = []string{"ipv4@", "ipv6@", "tcp@", "tcp4@", "tcp6@", "udp@", "udp4@", "udp6@", "quic4@", "quic6@"}

// parseListens reads the address argument of a bind (its first word) the way Ruling 13 says:
// the argument is split on ","; an IP family prefix is stripped; any other "family@" (unix@,
// abns@, fd@, sockpair@, uxst@, uxdg@ or one Alice does not know) and a path ("/...") give no
// listen; "[v6]:port" and "host:port" split at the last colon; "*", "", "0.0.0.0" and "::" are
// any address (""). The port must be decimal 1-65535: a range, a sign, a "$" or anything else
// drops the entry, and so does a host with "$", "[", "]", a control character, invalid UTF-8 or
// more than 253 bytes. Entries keep
// their order; Addr is a copy, so the argument is not retained.
//
// At most limit listens are returned (one 1 MiB argument could otherwise name about 200,000);
// cut is true when a further entry was left out.
func parseListens(arg string, limit int) (out []Listen, cut bool) {
	for rest := arg; ; {
		entry, more, found := strings.Cut(rest, ",")
		if l, ok := parseListen(entry); ok {
			if len(out) >= limit {
				return out, true
			}
			out = append(out, l)
		}
		if !found {
			return out, false
		}
		rest = more
	}
}

func parseListen(s string) (Listen, bool) {
	for _, p := range listenPrefixes {
		if t, ok := strings.CutPrefix(s, p); ok {
			s = t
			break
		}
	}
	if strings.ContainsAny(s, "@$") || strings.HasPrefix(s, "/") {
		return Listen{}, false
	}
	colon := strings.LastIndexByte(s, ':')
	if colon < 0 {
		return Listen{}, false
	}
	host, portText := s[:colon], s[colon+1:]
	if inner, ok := strings.CutPrefix(host, "["); ok {
		if host, ok = strings.CutSuffix(inner, "]"); !ok {
			return Listen{}, false
		}
	}
	if strings.ContainsAny(host, "[]") || len(host) > maxHost || !utf8.ValidString(host) || hasControl(host) {
		return Listen{}, false
	}
	port, rest, ok := leadingNumber(portText)
	if !ok || rest != "" || port < 1 || port > 65535 {
		return Listen{}, false
	}
	switch host {
	case "*", "0.0.0.0", "::":
		host = ""
	}
	return Listen{Addr: strings.Clone(host), Port: port}, true
}

// hasControl says whether s holds a C0 control character or DEL.
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
