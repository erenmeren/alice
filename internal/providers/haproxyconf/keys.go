package haproxyconf

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/providers/linuxssh/helperproto"
)

// ResolveKeys sets the key file of every supported pair (Ruling 12): HAProxy takes the key from
// the certificate PEM first and looks for the companion file only when the PEM has none. So Key
// is Cert when keyInCert(Cert) says the PEM holds a private key, or when key lookup is off
// (KeyBeside ""); otherwise it is KeyBeside. keyInCert is asked once per distinct certificate,
// and never for an unsupported pair.
func ResolveKeys(c *Config, keyInCert func(cert string) bool) {
	known := map[string]bool{}
	for i := range c.Servers {
		for j := range c.Servers[i].Pairs {
			p := &c.Servers[i].Pairs[j]
			if p.Unsupported != "" || p.KeyBeside == "" {
				continue
			}
			inCert, ok := known[p.Cert]
			if !ok {
				inCert = keyInCert(p.Cert)
				known[p.Cert] = inCert
			}
			if inCert {
				p.Key = p.Cert
			} else {
				p.Key = p.KeyBeside
			}
		}
	}
}

// MarkWritable makes every supported pair unsupported config_file_writable. The root helper calls
// it when haproxy.cfg or a read crt-list can be changed by a user other than root: crt-base and
// the global settings reach the whole configuration, so the rule is Apache's coarse one (Ruling 4).
func MarkWritable(c *Config) {
	for i := range c.Servers {
		for j := range c.Servers[i].Pairs {
			if p := &c.Servers[i].Pairs[j]; p.Unsupported == "" {
				p.Unsupported = ReasonConfigFileWritable
			}
		}
	}
}

// CertPaths returns the distinct certificate paths of supported pairs, in order.
func (c Config) CertPaths() []string { return c.paths(func(p Pair) string { return p.Cert }) }

// KeyPaths returns the distinct key paths of supported pairs, in order.
func (c Config) KeyPaths() []string { return c.paths(func(p Pair) string { return p.Key }) }

func (c Config) paths(get func(Pair) string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range c.Servers {
		for _, p := range s.Pairs {
			if v := get(p); p.Unsupported == "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// ToWire converts a server for the helper's answer (shared by the helper and its emulator).
// Slices are never nil, text is cleaned of control characters and invalid UTF-8 and cut (file
// 4096 bytes; section, names and addresses 253 bytes), Raw is CertRaw cut to 200 runes for an
// unsupported pair only, and Stream, DefaultServer and Inherited are false. Parse gives every
// text already cleaned and cut, so the cost of a server does not grow with the configuration's
// longest word, however many servers share it (review I1).
func ToWire(s Server) helperproto.DumpServer {
	out := helperproto.DumpServer{File: clean(s.File, 4096), Line: s.Line, Section: clean(s.Section, maxText), Names: []string{},
		Listens: []helperproto.DumpListen{}, Pairs: []helperproto.DumpPair{}}
	for _, n := range s.Names {
		out.Names = append(out.Names, clean(n, maxText))
	}
	for _, l := range s.Listens {
		out.Listens = append(out.Listens, helperproto.DumpListen{Addr: clean(l.Addr, maxText), Port: l.Port})
	}
	for _, p := range s.Pairs {
		wp := helperproto.DumpPair{Cert: p.Cert, Key: p.Key, Unsupported: p.Unsupported}
		if p.Unsupported != "" {
			wp.Raw = shown(p.CertRaw) // Parse already gives it in this form: cheap (review I1)
		}
		out.Pairs = append(out.Pairs, wp)
	}
	return out
}

// clean drops control characters and invalid UTF-8 and cuts s to at most maxBytes on a rune
// boundary (the helper's rule for text it returns).
func clean(s string, maxBytes int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	for len(s) > maxBytes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}
