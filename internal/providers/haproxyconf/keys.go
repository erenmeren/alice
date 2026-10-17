package haproxyconf

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/providers/linuxssh/helperproto"
)

// ResolveKeys makes every pair still pending and conditional supported with its key file (Ruling 12;
// review S3: a reason a caller set stays). HAProxy takes the key from
// the certificate PEM first and looks for the companion file only when the PEM has none. So Key
// is Cert when keyInCert(Cert) says the PEM holds a private key, or when key lookup is off
// (KeyBeside ""); otherwise it is KeyBeside. When Parse found the key settings unstable, only a
// key in the PEM is known, and a pair without one stays conditional. keyInCert is asked once
// per distinct certificate, and only for pending pairs. Until it runs, no pair is supported.
func ResolveKeys(c *Config, keyInCert func(cert string) bool) {
	known := map[string]bool{}
	inCert := func(cert string) bool {
		v, ok := known[cert]
		if !ok {
			v = keyInCert(cert)
			known[cert] = v
		}
		return v
	}
	for i := range c.Servers {
		for j := range c.Servers[i].Pairs {
			p := &c.Servers[i].Pairs[j]
			switch {
			case !p.pending || p.Unsupported != ReasonConditional:
				// Review S3: a pair a caller marked unsupported itself stays so.
			case p.keyUnsure && !inCert(p.Cert):
				*p = Pair{CertRaw: p.CertRaw, Unsupported: ReasonConditional}
			default:
				p.Unsupported, p.pending, p.keyUnsure = "", false, false
				if p.Key = p.Cert; p.KeyBeside != "" && !inCert(p.Cert) {
					p.Key = p.KeyBeside
				}
			}
		}
	}
}

// MarkWritable makes every supported, pending or conditional pair unsupported
// config_file_writable. The root helper calls it when haproxy.cfg or a read crt-list can be
// changed by a user other than root: crt-base and the global settings reach the whole
// configuration, so the rule is Apache's coarse one (Ruling 4), and a conditional pair of such a
// configuration is shown with the same reason (review M6 of Task 6). A pending pair is no longer
// pending, so a later ResolveKeys never makes it supported (review R2), and loses its unresolved
// Key (review S2). A pair with another reason (variable, path_not_allowed, unknown_keyword)
// keeps it.
func MarkWritable(c *Config) {
	for i := range c.Servers {
		for j := range c.Servers[i].Pairs {
			switch p := &c.Servers[i].Pairs[j]; {
			case p.pending:
				// Review S2: its Key is not resolved yet, so it is not shown.
				*p = Pair{CertRaw: p.CertRaw, Cert: p.Cert, Unsupported: ReasonConfigFileWritable}
			case p.Unsupported == "":
				p.Unsupported = ReasonConfigFileWritable
			case p.Unsupported == ReasonConditional:
				*p = Pair{CertRaw: p.CertRaw, Unsupported: ReasonConfigFileWritable}
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
		if p.pending {
			wp.Cert, wp.Key = "", "" // never resolved: shown as the conditional pair it is
		}
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
