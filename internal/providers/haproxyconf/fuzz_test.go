package haproxyconf

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"alice/internal/providers/linuxssh/helperproto"
)

// FuzzParseCrtList (§25.6): the crt-list parser never panics; every line it returns has a
// positive line number, a non-empty path and no "!" filter; parsing is deterministic.
func FuzzParseCrtList(f *testing.F) {
	f.Add([]byte("# comment\n/probe/certs/a.pem\n" +
		"h.pem [alpn h2 ssl-min-ver TLSv1.2] h.example.test *.h.example.test !nope.h.example.test\n" +
		"/b.pem b.example.test other.example.test # trailing comment\n   \n  /a.pem indented.example.test\n" +
		"   # indented\n\"/a.pem\" x\n"))
	f.Add([]byte("[a b\n"))
	f.Add([]byte("/a.pem[x]y [z]\n"))
	f.Add([]byte("/a.pem ] [\n"))
	f.Add([]byte("/a.pem x [y]\n"))
	f.Add([]byte("/a.pem ! !! !x\r\n\t\v\f\n"))
	f.Add([]byte("\r/x/missing.pem x\n \r/a.pem y\n"))
	f.Add([]byte("/a\x00b\n"))
	f.Add([]byte(strings.Repeat("/a.pem [x] y\n", 100)))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := parseCrtList(data)
		again, err2 := parseCrtList(data)
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(got, again) {
			t.Fatalf("parseCrtList is not deterministic")
		}
		if err != nil {
			if got != nil {
				t.Fatalf("lines with an error: %+v", got)
			}
			return
		}
		prev := 0
		for _, l := range got {
			if l.n < 1 || l.n <= prev {
				t.Fatalf("line number %d after %d", l.n, prev)
			}
			prev = l.n
			if l.path == "" || strings.ContainsAny(l.path, " \t\n\v\f\r[]") {
				t.Fatalf("path %q", l.path)
			}
			for _, n := range l.names {
				if n == "" || strings.HasPrefix(n, "!") || strings.ContainsAny(n, " \t\n\v\f\r[]") {
					t.Fatalf("name %q", n)
				}
			}
		}
	})
}

// FuzzLex (§25.6): the configuration lexer never panics; every line has a positive, increasing
// number and at least one word, a word's dollar flag says whether it holds a "$", and lexing is
// deterministic.
func FuzzLex(f *testing.F) {
	f.Add([]byte("global\n  crt-base /etc/ssl\nfrontend f\n  bind :443,[::1]:9443 ssl crt \"/a b.pem\" crt '/a$b' # c\n"))
	f.Add([]byte("crt /a\\x41\\t\\ \\$ \\\n.if 1\n"))
	f.Add([]byte("crt \"/a\n"))
	f.Add([]byte("a\\x0\n"))
	f.Add([]byte("a\r\n'b'\"c\"d#e\n"))
	f.Add([]byte("acl st path_reg ^/a\\.b\\d+$\nx /\\1 \"\\q\\$\" \\$\n\r a\rb \"c\rd\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := lex(data)
		again, err2 := lex(data)
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(got, again) {
			t.Fatalf("lex is not deterministic")
		}
		if err != nil {
			if got != nil {
				t.Fatalf("lines with an error: %+v", got)
			}
			return
		}
		prev := 0
		for _, l := range got {
			if l.n < 1 || l.n <= prev || len(l.words) == 0 {
				t.Fatalf("line %+v after %d", l, prev)
			}
			prev = l.n
			for _, w := range l.words {
				if w.dollar != strings.Contains(w.text, "$") || strings.IndexByte(w.text, 0) >= 0 {
					t.Fatalf("word %+v", w)
				}
			}
		}
	})
}

// FuzzParseHAProxyConfig (§25.6): Parse never panics on a hostile haproxy.cfg. The fuzzed data is
// also every crt-list file, and every path ending "/d" is a directory with a certificate, a
// dotfile and a key. Every supported pair has a helper path for its certificate and companion,
// an unsupported one no path, every server a positive line and a pair, and the servers stay
// within MaxServers; Parse is deterministic and ToWire never gives a nil slice.
func FuzzParseHAProxyConfig(f *testing.F) {
	f.Add([]byte("global\n  crt-base /c\n  ssl-load-extra-files ocsp key\n  ssl-load-extra-del-ext\n" +
		"defaults\n  mode http\nfrontend fe\n  bind :9443,ipv6@[::1]:9444 ssl crt a.pem crt /c/d crt-list /l/x.txt alpn h2\n" +
		"  disabled\n  enabled\nlisten li\n  bind *:9445 name crt crt /c/b.crt ssl\nbackend be\n  bind :1 ssl crt /x.pem\n"))
	f.Add([]byte(".if 0\nfrontend a\n.elif defined(X)\nfrontend b\n.else\n.if 1\nglobal\n crt-base c\n.endif\n.endif\n" +
		"  bind :1 ssl crt x.pem crt \"${D}/y\" crt '/c/../z' default-crt /q\n"))
	f.Add([]byte("/c/a.pem [alpn h2] a.example.test !b\nfrontend f\n bind :1 ssl crt-list /f.txt crt-list rel crt-list /\n"))
	f.Add([]byte(".if\n.endif\n.if\n"))
	f.Add([]byte("frontend f\n bind " + strings.Repeat(":1,", 50) + " ssl crt /d crt /d\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		in := Input{Path: "/etc/haproxy/haproxy.cfg", Data: data, Version: "2.6.12",
			ReadFile: func(path string) ([]byte, error) {
				if strings.HasSuffix(path, "/n") {
					return nil, fmt.Errorf("%w: missing", ErrNotRead) // review I2 of Task 6
				}
				return data, nil
			},
			ReadDir: func(path string) ([]string, bool, error) {
				switch {
				case strings.HasSuffix(path, "/d"):
					return []string{"a.pem", ".b.pem", "c.key"}, true, nil
				case strings.HasSuffix(path, "/e"):
					return nil, false, fmt.Errorf("%w: listing", ErrNotRead)
				}
				return nil, false, nil
			},
		}
		got, err := Parse(in)
		again, err2 := Parse(in)
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(got, again) {
			t.Fatalf("Parse is not deterministic")
		}
		// Review I1 of Task 6: a writable haproxy.cfg makes Parse call neither callback and
		// leaves no pair it could support.
		w := Input{Path: in.Path, Data: data, Version: in.Version, Writable: true,
			ReadFile: func(string) ([]byte, error) { t.Fatal("ReadFile with Writable"); return nil, nil },
			ReadDir:  func(string) ([]string, bool, error) { t.Fatal("ReadDir with Writable"); return nil, false, nil },
		}
		if wc, err := Parse(w); err == nil {
			for _, s := range wc.Servers {
				for _, p := range s.Pairs {
					if p.pending || p.Cert != "" || p.Key != "" {
						t.Fatalf("a pair of a writable configuration with paths: %+v", p)
					}
				}
			}
		}
		if err != nil {
			if got.Servers != nil || got.Warnings != nil {
				t.Fatalf("a result with an error: %+v", got)
			}
			return
		}
		if len(got.Servers) > MaxServers {
			t.Fatalf("%d servers", len(got.Servers))
		}
		// Review C1: the bounds hold on the wire, where shared listens are copied per server.
		listens, wire := 0, 0
		for _, s := range got.Servers {
			listens += len(s.Listens)
			b, err := json.Marshal(ToWire(s))
			if err != nil {
				t.Fatal(err)
			}
			wire += len(b) + 1
		}
		if listens > MaxListens || wire > got.wire || got.wire > MaxWire {
			t.Fatalf("%d listens, %d bytes on the wire, estimated %d", listens, wire, got.wire)
		}
		for _, s := range got.Servers {
			if s.Line < 1 || s.File != in.Path || len(s.Pairs) == 0 {
				t.Fatalf("server %+v", s)
			}
			for _, p := range s.Pairs {
				switch {
				case p.Unsupported == "":
					t.Fatalf("supported before ResolveKeys: %+v", p) // review R2
				case !p.pending:
					if p.Cert != "" || p.Key != "" || p.KeyBeside != "" {
						t.Fatalf("unsupported pair with paths: %+v", p)
					}
				case p.Unsupported != ReasonConditional || !helperproto.ValidPath(p.Cert) || p.Cert == "/" || p.Key != p.Cert:
					t.Fatalf("pending pair %+v", p)
				case p.KeyBeside != "" && !helperproto.ValidPath(p.KeyBeside):
					t.Fatalf("companion of %+v", p)
				}
			}
			w := ToWire(s)
			if w.Names == nil || w.Listens == nil || w.Pairs == nil || len(w.Pairs) != len(s.Pairs) {
				t.Fatalf("wire %+v", w)
			}
		}
		// After ResolveKeys every supported pair has a key Parse named: its certificate, or the
		// companion from stable settings; nothing is left unsure.
		n := 0
		ResolveKeys(&got, func(string) bool { n++; return n%2 == 0 })
		for _, s := range got.Servers {
			for _, p := range s.Pairs {
				if p.keyUnsure || p.pending || p.Unsupported == "" && p.Key != p.Cert && p.Key != p.KeyBeside {
					t.Fatalf("resolved pair %+v", p)
				}
			}
		}
	})
}
