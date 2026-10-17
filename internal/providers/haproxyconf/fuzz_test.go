package haproxyconf

import (
	"reflect"
	"strings"
	"testing"
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
