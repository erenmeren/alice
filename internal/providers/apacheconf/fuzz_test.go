package apacheconf

import (
	"reflect"
	"strings"
	"testing"

	"alice/internal/providers/linuxssh/helperproto"
)

// FuzzParseApacheIncludes (§25.6): the DUMP_INCLUDES parser never panics; every entry it returns
// has a valid parent (the root first, then an earlier entry), a positive line number unless it is
// the root, and a valid helper path; parsing is deterministic.
func FuzzParseApacheIncludes(f *testing.F) {
	f.Add([]byte(debianIncludes))
	f.Add([]byte(rockyIncludes))
	f.Add([]byte("Included configuration files:\n  (*) /etc/apache2/apache2.conf\n    (146) /etc/apache2/mods-enabled/ssl.load\n" +
		"    (225) /etc/apache2/sites-enabled/a.conf\n      (3) /etc/apache2/snippets/tls.conf\n" +
		"        (9) /etc/apache2/snippets/deep.conf\n      (4) /etc/apache2/snippets/other.conf\nSyntax OK\n"))
	f.Add([]byte("Included configuration files:\n  (*) /a\n  (*) /b\n"))
	f.Add([]byte("Included configuration files:\n    (5) /a\n  (*) /b\n"))
	f.Add([]byte("Included configuration files:\n  (*) /a\n      (5) /b\n"))
	f.Add([]byte("Included configuration files:\n  (*) /a\n     (5) /b\n"))
	f.Add([]byte("Included configuration files:\n  (*) /a\n    (x) /b\n"))
	f.Add([]byte("Included configuration files:\n  (*) /a\n    (5) b\n"))
	f.Add([]byte("Included configuration files:\n  (*) /a\n    (5) /b/../c\n    (0) /d\n    (007) /e\n"))
	f.Add([]byte("Included configuration files:\r\n  (*) /a\r\n"))
	f.Add([]byte("Included configuration files:\n  (*) /a\n" + strings.Repeat("    (1) /b\n      (2) /c\n", 50)))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := ParseIncludes(in)
		again, err2 := ParseIncludes(in)
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(got, again) {
			t.Fatalf("ParseIncludes is not deterministic")
		}
		if err != nil {
			if got != nil {
				t.Fatalf("entries with an error: %+v", got)
			}
			return
		}
		if len(got) == 0 || len(got) > MaxFiles {
			t.Fatalf("%d entries", len(got))
		}
		for i, e := range got {
			if !helperproto.ValidPath(e.Path) {
				t.Fatalf("entry %d: invalid path %q", i, e.Path)
			}
			switch {
			case i == 0 && (e.Parent != -1 || e.Line != 0):
				t.Fatalf("root %+v", e)
			case i > 0 && (e.Parent < 0 || e.Parent >= i || e.Line < 1):
				t.Fatalf("entry %d: %+v", i, e)
			}
		}
	})
}
