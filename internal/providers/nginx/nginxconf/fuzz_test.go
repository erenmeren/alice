package nginxconf

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"alice/internal/providers/linuxssh/helperproto"
)

// §25.6 FuzzParseNginxConfig: never panics; output paths come only from ssl_certificate and
// ssl_certificate_key arguments and are valid helper paths; parsing is deterministic.
func FuzzParseNginxConfig(f *testing.F) {
	dir := filepath.Join("..", "..", "..", "..", "test", "testdata", "nginx")
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("http { server { listen 443 ssl; ssl_certificate \"/a b\"; ssl_certificate_key ${x}; } }"))
	f.Add([]byte("http { x { y; } server { listen 443 ssl; if ($a ~ \"(b)\") { return 1; } content_by_lua_block { local s = \"}\" } ssl_certificate /lib/../etc/s; } }"))
	f.Add([]byte("# configuration file /a:\ninclude /b;\n# configuration file /b:\ninclude /a;\n"))
	f.Add([]byte("http { server { listen 443 ssl; ssl_certificate /etc/a\\.crt; ssl_certificate_key /etc/a#.key; } }\r\n"))
	f.Add([]byte(inheritedPairs(4, 3, true)))      // A2-I2: shared http-level file sets
	f.Add([]byte(ownKeysPairs(3, 2)))              // A2-I2: inherited certificates, own keys
	f.Add([]byte(inheritedPairs(300, 300, false))) // A2-I2: over the pair budget
	f.Add([]byte("# configuration file /etc/nginx/nginx.conf:\nhttp { include conf.d/[!_]*.conf; include c/[]!-]?[^a-c\\]].conf; include d/[x; }\n" +
		"# configuration file /etc/nginx/conf.d/a.conf:\nserver { listen 443 ssl; ssl_certificate /a; ssl_certificate_key /b; }\n")) // L-9: glob(3) sets
	f.Fuzz(func(t *testing.T, in []byte) {
		c1, err1 := Parse(in, "/etc/nginx")
		c2, err2 := Parse(in, "/etc/nginx")
		if (err1 == nil) != (err2 == nil) || !reflect.DeepEqual(c1, c2) {
			t.Fatalf("Parse is not deterministic")
		}
		if err1 != nil {
			return
		}
		markers := bytes.Count(in, []byte("\n"+markerPrefix))
		if bytes.HasPrefix(in, []byte(markerPrefix)) {
			markers++
		}
		if len(c1.Files) > markers {
			t.Fatalf("%d files for %d marker lines", len(c1.Files), markers)
		}
		sections := map[string]bool{}
		for _, sec := range c1.Sections {
			sections[sec.File] = true
		}
		for _, s := range c1.Servers {
			for _, f := range s.Files {
				if !sections[f] {
					t.Fatalf("server file %q is not a section", f)
				}
			}
			for _, p := range s.Pairs {
				if !sections[p.CertFile] || (p.KeyRaw != "" && !sections[p.KeyFile]) {
					t.Fatalf("a directive file is not a section: %+v", p)
				}
				for _, f := range p.Files {
					if !sections[f] {
						t.Fatalf("pair file %q is not a section", f)
					}
				}
				if !slices.Contains(p.Files, p.CertFile) || (p.KeyRaw != "" && !slices.Contains(p.Files, p.KeyFile)) {
					t.Fatalf("a pair's files miss its directive files: %+v", p)
				}
				for _, path := range []string{p.Cert, p.Key} {
					if path != "" && !helperproto.ValidPath(path) {
						t.Fatalf("invalid path %q", path)
					}
				}
				if p.Unsupported == "" {
					if p.Cert == p.Key {
						t.Fatalf("a supported pair with one file for both: %+v", p)
					}
					for _, raw := range []string{p.CertRaw, p.KeyRaw} {
						for _, seg := range strings.Split(raw, "/") {
							if seg == "." || seg == ".." {
								t.Fatalf("a supported pair with a dot segment: %+v", p)
							}
						}
					}
				}
				// Without escapes every supported path's file name appears in the input as written.
				if p.Unsupported == "" && (p.Cert == "" || p.Key == "" ||
					(!bytes.ContainsRune(in, '\\') && !bytes.Contains(in, []byte(filepath.Base(p.Cert))))) {
					t.Fatalf("a supported pair whose certificate path is not in the input: %+v", p)
				}
			}
		}
	})
}
