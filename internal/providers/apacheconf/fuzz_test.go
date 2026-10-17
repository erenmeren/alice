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

// FuzzParseApacheConfig (§25.6): Parse never panics on a one-file configuration with ssl_module
// loaded; every supported pair names valid helper paths, every server a line, and ToWire accepts
// every server.
func FuzzParseApacheConfig(f *testing.F) {
	f.Add([]byte("<IfModule mod_ssl.c>\n<VirtualHost _default_:443>\nServerName a.test\nSSLEngine on\n" +
		"SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem\nSSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key\n</VirtualHost>\n</IfModule>\n"))
	f.Add([]byte("Define D /etc/ssl\nSSLEngine on\nSSLCertificateFile ${D}/a.pem\nSSLCertificateFile ssl/b.pem\n" +
		"<VirtualHost [::1]:8443 *:443>\nSSLCertificateFile ../x\nSSLCertificateKeyFile ${NOPE}\n</VirtualHost>\n"))
	f.Add([]byte("<IfVersion ~ ^2>\nDefine X\n</IfVersion>\n<IfDefine X>\n<VirtualHost *:443>\nSSLEngine on\n<If true>\n" +
		"SSLCertificateFile /a\n</If>\n</VirtualHost>\n</IfDefine>\nUnDefine X\nLoadModule foo_module x.so\n<IfModule !foo_module>\n</IfModule>\n"))
	f.Add([]byte("Include \\\n x.conf\n<Macro M $a>\nSSLCertificateFile $a\n</Macro>\nUse M /a\n<Directory />\nDefine A ${A}${A}\n</Directory>\n"))
	f.Add([]byte("<VirtualHost *:443>\nSSLEngine on\nSSLCertificateFile /\nSSLCertificateFile /etc/${x\n</VirtualHost>\n\"unterminated\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		in := Input{
			Includes: []Included{{Path: "/etc/apache2/apache2.conf", Parent: -1}},
			Files:    map[string][]byte{"/etc/apache2/apache2.conf": data},
			Modules:  Modules{Static: map[string]bool{"core_module": true, "ssl_module": true}},
			Run:      RunConfig{ServerRoot: "/etc/apache2", Defines: map[string]string{"SSL": ""}},
			Version:  "2.4.57",
		}
		cfg, err := Parse(in)
		if err != nil {
			if len(cfg.Servers) != 0 || len(cfg.Files) != 0 {
				t.Fatalf("a configuration with an error: %+v", cfg)
			}
			return
		}
		for _, s := range cfg.Servers {
			if s.Line < 1 || s.File != "/etc/apache2/apache2.conf" {
				t.Fatalf("server at %s:%d", s.File, s.Line)
			}
			for _, p := range s.Pairs {
				if p.Unsupported == "" && (!helperproto.ValidPath(p.Cert) || !helperproto.ValidPath(p.Key)) {
					t.Fatalf("supported pair with an invalid path: %+v", p)
				}
			}
			w := ToWire(s)
			if w.Names == nil || w.Listens == nil || w.Pairs == nil || w.Stream {
				t.Fatalf("wire server %+v", w)
			}
		}
		for _, p := range cfg.CertPaths() {
			if !helperproto.ValidPath(p) {
				t.Fatalf("cert path %q", p)
			}
		}
	})
}
