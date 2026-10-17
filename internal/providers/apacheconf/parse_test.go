package apacheconf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
)

// tfile is one entry of a test include tree: parent is the index of the including entry (-1 for
// the root), line the line of its Include directive.
type tfile struct {
	path   string
	parent int
	line   int
	text   string
}

const (
	rootConf = "/etc/apache2/apache2.conf"
	siteConf = "/etc/apache2/sites-enabled/a.conf"
	snippet  = "/etc/apache2/snippets/tls.conf"
)

func root(text string) tfile { return tfile{rootConf, -1, 0, text} }

// testInput is a Debian-like input: ssl_module compiled in, ServerRoot /etc/apache2, no defines,
// version 2.4.57.
func testInput(files ...tfile) Input {
	in := Input{
		Files:   map[string][]byte{},
		Modules: Modules{Static: map[string]bool{"core_module": true, "ssl_module": true}, Loaded: map[string]bool{"core_module": true, "ssl_module": true}},
		Run:     RunConfig{ServerRoot: "/etc/apache2", Defines: map[string]string{}},
		Version: "2.4.57",
	}
	for _, f := range files {
		in.Includes = append(in.Includes, Included{Path: f.path, Parent: f.parent, Line: f.line})
		in.Files[f.path] = []byte(f.text)
	}
	return in
}

func noSSLModule(in *Input) {
	in.Modules = Modules{Static: map[string]bool{"core_module": true}, Loaded: map[string]bool{"core_module": true}}
}

func pair(cert, key string) Pair { return Pair{Cert: cert, Key: key, CertRaw: cert, KeyRaw: key} }

func vhost(body string) string {
	return "<VirtualHost *:443>\n" + body + "</VirtualHost>\n"
}

func TestParse(t *testing.T) {
	sslVhost := vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\nSSLCertificateKeyFile /etc/ssl/a.key\n")
	aServer := []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}}}
	conditional := func(line int, cert, key string) []Server {
		return []Server{{File: rootConf, Line: line, Listens: []Listen{{"", 443, true}},
			Pairs: []Pair{{CertRaw: cert, KeyRaw: key, Unsupported: ReasonConditional}}}}
	}
	for _, tc := range []struct {
		name  string
		files []tfile
		edit  func(*Input)
		want  []Server
	}{
		{name: "two vhosts in a spliced site inside IfModule mod_ssl.c", files: []tfile{
			root("ServerName main.example.test\nIncludeOptional sites-enabled/*.conf\n"),
			{siteConf, 0, 2, "<IfModule mod_ssl.c>\n" +
				"<VirtualHost *:443>\n  ServerName a.example.test\n  ServerAlias www.a.example.test a2.example.test\n  SSLEngine on\n" +
				"  SSLCertificateFile /etc/ssl/a.pem\n  SSLCertificateKeyFile /etc/ssl/a.key\n</VirtualHost>\n" +
				"<VirtualHost *:443>\n  ServerName b.example.test\n  SSLEngine on\n" +
				"  SSLCertificateFile /etc/ssl/b.pem\n  SSLCertificateKeyFile /etc/ssl/b.key\n</VirtualHost>\n</IfModule>\n"},
		}, want: []Server{
			{File: siteConf, Line: 2, Names: []string{"a.example.test", "www.a.example.test", "a2.example.test"}, Listens: []Listen{{"", 443, true}},
				Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}},
			{File: siteConf, Line: 9, Names: []string{"b.example.test"}, Listens: []Listen{{"", 443, false}},
				Pairs: []Pair{pair("/etc/ssl/b.pem", "/etc/ssl/b.key")}},
		}},
		{name: "rsa and ecdsa", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/rsa.pem\nSSLCertificateFile /etc/ssl/ec.pem\n" +
			"SSLCertificateKeyFile /etc/ssl/rsa.key\nSSLCertificateKeyFile /etc/ssl/ec.key\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}},
				Pairs: []Pair{pair("/etc/ssl/rsa.pem", "/etc/ssl/rsa.key"), pair("/etc/ssl/ec.pem", "/etc/ssl/ec.key")}}}},
		{name: "combined: the key is in the certificate file", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/both.pem\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}},
				Pairs: []Pair{{Cert: "/etc/ssl/both.pem", Key: "/etc/ssl/both.pem", CertRaw: "/etc/ssl/both.pem"}}}}},
		{name: "a second key without a certificate is ignored", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n" +
			"SSLCertificateKeyFile /etc/ssl/a.key\nSSLCertificateKeyFile /etc/ssl/b.key\n"))}, want: aServer},
		{name: "inherited from the main server", files: []tfile{root("SSLCertificateFile /etc/ssl/m.pem\nSSLCertificateKeyFile /etc/ssl/m.key\n" +
			"<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n")},
			want: []Server{{File: rootConf, Line: 3, Listens: []Listen{{"", 443, true}},
				Pairs: []Pair{{Cert: "/etc/ssl/m.pem", Key: "/etc/ssl/m.key", CertRaw: "/etc/ssl/m.pem", KeyRaw: "/etc/ssl/m.key", Inherited: true}}}}},
		{name: "own certificate, the main server's key", files: []tfile{root("SSLCertificateKeyFile /etc/ssl/m.key\n" +
			vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/v.pem\n"))},
			want: []Server{{File: rootConf, Line: 2, Listens: []Listen{{"", 443, true}},
				Pairs: []Pair{{Cert: "/etc/ssl/v.pem", Key: "/etc/ssl/m.key", CertRaw: "/etc/ssl/v.pem", KeyRaw: "/etc/ssl/m.key", Inherited: true}}}}},
		// mod_ssl merges the lists index by index (modssl_ctx_cfg_merge_certkeys_array): the
		// vhost's first certificate replaces the main server's first, the main server's second stays.
		{name: "certificate lists merge index by index", files: []tfile{root("SSLCertificateFile /etc/ssl/m1.pem\nSSLCertificateFile /etc/ssl/m2.pem\n" +
			vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/v1.pem\n"))},
			want: []Server{{File: rootConf, Line: 3, Listens: []Listen{{"", 443, true}},
				Pairs: []Pair{{Cert: "/etc/ssl/v1.pem", Key: "/etc/ssl/v1.pem", CertRaw: "/etc/ssl/v1.pem"},
					{Cert: "/etc/ssl/m2.pem", Key: "/etc/ssl/m2.pem", CertRaw: "/etc/ssl/m2.pem", Inherited: true}}}}},
		{name: "a third own certificate comes after the main server's", files: []tfile{root("SSLCertificateFile /etc/ssl/m1.pem\nSSLCertificateFile /etc/ssl/m2.pem\nSSLCertificateFile /etc/ssl/m3.pem\n" +
			vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/v1.pem\nSSLCertificateFile /etc/ssl/v2.pem\nSSLCertificateFile /etc/ssl/v3.pem\n"))},
			want: []Server{{File: rootConf, Line: 4, Listens: []Listen{{"", 443, true}},
				Pairs: []Pair{{Cert: "/etc/ssl/v1.pem", Key: "/etc/ssl/v1.pem", CertRaw: "/etc/ssl/v1.pem"},
					{Cert: "/etc/ssl/v2.pem", Key: "/etc/ssl/v2.pem", CertRaw: "/etc/ssl/v2.pem"},
					{Cert: "/etc/ssl/m3.pem", Key: "/etc/ssl/m3.pem", CertRaw: "/etc/ssl/m3.pem", Inherited: true},
					{Cert: "/etc/ssl/v3.pem", Key: "/etc/ssl/v3.pem", CertRaw: "/etc/ssl/v3.pem"}}}}},
		{name: "SSLEngine optional is not on", files: []tfile{root(vhost("SSLEngine optional\nSSLCertificateFile /etc/ssl/a.pem\n"))}},
		{name: "SSLEngine missing", files: []tfile{root(vhost("SSLCertificateFile /etc/ssl/a.pem\n"))}},
		{name: "SSLEngine off later wins", files: []tfile{root(vhost("SSLEngine on\nSSLEngine off\nSSLCertificateFile /etc/ssl/a.pem\n"))}},
		{name: "SSLEngine on without a certificate", files: []tfile{root(vhost("SSLEngine on\n"))}},
		{name: "a plain vhost", files: []tfile{root("<VirtualHost *:80>\nServerName a\n</VirtualHost>\n")}},
		{name: "main server with its own SSLEngine on", files: []tfile{root("ServerName https://www.main.test:443\nSSLEngine on\n" +
			"SSLCertificateFile /etc/ssl/m.pem\nSSLCertificateKeyFile /etc/ssl/m.key\n")},
			want: []Server{{File: rootConf, Line: 3, Names: []string{"www.main.test"}, Main: true, Pairs: []Pair{pair("/etc/ssl/m.pem", "/etc/ssl/m.key")}}}},
		{name: "main server first, then its vhosts", files: []tfile{root("SSLEngine on\n" + vhost("SSLCertificateFile /etc/ssl/v.pem\n") +
			"SSLCertificateFile /etc/ssl/m.pem\n")},
			want: []Server{{File: rootConf, Line: 5, Main: true, Pairs: []Pair{{Cert: "/etc/ssl/m.pem", Key: "/etc/ssl/m.pem", CertRaw: "/etc/ssl/m.pem"}}},
				{File: rootConf, Line: 2, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/v.pem", Key: "/etc/ssl/v.pem", CertRaw: "/etc/ssl/v.pem"}}}}},
		{name: "main server engine without certificates", files: []tfile{root("SSLEngine on\n")}},
		{name: "IfModule !mod_ssl.c is skipped", files: []tfile{root("<IfModule !mod_ssl.c>\n" + sslVhost + "</IfModule>\n")}},
		{name: "IfModule mod_ssl.c", files: []tfile{root(sslVhost + "<IfModule mod_ssl.c>\n</IfModule>\n")}, want: aServer},
		{name: "ssl_module not loaded", files: []tfile{root("<IfModule ssl_module>\n" + sslVhost + "</IfModule>\n")}, edit: noSSLModule},
		{name: "LoadModule after the IfModule", files: []tfile{root("<IfModule ssl_module>\n" + sslVhost + "</IfModule>\nLoadModule ssl_module modules/mod_ssl.so\n")},
			edit: noSSLModule},
		{name: "LoadModule before the IfModule", files: []tfile{root("LoadModule ssl_module modules/mod_ssl.so\n<IfModule mod_ssl.c>\n" + sslVhost + "</IfModule>\n")},
			edit: noSSLModule, want: []Server{{File: rootConf, Line: 3, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}}}},
		{name: "LoadModule in a false region does not load", files: []tfile{root("<IfDefine NOPE>\nLoadModule ssl_module modules/mod_ssl.so\n</IfDefine>\n" +
			"<IfModule ssl_module>\n" + sslVhost + "</IfModule>\n")}, edit: noSSLModule},
		{name: "LoadModule in an uncertain region makes the module uncertain", files: []tfile{root("<IfVersion ~ ^2>\nLoadModule ssl_module modules/mod_ssl.so\n</IfVersion>\n" +
			"<IfModule ssl_module>\n" + sslVhost + "</IfModule>\n")}, edit: noSSLModule, want: conditional(5, "/etc/ssl/a.pem", "/etc/ssl/a.key")},
		{name: "IfModule core source names", files: []tfile{root("<IfModule core.c>\n<IfModule !prefork.c>\n" + sslVhost + "</IfModule>\n</IfModule>\n")},
			want: []Server{{File: rootConf, Line: 3, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}}}},
		{name: "IfDefine from DUMP_RUN_CFG", files: []tfile{root("<IfDefine SSL>\n" + sslVhost + "</IfDefine>\n")},
			edit: func(in *Input) { in.Run.Defines["SSL"] = "" },
			want: []Server{{File: rootConf, Line: 2, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}}}},
		{name: "IfDefine !X from DUMP_RUN_CFG", files: []tfile{root("<IfDefine !SSL>\n" + sslVhost + "</IfDefine>\n")},
			edit: func(in *Input) { in.Run.Defines["SSL"] = "" }},
		{name: "IfDefine undefined", files: []tfile{root("<IfDefine SSL>\n" + sslVhost + "</IfDefine>\n")}},
		{name: "Define and UnDefine in read order", files: []tfile{root("Define X\n<IfDefine X>\n" + sslVhost + "</IfDefine>\nUnDefine X\n<IfDefine X>\n" +
			vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/b.pem\n") + "</IfDefine>\n")},
			want: []Server{{File: rootConf, Line: 3, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}}}},
		{name: "a run define the configuration also sets is uncertain before the Define", files: []tfile{root("<IfDefine X>\n" + sslVhost + "</IfDefine>\nDefine X\n")},
			edit: func(in *Input) { in.Run.Defines["X"] = "" }, want: conditional(2, "/etc/ssl/a.pem", "/etc/ssl/a.key")},
		{name: "a name the configuration undefines may come from the command line", files: []tfile{root("<IfDefine X>\n" + sslVhost + "</IfDefine>\nUnDefine X\n")},
			want: conditional(2, "/etc/ssl/a.pem", "/etc/ssl/a.key")},
		{name: "Define in a false region does nothing", files: []tfile{root("<IfDefine NOPE>\nDefine X\n</IfDefine>\n<IfDefine X>\n" + sslVhost + "</IfDefine>\n")}},
		{name: "Define in an uncertain region is uncertain", files: []tfile{root("<IfVersion ~ x>\nDefine X\nUnDefine Y\n</IfVersion>\n<IfDefine X>\n" + sslVhost + "</IfDefine>\n")},
			want: conditional(6, "/etc/ssl/a.pem", "/etc/ssl/a.key")},
		{name: "UnDefine in an uncertain region is uncertain", files: []tfile{root("Define X\n<If true>\nUnDefine X\n</If>\n<IfDefine X>\n" + sslVhost + "</IfDefine>\n")},
			want: conditional(6, "/etc/ssl/a.pem", "/etc/ssl/a.key")},
		{name: "IfVersion >= 2.4", files: []tfile{root("<IfVersion >= 2.4>\n" + sslVhost + "</IfVersion>\n")},
			want: []Server{{File: rootConf, Line: 2, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}}}},
		{name: "IfVersion < 2.4", files: []tfile{root("<IfVersion < 2.4>\n" + sslVhost + "</IfVersion>\n")}},
		{name: "IfVersion ~ ^2 is uncertain", files: []tfile{root(vhost("SSLEngine on\n<IfVersion ~ ^2>\nSSLCertificateFile /etc/ssl/a.pem\n</IfVersion>\n"))},
			want: conditional(1, "/etc/ssl/a.pem", "")},
		{name: "If around a pair", files: []tfile{root(vhost("SSLEngine on\n<If \"%{SERVER_PORT} == '443'\">\nSSLCertificateFile /etc/ssl/a.pem\n</If>\n"))},
			want: conditional(1, "/etc/ssl/a.pem", "")},
		{name: "IfModule weird", files: []tfile{root(vhost("SSLEngine on\n<IfModule weird>\nSSLCertificateFile /etc/ssl/a.pem\nSSLCertificateKeyFile /etc/ssl/a.key\n</IfModule>\n"))},
			want: conditional(1, "/etc/ssl/a.pem", "/etc/ssl/a.key")},
		{name: "an uncertain key makes the pair conditional", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n<IfFile /x>\nSSLCertificateKeyFile /etc/ssl/a.key\n</IfFile>\n"))},
			want: conditional(1, "/etc/ssl/a.pem", "/etc/ssl/a.key")},
		{name: "a vhost in an uncertain region", files: []tfile{root("SSLCertificateFile /etc/ssl/a.pem\n<IfDirective Foo>\n" + vhost("SSLEngine on\n") + "</IfDirective>\n")},
			want: []Server{{File: rootConf, Line: 3, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "/etc/ssl/a.pem", Inherited: true, Unsupported: ReasonConditional}}}}},
		{name: "an uncertain SSLEngine on", files: []tfile{root(vhost("<IfSection Foo>\nSSLEngine on\n</IfSection>\nSSLCertificateFile /etc/ssl/a.pem\n"))},
			want: conditional(1, "/etc/ssl/a.pem", "")},
		{name: "Define expands", files: []tfile{root("Define CERTS /etc/ssl/alice\n" + vhost("SSLEngine on\nSSLCertificateFile ${CERTS}/a.pem\n"))},
			want: []Server{{File: rootConf, Line: 2, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/alice/a.pem", Key: "/etc/ssl/alice/a.pem", CertRaw: "${CERTS}/a.pem"}}}}},
		{name: "a Define value expands at read time", files: []tfile{root("Define A /etc\nDefine B ${A}/ssl\nDefine A /nope\n" + vhost("SSLEngine on\nSSLCertificateFile ${B}/a.pem\n"))},
			want: []Server{{File: rootConf, Line: 4, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "${B}/a.pem"}}}}},
		{name: "undefined variable", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile ${NOPE}/a.pem\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "${NOPE}/a.pem", Unsupported: ReasonVariable}}}}},
		{name: "a define without a value is no variable", files: []tfile{root("Define D\n" + vhost("SSLEngine on\nSSLCertificateFile /a/${D}.pem\n"))},
			want: []Server{{File: rootConf, Line: 2, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "/a/${D}.pem", Unsupported: ReasonVariable}}}}},
		{name: "a Define value with an undefined variable", files: []tfile{root("Define D ${ENV}/x\n" + vhost("SSLEngine on\nSSLCertificateFile ${D}/a.pem\n"))},
			want: []Server{{File: rootConf, Line: 2, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "${D}/a.pem", Unsupported: ReasonVariable}}}}},
		{name: "an undefined variable in the key", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\nSSLCertificateKeyFile ${K}\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "/etc/ssl/a.pem", KeyRaw: "${K}", Unsupported: ReasonVariable}}}}},
		{name: "a variable with an uncertain value", files: []tfile{root("<IfVersion /x/>\nDefine D /etc\n</IfVersion>\n" + vhost("SSLEngine on\nSSLCertificateFile ${D}/a.pem\n"))},
			want: conditional(4, "${D}/a.pem", "")},
		{name: "a run define value expands", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile ${D}/a.pem\n"))},
			edit: func(in *Input) { in.Run.Defines["D"] = "/srv" },
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/srv/a.pem", Key: "/srv/a.pem", CertRaw: "${D}/a.pem"}}}}},
		{name: "an unclosed ${ is literal", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /etc/${x.pem\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "/etc/${x.pem", Unsupported: ReasonPathNotAllowed}}}}}, // ValidPath refuses "$"
		{name: "relative path against ServerRoot", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile ssl/a.pem\nSSLCertificateKeyFile ssl/a.key\n"))},
			edit: func(in *Input) { in.Run.ServerRoot = "/etc/httpd" },
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/httpd/ssl/a.pem", Key: "/etc/httpd/ssl/a.key", CertRaw: "ssl/a.pem", KeyRaw: "ssl/a.key"}}}}},
		{name: "relative path without ServerRoot", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile ssl/a.pem\n"))},
			edit: func(in *Input) { in.Run.ServerRoot = "" },
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "ssl/a.pem", Unsupported: ReasonPathNotAllowed}}}}},
		{name: "dot dot is not allowed", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile ../a.pem\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "../a.pem", Unsupported: ReasonPathNotAllowed}}}}},
		{name: "a bad key path", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\nSSLCertificateKeyFile /etc/ssl/\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "/etc/ssl/a.pem", KeyRaw: "/etc/ssl/", Unsupported: ReasonPathNotAllowed}}}}},
		{name: "a directory or / is not a file", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "/", Unsupported: ReasonPathNotAllowed}}}}},
		{name: "Include inside a VirtualHost", files: []tfile{
			root("<VirtualHost *:443>\nSSLEngine on\nInclude snippets/tls.conf\n</VirtualHost>\n"),
			{snippet, 0, 3, "SSLCertificateFile /etc/ssl/s.pem\nSSLCertificateKeyFile /etc/ssl/s.key\n"},
		}, want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/s.pem", "/etc/ssl/s.key")}}}},
		{name: "a continued Include matches its last line", files: []tfile{
			root("SSLEngine on\nInclude \\\n  snippets/tls.conf\n"),
			{snippet, 0, 3, "SSLCertificateFile /etc/ssl/s.pem\n"},
		}, want: []Server{{File: snippet, Line: 1, Main: true, Pairs: []Pair{{Cert: "/etc/ssl/s.pem", Key: "/etc/ssl/s.pem", CertRaw: "/etc/ssl/s.pem"}}}}},
		{name: "many children at one Include line, in tree order, and grandchildren", files: []tfile{
			root("IncludeOptional mods-enabled/*.load\nIncludeOptional sites-enabled/*.conf\n"),
			{"/etc/apache2/mods-enabled/alias.load", 0, 1, "LoadModule alias_module x.so\n"},
			{"/etc/apache2/mods-enabled/ssl.load", 0, 1, "LoadModule ssl_module x.so\n"},
			{siteConf, 0, 2, "<IfModule ssl_module>\n<VirtualHost *:443>\nSSLEngine on\nInclude ../snippets/tls.conf\n</VirtualHost>\n</IfModule>\n"},
			{snippet, 3, 4, "Include ../snippets/b.conf\n"},
			{"/etc/apache2/snippets/b.conf", 4, 1, "SSLCertificateFile /etc/ssl/b.pem\n"},
			{"/etc/apache2/sites-enabled/z.conf", 0, 2, vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/z.pem\n")},
		}, edit: noSSLModule, want: []Server{
			{File: siteConf, Line: 2, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/b.pem", Key: "/etc/ssl/b.pem", CertRaw: "/etc/ssl/b.pem"}}},
			{File: "/etc/apache2/sites-enabled/z.conf", Line: 1, Listens: []Listen{{"", 443, false}}, Pairs: []Pair{{Cert: "/etc/ssl/z.pem", Key: "/etc/ssl/z.pem", CertRaw: "/etc/ssl/z.pem"}}},
		}},
		{name: "a file listed twice is read twice", files: []tfile{
			root("Include a.conf\nInclude a.conf\n"),
			{"/etc/apache2/a.conf", 0, 1, vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n")},
			{"/etc/apache2/a.conf", 0, 2, vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n")},
		}, want: []Server{
			{File: "/etc/apache2/a.conf", Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}},
			{File: "/etc/apache2/a.conf", Line: 1, Listens: []Listen{{"", 443, false}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}},
		}},
		{name: "an Include with no children in a false region", files: []tfile{root("<IfModule !ssl_module>\nInclude x.conf\n</IfModule>\n" + sslVhost)},
			want: []Server{{File: rootConf, Line: 4, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}}}},
		{name: "an Include in an uncertain region is spliced", files: []tfile{
			root("<IfVersion ~ x>\nInclude snippets/tls.conf\n</IfVersion>\n"),
			{snippet, 0, 2, sslVhost},
		}, want: []Server{{File: snippet, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "/etc/ssl/a.pem", KeyRaw: "/etc/ssl/a.key", Unsupported: ReasonConditional}}}}},
		{name: "Include in a Directory is spliced, the directives there are not collected", files: []tfile{
			root(vhost("SSLEngine on\n<Directory /x>\nSSLCertificateFile /etc/ssl/no.pem\nInclude snippets/tls.conf\n</Directory>\nSSLCertificateFile /etc/ssl/a.pem\n")),
			{snippet, 0, 5, "Define D /etc/ssl\n"},
		}, want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}}}},
		{name: "a Define inside a Directory applies", files: []tfile{root("<Directory /x>\nDefine D /etc/ssl\n</Directory>\n" + vhost("SSLEngine on\nSSLCertificateFile ${D}/a.pem\n"))},
			want: []Server{{File: rootConf, Line: 4, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "${D}/a.pem"}}}}},
		{name: "a Macro is not expanded and its body is uncertain", files: []tfile{root("<Macro TLS $c>\nDefine D /etc/ssl\n" + vhost("SSLEngine on\nSSLCertificateFile $c\n") + "</Macro>\n" +
			vhost("SSLEngine on\nSSLCertificateFile ${D}/a.pem\n"))},
			want: conditional(8, "${D}/a.pem", "")},
		{name: "a nested VirtualHost is not a server", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n<VirtualHost *:8443>\nSSLCertificateFile /etc/ssl/b.pem\n</VirtualHost>\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}}}},
		{name: "case-insensitive names", files: []tfile{root("<virtualhost *:443>\nsslengine ON\nsslcertificatefile /etc/ssl/a.pem\nSSLCERTIFICATEKEYFILE /etc/ssl/a.key\n</VIRTUALHOST>\n")},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}}}},
		{name: "ServerName with scheme and port", files: []tfile{root(vhost("ServerName https://www.example.test:443\nServerName https://www.example.test:443\nSSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n"))},
			want: []Server{{File: rootConf, Line: 1, Names: []string{"www.example.test"}, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}}}},
		{name: "ServerName forms", files: []tfile{root(vhost("ServerName [::1]:443\nServerAlias ${ALIAS} b.test:x\nSSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n") +
			vhost("ServerName ${HOST}\nServerAlias\nSSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n"))},
			edit: func(in *Input) { in.Run.Defines["ALIAS"] = "alias.test" },
			want: []Server{{File: rootConf, Line: 1, Names: []string{"[::1]", "alias.test", "b.test:x"}, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}},
				{File: rootConf, Line: 7, Names: []string{"${HOST}"}, Listens: []Listen{{"", 443, false}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}}}},
		{name: "an unclosed bracket and an undefined alias", files: []tfile{root(vhost("ServerName http://[::1\nServerAlias ${NOPE}.test\nSSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n"))},
			want: []Server{{File: rootConf, Line: 1, Names: []string{"[::1", "${NOPE}.test"}, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}}}},
		// fix round 1
		{name: "a hidden directive name in a vhost", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /a.pem\n${K} /a.key\n"))},
			edit: func(in *Input) { in.Run.Defines["K"] = "SSLCertificateKeyFile" }, want: conditional(1, "/a.pem", "")},
		{name: "a hidden section name in a vhost", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /a.pem\n<${M} ssl_module>\nSSLCertificateKeyFile /a.key\n</${M}>\n"))},
			want: conditional(1, "/a.pem", "")},
		{name: "a hidden directive name at the main level", files: []tfile{root("${E} on\n" + vhost("SSLEngine on\nSSLCertificateFile /a.pem\n"))},
			want: conditional(2, "/a.pem", "")},
		{name: "a hidden name in a Directory changes nothing", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /a.pem\n<Directory />\n${K} x\n</Directory>\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/a.pem", Key: "/a.pem", CertRaw: "/a.pem"}}}}},
		{name: "a hidden Define name makes run defines uncertain", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile ${D}/a.pem\n") + "Define ${N} /srv\n")},
			edit: func(in *Input) { in.Run.Defines["D"] = "/srv" }, want: conditional(1, "${D}/a.pem", "")},
		{name: "a hidden UnDefine name makes run defines uncertain", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile ${D}/a.pem\n") + "UnDefine ${N}\n")},
			edit: func(in *Input) { in.Run.Defines["D"] = "/srv" }, want: conditional(1, "${D}/a.pem", "")},
		{name: "an uncertain certificate makes the later ones conditional", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /a.pem\n<IfFile /x>\nSSLCertificateFile /b.pem\n</IfFile>\nSSLCertificateFile /c.pem\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/a.pem", Key: "/a.pem", CertRaw: "/a.pem"},
				{CertRaw: "/b.pem", Unsupported: ReasonConditional}, {CertRaw: "/c.pem", Unsupported: ReasonConditional}}}}},
		{name: "an uncertain key makes the later keys conditional", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateFile /a.pem\nSSLCertificateFile /b.pem\n" +
			"<If true>\nSSLCertificateKeyFile /a.key\n</If>\nSSLCertificateKeyFile /b.key\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{CertRaw: "/a.pem", KeyRaw: "/a.key", Unsupported: ReasonConditional},
				{CertRaw: "/b.pem", KeyRaw: "/b.key", Unsupported: ReasonConditional}}}}},
		{name: "SSLEngine with an address is uncertain", files: []tfile{root(vhost("SSLEngine *:443\nSSLCertificateFile /a.pem\n"))},
			want: conditional(1, "/a.pem", "")},
		{name: "SSLEngine with addresses is uncertain", files: []tfile{root(vhost("SSLEngine 10.0.0.1:443 *:8443\nSSLCertificateFile /a.pem\n"))},
			want: conditional(1, "/a.pem", "")},
		{name: "a vhost without ServerName on a wildcard address takes the main server's", files: []tfile{root("ServerName https://main.test:443\n" +
			vhost("ServerAlias b.test\nSSLEngine on\nSSLCertificateFile /a.pem\n") +
			"<VirtualHost 10.0.0.1:443>\nSSLEngine on\nSSLCertificateFile /a.pem\n</VirtualHost>\n")},
			want: []Server{{File: rootConf, Line: 2, Names: []string{"main.test", "b.test"}, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/a.pem", Key: "/a.pem", CertRaw: "/a.pem"}}},
				{File: rootConf, Line: 7, Listens: []Listen{{"10.0.0.1", 443, true}}, Pairs: []Pair{{Cert: "/a.pem", Key: "/a.pem", CertRaw: "/a.pem"}}}}},
		{name: "[::] is any address", files: []tfile{root("<VirtualHost [::]:443>\nSSLEngine on\nSSLCertificateFile /a.pem\n</VirtualHost>\n")},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/a.pem", Key: "/a.pem", CertRaw: "/a.pem"}}}}},
		{name: "IPv6 and _default_ listens", files: []tfile{root("<VirtualHost [::1]:8443>\n</VirtualHost>\n<VirtualHost [::1]:8443 _default_:443>\nSSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n</VirtualHost>\n")},
			want: []Server{{File: rootConf, Line: 3, Listens: []Listen{{"::1", 8443, false}, {"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}}}},
		{name: "the first vhost of an address is its default", files: []tfile{root("<VirtualHost [::1]:8443 10.0.0.1:443 0.0.0.0:443>\nSSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n</VirtualHost>\n" +
			"<VirtualHost 10.0.0.1:443 *:443 _default_:443>\nSSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n</VirtualHost>\n")},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"::1", 8443, true}, {"10.0.0.1", 443, true}, {"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}},
				{File: rootConf, Line: 5, Listens: []Listen{{"10.0.0.1", 443, false}, {"", 443, false}, {"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}}}},
		{name: "listens without a usable port are dropped", files: []tfile{root("<VirtualHost a.test *:* [::1] [::1]x [::1 ::1 :443 *:0 *:65536 *:x1 ${P}:443 ${Q}:443 *:65535>\nSSLEngine on\nSSLCertificateFile /etc/ssl/a.pem\n</VirtualHost>\n")},
			edit: func(in *Input) { in.Run.Defines["Q"] = "10.1.1.1" },
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"10.1.1.1", 443, true}, {"", 65535, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}}}},
		{name: "vhosts in a false region do not take the default", files: []tfile{root("<IfDefine NOPE>\n<VirtualHost *:443>\n</VirtualHost>\n</IfDefine>\n" + sslVhost)},
			want: []Server{{File: rootConf, Line: 5, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{pair("/etc/ssl/a.pem", "/etc/ssl/a.key")}}}},
		{name: "SSLCertificateChainFile is ignored", files: []tfile{root(vhost("SSLEngine on\nSSLCertificateChainFile /etc/ssl/chain.pem\nSSLCertificateFile /etc/ssl/a.pem\nSSLCertificateKeyFile /etc/ssl/a.key\n"))},
			want: aServer},
		{name: "directives with the wrong number of arguments are ignored", files: []tfile{root(vhost("SSLEngine\nSSLEngine on\nSSLCertificateFile\nSSLCertificateFile a b\n" +
			"SSLCertificateFile /etc/ssl/a.pem\nSSLCertificateKeyFile\nServerName\nDefine\nDefine a b c\nUnDefine\nLoadModule\n"))},
			want: []Server{{File: rootConf, Line: 1, Listens: []Listen{{"", 443, true}}, Pairs: []Pair{{Cert: "/etc/ssl/a.pem", Key: "/etc/ssl/a.pem", CertRaw: "/etc/ssl/a.pem"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := testInput(tc.files...)
			if tc.edit != nil {
				tc.edit(&in)
			}
			got, err := Parse(in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.Servers)
		})
	}
}

func TestParseErrors(t *testing.T) {
	deep := strings.Repeat("<IfDefine X>\n", 101) + strings.Repeat("</IfDefine>\n", 101)
	half := strings.Repeat("<IfDefine !X>\n", 60)
	halfEnd := strings.Repeat("</IfDefine>\n", 60)
	for _, tc := range []struct {
		name  string
		files []tfile
		edit  func(*Input)
		err   error
	}{
		{name: "a tree child at a line with no Include", files: []tfile{root("SSLEngine on\n"), {snippet, 0, 1, ""}}, err: ErrIncludeMismatch},
		{name: "a tree child at a line past the end", files: []tfile{root("Include x\n"), {snippet, 0, 7, ""}}, err: ErrIncludeMismatch},
		{name: "a continued Include at its first line", files: []tfile{root("Include \\\n x.conf\n"), {snippet, 0, 1, ""}}, err: ErrIncludeMismatch},
		{name: "a tree child under an Include in a false region", files: []tfile{root("<IfModule !ssl_module>\nInclude x.conf\n</IfModule>\n"), {snippet, 0, 2, ""}},
			err: ErrIncludeMismatch},
		{name: "a grandchild of a file never spliced", files: []tfile{root("<IfDefine NOPE>\nInclude a.conf\n</IfDefine>\n"), {"/etc/apache2/a.conf", 0, 1, "Include b\n"},
			{snippet, 1, 1, ""}}, err: ErrIncludeMismatch},
		{name: "a file the caller did not give", files: []tfile{root("Include x\n"), {snippet, 0, 1, ""}}, edit: func(in *Input) { delete(in.Files, snippet) },
			err: ErrIncludeMismatch},
		{name: "no tree", edit: func(in *Input) { in.Includes = nil }, err: ErrOutput},
		{name: "a root with a parent", files: []tfile{{rootConf, 0, 0, ""}}, err: ErrOutput},
		{name: "a parent after the child", files: []tfile{root("Include x\n"), {snippet, 1, 1, ""}}, err: ErrOutput},
		{name: "a child without a line", files: []tfile{root("Include x\n"), {snippet, 0, 0, ""}}, err: ErrOutput},
		{name: "too many files", files: []tfile{root("")}, edit: func(in *Input) {
			for range MaxFiles {
				in.Includes = append(in.Includes, Included{Path: snippet, Parent: 0, Line: 1})
			}
			in.Files[snippet] = nil
		}, err: ErrTooComplex},
		{name: "includes nested deeper than MaxDepth", files: []tfile{root("Include x\n")}, edit: func(in *Input) {
			for i := 1; i <= MaxDepth+1; i++ {
				in.Includes = append(in.Includes, Included{Path: snippet, Parent: i - 1, Line: 1})
			}
			in.Files[snippet] = []byte("Include x\n")
		}, err: ErrTooDeep},
		{name: "sections nested 101 deep in one file", files: []tfile{root(deep)}, err: ErrTooDeep},
		{name: "sections nested 101 deep across files", files: []tfile{root(half + "Include x\n" + halfEnd), {snippet, 0, 61, half + halfEnd}}, err: ErrTooDeep},
		{name: "a syntax error in a spliced file", files: []tfile{root("Include x\n"), {snippet, 0, 1, "Foo \"a\n"}}, err: ErrSyntax},
		{name: "a NUL", files: []tfile{root("Foo\x00\n")}, err: ErrNUL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := testInput(tc.files...)
			if tc.edit != nil {
				tc.edit(&in)
			}
			got, err := Parse(in)
			require.ErrorIs(t, err, tc.err)
			assert.Equal(t, Config{}, got)
		})
	}
}

func TestParseWholeConfigurationLimits(t *testing.T) {
	t.Run("words over MaxTokens across files", func(t *testing.T) {
		words := strings.Repeat("A\n", MaxTokens/2+1)
		in := testInput(root("Include x\n"+words), tfile{snippet, 0, 1, words})
		_, err := Parse(in)
		require.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("exactly MaxTokens across files", func(t *testing.T) {
		words := strings.Repeat("A\n", MaxTokens/2-1)
		in := testInput(root("Include x\n"+words), tfile{snippet, 0, 1, words})
		_, err := Parse(in)
		require.NoError(t, err)
	})
	t.Run("a file read twice counts twice", func(t *testing.T) {
		words := strings.Repeat("A\n", MaxTokens/3)
		in := testInput(root("Include x\nInclude x\n"), tfile{snippet, 0, 1, words}, tfile{snippet, 0, 2, words})
		_, err := Parse(in)
		require.NoError(t, err)
		in.Includes = append(in.Includes, Included{Path: snippet, Parent: 0, Line: 2})
		_, err = Parse(in)
		require.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("input over MaxInput across files, before any lexing", func(t *testing.T) {
		// the root has a syntax error: ErrTooLarge comes first, nothing was lexed
		comments := "Foo \"\n" + strings.Repeat("#", MaxInput/2)
		in := testInput(root("Include x\n"+comments), tfile{snippet, 0, 1, comments})
		_, err := Parse(in)
		require.ErrorIs(t, err, ErrTooLarge)
	})
	t.Run("pairs over MaxPairs", func(t *testing.T) {
		var b strings.Builder
		for i := range 300 {
			fmt.Fprintf(&b, "SSLCertificateFile /etc/ssl/%d.pem\n", i)
		}
		b.WriteString(strings.Repeat("<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n", 300))
		_, err := Parse(testInput(root(b.String())))
		require.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("main server pairs over MaxPairs", func(t *testing.T) {
		b := "SSLEngine on\n" + strings.Repeat("SSLCertificateFile /a.pem\n", MaxPairs+1)
		_, err := Parse(testInput(root(b)))
		require.ErrorIs(t, err, ErrTooComplex)
		_, err = Parse(testInput(root(strings.Repeat("SSLCertificateFile /a.pem\n", MaxPairs+1))))
		require.NoError(t, err, "not a server: no pairs")
	})
	t.Run("one line of many expansions stops at the budget", func(t *testing.T) {
		// 1 MB of configuration: one 8000-byte define, then ~200k references on one line.
		cfg := "Define A /" + strings.Repeat("a", 7999) + "\n" + vhost("ServerAlias"+strings.Repeat(" ${A}", 200000)+"\n")
		in := testInput(root(cfg))
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		_, err := Parse(in)
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		require.ErrorIs(t, err, ErrTooComplex)
		allocated := after.TotalAlloc - before.TotalAlloc
		t.Logf("allocated %d bytes in %v", allocated, elapsed)
		assert.Less(t, allocated, uint64(64<<20))
		assert.Less(t, elapsed, 2*time.Second*raceSlowdown)
	})
	t.Run("one section line of many expansions stops at the budget", func(t *testing.T) {
		cfg := "Define A /" + strings.Repeat("a", 7999) + "\n<VirtualHost" + strings.Repeat(" ${A}:443", 100000) + ">\n</VirtualHost>\n"
		_, err := Parse(testInput(root(cfg)))
		require.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("text after the last variable counts against 8 KiB", func(t *testing.T) {
		cfg := vhost("SSLEngine on\nSSLCertificateFile ${D}/" + strings.Repeat("b", maxExpansion) + "\n")
		in := testInput(root(cfg))
		in.Run.Defines["D"] = "/etc"
		got, err := Parse(in)
		require.NoError(t, err)
		assert.Equal(t, ReasonVariable, got.Servers[0].Pairs[0].Unsupported)
	})
	t.Run("an expansion longer than 8 KiB is not used", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("Define A0 /" + strings.Repeat("a", 63) + "\n")
		for i := 1; i <= 8; i++ {
			fmt.Fprintf(&b, "Define A%d ${A%d}${A%d}\n", i, i-1, i-1)
		}
		b.WriteString(vhost("SSLEngine on\nSSLCertificateFile ${A7}\nSSLCertificateFile ${A8}\n"))
		cfg, err := Parse(testInput(root(b.String())))
		require.NoError(t, err)
		require.Len(t, cfg.Servers, 1)
		assert.Equal(t, ReasonPathNotAllowed, cfg.Servers[0].Pairs[0].Unsupported, "8192 bytes: expanded, no valid path")
		assert.Equal(t, ReasonVariable, cfg.Servers[0].Pairs[1].Unsupported)
	})
	t.Run("expansions over MaxInput in total", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("Define A0 /" + strings.Repeat("a", 63) + "\n")
		for i := 1; i <= 7; i++ {
			fmt.Fprintf(&b, "Define A%d ${A%d}${A%d}\n", i, i-1, i-1)
		}
		b.WriteString(strings.Repeat("Define B ${A7}\n", MaxInput/8192+1))
		_, err := Parse(testInput(root(b.String())))
		require.ErrorIs(t, err, ErrTooComplex)
	})
}

// TestParseHostileShapes: shapes that would be quadratic or deep in a naive walk stay fast.
func TestParseHostileShapes(t *testing.T) {
	limit := 3 * time.Second * raceSlowdown
	for name, in := range map[string]Input{
		"many vhosts on one address": testInput(root(strings.Repeat("<VirtualHost *:443>\nSSLEngine on\nSSLCertificateFile /a.pem\n</VirtualHost>\n", 60000))),
		"many children at one line": func() Input {
			in := testInput(root("Include x\n"))
			for range MaxFiles - 1 {
				in.Includes = append(in.Includes, Included{Path: snippet, Parent: 0, Line: 1})
			}
			in.Files[snippet] = []byte(vhost("SSLEngine on\nSSLCertificateFile /a.pem\n"))
			return in
		}(),
		"a long include chain": func() Input {
			in := testInput(root("Include x\n"))
			for i := 1; i <= MaxDepth; i++ {
				in.Includes = append(in.Includes, Included{Path: snippet, Parent: i - 1, Line: 1})
			}
			in.Files[snippet] = []byte("Include x\n" + strings.Repeat("<IfDefine X>\n</IfDefine>\n", 1000))
			return in
		}(),
		"many main keys, many listed vhosts": testInput(root(strings.Repeat("SSLCertificateKeyFile /a.key\n", 100000) +
			strings.Repeat("<VirtualHost *:443>\nSSLEngine on\nSSLCertificateFile /a.pem\n</VirtualHost>\n", 60000))),
		"many main certificates, many plain vhosts": testInput(root(strings.Repeat("SSLCertificateFile /a.pem\n", 300000) +
			strings.Repeat("<VirtualHost *:80>\n</VirtualHost>\n", 100000))),
		"many defines and expansions": testInput(root(strings.Repeat("Define A /etc/ssl\nDefine B ${A}${A}${A}\n", 50000) +
			vhost("SSLEngine on\n"+strings.Repeat("SSLCertificateFile ${B}/a.pem\n", 50000)))),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := Parse(in)
			require.NoError(t, err)
			assert.Less(t, time.Since(start), limit)
		})
	}
}

// readTree builds the input of a captured host from testdata/<name>: the tool output under _tool
// and the configuration files under their absolute paths.
func readTree(t *testing.T, name string) Input {
	t.Helper()
	dir := filepath.Join("testdata", name)
	tool := func(f string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, "_tool", f))
		require.NoError(t, err)
		return b
	}
	version, confPath := ParseV(tool("V.txt"))
	includes, err := ParseIncludes(tool("includes.txt"))
	require.NoError(t, err)
	require.Equal(t, confPath, includes[0].Path)
	modules, err := ParseModules(tool("modules.txt"))
	require.NoError(t, err)
	run, err := ParseRunConfig(tool("runcfg.txt"))
	require.NoError(t, err)
	in := Input{Includes: includes, Files: map[string][]byte{}, Modules: modules, Run: run, Version: version}
	for _, e := range includes {
		b, err := os.ReadFile(filepath.Join(dir, e.Path))
		require.NoError(t, err)
		in.Files[e.Path] = b
	}
	return in
}

func TestParseCapturedTrees(t *testing.T) {
	t.Run("debian 12", func(t *testing.T) {
		in := readTree(t, "debian")
		require.Len(t, in.Includes, 41)
		cfg, err := Parse(in)
		require.NoError(t, err)
		assert.Equal(t, []Server{{File: "/etc/apache2/sites-enabled/default-ssl.conf", Line: 2, Listens: []Listen{{"", 443, true}},
			Pairs: []Pair{pair("/etc/ssl/certs/ssl-cert-snakeoil.pem", "/etc/ssl/private/ssl-cert-snakeoil.key")}}}, cfg.Servers)
		assert.Len(t, cfg.Files, 41)
		assert.Equal(t, "/etc/apache2/apache2.conf", cfg.Files[0])
		assert.Equal(t, []string{"/etc/ssl/certs/ssl-cert-snakeoil.pem"}, cfg.CertPaths())
		assert.Equal(t, []string{"/etc/ssl/private/ssl-cert-snakeoil.key"}, cfg.KeyPaths())
	})
	t.Run("debian 12 without the ssl module", func(t *testing.T) {
		in := readTree(t, "debian")
		var tree []Included
		for _, e := range in.Includes {
			if e.Path != "/etc/apache2/mods-enabled/ssl.load" && e.Path != "/etc/apache2/mods-enabled/ssl.conf" {
				tree = append(tree, e)
			}
		}
		in.Includes = tree
		cfg, err := Parse(in)
		require.NoError(t, err)
		assert.Empty(t, cfg.Servers)
	})
	t.Run("rocky 9", func(t *testing.T) {
		cfg, err := Parse(readTree(t, "rocky"))
		require.NoError(t, err)
		assert.Equal(t, []Server{{File: "/etc/httpd/conf.d/ssl.conf", Line: 14, Listens: []Listen{{"", 443, true}},
			Pairs: []Pair{pair("/etc/pki/tls/certs/localhost.crt", "/etc/pki/tls/private/localhost.key")}}}, cfg.Servers)
		assert.Equal(t, []string{"/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.modules.d/00-base.conf", "/etc/httpd/conf.modules.d/00-mpm.conf",
			"/etc/httpd/conf.modules.d/00-ssl.conf", "/etc/httpd/conf.d/ssl.conf"}, cfg.Files)
	})
	t.Run("rocky 9 with the conf.d line moved", func(t *testing.T) {
		in := readTree(t, "rocky")
		in.Includes[len(in.Includes)-1].Line = 357
		_, err := Parse(in)
		require.ErrorIs(t, err, ErrIncludeMismatch)
	})
}

func TestIfVersion(t *testing.T) {
	for _, tc := range []struct {
		args    string
		version string
		want    bool // the vhost is listed with a supported pair
		uncert  bool
	}{
		{">= 2.4", "2.4.57", true, false},
		{"> 2.4.57", "2.4.57", false, false},
		{"> 2.4.56", "2.4.57", true, false},
		{"<= 2.4.57", "2.4.57", true, false},
		{"< 2.4.58", "2.4.57", true, false},
		{"< 2", "2.4.57", false, false},
		{"> 3", "2.4.57", false, false},
		{"< 3", "2.4.57", true, false},
		{"= 2.4", "2.4.57", false, false},
		{"2.4.57", "2.4.57", true, false},
		{"== 2.4.57", "2.4.57", true, false},
		{"!= 2.4.57", "2.4.57", false, false},
		{"! 2.4.57", "2.4.57", false, false},
		{"!< 2.5", "2.4.57", false, false},
		{">= 2.4", "2.4.57-dev", true, false},
		{"~ ^2", "2.4.57", false, true},
		{"/^2/", "2.4.57", false, true},
		{"= /^2/", "2.4.57", false, true},
		{"=~ 2", "2.4.57", false, true},
		{"> x", "2.4.57", false, true},
		{"> 2.4.57.1", "2.4.57", false, true},
		{"> 2..4", "2.4.57", false, true},
		{"> 1234567890", "2.4.57", false, true},
		{">= 2.4", "", false, true},
		{">= 2.4", "x.y", false, true},
		{">= 2.4 x", "2.4.57", false, true},
		{"> ${V}", "2.4.57", false, true},
	} {
		t.Run(tc.args+" for "+tc.version, func(t *testing.T) {
			in := testInput(root("<IfVersion " + tc.args + ">\n" + vhost("SSLEngine on\nSSLCertificateFile /a.pem\n") + "</IfVersion>\n"))
			in.Version = tc.version
			cfg, err := Parse(in)
			require.NoError(t, err)
			switch {
			case tc.uncert:
				require.Len(t, cfg.Servers, 1)
				assert.Equal(t, ReasonConditional, cfg.Servers[0].Pairs[0].Unsupported)
			case tc.want:
				require.Len(t, cfg.Servers, 1)
				assert.Empty(t, cfg.Servers[0].Pairs[0].Unsupported)
			default:
				assert.Empty(t, cfg.Servers)
			}
		})
	}
}

func TestConditionArguments(t *testing.T) {
	for _, tc := range []struct {
		section string
		want    string // "on", "off" or "uncertain"
	}{
		{"<IfModule>", "uncertain"},
		{"<IfModule a b>", "uncertain"},
		{"<IfModule !>", "uncertain"},
		{"<IfModule mod_ssl.c>", "on"},
		{"<IfModule !ssl_module>", "off"},
		{"<IfModule ${M}>", "uncertain"},
		{"<IfModule ${S}>", "on"},
		{"<IfModule !weird>", "uncertain"},
		{"<IfDefine>", "uncertain"},
		{"<IfDefine !>", "uncertain"},
		{"<IfDefine a b>", "uncertain"},
		{"<IfDefine ${M}>", "uncertain"},
		{"<IfDefine DUMP_RUN_CFG>", "off"},
		{"<IfVersion>", "uncertain"},
		{"<ElseIf true>", "uncertain"},
		{"<Else>", "uncertain"},
		{"<IfFile /x>", "uncertain"},
		{"<Location />", "off"}, // descended, not collected
	} {
		t.Run(tc.section, func(t *testing.T) {
			name := strings.TrimPrefix(strings.Fields(strings.Trim(tc.section, "<>"))[0], "<")
			in := testInput(root(vhost("SSLEngine on\n" + tc.section + "\nSSLCertificateFile /a.pem\n</" + name + ">\n")))
			in.Run.Defines["S"] = "ssl_module"
			cfg, err := Parse(in)
			require.NoError(t, err)
			switch tc.want {
			case "on":
				require.Len(t, cfg.Servers, 1)
				assert.Empty(t, cfg.Servers[0].Pairs[0].Unsupported)
			case "off":
				assert.Empty(t, cfg.Servers)
			default:
				require.Len(t, cfg.Servers, 1)
				assert.Equal(t, ReasonConditional, cfg.Servers[0].Pairs[0].Unsupported)
			}
		})
	}
	t.Run("a Define name that cannot be expanded makes every IfDefine uncertain", func(t *testing.T) {
		in := testInput(root("Define ${ENV} 1\n<IfDefine !X>\n" + vhost("SSLEngine on\nSSLCertificateFile /a.pem\n") + "</IfDefine>\n"))
		cfg, err := Parse(in)
		require.NoError(t, err)
		require.Len(t, cfg.Servers, 1)
		assert.Equal(t, ReasonConditional, cfg.Servers[0].Pairs[0].Unsupported)
	})
	t.Run("an UnDefine name that cannot be expanded", func(t *testing.T) {
		in := testInput(root("UnDefine ${ENV}\n<IfDefine X>\n" + vhost("SSLEngine on\nSSLCertificateFile /a.pem\n") + "</IfDefine>\n"))
		in.Run.Defines["X"] = ""
		cfg, err := Parse(in)
		require.NoError(t, err)
		require.Len(t, cfg.Servers, 1)
		assert.Equal(t, ReasonConditional, cfg.Servers[0].Pairs[0].Unsupported)
	})
	t.Run("a LoadModule name that cannot be expanded makes unloaded modules uncertain", func(t *testing.T) {
		in := testInput(root("LoadModule ${ENV}_module x.so\n<IfModule ssl_module>\n" + vhost("SSLEngine on\nSSLCertificateFile /a.pem\n") + "</IfModule>\n" +
			"<IfModule core_module>\n" + vhost("SSLEngine on\nSSLCertificateFile /b.pem\n") + "</IfModule>\n"))
		noSSLModule(&in)
		cfg, err := Parse(in)
		require.NoError(t, err)
		require.Len(t, cfg.Servers, 2)
		assert.Equal(t, ReasonConditional, cfg.Servers[0].Pairs[0].Unsupported)
		assert.Empty(t, cfg.Servers[1].Pairs[0].Unsupported, "a compiled-in module stays certain")
	})
	t.Run("a LoadModule with an expanded name", func(t *testing.T) {
		in := testInput(root("Define M ssl_module\nLoadModule ${M} x.so\n<IfModule ssl_module>\n" + vhost("SSLEngine on\nSSLCertificateFile /a.pem\n") + "</IfModule>\n"))
		noSSLModule(&in)
		cfg, err := Parse(in)
		require.NoError(t, err)
		require.Len(t, cfg.Servers, 1)
		assert.Empty(t, cfg.Servers[0].Pairs[0].Unsupported)
	})
}

func TestPaths(t *testing.T) {
	cfg := Config{Servers: []Server{
		{Pairs: []Pair{{Cert: "/a.pem", Key: "/a.key"}, {Cert: "/b.pem", Key: "/b.pem"}, {CertRaw: "${X}", Unsupported: ReasonVariable}}},
		{Pairs: []Pair{{Cert: "/a.pem", Key: "/a.key"}, {Cert: "/c.pem", Key: "/c.key", Unsupported: ReasonConfigFileWritable}}},
	}}
	assert.Equal(t, []string{"/a.pem", "/b.pem"}, cfg.CertPaths())
	assert.Equal(t, []string{"/a.key", "/b.pem"}, cfg.KeyPaths())
	assert.Empty(t, Config{}.CertPaths())
}

func TestMarkWritable(t *testing.T) {
	cfg := Config{Servers: []Server{
		{Pairs: []Pair{{Cert: "/a.pem", Key: "/a.key"}, {CertRaw: "${X}", Unsupported: ReasonVariable}}},
		{Pairs: []Pair{{CertRaw: "x", Unsupported: ReasonConditional}, {Cert: "/b.pem", Key: "/b.pem", Inherited: true}}},
	}}
	MarkWritable(&cfg)
	assert.Equal(t, []Server{
		{Pairs: []Pair{{Cert: "/a.pem", Key: "/a.key", Unsupported: ReasonConfigFileWritable}, {CertRaw: "${X}", Unsupported: ReasonVariable}}},
		{Pairs: []Pair{{CertRaw: "x", Unsupported: ReasonConditional}, {Cert: "/b.pem", Key: "/b.pem", Inherited: true, Unsupported: ReasonConfigFileWritable}}},
	}, cfg.Servers)
	assert.Empty(t, cfg.CertPaths())
	MarkWritable(&Config{})
}

func TestToWire(t *testing.T) {
	assert.Equal(t, helperproto.DumpServer{File: "/a.conf", Line: 3, Names: []string{}, Listens: []helperproto.DumpListen{}, Pairs: []helperproto.DumpPair{}},
		ToWire(Server{File: "/a.conf", Line: 3}))
	long := strings.Repeat("é", 250)
	got := ToWire(Server{File: "/a.conf", Line: 1, Main: true, Names: []string{"a.test", "b\x01.test", strings.Repeat("n", 300)},
		Listens: []Listen{{"", 443, true}, {"::1", 8443, false}},
		Pairs: []Pair{
			{Cert: "/a.pem", Key: "/a.key", CertRaw: "/a.pem", KeyRaw: "/a.key", Inherited: true},
			{CertRaw: "${X}/" + long, KeyRaw: "k", Unsupported: ReasonVariable},
			{CertRaw: "a\x7f\nb\xff", Unsupported: ReasonConditional},
		}})
	assert.Equal(t, helperproto.DumpServer{File: "/a.conf", Line: 1, Names: []string{"a.test", "b.test", strings.Repeat("n", 253)},
		Listens: []helperproto.DumpListen{{Addr: "", Port: 443, DefaultServer: true}, {Addr: "::1", Port: 8443}},
		Pairs: []helperproto.DumpPair{
			{Cert: "/a.pem", Key: "/a.key", Inherited: true},
			{Unsupported: ReasonVariable, Raw: "${X}/" + strings.Repeat("é", 195)},
			{Unsupported: ReasonConditional, Raw: "ab"},
		}}, got)
}

func TestParseIsDeterministic(t *testing.T) {
	in := readTree(t, "debian")
	a, err := Parse(in)
	require.NoError(t, err)
	b, err := Parse(in)
	require.NoError(t, err)
	assert.Equal(t, a, b)
	assert.False(t, errors.Is(err, ErrOutput))
}
