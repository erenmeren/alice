package apacheconf

import (
	"bytes"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// debianV is "apache2ctl -V" of Debian 12 (Apache 2.4.68), captured on a real host and trimmed.
const debianV = `Server version: Apache/2.4.68 (Debian)
Server built:   2026-06-12T05:08:45
Server's Module Magic Number: 20120211:142
Architecture:   64-bit
Server MPM:     event
  threaded:     yes (fixed thread count)
    forked:     yes (variable process count)
Server compiled with....
 -D APR_HAS_SENDFILE
 -D APR_HAVE_IPV6 (IPv4-mapped addresses enabled)
 -D DYNAMIC_MODULE_LIMIT=256
 -D HTTPD_ROOT="/etc/apache2"
 -D SUEXEC_BIN="/usr/lib/apache2/suexec"
 -D DEFAULT_PIDLOG="/run/apache2.pid"
 -D AP_TYPES_CONFIG_FILE="mime.types"
 -D SERVER_CONFIG_FILE="apache2.conf"
`

// rockyV is "httpd -V" of Rocky Linux 9 (Apache 2.4.62), captured on a real host and trimmed.
const rockyV = `Server version: Apache/2.4.62 (Rocky Linux)
Server built:   Aug 13 2026 00:00:00
Server MPM:     event
Server compiled with....
 -D APR_HAS_SENDFILE
 -D HTTPD_ROOT="/etc/httpd"
 -D SUEXEC_BIN="/usr/sbin/suexec"
 -D DEFAULT_PIDLOG="run/httpd.pid"
 -D AP_TYPES_CONFIG_FILE="conf/mime.types"
 -D SERVER_CONFIG_FILE="conf/httpd.conf"
`

func TestParseV(t *testing.T) {
	for name, tc := range map[string]struct {
		in, version, confPath string
	}{
		"debian (brief)": {"Server version: Apache/2.4.57 (Debian)\n -D HTTPD_ROOT=\"/etc/apache2\"\n -D SERVER_CONFIG_FILE=\"apache2.conf\"\n",
			"2.4.57", "/etc/apache2/apache2.conf"},
		"debian 12 real":   {debianV, "2.4.68", "/etc/apache2/apache2.conf"},
		"rocky 9 real":     {rockyV, "2.4.62", "/etc/httpd/conf/httpd.conf"},
		"rhel (brief)":     {"Server version: Apache/2.4.57 (Red Hat Enterprise Linux)\n -D HTTPD_ROOT=\"/etc/httpd\"\n -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"\n", "2.4.57", "/etc/httpd/conf/httpd.conf"},
		"no os token":      {"Server version: Apache/2.4.58\n -D SERVER_CONFIG_FILE=\"/etc/httpd.conf\"\n", "2.4.58", "/etc/httpd.conf"},
		"crlf":             {"Server version: Apache/2.4.58 (Unix)\r\n -D SERVER_CONFIG_FILE=\"/etc/httpd.conf\"\r\n", "", ""},
		"cr elsewhere":     {"Server version: Apache/2.4.58 (Unix)\n -D SERVER_CONFIG_FILE=\"/etc/httpd.conf\"\nX\ry\n", "", ""},
		"too large":        {"Server version: Apache/2.4.58 (Unix)\n" + strings.Repeat("x", MaxInput), "", ""},
		"long define":      {"Server version: Apache/2.4.58 (Unix)\n -D SERVER_CONFIG_FILE=\"/" + strings.Repeat("a", 4096) + "\"\n", "2.4.58", ""},
		"absolute file":    {"Server version: Apache/2.4.58 (Unix)\n -D HTTPD_ROOT=\"/opt/x\"\n -D SERVER_CONFIG_FILE=\"/etc/a/httpd.conf\"\n", "2.4.58", "/etc/a/httpd.conf"},
		"root slash":       {"Server version: Apache/2.4.58 (Unix)\n -D HTTPD_ROOT=\"/\"\n -D SERVER_CONFIG_FILE=\"httpd.conf\"\n", "2.4.58", "/httpd.conf"},
		"space in version": {"Server version: Apache/2.4 .57 (Debian)\n", "", ""},
		"trailing junk":    {"Server version: Apache/2.4.57 junk\n", "", ""},
		"version too long": {"Server version: Apache/" + strings.Repeat("1", 41) + " (Debian)\n", "", ""},
		"version 40":       {"Server version: Apache/" + strings.Repeat("1", 40) + " (Debian)\n", strings.Repeat("1", 40), ""},
		"bad character":    {"Server version: Apache/2.4;57 (Debian)\n", "", ""},
		"underscore":       {"Server version: Apache/2.4_57 (Debian)\n", "", ""},
		"not apache":       {"Server version: nginx/1.24.0\n", "", ""},
		"empty version":    {"Server version: Apache/ (Debian)\n", "", ""},
		"first version wins": {"Server version: Apache/2.4.1 (Unix)\nServer version: Apache/9.9.9 (Unix)\n",
			"2.4.1", ""},
		"relative root":   {"Server version: Apache/2.4.58 (Unix)\n -D HTTPD_ROOT=\"etc/httpd\"\n -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"\n", "2.4.58", ""},
		"no root":         {"Server version: Apache/2.4.58 (Unix)\n -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"\n", "2.4.58", ""},
		"no file":         {"Server version: Apache/2.4.58 (Unix)\n -D HTTPD_ROOT=\"/etc/httpd\"\n", "2.4.58", ""},
		"dot dot file":    {"Server version: Apache/2.4.58 (Unix)\n -D HTTPD_ROOT=\"/etc/httpd\"\n -D SERVER_CONFIG_FILE=\"../x.conf\"\n", "2.4.58", ""},
		"unclean root":    {"Server version: Apache/2.4.58 (Unix)\n -D HTTPD_ROOT=\"/etc/httpd/\"\n -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"\n", "2.4.58", ""},
		"space in path":   {"Server version: Apache/2.4.58 (Unix)\n -D SERVER_CONFIG_FILE=\"/etc/a b.conf\"\n", "2.4.58", ""},
		"file is root":    {"Server version: Apache/2.4.58 (Unix)\n -D SERVER_CONFIG_FILE=\"/\"\n", "2.4.58", ""},
		"unquoted define": {"Server version: Apache/2.4.58 (Unix)\n -D SERVER_CONFIG_FILE=/etc/httpd.conf\n", "2.4.58", ""},
		"unclosed define": {"Server version: Apache/2.4.58 (Unix)\n -D SERVER_CONFIG_FILE=\"/etc/httpd.conf\n", "2.4.58", ""},
		"empty":           {"", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			v, c := ParseV([]byte(tc.in))
			assert.Equal(t, tc.version, v, "version")
			assert.Equal(t, tc.confPath, c, "confPath")
		})
	}
}

// debianIncludes is the stdout of "apache2ctl -D DUMP_INCLUDES -t" on Debian 12, trimmed (the
// AH00558 notice of the capture is stderr and does not reach the parser).
const debianIncludes = `Included configuration files:
  (*) /etc/apache2/apache2.conf
    (146) /etc/apache2/mods-enabled/access_compat.load
    (146) /etc/apache2/mods-enabled/ssl.load
    (147) /etc/apache2/mods-enabled/ssl.conf
    (150) /etc/apache2/ports.conf
    (222) /etc/apache2/conf-enabled/security.conf
    (225) /etc/apache2/sites-enabled/000-default.conf
    (225) /etc/apache2/sites-enabled/default-ssl.conf
`

// rockyIncludes is the start of "httpd -D DUMP_INCLUDES -t" on Rocky 9.
const rockyIncludes = `Included configuration files:
  (*) /etc/httpd/conf/httpd.conf
    (358) /etc/httpd/conf.d/ssl.conf
`

func TestParseIncludes(t *testing.T) {
	t.Run("debian 12 real", func(t *testing.T) {
		got, err := ParseIncludes([]byte(debianIncludes))
		require.NoError(t, err)
		require.Len(t, got, 8)
		assert.Equal(t, Included{Path: "/etc/apache2/apache2.conf", Parent: -1, Line: 0}, got[0])
		assert.Equal(t, Included{Path: "/etc/apache2/mods-enabled/access_compat.load", Parent: 0, Line: 146}, got[1])
		assert.Equal(t, Included{Path: "/etc/apache2/sites-enabled/default-ssl.conf", Parent: 0, Line: 225}, got[7])
	})
	t.Run("rocky 9 real", func(t *testing.T) {
		got, err := ParseIncludes([]byte(rockyIncludes))
		require.NoError(t, err)
		assert.Equal(t, []Included{{"/etc/httpd/conf/httpd.conf", -1, 0}, {"/etc/httpd/conf.d/ssl.conf", 0, 358}}, got)
	})
	t.Run("grandchildren and Syntax OK", func(t *testing.T) {
		in := "Included configuration files:\n" +
			"  (*) /etc/apache2/apache2.conf\n" +
			"    (146) /etc/apache2/mods-enabled/ssl.load\n" +
			"    (225) /etc/apache2/sites-enabled/a.conf\n" +
			"      (3) /etc/apache2/snippets/tls.conf\n" +
			"        (9) /etc/apache2/snippets/deep.conf\n" +
			"      (4) /etc/apache2/snippets/other.conf\n" +
			"    (226) /etc/apache2/sites-enabled/b.conf\n" +
			"      (3) /etc/apache2/snippets/tls.conf\n" +
			"Syntax OK\n"
		got, err := ParseIncludes([]byte(in))
		require.NoError(t, err)
		assert.Equal(t, []Included{
			{"/etc/apache2/apache2.conf", -1, 0},
			{"/etc/apache2/mods-enabled/ssl.load", 0, 146},
			{"/etc/apache2/sites-enabled/a.conf", 0, 225},
			{"/etc/apache2/snippets/tls.conf", 2, 3},
			{"/etc/apache2/snippets/deep.conf", 3, 9},
			{"/etc/apache2/snippets/other.conf", 2, 4},
			{"/etc/apache2/sites-enabled/b.conf", 0, 226},
			{"/etc/apache2/snippets/tls.conf", 6, 3}, // listed twice: Apache allows it
		}, got)
	})
	t.Run("root only, no final newline", func(t *testing.T) {
		got, err := ParseIncludes([]byte("Included configuration files:\n  (*) /etc/httpd/conf/httpd.conf"))
		require.NoError(t, err)
		assert.Equal(t, []Included{{"/etc/httpd/conf/httpd.conf", -1, 0}}, got)
	})

	const h = "Included configuration files:\n"
	const root = "  (*) /etc/apache2/apache2.conf\n"
	for name, in := range map[string]string{
		"empty":              "",
		"no header":          root,
		"header late":        "x\n" + h + root,
		"header only":        h,
		"two roots":          h + root + root,
		"child before root":  h + "    (5) /etc/apache2/a.conf\n" + root,
		"numbered root":      h + "  (5) /etc/apache2/apache2.conf\n",
		"root indented":      h + "    (*) /etc/apache2/apache2.conf\n",
		"numbered at depth0": h + root + "  (5) /etc/apache2/a.conf\n",
		"jump of two levels": h + root + "      (5) /etc/apache2/a.conf\n",
		"odd indentation":    h + root + "     (5) /etc/apache2/a.conf\n",
		"no indentation":     h + "(*) /etc/apache2/apache2.conf\n",
		"tab indentation":    h + "\t(*) /etc/apache2/apache2.conf\n",
		"(x)":                h + root + "    (x) /etc/apache2/a.conf\n",
		"(0)":                h + root + "    (0) /etc/apache2/a.conf\n",
		"leading zero":       h + root + "    (05) /etc/apache2/a.conf\n",
		"negative":           h + root + "    (-5) /etc/apache2/a.conf\n",
		"huge number":        h + root + "    (12345678901) /etc/apache2/a.conf\n",
		"empty number":       h + root + "    () /etc/apache2/a.conf\n",
		"no paren":           h + root + "    5 /etc/apache2/a.conf\n",
		"unclosed paren":     h + root + "    (5 /etc/apache2/a.conf\n",
		"two spaces":         h + root + "    (5)  /etc/apache2/a.conf\n",
		"no path":            h + root + "    (5)\n",
		"empty path":         h + root + "    (5) \n",
		"relative path":      h + root + "    (5) conf.d/a.conf\n",
		"relative root":      h + "  (*) apache2.conf\n",
		"unclean path":       h + root + "    (5) /etc/apache2/../a.conf\n",
		"dot segment":        h + root + "    (5) /etc/apache2/./a.conf\n",
		"space in path":      h + root + "    (5) /etc/apache2/a b.conf\n",
		"blank line":         h + root + "\n    (5) /etc/apache2/a.conf\n",
		"stray text":         h + root + "AH00558: apache2: Could not reliably determine\n",
		"crlf":               "Included configuration files:\r\n  (*) /etc/apache2/apache2.conf\r\n",
		"nul":                h + "  (*) /etc/apache2/apache2.conf\x00\n",
		"cr after the tree":  h + root + "Syntax OK\r\n",
		"long path":          h + "  (*) /" + strings.Repeat("a", 4096) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseIncludes([]byte(in))
			assert.ErrorIs(t, err, ErrOutput)
			assert.Nil(t, got)
		})
	}

	t.Run("4097 entries", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(h + root)
		for i := 1; i < MaxFiles; i++ {
			b.WriteString("    (1) /etc/apache2/f" + strconv.Itoa(i) + ".conf\n")
		}
		got, err := ParseIncludes([]byte(b.String()))
		require.NoError(t, err)
		require.Len(t, got, MaxFiles)
		b.WriteString("    (1) /etc/apache2/one-more.conf\n")
		_, err = ParseIncludes([]byte(b.String()))
		assert.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("too deep", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(h + root)
		for k := 1; k <= MaxDepth; k++ {
			b.WriteString(strings.Repeat(" ", 2+2*k) + "(1) /etc/apache2/d" + strconv.Itoa(k) + ".conf\n")
		}
		_, err := ParseIncludes([]byte(b.String()))
		require.NoError(t, err)
		b.WriteString(strings.Repeat(" ", 2+2*(MaxDepth+1)) + "(1) /etc/apache2/deeper.conf\n")
		_, err = ParseIncludes([]byte(b.String()))
		assert.ErrorIs(t, err, ErrTooDeep)
	})
	t.Run("too large", func(t *testing.T) {
		_, err := ParseIncludes(make([]byte, MaxInput+1))
		assert.ErrorIs(t, err, ErrTooLarge)
	})
}

// debianModules is the stdout of "apache2ctl -D DUMP_MODULES -t" on Debian 12, trimmed.
const debianModules = `Loaded Modules:
 core_module (static)
 so_module (static)
 http_module (static)
 unixd_module (static)
 alias_module (shared)
 mpm_event_module (shared)
 socache_shmcb_module (shared)
 ssl_module (shared)
`

func TestParseModules(t *testing.T) {
	t.Run("debian 12 real", func(t *testing.T) {
		m, err := ParseModules([]byte(debianModules))
		require.NoError(t, err)
		assert.Equal(t, map[string]bool{"core_module": true, "so_module": true, "http_module": true, "unixd_module": true}, m.Static)
		assert.Equal(t, map[string]bool{"core_module": true, "so_module": true, "http_module": true, "unixd_module": true,
			"alias_module": true, "mpm_event_module": true, "socache_shmcb_module": true, "ssl_module": true}, m.Loaded)
	})
	t.Run("rocky 9 real", func(t *testing.T) {
		m, err := ParseModules([]byte("Loaded Modules:\n core_module (static)\n ssl_module (shared)"))
		require.NoError(t, err)
		assert.True(t, m.Static["core_module"])
		assert.True(t, m.Loaded["core_module"])
		assert.False(t, m.Static["ssl_module"])
		assert.True(t, m.Loaded["ssl_module"])
	})
	t.Run("header only", func(t *testing.T) {
		m, err := ParseModules([]byte("Loaded Modules:\n"))
		require.NoError(t, err)
		assert.NotNil(t, m.Static)
		assert.NotNil(t, m.Loaded)
		assert.Empty(t, m.Loaded)
	})
	const h = "Loaded Modules:\n"
	for name, in := range map[string]string{
		"empty":           "",
		"no header":       " core_module (static)\n",
		"no space":        h + "core_module (static)\n",
		"two spaces":      h + "  core_module (static)\n",
		"unknown kind":    h + " core_module (builtin)\n",
		"no kind":         h + " core_module\n",
		"extra word":      h + " core_module (static) x\n",
		"empty name":      h + "  (static)\n",
		"bad name":        h + " core$module (static)\n",
		"blank line":      h + "\n ssl_module (shared)\n",
		"syntax ok":       h + " ssl_module (shared)\nSyntax OK\n",
		"crlf":            "Loaded Modules:\r\n ssl_module (shared)\r\n",
		"long name":       h + " " + strings.Repeat("a", 256) + " (shared)\n",
		"stray stderr":    h + "AH00558: apache2: Could not reliably determine\n",
		"cr in a name":    h + " ssl\r_module (shared)\n",
		"name with space": h + " a b (shared)\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseModules([]byte(in))
			assert.ErrorIs(t, err, ErrOutput)
		})
	}
	t.Run("too large", func(t *testing.T) {
		_, err := ParseModules(make([]byte, MaxInput+1))
		assert.ErrorIs(t, err, ErrTooLarge)
	})
}

// debianRunCfg is the stdout of "apache2ctl -D DUMP_RUN_CFG -t" on Debian 12.
const debianRunCfg = `ServerRoot: "/etc/apache2"
Main DocumentRoot: "/var/www/html"
Main ErrorLog: "/var/log/apache2/error.log"
Mutex ssl-cache: using_defaults
Mutex default: dir="/var/run/apache2/" mechanism=default
Mutex watchdog-callback: using_defaults
PidFile: "/var/run/apache2/apache2.pid"
Define: DUMP_RUN_CFG
User: name="www-data" id=33
Group: name="www-data" id=33
`

func TestParseRunConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want RunConfig
	}{
		"debian 12 real": {debianRunCfg, RunConfig{ServerRoot: "/etc/apache2", Defines: map[string]string{}}},
		"rocky 9 real": {"ServerRoot: \"/etc/httpd\"\nMain DocumentRoot: \"/var/www/html\"\nMutex default: dir=\"/run/httpd/\" mechanism=default \n" +
			"PidFile: \"/run/httpd/httpd.pid\"\nDefine: DUMP_RUN_CFG\nUser: name=\"apache\" id=48\nGroup: name=\"apache\" id=48\n",
			RunConfig{ServerRoot: "/etc/httpd", Defines: map[string]string{}}},
		"defines": {"ServerRoot: \"/etc/httpd\"\nDefine: DUMP_RUN_CFG\nDefine: FOO\nDefine: CERTS=/etc/ssl/a b\nDefine: EMPTY=\nDefine: EQ=a=b\n",
			RunConfig{ServerRoot: "/etc/httpd", Defines: map[string]string{"FOO": "", "CERTS": "/etc/ssl/a b", "EMPTY": "", "EQ": "a=b"}}},
		"other dump defines dropped": {"Define: DUMP_INCLUDES\nDefine: DUMP_MODULES\nDefine: DUMP_VHOSTS\nDefine: DUMP_X=1\nDefine: SSL\n",
			RunConfig{Defines: map[string]string{"SSL": ""}}},
		"later define wins":   {"Define: A=1\nDefine: A=2\n", RunConfig{Defines: map[string]string{"A": "2"}}},
		"no server root":      {"Define: X\n", RunConfig{Defines: map[string]string{"X": ""}}},
		"trailing slash":      {"ServerRoot: \"/etc/httpd/\"\n", RunConfig{ServerRoot: "/etc/httpd", Defines: map[string]string{}}},
		"server root is /":    {"ServerRoot: \"/\"\n", RunConfig{ServerRoot: "/", Defines: map[string]string{}}},
		"server root is //":   {"ServerRoot: \"//\"\n", RunConfig{ServerRoot: "/", Defines: map[string]string{}}},
		"other lines ignored": {"Whatever: x\n\nAH00558: y\n", RunConfig{Defines: map[string]string{}}},
		"empty":               {"", RunConfig{Defines: map[string]string{}}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseRunConfig([]byte(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	for name, in := range map[string]string{
		"two server roots":      "ServerRoot: \"/etc/httpd\"\nServerRoot: \"/etc/x\"\n",
		"unquoted root":         "ServerRoot: /etc/httpd\n",
		"relative root":         "ServerRoot: \"etc/httpd\"\n",
		"empty root":            "ServerRoot: \"\"\n",
		"unclean root":          "ServerRoot: \"/etc/../httpd\"\n",
		"root with space":       "ServerRoot: \"/etc/a b\"\n",
		"empty define name":     "Define: \n",
		"define name equals":    "Define: =x\n",
		"define name space":     "Define: A B\n",
		"crlf":                  "ServerRoot: \"/etc/httpd\"\r\nDefine: A=b\r\n",
		"cr in a value":         "Define: A=b\rc\n",
		"cr in an ignored line": "Main DocumentRoot: \"/var/www\r\"\n",
		"long root":             "ServerRoot: \"/" + strings.Repeat("a", 4096) + "\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRunConfig([]byte(in))
			assert.ErrorIs(t, err, ErrOutput)
		})
	}
	t.Run("too large", func(t *testing.T) {
		_, err := ParseRunConfig(make([]byte, MaxInput+1))
		assert.ErrorIs(t, err, ErrTooLarge)
	})
}

func TestModuleName(t *testing.T) {
	for in, want := range map[string]string{
		"mod_ssl.c":          "ssl_module",
		"ssl_module":         "ssl_module",
		"mod_proxy_http.c":   "proxy_http_module",
		"mod_authz_core.c":   "authz_core_module",
		"core.c":             "core_module",
		"http_core.c":        "http_module",
		"prefork.c":          "mpm_prefork_module",
		"worker.c":           "mpm_worker_module",
		"event.c":            "mpm_event_module",
		"mpm_event_module":   "mpm_event_module",
		"php7_module":        "php7_module",
		"mod_Rewrite.c":      "Rewrite_module",
		"mod_ssl_module":     "mod_ssl_module",
		"weird":              "",
		"":                   "",
		"_module":            "",
		"mod_.c":             "",
		"mod_ssl":            "",
		"ssl.c":              "",
		"mod_a b.c":          "",
		"mod_ssl.c ":         "",
		"ssl-module":         "",
		"a.b_module":         "",
		"mod_../x.c":         "",
		"unixd.c":            "",
		"!ssl_module":        "",
		"mod_ssl.c\x00":      "",
		"mod_ssl.cpp":        "",
		"mod_ssl.c.c":        "",
		"MOD_SSL.C":          "",
		"ssl_MODULE":         "",
		"x_module_module":    "x_module_module",
		"mod_x_module.c":     "x_module_module",
		"mod_mod_ssl.c":      "mod_ssl_module",
		"mod_ç.c":            "",
		"core_module":        "core_module",
		"http_core_module.c": "",
	} {
		t.Run(in, func(t *testing.T) {
			got, ok := ModuleName(in)
			assert.Equal(t, want, got)
			assert.Equal(t, want != "", ok)
		})
	}
}

// The error values are distinct and named after the package.
func TestErrors(t *testing.T) {
	all := []error{ErrTooLarge, ErrLineTooLong, ErrTooComplex, ErrTooDeep, ErrSyntax, ErrNUL, ErrOutput, ErrIncludeMismatch}
	for i, a := range all {
		assert.True(t, strings.HasPrefix(a.Error(), "apacheconf: "), a.Error())
		for j, b := range all {
			assert.Equal(t, i == j, errors.Is(a, b))
		}
	}
	assert.Equal(t, "variable", ReasonVariable)
	assert.Equal(t, "conditional", ReasonConditional)
	assert.Equal(t, "path_not_allowed", ReasonPathNotAllowed)
	assert.Equal(t, "config_file_writable", ReasonConfigFileWritable)
}

func TestOutputCaps(t *testing.T) {
	var b strings.Builder
	b.WriteString("Loaded Modules:\n")
	for i := range MaxModules {
		b.WriteString(" m" + strconv.Itoa(i) + "_module (shared)\n")
	}
	m, err := ParseModules([]byte(b.String()))
	require.NoError(t, err)
	assert.Len(t, m.Loaded, MaxModules)
	b.WriteString(" one_more_module (shared)\n")
	_, err = ParseModules([]byte(b.String()))
	assert.ErrorIs(t, err, ErrTooComplex)

	b.Reset()
	for i := range MaxDefines {
		b.WriteString("Define: D" + strconv.Itoa(i) + "=v\n")
	}
	rc, err := ParseRunConfig([]byte(b.String()))
	require.NoError(t, err)
	assert.Len(t, rc.Defines, MaxDefines)
	b.WriteString("Define: DUMP_RUN_CFG\n") // DUMP_* lines count too
	_, err = ParseRunConfig([]byte(b.String()))
	assert.ErrorIs(t, err, ErrTooComplex)
}

// allocated is the number of bytes f allocates.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// The parsers run in the root helper on up to 20 MiB of hostile output: they never split it into
// strings, so what they allocate stays far below the input size whatever its shape.
func TestOutputAllocations(t *testing.T) {
	newlines := append([]byte("Included configuration files:\n"), bytes.Repeat([]byte("\n"), MaxInput-64)...)
	syntaxOK := append([]byte("Included configuration files:\n  (*) /etc/a.conf\n"), bytes.Repeat([]byte("Syntax OK\n"), MaxInput/10-8)...)
	modules := append([]byte("Loaded Modules:\n"), bytes.Repeat([]byte(" a_module (shared)\n"), (MaxInput-64)/19)...)
	ignored := bytes.Repeat([]byte("x\n"), MaxInput/2)
	for name, tc := range map[string]struct {
		in    []byte
		parse func([]byte)
	}{
		"includes: newlines":     {newlines, func(b []byte) { _, _ = ParseIncludes(b) }},
		"includes: Syntax OK":    {syntaxOK, func(b []byte) { _, _ = ParseIncludes(b) }},
		"modules: many lines":    {modules, func(b []byte) { _, _ = ParseModules(b) }},
		"run config: ignored":    {ignored, func(b []byte) { _, _ = ParseRunConfig(b) }},
		"-V: ignored":            {ignored, func(b []byte) { _, _ = ParseV(b) }},
		"modules: one long line": {append([]byte("Loaded Modules:\n "), bytes.Repeat([]byte("a"), MaxInput-64)...), func(b []byte) { _, _ = ParseModules(b) }},
	} {
		t.Run(name, func(t *testing.T) {
			got := allocated(func() { tc.parse(tc.in) })
			t.Logf("%d bytes allocated for %d bytes of input", got, len(tc.in))
			assert.Less(t, got, uint64(1<<20), "allocations must not grow with the input")
		})
	}
}
