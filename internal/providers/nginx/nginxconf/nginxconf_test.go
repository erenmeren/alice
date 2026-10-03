package nginxconf

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "test", "testdata", "nginx", name))
	require.NoError(t, err)
	return b
}

func parse(t *testing.T, name string) Config {
	t.Helper()
	c, err := Parse(fixture(t, name), "/etc/nginx")
	require.NoError(t, err)
	return c
}

func TestSingle(t *testing.T) {
	c := parse(t, "single.conf")
	require.Len(t, c.Servers, 1, "the port-80 redirect has no SSL listen")
	s := c.Servers[0]
	assert.Equal(t, "/etc/nginx/conf.d/www.conf", s.File)
	assert.Equal(t, 1, s.Line)
	assert.Equal(t, []string{"www.example.test", "example.test"}, s.Names)
	assert.Equal(t, []Listen{{Port: 443, SSL: true}, {Addr: "::", Port: 443, SSL: true}}, SSLListens(s))
	assert.Equal(t, []Pair{{Cert: "/etc/nginx/ssl/www.crt", Key: "/etc/nginx/ssl/www.key",
		CertRaw: "/etc/nginx/ssl/www.crt", KeyRaw: "/etc/nginx/ssl/www.key",
		CertFile: "/etc/nginx/conf.d/www.conf", KeyFile: "/etc/nginx/conf.d/www.conf"}}, s.Pairs)
	assert.Equal(t, []string{"/etc/nginx/conf.d/www.conf"}, s.Files)
	assert.Equal(t, []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/www.conf"}, c.Files)
	assert.True(t, c.HasPair("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"))
	assert.False(t, c.HasPair("/etc/nginx/ssl/www.crt", "/etc/shadow"))
	assert.False(t, c.HasPair("/etc/nginx/ssl/www.key", "/etc/nginx/ssl/www.crt"), "order matters")
}

func TestFixtureTable(t *testing.T) {
	for _, tc := range []struct {
		file        string
		servers     int
		certPaths   []string
		unsupported []string // Unsupported of every pair, in order
		warnings    []string
	}{
		{"letsencrypt.conf", 1, []string{"/etc/letsencrypt/live/shop.example.test/fullchain.pem"}, []string{""}, nil},
		{"whitespace.conf", 1, []string{"/etc/nginx/ssl/q.crt"}, []string{""}, nil},
		{"many.conf", 3, []string{"/etc/ssl/certs/a.pem", "/etc/ssl/certs/b.pem", "/etc/ssl/certs/c.pem"}, []string{"", "", ""}, nil},
		{"includes.conf", 2, []string{"/etc/nginx/ssl/one.crt", "/etc/nginx/ssl/two.crt"}, []string{"", ""}, nil},
		{"variables.conf", 1, nil, []string{ReasonVariable}, nil},
		{"stream.conf", 2, []string{"/etc/nginx/ssl/www.crt"}, []string{"", ReasonStream}, []string{"stream_tls"}},
		{"inherited.conf", 2, []string{"/etc/nginx/ssl/all.crt", "/etc/nginx/ssl/b.crt"}, []string{"", ""}, nil},
		{"dual.conf", 1, []string{"/etc/nginx/ssl/rsa.crt", "/etc/nginx/ssl/ec.crt"}, []string{"", ""}, nil},
		{"shared.conf", 3, []string{"/etc/nginx/ssl/shared.crt"}, []string{"", "", ""}, nil},
		{"relative.conf", 1, []string{"/etc/nginx/ssl/rel.crt"}, []string{""}, nil},
		{"password.conf", 1, nil, []string{ReasonPasswordFile}, nil},
		{"combined.conf", 4, nil, []string{ReasonCombinedFile, ReasonEngineKey, ReasonDataValue, ReasonKeyMissing}, nil},
		{"space-path.conf", 1, nil, []string{ReasonPathNotAllowed}, nil},
	} {
		t.Run(tc.file, func(t *testing.T) {
			c := parse(t, tc.file)
			assert.Len(t, c.Servers, tc.servers)
			assert.Equal(t, tc.certPaths, c.CertPaths())
			var reasons []string
			for _, s := range c.Servers {
				for _, p := range s.Pairs {
					reasons = append(reasons, p.Unsupported)
				}
			}
			assert.Equal(t, tc.unsupported, reasons)
			assert.Equal(t, tc.warnings, c.Warnings)
		})
	}
}

func TestInheritedPairIsMarked(t *testing.T) {
	c := parse(t, "inherited.conf")
	assert.True(t, c.Servers[0].Pairs[0].Inherited)
	assert.False(t, c.Servers[1].Pairs[0].Inherited)
}

func TestListenForms(t *testing.T) {
	c := parse(t, "listen-forms.conf")
	var got []Listen
	for _, s := range c.Servers {
		got = append(got, SSLListens(s)...)
	}
	assert.Equal(t, []Listen{
		{Port: 443, SSL: true}, {Addr: "10.0.0.5", Port: 8443, SSL: true}, {Addr: "::1", Port: 9443, SSL: true},
		{Port: 4443, SSL: true}, {Addr: "localhost", Port: 5443, SSL: true}, {Port: 7443, SSL: true},
		{Port: 6443, SSL: true, DefaultServer: true},
	}, got, "unix sockets and invalid ports are ignored; ssl on makes every listen SSL")
}

func TestServerLinesAreWithinTheirFile(t *testing.T) {
	c := parse(t, "includes.conf")
	assert.Equal(t, "/etc/nginx/conf.d/one.conf", c.Servers[0].File)
	assert.Equal(t, "/etc/nginx/conf.d/two.conf", c.Servers[1].File)
	assert.Equal(t, 1, c.Servers[1].Line)
}

func TestLimitsAndSyntax(t *testing.T) {
	for _, tc := range []struct {
		in  string
		err error
	}{
		{strings.Repeat("a", MaxInput+1), ErrTooLarge},
		{"http {" + strings.Repeat("x {", MaxDepth) + strings.Repeat("}", MaxDepth) + "}", ErrTooDeep},
		{"http { server { listen 443 ssl; ", ErrSyntax},
		{"http { } }", ErrSyntax},
		{`http { server_name "unterminated; }`, ErrSyntax},
		{"http { listen 443 ssl }", ErrSyntax},
		{"# x\n" + strings.Repeat("a", MaxLine+1) + ";", ErrLineTooLong},
	} {
		_, err := Parse([]byte(tc.in), "/etc/nginx")
		assert.True(t, errors.Is(err, tc.err), "%.40q: %v", tc.in, err)
	}
	c, err := Parse([]byte(""), "/etc/nginx")
	require.NoError(t, err)
	assert.Empty(t, c.Servers)
}

func TestEscapesAndQuotedSemicolons(t *testing.T) {
	c, err := Parse([]byte(`http { server { listen 443 ssl; server_name "a;b" 'c\'d' e\;f;
ssl_certificate /etc/nginx/ssl/x.crt; ssl_certificate_key /etc/nginx/ssl/x.key; } }`), "/etc/nginx")
	require.NoError(t, err)
	assert.Equal(t, []string{"a;b", "c'd", "e;f"}, c.Servers[0].Names)
}

func TestRelativeWithoutConfDirIsNotAllowed(t *testing.T) {
	c, err := Parse(fixture(t, "relative.conf"), "")
	require.NoError(t, err)
	assert.Equal(t, ReasonPathNotAllowed, c.Servers[0].Pairs[0].Unsupported)
}

// parseInline parses in and returns the result, failing the test on a parse error.
func parseInline(t *testing.T, in string) Config {
	t.Helper()
	c, err := Parse([]byte(in), "/etc/nginx")
	require.NoError(t, err)
	return c
}

const okServer = "listen 443 ssl; ssl_certificate /etc/nginx/ssl/x.crt; ssl_certificate_key /etc/nginx/ssl/x.key;"

func TestRobustnessErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		in  string
		err error
	}{
		"NUL byte":                   {"http { server { " + okServer + " } }\x00", ErrNUL},
		"unterminated single quote":  {"http { server_name 'abc; }", ErrSyntax},
		"unterminated brace":         {"http {", ErrSyntax},
		"stray closing brace":        {"}", ErrSyntax},
		"quote glued to a word":      {`http { server_name "a"b; }`, ErrSyntax},
		"block without a name":       {"{ }", ErrSyntax},
		"missing semicolon at end":   {"http { x }", ErrSyntax},
		"missing semicolon at EOF":   {"worker_processes 1", ErrSyntax},
		"overlong line":              {strings.Repeat(" ", MaxLine+1), ErrLineTooLong},
		"overlong quoted token":      {`a "` + strings.Repeat("x\n", MaxLine/2+1) + `";`, ErrLineTooLong},
		"include loop":               {"# configuration file /a:\ninclude /b;\n# configuration file /b:\ninclude /a;\n", ErrIncludeLoop},
		"too many tokens":            {strings.Repeat(";\n", MaxTokens+1), ErrTooComplex},
		"too many files":             {manyFiles(MaxFiles + 1), ErrTooComplex},
		"same file named twice":      {"# configuration file /a:\n# configuration file /a:\n", ErrDuplicateFile},
		"deep nesting through files": {deepIncludes(), ErrTooDeep},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in), "/etc/nginx")
			assert.ErrorIs(t, err, tc.err)
		})
	}
}

// nginx prints a file reached under two spellings twice; names are compared as raw text.
func TestTheSameFileUnderTwoSpellingsIsNotADuplicate(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { include conf.d/a.conf; include ./conf.d/a.conf; }\n" +
		"# configuration file /etc/nginx/conf.d/a.conf:\nserver { " + okServer + " }\n" +
		"# configuration file /etc/nginx/./conf.d/a.conf:\nserver { " + okServer + " }\n"
	c := parseInline(t, in)
	assert.Len(t, c.Servers, 2)
	assert.Equal(t, []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/a.conf", "/etc/nginx/./conf.d/a.conf"}, c.Files)
	_, err := Parse([]byte("# configuration file /a/b:\n# configuration file /a//b:\n"), "/etc/nginx")
	assert.NoError(t, err)
}

// S1: the files that hold a server block, everything spliced into it, and each pair's directives
// are reported, so the helper can refuse pairs a non-root user could have written.
func TestDirectiveFilesAreReported(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\n" +
		"http { ssl_certificate_key /etc/nginx/ssl/top.key; include /etc/nginx/sites/*; }\n" +
		"# configuration file /etc/nginx/sites/a:\n" +
		"server { listen 443 ssl; include /etc/nginx/snippets/tls.conf; ssl_certificate /etc/nginx/ssl/a2.crt; }\n" +
		"# configuration file /etc/nginx/sites/b:\n" +
		"server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/b.crt; }\n" +
		"# configuration file /etc/nginx/snippets/tls.conf:\n" +
		"ssl_certificate /etc/nginx/ssl/a.crt;\nssl_certificate_key /etc/nginx/ssl/a.key;\n"
	c := parseInline(t, in)
	require.Len(t, c.Servers, 2)
	a, b := c.Servers[0], c.Servers[1]
	assert.Equal(t, []string{"/etc/nginx/sites/a", "/etc/nginx/snippets/tls.conf"}, a.Files)
	assert.Equal(t, "/etc/nginx/snippets/tls.conf", a.Pairs[0].CertFile)
	assert.Equal(t, "/etc/nginx/snippets/tls.conf", a.Pairs[0].KeyFile)
	assert.Equal(t, "/etc/nginx/sites/a", a.Pairs[1].CertFile)
	assert.Equal(t, "", a.Pairs[1].KeyFile, "no second key directive")
	assert.Equal(t, []string{"/etc/nginx/sites/b"}, b.Files)
	assert.Equal(t, "/etc/nginx/sites/b", b.Pairs[0].CertFile)
	assert.Equal(t, "/etc/nginx/nginx.conf", b.Pairs[0].KeyFile, "inherited from the http block")
	assert.True(t, b.Pairs[0].Inherited)
}

func manyFiles(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("# configuration file /m" + strconv.Itoa(i) + ":\n")
	}
	return b.String()
}

// deepIncludes builds MaxDepth+2 files that each open one block and include the next one.
func deepIncludes() string {
	var b strings.Builder
	for i := 0; i <= MaxDepth+1; i++ {
		b.WriteString("# configuration file /d" + strconv.Itoa(i) + ":\n")
		if i == 0 {
			b.WriteString("http ")
		} else {
			b.WriteString("server ")
		}
		b.WriteString("{ include /d" + strconv.Itoa(i+1) + "; }\n")
	}
	return b.String()
}

func TestIncludeFanOutIsBounded(t *testing.T) {
	// File i includes file i+1 twenty times: 20^depth nodes if expanded without a budget.
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("# configuration file /f" + strconv.Itoa(i) + ":\n")
		b.WriteString(strings.Repeat("include /f"+strconv.Itoa(i+1)+";\n", 20))
	}
	_, err := Parse([]byte(b.String()), "/etc/nginx")
	assert.ErrorIs(t, err, ErrTooComplex)
}

func TestEmptyAndCommentOnlyInput(t *testing.T) {
	for _, in := range []string{"", "\n\n", "# only a comment", "# unterminated comment {\"", "   \t\r\n"} {
		c, err := Parse([]byte(in), "/etc/nginx")
		require.NoError(t, err, "%q", in)
		assert.Empty(t, c.Servers)
	}
}

func TestCRLFLineEndings(t *testing.T) {
	in := strings.ReplaceAll(string(fixture(t, "includes.conf")), "\n", "\r\n")
	c, err := Parse([]byte(in), "/etc/nginx")
	require.NoError(t, err)
	require.Len(t, c.Servers, 2)
	assert.Equal(t, "/etc/nginx/conf.d/one.conf", c.Servers[0].File, "a marker line ending in CRLF is still a marker")
	assert.Equal(t, []string{"/etc/nginx/ssl/one.crt", "/etc/nginx/ssl/two.crt"}, c.CertPaths())
}

func TestInvalidUTF8IsReplacedAndNeverReachesPaths(t *testing.T) {
	c := parseInline(t, "http { server { listen 443 ssl; server_name a\xff\xfeb;\n"+
		"ssl_certificate /etc/nginx/ssl/\xffx.crt; ssl_certificate_key /etc/nginx/ssl/x.key; } }")
	require.Len(t, c.Servers, 1)
	assert.Equal(t, []string{"a\uFFFDb"}, c.Servers[0].Names)
	assert.Equal(t, ReasonPathNotAllowed, c.Servers[0].Pairs[0].Unsupported)
	assert.Empty(t, c.CertPaths())
}

func TestHashInsideAWordIsNotAComment(t *testing.T) {
	// nginx starts a comment only at the start of a token, so this path really contains '#'.
	c := parseInline(t, "http { server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/a#b.crt; ssl_certificate_key /etc/nginx/ssl/a.key; } }")
	require.Len(t, c.Servers, 1)
	assert.Equal(t, "/etc/nginx/ssl/a#b.crt", c.Servers[0].Pairs[0].CertRaw)
	assert.Equal(t, ReasonPathNotAllowed, c.Servers[0].Pairs[0].Unsupported)
}

func TestBackslashDoesNotHideACharacterFromThePath(t *testing.T) {
	// nginx keeps the backslash in "x\.crt", so the file nginx opens is not /etc/nginx/ssl/x.crt.
	c := parseInline(t, `http { server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/x\.crt; ssl_certificate_key /etc/nginx/ssl/x.key; } }`)
	require.Len(t, c.Servers, 1)
	assert.Equal(t, `/etc/nginx/ssl/x\.crt`, c.Servers[0].Pairs[0].CertRaw)
	assert.Equal(t, ReasonPathNotAllowed, c.Servers[0].Pairs[0].Unsupported)
	assert.Empty(t, c.CertPaths())
}

func TestVariablesAndBraceWordsAreNotBlocks(t *testing.T) {
	c := parseInline(t, `http { server { listen 443 ssl; set $x ${y}z; ssl_certificate /etc/nginx/ssl/${host}.crt; ssl_certificate_key "/etc/nginx/ssl/$host.key"; } }`)
	require.Len(t, c.Servers, 1)
	assert.Equal(t, ReasonVariable, c.Servers[0].Pairs[0].Unsupported)
	assert.Equal(t, "/etc/nginx/ssl/${host}.crt", c.Servers[0].Pairs[0].CertRaw)
}

func TestQuotedValuesWithEscapesAndSpaces(t *testing.T) {
	c := parseInline(t, `http { server { listen 443 ssl; server_name "a \"b\" c" 'd\\e' "tab\there"; `+
		`ssl_certificate "/etc/nginx/my certs/a.crt"; ssl_certificate_key "/etc/nginx/ssl/a.key"; } }`)
	require.Len(t, c.Servers, 1)
	assert.Equal(t, []string{`a "b" c`, `d\e`, "tab\there"}, c.Servers[0].Names)
	assert.Equal(t, ReasonPathNotAllowed, c.Servers[0].Pairs[0].Unsupported)
}

func TestIncludedSnippetSuppliesTheCertificate(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { server { listen 443 ssl; include snippets/tls.conf; } }\n" +
		"# configuration file /etc/nginx/snippets/tls.conf:\nssl_certificate /etc/nginx/ssl/s.crt;\nssl_certificate_key /etc/nginx/ssl/s.key;\n"
	c := parseInline(t, in)
	require.Len(t, c.Servers, 1)
	assert.True(t, c.HasPair("/etc/nginx/ssl/s.crt", "/etc/nginx/ssl/s.key"))
}

func TestFilesThatNothingIncludesAreIgnored(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { }\n" +
		"# configuration file /etc/nginx/orphan.conf:\nserver { " + okServer + " }\n"
	assert.Empty(t, parseInline(t, in).Servers, "a top-level server block outside http is not part of the configuration")
}

func TestIncludeGlobAndRelativeWithoutConfDir(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { include conf.d/*.conf; include /etc/nginx/x?.conf; }\n" +
		"# configuration file /etc/nginx/conf.d/a.conf:\nserver { " + okServer + " }\n" +
		"# configuration file /etc/nginx/xy.conf:\nserver { listen 8443 ssl; ssl_certificate /etc/nginx/ssl/y.crt; ssl_certificate_key /etc/nginx/ssl/y.key; }\n" +
		"# configuration file /etc/nginx/notmatched.conf:\nserver { " + okServer + " }\n"
	assert.Len(t, parseInline(t, in).Servers, 2)
	c, err := Parse([]byte(in), "")
	require.NoError(t, err)
	assert.Len(t, c.Servers, 1, "without a conf dir only the absolute include is resolved")
}

func TestTheSameFileIncludedTwiceIsFine(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { include /s; include /s; }\n# configuration file /s:\nserver { " + okServer + " }\n"
	assert.Len(t, parseInline(t, in).Servers, 2)
}

func TestMarkerOnlyCountsAtLineStart(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { server { " + okServer + " } }\n  # configuration file /evil:\n"
	c := parseInline(t, in)
	assert.Equal(t, []string{"/etc/nginx/nginx.conf"}, c.Files)
}

func TestMultilineQuotedStringKeepsLineNumbers(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp {\nadd_header X \"a\nb\nc\";\nserver { " + okServer + " } }\n"
	assert.Equal(t, 5, parseInline(t, in).Servers[0].Line)
}

func TestHostileSizesFinishQuickly(t *testing.T) {
	for name, in := range map[string]string{
		"semicolons":      strings.Repeat(";\n", MaxInput/2),
		"open braces":     strings.Repeat("a{\n", MaxInput/3),
		"short words":     strings.Repeat("a\n", MaxInput/2),
		"markers":         manyFiles(MaxFiles * 2),
		"empty blocks":    strings.Repeat("a{}", MaxInput/3),
		"include chain":   includeChain(),
		"quoted garbage":  strings.Repeat(`"a" `, MaxInput/4),
		"lua braces":      "content_by_lua_block " + strings.Repeat("{ ", MaxInput/2),
		"include storm":   includeStorm(),
		"glob everything": globStorm(),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := Parse([]byte(in), "/etc/nginx")
			assert.Error(t, err)
			assert.Less(t, time.Since(start), 2*time.Second)
		})
	}
}

// includeChain is 2000 files that include the next one, the last with 200k wildcard includes
// that each match 2000 empty files.
func includeChain() string {
	var b strings.Builder
	for i := 0; i < 2000; i++ {
		b.WriteString("# configuration file /c" + strconv.Itoa(i) + ":\n")
		if i < 1999 {
			b.WriteString("include /c" + strconv.Itoa(i+1) + ";\n")
		} else {
			b.WriteString(strings.Repeat("include /l*;\n", 200000))
		}
	}
	for i := 0; i < 2000; i++ {
		b.WriteString("# configuration file /l" + strconv.Itoa(i) + ":\n")
	}
	return b.String()
}

// includeStorm includes one small file a million times.
func includeStorm() string {
	return "# configuration file /a:\n" + strings.Repeat("include /b;", 500000) + "\n# configuration file /b:\nlisten 1;\n"
}

// globStorm has many files and a few wildcard includes with long patterns.
func globStorm() string {
	var b strings.Builder
	b.WriteString("# configuration file /a:\n" + strings.Repeat("include /*/*/*/*/*/*/*/*/*/*/*/*.conf;\n", 20000))
	for i := 0; i < MaxFiles-1; i++ {
		b.WriteString("# configuration file /d/d/d/d/d/d/d/d/d/d/d/" + strconv.Itoa(i) + ".conf:\n")
	}
	return b.String()
}

// The memory one dump can cost is bounded whatever its shape: dropped directives are counted, not
// stored, a kept directive has at most maxArgs arguments and the dump at most maxNodes kept ones.
func TestAllocationCeiling(t *testing.T) {
	for name, tc := range map[string]struct {
		in  string
		err error
	}{
		// 1 MB: /a includes /b twice, /b is 500000 directives nobody reads.
		"many dropped directives": {"# configuration file /a:\nhttp { include /b; include /b; }\n# configuration file /b:\n" +
			strings.Repeat("a;", 500000) + "\n", nil},
		// One directive nobody reads with a million arguments.
		"one long dropped directive": {"http { add_header" + strings.Repeat("\n x", MaxTokens-10) + "; }", nil},
		// One kept directive with a million arguments.
		"one long server_name": {"http { server { server_name" + strings.Repeat("\n x", MaxTokens-10) + "; } }", ErrTooComplex},
		// As many kept directives as the token budget allows.
		"340k listen lines": {"http { server {\n" + strings.Repeat("listen 1;\n", (MaxTokens-10)/3) + "} }", ErrTooComplex},
	} {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			c, err := Parse([]byte(tc.in), "/etc/nginx")
			runtime.ReadMemStats(&after)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				assert.Empty(t, c.Servers)
			}
			t.Logf("allocated %d MiB", (after.TotalAlloc-before.TotalAlloc)>>20)
			assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(64<<20))
		})
	}
}

func TestKeptDirectiveArgumentsAreCapped(t *testing.T) {
	names := func(n int) string {
		return "http { server { listen 443 ssl; server_name" + strings.Repeat(" a.example", n) + "; " +
			"ssl_certificate /etc/nginx/ssl/x.crt; ssl_certificate_key /etc/nginx/ssl/x.key; } }"
	}
	c := parseInline(t, names(maxArgs))
	require.Len(t, c.Servers, 1)
	assert.Len(t, c.Servers[0].Names, maxArgs)
	_, err := Parse([]byte(names(maxArgs+1)), "/etc/nginx")
	assert.ErrorIs(t, err, ErrTooComplex)
	_, err = Parse([]byte("http { add_header"+strings.Repeat(" x", maxArgs*2)+"; }"), "/etc/nginx")
	assert.NoError(t, err, "a directive nobody reads may be long")
}

func TestForgedMarkerCannotChangeAnotherServersPairs(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\n" +
		"http { include /etc/nginx/sites-enabled/*; server { listen 443 ssl; server_name bank; include /etc/nginx/snippets/bank-tls.conf; } }\n" +
		"# configuration file /etc/nginx/sites-enabled/evil:\n" +
		"server { listen 8443 ssl; ssl_certificate /etc/nginx/ssl/own.crt; ssl_certificate_key /etc/nginx/ssl/own.key; }\n" +
		"# configuration file /etc/nginx/snippets/bank-tls.conf:\n" +
		"ssl_certificate /etc/nginx/ssl/evil2.crt;\n" +
		"# configuration file /etc/nginx/snippets/bank-tls.conf:\n" +
		"ssl_certificate /etc/nginx/ssl/bank.crt;\nssl_certificate_key /etc/nginx/ssl/bank.key;\n"
	_, err := Parse([]byte(in), "/etc/nginx")
	assert.ErrorIs(t, err, ErrDuplicateFile)
}

func TestSectionsExposeNamesAndBytes(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { include /s; }\n# configuration file /s:\nlisten 1;\n"
	c := parseInline(t, in)
	require.Len(t, c.Sections, 2)
	assert.Equal(t, "/etc/nginx/nginx.conf", c.Sections[0].File)
	assert.Equal(t, "http { include /s; }\n", string(c.Sections[0].Body))
	assert.Equal(t, "/s", c.Sections[1].File)
	assert.Equal(t, "listen 1;\n", string(c.Sections[1].Body))
}

func TestGlobFollowsGlob3(t *testing.T) {
	srv := func(n string) string {
		return "server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/" + n + ".crt; ssl_certificate_key /etc/nginx/ssl/" + n + ".key; }\n"
	}
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/sites/*; include /etc/nginx/deep/*.conf; }\n" +
		"# configuration file /etc/nginx/sites/.hidden:\n" + srv("hidden") +
		"# configuration file /etc/nginx/sites/vis:\n" + srv("vis") +
		"# configuration file /etc/nginx/deep/x/y.conf:\n" + srv("deep")
	c := parseInline(t, in)
	assert.Equal(t, []string{"/etc/nginx/ssl/vis.crt"}, c.CertPaths(), "* never matches a leading dot nor a slash")
	in = "# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/sites/.h*; }\n# configuration file /etc/nginx/sites/.hidden:\n" + srv("hidden")
	assert.Equal(t, []string{"/etc/nginx/ssl/hidden.crt"}, parseInline(t, in).CertPaths(), "a literal dot matches")
}

func TestGlobMatchesAreSortedByName(t *testing.T) {
	srv := func(n string) string {
		return "server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/" + n + ".crt; ssl_certificate_key /etc/nginx/ssl/" + n + ".key; }\n"
	}
	// z.conf is dumped first because an earlier include named it; the glob still yields a, z.
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/c/z.conf; include /etc/nginx/c/*.conf; }\n" +
		"# configuration file /etc/nginx/c/z.conf:\n" + srv("z") +
		"# configuration file /etc/nginx/c/a.conf:\n" + srv("a")
	assert.Equal(t, []string{"/etc/nginx/ssl/z.crt", "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/z.crt"}, certPathsInOrder(parseInline(t, in)))
	in = "# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/c/*.conf; }\n" +
		"# configuration file /etc/nginx/c/z.conf:\n" + srv("z") +
		"# configuration file /etc/nginx/c/a.conf:\n" + srv("a")
	assert.Equal(t, []string{"/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/z.crt"}, certPathsInOrder(parseInline(t, in)))
}

func certPathsInOrder(c Config) []string {
	var out []string
	for _, s := range c.Servers {
		for _, p := range s.Pairs {
			out = append(out, p.Cert)
		}
	}
	return out
}

func TestIncludePatternsAreComparedAsRawBytes(t *testing.T) {
	in := "# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/\xff.conf; }\n# configuration file /etc/nginx/\xfe.conf:\nserver { " + okServer + " }\n"
	assert.Empty(t, parseInline(t, in).Servers, "two different invalid bytes must not both become U+FFFD and match")
	in = "# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/\xff.conf; }\n# configuration file /etc/nginx/\xff.conf:\nserver { " + okServer + " }\n"
	assert.Len(t, parseInline(t, in).Servers, 1)
}

func TestIfConditionWithAQuotedString(t *testing.T) {
	c := parseInline(t, `http { server { listen 443 ssl; if ($http_user_agent ~* "(bot|crawler)") { return 403; } `+
		`if ($a = 'x') { return 404; } ssl_certificate /etc/nginx/ssl/x.crt; ssl_certificate_key /etc/nginx/ssl/x.key; } }`)
	require.Len(t, c.Servers, 1)
	assert.True(t, c.HasPair("/etc/nginx/ssl/x.crt", "/etc/nginx/ssl/x.key"))
}

func TestDotSegmentsAreNeverAccepted(t *testing.T) {
	for _, raw := range []string{"/lib/../etc/shadow", "/etc/nginx/./ssl/x.crt", "../nginx/ssl/rel.crt", "ssl/../x.crt", "./x.crt", "/etc/nginx/ssl/.."} {
		c := parseInline(t, "http { server { listen 443 ssl; ssl_certificate "+raw+"; ssl_certificate_key /etc/nginx/ssl/x.key; } }")
		require.Len(t, c.Servers, 1, raw)
		assert.Equal(t, ReasonPathNotAllowed, c.Servers[0].Pairs[0].Unsupported, raw)
		c = parseInline(t, "http { server { listen 443 ssl; ssl_certificate /etc/nginx/ssl/x.crt; ssl_certificate_key "+raw+"; } }")
		require.Len(t, c.Servers, 1, raw)
		assert.Equal(t, ReasonPathNotAllowed, c.Servers[0].Pairs[0].Unsupported, raw)
	}
	c := parseInline(t, "http { server { listen 443 ssl; ssl_certificate ssl/rel.crt; ssl_certificate_key ssl/rel.key; } }")
	assert.True(t, c.HasPair("/etc/nginx/ssl/rel.crt", "/etc/nginx/ssl/rel.key"), "relative paths without dot segments resolve")
}

func TestEscapedDollarBraceIsNotAVariableBrace(t *testing.T) {
	// nginx clears its variable flag after a backslash, so "{" ends the word and opens a block.
	c := parseInline(t, `http { x \${ listen 1; } server { `+okServer+` } }`)
	assert.Len(t, c.Servers, 1)
}

func TestLuaBlocksAreSkipped(t *testing.T) {
	lua := `content_by_lua_block {
  local s = "}" -- } in a comment
  local t = '{'
  --[[ multi
  } line ]]
  local l = [==[ } ]] ]==]
  if x then ngx.say("a") end
  # not nginx syntax 'quote
}
init_by_lua_block { local x = { a = { 1 } } }
`
	c := parseInline(t, "http { server { "+okServer+"\n"+lua+" } "+lua+" }")
	require.Len(t, c.Servers, 1)
	assert.True(t, c.HasPair("/etc/nginx/ssl/x.crt", "/etc/nginx/ssl/x.key"))
	_, err := Parse([]byte("http { content_by_lua_block { local x = {"), "/etc/nginx")
	assert.ErrorIs(t, err, ErrSyntax)
	_, err = Parse([]byte("http { content_by_lua_block { local x = [[ unterminated }"), "/etc/nginx")
	assert.ErrorIs(t, err, ErrSyntax)
}

func TestSSLOnIsInheritedFromHTTP(t *testing.T) {
	c := parseInline(t, "http { ssl on; server { listen 7443; ssl_certificate /etc/nginx/ssl/a.crt; ssl_certificate_key /etc/nginx/ssl/a.key; } "+
		"server { listen 8443; ssl off; ssl_certificate /etc/nginx/ssl/b.crt; ssl_certificate_key /etc/nginx/ssl/b.key; } }")
	require.Len(t, c.Servers, 1)
	assert.Equal(t, []Listen{{Port: 7443, SSL: true}}, SSLListens(c.Servers[0]))
}

func TestQUICListenCountsAsTLS(t *testing.T) {
	c := parseInline(t, "http { server { listen 443 quic reuseport; ssl_certificate /etc/nginx/ssl/a.crt; ssl_certificate_key /etc/nginx/ssl/a.key; } }")
	require.Len(t, c.Servers, 1)
	assert.Equal(t, []Listen{{Port: 443, SSL: true}}, SSLListens(c.Servers[0]))
}

func TestStreamServerInheritingCertificatesWarns(t *testing.T) {
	c := parseInline(t, "stream { ssl_certificate /etc/ssl/m.crt; ssl_certificate_key /etc/ssl/m.key; server { listen 993 ssl; } server { listen 25; } }")
	require.Len(t, c.Servers, 1, "the plain-TCP server does not use the certificate")
	assert.True(t, c.Servers[0].Stream)
	assert.True(t, c.Servers[0].Pairs[0].Inherited)
	assert.Equal(t, ReasonStream, c.Servers[0].Pairs[0].Unsupported)
	assert.Equal(t, []string{WarnStreamTLS}, c.Warnings)
}

func TestMailTLSWarns(t *testing.T) {
	assert.Equal(t, []string{WarnMailTLS}, parseInline(t, "mail { server { listen 993 ssl; ssl_certificate /etc/ssl/m.crt; ssl_certificate_key /etc/ssl/m.key; } }").Warnings)
	assert.Equal(t, []string{WarnMailTLS}, parseInline(t, "mail { ssl_certificate /etc/ssl/m.crt; server { listen 993; } }").Warnings)
	assert.Empty(t, parseInline(t, "mail { server { listen 143; } }").Warnings)
}

func TestWarningCodesComeFromHelperproto(t *testing.T) {
	assert.Equal(t, helperproto.WarnStreamTLS, WarnStreamTLS)
	assert.Equal(t, helperproto.WarnMailTLS, WarnMailTLS)
	assert.Equal(t, helperproto.MaxNginxConfig, MaxInput)
}
