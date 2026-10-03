package nginxconf

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		CertRaw: "/etc/nginx/ssl/www.crt", KeyRaw: "/etc/nginx/ssl/www.key"}}, s.Pairs)
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
		"too many files":             {strings.Repeat("# configuration file /a:\n", MaxFiles+1), ErrTooComplex},
		"deep nesting through files": {deepIncludes(), ErrTooDeep},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in), "/etc/nginx")
			assert.ErrorIs(t, err, tc.err)
		})
	}
}

// deepIncludes builds MaxDepth+2 files that each open one block and include the next one.
func deepIncludes() string {
	var b strings.Builder
	for i := 0; i <= MaxDepth+1; i++ {
		b.WriteString("# configuration file /d" + strconv.Itoa(i) + ":\nx { include /d" + strconv.Itoa(i+1) + "; }\n")
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
		"semicolons":   strings.Repeat(";\n", MaxInput/2),
		"open braces":  strings.Repeat("a{\n", MaxInput/3),
		"short words":  strings.Repeat("a\n", MaxInput/2),
		"markers":      strings.Repeat("# configuration file /a:\n", MaxInput/24),
		"empty blocks": strings.Repeat("a{}", MaxInput/3),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(in), "/etc/nginx")
			assert.Error(t, err)
		})
	}
}

func TestBlankLinesBeforeTheFirstMarkerDoNotHideTheMainFile(t *testing.T) {
	in := "\n  \n# configuration file /etc/nginx/nginx.conf:\nhttp { server { " + okServer + " } }\n"
	assert.Len(t, parseInline(t, in).Servers, 1)
}

func TestDirectoryPathsAreNotCertificateFiles(t *testing.T) {
	for _, raw := range []string{`""`, ".", "..", "ssl/", "/etc/nginx/ssl/.", "/etc/nginx/ssl/x/.."} {
		c := parseInline(t, "http { server { listen 443 ssl; ssl_certificate "+raw+"; ssl_certificate_key /etc/nginx/ssl/x.key; } }")
		require.Len(t, c.Servers, 1, raw)
		assert.Equal(t, ReasonPathNotAllowed, c.Servers[0].Pairs[0].Unsupported, raw)
	}
}
