package apacheconf

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLex(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want []line
	}{
		"continuation": {"SSLCertificateFile \\\n /a.pem\n",
			[]line{{first: 1, last: 2, name: "sslcertificatefile", args: []string{"/a.pem"}}}},
		"continuation crlf and line numbers": {"\n# c\nA \\\r\n b \\\n c\nD e\n",
			[]line{{first: 3, last: 5, name: "a", args: []string{"b", "c"}}, {first: 6, last: 6, name: "d", args: []string{"e"}}}},
		"continuation joins words": {"Foo ab\\\ncd\n", []line{{first: 1, last: 2, name: "foo", args: []string{"abcd"}}}},
		"continuation at the end":  {"Foo a \\\n", []line{{first: 1, last: 1, name: "foo", args: []string{"a"}}}},
		"backslash at eof":         {"Foo a\\", []line{{first: 1, last: 1, name: "foo", args: []string{"a\\"}}}},
		"backslash space newline":  {"Foo a\\ \nB\n", []line{{first: 1, last: 1, name: "foo", args: []string{"a\\"}}, {first: 2, last: 2, name: "b"}}},
		"double quotes":            {`Foo "a b" c`, []line{{first: 1, last: 1, name: "foo", args: []string{"a b", "c"}}}},
		"single quotes":            {`Foo 'a b' c`, []line{{first: 1, last: 1, name: "foo", args: []string{"a b", "c"}}}},
		"escaped quote":            {`Foo "a\"b"`, []line{{first: 1, last: 1, name: "foo", args: []string{`a"b`}}}},
		"escaped single quote":     {`Foo 'a\'b'`, []line{{first: 1, last: 1, name: "foo", args: []string{`a'b`}}}},
		"other backslash literal":  {`Foo "a\b"`, []line{{first: 1, last: 1, name: "foo", args: []string{`a\b`}}}},
		"other quote kept escaped": {`Foo "a\'b"`, []line{{first: 1, last: 1, name: "foo", args: []string{`a\'b`}}}},
		// ap_getword_conf: a doubled backslash is one backslash, quoted or not.
		"double backslash":          {`Foo "a\\b" c\\d e\f`, []line{{first: 1, last: 1, name: "foo", args: []string{`a\b`, `c\d`, `e\f`}}}},
		"backslash before closing":  {`Foo "a\\" b`, []line{{first: 1, last: 1, name: "foo", args: []string{`a\`, "b"}}}},
		"quote inside a word":       {`Foo a"b c"`, []line{{first: 1, last: 1, name: "foo", args: []string{`a"b`, `c"`}}}},
		"word after closing quote":  {`Foo "a"b`, []line{{first: 1, last: 1, name: "foo", args: []string{"a", "b"}}}},
		"empty quoted":              {`Foo "" ''`, []line{{first: 1, last: 1, name: "foo", args: []string{"", ""}}}},
		"comment":                   {"  # c\n", nil},
		"comment continued":         {"# c \\\nFoo\nBar\n", []line{{first: 3, last: 3, name: "bar"}}},
		"hash later is an argument": {"x # y\n", []line{{first: 1, last: 1, name: "x", args: []string{"#", "y"}}}},
		"tabs and blank lines":      {"\n\t \n\tFoo\t a \t\r\n", []line{{first: 3, last: 3, name: "foo", args: []string{"a"}}}},
		"vertical tab and form feed": {"\vFoo\fa\v\n",
			[]line{{first: 1, last: 1, name: "foo", args: []string{"a"}}}},
		"name is case-insensitive": {"SSLEngine On\n", []line{{first: 1, last: 1, name: "sslengine", args: []string{"On"}}}},
		"non-ascii name kept":      {"İnclude x\n", []line{{first: 1, last: 1, name: "İnclude", args: []string{"x"}}}},
		"section": {"<VirtualHost *:443>\n</virtualhost>\n", []line{
			{first: 1, last: 1, name: "virtualhost", args: []string{"*:443"}, section: true},
			{first: 2, last: 2, name: "virtualhost", closing: true}}},
		"section two addresses": {"<VirtualHost 10.0.0.1:443 [::1]:443 >\n</VirtualHost>\n", []line{
			{first: 1, last: 1, name: "virtualhost", args: []string{"10.0.0.1:443", "[::1]:443"}, section: true},
			{first: 2, last: 2, name: "virtualhost", closing: true}}},
		"section without arguments": {"<Else>\n</Else>\n", []line{
			{first: 1, last: 1, name: "else", section: true},
			{first: 2, last: 2, name: "else", closing: true}}},
		"section name with closing bracket and args": {"<IfModule> mod_ssl.c>\n</IfModule>\n", []line{
			{first: 1, last: 1, name: "ifmodule", args: []string{"mod_ssl.c"}, section: true},
			{first: 2, last: 2, name: "ifmodule", closing: true}}},
		"text after the last bracket is dropped": {"<IfDefine X> y\n</IfDefine>\n", []line{
			{first: 1, last: 1, name: "ifdefine", args: []string{"X"}, section: true},
			{first: 2, last: 2, name: "ifdefine", closing: true}}},
		"if expression": {"<If \"%{X} == 'a'\">\n</If>\n", []line{
			{first: 1, last: 1, name: "if", args: []string{"%{X} == 'a'"}, section: true},
			{first: 2, last: 2, name: "if", closing: true}}},
		"if expression with bracket": {"<If \"%{X} > 'a'\">\n</If>\n", []line{
			{first: 1, last: 1, name: "if", args: []string{"%{X} > 'a'"}, section: true},
			{first: 2, last: 2, name: "if", closing: true}}},
		"negated ifmodule": {"<IfModule !mod_ssl.c>\n  Foo\n</IfModule>\n", []line{
			{first: 1, last: 1, name: "ifmodule", args: []string{"!mod_ssl.c"}, section: true},
			{first: 2, last: 2, name: "foo"},
			{first: 3, last: 3, name: "ifmodule", closing: true}}},
		"nested": {"<IfModule ssl_module>\n<VirtualHost _default_:443>\nSSLEngine on\n</VirtualHost>\n</IfModule>\n", []line{
			{first: 1, last: 1, name: "ifmodule", args: []string{"ssl_module"}, section: true},
			{first: 2, last: 2, name: "virtualhost", args: []string{"_default_:443"}, section: true},
			{first: 3, last: 3, name: "sslengine", args: []string{"on"}},
			{first: 4, last: 4, name: "virtualhost", closing: true},
			{first: 5, last: 5, name: "ifmodule", closing: true}}},
		"continued section": {"<VirtualHost \\\n *:443>\n</VirtualHost>\n", []line{
			{first: 1, last: 2, name: "virtualhost", args: []string{"*:443"}, section: true},
			{first: 3, last: 3, name: "virtualhost", closing: true}}},
		"empty": {"", nil},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := lex("/etc/apache2/apache2.conf", []byte(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLexErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want error
	}{
		"unterminated quote":         {"Foo \"a b\n", ErrSyntax},
		"unterminated single quote":  {"Foo 'a b\n", ErrSyntax},
		"escaped closing quote":      {`Foo "a\"`, ErrSyntax},
		"unterminated section quote": {"<If \"a>\n</If>\n", ErrSyntax},
		"nul":                        {"Foo a\x00b\n", ErrNUL},
		"nul in a comment":           {"# \x00\n", ErrNUL},
		"section without bracket":    {"<VirtualHost *:443\n</VirtualHost>\n", ErrSyntax},
		"empty section name":         {"<>\n", ErrSyntax},
		"lone bracket":               {"< x>\n", ErrSyntax},
		"unclosed section":           {"<VirtualHost *:443>\nFoo\n", ErrSyntax},
		"stray closing":              {"</VirtualHost>\n", ErrSyntax},
		"mismatched closing":         {"<VirtualHost *:443>\n</IfModule>\n", ErrSyntax},
		"closing with arguments":     {"<If x>\n</If> y\n", ErrSyntax},
		"closing without bracket":    {"<If x>\n</If\n", ErrSyntax},
		"closing with space":         {"<If x>\n</If >\n", ErrSyntax},
		"empty closing":              {"<If x>\n</>\n", ErrSyntax},
		"empty quoted name":          {"\"\" x\n", ErrSyntax},
		"quoted closing tag":         {"<If x>\n\"</If>\"\n</If>\n", ErrSyntax},
		"single-quoted closing tag":  {"<If x>\n'</If>'\n", ErrSyntax},
		"closing with a tab":         {"<If x>\n</If\t>\n", ErrSyntax},
		"unterminated quoted name":   {"\"Foo x\n", ErrSyntax},
		"line too long":              {"Foo " + strings.Repeat("a", MaxLine-3) + "\n", ErrLineTooLong},
		"continued line too long": {"Foo \\\n" + strings.Repeat("a", MaxLine/2) + " \\\n" + strings.Repeat("a", MaxLine/2) + "\n",
			ErrLineTooLong},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := lex("/etc/apache2/x.conf", []byte(tc.in))
			assert.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("1 MiB line is fine", func(t *testing.T) {
		got, err := lex("/x", []byte("Foo "+strings.Repeat("a", MaxLine-4)+"\n"))
		require.NoError(t, err)
		require.Len(t, got, 1)
	})
	t.Run("1 MiB+1 line", func(t *testing.T) {
		_, err := lex("/x", []byte(strings.Repeat("a", MaxLine+1)))
		assert.ErrorIs(t, err, ErrLineTooLong)
	})
	t.Run("too large", func(t *testing.T) {
		_, err := lex("/x", make([]byte, MaxInput+1))
		assert.ErrorIs(t, err, ErrTooLarge)
	})
	t.Run("too deep", func(t *testing.T) {
		in := strings.Repeat("<IfModule x>\n", MaxDepth) + strings.Repeat("</IfModule>\n", MaxDepth)
		_, err := lex("/x", []byte(in))
		require.NoError(t, err)
		in = strings.Repeat("<IfModule x>\n", MaxDepth+1) + strings.Repeat("</IfModule>\n", MaxDepth+1)
		_, err = lex("/x", []byte(in))
		assert.ErrorIs(t, err, ErrTooDeep)
	})
	t.Run("too many tokens", func(t *testing.T) {
		in := strings.Repeat("a\n", MaxTokens)
		_, err := lex("/x", []byte(in))
		require.NoError(t, err)
		_, err = lex("/x", []byte(in+"a\n"))
		assert.ErrorIs(t, err, ErrTooComplex)
		long := strings.Repeat("a ", MaxLine/2-1) + "\n" // one line of about half a million tokens
		_, err = lex("/x", []byte(long+long+long))
		assert.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("errors name the file and line", func(t *testing.T) {
		_, err := lex("/etc/apache2/x.conf", []byte("A\nB \"c\n"))
		require.ErrorIs(t, err, ErrSyntax)
		assert.Contains(t, err.Error(), "/etc/apache2/x.conf line 2")
		_, err = lex("/etc/apache2/x.conf", []byte("A\nB\n\x00"))
		require.ErrorIs(t, err, ErrNUL)
		assert.Contains(t, err.Error(), "/etc/apache2/x.conf line 3")
	})
}

// §25.6: hostile sizes are refused (or lexed) quickly.
func TestLexHostileSizes(t *testing.T) {
	for name, in := range map[string]string{
		"many continuations": strings.Repeat("a\\\n", MaxLine/2-1) + "\n",
		"many quotes":        "Foo " + strings.Repeat(`"a" `, MaxLine/4-2) + "\n",
		"many sections":      strings.Repeat("<A>\n</A>\n", MaxTokens/2),
		"many backslashes":   "Foo \"" + strings.Repeat(`\\`, MaxLine/2-4) + "\"\n",
		"max input comments": strings.Repeat("#"+strings.Repeat("x", 1000)+"\n", MaxInput/1002),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, _ = lex("/x", []byte(in))
			assert.Less(t, time.Since(start), 2*time.Second*slowdown())
		})
	}
}
