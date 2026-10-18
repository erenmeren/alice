package haproxyconf

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCrtList is the verified sample of Ruling 11, line for line.
func TestParseCrtList(t *testing.T) {
	in := "# comment\n" +
		"/probe/certs/a.pem\n" +
		"h.pem [alpn h2 ssl-min-ver TLSv1.2] h.example.test *.h.example.test !nope.h.example.test\n" +
		"/b.pem b.example.test other.example.test # trailing comment\n" +
		"   \n" +
		"  /a.pem indented.example.test\n" +
		"   # indented\n" +
		"\"/a.pem\" x\n"
	got, err := parseCrtList([]byte(in))
	require.NoError(t, err)
	assert.Equal(t, []crtListLine{
		{2, "/probe/certs/a.pem", nil, false},
		{3, "h.pem", []string{"h.example.test", "*.h.example.test"}, false},
		{4, "/b.pem", []string{"b.example.test", "other.example.test", "#", "trailing", "comment"}, false},
		{6, "/a.pem", []string{"indented.example.test"}, false},
		{7, "#", []string{"indented"}, false}, // an indented "#" is a path, and what follows are filters
		{8, `"/a.pem"`, []string{"x"}, false},
	}, got)
}

func TestParseCrtListLines(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want []crtListLine
	}{
		"empty":               {"", nil},
		"comments and blanks": {"#a\n\n\t\n#b", nil},
		"no final newline":    {"/a.pem x", []crtListLine{{1, "/a.pem", []string{"x"}, false}}},
		"crlf":                {"/a.pem x\r\n/b.pem\r\n", []crtListLine{{1, "/a.pem", []string{"x"}, false}, {2, "/b.pem", nil, false}}},
		// Review I3 (probed on 2.4, 2.6 and 2.8): a line starting with CR is skipped; a CR
		// later in the line is a blank.
		"cr first":               {"\r/x/missing.pem x\n/a.pem\n", []crtListLine{{2, "/a.pem", nil, false}}},
		"cr after a blank":       {" \r/a.pem x\n", []crtListLine{{1, "/a.pem", []string{"x"}, false}}},
		"tabs":                   {"\t/a.pem\tx\ty\n", []crtListLine{{1, "/a.pem", []string{"x", "y"}, false}}},
		"options only":           {"/a.pem [alpn h2]\n", []crtListLine{{1, "/a.pem", nil, false}}},
		"options without blanks": {"/a.pem[alpn h2]x y\n", []crtListLine{{1, "/a.pem", []string{"x", "y"}, false}}},
		"empty options":          {"/a.pem [] x\n", []crtListLine{{1, "/a.pem", []string{"x"}, false}}},
		"tab inside options":     {"/a.pem [verify\tnone ] x\n", []crtListLine{{1, "/a.pem", []string{"x"}, false}}},
		"only negative":          {"/a.pem !x !y\n", []crtListLine{{1, "/a.pem", nil, false}}},
		"bang alone":             {"/a.pem ! x\n", []crtListLine{{1, "/a.pem", []string{"x"}, false}}},
		"no escapes":             {`/a\ b.pem x\y`, []crtListLine{{1, `/a\`, []string{"b.pem", `x\y`}, false}}},
		"dollar kept":            {"/a/${X}.pem x\n", []crtListLine{{1, "/a/${X}.pem", []string{"x"}, false}}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseCrtList([]byte(tc.in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseCrtListErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want error
	}{
		"unclosed options": {"[a b\n", ErrSyntax},
		"unclosed options after a path (refused here to fail closed)": {"/a.pem [a b\n", ErrSyntax},
		"options before the path":                                     {"  [alpn h2] /a.pem\n", ErrSyntax},
		"two option blocks":                                           {"/a.pem [a] [b]\n", ErrSyntax},
		"nested bracket":                                              {"/a.pem [a [b]]\n", ErrSyntax},
		"closing without opening":                                     {"/a.pem a]\n", ErrSyntax},
		"filters before options (refused here to fail closed)":        {"/a.pem x [alpn h2]\n", ErrSyntax},
		"nul":              {"/a.pem\x00\n", ErrNUL},
		"nul in a comment": {"#\x00\n", ErrNUL},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseCrtList([]byte(tc.in))
			assert.ErrorIs(t, err, tc.want)
			assert.Nil(t, got)
		})
	}

	t.Run("errors name the line", func(t *testing.T) {
		_, err := parseCrtList([]byte("/a.pem\n/b.pem [x\n"))
		require.ErrorIs(t, err, ErrSyntax)
		assert.Contains(t, err.Error(), "line 2")
	})
	t.Run("1 MiB line is fine", func(t *testing.T) {
		got, err := parseCrtList([]byte(strings.Repeat("a", MaxLine) + "\n"))
		require.NoError(t, err)
		require.Len(t, got, 1)
	})
	t.Run("1 MiB+1 line", func(t *testing.T) {
		_, err := parseCrtList([]byte(strings.Repeat("a", MaxLine+1)))
		assert.ErrorIs(t, err, ErrLineTooLong)
	})
	t.Run("too large", func(t *testing.T) {
		_, err := parseCrtList(make([]byte, MaxInput+1))
		assert.ErrorIs(t, err, ErrTooLarge)
	})
	t.Run("too many words", func(t *testing.T) {
		in := strings.Repeat("a b c d e f g h\n", MaxTokens/8)
		got, err := parseCrtList([]byte(in))
		require.NoError(t, err)
		require.Len(t, got, MaxTokens/8)
		_, err = parseCrtList([]byte(in + "a\n"))
		assert.ErrorIs(t, err, ErrTooComplex)
		// words inside an option block count too
		_, err = parseCrtList([]byte(strings.Repeat("a b c d e f g h\n", MaxTokens/8-1) + "a [b c d e f g h x]\n"))
		assert.ErrorIs(t, err, ErrTooComplex)
	})
}

// §25.6: hostile sizes are refused (or parsed) quickly.
func TestParseCrtListHostileSizes(t *testing.T) {
	for name, in := range map[string]string{
		"many names":    strings.Repeat("/a.pem "+strings.Repeat("x ", 1000)+"\n", MaxTokens/1001),
		"long option":   "/a.pem [" + strings.Repeat("a ", MaxLine/2-8) + "]\n",
		"many brackets": "/a.pem [" + strings.Repeat("[", MaxLine-16) + "\n",
		"many lines":    strings.Repeat("/a.pem\n", MaxInput/7),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, _ = parseCrtList([]byte(in))
			assert.Less(t, time.Since(start), 2*time.Second*slowdown())
		})
	}
}

// TestParseCrtListOverrides (final review I1): HAProxy 3.0's crt-list option block also takes the
// crt-store load keywords crt, key, ocsp, issuer and sctl, which name files of the line's own.
// A block holding one of them, anywhere, sets override; so does a block word with a quote, a
// backslash or a "$", which this reader does not interpret (an unparseable block). Filters and
// other options do not.
func TestParseCrtListOverrides(t *testing.T) {
	for _, kw := range []string{"key", "crt", "ocsp", "issuer", "sctl"} {
		t.Run(kw, func(t *testing.T) {
			got, err := parseCrtList([]byte("/c/a.pem [alpn h2 " + kw + " /k/other] a.example\n/c/b.pem [" + kw + " /k/x]\n"))
			require.NoError(t, err)
			assert.Equal(t, []crtListLine{
				{1, "/c/a.pem", []string{"a.example"}, true},
				{2, "/c/b.pem", nil, true},
			}, got)
		})
	}
	for name, tc := range map[string]struct {
		in   string
		want bool
	}{
		"other options":                {"/c/a.pem [alpn h2 ssl-min-ver TLSv1.2] key\n", false},
		"a filter named key":           {"/c/a.pem key crt\n", false},
		"no block":                     {"/c/a.pem\n", false},
		"empty block":                  {"/c/a.pem [] x\n", false},
		"keyword without blank":        {"/c/a.pem[key /k/x]x\n", true},
		"ocsp-update is not a file":    {"/c/a.pem [ocsp-update on]\n", false},
		"a quote (unparseable)":        {"/c/a.pem [alpn \"h2\"]\n", true},
		"a single quote (unparseable)": {"/c/a.pem [alpn 'h2']\n", true},
		"a backslash (unparseable)":    {"/c/a.pem [alpn h\\2]\n", true},
		"a dollar (unparseable)":       {"/c/a.pem [alpn ${A}]\n", true},
		"a quote in a filter":          {"/c/a.pem [alpn h2] \"x\"\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseCrtList([]byte(tc.in))
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, tc.want, got[0].override)
		})
	}
}
