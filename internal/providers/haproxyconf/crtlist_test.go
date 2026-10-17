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
		{2, "/probe/certs/a.pem", nil},
		{3, "h.pem", []string{"h.example.test", "*.h.example.test"}},
		{4, "/b.pem", []string{"b.example.test", "other.example.test", "#", "trailing", "comment"}},
		{6, "/a.pem", []string{"indented.example.test"}},
		{7, "#", []string{"indented"}}, // an indented "#" is a path, and what follows are filters
		{8, `"/a.pem"`, []string{"x"}},
	}, got)
}

func TestParseCrtListLines(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want []crtListLine
	}{
		"empty":                  {"", nil},
		"comments and blanks":    {"#a\n\n\t\n#b", nil},
		"no final newline":       {"/a.pem x", []crtListLine{{1, "/a.pem", []string{"x"}}}},
		"crlf":                   {"/a.pem x\r\n/b.pem\r\n", []crtListLine{{1, "/a.pem", []string{"x"}}, {2, "/b.pem", nil}}},
		"tabs":                   {"\t/a.pem\tx\ty\n", []crtListLine{{1, "/a.pem", []string{"x", "y"}}}},
		"options only":           {"/a.pem [alpn h2]\n", []crtListLine{{1, "/a.pem", nil}}},
		"options without blanks": {"/a.pem[alpn h2]x y\n", []crtListLine{{1, "/a.pem", []string{"x", "y"}}}},
		"empty options":          {"/a.pem [] x\n", []crtListLine{{1, "/a.pem", []string{"x"}}}},
		"tab inside options":     {"/a.pem [verify\tnone ] x\n", []crtListLine{{1, "/a.pem", []string{"x"}}}},
		"only negative":          {"/a.pem !x !y\n", []crtListLine{{1, "/a.pem", nil}}},
		"bang alone":             {"/a.pem ! x\n", []crtListLine{{1, "/a.pem", []string{"x"}}}},
		"no escapes":             {`/a\ b.pem x\y`, []crtListLine{{1, `/a\`, []string{"b.pem", `x\y`}}}},
		"dollar kept":            {"/a/${X}.pem x\n", []crtListLine{{1, "/a/${X}.pem", []string{"x"}}}},
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
		"unclosed options":              {"[a b\n", ErrSyntax},
		"unclosed options after a path": {"/a.pem [a b\n", ErrSyntax},
		"options before the path":       {"  [alpn h2] /a.pem\n", ErrSyntax},
		"two option blocks":             {"/a.pem [a] [b]\n", ErrSyntax},
		"nested bracket":                {"/a.pem [a [b]]\n", ErrSyntax},
		"closing without opening":       {"/a.pem a]\n", ErrSyntax},
		"filters before options":        {"/a.pem x [alpn h2]\n", ErrSyntax},
		"nul":                           {"/a.pem\x00\n", ErrNUL},
		"nul in a comment":              {"#\x00\n", ErrNUL},
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
			assert.Less(t, time.Since(start), 2*time.Second*raceSlowdown)
		})
	}
}
