package haproxyconf

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// w is a word without "$"; d one with it.
func w(s string) word { return word{text: s} }
func d(s string) word { return word{text: s, dollar: true} }

func TestLex(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want []line
	}{
		"comment after blank": {"bind :443 ssl crt /a.pem # crt /b.pem\n",
			[]line{{1, []word{w("bind"), w(":443"), w("ssl"), w("crt"), w("/a.pem")}}}},
		"comment without blank": {"crt /a.pem#crt /b\n", []line{{1, []word{w("crt"), w("/a.pem")}}}},
		"double quotes":         {`crt "/a b.pem"`, []line{{1, []word{w("crt"), w("/a b.pem")}}}},
		"single quotes dollar":  {`crt '/a$b'`, []line{{1, []word{w("crt"), d("/a$b")}}}},
		"quoted variable":       {`crt "${D}/a.pem"`, []line{{1, []word{w("crt"), d("${D}/a.pem")}}}},
		"bare variable":         {`crt ${D}/a.pem`, []line{{1, []word{w("crt"), d("${D}/a.pem")}}}},
		// Review I1 (Ruling 5 amended; probed on 2.4, 2.6 and 2.8): \$ is consumed only inside
		// double quotes, and an unknown escape is kept as written.
		"escaped dollar":           {`crt /a\$b`, []line{{1, []word{w("crt"), d(`/a\$b`)}}}},
		"escaped dollar in double": {`crt "/a\$b"`, []line{{1, []word{w("crt"), d("/a$b")}}}},
		"escaped dollar in single": {`crt '/a\$b'`, []line{{1, []word{w("crt"), d(`/a\$b`)}}}},
		"unknown escape":           {`crt /a\q`, []line{{1, []word{w("crt"), w(`/a\q`)}}}},
		"unknown escape in double": {`crt "/a\qb"`, []line{{1, []word{w("crt"), w(`/a\qb`)}}}},
		"regex escapes":            {`acl st path_reg ^/a\.b\d+$`, []line{{1, []word{w("acl"), w("st"), w("path_reg"), d(`^/a\.b\d+$`)}}}},
		"back-reference":           {`http-request replace-path /api/(.*) /\1`, []line{{1, []word{w("http-request"), w("replace-path"), w("/api/(.*)"), w(`/\1`)}}}},
		"backslash before x":       {`a \\x41`, []line{{1, []word{w("a"), w(`\x41`)}}}},
		"hex dollar":               {`crt /a\x24b`, []line{{1, []word{w("crt"), d("/a$b")}}}},
		"escaped space":            {`crt /a\ b`, []line{{1, []word{w("crt"), w("/a b")}}}},
		"escaped tab":              {`crt /cer\ts`, []line{{1, []word{w("crt"), w("/cer\ts")}}}},
		"escaped cr and lf":        {`crt /a\r\n`, []line{{1, []word{w("crt"), w("/a\r\n")}}}},
		"hex":                      {`crt /a\x41`, []line{{1, []word{w("crt"), w("/aA")}}}},
		"hex lower":                {`crt /a\x6a\xFf`, []line{{1, []word{w("crt"), w("/aj\xff")}}}},
		"escaped specials":         {`crt \\\"\'\#`, []line{{1, []word{w("crt"), w(`\"'#`)}}}},
		"escape in double":         {`crt "a\"b\#c\\"`, []line{{1, []word{w("crt"), w(`a"b#c\`)}}}},
		"backslash in single":      {`crt 'a\qb\'`, []line{{1, []word{w("crt"), w(`a\qb\`)}}}},
		"hash in double":           {`crt "a#b" c`, []line{{1, []word{w("crt"), w("a#b"), w("c")}}}},
		"hash in single":           {`crt 'a#b' c`, []line{{1, []word{w("crt"), w("a#b"), w("c")}}}},
		"quote inside other":       {`crt "a'b" 'c"d'`, []line{{1, []word{w("crt"), w("a'b"), w(`c"d`)}}}},
		"concatenation":            {`crt /a "b"c`, []line{{1, []word{w("crt"), w("/a"), w("bc")}}}},
		"mixed concatenation":      {`crt a'b c'"d"e`, []line{{1, []word{w("crt"), w("ab cde")}}}},
		"empty quoted":             {`crt "" ''`, []line{{1, []word{w("crt"), w(""), w("")}}}},
		"trailing backslash":       {"crt \\\nbind\n", []line{{1, []word{w("crt"), w(`\`)}}, {2, []word{w("bind")}}}},
		"trailing backslash word":  {"crt /a\\\n", []line{{1, []word{w("crt"), w(`/a\`)}}}},
		"backslash at eof":         {"crt \\", []line{{1, []word{w("crt"), w(`\`)}}}},
		"backslash before crlf":    {"crt /a\\\r\n", []line{{1, []word{w("crt"), w(`/a\`)}}}},
		// Review I2 (probed on 2.4, 2.6 and 2.8): a CR after the first word ends the line, so
		// the second crt is never seen; a CR before the first word is a blank.
		"cr ends the line":       {"bind :9443 ssl crt /p/good.pem\rcrt /x/missing.pem\n", []line{{1, []word{w("bind"), w(":9443"), w("ssl"), w("crt"), w("/p/good.pem")}}}},
		"cr right after a word":  {"a\rb\nc\n", []line{{1, []word{w("a")}}, {2, []word{w("c")}}}},
		"cr after a blank":       {"a \r b\n", []line{{1, []word{w("a")}}}},
		"cr after a quoted word": {"\"a\"\rb\n", []line{{1, []word{w("a")}}}},
		"leading cr":             {"\r  bind :9443\n", []line{{1, []word{w("bind"), w(":9443")}}}},
		"cr only":                {"\r\r\nx\n", []line{{2, []word{w("x")}}}},
		"backslash before a cr":  {"crt /p/a\\\rcrt /x/missing.pem\n", []line{{1, []word{w("crt"), w(`/p/a\`)}}}},
		"crlf":                   {"global\r\n  crt-base /c\r\n", []line{{1, []word{w("global")}}, {2, []word{w("crt-base"), w("/c")}}}},
		"blanks":                 {"\t bind\t:443 \v\f ssl \n", []line{{1, []word{w("bind"), w(":443"), w("ssl")}}}},
		"case kept":              {"BIND :443\n", []line{{1, []word{w("BIND"), w(":443")}}}},
		"line numbers": {"\n# c\nglobal\n\n  # d\n   \nfrontend f # x\n.if 1\n", []line{
			{3, []word{w("global")}}, {7, []word{w("frontend"), w("f")}}, {8, []word{w(".if"), w("1")}}}},
		"comment only":     {"#a\n  # b\n", nil},
		"empty":            {"", nil},
		"no final newline": {"a\nb", []line{{1, []word{w("a")}}, {2, []word{w("b")}}}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := lex([]byte(tc.in))
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
		"cr in double quotes":             {"crt \"/p/good.pem\r\"\n", ErrSyntax},
		"cr in single quotes":             {"crt '/p/good.pem\r'\n", ErrSyntax},
		"short hex":                       {`crt /a\x4`, ErrSyntax},
		"bad hex":                         {`crt /a\x4g`, ErrSyntax},
		"hex at eof":                      {`crt /a\x`, ErrSyntax},
		"hex nul":                         {`crt /a\x00`, ErrNUL},
		"unterminated double":             {`crt "/a`, ErrSyntax},
		"unterminated single":             {`crt '/a`, ErrSyntax},
		"quote over newline":              {"crt \"/a\nb\"\n", ErrSyntax},
		"escape before newline in quotes": {"crt \"/a\\\nb\"\n", ErrSyntax},
		"nul":                             {"crt /a\x00b\n", ErrNUL},
		"nul in a comment":                {"# \x00\n", ErrNUL},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := lex([]byte(tc.in))
			assert.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("1 MiB line is fine", func(t *testing.T) {
		got, err := lex([]byte(strings.Repeat("a", MaxLine) + "\n"))
		require.NoError(t, err)
		require.Len(t, got, 1)
	})
	t.Run("1 MiB+1 line", func(t *testing.T) {
		_, err := lex([]byte("a\n" + strings.Repeat("a", MaxLine+1)))
		assert.ErrorIs(t, err, ErrLineTooLong)
		assert.Contains(t, err.Error(), "line 2")
	})
	t.Run("too many words", func(t *testing.T) {
		in := strings.Repeat("a a a a a a a a\n", MaxTokens/8)
		got, err := lex([]byte(in))
		require.NoError(t, err)
		require.Len(t, got, MaxTokens/8)
		_, err = lex([]byte(in + "a\n"))
		assert.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("too large", func(t *testing.T) {
		_, err := lex(make([]byte, MaxInput+1))
		assert.ErrorIs(t, err, ErrTooLarge)
		_, err = lex([]byte(strings.Repeat("#"+strings.Repeat("x", 1023)+"\n", MaxInput/1025)))
		assert.NoError(t, err)
	})
	t.Run("errors name the line", func(t *testing.T) {
		_, err := lex([]byte("a\nb \"c\n"))
		require.ErrorIs(t, err, ErrSyntax)
		assert.Contains(t, err.Error(), "line 2")
		_, err = lex([]byte("a\nb\n\x00"))
		require.ErrorIs(t, err, ErrNUL)
		assert.Contains(t, err.Error(), "line 3")
	})
}

// §25.6: hostile sizes are refused (or lexed) quickly.
func TestLexHostileSizes(t *testing.T) {
	for name, in := range map[string]string{
		"many words":       strings.Repeat(strings.Repeat("a ", 1000)+"\n", MaxTokens/1000),
		"many quotes":      strings.Repeat(`"a"`, MaxLine/3) + "\n",
		"many escapes":     strings.Repeat(`\x41`, MaxLine/4) + "\n",
		"many backslashes": strings.Repeat(`\\`, MaxLine/2) + "\n",
		"many lines":       strings.Repeat("\n", MaxInput),
		"long comments":    strings.Repeat("#"+strings.Repeat("x", 1000)+"\n", MaxInput/1002),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, _ = lex([]byte(in))
			assert.Less(t, time.Since(start), 2*time.Second*raceSlowdown)
		})
	}
}
