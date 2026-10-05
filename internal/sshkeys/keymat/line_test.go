package keymat

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestComment(t *testing.T) {
	day := time.Date(2026, 10, 5, 23, 59, 0, 0, time.FixedZone("x", 3*3600))
	cases := map[string]string{
		"CI deploy key":         "alice:ci-deploy-key:2026-10-05",
		"İstanbul yedek":        "alice:stanbul-yedek:2026-10-05",
		"  --  ":                "alice:key:2026-10-05",
		"web.prod_01":           "alice:web.prod_01:2026-10-05",
		strings.Repeat("a", 80): "alice:" + strings.Repeat("a", 40) + ":2026-10-05",
		"a\u202eb":              "alice:a-b:2026-10-05",
	}
	for label, want := range cases {
		got := Comment(label, day)
		assert.Equal(t, want, got, label)
		assert.Regexp(t, `^[!-~]{1,100}$`, got)
	}
}

func TestFromOption(t *testing.T) {
	got, err := FromOption(" 10.0.0.0/8, 192.0.2.7,2001:db8::/32 ")
	require.NoError(t, err)
	assert.Equal(t, `from="10.0.0.0/8,192.0.2.7,2001:db8::/32"`, got)
	for _, bad := range []string{"", " ", "10.0.0.1/8", "host.example", "10.0.0.0/8,", `1.2.3.4"`, "fe80::1%eth0",
		strings.Repeat("10.0.0.1,", MaxFromEntries) + "10.0.0.1", "*"} {
		_, err := FromOption(bad)
		assert.ErrorIs(t, err, ErrFromOption, bad)
	}
}

func TestLine(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	line, err := Line(`from="10.0.0.0/8",restrict`, m.PublicKey, "alice:web:2026-10-05")
	require.NoError(t, err)
	assert.Equal(t, `from="10.0.0.0/8",restrict `+m.PublicKey+" alice:web:2026-10-05", line)
	pk, comment, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, m.Fingerprint, ssh.FingerprintSHA256(pk))
	assert.Equal(t, "alice:web:2026-10-05", comment)
	assert.Equal(t, []string{`from="10.0.0.0/8"`, "restrict"}, opts)

	// Quoted values may hold spaces, commas, escaped quotes and non-ASCII text.
	ok, err := Line(`command="echo a, b \"c\" é",no-pty`, m.PublicKey, "c")
	require.NoError(t, err)
	assert.Equal(t, `command="echo a, b \"c\" é",no-pty `+m.PublicKey+" c", ok)

	plain, err := Line("", m.PublicKey, "c")
	require.NoError(t, err)
	assert.Equal(t, m.PublicKey+" c", plain)

	for name, args := range map[string][3]string{
		"cert-authority":        {"cert-authority", m.PublicKey, "c"},
		"Cert-Authority":        {`Cert-Authority`, m.PublicKey, "c"},
		"newline in options":    {"restrict\nssh-ed25519 AAAA", m.PublicKey, "c"},
		"space in comment":      {"", m.PublicKey, "two words"},
		"empty comment":         {"", m.PublicKey, ""},
		"bad key":               {"", "ssh-ed25519 AAAA", "c"},
		"two keys":              {"", m.PublicKey + " c\n" + m.PublicKey, "c"},
		"options with a space":  {"two words", m.PublicKey, "c"},
		"leading vertical tab":  {"\vrestrict", m.PublicKey, "c"},
		"trailing vertical tab": {"restrict\v", m.PublicKey, "c"},
		"NEL":                   {"\u0085restrict", m.PublicKey, "c"},
		"empty item":            {",,restrict", m.PublicKey, "c"},
		"leading comma":         {",restrict", m.PublicKey, "c"},
		"trailing comma":        {"restrict,", m.PublicKey, "c"},
		"trailing space":        {"restrict ", m.PublicKey, "c"},
		"control in quotes":     {"command=\"\x1b[2J\"", m.PublicKey, "c"},
		"escaped control":       {"command=\"a\\\x1b\"", m.PublicKey, "c"},
		"DEL":                   {"restrict\x7f", m.PublicKey, "c"},
		"open quote":            {`command="abc`, m.PublicKey, "c"},
		"dangling escape":       {`command="abc\`, m.PublicKey, "c"},
		"cert-authority value":  {`cert-authority="x"`, m.PublicKey, "c"},
		"NUL":                   {"", m.PublicKey, "c\x00"},
	} {
		_, err := Line(args[0], args[1], args[2])
		assert.ErrorIs(t, err, ErrLine, name)
	}
}

func TestHasOption(t *testing.T) {
	assert.True(t, HasOption(`restrict,Command="x,y"`, "command"))
	assert.True(t, HasOption(`no-pty`, "NO-PTY"))
	assert.False(t, HasOption(`environment="command=x"`, "command"))
	assert.False(t, HasOption("", "command"))
}

func TestHasFromOption(t *testing.T) {
	assert.True(t, HasFromOption(`from="10.0.0.0/8"`))
	assert.True(t, HasFromOption(`restrict,FROM="1.2.3.4"`))
	assert.False(t, HasFromOption(`command="echo from=x",restrict`))
	assert.False(t, HasFromOption(""))
	assert.False(t, HasFromOption(`environment="A=from=1"`))
	assert.False(t, HasFromOption(`command="a\"b,from=1"`), "an escaped quote does not end the string")
}
