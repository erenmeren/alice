package ldapx

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const guid = "0123456789abcdef0123456789abcdef"

func TestUsername(t *testing.T) {
	cases := []struct{ login, want string }{
		{"ÇİĞDEM", "cigdem"},
		{"çiğdem", "cigdem"},
		{"Şeref Üstün", "serefustun"},
		{"IŞIK", "isik"},
		{"ışık", "isik"},
		{"Ada.Yilmaz@Corp.Example.com", "ada.yilmaz@corp.example.com"},
		{"CORP\\ada", "corpada"},
		{"François Lefèvre", "francoislefevre"},
		{"..ada..", "ada"},
		{"-_@ada@_-", "ada"},
		{"Straße", "strasse"},
		{"ab", "ab"},
		{"KELVINK", "kelvink"}, // the Kelvin sign folds to k
	}
	for _, c := range cases {
		assert.Equal(t, c.want, Username(c.login, guid), "%q", c.login)
	}
	long := Username(strings.Repeat("a", 100), guid)
	assert.Len(t, long, 64)
	assert.Equal(t, strings.Repeat("a", 63), Username(strings.Repeat("a", 63)+"."+strings.Repeat("b", 10), guid), "no trailing dot after the cut")
}

// A name that becomes empty, shorter than two characters or otherwise unusable falls back to ldap-<12 hex>.
func TestUsernameFallback(t *testing.T) {
	for _, login := range []string{"", " ", "日本語", "@@@", "...", "a", "ı", "-x-", "\x00", "\xff\xfe", "Ωμέγα"} {
		assert.Equal(t, "ldap-0123456789ab", Username(login, guid), "%q", login)
	}
	assert.Equal(t, "ldap-abcd", Username("", "abcd"), "a short unique id is used whole")
	assert.Equal(t, "ldap-abcd", Username("", "ABCD"), "the unique id is lower-cased")
	assert.Equal(t, "ldap-ab12", Username("", "a-b!1 2"), "only hex digits of the unique id are used")
	assert.Equal(t, "ldap-user", Username("", ""), "no unique id at all")
	assert.Regexp(t, usernameRE, Username("", "zz"))
}

// The policy of the package documentation: characters outside the table and non-ASCII are dropped, look-alike
// letters of other scripts are not mapped, a collapsed name falls back, the same name can come out twice.
func TestUsernamePolicy(t *testing.T) {
	assert.Equal(t, "dmin", Username("аdmin", guid), "Cyrillic а is dropped, not mapped to a")
	assert.Equal(t, "pen", Username("οpen", guid), "Greek ο is dropped, not mapped to o")
	assert.Equal(t, "mega", Username("Ωmega", guid))
	assert.Equal(t, "ldap-0123456789ab", Username("админ", guid), "all Cyrillic collapses and falls back")
	assert.Equal(t, Username("Öztürk", guid), Username("oztürk", "ffff"), "a clash is the caller's to resolve")
}

func TestUniqueID(t *testing.T) {
	// objectGUID: 16 raw bytes.
	raw := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	id, err := UniqueID(raw)
	require.NoError(t, err)
	assert.Equal(t, guid, id)
	// entryUUID: an ASCII uuid; its bytes are hexed too.
	id, err = UniqueID([]byte("8f9c3a2e-0000-4000-8000-000000000001"))
	require.NoError(t, err)
	assert.Equal(t, "38663963336132652d303030302d343030302d383030302d303030303030303030303031", id)
	assert.Len(t, id, 72)
	id, err = UniqueID([]byte{0xAB})
	require.NoError(t, err)
	assert.Equal(t, "ab", id)
	id, err = UniqueID(make([]byte, 127))
	require.NoError(t, err)
	assert.Len(t, id, 254)
	for _, b := range [][]byte{nil, {}, make([]byte, 128)} {
		_, err := UniqueID(b)
		assert.ErrorIs(t, err, ErrUniqueID, "%d bytes", len(b))
	}
}

func TestValidLoginName(t *testing.T) {
	for _, s := range []string{"a", "-", "a b", "a\u00a0b", "ada", "Çiğdem Öztürk", "CORP\\ada", "ada@corp.example.com", strings.Repeat("ş", 256), "*)(uid=*"} {
		assert.True(t, ValidLoginName(s), "%q", s)
	}
	for _, s := range []string{"", "a\x00b", "\x00", "a\nb", "a\tb", "a\x7fb", "a\u0085b", "\xff", "a\xc3", strings.Repeat("a", 257),
		" ", "   ", " ada", "ada ", "\u00a0ada", "ada\u3000", "\u200b", "a\u200bb", "a\u00adb", "a\u202eb", "a\u2028b", "a\u2029b",
		"\ufeffada", "a\u200fb", "a\u200cb", "a\u2066b"} {
		assert.False(t, ValidLoginName(s), "%q", s)
	}
}
