package helperproto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Protocol 7 (ACME Task 7, A1): the helper reports 7 / 1.6.0, Alice still opens a protocol 6 helper
// for every existing operation and needs 7 only for an HTTP-01 challenge.
func TestProtocol7(t *testing.T) {
	assert.Equal(t, 7, Protocol)
	assert.Equal(t, "1.6.0", Version)
	assert.Equal(t, 6, MinProtocol)
	assert.Equal(t, 7, HTTP01MinProtocol)
	assert.LessOrEqual(t, MinProtocol, HTTP01MinProtocol)
	assert.LessOrEqual(t, HTTP01MinProtocol, Protocol)
	assert.Equal(t, "acme-challenge-put", SubACMEChallengePut)
	assert.Equal(t, "acme-challenge-rm", SubACMEChallengeRm)
	assert.Equal(t, "/var/www/alice-acme", ACMEWebroot)
	assert.Equal(t, "/var/www/alice-acme/.well-known/acme-challenge", ACMEChallengeDir)
	assert.Equal(t, []string{"var", "www", "alice-acme", ".well-known", "acme-challenge"}, ACMEChallengeDirElems())
	assert.Equal(t, 512, MaxACMEBody)
	assert.Equal(t, 22, MinACMEToken)
	assert.Equal(t, 128, MaxACMEToken)
	assert.Equal(t, "/var/www/alice-acme/.well-known/acme-challenge/"+strings.Repeat("a", 22), ACMEChallengePath(strings.Repeat("a", 22)))
	assert.Equal(t, "/.well-known/acme-challenge/"+strings.Repeat("a", 22), ACMEChallengeURLPath(strings.Repeat("a", 22)))
}

func TestValidACMEToken(t *testing.T) {
	for _, ok := range []string{
		strings.Repeat("a", 22), strings.Repeat("Z", 128), "-" + strings.Repeat("x", 42), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
	} {
		assert.True(t, ValidACMEToken(ok), "%q", ok)
	}
	for _, bad := range []string{
		"", strings.Repeat("a", 21), strings.Repeat("a", 129), "..", "../" + strings.Repeat("a", 22), strings.Repeat("a", 21) + "/",
		strings.Repeat("a", 21) + ".", strings.Repeat("a", 21) + "\x00", strings.Repeat("a", 21) + "=", strings.Repeat("a", 21) + "+",
		strings.Repeat("a", 20) + "ç", strings.Repeat("a", 21) + " ", strings.Repeat("a", 21) + "\n", strings.Repeat("a", 21) + "'",
		"а" + strings.Repeat("a", 21), // Cyrillic a
	} {
		assert.False(t, ValidACMEToken(bad), "%q", bad)
	}
}

func TestValidKeyAuthorization(t *testing.T) {
	tok := strings.Repeat("t", 43)
	thumb := strings.Repeat("A", 42) + "_"
	assert.True(t, ValidKeyAuthorization(tok, []byte(tok+"."+thumb)))
	assert.True(t, ValidKeyAuthorization("-"+tok, []byte("-"+tok+"."+"-"+thumb[1:])))
	for name, body := range map[string]string{
		"empty":            "",
		"other token":      strings.Repeat("u", 43) + "." + thumb,
		"no dot":           tok + thumb,
		"short thumbprint": tok + "." + thumb[1:],
		"long thumbprint":  tok + "." + thumb + "A",
		"newline":          tok + "." + thumb + "\n",
		"padding":          tok + "." + thumb[1:] + "=",
		"two dots":         tok + ".." + thumb[2:],
		"nul":              tok + "." + thumb[1:] + "\x00",
		"slash":            tok + "." + thumb[1:] + "/",
		"utf8":             tok + "." + thumb[2:] + "ç",
	} {
		assert.False(t, ValidKeyAuthorization(tok, []byte(body)), name)
	}
	assert.False(t, ValidKeyAuthorization("short", []byte("short."+thumb)), "an invalid token never validates")
	assert.LessOrEqual(t, MaxACMEToken+1+43, MaxACMEBody, "every valid key authorization fits the body cap")
}

func TestACMEWireShapes(t *testing.T) {
	b, err := json.Marshal(ACMEChallengePutResponse{OK: true, Path: "/p", Replaced: true})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"path":"/p","replaced":true}`, string(b))
	b, err = json.Marshal(ACMEChallengeRmResponse{OK: true, Path: "/p", Removed: false})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"path":"/p","removed":false}`, string(b))
}
