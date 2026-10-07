package claims

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Review Focus 1, O-05: next never leaves Alice.
func TestSafeNextRefusesOpenRedirects(t *testing.T) {
	ok := []string{"/", "/certificates?expiry=30&target_id=0192e000-0000-7000-8000-000000000001", "/ssh-keys/abc", "/settings#mail"}
	for _, v := range ok {
		assert.Equal(t, v, SafeNext(v), v)
	}
	bad := []string{"", "https://evil.example", "//evil.example", "/\\evil.example", "\\\\evil", "/%0d%0aSet-Cookie:x",
		"javascript:alert(1)", "/ok\r\nLocation: x", "/ok\tx", "relative/path", "/api/v1/auth/logout", "/api", "https:/evil",
		"/" + strings.Repeat("a", 2048), "/\u2028x", "/ x", "/%zz"}
	for _, v := range bad {
		assert.Equal(t, "/", SafeNext(v), "%q", v)
	}
}

// O-12: plain HTTP and odd issuer addresses are refused at configuration time.
func TestValidateIssuer(t *testing.T) {
	for _, v := range []string{"https://login.microsoftonline.com/0192e000-0000-7000-8000-000000000001/v2.0",
		"https://adfs.example.com/adfs", "https://keycloak.example.com:8443/realms/corp", "https://idp.alice-e2e.test:9444"} {
		assert.NoError(t, ValidateIssuer(v), v)
	}
	for _, v := range []string{"", "http://idp.example.com", "https://", "https://user@idp.example.com", "https://idp.example.com?x=1",
		"https://idp.example.com#f", " https://idp.example.com", "https://idp.example.com/ x", "ftp://idp", "idp.example.com",
		"https://" + strings.Repeat("a", 500)} {
		assert.ErrorIs(t, ValidateIssuer(v), ErrIssuer, "%q", v)
	}
}

func TestUsername(t *testing.T) {
	assert.Equal(t, "ada.yilmaz@example.com", Username(Claims{PreferredUsername: "Ada.Yilmaz@Example.com", Subject: "s"}))
	assert.Equal(t, "ada@corp.example.com", Username(Claims{UPN: "ADA@corp.example.com", Subject: "s"}))
	assert.Equal(t, "ada@example.com", Username(Claims{Email: "ada@example.com", Subject: "s"}))
	assert.Equal(t, "dlmaz", Username(Claims{PreferredUsername: "İıöÖdlmaz", Subject: "s"}), "non-ASCII letters are dropped")
	u := Username(Claims{Issuer: "https://idp", Subject: "s", PreferredUsername: "@@@"})
	assert.Regexp(t, `^sso-[0-9a-f]{12}$`, u)
	assert.Equal(t, u, Username(Claims{Issuer: "https://idp", Subject: "s"}), "stable for the same identity")
	assert.NotEqual(t, u, Username(Claims{Issuer: "https://idp", Subject: "t"}))
	assert.Len(t, Username(Claims{PreferredUsername: strings.Repeat("a", 100)}), 64)
}

// S-13: a fragment is kept, so the caller must insert a query before the "#", never after it.
func TestSafeNextKeepsTheFragmentForTheCaller(t *testing.T) {
	assert.Equal(t, "/settings?tab=sso#mail", SafeNext("/settings?tab=sso#mail"))
	assert.Equal(t, "/settings#mail", SafeNext("/settings#mail"))
	assert.Equal(t, "/", SafeNext("/settings#ma il"))
}
