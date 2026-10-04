package audit

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckDetailsKeys(t *testing.T) {
	rejected := []string{
		"password", "Password", "PASSWORD", "new_password", "api_token", "session_token", "totp_code", "mfa_code",
		"setup_code", "apiToken", "sessionToken", "private_key", "privateKey", "private_anything", "recovery_code",
		"recovery_codes", "totp_secret", "client-secret", "db.password", "otp", "encryption_key", "dek", "credential",
		"credentials", "cookie", "session", "passphrase", "code", "token", "key", "secret",
	}
	for _, k := range rejected {
		assert.ErrorIs(t, checkDetails(map[string]string{k: "v"}), ErrForbiddenDetailKey, k)
	}
	allowed := []string{
		"token_id", "token_prefix", "key_id", "session_id", "recovery_codes_count", "tokenId", "error_code", "reason_code",
		"reason", "failed_logins", "minutes", "method", "username", "role", "display_name", "email", "role_from", "role_to",
		"disabled", "scope", "owner_id", "format", "intact", "permission", "path", "checked", "head_seq", "problem",
		"first_bad_seq", "i", "city", "a", "b",
		"class", "suppressed_count", "window_start", "window_end", // coalesced denial rows (AUD-06)
	}
	for _, k := range allowed {
		assert.NoError(t, checkDetails(map[string]string{k: "v"}), k)
	}
}

func TestSanitizeReplacesNULAndInvalidUTF8(t *testing.T) {
	assert.Equal(t, "a�b�c", sanitize("a\x00b\xffc"))
	assert.Equal(t, "İzmir", sanitize("İzmir"))
}

func TestCanonicalIPDropsZone(t *testing.T) {
	assert.Equal(t, "fe80::1", canonicalIP(mustAddr("fe80::1%eth0")))
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
