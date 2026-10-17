package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every web-server kind's reasons are registered: an unregistered one would surface as ALC-SYS-0003.
func TestWebServerReasonsAreRegistered(t *testing.T) {
	for kind, reasons := range map[string][]string{
		"nginx":  {"not_found", "profile_missing", "config_invalid"},
		"apache": {"not_found", "profile_missing", "config_invalid", "helper_too_old"},
	} {
		for _, r := range reasons {
			assert.NotEqual(t, ErrUnexpected, codeForReason(kind+"."+r), "%s.%s", kind, r)
		}
	}
	for i, r := range []string{"not_found", "config_invalid", "profile_missing", "helper_too_old"} {
		got := codeForReason("apache." + r)
		assert.Equal(t, "ALC-APC-000"+string(rune('1'+i)), got.Code, r)
	}
	assert.Equal(t, 502, codeForReason("apache.not_found").Status)
	assert.Equal(t, 409, codeForReason("apache.config_invalid").Status)
	assert.Equal(t, 502, codeForReason("apache.profile_missing").Status)
	assert.Equal(t, 502, codeForReason("apache.helper_too_old").Status)
}
