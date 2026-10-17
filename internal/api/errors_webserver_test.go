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
	for i, want := range []string{"ALC-APC-0001", "ALC-APC-0002", "ALC-APC-0003", "ALC-APC-0004"} {
		r := []string{"not_found", "config_invalid", "profile_missing", "helper_too_old"}[i]
		assert.Equal(t, want, codeForReason("apache."+r).Code, r)
	}
	assert.Equal(t, 502, codeForReason("apache.not_found").Status)
	assert.Equal(t, 409, codeForReason("apache.config_invalid").Status)
	assert.Equal(t, 502, codeForReason("apache.profile_missing").Status)
	assert.Equal(t, 502, codeForReason("apache.helper_too_old").Status)
}
