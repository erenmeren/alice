package auth_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/auth"
	"alice/internal/platform/validate"
)

func TestValidateProfile(t *testing.T) {
	codes := func(v validate.Errors) map[string]string {
		out := map[string]string{}
		for _, f := range v {
			out[f.Field] = f.Code
		}
		return out
	}
	assert.Empty(t, auth.ValidateProfile("admin", "Ayşe Yılmaz", ""))
	assert.Empty(t, auth.ValidateProfile("Ops.Team_1-x", "Işıl Çağlar Öztürk", "isil@example.com.tr"))
	assert.Equal(t, map[string]string{"username": validate.Required, "display_name": validate.Required},
		codes(auth.ValidateProfile("", "  ", "")))
	assert.Equal(t, validate.Pattern, codes(auth.ValidateProfile("İsmail", "İsmail", ""))["username"], "non-ASCII usernames are rejected")
	assert.Equal(t, validate.Pattern, codes(auth.ValidateProfile("a", "x", ""))["username"], "at least two characters")
	assert.Equal(t, validate.Pattern, codes(auth.ValidateProfile("-lead", "x", ""))["username"])
	assert.Equal(t, validate.Pattern, codes(auth.ValidateProfile("has space", "x", ""))["username"])
	assert.Equal(t, validate.TooLong, codes(auth.ValidateProfile("ok", strings.Repeat("ç", 101), ""))["display_name"])
	assert.Equal(t, validate.Email, codes(auth.ValidateProfile("ok", "x", "Ayşe <ayse@example.com>"))["email"])
	assert.Equal(t, validate.Email, codes(auth.ValidateProfile("ok", "x", "not-an-email"))["email"])
}
