package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/validate"
)

// AUD-13: the stand-in for a name PostgreSQL cannot store is itself storable and can never be an
// account's name.
func TestUnstorableLoginNameIsNoAccountName(t *testing.T) {
	assert.True(t, validate.StorableText(unstorableLoginName))
	assert.False(t, usernameRE.MatchString(unstorableLoginName))
	assert.Error(t, ValidateProfile(unstorableLoginName, "x", "").Err(), "user creation refuses it")
}
