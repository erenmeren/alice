package license_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/license"
)

// Error texts name the problem, never file content.
func TestErrorTexts(t *testing.T) {
	assert.Equal(t, "license: not a valid license file (fields)", (&license.InvalidError{Problem: "fields"}).Error())
	assert.Equal(t, "license: issued for installation …AAAAAA, this is …BBBBBB",
		(&license.WrongInstallationError{Expected: "BBBBBB", Got: "AAAAAA"}).Error())
	assert.Equal(t, "license: 10 of 10 licensed targets are in use", (&license.TargetLimitError{Max: 10, Used: 10}).Error())
	assert.Equal(t, "revoked_key", license.RejectReason(license.ErrRevokedKey))
	assert.Equal(t, "unknown_key", license.RejectReason(license.ErrUnknownKey))
	assert.Equal(t, "error", license.RejectReason(errors.New("database down")))
}

func TestClassNames(t *testing.T) {
	assert.Equal(t, "always", license.ClassAlways.String())
	assert.Equal(t, "read_only", license.ClassReadOnly.String())
	assert.Equal(t, "change", license.ClassChange.String())
	assert.Equal(t, "unset", license.ClassUnset.String())
	assert.False(t, license.ClassUnset.Valid())
}
