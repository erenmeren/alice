package api

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/providers"
)

func TestHelperOutdatedHTTP01Classifies(t *testing.T) {
	got, params, ok := classify(providers.NewError("ssh.helper_outdated_http01", false, errors.New("cause text"),
		map[string]string{"helper_protocol": "6", "required_protocol": "7"}))
	assert.True(t, ok)
	assert.Equal(t, ErrHelperOutdatedHTTP01, got)
	assert.Equal(t, map[string]string{"helper_protocol": "6", "required_protocol": "7"}, params)
}
