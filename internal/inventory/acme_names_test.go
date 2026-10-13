package inventory_test

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
)

// CheckACMENames is the definition's name rule without a database (the API's boundary check).
func TestCheckACMENames(t *testing.T) {
	assert.Nil(t, inventory.CheckACMENames([]string{"www.example.com", "*.example.com", " API.example.com "}))
	many := make([]string, inventory.MaxACMENames+1)
	for i := range many {
		many[i] = "n" + strconv.Itoa(i) + ".example.com"
	}
	for _, tc := range []struct {
		names []string
		code  string
	}{
		{nil, validate.Required}, {many, validate.TooLong}, {[]string{"www.*.example.com"}, validate.Pattern},
		{[]string{"192.0.2.1"}, validate.Pattern}, {[]string{"a.example.com", "A.example.com"}, validate.Pattern},
	} {
		fe := inventory.CheckACMENames(tc.names)
		if assert.NotNil(t, fe, "%v", tc.names) {
			assert.Equal(t, "names", fe.Field)
			assert.Equal(t, tc.code, fe.Code, "%v", tc.names)
		}
	}
}
