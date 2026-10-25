package inventory_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/providers/tlsverify"
)

// The canary's server name (R65, design §9.3) is the name the post-deploy probe sends: the inventory's copy of
// tlsverify.SNIFor answers the same for every shape of name a location or a certificate carries.
func TestCanarySNIIsTheProbesName(t *testing.T) {
	for _, tc := range []struct{ names, sans []string }{
		{nil, nil},
		{[]string{"www.example.test"}, nil},
		{[]string{"_", "WWW.Example.TEST"}, nil},
		{[]string{"*.shop.example"}, nil},
		{[]string{".shop.example"}, nil},
		{[]string{"~^.*$"}, []string{"san.example"}},
		{[]string{"a*b.example"}, []string{"*.c.example"}},
		{[]string{"10.0.0.1"}, []string{"x.example"}},
		{[]string{"bad name"}, []string{"-bad.example", "ok.example"}},
		{nil, []string{"*"}},
	} {
		assert.Equal(t, tlsverify.SNIFor(tc.names, tc.sans), inventory.CanarySNI(tc.names, tc.sans), "%v %v", tc.names, tc.sans)
	}
}
