package inventory_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/inventory"
	"alice/internal/providers/linuxssh/helperproto"
)

// The inventory may not import helperproto (archtest), so it mirrors ValidSNI; the verification
// probe sends the stored name to the helper, which checks it again. Both must agree.
func TestValidSNIMirrorsHelperproto(t *testing.T) {
	cases := []string{"", "a", "www.example.test", "check.example.test", "x-y.z", "-a.b", "a-.b", "a..b", ".a", "a.", "A.b",
		"*.example.test", "*", "192.0.2.1", "::1", "1.2.3", "10.0.0.256", "a_b.c", "ş.example", "a b", strings.Repeat("a", 63) + ".b",
		strings.Repeat("a", 64) + ".b", strings.Repeat("a.", 126) + "a", strings.Repeat("a.", 127) + "a", "xn--bcher-kva.example", "0x1.a"}
	for _, s := range cases {
		assert.Equal(t, helperproto.ValidSNI(s), inventory.ValidSNI(s), "%q", s)
	}
}
