package windows

import (
	"strings"
	"testing"
)

func TestHelperChecksumsKnown(t *testing.T) {
	oldAMD, oldARM := helperSHA256WindowsAMD64, helperSHA256WindowsARM64
	t.Cleanup(func() { helperSHA256WindowsAMD64, helperSHA256WindowsARM64 = oldAMD, oldARM })

	good := strings.Repeat("ab", 32)
	cases := []struct {
		name     string
		amd, arm string
		want     bool
	}{
		{"both empty", "", "", false},
		{"amd64 only", good, "", false},
		{"arm64 only", "", good, false},
		{"upper case", strings.ToUpper(good), good, false}, //nolint:forbidigo // ASCII hex
		{"too short", good[:63], good, false},
		{"not hex", strings.Repeat("zz", 32), good, false},
		{"trailing newline", good + "\n", good, false},
		{"both set", good, strings.Repeat("01", 32), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			helperSHA256WindowsAMD64, helperSHA256WindowsARM64 = c.amd, c.arm
			if got := HelperChecksumsKnown(); got != c.want {
				t.Fatalf("HelperChecksumsKnown() = %v, want %v", got, c.want)
			}
		})
	}
}
