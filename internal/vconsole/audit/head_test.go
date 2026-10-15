package audit_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/vconsole/audit"
)

func TestParseHeadPrefixAcceptsSixteenToSixtyThreeHexDigits(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	for _, n := range []int{16, 17, 40, 63} {
		p, err := audit.ParseHeadPrefix("7:" + hex64[:n])
		require.NoError(t, err, n)
		assert.Equal(t, audit.HeadPrefix{Seq: 7, Prefix: hex64[:n]}, p, n)
	}
	p, err := audit.ParseHeadPrefix("12:" + strings.Repeat("ABCDEF", 3))
	require.NoError(t, err)
	assert.Equal(t, audit.HeadPrefix{Seq: 12, Prefix: strings.Repeat("abcdef", 3)}, p, "upper case is lower-cased")
	p, err = audit.ParseHeadPrefix("0005:" + hex64[:16])
	require.NoError(t, err)
	assert.Equal(t, audit.HeadPrefix{Seq: 5, Prefix: hex64[:16]}, p, "leading zeros of the sequence are normalised")
	assert.Equal(t, "5:"+hex64[:16], p.String())
}

func TestParseHeadPrefixRefusesTooShortAndJunk(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	_, err := audit.ParseHeadPrefix("7:" + hex64[:15])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 16 hex digits")
	for _, bad := range []string{"", "7", "7:", ":" + hex64[:20], "0:" + hex64[:20], "-1:" + hex64[:20], "+5:" + hex64[:20],
		"5:" + hex64, "5:" + hex64[:19] + "g", "5:" + hex64[:19] + " ", " 5:" + hex64[:20], "5: " + hex64[:20],
		"99999999999999999999:" + hex64[:20], "5:5:" + hex64[:20], "x5:" + hex64[:20]} {
		_, err := audit.ParseHeadPrefix(bad)
		assert.Error(t, err, "%q", bad)
	}
}

func TestParseHeadStaysStrict(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	for _, n := range []int{16, 63} {
		_, err := audit.ParseHead("5:" + hex64[:n])
		assert.Error(t, err, "ParseHead takes only the full hash (%d digits refused)", n)
	}
	h, err := audit.ParseHead("5:" + hex64)
	require.NoError(t, err)
	assert.Equal(t, audit.Head{Seq: 5, Hash: hex64}, h)
}
