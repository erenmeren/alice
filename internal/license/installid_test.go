package license_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// lowerASCII lower-cases ASCII letters (strings.ToLower is banned repo-wide).
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func idBody(id string) string { return strings.ReplaceAll(strings.TrimPrefix(id, "ALICE-"), "-", "") }

func TestNewInstallationIDFormat(t *testing.T) {
	re := regexp.MustCompile(`^ALICE(-[0-9A-HJKMNP-TV-Z]{4}){4}$`)
	seen := map[string]bool{}
	for range 1000 {
		id := license.NewInstallationID()
		require.Regexp(t, re, id)
		got, err := license.ParseInstallationID(id)
		require.NoError(t, err)
		require.Equal(t, id, got)
		require.False(t, seen[id], "IDs are random")
		seen[id] = true
	}
}

func TestParseInstallationIDNormalizesHandTypedInput(t *testing.T) {
	id := license.NewInstallationID()
	body := idBody(id)
	for _, typed := range []string{
		id,
		"  " + id + "\t",
		lowerASCII(id),
		body,
		body[:4] + " " + body[4:8] + " " + body[8:12] + " " + body[12:],
		"alice " + lowerASCII(body),
		strings.NewReplacer("0", "O", "1", "l").Replace(id), // Crockford: O means 0, I and L mean 1
		strings.NewReplacer("1", "I").Replace(id),
	} {
		got, err := license.ParseInstallationID(typed)
		require.NoError(t, err, typed)
		assert.Equal(t, id, got, typed)
	}
}

// Review Focus 4: a real typo is caught by the check character.
func TestInstallationIDDetectsTypos(t *testing.T) {
	for range 20 {
		chars := []byte(idBody(license.NewInstallationID()))
		for i := range chars {
			for j := 0; j < len(crockford); j++ {
				if crockford[j] == chars[i] {
					continue
				}
				typo := append([]byte(nil), chars...)
				typo[i] = crockford[j]
				_, err := license.ParseInstallationID(string(typo))
				require.ErrorIs(t, err, license.ErrInvalidInstallationID, "substitution at %d", i)
			}
		}
		for i := 0; i+1 < len(chars); i++ {
			a, b := chars[i], chars[i+1]
			// "0Z"/"Z0" is the one neighbour swap Luhn mod 32 cannot see.
			if a == b || (a == '0' && b == 'Z') || (a == 'Z' && b == '0') {
				continue
			}
			swapped := append([]byte(nil), chars...)
			swapped[i], swapped[i+1] = b, a
			_, err := license.ParseInstallationID(string(swapped))
			require.ErrorIs(t, err, license.ErrInvalidInstallationID, "transposition at %d", i)
		}
	}
}

func TestParseInstallationIDRejectsMalformedInput(t *testing.T) {
	id := license.NewInstallationID()
	for _, bad := range []string{
		"", "ALICE-", id[:len(id)-1], id + "0", id[:len(id)-1] + "U", "ALİCE-" + idBody(id), strings.Replace(id, "-", "_", 1),
	} {
		_, err := license.ParseInstallationID(bad)
		assert.ErrorIs(t, err, license.ErrInvalidInstallationID, bad)
	}
}
