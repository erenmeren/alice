package auth

import (
	"bytes"
	"image/png"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 6238 Appendix B secret ("12345678901234567890") in base32.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func codeAt(t *testing.T, secret string, step int64) string {
	t.Helper()
	c, err := hotp.GenerateCodeCustom(secret, uint64(step), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)
	return c
}

func TestVerifyTOTPKnownAnswer(t *testing.T) {
	// RFC 6238: T = 59 s → 94287082 (8 digits); the 6-digit code is the last six digits.
	step, ok := VerifyTOTP(rfcSecret, "287082", time.Unix(59, 0), 0)
	assert.True(t, ok)
	assert.Equal(t, int64(1), step)
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 10, 0, time.UTC)
	cur := now.Unix() / 30

	// Current code accepted once; the same code (same step) is then rejected.
	step, ok := VerifyTOTP(rfcSecret, codeAt(t, rfcSecret, cur), now, 0)
	require.True(t, ok)
	assert.Equal(t, cur, step)
	_, ok = VerifyTOTP(rfcSecret, codeAt(t, rfcSecret, cur), now, step)
	assert.False(t, ok, "a code must not be accepted twice")

	// The next step's code works after the current one was used.
	step2, ok := VerifyTOTP(rfcSecret, codeAt(t, rfcSecret, cur+1), now.Add(30*time.Second), step)
	assert.True(t, ok)
	assert.Equal(t, cur+1, step2)

	// A code from the previous step is accepted when newer than the last used step…
	step3, ok := VerifyTOTP(rfcSecret, codeAt(t, rfcSecret, cur-1), now, cur-2)
	assert.True(t, ok)
	assert.Equal(t, cur-1, step3)
	// …and rejected once the current step was used.
	_, ok = VerifyTOTP(rfcSecret, codeAt(t, rfcSecret, cur-1), now, cur)
	assert.False(t, ok)

	// ±1 step skew: next step accepted, two steps away rejected.
	_, ok = VerifyTOTP(rfcSecret, codeAt(t, rfcSecret, cur+1), now, 0)
	assert.True(t, ok)
	_, ok = VerifyTOTP(rfcSecret, codeAt(t, rfcSecret, cur+2), now, 0)
	assert.False(t, ok)
	_, ok = VerifyTOTP(rfcSecret, codeAt(t, rfcSecret, cur-2), now, 0)
	assert.False(t, ok)
}

func TestVerifyTOTPRejectsMalformedCodes(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 10, 0, time.UTC)
	good := codeAt(t, rfcSecret, now.Unix()/30)
	for _, c := range []string{"", good[:5], good + "0", "12a456", " " + good[1:], "１２３４５６", "-12345"} {
		_, ok := VerifyTOTP(rfcSecret, c, now, 0)
		assert.False(t, ok, "%q", c)
	}
	_, ok := VerifyTOTP("not base32!", good, now, 0)
	assert.False(t, ok, "a malformed secret never verifies")
}

func TestNewTOTP(t *testing.T) {
	e, err := NewTOTP("admin")
	require.NoError(t, err)
	assert.Len(t, e.Secret, 32, "160-bit secret in unpadded base32")
	assert.NotContains(t, e.Secret, "=")

	u, err := url.Parse(e.URI)
	require.NoError(t, err)
	assert.Equal(t, "otpauth", u.Scheme)
	assert.Equal(t, "totp", u.Host)
	assert.Equal(t, "/Alice:admin", u.Path)
	q := u.Query()
	assert.Equal(t, e.Secret, q.Get("secret"))
	assert.Equal(t, "Alice", q.Get("issuer"))
	assert.Equal(t, "SHA1", q.Get("algorithm"))
	assert.Equal(t, "6", q.Get("digits"))
	assert.Equal(t, "30", q.Get("period"))

	img, err := png.Decode(bytes.NewReader(e.QRPNG))
	require.NoError(t, err)
	assert.Equal(t, 256, img.Bounds().Dx())
	assert.Equal(t, 256, img.Bounds().Dy())

	other, err := NewTOTP("admin")
	require.NoError(t, err)
	assert.NotEqual(t, e.Secret, other.Secret)

	// A freshly generated secret verifies with its own current code.
	now := time.Now()
	_, ok := VerifyTOTP(e.Secret, codeAt(t, e.Secret, now.Unix()/30), now, 0)
	assert.True(t, ok)
	assert.False(t, strings.Contains(e.URI, " "))
}
