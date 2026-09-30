package auth

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"image/png"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// TOTPIssuer is the issuer shown in authenticator apps.
const TOTPIssuer = "Alice"

// TOTP parameters (SEC-006): RFC 6238 with SHA-1, 6 digits, 30-second steps.
const (
	totpPeriod     = 30
	totpDigits     = 6
	totpSecretSize = 20 // 160 bits (SEC-007)
	totpQRSize     = 256
)

// TOTPEnrollment is what a user needs to add Alice to an authenticator app.
// It is shown once and must never be logged.
type TOTPEnrollment struct {
	Secret string // base32 without padding (32 characters)
	URI    string // otpauth://totp/Alice:<account>?...
	QRPNG  []byte // 256x256 PNG of URI
}

// NewTOTP creates a fresh 160-bit TOTP secret for accountName.
func NewTOTP(accountName string) (TOTPEnrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: accountName,
		Period:      totpPeriod,
		SecretSize:  totpSecretSize,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("generate TOTP secret: %w", err)
	}
	img, err := key.Image(totpQRSize, totpQRSize)
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("render TOTP QR code: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return TOTPEnrollment{}, fmt.Errorf("encode TOTP QR code: %w", err)
	}
	return TOTPEnrollment{Secret: key.Secret(), URI: key.URL(), QRPNG: buf.Bytes()}, nil
}

// VerifyTOTP checks code against secret at now, accepting the current step and
// one step either side. Only steps strictly greater than lastStep are accepted,
// so a code (or an older one) can never be replayed (SEC-006). On success it
// returns the matched step, which the caller stores as the new lastStep.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if !isDigits(code, totpDigits) {
		return 0, false
	}
	current := now.Unix() / totpPeriod
	for _, step := range []int64{current - 1, current, current + 1} {
		if step <= lastStep || step < 0 {
			continue
		}
		want, err := hotp.GenerateCodeCustom(secret, uint64(step), hotp.ValidateOpts{ //nolint:gosec // G115: step >= 0 checked above
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false // malformed secret
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func isDigits(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
