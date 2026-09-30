package auth

import (
	"errors"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"alice/internal/auth/breached"
)

// Password length limits in runes, measured after NFKC normalization (SEC-002).
const (
	MinPasswordLength = 12
	MaxPasswordLength = 128
)

// Password policy errors.
var (
	ErrPasswordTooShort = errors.New("auth: password too short")
	ErrPasswordTooLong  = errors.New("auth: password too long")
	ErrPasswordBreached = errors.New("auth: password is on the breached-password list")
)

// NormalizePassword applies Unicode NFKC so that visually identical input
// (for example full-width digits) hashes the same way on every device.
// Callers hash and verify the normalized form.
func NormalizePassword(pw string) string { return norm.NFKC.String(pw) }

// CheckPasswordPolicy enforces length and the breached-password list. There are
// no composition rules (SEC-002, SEC-003).
func CheckPasswordPolicy(pw string) error {
	n := NormalizePassword(pw)
	switch l := utf8.RuneCountInString(n); {
	case l < MinPasswordLength:
		return ErrPasswordTooShort
	case l > MaxPasswordLength:
		return ErrPasswordTooLong
	}
	if breached.Contains(n) {
		return ErrPasswordBreached
	}
	return nil
}
