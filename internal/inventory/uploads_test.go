package inventory

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/i18n"
	"alice/internal/platform/validate"
	"alice/locales"
)

// Every refusal of the certs package has its reason and a specific error; none is left to be
// reported as an internal error.
func TestEveryCertsRefusalHasAReason(t *testing.T) {
	for _, tc := range []struct {
		in     error
		reason string
		out    error
	}{
		{certs.ErrInvalid, "invalid", ErrCertificateInvalid},
		{fmt.Errorf("%w: no certificate found", certs.ErrInvalid), "invalid", ErrCertificateInvalid},
		{certs.ErrKeyMismatch, "key_mismatch", ErrKeyMismatch},
		{certs.ErrExpired, "expired", ErrCertificateExpired},
		{certs.ErrKeyEncrypted, "key_encrypted", ErrKeyEncrypted},
		{certs.ErrPFXPassword, "pfx_password", ErrPFXPassword},
		{certs.ErrWeak, "weak", ErrWeakCertificate},
		{certs.ErrUnsupportedKey, "unsupported_key", ErrUnsupportedKey},
		{certs.ErrTooLarge, "too_large", ErrCertificateTooLarge},
		{certs.ErrCSRMismatch, "csr_mismatch", ErrCSRMismatch},
		{errors.New("something certs never returns"), "invalid", ErrCertificateInvalid},
	} {
		reason, out := refusal(tc.in)
		assert.Equal(t, tc.reason, reason, "%v", tc.in)
		assert.ErrorIs(t, out, tc.out, "%v", tc.in)
	}
	// D21: no key is the field error of a missing key.
	reason, out := refusal(certs.ErrNoKey)
	assert.Equal(t, "validation", reason)
	var verrs validate.Errors
	require.ErrorAs(t, out, &verrs)
	assert.Equal(t, validate.Errors{{Field: "private_key_pem", Code: validate.Required}}, verrs)
}

func TestKeyInCertificateCodeIsTranslated(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for _, lang := range []string{"en", "tr"} {
		assert.NotEqual(t, CodeKeyInCertificate, cat.T(lang, CodeKeyInCertificate, nil), lang)
	}
}

func TestKeyTriggerSQLStatesAreMapped(t *testing.T) {
	wrap := func(code string) error { return fmt.Errorf("exec: %w", &pgconn.PgError{Code: code}) }
	assert.ErrorIs(t, keyTriggerError(wrap("Z1001")), ErrKeyMismatch)
	assert.ErrorIs(t, keyTriggerError(wrap("Z1002")), ErrCertificateDuplicate)
	other := wrap("23505")
	assert.Same(t, other, keyTriggerError(other), "unmapped errors pass through")
	plain := errors.New("x")
	assert.Same(t, plain, keyTriggerError(plain))
}
