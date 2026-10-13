package inventory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/certs"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

func TestACMEFailureBackoff(t *testing.T) {
	for failures, want := range map[int]time.Duration{-1: 0, 0: 0, 1: time.Hour, 2: 2 * time.Hour, 3: 4 * time.Hour, 4: 8 * time.Hour,
		5: 16 * time.Hour, 6: 24 * time.Hour, 7: 24 * time.Hour, 1000: 24 * time.Hour} {
		assert.Equal(t, want, ACMEFailureBackoff(failures), failures)
	}
}

func TestACMEOrderErrorCode(t *testing.T) {
	rate := &ACMEError{Reason: acme.ReasonCARateLimited, RetryAfter: 48 * time.Hour}
	for _, tc := range []struct {
		err   error
		code  string
		after time.Duration
	}{
		{nil, "internal.unexpected", 0},
		{license.ErrLocked, ACMELicenseLocked, 0},
		{fmt.Errorf("wrapped: %w", license.ErrUnclassified), ACMELicenseLocked, 0},
		{rate, acme.ReasonCARateLimited, MaxACMEBackoff},
		{&acme.Error{Reason: acme.ReasonValidationFailedDNS}, acme.ReasonValidationFailedDNS, 0},
		{&acme.Error{Reason: "acme.something_new"}, acme.ReasonDirectoryInvalid, 0},
		{ErrACMENameNotAllowed, acme.ReasonNameNotAllowed, 0},
		{ErrACMEChallengeUnavailable, acme.ReasonChallengeUnavailable, 0},
		{ErrACMEAccountState, "acme.account_state", 0},
		{ErrACMERolloverPending, "acme.rollover_pending", 0},
		{ErrACMEProviderBusy, "acme.rollover_pending", 0},
		{ErrACMESecretUnreadable, "acme.secret_unreadable", 0},
		{errPendingKeySeal, "acme.secret_unreadable", 0},
		{keygen.ErrKeyPolicy, acme.ReasonKeyPolicyNotAllowed, 0},
		{ErrACMEPendingKey, ACMEOrderAbandoned, 0},
		{ErrACMEChainMismatch, acme.ReasonDirectoryInvalid, 0},
		{certs.ErrExpired, acme.ReasonDirectoryInvalid, 0},
		{context.DeadlineExceeded, acme.ReasonNotIssuedInTime, 0},
		{providers.NewError("ssh.unreachable", true, nil, nil), "ssh.unreachable", 0},
		{providers.NewError("not a code!", true, nil, nil), "internal.unexpected", 0},
		{errors.New("a database said something"), "internal.unexpected", 0},
	} {
		code, after := ACMEOrderErrorCode(tc.err)
		assert.Equal(t, tc.code, code, "%v", tc.err)
		assert.Equal(t, tc.after, after, "%v", tc.err)
	}
	assert.True(t, ACMEFinishRefused(ErrACMEChainMismatch))
	assert.True(t, ACMEFinishRefused(fmt.Errorf("x: %w", certs.ErrInvalid)))
	assert.False(t, ACMEFinishRefused(errors.New("inventory: record the ACME certificate's issuance: connection reset")))
}

func TestACMECertFieldValidation(t *testing.T) {
	names, fe := normACMENames("names", []string{" www.Example.test ", "*.example.test"})
	assert.Nil(t, fe)
	assert.Equal(t, []string{"www.example.test", "*.example.test"}, names)
	assert.True(t, hasWildcard(names))
	assert.False(t, hasWildcard([]string{"a.example.test"}))
	_, errs, verrs := patchACMECert(ACMECertificate{Names: []string{"a.example.test"}, KeyType: "ecdsa_p256", Challenge: "dns01",
		RenewBeforeDays: 30}, ACMECertificatePatch{Names: &[]string{}})
	assert.Nil(t, errs)
	assert.Equal(t, validate.Errors{{Field: "names", Code: validate.Required}, {Field: "hook_id", Code: validate.Required},
		{Field: "provider_id", Code: validate.Required}}, verrs)
}
