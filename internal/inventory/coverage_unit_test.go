package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// The incident engine keeps a closed code on a location for every refusal of RequestDeployment that belongs to the
// location or the certificate (isRefusal), and a database failure is never one. Each refusal, bare or wrapped in the
// *LocationRefusalError that names its location, maps to the API's reason of the same error.
func TestIncidentRefusalCodes(t *testing.T) {
	loc := uuid.New()
	for _, tc := range []struct {
		err     error
		refusal bool
		code    string
	}{
		{&KeyTypeMismatchError{Expected: "rsa", Actual: "ecdsa"}, true, IncidentCodeNotDeployable},
		{ErrLocationUnsupported, true, "nginx.location_unsupported"},
		{ErrNginxConfigInvalid, true, "nginx.config_invalid"},
		{ErrLocationNeedsDiscovery, true, "deployment.rescan_needed"},
		{ErrChainUnconfirmed, true, "certificate.chain_unconfirmed"},
		{ErrCertificateExpired, true, "certificate.expired"},
		{ErrCertificateNotYetValid, true, "certificate.not_yet_valid"},
		{ErrNoPrivateKey, true, "certificate.no_private_key"},
		{ErrUnsupportedKey, true, "certificate.unsupported_key"},
		{ErrCertificateRevoked, true, ReasonCertificateRevoked},
		{ErrCertificateCompromised, true, ReasonCertificateCompromised},
		{ErrNotFound, true, "system.not_found"},
		{ErrTargetDisabled, true, "internal.unexpected"},
		{ErrTargetNotReady, false, "deployment.target_not_ready"},
		{ErrACMEAccountState, false, "acme.account_state"},
		{ErrACMERolloverPending, false, "acme.rollover_pending"},
		{errors.New("connection reset"), false, "internal.unexpected"},
	} {
		assert.Equal(t, tc.refusal, isRefusal(tc.err), "%v", tc.err)
		assert.Equal(t, tc.code, codeOf(tc.err), "%v", tc.err)
		wrapped := &LocationRefusalError{LocationID: loc, Err: tc.err}
		assert.True(t, isRefusal(wrapped), "a refusal naming a location is always the location's: %v", tc.err)
		assert.Equal(t, tc.code, codeOf(wrapped), "%v", tc.err)
	}
	assert.True(t, isRefusal(fmt.Errorf("context: %w", ErrNotFound)))
}

// A failed revocation is recorded with a closed code: the CA's reason, an inventory refusal, an unreachable CA for a
// context that ended, and unexpected for anything else.
func TestRevokeErrorCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{&ACMEError{Reason: acme.ReasonRevokeUnsupported}, acme.ReasonRevokeUnsupported},
		{fmt.Errorf("revoke: %w", &ACMEError{Reason: acme.ReasonProviderUnreachable}), acme.ReasonProviderUnreachable},
		{ErrACMEAccountState, "acme.account_state"},
		{ErrACMERolloverPending, "acme.rollover_pending"},
		{ErrACMESecretUnreadable, "acme.secret_unreadable"},
		{context.DeadlineExceeded, acme.ReasonProviderUnreachable},
		{context.Canceled, acme.ReasonProviderUnreachable},
		{errors.New("disk full"), "internal.unexpected"},
	} {
		assert.Equal(t, tc.code, revokeErrorCode(tc.err), "%v", tc.err)
	}
}

// A deployment record keeps the trust a provider reported only within the closed lists (R51): an unknown status,
// reason or store is blank, a reason only with untrusted, and the port only with a reason and in range.
func TestRecordedTrust(t *testing.T) {
	port := func(p int) *int { return &p }
	for _, tc := range []struct {
		name string
		in   providers.Trust
		want providers.Trust
		port *int
	}{
		{"trusted", providers.Trust{Status: providers.TrustTrusted, Store: providers.TrustStoreSystem, Enforced: true, Port: 443},
			providers.Trust{Status: providers.TrustTrusted, Store: providers.TrustStoreSystem, Enforced: true}, nil},
		{"untrusted with its reason and port",
			providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrIncompleteChain, Port: 8443, Store: providers.TrustStoreACME},
			providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrIncompleteChain, Port: 8443, Store: providers.TrustStoreACME}, port(8443)},
		{"a port out of range is dropped", providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrExpired, Port: 70000},
			providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrExpired}, nil},
		{"no port", providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrExpired},
			providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrExpired}, nil},
		{"untrusted without a reason is blank", providers.Trust{Status: providers.TrustUntrusted, Port: 443}, providers.Trust{}, nil},
		{"a reason without untrusted is blank", providers.Trust{Status: providers.TrustTrusted, Error: providers.TrustErrChainOrder},
			providers.Trust{}, nil},
		{"values outside the lists", providers.Trust{Status: "maybe", Error: "<script>", Store: "/etc/ssl", Port: 443},
			providers.Trust{}, nil},
		{"an unknown reason blanks untrusted", providers.Trust{Status: providers.TrustUntrusted, Error: "bad", Port: 443},
			providers.Trust{}, nil},
		{"unchecked", providers.Trust{Status: providers.TrustUnchecked, Store: providers.TrustStoreUploadedRoot},
			providers.Trust{Status: providers.TrustUnchecked, Store: providers.TrustStoreUploadedRoot}, nil},
	} {
		got, p := recordedTrust(tc.in)
		assert.Equal(t, tc.want, got, tc.name)
		assert.Equal(t, tc.port, p, tc.name)
	}
}

// The closed reason of a refused Key Vault precheck covers every refusal; anything else is "refused".
func TestPrecheckReason(t *testing.T) {
	for err, want := range map[error]string{
		ErrBindingGone: "binding_gone", ErrAutoDeployOff: "auto_deploy_off", ErrVaultUnavailable: "vault_unavailable",
		ErrKVCertificateMissing: "certificate_missing", ErrVersionDisabled: "version_disabled", ErrCertificateExpired: "expired",
		ErrCertificateNotYetValid: "not_yet_valid", ErrVersionHeld: "version_held", ErrVersionSuperseded: "version_superseded",
		ErrWaveStopped: "wave_stopped", errors.New("other"): "refused",
	} {
		assert.Equal(t, want, precheckReason(fmt.Errorf("precheck: %w", err)), "%v", err)
	}
}

// A rollback restores the key type of the certificate it puts back; without a recorded one it is the new
// certificate's (the location never held another type).
func TestMaterialOldKeyType(t *testing.T) {
	assert.Equal(t, "ecdsa", Material{KeyType: "ecdsa"}.oldKeyType())
	assert.Equal(t, "rsa", Material{KeyType: "ecdsa", OldKeyType: "rsa"}.oldKeyType())
}

// The summary e-mail's kind is the suffix of its key; a key without a known kind has none.
func TestNoticeKind(t *testing.T) {
	v := uuid.New().String()
	for key, want := range map[string]string{v + "/new": "new", v + "/stopped": "stopped", v + "/skipped": "skipped", v + "/other": "", "new": ""} {
		assert.Equal(t, want, noticeKind2(key), key)
	}
}

// An error's params keep only the allowed keys, without control characters (a helper's text never reaches a log raw).
func TestBoundParamsDropsControlCharacters(t *testing.T) {
	got := boundParams(map[string]string{"port": "44\x003\n", "secret": "x", "phase": "commit\x7fted"}, errorParamKeys)
	assert.Equal(t, map[string]string{"port": "443", "phase": "committed"}, got)
}

// The whitespace a paste brings before an HMAC key is dropped too (TestNormEAB has the trailing padding and the
// refusals).
func TestNormEABTrimsLeadingWhitespace(t *testing.T) {
	key := "c2VjcmV0LWhtYWMta2V5LTMyLWJ5dGVzLWxvbmctZW5vdWdo"
	kid, text, errs := normEAB(&ACMEEABInput{KID: "kid-1", HMAC: secrets.NewPlaintext([]byte("\r\n  " + key + "==\r\n"))})
	require.Empty(t, errs)
	assert.Equal(t, "kid-1", kid)
	assert.Equal(t, key, string(text))
}

// The closed lists the API registers: the incident's codes and the ACME renewal e-mails, each once, in their namespace.
func TestClosedListsOfIncidentsAndACMEMails(t *testing.T) {
	codes := IncidentCodes()
	require.Len(t, codes, 9)
	assert.Len(t, slices.Compact(slices.Sorted(slices.Values(codes))), len(codes), "each code once")
	for _, c := range codes {
		assert.True(t, strings.HasPrefix(c, "incident."), c)
	}
	mails := ACMETemplates()
	require.NotEmpty(t, mails)
	assert.Len(t, slices.Compact(slices.Sorted(slices.Values(mails))), len(mails), "each template once")
	for _, m := range mails {
		assert.True(t, strings.HasPrefix(m, "acme."), m)
		assert.NotContains(t, Templates(), m, "the ACME mails have their own params")
	}
	assert.Equal(t, acme.ReplacesOutcomes(), ACMEReplacesOutcomes())
}
