package inventory

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/secrets"
)

const (
	testTenant      = "1111aaaa-2222-bbbb-3333-cccc4444dddd"
	testTenantUpper = "1111AAAA-2222-BBBB-3333-CCCC4444DDDD"
	testClient      = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testClientUpper = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
)

func goodSecretVault() NewVault {
	return NewVault{Name: "Prod vault", VaultURL: "https://Contoso.vault.azure.net/", Auth: providers.AzureAuthClientSecret,
		TenantID: " " + testTenantUpper + " ", ClientID: testClient, ClientSecret: secrets.NewPlaintext([]byte("s3cret-value"))}
}

type fieldCode struct{ field, code string }

func codesOf(errs validate.Errors) []fieldCode {
	out := make([]fieldCode, 0, len(errs))
	for _, e := range errs {
		out = append(out, fieldCode{e.Field, e.Code})
	}
	return out
}

func TestValidateNewVaultAcceptsAndNormalizes(t *testing.T) {
	in := goodSecretVault()
	out, v, errs := validateNewVault(in)
	require.Empty(t, errs)
	assert.Equal(t, "Prod vault", out.Name)
	assert.Equal(t, "https://contoso.vault.azure.net", v.URL)
	assert.Equal(t, testTenant, out.TenantID, "GUIDs are stored in their canonical lower-case form")
	assert.Equal(t, 15, out.PollIntervalMinutes, "0 means the default of 15 minutes")

	in.PollIntervalMinutes = 5
	out, _, errs = validateNewVault(in)
	require.Empty(t, errs)
	assert.Equal(t, 5, out.PollIntervalMinutes)
}

func TestValidateNewVaultTable(t *testing.T) {
	tooLong := secrets.NewPlaintext([]byte(strings.Repeat("x", 1025)))
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		mod  func(*NewVault)
		want []fieldCode
	}{
		{"empty name", func(n *NewVault) { n.Name = "  " }, []fieldCode{{"name", validate.Required}}},
		{"control character in the name", func(n *NewVault) { n.Name = "a\u202eb" }, []fieldCode{{"name", validate.Pattern}}},
		{"vault address with a port", func(n *NewVault) { n.VaultURL = "https://contoso.vault.azure.net:8443" }, []fieldCode{{"vault_url", validate.Pattern}}},
		{"vault address of another host", func(n *NewVault) { n.VaultURL = "https://contoso.vault.azure.net.evil.test" }, []fieldCode{{"vault_url", validate.Pattern}}},
		{"vault address over http", func(n *NewVault) { n.VaultURL = "http://contoso.vault.azure.net" }, []fieldCode{{"vault_url", validate.Pattern}}},
		{"vault address missing", func(n *NewVault) { n.VaultURL = "" }, []fieldCode{{"vault_url", validate.Required}}},
		{"unknown sign-in method", func(n *NewVault) { n.Auth = "password" }, []fieldCode{{"auth", validate.OneOf}}},
		{"missing sign-in method", func(n *NewVault) { n.Auth = "" }, []fieldCode{{"auth", validate.OneOf}}},
		{"tenant as a domain", func(n *NewVault) { n.TenantID = "contoso.onmicrosoft.com" }, []fieldCode{{"tenant_id", validate.Pattern}}},
		{"tenant missing", func(n *NewVault) { n.TenantID = "" }, []fieldCode{{"tenant_id", validate.Required}}},
		{"client as a name", func(n *NewVault) { n.ClientID = "my-app" }, []fieldCode{{"client_id", validate.Pattern}}},
		{"client missing", func(n *NewVault) { n.ClientID = "" }, []fieldCode{{"client_id", validate.Required}}},
		{"client secret missing", func(n *NewVault) { n.ClientSecret = secrets.Plaintext{} }, []fieldCode{{"client_secret", validate.Required}}},
		{"client secret too long", func(n *NewVault) { n.ClientSecret = tooLong }, []fieldCode{{"client_secret", validate.TooLong}}},
		{"certificate given with a client secret", func(n *NewVault) { n.Certificate = certs.Upload{PFX: []byte{1}} }, []fieldCode{{"certificate", validate.Pattern}}},
		{"poll interval below the range", func(n *NewVault) { n.PollIntervalMinutes = 4 }, []fieldCode{{"poll_interval_minutes", validate.OutOfRange}}},
		{"poll interval above the range", func(n *NewVault) { n.PollIntervalMinutes = 1441 }, []fieldCode{{"poll_interval_minutes", validate.OutOfRange}}},
		{"negative poll interval", func(n *NewVault) { n.PollIntervalMinutes = -1 }, []fieldCode{{"poll_interval_minutes", validate.OutOfRange}}},
		{"certificate method needs a certificate", func(n *NewVault) {
			n.Auth, n.ClientSecret = providers.AzureAuthCertificate, secrets.Plaintext{}
		}, []fieldCode{{"certificate", validate.Required}}},
		{"certificate method refuses a client secret", func(n *NewVault) {
			n.Auth, n.Certificate = providers.AzureAuthCertificate, certs.Upload{PFX: []byte{1}}
		}, []fieldCode{{"client_secret", validate.Pattern}}},
		{"expiry only with a client secret", func(n *NewVault) {
			n.Auth, n.ClientSecret, n.Certificate = providers.AzureAuthCertificate, secrets.Plaintext{}, certs.Upload{PFX: []byte{1}}
			n.SecretExpiresOn = &exp
		}, []fieldCode{{"secret_expires_on", validate.Pattern}}},
		{"managed identity refuses a client secret", func(n *NewVault) {
			n.Auth, n.TenantID = providers.AzureAuthManagedIdentity, ""
		}, []fieldCode{{"client_secret", validate.Pattern}}},
		{"managed identity refuses a tenant", func(n *NewVault) {
			n.Auth, n.ClientSecret = providers.AzureAuthManagedIdentity, secrets.Plaintext{}
		}, []fieldCode{{"tenant_id", validate.Pattern}}},
		{"managed identity refuses a certificate", func(n *NewVault) {
			n.Auth, n.ClientSecret, n.TenantID, n.Certificate = providers.AzureAuthManagedIdentity, secrets.Plaintext{}, "", certs.Upload{PFX: []byte{1}}
		}, []fieldCode{{"certificate", validate.Pattern}}},
		{"several problems are all reported", func(n *NewVault) { n.Name, n.TenantID, n.PollIntervalMinutes = "", "x", 3 },
			[]fieldCode{{"name", validate.Required}, {"tenant_id", validate.Pattern}, {"poll_interval_minutes", validate.OutOfRange}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := goodSecretVault()
			tc.mod(&in)
			_, _, errs := validateNewVault(in)
			assert.Equal(t, tc.want, codesOf(errs))
		})
	}
}

func TestValidateNewVaultOptionalClientForManagedIdentity(t *testing.T) {
	in := NewVault{Name: "mi", VaultURL: "contoso", Auth: providers.AzureAuthManagedIdentity}
	out, _, errs := validateNewVault(in)
	require.Empty(t, errs, "the user-assigned client ID is optional")
	assert.Empty(t, out.ClientID)

	in.ClientID = testClientUpper
	out, _, errs = validateNewVault(in)
	require.Empty(t, errs)
	assert.Equal(t, testClient, out.ClientID)

	in.ClientID = "not-a-guid"
	_, _, errs = validateNewVault(in)
	assert.Equal(t, []fieldCode{{"client_id", validate.Pattern}}, codesOf(errs))
}

func TestValidateNewVaultAcceptsACertificateUpload(t *testing.T) {
	in := goodSecretVault()
	in.Auth, in.ClientSecret = providers.AzureAuthCertificate, secrets.Plaintext{}
	in.Certificate = certs.Upload{CertificatePEM: []byte("x"), PrivateKeyPEM: []byte("y")}
	_, _, errs := validateNewVault(in)
	assert.Empty(t, errs, "the certificate itself is parsed later, by certs")
}

func TestPollIntervalValidation(t *testing.T) {
	for _, m := range []int{5, 15, 1440} {
		assert.Nil(t, validPollMinutes(m), m)
	}
	for _, m := range []int{0, 4, 1441, -5} {
		fe := validPollMinutes(m)
		require.NotNil(t, fe, m)
		assert.Equal(t, validate.OutOfRange, fe.Code)
		assert.Equal(t, map[string]string{"min": "5", "max": "1440"}, fe.Params)
	}
}

func TestVaultCheckOutcome(t *testing.T) {
	ok := func(name string) providers.AzureCheck {
		return providers.AzureCheck{Name: name, Result: providers.AzureResultOK}
	}
	tests := []struct {
		name       string
		facts      *providers.AzureFacts
		wantStatus string
		wantCode   string
	}{
		{"nothing known", nil, StatusOK, ""},
		{"all ok", &providers.AzureFacts{Checks: []providers.AzureCheck{ok("sign_in"), ok("list_certificates")}}, StatusOK, ""},
		{"not checked rows do not degrade", &providers.AzureFacts{Checks: []providers.AzureCheck{ok("sign_in"),
			{Name: providers.AzureCheckImport, Result: providers.AzureResultNotChecked}}}, StatusOK, ""},
		{"a forbidden row degrades", &providers.AzureFacts{Checks: []providers.AzureCheck{ok("sign_in"),
			{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultForbidden, Reason: "azure.forbidden", Role: providers.RoleKeyVaultReader}}},
			StatusDegraded, "azure.forbidden"},
		{"a forbidden row without a reason still names one", &providers.AzureFacts{Checks: []providers.AzureCheck{
			{Name: providers.AzureCheckListKeys, Result: providers.AzureResultForbidden}}}, StatusDegraded, "azure.forbidden"},
		{"a failed row with a firewall reason", &providers.AzureFacts{Checks: []providers.AzureCheck{
			{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultFailed, Reason: "azure.firewall"}}}, StatusDegraded, "azure.firewall"},
		{"a failed row with an unsafe reason is stored as unexpected", &providers.AzureFacts{Checks: []providers.AzureCheck{
			{Name: providers.AzureCheckListKeys, Result: providers.AzureResultFailed, Reason: "Bad Reason: with text"}}}, StatusDegraded, "internal.unexpected"},
		{"the first failing row names the reason", &providers.AzureFacts{Checks: []providers.AzureCheck{
			{Name: providers.AzureCheckListKeys, Result: providers.AzureResultForbidden, Reason: "azure.forbidden"},
			{Name: providers.AzureCheckListSecrets, Result: providers.AzureResultFailed, Reason: "azure.firewall"}}}, StatusDegraded, "azure.forbidden"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, code := vaultCheckOutcome(tc.facts)
			assert.Equal(t, tc.wantStatus, status)
			assert.Equal(t, tc.wantCode, code)
		})
	}
}

func TestRowsThatRefuseTheVault(t *testing.T) {
	row := func(name, result, reason string) providers.AzureCheck {
		return providers.AzureCheck{Name: name, Result: result, Reason: reason}
	}
	refused := func(checks ...providers.AzureCheck) *providers.Error {
		return refusalFromRows(&providers.AzureFacts{Checks: checks})
	}
	assert.Nil(t, refused(row("sign_in", "ok", "")))
	assert.Nil(t, refused(row("sign_in", "ok", ""), row("list_certificates", "forbidden", "azure.forbidden")))
	assert.Nil(t, refused(row("sign_in", "ok", ""), row("list_certificates", "failed", "azure.firewall")))
	assert.Nil(t, refused(row("sign_in", "ok", ""), row("list_keys", "failed", "azure.vault_not_found")), "only the first vault call decides")

	e := refused(row("sign_in", "failed", "azure.auth_failed"))
	require.NotNil(t, e)
	assert.Equal(t, "azure.auth_failed", e.Code)
	e = refused(row("sign_in", "failed", ""))
	require.NotNil(t, e)
	assert.Equal(t, "azure.auth_failed", e.Code, "a failed sign-in row without a reason is still a failed sign-in")
	e = refused(row("sign_in", "ok", ""), row("list_certificates", "failed", "azure.vault_not_found"))
	require.NotNil(t, e)
	assert.Equal(t, "azure.vault_not_found", e.Code)
	e = refused(row("sign_in", "ok", ""), row("list_certificates", "failed", "Bad: text"))
	require.NotNil(t, e)
	assert.Equal(t, "internal.unexpected", e.Code)
	assert.Nil(t, refusalFromRows(nil))
}

func TestStorageErrorsAreMappedToClosedErrors(t *testing.T) {
	assert.ErrorIs(t, mapTargetWriteError(&pgconn.PgError{Code: "23505"}), ErrDuplicateTarget)
	assert.ErrorIs(t, mapTargetWriteError(&pgconn.PgError{Code: "Z1006"}), ErrCredentialNotTheTargets)
	assert.ErrorIs(t, mapTargetWriteError(&pgconn.PgError{Code: "Z1005"}), ErrNotAVault)
	unrelated := &pgconn.PgError{Code: "23514"}
	assert.Same(t, unrelated, mapTargetWriteError(unrelated), "every other error passes through for the caller to wrap")
	for _, code := range []string{"23505", "Z1006", "Z1005"} {
		err := mapTargetWriteError(&pgconn.PgError{Code: code})
		assert.NotContains(t, err.Error(), code, "a SQLSTATE never reaches the caller")
	}
	var pg *pgconn.PgError
	assert.False(t, errors.As(mapTargetWriteError(&pgconn.PgError{Code: "Z1006"}), &pg))
	assert.NoError(t, mapTargetWriteError(nil))
}

func TestVaultInfoKinds(t *testing.T) {
	assert.Equal(t, "azure_sp_secret", kindOf(providers.AzureAuthClientSecret))
	assert.Equal(t, "azure_sp_cert", kindOf(providers.AzureAuthCertificate))
	assert.Equal(t, "azure_managed_identity", kindOf(providers.AzureAuthManagedIdentity))
	for _, a := range []string{providers.AzureAuthClientSecret, providers.AzureAuthCertificate, providers.AzureAuthManagedIdentity} {
		assert.Equal(t, a, authOfKind(kindOf(a)))
	}
	assert.Equal(t, "", authOfKind("ssh_private_key"))
}

func TestMemorySourceHandsOutCopies(t *testing.T) {
	secret := secrets.NewPlaintext([]byte("abc"))
	src := memorySource{id: providers.AzureIdentity{Auth: providers.AzureAuthClientSecret, TenantID: testTenant, ClientID: testClient, ClientSecret: secret}}
	got, release, err := src.AzureIdentity(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "abc", string(got.ClientSecret.Bytes()))
	release()
	assert.Equal(t, "abc", string(secret.Bytes()), "the pre-flight's release must not clear the caller's secret, which is sealed afterwards")
	assert.Zero(t, countNonZero(got.ClientSecret.Bytes()), "what was handed out is zeroed")
	_, _, err = src.SSHSigner(t.Context())
	assert.ErrorIs(t, err, errNotAnSSHTarget)
}

func countNonZero(b []byte) int {
	n := 0
	for _, c := range b {
		if c != 0 {
			n++
		}
	}
	return n
}
