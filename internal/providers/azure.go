package providers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"alice/internal/secrets"
)

// Sign-in methods of a vault's credential (R40 rows 4, 9).
const (
	AzureAuthClientSecret    = "client_secret"
	AzureAuthCertificate     = "certificate"
	AzureAuthManagedIdentity = "managed_identity"
)

// AzureIdentity is the identity Alice signs in to Azure with for one vault. It carries secrets:
// Format and LogValue print the method and the IDs only, the secret fields are Plaintext and have
// no JSON form, and Zero clears them in place.
type AzureIdentity struct {
	Auth           string            // AzureAuth*
	TenantID       string            // a GUID; "" for a managed identity
	ClientID       string            // the application (client) ID; for a managed identity the optional user-assigned client ID
	ClientSecret   secrets.Plaintext `json:"-"` // AzureAuthClientSecret
	CertificateDER []byte            `json:"-"` // AzureAuthCertificate: the registered certificate (public)
	PrivateKeyDER  secrets.Plaintext `json:"-"` // AzureAuthCertificate: its RSA key, PKCS #8
}

func (a AzureIdentity) redacted() string {
	return fmt.Sprintf("providers.AzureIdentity{auth:%s, tenant:%s, client:%s, secret:[redacted]}", a.Auth, a.TenantID, a.ClientID)
}

// Format prints the method and the IDs only, for every verb and flag (pointers too).
func (a AzureIdentity) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, a.redacted()) }

// LogValue keeps the secrets out of slog output.
func (a AzureIdentity) LogValue() slog.Value { return slog.StringValue(a.redacted()) }

// Zero clears the client secret and the private key in place.
func (a AzureIdentity) Zero() {
	a.ClientSecret.Zero()
	a.PrivateKeyDER.Zero()
}

// AzureCredentialSource is implemented by the credential source of a vault. release zeroes what was
// decrypted; the caller calls it as soon as the SDK credential is built.
type AzureCredentialSource interface {
	AzureIdentity(ctx context.Context) (AzureIdentity, func(), error)
}

// NewSecret wraps bytes a provider received (a vault secret value) in a Plaintext holder; the
// azurekv provider may not import internal/secrets (archtest), so it builds holders through here.
// The holder shares b: whoever owns the bytes zeroes them.
func NewSecret(b []byte) secrets.Plaintext { return secrets.NewPlaintext(b) }

// SecretRequest names one version of a vault certificate.
type SecretRequest struct{ Name, Version string }

// CertificateSecret is the backing secret of a vault certificate version. Value is base64 PFX or
// PEM text exactly as the vault returned it; Format and LogValue print the content type only.
type CertificateSecret struct {
	ContentType string            // "application/x-pkcs12" | "application/x-pem-file" | anything the vault says
	Value       secrets.Plaintext `json:"-"`
}

func (c CertificateSecret) redacted() string {
	return fmt.Sprintf("providers.CertificateSecret{content_type:%s, value:[redacted]}", c.ContentType)
}

// Format prints the content type only, for every verb and flag.
func (c CertificateSecret) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, c.redacted()) }

// LogValue keeps the value out of slog output.
func (c CertificateSecret) LogValue() slog.Value { return slog.StringValue(c.redacted()) }

// Zero clears the value in place.
func (c CertificateSecret) Zero() { c.Value.Zero() }

// ImportRequest asks the vault to add a version to certificate Name from a PFX (empty password).
type ImportRequest struct {
	OperationID uuid.UUID         // = kv_imports.id (logs and steps only; the vault has no idempotency key)
	Name        string            // the certificate name in the vault
	PFX         secrets.Plaintext `json:"-"` // the caller zeroes it
	KeyType     string            // "rsa" | "ecdsa"
	KeySize     int               // RSA bits, or 256/384 for ECDSA
	// ReplaceExisting is the Administrator's explicit confirmation that Name may already exist in
	// the vault: an import then adds a version, replaces the certificate's policy and can switch
	// off the vault's own renewal (ruling S9). A provider that finds Name in the vault while this
	// is false refuses before any call that changes the vault.
	ReplaceExisting bool
}

func (r ImportRequest) redacted() string {
	return fmt.Sprintf("providers.ImportRequest{operation:%s, name:%s, pfx:[redacted]}", r.OperationID, r.Name)
}

// Format prints the operation and the name only, for every verb and flag.
func (r ImportRequest) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, r.redacted()) }

// LogValue keeps the PFX out of slog output.
func (r ImportRequest) LogValue() slog.Value { return slog.StringValue(r.redacted()) }

// Zero clears the PFX in place.
func (r ImportRequest) Zero() { r.PFX.Zero() }

// Import outcomes (a closed set; the rules are ImportResult.Validate and CheckImportReturn).
const (
	ImportCreated   = "created"   // the vault answered with the new version
	ImportRefused   = "refused"   // nothing was created: refused before the send, or a well-formed refusal from the vault
	ImportUncertain = "uncertain" // the request may have reached the vault; read the truth from a later listing
)

// ImportResult is the result of ImportCertificate.
type ImportResult struct {
	Outcome    string
	Version    string // created: the new version ID
	Thumbprint string // created: hex SHA-1 of the new version's leaf
	CER        []byte // created: the leaf DER
}

// KVKnown is what Alice stored about a vault certificate (spec §6.2, §11.6; R40 rows 15-17).
type KVKnown struct {
	Version    string    // the current version whose details Alice read
	Thumbprint string    // its x5t (hex)
	Updated    time.Time // its attributes.updated
}

// KVInventory is the Key Vault half of discovery.
type KVInventory struct {
	Certificates   []KVCertificate
	Keys           []KVKey    // when KVKeys was asked
	Secrets        []KVSecret // when KVSecrets was asked
	KeysListed     bool       // the key list was read completely
	SecretsListed  bool
	Truncated      []string // "certificates" | "keys" | "secrets" | "versions": cut at a bound; nothing of that kind is marked missing
	DetailsPending int      // certificates whose details wait for the next poll (MaxKVDetails)
	Failures       []KVListFailure
}

// KVListFailure is a listing that failed.
type KVListFailure struct {
	Object string // "certificates" | "keys" | "secrets"
	Err    *Error // azure.forbidden (F-40), azure.firewall, azure.throttled, …
}

// KVCertificate is one listed vault certificate.
type KVCertificate struct {
	Name                                 string
	Thumbprint                           string // the listing's x5t (hex)
	Enabled                              bool
	NotBefore, Expires, Created, Updated *time.Time
	Details                              *KVCertificateDetails  // set when read in this call
	Versions                             []KVCertificateVersion // set with Details when the current version differs from KVKnown (newest first, at most MaxKVVersions)
}

// KVCertificateDetails are the latest version's details.
type KVCertificateDetails struct {
	Version     string // the latest version's ID
	Thumbprint  string // its x5t (hex)
	Updated     *time.Time
	CER         []byte // the leaf DER (public)
	Exportable  *bool  // nil when the policy was not returned
	KeyType     string // "rsa" | "ecdsa" | "other" | ""
	KeySize     int
	ContentType string // "pkcs12" | "pem" | "other" | ""
	IssuerName  string
	AutoRenew   bool
}

// KVCertificateVersion is one listed version.
type KVCertificateVersion struct {
	Version, Thumbprint         string
	Enabled                     bool
	NotBefore, Expires, Created *time.Time
}

// KVKey is one listed key.
type KVKey struct {
	Name                                 string
	Enabled                              bool
	Managed                              bool
	NotBefore, Expires, Created, Updated *time.Time
	Details                              *KVKeyDetails // set when read in this call
	DetailsProblem                       string        // "forbidden" | "failed" | "" (GetKey refused or failed; R40 row 16)
}

// KVKeyDetails are a key's public details.
type KVKeyDetails struct {
	Version string
	KeyType string // "rsa" | "ec" | "oct" | "other"
	HSM     bool
	Size    int    // RSA modulus bits
	Curve   string // "P-256" | "P-256K" | "P-384" | "P-521" | "other" | ""
}

// KVSecret is one listed secret (metadata only: a vault secret's value is never read here).
type KVSecret struct {
	Name                                 string
	ContentType                          string
	Enabled                              bool
	Managed                              bool
	NotBefore, Expires, Created, Updated *time.Time
}

// AzureFacts is the vault's access check (ConnectionReport.Azure).
type AzureFacts struct {
	ObjectID        string       `json:"object_id"`        // the oid of Alice's token (display only, never trusted; a GUID or "")
	TenantID        string       `json:"tenant_id"`        // the tid of the token (a GUID or "")
	PermissionModel string       `json:"permission_model"` // "rbac" | "access_policy" | "unknown"
	Checks          []AzureCheck `json:"checks"`
	CheckedAt       time.Time    `json:"checked_at"`
}

// AzureCheck is one row of the access check.
type AzureCheck struct {
	Name   string `json:"name"`             // AzureCheck*
	Result string `json:"result"`           // AzureResult*
	Reason string `json:"reason,omitempty"` // the provider error code of a failed check
	Role   string `json:"role,omitempty"`   // the role that would allow it (forbidden)
}

// Access check rows and results.
const (
	AzureCheckSignIn           = "sign_in"
	AzureCheckListCertificates = "list_certificates"
	AzureCheckListKeys         = "list_keys"
	AzureCheckListSecrets      = "list_secrets"
	AzureCheckReadSecret       = "read_secret"
	AzureCheckImport           = "import"

	AzureResultOK         = "ok"
	AzureResultForbidden  = "forbidden"
	AzureResultFailed     = "failed"
	AzureResultNotChecked = "not_checked"
)

// Roles named in messages and the access check (spec §11.4; never translated).
const (
	RoleKeyVaultReader              = "Key Vault Reader"
	RoleKeyVaultSecretsUser         = "Key Vault Secrets User"
	RoleKeyVaultCertificatesOfficer = "Key Vault Certificates Officer"
)
