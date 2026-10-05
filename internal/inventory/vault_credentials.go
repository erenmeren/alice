package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/secrets"
)

// A vault's sign-in credential (spec §11.3; R40 rows 4, 9): a client secret, a certificate with its
// RSA key, or a managed identity (nothing secret). The secret part is the credential row's sealed
// payload (the Phase 3 envelope, AAD credentials/<id>/ciphertext); everything else is
// public_info. Credentials are append-only: a replacement is a new row that the vault moves to.

const purposeAzureVault = "azure_vault"

// vaultInfo is credentials.public_info of a vault credential (never a secret).
type vaultInfo struct {
	Auth            string     `json:"auth"`
	TenantID        string     `json:"tenant_id,omitempty"`
	ClientID        string     `json:"client_id,omitempty"`
	SecretExpiresOn *time.Time `json:"secret_expires_on,omitempty"`
	CertificateDER  []byte     `json:"certificate_der,omitempty"` // public
	CertThumbprint  string     `json:"cert_thumbprint,omitempty"`
	CertNotAfter    *time.Time `json:"cert_not_after,omitempty"`
}

// kindOf maps a sign-in method to credentials.kind.
func kindOf(auth string) string {
	switch auth {
	case providers.AzureAuthCertificate:
		return "azure_sp_cert"
	case providers.AzureAuthManagedIdentity:
		return "azure_managed_identity"
	default:
		return "azure_sp_secret"
	}
}

// authOfKind is the inverse of kindOf ("" for a kind that is not a vault credential's).
func authOfKind(kind string) string {
	switch kind {
	case "azure_sp_secret":
		return providers.AzureAuthClientSecret
	case "azure_sp_cert":
		return providers.AzureAuthCertificate
	case "azure_managed_identity":
		return providers.AzureAuthManagedIdentity
	}
	return ""
}

// vaultInfoOf builds the Target's vault half from the config, the credential's public information
// ("null" when the vault has none) and the stored access check.
func vaultInfoOf(c targetConfig, raw []byte, interval time.Duration, access *providers.AzureFacts) (VaultInfo, error) {
	var in vaultInfo
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &in); err != nil {
			return VaultInfo{}, fmt.Errorf("inventory: decode the vault credential: %w", err)
		}
	}
	return VaultInfo{URL: c.VaultURL, Host: c.Host, Auth: in.Auth, TenantID: in.TenantID, ClientID: in.ClientID,
		SecretExpiresOn: utcPtr(in.SecretExpiresOn), CertThumbprint: in.CertThumbprint, CertNotAfter: utcPtr(in.CertNotAfter),
		PollInterval: interval, Access: access}, nil
}

// sealedVaultCredential is a vault credential ready to insert: the row's public part and the
// envelope of its secret part.
type sealedVaultCredential struct {
	ID     uuid.UUID
	Kind   string
	Info   []byte
	Sealed secrets.Envelope
}

// sealVaultCredential seals payload (the client secret's bytes, the PKCS #8 key, or nothing for a
// managed identity) for a new credential row. The caller zeroes payload.
func (s *Service) sealVaultCredential(info vaultInfo, payload []byte) (sealedVaultCredential, error) {
	raw, err := json.Marshal(info)
	if err != nil {
		return sealedVaultCredential{}, err
	}
	id := uuid.Must(uuid.NewV7())
	env, err := s.keyring.Seal(credentialLocation(id), payload)
	if err != nil {
		return sealedVaultCredential{}, fmt.Errorf("inventory: seal the vault credential: %w", err)
	}
	return sealedVaultCredential{ID: id, Kind: kindOf(info.Auth), Info: raw, Sealed: env}, nil
}

// insertVaultCredential inserts the credential row of vault target. It runs before the vault's row
// is inserted, or before credential_id moves, in the same transaction.
func (s *Service) insertVaultCredential(ctx context.Context, tx pgx.Tx, c sealedVaultCredential, target uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		c.ID, purposeAzureVault, c.Kind, c.Info, c.Sealed.Ciphertext, c.Sealed.Nonce, c.Sealed.WrappedDEK, c.Sealed.KeyVersion, now, target)
	if err != nil {
		return fmt.Errorf("inventory: store the vault credential: %w", err)
	}
	return nil
}

// VaultCredentialSource is the credential source of one vault: the identity Alice signs in with.
// It also satisfies providers.CredentialSource, so a registry can hand it to any provider, but
// answers every SSH request with an error: a vault has no SSH key.
type VaultCredentialSource interface {
	providers.CredentialSource
	providers.AzureCredentialSource
}

// VaultCredentials returns the source of vault id's own credential for provider sessions.
func (s *Service) VaultCredentials(id uuid.UUID) VaultCredentialSource {
	return vaultSource{s: s, id: id}
}

type vaultSource struct {
	s  *Service
	id uuid.UUID
}

// SSHSigner always fails: a vault is not an SSH target.
func (vaultSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, nil, errNotAnSSHTarget
}

// AzureIdentity decrypts the vault's credential for one session. release zeroes the decrypted
// secret; the caller calls it as soon as the SDK credential is built. A credential row that names
// another target is refused (errForeignCredential), never used. Errors carry no secret.
func (v vaultSource) AzureIdentity(ctx context.Context) (providers.AzureIdentity, func(), error) {
	var (
		credID, owner, vault uuid.UUID
		kind                 string
		raw                  []byte
		env                  secrets.Envelope
	)
	err := v.s.pool.QueryRow(ctx, `SELECT c.id, c.kind, c.public_info, c.ciphertext, c.nonce, c.wrapped_dek, c.key_version, c.target_id, t.id
FROM targets t JOIN credentials c ON c.id = t.credential_id
WHERE t.id = $1 AND t.deleted_at IS NULL AND c.purpose = $2`, v.id, purposeAzureVault).
		Scan(&credID, &kind, &raw, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion, &owner, &vault)
	if errors.Is(err, pgx.ErrNoRows) {
		return providers.AzureIdentity{}, nil, ErrNotFound
	}
	if err != nil {
		return providers.AzureIdentity{}, nil, fmt.Errorf("inventory: read the vault credential: %w", err)
	}
	if owner != vault {
		return providers.AzureIdentity{}, nil, errForeignCredential
	}
	var info vaultInfo
	if err := json.Unmarshal(raw, &info); err != nil || info.Auth == "" || authOfKind(kind) != info.Auth {
		return providers.AzureIdentity{}, nil, errors.New("inventory: the stored vault credential is damaged")
	}
	pt, err := v.s.keyring.Open(credentialLocation(credID), env)
	if err != nil { // secrets.ErrDecrypt, which says nothing about why
		return providers.AzureIdentity{}, nil, fmt.Errorf("%w (%w)", ErrVaultCredentialUnreadable, err)
	}
	id := providers.AzureIdentity{Auth: info.Auth, TenantID: info.TenantID, ClientID: info.ClientID}
	switch info.Auth {
	case providers.AzureAuthClientSecret:
		id.ClientSecret = pt
	case providers.AzureAuthCertificate:
		id.CertificateDER, id.PrivateKeyDER = slices.Clone(info.CertificateDER), pt
	default: // managed identity: nothing secret was sealed
		pt.Zero()
	}
	return id, id.Zero, nil
}

// memorySource is the source of a pre-flight: the identity of a request that is not stored yet. It
// hands out copies, because the provider's release zeroes what it was given while the caller still
// seals the original afterwards.
type memorySource struct{ id providers.AzureIdentity }

func (memorySource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, nil, errNotAnSSHTarget
}

func (m memorySource) AzureIdentity(context.Context) (providers.AzureIdentity, func(), error) {
	id := m.id
	id.ClientSecret = secrets.NewPlaintext(slices.Clone(m.id.ClientSecret.Bytes()))
	id.PrivateKeyDER = secrets.NewPlaintext(slices.Clone(m.id.PrivateKeyDER.Bytes()))
	id.CertificateDER = slices.Clone(m.id.CertificateDER)
	return id, id.Zero, nil
}
