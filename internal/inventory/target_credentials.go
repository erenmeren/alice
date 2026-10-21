package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/secrets"
)

// The sign-in credential of an API target (R59 G3, migration 00031): a BIG-IP's user name and password (purpose
// f5_device, kind f5_password), a Kubernetes cluster's ServiceAccount token (kubernetes_cluster, k8s_token) or client
// certificate and key (kubernetes_cluster, k8s_client_cert). It belongs to its target as a vault's does: the secret part
// is the row's sealed payload (AAD credentials/<id>/ciphertext), the rest (the kind of secret, the user name, the client
// certificate) is public_info; credentials are append-only and a replacement is a new row the target moves to.

const (
	purposeF5Device          = "f5_device"
	purposeKubernetesCluster = "kubernetes_cluster"
)

var (
	// errTargetSecretInvalid: a sign-in secret that does not suit the target type (a token for a BIG-IP), or misses
	// its parts (a password without a user name, a client certificate without its key).
	errTargetSecretInvalid = errors.New("inventory: the sign-in secret does not suit the target")
	// errTargetCredentialUnreadable: the stored credential did not decrypt (secrets.ErrDecrypt says nothing about why).
	errTargetCredentialUnreadable = errors.New("inventory: the target's credential cannot be read")
	errNoSSHForAPITarget          = errors.New("inventory: an API target has no SSH credential")
)

// targetSecretInfo is credentials.public_info of an API target's credential (never a secret).
type targetSecretInfo struct {
	Secret               string `json:"secret"` // providers.TargetSecret*
	Username             string `json:"username,omitempty"`
	ClientCertificatePEM string `json:"client_certificate_pem,omitempty"`
}

// targetCredentialShape is the purpose and kind of the credential of target type typ holding a secret of kind secret
// (ok false when the type takes no such secret).
func targetCredentialShape(typ, secret string) (purpose, kind string, ok bool) {
	switch {
	case typ == providers.TargetTypeF5BigIP && secret == providers.TargetSecretPassword:
		return purposeF5Device, "f5_password", true
	case typ == providers.TargetTypeKubernetes && secret == providers.TargetSecretToken:
		return purposeKubernetesCluster, "k8s_token", true
	case typ == providers.TargetTypeKubernetes && secret == providers.TargetSecretClientCertificate:
		return purposeKubernetesCluster, "k8s_client_cert", true
	}
	return "", "", false
}

// sealedTargetCredential is an API target's credential ready to insert.
type sealedTargetCredential struct {
	ID            uuid.UUID
	Purpose, Kind string
	Info          []byte
	Sealed        secrets.Envelope
}

// sealTargetCredential seals the secret part of sec for a new credential row of a target of type typ (the target phases'
// create and replace paths call it; the caller zeroes sec).
func (s *Service) sealTargetCredential(typ string, sec providers.TargetSecret) (sealedTargetCredential, error) {
	purpose, kind, ok := targetCredentialShape(typ, sec.Kind)
	if !ok {
		return sealedTargetCredential{}, errTargetSecretInvalid
	}
	info := targetSecretInfo{Secret: sec.Kind}
	var payload []byte
	switch sec.Kind {
	case providers.TargetSecretPassword:
		info.Username, payload = sec.Username, sec.Password.Bytes()
		ok = sec.Username != "" && len(payload) > 0
	case providers.TargetSecretToken:
		payload = sec.Token.Bytes()
		ok = len(payload) > 0
	default: // client certificate
		info.ClientCertificatePEM, payload = string(sec.ClientCertificatePEM), sec.ClientKeyPEM.Bytes()
		ok = len(sec.ClientCertificatePEM) > 0 && len(payload) > 0
	}
	if !ok {
		return sealedTargetCredential{}, errTargetSecretInvalid
	}
	raw, err := json.Marshal(info)
	if err != nil {
		return sealedTargetCredential{}, err
	}
	id := uuid.Must(uuid.NewV7())
	env, err := s.keyring.Seal(credentialLocation(id), payload)
	if err != nil {
		return sealedTargetCredential{}, fmt.Errorf("inventory: seal the target's credential: %w", err)
	}
	return sealedTargetCredential{ID: id, Purpose: purpose, Kind: kind, Info: raw, Sealed: env}, nil
}

// insertTargetCredential inserts the credential row of target (before the target's row, or before credential_id moves,
// in the same transaction: its target is checked at commit).
func insertTargetCredential(ctx context.Context, tx pgx.Tx, c sealedTargetCredential, target uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		c.ID, c.Purpose, c.Kind, c.Info, c.Sealed.Ciphertext, c.Sealed.Nonce, c.Sealed.WrappedDEK, c.Sealed.KeyVersion, now, target)
	if err != nil {
		return fmt.Errorf("inventory: store the target's credential: %w", err)
	}
	return nil
}

// TargetCredentialSource is the credential source of one API target: its sign-in secret. It also satisfies
// providers.CredentialSource, so a registry can hand it to any provider, but answers every SSH request with an error.
type TargetCredentialSource interface {
	providers.CredentialSource
	providers.TargetSecretSource
}

// TargetCredentials returns the source of API target id's own credential for provider sessions.
func (s *Service) TargetCredentials(id uuid.UUID) TargetCredentialSource {
	return targetSource{s: s, id: id}
}

type targetSource struct {
	s  *Service
	id uuid.UUID
}

// SSHSigner always fails: an API target is not reached over SSH.
func (targetSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, nil, errNoSSHForAPITarget
}

// TargetSecret decrypts the target's credential for one session. release zeroes the decrypted secret. A credential row
// that names another target, or whose purpose is not the target type's, is refused (errForeignCredential), never used.
// Errors carry no secret.
func (t targetSource) TargetSecret(ctx context.Context) (providers.TargetSecret, func(), error) {
	var (
		credID, owner uuid.UUID
		typ, purpose  string
		kind          string
		raw           []byte
		env           secrets.Envelope
	)
	err := t.s.pool.QueryRow(ctx, `SELECT c.id, c.purpose, c.kind, c.public_info, c.ciphertext, c.nonce, c.wrapped_dek, c.key_version,
    coalesce(c.target_id, '00000000-0000-0000-0000-000000000000'), t.type
FROM targets t JOIN credentials c ON c.id = t.credential_id
WHERE t.id = $1 AND t.deleted_at IS NULL`, t.id).
		Scan(&credID, &purpose, &kind, &raw, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion, &owner, &typ)
	if errors.Is(err, pgx.ErrNoRows) {
		return providers.TargetSecret{}, nil, ErrNotFound
	}
	if err != nil {
		return providers.TargetSecret{}, nil, fmt.Errorf("inventory: read the target's credential: %w", err)
	}
	var info targetSecretInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return providers.TargetSecret{}, nil, errors.New("inventory: the stored target credential is damaged")
	}
	wantPurpose, wantKind, ok := targetCredentialShape(typ, info.Secret)
	if owner != t.id || !ok || purpose != wantPurpose || kind != wantKind {
		return providers.TargetSecret{}, nil, errForeignCredential
	}
	pt, err := t.s.keyring.Open(credentialLocation(credID), env)
	if err != nil {
		return providers.TargetSecret{}, nil, fmt.Errorf("%w (%w)", errTargetCredentialUnreadable, err)
	}
	sec := providers.TargetSecret{Kind: info.Secret}
	switch info.Secret {
	case providers.TargetSecretPassword:
		sec.Username, sec.Password = info.Username, pt
	case providers.TargetSecretToken:
		sec.Token = pt
	default:
		sec.ClientCertificatePEM, sec.ClientKeyPEM = []byte(info.ClientCertificatePEM), pt
	}
	return sec, sec.Zero, nil
}
