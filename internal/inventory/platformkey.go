package inventory

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"alice/internal/audit"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// The platform key is the Ed25519 key Alice signs in to every server with (decisions "Secrets
// protection", §13.5, R37 item 1). Its 32-byte seed is stored only as an envelope in
// credentials.ciphertext, bound to its row by the AAD credentials/<id>/ciphertext.

const purposePlatformSSH = "platform_ssh"

type platformInfo struct {
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

func credentialLocation(id uuid.UUID) secrets.Location {
	return secrets.Location{Table: "credentials", RowID: id.String(), Column: "ciphertext"}
}

// PlatformKey returns the public half of the platform key, or ErrNoPlatformKey.
func (s *Service) PlatformKey(ctx context.Context) (PlatformKey, error) {
	return loadPlatformKey(ctx, s.pool)
}

func loadPlatformKey(ctx context.Context, q db.Querier) (PlatformKey, error) {
	var pk PlatformKey
	var raw []byte
	err := q.QueryRow(ctx, "SELECT id, public_info FROM credentials WHERE purpose = $1", purposePlatformSSH).Scan(&pk.ID, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformKey{}, ErrNoPlatformKey
	}
	if err != nil {
		return PlatformKey{}, fmt.Errorf("inventory: read the platform key: %w", err)
	}
	var info platformInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return PlatformKey{}, fmt.Errorf("inventory: decode the platform key: %w", err)
	}
	pk.PublicKey, pk.Fingerprint = info.PublicKey, info.Fingerprint
	return pk, nil
}

// EnsurePlatformKey creates the platform key on first use (startup, or the e2e reset) and returns
// it. Concurrent callers create exactly one key: the insert yields to the unique partial index.
func (s *Service) EnsurePlatformKey(ctx context.Context) (PlatformKey, error) {
	if pk, err := s.PlatformKey(ctx); !errors.Is(err, ErrNoPlatformKey) {
		return pk, err
	}
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	s.randMu.Lock()
	_, err := io.ReadFull(s.rand, seed)
	s.randMu.Unlock()
	if err != nil {
		return PlatformKey{}, fmt.Errorf("inventory: generate the platform key: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return PlatformKey{}, fmt.Errorf("inventory: encode the platform key: %w", err)
	}
	info := platformInfo{
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + PlatformKeyComment,
		Fingerprint: ssh.FingerprintSHA256(pub),
	}
	rawInfo, err := json.Marshal(info)
	if err != nil {
		return PlatformKey{}, err
	}
	id := uuid.Must(uuid.NewV7())
	env, err := s.keyring.Seal(credentialLocation(id), seed)
	if err != nil {
		return PlatformKey{}, fmt.Errorf("inventory: seal the platform key: %w", err)
	}
	now := s.clock.Now().UTC()
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, $2, 'ssh_private_key', $3, $4, $5, $6, $7, $8)
ON CONFLICT (purpose) WHERE purpose = 'platform_ssh' DO NOTHING`,
			id, purposePlatformSSH, rawInfo, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, now)
		if err != nil {
			return fmt.Errorf("inventory: store the platform key: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil // another caller created it first
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("inventory"), Action: "platform_key.created",
			ObjectType: "credential", ObjectID: id.String(), Result: audit.Success,
			Details: map[string]string{"fingerprint": info.Fingerprint, "credential_id": id.String()}})
		return err
	})
	if err != nil {
		return PlatformKey{}, err
	}
	return s.PlatformKey(ctx)
}

// Credentials returns the source of the platform key for provider sessions.
func (s *Service) Credentials() providers.CredentialSource { return platformCredentials{s: s} }

type platformCredentials struct{ s *Service }

// SSHSigner decrypts the seed for one session. release zeroes the seed and the private key; the
// caller calls it as soon as the SSH handshake is done. Errors never carry key material.
func (c platformCredentials) SSHSigner(ctx context.Context) (ssh.Signer, func(), error) {
	var id uuid.UUID
	var env secrets.Envelope
	err := c.s.pool.QueryRow(ctx, `SELECT id, ciphertext, nonce, wrapped_dek, key_version FROM credentials WHERE purpose = $1`,
		purposePlatformSSH).Scan(&id, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNoPlatformKey
	}
	if err != nil {
		return nil, nil, fmt.Errorf("inventory: read the platform key: %w", err)
	}
	pt, err := c.s.keyring.Open(credentialLocation(id), env)
	if err != nil {
		return nil, nil, errors.New("inventory: the platform key cannot be decrypted with this master key")
	}
	if len(pt.Bytes()) != ed25519.SeedSize {
		pt.Zero()
		return nil, nil, errors.New("inventory: the stored platform key is damaged")
	}
	priv := ed25519.NewKeyFromSeed(pt.Bytes())
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		pt.Zero()
		clear(priv)
		return nil, nil, errors.New("inventory: the stored platform key is damaged")
	}
	release := func() {
		pt.Zero()
		clear(priv)
	}
	return signer, release, nil
}

// platformKeyOptions restrict the platform key (SEC-082). They are linuxssh's keyOptions:
// inventory may not import the provider (§5.4).
const platformKeyOptions = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc"

// authorizedKeysLine is the line the setup script installs for alice-svc (SEC-082). It must equal
// linuxssh.AuthorizedKeysLine for the same input (Task 16 tests the equality). from is a canonical
// IP address (SetupGuide checks it), a subset of what linuxssh.ValidateFrom accepts.
func authorizedKeysLine(publicKey, from string) string {
	opts := platformKeyOptions
	if from != "" {
		opts = `from="` + from + `",` + opts
	}
	return opts + " " + publicKey
}

// SetupGuide returns the platform key and the setup snippets for both sudoers profiles. from is an
// optional IP address that the authorized_keys line restricts Alice's key to (§12.2). It is
// placed in the line in its canonical form (an IPv6 address in lower case), so the text inside the
// quoted from="…" option is always exactly an address. Zones and IPv4-mapped IPv6 addresses are
// refused: sshd matches the client's address as it sees it, and a mapped form would never match.
func (s *Service) SetupGuide(ctx context.Context, from string) (Guide, error) {
	if from != "" {
		a, err := netip.ParseAddr(from)
		if err != nil || a.Zone() != "" || a.Is4In6() {
			var errs validate.Errors
			errs.Add("from", validate.Pattern, nil)
			return Guide{}, errs
		}
		from = a.String()
	}
	pk, err := s.EnsurePlatformKey(ctx)
	if err != nil {
		return Guide{}, err
	}
	p, ok := s.registry.Get(providers.KindLinuxSSH)
	if !ok {
		return Guide{}, errors.New("inventory: the linuxssh provider is not registered")
	}
	sg, ok := p.(providers.SetupGuide)
	if !ok {
		return Guide{}, errors.New("inventory: the linuxssh provider has no setup guide")
	}
	line := authorizedKeysLine(pk.PublicKey, from)
	path, protocol := sg.HelperInfo()
	profiles := sg.SetupSnippets(line)
	for _, p := range profiles {
		if p.Script == "" {
			// The provider refused to embed the line: a guide without a script is never shown.
			return Guide{}, errors.New("inventory: the provider cannot build the setup script")
		}
	}
	return Guide{PlatformKey: pk, AuthorizedKeysLine: line, HelperPath: path, HelperProtocol: protocol,
		Profiles: profiles}, nil
}
