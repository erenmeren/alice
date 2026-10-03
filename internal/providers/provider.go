// Package providers defines the compile-time provider framework (spec §6): the Provider and
// Session interfaces, capabilities, declarative config schemas, the frozen registry and the one
// error type providers return. Providers are pure adapters: no database access (archtest), no
// runtime code loading.
package providers

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"alice/internal/platform/clock"
	"alice/internal/platform/validate"
)

// Kind names a provider.
type Kind string

// Provider kinds of v1.
const (
	KindLinuxSSH Kind = "linuxssh"
	KindNginx    Kind = "nginx"
	KindAzureKV  Kind = "azurekv"
)

// KindForTargetType maps targets.type to the provider kind (spec §6.4).
func KindForTargetType(t string) (Kind, bool) {
	switch t {
	case "linux":
		return KindLinuxSSH, true
	case "nginx":
		return KindNginx, true
	case "azure_key_vault":
		return KindAzureKV, true
	default:
		return "", false
	}
}

// TargetConfig is the non-secret target configuration (targets.config).
type TargetConfig map[string]any

// TargetRef identifies the target a session works on.
type TargetRef struct {
	ID     uuid.UUID
	Name   string
	Kind   Kind
	Config TargetConfig
}

// HostKey is an SSH server key in wire form plus its SHA-256 fingerprint ("SHA256:…").
type HostKey struct {
	Type        string // ssh.PublicKey.Type(), e.g. "ssh-ed25519"
	PublicKey   []byte // ssh.PublicKey.Marshal()
	Fingerprint string // ssh.FingerprintSHA256
}

// ErrNoPinnedKey is returned by HostKeyStore.Pinned when no key is pinned for the target.
var ErrNoPinnedKey = errors.New("providers: no pinned host key")

// HostKeyStore is implemented by inventory. Pinned returns ErrNoPinnedKey when nothing is pinned.
// Observed records a presented key that is not pinned; changed is true when another key is pinned.
// Observed must honour ctx, may complete after Dial has returned (Dial stops waiting at its
// handshake budget), and must be idempotent per (target, key).
type HostKeyStore interface {
	Pinned(ctx context.Context, target uuid.UUID) (HostKey, error)
	Observed(ctx context.Context, target uuid.UUID, key HostKey, changed bool) error
}

// CredentialSource hands a provider the secret of one session. release zeroes what was decrypted.
type CredentialSource interface {
	SSHSigner(ctx context.Context) (signer ssh.Signer, release func(), err error)
}

// Env carries injected dependencies so providers stay pure.
type Env struct {
	Clock    clock.Clock
	HostKeys HostKeyStore
	Log      *slog.Logger // already redacting
	// FreshConnection asks for a new connection instead of a reused one: an explicit connection
	// test must see the host key the server presents now (R37 item 21). The connection may be
	// kept for reuse afterwards.
	FreshConnection bool
}

// Provider is one kind of managed system.
type Provider interface {
	Kind() Kind
	DisplayNameKey() string
	Capabilities() CapabilitySet
	ConfigSchema() ConfigSchema
	CredentialSchema() CredentialSchema
	ValidateConfig(cfg TargetConfig) []validate.FieldError
	Open(ctx context.Context, t TargetRef, cred CredentialSource, env Env) (Session, error)
}

// Session is one connection scope. Methods of capabilities a provider does not advertise return
// ErrUnsupported (embed UnsupportedSession). Later phases add deploy and import methods.
type Session interface {
	Close() error
	TestConnection(ctx context.Context) (ConnectionReport, error)
	Discover(ctx context.Context, req DiscoverRequest) (DiscoveryResult, error)
	ListAuthorizedKeys(ctx context.Context) ([]DiscoveredSSHKey, error)
	AddAuthorizedKey(ctx context.Context, req AuthKeyChange, log StepLogger) (AuthKeyResult, error)
	RemoveAuthorizedKey(ctx context.Context, req AuthKeyChange, log StepLogger) (AuthKeyResult, error)
}

// ConnectionCache is implemented by providers that keep connections to targets between sessions
// (linuxssh's pool). ForgetTarget closes the idle connections of a deleted target and drops what
// the provider keeps for it; a connection still in use is closed when its session ends.
type ConnectionCache interface {
	ForgetTarget(target uuid.UUID)
}

// SetupGuide is implemented by providers that need host preparation (linuxssh).
type SetupGuide interface {
	SetupSnippets(authorizedKeysLine string) map[string]SetupSnippet // key: profile "linux" | "nginx"
	HelperInfo() (path string, protocol int)                         // "/usr/local/libexec/alice-helper", helperproto.Protocol
}

// SetupSnippet is the host preparation for one sudoers profile.
type SetupSnippet struct {
	Profile string // "linux" | "nginx"
	Sudoers string // content of /etc/sudoers.d/alice
	Script  string // shell script to run as root on the target
}
