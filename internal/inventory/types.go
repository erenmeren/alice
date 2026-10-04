package inventory

import (
	"time"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// Fixed names (spec §12.2, R37 item 1).
const (
	ServiceUser        = "alice-svc"
	PlatformKeyComment = "alice-platform"
	defaultSSHPort     = 22
	defaultInterval    = 24 * time.Hour
)

// Target types (targets.type): a Linux server (SSH keys), an Nginx server (SSH keys and
// certificates, spec §12) and an Azure Key Vault (spec §11). CreateTarget adds the servers,
// CreateVault the vaults; neither accepts the other's type.
const (
	TypeLinux         = "linux"
	TypeNginx         = "nginx"
	TypeAzureKeyVault = "azure_key_vault"
)

// Target statuses (targets.status, R37 item 6).
const (
	StatusPendingHostKey = "pending_host_key"
	StatusChecking       = "checking"
	StatusOK             = "ok"
	StatusUnreachable    = "unreachable"
	StatusHostKeyChanged = "host_key_changed"
	StatusAuthFailed     = "auth_failed"
	StatusDisabled       = "disabled"
	// StatusDegraded is a vault that works only in part (a missing role, a firewall; R40 row 12).
	StatusDegraded = "degraded"
)

// Actor is who asks: the audit actor plus the user and role behind it.
type Actor struct {
	Audit  audit.Actor
	UserID uuid.UUID
	Role   rbac.Role
}

// jobKind is "user" for a person's request and "system" for Alice's own.
func (a Actor) jobKind() string {
	if a.UserID == uuid.Nil {
		return "system"
	}
	return "user"
}

// PlatformKey is the public half of Alice's own SSH key.
type PlatformKey struct {
	ID          uuid.UUID
	PublicKey   string
	Fingerprint string
}

// Guide is what an administrator needs to prepare a server (setup snippet, §12.2).
type Guide struct {
	PlatformKey
	AuthorizedKeysLine string
	HelperPath         string
	HelperProtocol     int
	Profiles           map[string]providers.SetupSnippet
}

// Target is one managed server. It never carries credentials.
type Target struct {
	ID                   uuid.UUID
	Name                 string
	Type                 string
	Host                 string
	Port                 int
	Username             string
	Status               string
	LastErrorCode        string
	LastSuccessAt        *time.Time
	LastDiscoveryAt      *time.Time
	DiscoveryInterval    time.Duration
	KeysManagedElsewhere bool
	Facts                Facts
	Vault                *VaultInfo // set for a Key Vault (Type TypeAzureKeyVault), nil for a server
	Capabilities         []string
	Version              int
	CreatedAt, UpdatedAt time.Time
}

// Facts are what the last connection test and discovery learned (targets.facts).
type Facts struct {
	OS             providers.OSRelease           `json:"os"`
	HelperVersion  string                        `json:"helper_version"`
	HelperProtocol int                           `json:"helper_protocol"`
	SSHD           *providers.SSHDSummary        `json:"sshd,omitempty"`
	HostKeys       []providers.DiscoveredHostKey `json:"host_keys,omitempty"`
	Warnings       []providers.Warning           `json:"warnings,omitempty"`
	Unreadable     []providers.UnreadableLine    `json:"unreadable,omitempty"`
	UID0Users      []string                      `json:"uid0_users,omitempty"` // listed accounts with uid 0 (last-root-key guard)
	Nginx          *providers.NginxFacts         `json:"nginx,omitempty"`      // what the last test or certificate scan learned of Nginx
	// The vault half (a Key Vault target only): the last access check, when the last poll read
	// the vault's metadata, and the counters of the failure transitions (Task 11).
	Azure             *providers.AzureFacts `json:"azure,omitempty"`
	KVMetadataAt      *time.Time            `json:"kv_metadata_at,omitempty"`
	KVAuthFailures    int                   `json:"kv_auth_failures,omitempty"`
	KVThrottledCycles int                   `json:"kv_throttled_cycles,omitempty"`
	KVReconciledAt    *time.Time            `json:"kv_reconciled_at,omitempty"` // start of the last poll that was stored completely
	KVHoldRenewals    bool                  `json:"kv_hold_renewals,omitempty"` // new versions stay held while details of the first poll after a reopening are pending
	KVEmptyAt         *time.Time            `json:"kv_empty_at,omitempty"`      // when the first empty certificate listing was stored
	KVEmptyPolls      int                   `json:"kv_empty_polls,omitempty"`   // empty complete certificate listings in a row
	KVPoll            *KVPollFacts          `json:"kv_poll,omitempty"`          // what the last poll found wrong
}

// VaultInfo is what a Key Vault target adds to Target: its address, how Alice signs in and the
// public facts of that credential. It never carries a secret.
type VaultInfo struct {
	URL             string // https://<name>.vault.azure.net
	Host            string
	Auth            string // providers.AzureAuth*
	TenantID        string
	ClientID        string
	SecretExpiresOn *time.Time // the client secret's expiry, when the Administrator told Alice
	CertThumbprint  string     // the sign-in certificate's SHA-1 thumbprint (certificate method)
	CertNotAfter    *time.Time
	PollInterval    time.Duration
	Access          *providers.AzureFacts // the last access check (Facts.Azure)
}

// NewTarget is the input of CreateTarget.
type NewTarget struct {
	Name     string
	Type     string // TypeLinux or TypeNginx
	Host     string
	Port     int    // 0 = 22
	Username string // "" = alice-svc
}

// TargetPatch is the input of UpdateTarget; nil fields stay unchanged (R37 item 10).
type TargetPatch struct {
	Name                   *string
	DiscoveryIntervalHours *int // 1..720, servers only
	PollIntervalMinutes    *int // 5..1440, vaults only
}

// targetConfig is targets.config.
type targetConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	VaultURL string `json:"vault_url,omitempty"` // a Key Vault only (host is its host name, port 443)
}
