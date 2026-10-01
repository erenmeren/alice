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

// Target statuses (targets.status, R37 item 6).
const (
	StatusPendingHostKey = "pending_host_key"
	StatusChecking       = "checking"
	StatusOK             = "ok"
	StatusUnreachable    = "unreachable"
	StatusHostKeyChanged = "host_key_changed"
	StatusAuthFailed     = "auth_failed"
	StatusDisabled       = "disabled"
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
}

// NewTarget is the input of CreateTarget.
type NewTarget struct {
	Name     string
	Type     string // "linux" in Phase 3
	Host     string
	Port     int    // 0 = 22
	Username string // "" = alice-svc
}

// TargetPatch is the input of UpdateTarget; nil fields stay unchanged (R37 item 10).
type TargetPatch struct {
	Name                   *string
	DiscoveryIntervalHours *int // 1..720
}

// targetConfig is targets.config.
type targetConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
}
