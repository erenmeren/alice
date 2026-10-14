// Package alerts finds the expiry notices that are due and queues them once (spec §26.9; R42 rows 3-5, 12). What is
// monitored is defined in one place (monitored.go) and shared with the dashboard.
package alerts

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/clock"
)

// Kind is what expires.
type Kind string

// The four managed kinds and the discovered one. KindDiscoveredCertificate (network discovery, decision 5 and
// amendment A7) is an unmanaged certificate a scan found on a scope with alert_on_expiry: it is alerted, never counted
// on the Overview and never listed by its expiring list (decision D2).
const (
	KindCertificate           Kind = "certificate_expiry"
	KindKVCertificate         Kind = "kv_certificate_expiry"
	KindKVKey                 Kind = "kv_key_expiry"
	KindKVCredential          Kind = "kv_credential_expiry" //nolint:gosec // G101: a kind name, not a credential
	KindDiscoveredCertificate Kind = "discovered_certificate_expiry"
)

// Kinds lists every kind the scan alerts, in their fixed order.
func Kinds() []Kind {
	return []Kind{KindCertificate, KindKVCertificate, KindKVKey, KindKVCredential, KindDiscoveredCertificate}
}

// ManagedKinds are the kinds of what Alice manages: the Overview's expiring list reads these only.
func ManagedKinds() []Kind {
	return []Kind{KindCertificate, KindKVCertificate, KindKVKey, KindKVCredential}
}

// discoveredNamespace is the fixed uuid v5 namespace of the discovered certificates' ledger object ids. It never changes:
// the ledger's rows refer to ids derived from it.
var discoveredNamespace = uuid.MustParse("8d6c3f3e-0f4b-4d1e-9a51-6a7f2c1e9b40")

// DiscoveredObjectID is the ledger object id of a discovered certificate (A7: the ledger's object_id is a uuid; a
// discovered certificate has none, its key is the SHA-256 fingerprint): the uuid v5 of the fingerprint.
func DiscoveredObjectID(fingerprint string) uuid.UUID {
	return uuid.NewSHA1(discoveredNamespace, []byte(fingerprint))
}

// Scan limits and the thresholds setting.
const (
	ScanEvery        = 15 * time.Minute
	MaxEmailsPerScan = 20
	ThresholdsKey    = "alerts.thresholds_days"
)

// Item is one monitored thing that expires (R42 row 4).
type Item struct {
	Kind        Kind
	ObjectID    uuid.UUID // certificates.id, kv_certificates.id, kv_keys.id, the vault's targets.id or DiscoveredObjectID
	Name        string    // subject CN (else the label, else the fingerprint's first 16 characters), or the vault object's name, or the vault's name
	ExpiresAt   time.Time
	Fingerprint string   // certificates and discovered certificates
	Websites    []string // certificates: server names of its live locations (sorted, at most 10)
	Servers     []string // certificates: names of the targets of its live locations (sorted, at most 10)
	TargetIDs   []uuid.UUID
	Vault       string // Key Vault kinds: the vault target's name
	VaultID     uuid.UUID
	Endpoints   []string // discovered certificates: host:port of the alerting scopes' endpoints that present it (sorted, at most 10)
	Scopes      []string // discovered certificates: names of those scopes (sorted, at most 10)

	moreWebsites, moreServers bool // an eleventh entry exists (Websites and Endpoints, Servers and Scopes)
}

// Counts are the dashboard numbers, from the same definition of "monitored".
type Counts struct {
	Monitored, Expired, Within7, Within30, Within60 int // certificates (exclusive buckets of expiry.BucketOf)
	KVExpired, KVWithin30                           int // Key Vault certificates, keys and client secrets together
}

// ThresholdSettings is the thresholds setting.
type ThresholdSettings struct {
	Days    []int
	Version int // 0: the defaults, never saved
}

// ScanResult says what one scan did.
type ScanResult struct {
	Queued     map[Kind]int // notices whose email was queued
	Suppressed map[Kind]int // notices recorded over MaxEmailsPerScan (one summary email per kind)
	Failed     int          // items skipped because recording or queueing failed (logged; retried by the next scan)
}

// LicenseState gives the current license evaluation.
type LicenseState interface{ Snapshot() license.Snapshot }

// Notifier queues an Administrator e-mail inside tx.
type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}

// Config wires Service.
type Config struct {
	Pool     *pgxpool.Pool
	Audit    *audit.Log
	Clock    clock.Clock
	License  LicenseState
	Notifier Notifier
	Log      *slog.Logger // nil: discard
}

// Service finds and records expiry notices.
type Service struct {
	pool     *pgxpool.Pool
	audit    *audit.Log
	clock    clock.Clock
	license  LicenseState
	notifier Notifier
	log      *slog.Logger
}

// New builds the service.
func New(c Config) *Service {
	lg := c.Log
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	return &Service{pool: c.Pool, audit: c.Audit, clock: c.Clock, license: c.License, notifier: c.Notifier, log: lg}
}
