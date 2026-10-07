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

// The four monitored kinds.
const (
	KindCertificate   Kind = "certificate_expiry"
	KindKVCertificate Kind = "kv_certificate_expiry"
	KindKVKey         Kind = "kv_key_expiry"
	KindKVCredential  Kind = "kv_credential_expiry" //nolint:gosec // G101: a kind name, not a credential
)

// Kinds lists the kinds in their fixed order.
func Kinds() []Kind {
	return []Kind{KindCertificate, KindKVCertificate, KindKVKey, KindKVCredential}
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
	ObjectID    uuid.UUID // certificates.id, kv_certificates.id, kv_keys.id or the vault's targets.id
	Name        string    // subject CN (else the label, else the fingerprint's first 16 characters), or the vault object's name, or the vault's name
	ExpiresAt   time.Time
	Fingerprint string   // certificates only
	Websites    []string // certificates: server names of its live locations (sorted, at most 10)
	Servers     []string // certificates: names of the targets of its live locations (sorted, at most 10)
	TargetIDs   []uuid.UUID
	Vault       string // Key Vault kinds: the vault target's name
	VaultID     uuid.UUID

	moreWebsites, moreServers bool // an eleventh entry exists
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
