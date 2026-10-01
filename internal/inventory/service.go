// Package inventory owns targets, credentials (the platform SSH key), pinned host keys and the
// SSH key inventory (spec §7.2, §7.3). It orchestrates providers only through the providers
// interface package and checks the license limit in the transaction that inserts a target.
package inventory

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// LicenseGate is license.Service: CheckCanAddTarget runs inside the insert transaction; Tick runs
// after a committed add or delete so the snapshot's target count and the banners are current.
type LicenseGate interface {
	CheckCanAddTarget(ctx context.Context, tx pgx.Tx) error
	Tick(ctx context.Context) error
}

// Notifier is notify.AdminNotifier (inventory may not import notify, §5.4).
type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}

// Config holds the service dependencies.
type Config struct {
	Pool     *pgxpool.Pool
	Keyring  *secrets.Keyring
	Audit    *audit.Log
	Clock    clock.Clock
	License  LicenseGate
	Registry *providers.Registry
	Jobs     Enqueuer
	Notifier Notifier // nil = no emails
	Log      *slog.Logger
	Rand     io.Reader // platform key generation; nil = crypto/rand
}

// Service is the inventory module.
type Service struct {
	pool     *pgxpool.Pool
	keyring  *secrets.Keyring
	audit    *audit.Log
	clock    clock.Clock
	license  LicenseGate
	registry *providers.Registry
	jobs     Enqueuer
	notifier Notifier
	log      *slog.Logger
	randMu   sync.Mutex // Config.Rand need not be safe for concurrent use
	rand     io.Reader
}

// New builds the service.
func New(c Config) *Service {
	s := &Service{pool: c.Pool, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, license: c.License,
		registry: c.Registry, jobs: c.Jobs, notifier: c.Notifier, log: c.Log, rand: c.Rand}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.rand == nil {
		s.rand = rand.Reader
	}
	return s
}
