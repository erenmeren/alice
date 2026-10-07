// Package reports reads what the dashboard, the exports and the saved views show (spec §26.9; R42 rows 13-14, 27).
// Counts come from the one definition of "monitored" in package alerts; the other numbers are read here.
package reports

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/notify"
	"alice/internal/platform/clock"
)

// Windows of the dashboard.
const (
	FailedWindow   = 7 * 24 * time.Hour  // failed deployments that count and are listed
	RotationWindow = 14 * 24 * time.Hour // upcoming rotations
)

// Inventory is the list reads the exports use (Task 10).
type Inventory interface {
	ListCertificates(ctx context.Context, f inventory.CertificateFilter) (inventory.CertificatePage, error)
	ListSSHKeys(ctx context.Context, f inventory.KeyFilter) (inventory.KeyPage, error)
}

// Config wires Service.
type Config struct {
	Pool     *pgxpool.Pool
	Clock    clock.Clock
	Audit    *audit.Log
	License  alerts.LicenseState
	Alerts   *alerts.Service
	Delivery interface {
		Delivery(ctx context.Context) (notify.Delivery, error)
	}
	Inventory Inventory
}

// Service answers the dashboard and the report reads.
type Service struct {
	pool     *pgxpool.Pool
	clock    clock.Clock
	audit    *audit.Log
	license  alerts.LicenseState
	alerts   *alerts.Service
	delivery interface {
		Delivery(ctx context.Context) (notify.Delivery, error)
	}
	inventory Inventory

	exportMu  sync.Mutex
	exporting map[uuid.UUID]bool // users with an export running (S-10)
}

// New builds the service.
func New(c Config) *Service {
	return &Service{pool: c.Pool, clock: c.Clock, audit: c.Audit, license: c.License, alerts: c.Alerts, delivery: c.Delivery,
		inventory: c.Inventory, exporting: map[uuid.UUID]bool{}}
}
