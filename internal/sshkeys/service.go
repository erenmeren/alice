// Package sshkeys is the SSH key lifecycle module (spec §13.4-§13.6, Phase 6): keys Alice
// generates and keeps sealed, their deployment to servers, the audited download of a private key,
// the destruction of retired keys, and (Tasks 8-9) rotation policies and runs. It reads and writes
// the inventory's tables through the inventory module's exported transactional helpers and never
// imports jobs, notify or api (internal/archtest).
//
// A generated private key exists in clear only inside Generate until it is sealed, inside a
// test-login signer for one handshake, and inside DownloadPrivateKey while the file is built; each
// holder zeroes it on every path. Nothing in this package logs a key, a passphrase or a seed, and
// no error carries one.
package sshkeys

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// LicenseGate is the lock-mode gate (license.Service.Allow).
type LicenseGate interface{ Allow(c license.Class) error }

// Notifier is notify.ServiceNotifier (sshkeys may not import notify): every rotation e-mail goes to the recipients of
// the key's service and of the services its policy's approval names (R56, design §7.2).
type Notifier interface {
	NotifyServices(ctx context.Context, tx pgx.Tx, services []uuid.UUID, template string, params map[string]string) error
}

// Inventory is the part of *inventory.Service this module uses.
type Inventory interface {
	TargetTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (inventory.Target, error)
	KeyLocationsTx(ctx context.Context, tx pgx.Tx, keyID uuid.UUID, lock bool) ([]inventory.KeyLocation, error)
	RecordKeyAddedTx(ctx context.Context, tx pgx.Tx, in inventory.KeyAdded) (uuid.UUID, error)
	MarkKeyRemoved(ctx context.Context, locationID uuid.UUID, actor audit.Actor, res providers.AuthKeyResult) error
	KeyLocation(ctx context.Context, id uuid.UUID) (inventory.KeyLocation, error)
}

// Config holds the module's dependencies.
type Config struct {
	Pool      *pgxpool.Pool
	Keyring   *secrets.Keyring
	Audit     *audit.Log
	Clock     clock.Clock
	License   LicenseGate
	Inventory Inventory
	Jobs      inventory.Enqueuer
	Notifier  Notifier // nil = no emails (tests only)
	Log       *slog.Logger
	// Rand is the randomness of Ed25519 seeds; nil = crypto/rand, which production passes (the
	// composition root leaves it nil or passes crypto/rand.Reader). RSA and ECDSA keys always use
	// the standard library's own randomness (keymat.Generate).
	Rand io.Reader
	// HelperBudget is how long one helper call may work on a server (helperproto.HelperBudget, which
	// the composition root passes): an undo after an add without a definite answer waits this long
	// plus 30 s after the add was sent (S3). Required.
	HelperBudget time.Duration
}

// Service is the SSH key module.
type Service struct {
	pool         *pgxpool.Pool
	keyring      *secrets.Keyring
	audit        *audit.Log
	clock        clock.Clock
	license      LicenseGate
	inv          Inventory
	jobs         inventory.Enqueuer
	notifier     Notifier
	log          *slog.Logger
	randMu       sync.Mutex // Config.Rand need not be safe for concurrent use
	rand         io.Reader
	randSafe     bool // rand is crypto/rand's Reader: no randMu needed
	helperBudget time.Duration
}

// New builds the module.
func New(c Config) *Service {
	s := &Service{pool: c.Pool, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, license: c.License, inv: c.Inventory,
		jobs: c.Jobs, notifier: c.Notifier, log: c.Log, rand: c.Rand, helperBudget: c.HelperBudget}
	if c.HelperBudget <= 0 {
		panic("sshkeys: Config.HelperBudget must be set (helperproto.HelperBudget)")
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.rand == nil || s.rand == rand.Reader {
		s.rand, s.randSafe = rand.Reader, true
	}
	return s
}

// genSlots bounds the keys generated at once in this process (MaxGenerations): an RSA 4096 key
// costs about a second of one core. A request beyond it is refused at once (ErrGenerateBusy).
var genSlots = make(chan struct{}, MaxGenerations)

// acquireGenSlot takes a generation slot without waiting; release gives it back.
func acquireGenSlot() (release func(), ok bool) {
	select {
	case genSlots <- struct{}{}:
		return func() { <-genSlots }, true
	default:
		return nil, false
	}
}

// Hook kinds of onHold.
const (
	holdGenerated = "generated" // a new key's PKCS #8
	holdOpened    = "opened"    // a key opened from its envelope
	holdFile      = "file"      // a built download file
	holdTx        = "tx"        // the download's counter transaction begins (no buffer)
)

// onHold sees every clear secret buffer this package owns when it is created (tests only; nil in
// production). A test keeps the slice and asserts it is zero once its owner returned or released.
var onHold func(kind string, b []byte)

func hold(kind string, b []byte) {
	if onHold != nil {
		onHold(kind, b)
	}
}
