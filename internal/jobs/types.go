// Package jobs runs Alice's background work. Every job type declares its license class
// (spec §8.6, X-01), and every run passes the license gate first: the periodic in-process
// scheduler before each tick, the durable PostgreSQL queue (§8.1, queue.go and runner.go)
// before and right after every claim.
package jobs

import (
	"fmt"
	"sort"
	"sync"

	"alice/internal/inventory"
	"alice/internal/license"
)

// Type is a job type and the way lock mode treats it.
type Type struct {
	Name  string
	Class license.Class
}

var (
	registryMu sync.Mutex
	registry   = map[string]Type{}
)

// Register declares a job type. It panics on an invalid license class or a duplicate name,
// so no job type can exist without a class (X-01).
func Register(name string, class license.Class) Type {
	if name == "" || !class.Valid() {
		panic(fmt.Sprintf("jobs: job type %q must declare a license class", name))
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("jobs: job type %q is registered twice", name))
	}
	t := Type{Name: name, Class: class}
	registry[name] = t
	return t
}

// Types returns every registered job type, sorted by name.
func Types() []Type {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Type, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func lookup(name string) (Type, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	t, ok := registry[name]
	return t, ok
}

// Phase 2 job types (spec §8.2). Both run in every license state (§8.6).
var (
	LicenseEvaluate = Register("license.evaluate", license.ClassAlways)
	NotifySend      = Register("notify.send", license.ClassAlways)
)

// Phase 3 queue job types (spec §8.2, §8.6): connection tests and discovery are read-only work
// (paused in lock); removing a key changes a managed server (refused in lock, R9).
var (
	TargetTestConnection = Register(inventory.JobTestConnection, license.ClassReadOnly)
	TargetDiscover       = Register(inventory.JobDiscover, license.ClassReadOnly)
	SSHKeyRemove         = Register(inventory.JobSSHKeyRemove, license.ClassChange)
)

// Kind says who asked for a job (jobs.kind).
type Kind string

// Job kinds.
const (
	KindUser      Kind = "user"
	KindScheduled Kind = "scheduled"
	KindSystem    Kind = "system"
)

func (k Kind) valid() bool { return k == KindUser || k == KindScheduled || k == KindSystem }

// Status is a job's state (jobs.status).
type Status string

// Job statuses. StatusBlocked: external-change work that was due while the license was
// expired; it runs only after an Administrator confirms it (R29, L-81).
const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
	StatusDead      Status = "dead"
	StatusBlocked   Status = "blocked_license"
)

// MaxAttemptsFor is the default number of attempts of a job type (spec §8.4): a connection
// test is shown to the user at once and not retried; discovery tolerates a flaky network.
func MaxAttemptsFor(t Type) int {
	switch t.Name {
	case inventory.JobTestConnection:
		return 1
	case inventory.JobDiscover:
		return 5
	default:
		return 3
	}
}
