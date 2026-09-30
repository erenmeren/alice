// Package jobs runs Alice's background work. Every job type declares its license class
// (spec §8.6, X-01), and every scheduled run passes the license gate first. Phase 2 has
// the periodic in-process scheduler; the durable PostgreSQL job queue (§8.1) arrives with
// targets in Phase 3 and uses the same registry and gate.
package jobs

import (
	"fmt"
	"sort"
	"sync"

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
