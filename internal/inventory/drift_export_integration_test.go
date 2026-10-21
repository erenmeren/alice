//go:build integration

package inventory

import "github.com/google/uuid"

// SetDriftRepairHook runs f before each location's repair is planned (the world changes between the planner's read and
// the location's transaction) and returns a function removing it.
func SetDriftRepairHook(f func(location uuid.UUID)) (restore func()) {
	driftRepairHook = f
	return func() { driftRepairHook = nil }
}
