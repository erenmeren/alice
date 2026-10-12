package db

import "time"

// SetRollbackTimeout lets tests shorten how long InTx waits for a rollback; it returns a function that restores it.
func SetRollbackTimeout(d time.Duration) (restore func()) {
	old := rollbackTimeout
	rollbackTimeout = d
	return func() { rollbackTimeout = old }
}
