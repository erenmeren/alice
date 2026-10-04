package license

import "time"

// SetUploadCommittedHook runs f after an upload has committed and before the evaluation
// that follows it (tests only: it lets a test end the request at that moment).
func SetUploadCommittedHook(s *Service, f func()) { s.uploadCommitted = f }

// SetRowLockTimeout lowers the wait for the license row lock (tests that hold the row).
func SetRowLockTimeout(s *Service, d time.Duration) { s.rowLockTimeout = d }

// AllowIn is the gate's pure decision (AUD-02).
var AllowIn = allowIn
