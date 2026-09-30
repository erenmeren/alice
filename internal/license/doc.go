// Package license verifies Alice's signed license files and computes the license
// state (evaluation, active, grace, locked) from a trusted clock (spec §16, §23).
//
// The file format, key set, state machine and clock guard are pure and tested
// without a database. Service (service.go) stores uploaded files verbatim,
// re-verifies them on every evaluation and is the single lock-mode gate (Allow)
// used by the API guard and the job scheduler.
package license
