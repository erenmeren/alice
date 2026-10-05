package sshkeys

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// HoldGenerationSlots takes every generation slot until the returned release is called.
func HoldGenerationSlots(t *testing.T) func() {
	t.Helper()
	for range MaxGenerations {
		genSlots <- struct{}{}
	}
	return func() {
		for range MaxGenerations {
			<-genSlots
		}
	}
}

// OnHold makes fn see every clear secret buffer the module holds, when it is created ("generated":
// a new key's PKCS #8, "opened": a key opened from its envelope, "file": a built download file),
// and the start of the download's counter transaction ("tx", nil). It is reset after the test.
func OnHold(t *testing.T, fn func(kind string, b []byte)) {
	t.Helper()
	onHold = fn
	t.Cleanup(func() { onHold = nil })
}

// OnOpenedKey makes fn see the plaintext of every key opened from its envelope.
func OnOpenedKey(t *testing.T, fn func(b []byte)) {
	t.Helper()
	OnHold(t, func(kind string, b []byte) {
		if kind == holdOpened {
			fn(b)
		}
	})
}

// OnPolicyRead makes fn run between the unlocked read of a policy's open run and the policy lock.
func OnPolicyRead(t *testing.T, fn func()) {
	t.Helper()
	onPolicyRead = fn
	t.Cleanup(func() { onPolicyRead = nil })
}

// OnLiveFound makes fn run after the destroyed keys found live were read, before their audit rows.
func OnLiveFound(t *testing.T, fn func()) {
	t.Helper()
	onLiveFound = fn
	t.Cleanup(func() { onLiveFound = nil })
}

// OnBeforeStart makes fn run between Run now's insert of a run and its start (nil: none).
func OnBeforeStart(t *testing.T, fn func()) {
	t.Helper()
	onBeforeStart = fn
	t.Cleanup(func() { onBeforeStart = nil })
}

// OnRetireCandidates makes fn run after the hourly task read the old keys to retire.
func OnRetireCandidates(t *testing.T, fn func()) {
	t.Helper()
	onRetireCandidates = fn
	t.Cleanup(func() { onRetireCandidates = nil })
}

// FailRefused ends a location the database refused to re-queue (see failRefused); ended reports
// whether an edge of the run's status existed.
func FailRefused(ctx context.Context, s *Service, locID uuid.UUID) (bool, error) {
	return s.failRefused(ctx, locID)
}

// ReconcileDeploy reconciles one ended deploy job (see reconcileDeploy): the re-checks under the job's lock.
func ReconcileDeploy(ctx context.Context, s *Service, jobID uuid.UUID) error {
	return s.reconcileDeploy(ctx, jobID)
}
