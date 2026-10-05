package sshkeys

import "testing"

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
