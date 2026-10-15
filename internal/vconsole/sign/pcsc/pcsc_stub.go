//go:build !yubikey

package pcsc

import "alice/internal/vconsole/sign/openpgp"

// Readers lists the names of the connected PC/SC readers. This build has no PC/SC support.
func Readers() ([]string, error) { return nil, ErrNoPCSC }

// Connect opens a YubiKey reader. This build has no PC/SC support.
func Connect(string) (openpgp.Card, error) { return nil, ErrNoPCSC }
