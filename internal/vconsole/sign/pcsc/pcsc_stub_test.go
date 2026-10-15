//go:build !yubikey

package pcsc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStubHasNoPCSC(t *testing.T) {
	names, err := Readers()
	require.ErrorIs(t, err, ErrNoPCSC)
	assert.Nil(t, names)

	card, err := Connect("")
	require.ErrorIs(t, err, ErrNoPCSC)
	assert.Nil(t, card)

	_, err = Connect("Yubico YubiKey OTP+FIDO+CCID 00 00")
	require.ErrorIs(t, err, ErrNoPCSC)
	assert.Equal(t, "pcsc: this build has no YubiKey support (build with -tags yubikey)", ErrNoPCSC.Error())
}
