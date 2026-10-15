//go:build yubikey

package pcsc

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ebfe/scard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Without a running PC/SC daemon (the case on this build machine) the call fails with a
// readable error and does not panic. With a daemon the test has nothing to check.
func TestReadersWithoutPCSCDaemonGivesAReadableError(t *testing.T) {
	names, err := Readers()
	if err == nil {
		t.Skipf("a PC/SC daemon is running here (%d readers); this test needs a machine without one", len(names))
	}
	t.Logf("Readers without a daemon: %v", err)
	assert.NotErrorIs(t, err, ErrNoPCSC, "the tagged build has PC/SC support")
	assert.Contains(t, err.Error(), "pcsc")
	if errors.Is(err, ErrNoService) {
		assert.Contains(t, err.Error(), "pcscd")
	}

	card, err := Connect("")
	require.Error(t, err)
	assert.Nil(t, card)
}

func TestPCSCErrorsAreMappedToReadableMessages(t *testing.T) {
	for _, tc := range []struct {
		code scard.Error
		want error
	}{
		{scard.ErrNoService, ErrNoService},
		{scard.ErrServiceStopped, ErrNoService},
		{scard.ErrNoReadersAvailable, ErrNoReaders},
		{scard.ErrNoSmartcard, ErrNoCard},
		{scard.ErrRemovedCard, ErrCardRemoved},
		{scard.ErrResetCard, ErrCardRemoved},
		{scard.ErrReaderUnavailable, ErrReaderUnavailable},
		{scard.ErrUnknownReader, ErrReaderUnavailable},
		{scard.ErrSharingViolation, ErrSharingViolation},
		{scard.ErrTimeout, ErrTimeout},
		{scard.ErrUnresponsiveCard, ErrTimeout},
	} {
		t.Run(fmt.Sprintf("%08X", uint32(tc.code)), func(t *testing.T) {
			err := mapErr("transmit", tc.code)
			require.ErrorIs(t, err, tc.want)
			assert.Contains(t, err.Error(), "transmit")
		})
	}
	assert.Contains(t, ErrSharingViolation.Error(), "gpgconf --kill scdaemon")

	other := mapErr("connect", scard.ErrInternalError)
	require.Error(t, other)
	assert.Contains(t, other.Error(), "connect")
	assert.NoError(t, mapErr("connect", nil))
	assert.Contains(t, mapErr("disconnect", scard.ErrRemovedCard).Error(), "disconnect")
}

// The signing connection holds the card exclusively: no other PC/SC client may slip a command in
// between VERIFY and the signature (package documentation).
func TestSigningConnectionIsExclusive(t *testing.T) {
	assert.Equal(t, scard.ShareExclusive, shareMode)
}
