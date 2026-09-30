package secrets_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
)

func TestSealWithSubkeyRoundTripAndBinding(t *testing.T) {
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	other, err := secrets.NewKeyring(1, bytes.Repeat([]byte{2}, 32))
	require.NoError(t, err)
	aad := []byte("alice/hwm-record/v1")

	sealed, err := k.SealWith(secrets.LabelHWMEnc, aad, []byte("sixteen bytes!!!"))
	require.NoError(t, err)
	again, err := k.SealWith(secrets.LabelHWMEnc, aad, []byte("sixteen bytes!!!"))
	require.NoError(t, err)
	assert.NotEqual(t, sealed, again, "random nonce per seal")

	pt, err := k.OpenWith(secrets.LabelHWMEnc, aad, sealed)
	require.NoError(t, err)
	assert.Equal(t, "sixteen bytes!!!", string(pt))

	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	for name, open := range map[string]func() ([]byte, error){
		"other label":  func() ([]byte, error) { return k.OpenWith(secrets.LabelHWM, aad, sealed) },
		"other aad":    func() ([]byte, error) { return k.OpenWith(secrets.LabelHWMEnc, []byte("x"), sealed) },
		"tampered":     func() ([]byte, error) { return k.OpenWith(secrets.LabelHWMEnc, aad, tampered) },
		"other master": func() ([]byte, error) { return other.OpenWith(secrets.LabelHWMEnc, aad, sealed) },
		"too short":    func() ([]byte, error) { return k.OpenWith(secrets.LabelHWMEnc, aad, sealed[:12]) },
	} {
		_, err := open()
		assert.ErrorIs(t, err, secrets.ErrDecrypt, name)
	}
	assert.NotEqual(t, k.Derive(secrets.LabelHWM), k.Derive(secrets.LabelHWMEnc), "MAC and encryption keys differ")
}
