package secrets_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
)

// fastKDF keeps unit tests quick; production uses secrets.BackupKDF.
var fastKDF = secrets.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

func TestBackupKDFMatchesSpec(t *testing.T) {
	assert.Equal(t, secrets.KDFParams{MemoryKiB: 65536, Time: 3, Threads: 4}, secrets.BackupKDF)
}

func TestBackupKeyRoundTrip(t *testing.T) {
	pass := []byte("CANARY correct horse battery staple")
	w, err := secrets.NewBackupKey(pass, fastKDF)
	require.NoError(t, err)
	assert.Equal(t, 1, w.Version)
	assert.Len(t, w.PublicKey, 32)
	assert.Len(t, w.Salt, 16)

	priv, err := w.Unwrap(pass)
	require.NoError(t, err)
	assert.Equal(t, w.PublicKey, priv.PublicKey().Bytes(), "unwrapped private key matches the stored public key")

	b, err := json.Marshal(w)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "CANARY")
	var back secrets.WrappedBackupKey
	require.NoError(t, json.Unmarshal(b, &back))
	_, err = back.Unwrap(pass)
	require.NoError(t, err, "survives a JSON round trip (stored in settings)")
}

func TestBackupKeyWrongPassphraseOrTampering(t *testing.T) {
	w, err := secrets.NewBackupKey([]byte("the right passphrase!"), fastKDF)
	require.NoError(t, err)
	_, err = w.Unwrap([]byte("the wrong passphrase!"))
	assert.ErrorIs(t, err, secrets.ErrDecrypt)

	swapped := w
	swapped.PublicKey = bytes.Repeat([]byte{1}, 32)
	_, err = swapped.Unwrap([]byte("the right passphrase!"))
	assert.ErrorIs(t, err, secrets.ErrDecrypt, "public key is bound by AAD")

	tampered := w
	tampered.Ciphertext = append([]byte(nil), w.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	_, err = tampered.Unwrap([]byte("the right passphrase!"))
	assert.ErrorIs(t, err, secrets.ErrDecrypt)
}

func TestBackupKeyRejectsHostileKDFParams(t *testing.T) {
	w, err := secrets.NewBackupKey([]byte("the right passphrase!"), fastKDF)
	require.NoError(t, err)
	w.KDF.MemoryKiB = 4 * 1024 * 1024 // 4 GiB
	_, err = w.Unwrap([]byte("the right passphrase!"))
	assert.ErrorContains(t, err, "1 GiB")

	_, err = secrets.NewBackupKey([]byte("x"), secrets.KDFParams{})
	assert.Error(t, err)
}

func TestTwoBackupKeysDiffer(t *testing.T) {
	a, err := secrets.NewBackupKey([]byte("same passphrase value"), fastKDF)
	require.NoError(t, err)
	b, err := secrets.NewBackupKey([]byte("same passphrase value"), fastKDF)
	require.NoError(t, err)
	assert.NotEqual(t, a.PublicKey, b.PublicKey)
	assert.NotEqual(t, a.Salt, b.Salt)
}
