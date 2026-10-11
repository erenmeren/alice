package secrets_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
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
	w, _, err := secrets.NewBackupKey(pass, fastKDF)
	require.NoError(t, err)
	assert.Equal(t, 2, w.Version)
	assert.Len(t, w.PublicKey, 32)
	assert.Len(t, w.SenderPublicKey, 32)
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
	w, _, err := secrets.NewBackupKey([]byte("the right passphrase!"), fastKDF)
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
	w, _, err := secrets.NewBackupKey([]byte("the right passphrase!"), fastKDF)
	require.NoError(t, err)
	w.KDF.MemoryKiB = 4 * 1024 * 1024 // 4 GiB
	_, err = w.Unwrap([]byte("the right passphrase!"))
	assert.ErrorContains(t, err, "1 GiB")

	_, _, err = secrets.NewBackupKey([]byte("x"), secrets.KDFParams{})
	assert.Error(t, err)
}

func TestTwoBackupKeysDiffer(t *testing.T) {
	a, as, err := secrets.NewBackupKey([]byte("same passphrase value"), fastKDF)
	require.NoError(t, err)
	b, bs, err := secrets.NewBackupKey([]byte("same passphrase value"), fastKDF)
	require.NoError(t, err)
	assert.NotEqual(t, a.PublicKey, b.PublicKey)
	assert.NotEqual(t, a.SenderPublicKey, b.SenderPublicKey)
	assert.NotEqual(t, as.Bytes(), bs.Bytes())
	assert.NotEqual(t, a.Salt, b.Salt)
}

// R43 row 41 (pre-flight S-2): the passphrase step also makes the installation's sender key S. Its public half is
// part of the wrapped record; its private half goes to the caller (setup stores it as the setting secret backup.sender).
func TestNewBackupKeyReturnsTheSenderKey(t *testing.T) {
	pass := []byte("CANARY sender key passphrase")
	w, sender, err := secrets.NewBackupKey(pass, fastKDF)
	require.NoError(t, err)
	require.NotNil(t, sender)
	assert.Equal(t, 2, w.Version)
	assert.Equal(t, w.SenderPublicKey, sender.PublicKey().Bytes())
	assert.NotEqual(t, w.PublicKey, w.SenderPublicKey)

	priv, err := w.Unwrap(pass)
	require.NoError(t, err)
	assert.NotEqual(t, priv.Bytes(), sender.Bytes(), "the recipient and the sender are two key pairs")

	b, err := json.Marshal(w)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"sender_public_key":`)
	assert.True(t, strings.HasSuffix(string(b), `"sender_public_key":"`+base64.StdEncoding.EncodeToString(w.SenderPublicKey)+`"}`),
		"sender_public_key is the last field (C7 header order): %s", b)
	assert.NotContains(t, string(b), base64.StdEncoding.EncodeToString(sender.Bytes()), "the sender private key is never in the record")
	assert.NotContains(t, string(b), "CANARY")
}

// The passphrase authenticates both public keys: changing either in the clear record makes Unwrap fail.
func TestWrappedKeyV2BindsSender(t *testing.T) {
	pass := []byte("the right passphrase!")
	w, _, err := secrets.NewBackupKey(pass, fastKDF)
	require.NoError(t, err)
	_, err = w.Unwrap(pass)
	require.NoError(t, err)

	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	sender := w
	sender.SenderPublicKey = other.PublicKey().Bytes()
	_, err = sender.Unwrap(pass)
	assert.ErrorIs(t, err, secrets.ErrDecrypt, "sender_public_key is bound by the AAD")

	flipped := w
	flipped.SenderPublicKey = append([]byte(nil), w.SenderPublicKey...)
	flipped.SenderPublicKey[31] ^= 0x01
	_, err = flipped.Unwrap(pass)
	assert.ErrorIs(t, err, secrets.ErrDecrypt)

	recipient := w
	recipient.PublicKey = other.PublicKey().Bytes()
	_, err = recipient.Unwrap(pass)
	assert.ErrorIs(t, err, secrets.ErrDecrypt, "public_key is bound by the AAD")

	swapped := w
	swapped.PublicKey, swapped.SenderPublicKey = w.SenderPublicKey, w.PublicKey
	_, err = swapped.Unwrap(pass)
	assert.ErrorIs(t, err, secrets.ErrDecrypt, "the two keys are not interchangeable")
}

// Only version 2 exists (no format-1 key was ever released); anything else is refused before the KDF runs.
func TestUnwrapRefusesVersion1(t *testing.T) {
	pass := []byte("the right passphrase!")
	w, _, err := secrets.NewBackupKey(pass, fastKDF)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*secrets.WrappedBackupKey){
		"version 1":        func(k *secrets.WrappedBackupKey) { k.Version = 1 },
		"version 3":        func(k *secrets.WrappedBackupKey) { k.Version = 3 },
		"version 0":        func(k *secrets.WrappedBackupKey) { k.Version = 0 },
		"no sender key":    func(k *secrets.WrappedBackupKey) { k.SenderPublicKey = nil },
		"short sender key": func(k *secrets.WrappedBackupKey) { k.SenderPublicKey = k.SenderPublicKey[:31] },
		"long sender key": func(k *secrets.WrappedBackupKey) {
			k.SenderPublicKey = append(append([]byte{}, k.SenderPublicKey...), 0)
		},
		"short public key": func(k *secrets.WrappedBackupKey) { k.PublicKey = k.PublicKey[:31] },
		"no salt":          func(k *secrets.WrappedBackupKey) { k.Salt = nil },
		"short nonce":      func(k *secrets.WrappedBackupKey) { k.Nonce = k.Nonce[:11] },
		"empty ciphertext": func(k *secrets.WrappedBackupKey) { k.Ciphertext = nil },
		"short ciphertext": func(k *secrets.WrappedBackupKey) { k.Ciphertext = k.Ciphertext[:47] },
	} {
		k := w
		mutate(&k)
		_, err := k.Unwrap(pass)
		assert.ErrorIs(t, err, secrets.ErrDecrypt, name)
	}

	// A v1-shaped record (no sender key, version 1) as development databases may still hold.
	var v1 secrets.WrappedBackupKey
	require.NoError(t, json.Unmarshal([]byte(`{"version":1,"public_key":"`+base64.StdEncoding.EncodeToString(w.PublicKey)+
		`","kdf":{"memory_kib":64,"time":1,"threads":1},"salt":"`+base64.StdEncoding.EncodeToString(w.Salt)+
		`","nonce":"`+base64.StdEncoding.EncodeToString(w.Nonce)+`","ciphertext":"`+base64.StdEncoding.EncodeToString(w.Ciphertext)+`"}`), &v1))
	_, err = v1.Unwrap(pass)
	assert.ErrorIs(t, err, secrets.ErrDecrypt)
}

// A record that authenticates under the v2 AAD but holds a private key whose public half is not public_key is refused:
// otherwise whoever can write the record could point the clear public key at one key and the wrapped key at another.
func TestUnwrapChecksThePublicKey(t *testing.T) {
	pass := []byte("the right passphrase!")
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	another, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	good, err := secrets.SealBackupKeyForTest(pass, fastKDF, recipient.Bytes(), recipient.PublicKey().Bytes(), sender.PublicKey().Bytes())
	require.NoError(t, err)
	priv, err := good.Unwrap(pass)
	require.NoError(t, err, "the helper seals exactly as NewBackupKey does")
	assert.Equal(t, recipient.Bytes(), priv.Bytes())

	bad, err := secrets.SealBackupKeyForTest(pass, fastKDF, another.Bytes(), recipient.PublicKey().Bytes(), sender.PublicKey().Bytes())
	require.NoError(t, err)
	_, err = bad.Unwrap(pass)
	assert.ErrorIs(t, err, secrets.ErrDecrypt)

	short, err := secrets.SealBackupKeyForTest(pass, fastKDF, another.Bytes()[:31], recipient.PublicKey().Bytes(), sender.PublicKey().Bytes())
	require.NoError(t, err)
	_, err = short.Unwrap(pass)
	assert.ErrorIs(t, err, secrets.ErrDecrypt, "a wrapped value that is not an X25519 key")
}

// Task 1 review I-1: the passphrase is NFKC-normalised inside secrets, at wrap and at Unwrap, so a restore typed in
// composed or decomposed Unicode (a macOS terminal, another input method) opens the same key.
func TestUnwrapNormalisesThePassphrase(t *testing.T) {
	composed := "çağrı İşgüzar ölçü é ＡＢＣ passphrase"            // NFC, with full-width letters
	decomposed := "çağrı İşgüzar ölçü é ＡＢＣ passphrase" // NFD
	require.NotEqual(t, composed, decomposed)

	w, _, err := secrets.NewBackupKey([]byte(composed), fastKDF)
	require.NoError(t, err)
	for name, p := range map[string]string{
		"composed":      composed,
		"decomposed":    decomposed,
		"compatibility": "çağrı İşgüzar ölçü é ABC passphrase", // the NFKC form of the full-width letters
	} {
		_, err := w.Unwrap([]byte(p))
		assert.NoError(t, err, name)
	}

	d, _, err := secrets.NewBackupKey([]byte(decomposed), fastKDF)
	require.NoError(t, err)
	_, err = d.Unwrap([]byte(composed))
	assert.NoError(t, err, "wrapped decomposed, unwrapped composed")

	_, err = w.Unwrap([]byte("cagri Isguzar olcu e ABC passphrase"))
	assert.ErrorIs(t, err, secrets.ErrDecrypt, "normalisation does not strip the marks")
}

// Records written before the fix were wrapped with the passphrase setup had already normalised. NFKC is idempotent,
// so they still open, and Unwrap does not modify the caller's buffer.
func TestUnwrapOpensKeysWrappedBeforeTheFix(t *testing.T) {
	normalised := []byte("çağrı İşgüzar ölçü é ABC passphrase") // NFKC already, as setup passed it
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	old, err := secrets.SealBackupKeyRawForTest(normalised, fastKDF, recipient.Bytes(), recipient.PublicKey().Bytes(), sender.PublicKey().Bytes())
	require.NoError(t, err)

	decomposed := []byte("çağrı İşgüzar ölçü é ABC passphrase")
	for _, p := range [][]byte{normalised, decomposed} {
		keep := bytes.Clone(p)
		priv, err := old.Unwrap(p)
		require.NoError(t, err)
		assert.Equal(t, recipient.Bytes(), priv.Bytes())
		assert.Equal(t, keep, p, "the caller's passphrase buffer is not cleared or rewritten")
	}
}

// An empty or oversized passphrase is refused at wrap, and at Unwrap it is ErrDecrypt before Argon2 runs.
func TestBackupKeyPassphraseLength(t *testing.T) {
	_, _, err := secrets.NewBackupKey(nil, fastKDF)
	assert.Error(t, err, "empty")
	_, _, err = secrets.NewBackupKey([]byte{}, fastKDF)
	assert.Error(t, err, "empty")
	maxRunes := []byte(strings.Repeat("ş", secrets.MaxPassphraseRunes))
	_, _, err = secrets.NewBackupKey(maxRunes, fastKDF)
	assert.NoError(t, err, "the setup maximum (1,024 runes) fits")
	_, _, err = secrets.NewBackupKey([]byte(strings.Repeat("ş", secrets.MaxPassphraseRunes+1)), fastKDF)
	assert.Error(t, err, "one rune over")
	_, _, err = secrets.NewBackupKey([]byte(strings.Repeat("a", 1<<20)), fastKDF)
	assert.Error(t, err, "1 MiB")

	w, _, err := secrets.NewBackupKey([]byte("the right passphrase!"), fastKDF)
	require.NoError(t, err)
	for name, p := range map[string][]byte{
		"empty":   {},
		"nil":     nil,
		"1 MiB":   []byte(strings.Repeat("a", 1<<20)),
		"1 rune+": []byte(strings.Repeat("ş", secrets.MaxPassphraseRunes+1)),
	} {
		_, err := w.Unwrap(p)
		assert.ErrorIs(t, err, secrets.ErrDecrypt, name)
	}
}
