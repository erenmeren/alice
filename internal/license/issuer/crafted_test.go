package issuer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests build files that only a holder of the passphrase or of the signing key could
// write, to prove the checks that run after decryption and after signature verification.

const craftedWords = "amber canyon violet orbit lantern quiet"

// craftKeyFile seals seed under craftedWords with the public key header pub.
func craftKeyFile(t *testing.T, seed []byte, pub ed25519.PublicKey) []byte {
	t.Helper()
	p := KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}
	salt := bytes.Repeat([]byte{1}, saltSize)
	headers := map[string]string{
		"Key-Id": "vk-2026-01", "Kdf": "argon2id", "Kdf-Params": "m=64,t=1,p=1",
		"Salt": base64.StdEncoding.EncodeToString(salt), "Public-Key": base64.StdEncoding.EncodeToString(pub),
	}
	gcm, err := keyCipher([]byte(craftedWords), salt, p)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	headers["Nonce"] = base64.StdEncoding.EncodeToString(nonce)
	ct := gcm.Seal(nil, nonce, seed, keyAADFor(headers))
	return pem.EncodeToMemory(&pem.Block{Type: privatePEMType, Headers: headers, Bytes: ct})
}

func TestOpenKeyRefusesAuthenticSealedGarbage(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	_, err := OpenKey(craftKeyFile(t, seed, pub), []byte(craftedWords))
	require.NoError(t, err, "the crafted file is well formed")

	_, err = OpenKey(craftKeyFile(t, seed[:16], pub), []byte(craftedWords))
	require.ErrorIs(t, err, ErrBadKeyFile, "a seed of the wrong length")

	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	_, err = OpenKey(craftKeyFile(t, seed, other), []byte(craftedWords))
	require.ErrorIs(t, err, ErrBadKeyFile, "a public key header that does not belong to the seed")
}

// A row whose chain and signature verify but whose values cannot be read back is still
// reported as a broken ledger (it could only come from a faulty writer).
func TestLedgerRefusesASignedButUnreadableRow(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	for name, fields := range map[string][]string{
		"timestamp": {"LIC-1", "C", "ALICE-X", "yesterday", "2026-10-01T00:00:00Z", "2027-10-01T00:00:00Z", "10", "", "ab"},
		"targets":   {"LIC-1", "C", "ALICE-X", "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z", "2027-10-01T00:00:00Z", "ten", "", "ab"},
	} {
		t.Run(name, func(t *testing.T) {
			chain := ledgerChain(make([]byte, sha256.Size), fields)
			sig := ed25519.Sign(priv, append([]byte(ledgerPrefix), chain...))
			var buf bytes.Buffer
			w := csv.NewWriter(&buf)
			require.NoError(t, w.Write(ledgerHeader))
			require.NoError(t, w.Write(append(fields, hex.EncodeToString(chain), base64.StdEncoding.EncodeToString(sig))))
			w.Flush()
			path := filepath.Join(t.TempDir(), LedgerFile)
			require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
			_, err := ReadLedger(path, pub)
			require.ErrorIs(t, err, ErrLedgerBroken)
			assert.ErrorContains(t, err, "row 1")
		})
	}
}
