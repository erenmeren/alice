package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shroudedKey is a pkcs8ShroudedKeyBag value of BuildPFX's form whose plaintext is plain, padded as given.
func shroudedKey(t *testing.T, password string, plain []byte, iterations int) []byte {
	t.Helper()
	salt, iv := random(16), random(aes.BlockSize)
	k := must(pbkdf2.Key(sha256.New, password, salt, 1, 32)) // the count written below may be one never computed
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(must(aes.NewCipher(k)), iv).CryptBlocks(encrypted, plain)
	kdf := p12PBKDF2Params{Salt: salt, Iterations: iterations, KeyLength: 32,
		Prf: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue}}
	scheme := p12PBES2Params{
		KDF:    pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: must(asn1.Marshal(kdf))}},
		Scheme: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: must(asn1.Marshal(iv))}},
	}
	return must(asn1.Marshal(p12EncryptedKey{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2,
		Parameters: asn1.RawValue{FullBytes: must(asn1.Marshal(scheme))}}, EncryptedData: encrypted}))
}

// The reader takes a third party's bytes in the emulator: every PKCS #7 pad byte is checked, and an
// iteration count past maxPFXIterations is refused before it is computed.
func TestOpenPFXRefusesBadPaddingAndHugeCounts(t *testing.T) {
	l := SelfSigned("pad.example.test", ECDSA256, now)
	der := must(x509.MarshalPKCS8PrivateKey(l.Key))
	good := append([]byte{}, der...)
	pad := aes.BlockSize - len(good)%aes.BlockSize
	for range pad {
		good = append(good, byte(pad))
	}
	key, err := decryptKey(shroudedKey(t, "pw", good, 1), []byte("pw"))
	require.NoError(t, err)
	assert.NotNil(t, key)

	// The last byte says 2 (or more), a byte before it says otherwise.
	bad := append([]byte{}, good...)
	if pad < 2 {
		bad = append(bad, make([]byte, aes.BlockSize)...)
		bad[len(bad)-1] = 2
	} else {
		bad[len(bad)-2] ^= 0xff
	}
	_, err = decryptKey(shroudedKey(t, "pw", bad, 1), []byte("pw"))
	assert.ErrorIs(t, err, ErrNotPFX)

	for _, n := range []int{0, maxPFXIterations + 1, 1 << 30} {
		start := time.Now()
		_, err = decryptKey(shroudedKey(t, "pw", good, n), []byte("pw"))
		assert.ErrorIs(t, err, ErrNotPFX, "%d iterations", n)
		assert.Less(t, time.Since(start), 5*time.Second, "refused before it is computed")
	}

	// A MAC count past the bound is refused before the MAC is computed.
	pfx := must(asn1.Marshal(p12PFX{Version: 3,
		AuthSafe: p12ContentInfo{ContentType: oidDataType, Content: explicit0(must(asn1.Marshal([]byte("x"))))},
		MacData: p12MacData{Mac: p12DigestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			Digest: make([]byte, 32)}, Salt: random(16), Iterations: 1 << 30}}))
	start := time.Now()
	_, _, err = OpenPFX(pfx, []byte("pw"))
	assert.ErrorIs(t, err, ErrNotPFX)
	assert.Less(t, time.Since(start), 5*time.Second)
}
