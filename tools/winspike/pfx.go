//go:build windows

package main

// A minimal PKCS #12 writer (RFC 7292) with the standard library only, to learn which PFX shape
// PFXImportCertStore accepts on the real images, since go-pkcs12 is not a dependency of this module (§6.3 step 6
// "builds a PKCS #12 in memory"). One unencrypted data ContentInfo holds a certBag and a key bag that share a
// localKeyId; the key bag is either a plain keyBag or a pkcs8ShroudedKeyBag under PBES2 (PBKDF2-HMAC-SHA256,
// AES-256-CBC); the MAC is HMAC-SHA256 with the PKCS #12 key derivation (RFC 7292 appendix B.2).

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"unicode/utf16"
)

var (
	oidData                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidKeyBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPKCS8ShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Certificate     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidLocalKeyID          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidSHA256              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidPBES2               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue // [0] EXPLICIT, built by explicit0
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int
}

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue // SET OF
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue // [0] EXPLICIT
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data asn1.RawValue // [0] EXPLICIT OCTET STRING
}

type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	PRF        pkix.AlgorithmIdentifier
}

func explicit0(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// bmpPassword is the PKCS #12 password encoding for the MAC: UTF-16BE with a two-byte terminator.
func bmpPassword(pw string) []byte {
	var out []byte
	for _, r := range utf16.Encode([]rune(pw)) {
		out = append(out, byte(r>>8), byte(r))
	}
	return append(out, 0, 0)
}

// pkcs12KDF is RFC 7292 B.2 with SHA-256 for one output block (size <= 32), enough for the HMAC-SHA256 key.
func pkcs12KDF(password, salt []byte, iterations int, id byte, size int) []byte {
	const v = 64
	fill := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		n := v * ((len(b) + v - 1) / v)
		out := make([]byte, n)
		for i := range out {
			out[i] = b[i%len(b)]
		}
		return out
	}
	d := bytes.Repeat([]byte{id}, v)
	in := append(fill(salt), fill(password)...)
	h := sha256.Sum256(append(d, in...))
	a := h[:]
	for i := 1; i < iterations; i++ {
		s := sha256.Sum256(a)
		a = s[:]
	}
	return a[:size]
}

func shroud(pkcs8 []byte, password string) ([]byte, error) {
	salt, iv := randBytes(16), randBytes(16)
	const iter = 10000
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(pkcs8)%aes.BlockSize
	plain := append(append([]byte(nil), pkcs8...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, plain)
	params := pbes2Params{
		KeyDerivationFunc: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: mustMarshal(
			pbkdf2Params{Salt: salt, Iterations: iter, PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA256,
				Parameters: asn1.NullRawValue}})}},
		EncryptionScheme: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: mustMarshal(iv)}},
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: mustMarshal(params)}},
		EncryptedData: enc,
	})
}

// buildPFX writes a PFX holding one certificate and its PKCS #8 key. shrouded selects pkcs8ShroudedKeyBag
// (PBES2) over a plain keyBag.
func buildPFX(certDER, pkcs8 []byte, password string, shrouded bool) ([]byte, error) {
	localKeyID := []byte{1}
	attrs := []pkcs12Attribute{{ID: oidLocalKeyID, Value: asn1.RawValue{Class: asn1.ClassUniversal,
		Tag: asn1.TagSet, IsCompound: true, Bytes: mustMarshal(localKeyID)}}}

	cb := mustMarshal(certBag{ID: oidX509Certificate, Data: explicit0(mustMarshal(certDER))})
	keyID, keyVal := oidKeyBag, pkcs8
	if shrouded {
		enc, err := shroud(pkcs8, password)
		if err != nil {
			return nil, err
		}
		keyID, keyVal = oidPKCS8ShroudedKeyBag, enc
	}
	bags := []safeBag{
		{ID: oidCertBag, Value: explicit0(cb), Attributes: attrs},
		{ID: keyID, Value: explicit0(keyVal), Attributes: attrs},
	}
	safeContents, err := asn1.Marshal(bags)
	if err != nil {
		return nil, err
	}
	authSafe, err := asn1.Marshal([]contentInfo{{ContentType: oidData, Content: explicit0(mustMarshal(safeContents))}})
	if err != nil {
		return nil, err
	}
	salt := randBytes(16)
	const iter = 2048
	macKey := pkcs12KDF(bmpPassword(password), salt, iter, 3, 32)
	m := hmac.New(sha256.New, macKey)
	m.Write(authSafe)
	return asn1.Marshal(pfxPdu{
		Version:  3,
		AuthSafe: contentInfo{ContentType: oidData, Content: explicit0(mustMarshal(authSafe))},
		MacData: macData{
			Mac:        digestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, Digest: m.Sum(nil)},
			MacSalt:    salt,
			Iterations: iter,
		},
	})
}
