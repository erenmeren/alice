package winhelper

// A minimal PKCS #12 writer (RFC 7292) with the standard library only (W2 Ruling 9; the helper links no
// PKCS #12 library), the writer tools/winspike/pfx.go measured on the real images in W0: one data
// ContentInfo holding a certBag and a pkcs8ShroudedKeyBag that share a localKeyId; the key bag is under
// PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC); the MAC is HMAC-SHA256 with the PKCS #12 key derivation
// (RFC 7292 appendix B.2) over the password as a BMPString.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
)

var (
	oidData                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
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

// The iteration counts of the W0 spike's PFX (accepted by PFXImportCertStore on 2022 and 2025).
const (
	pfxKeyIterations = 10000
	pfxMACIterations = 2048
	// pfxPasswordLen is NewPFXPassword's length: 32 characters of 6 random bits each.
	pfxPasswordLen = 32
)

var errPFX = errors.New("winhelper: the PKCS #12 could not be built")

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue // [0] EXPLICIT
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
	Value      asn1.RawValue     // [0] EXPLICIT
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

// passwordAlphabet is the alphabet of NewPFXPassword (64 printable ASCII characters).
const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// NewPFXPassword is a one-time PFX password: 32 printable ASCII characters (192 random bits). The
// caller clears it after the import.
func NewPFXPassword() []byte {
	pw := random(pfxPasswordLen)
	for i, b := range pw {
		pw[i] = passwordAlphabet[b&63]
	}
	return pw
}

// validPassword: printable ASCII, so its BMPString and its PBKDF2 bytes are the same text.
func validPassword(pw []byte) bool {
	if len(pw) == 0 {
		return false
	}
	for _, c := range pw {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// bmpString is the PKCS #12 password encoding for the MAC: UTF-16BE (of ASCII) with a two-byte
// terminator. The caller clears it.
func bmpString(pw []byte) []byte {
	out := make([]byte, 0, 2*len(pw)+2)
	for _, c := range pw {
		out = append(out, 0, c)
	}
	return append(out, 0, 0)
}

// pbkdf2SHA256 is PBKDF2-HMAC-SHA256 (RFC 8018) over a password the caller can clear (crypto/pbkdf2
// takes a string, which nobody can clear).
func pbkdf2SHA256(password, salt []byte, iterations, size int) []byte {
	prf := hmac.New(sha256.New, password)
	out := make([]byte, 0, size+sha256.Size)
	u := make([]byte, 0, sha256.Size)
	t := make([]byte, sha256.Size)
	var counter [4]byte
	for block := uint32(1); len(out) < size; block++ {
		binary.BigEndian.PutUint32(counter[:], block)
		prf.Reset()
		prf.Write(salt)
		prf.Write(counter[:])
		u = prf.Sum(u[:0])
		copy(t, u)
		for range iterations - 1 {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		out = append(out, t...)
	}
	clear(u)
	clear(t)
	key := bytes.Clone(out[:size])
	clear(out)
	return key
}

// pkcs12KDF is RFC 7292 B.2 with SHA-256 for one output block (size <= 32), enough for the HMAC-SHA256
// key. Every intermediate buffer is cleared.
func pkcs12KDF(password, salt []byte, iterations int, id byte, size int) []byte {
	const v = 64
	fill := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		out := make([]byte, v*((len(b)+v-1)/v))
		for i := range out {
			out[i] = b[i%len(b)]
		}
		return out
	}
	s, p := fill(salt), fill(password)
	in := make([]byte, 0, v+len(s)+len(p))
	in = append(append(append(in, bytes.Repeat([]byte{id}, v)...), s...), p...)
	a := sha256.Sum256(in)
	for i := 1; i < iterations; i++ {
		a = sha256.Sum256(a[:])
	}
	clear(p)
	clear(in)
	key := bytes.Clone(a[:size])
	clear(a[:])
	return key
}

// asn1Writer marshals a sequence of fixed, well-typed values and keeps the first error, so the writer
// checks once.
type asn1Writer struct{ err error }

func (w *asn1Writer) marshal(v any) []byte {
	if w.err != nil {
		return nil
	}
	b, err := asn1.Marshal(v)
	if err != nil {
		w.err = errPFX
	}
	return b
}

// random is n bytes from crypto/rand (which never fails: it ends the program instead).
func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func shroud(w *asn1Writer, pkcs8, password []byte) []byte {
	salt, iv := random(16), random(16)
	key := pbkdf2SHA256(password, salt, pfxKeyIterations, 32)
	defer clear(key)
	block, _ := aes.NewCipher(key) // a 32-byte key is always an AES-256 key
	pad := aes.BlockSize - len(pkcs8)%aes.BlockSize
	plain := make([]byte, len(pkcs8)+pad)
	defer clear(plain)
	copy(plain, pkcs8)
	for i := len(pkcs8); i < len(plain); i++ {
		plain[i] = byte(pad)
	}
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, plain)
	kdf := w.marshal(pbkdf2Params{Salt: salt, Iterations: pfxKeyIterations,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: asn1.NullRawValue}})
	params := w.marshal(pbes2Params{
		KeyDerivationFunc: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		EncryptionScheme:  pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: w.marshal(iv)}},
	})
	return w.marshal(encryptedPrivateKeyInfo{
		Algorithm:     pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		EncryptedData: enc,
	})
}

// BuildPFX writes a PFX holding the leaf certificate (DER) and its PKCS #8 private key under password
// (printable ASCII, NewPFXPassword). Only the leaf goes in: intermediates go to LocalMachine\CA as
// public certificates (W2 Ruling 9). BuildPFX clears every buffer of its own that held the key or the
// password in clear; it does not clear its inputs (the caller does, and the returned PFX after the
// import). Its error is one fixed text.
func BuildPFX(leafDER, keyPKCS8, password []byte) ([]byte, error) {
	if len(leafDER) == 0 || len(keyPKCS8) == 0 || !validPassword(password) {
		return nil, errPFX
	}
	var w asn1Writer
	attrs := []pkcs12Attribute{{ID: oidLocalKeyID, Value: asn1.RawValue{Class: asn1.ClassUniversal,
		Tag: asn1.TagSet, IsCompound: true, Bytes: w.marshal([]byte{1})}}}
	cb := w.marshal(certBag{ID: oidX509Certificate, Data: explicit0(w.marshal(leafDER))})
	safeContents := w.marshal([]safeBag{
		{ID: oidCertBag, Value: explicit0(cb), Attributes: attrs},
		{ID: oidPKCS8ShroudedKeyBag, Value: explicit0(shroud(&w, keyPKCS8, password)), Attributes: attrs},
	})
	authSafe := w.marshal([]contentInfo{{ContentType: oidData, Content: explicit0(w.marshal(safeContents))}})
	salt := random(16)
	bmp := bmpString(password)
	macKey := pkcs12KDF(bmp, salt, pfxMACIterations, 3, 32)
	clear(bmp)
	m := hmac.New(sha256.New, macKey)
	clear(macKey)
	m.Write(authSafe)
	out := w.marshal(pfxPdu{
		Version:  3,
		AuthSafe: contentInfo{ContentType: oidData, Content: explicit0(w.marshal(authSafe))},
		MacData: macData{
			Mac:        digestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, Digest: m.Sum(nil)},
			MacSalt:    salt,
			Iterations: pfxMACIterations,
		},
	})
	if w.err != nil {
		return nil, w.err
	}
	return out, nil
}
