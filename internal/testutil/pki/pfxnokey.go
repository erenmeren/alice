package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"unicode/utf16"
)

// CertificatesOnlyPFX builds a PFX that holds certs and no key, in the shape `openssl pkcs12 -export -nokeys`
// (OpenSSL 3) and .NET write: the certificate bags without any attribute (in particular without the Java trust
// attribute go-pkcs12's EncodeTrustStore adds), inside one PBES2 encrypted safe (PBKDF2-HMAC-SHA256, AES-256-CBC),
// and a SHA-256 MAC over the authenticated safe. password may be empty.
func CertificatesOnlyPFX(password string, certs ...*x509.Certificate) []byte {
	var bags []p12SafeBag
	for _, c := range certs {
		value := must(asn1.Marshal(p12CertBag{ID: oidX509CertBag, Value: c.Raw}))
		bags = append(bags, p12SafeBag{ID: oidCertBagType, Value: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: value}})
	}
	plain := must(asn1.Marshal(bags))

	// PBES2: PBKDF2-HMAC-SHA256 over the UTF-8 password, AES-256-CBC with PKCS#7 padding.
	salt, iv := random(16), random(aes.BlockSize)
	const iterations = 2048
	key := must(pbkdf2.Key(sha256.New, password, salt, iterations, 32))
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	for range pad {
		plain = append(plain, byte(pad))
	}
	block := must(aes.NewCipher(key))
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	kdf := p12PBKDF2Params{Salt: salt, Iterations: iterations, KeyLength: 32,
		Prf: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue}}
	scheme := p12PBES2Params{
		KDF:    pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: must(asn1.Marshal(kdf))}},
		Scheme: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: must(asn1.Marshal(iv))}},
	}
	encData := p12EncryptedData{Version: 0, Info: p12EncryptedContentInfo{ContentType: oidDataType,
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: must(asn1.Marshal(scheme))}},
		Content:   asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: encrypted}}}
	authSafe := must(asn1.Marshal([]p12ContentInfo{{ContentType: oidEncryptedDataType, Content: explicit0(must(asn1.Marshal(encData)))}}))

	// The MAC: HMAC-SHA256 with a key from the PKCS #12 KDF (RFC 7292 B.2, ID 3) over the BMP password.
	macSalt := random(16)
	macKey := p12KDF(3, macSalt, bmpPassword(password), iterations, 32)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(authSafe)
	pfx := p12PFX{Version: 3,
		AuthSafe: p12ContentInfo{ContentType: oidDataType, Content: explicit0(must(asn1.Marshal(authSafe)))},
		MacData: p12MacData{Mac: p12DigestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			Digest: mac.Sum(nil)}, Salt: macSalt, Iterations: iterations}}
	return must(asn1.Marshal(pfx))
}

type (
	p12PFX struct {
		Version  int
		AuthSafe p12ContentInfo
		MacData  p12MacData
	}
	p12ContentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}
	p12MacData struct {
		Mac        p12DigestInfo
		Salt       []byte
		Iterations int
	}
	p12DigestInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	p12EncryptedData struct {
		Version int
		Info    p12EncryptedContentInfo
	}
	p12EncryptedContentInfo struct {
		ContentType asn1.ObjectIdentifier
		Algorithm   pkix.AlgorithmIdentifier
		Content     asn1.RawValue
	}
	p12SafeBag struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	p12CertBag struct {
		ID    asn1.ObjectIdentifier
		Value []byte `asn1:"tag:0,explicit"`
	}
	p12PBES2Params struct {
		KDF    pkix.AlgorithmIdentifier
		Scheme pkix.AlgorithmIdentifier
	}
	p12PBKDF2Params struct {
		Salt       []byte
		Iterations int
		KeyLength  int
		Prf        pkix.AlgorithmIdentifier
	}
)

var (
	oidDataType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidCertBagType       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509CertBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidPBES2             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

func explicit0(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

func random(n int) []byte {
	b := make([]byte, n)
	must(rand.Read(b))
	return b
}

// bmpPassword is the password as PKCS #12 hashes it: UTF-16 big-endian with a terminating zero.
func bmpPassword(p string) []byte {
	out := make([]byte, 0, 2*len(p)+2)
	for _, u := range utf16.Encode([]rune(p)) {
		out = binary.BigEndian.AppendUint16(out, u)
	}
	return append(out, 0, 0)
}

// p12KDF is the PKCS #12 key derivation of RFC 7292 appendix B.2 with SHA-256 (u = 32, v = 64).
func p12KDF(id byte, salt, password []byte, iterations, size int) []byte {
	const v = 64 // SHA-256 block size; the output block is 32 bytes
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
	d := make([]byte, v)
	for i := range d {
		d[i] = id
	}
	I := append(fill(salt), fill(password)...)
	var out []byte
	for len(out) < size {
		h := sha256.New()
		h.Write(d)
		h.Write(I)
		a := h.Sum(nil)
		for range iterations - 1 {
			s := sha256.Sum256(a)
			a = s[:]
		}
		out = append(out, a...)
		// I_j = (I_j + B + 1) mod 2^(8v), B = A repeated to v bytes.
		b := fill(a)
		for j := 0; j < len(I); j += v {
			carry := uint16(1)
			for k := v - 1; k >= 0; k-- {
				x := uint16(I[j+k]) + uint16(b[k]) + carry
				I[j+k], carry = byte(x&0xff), x>>8
			}
		}
	}
	return out[:size]
}
