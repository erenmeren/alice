package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// kvScratch owns the buffers ParseKVSecret fills with key material (the decoded PFX, the PEM key
// blocks) and clears all of them when it returns, whichever way it returns. onWipe is a test hook.
type kvScratch struct {
	bufs   [][]byte
	onWipe func([]byte)
}

// take returns a zeroed buffer of n bytes that wipe clears.
func (s *kvScratch) take(n int) []byte {
	b := make([]byte, n)
	s.bufs = append(s.bufs, b)
	return b
}

func (s *kvScratch) wipe() {
	for _, b := range s.bufs {
		if s.onWipe != nil {
			s.onWipe(b)
		}
		clear(b)
	}
}

// ParseKVSecret decodes the backing secret of a vault certificate version (spec §11.5 items 3-5).
// application/x-pkcs12: base64 of a PFX with an empty password; application/x-pem-file: PEM text
// with CERTIFICATE and PRIVATE KEY blocks in any order. The result is validated as an upload
// (ValidateUpload: key match, expiry, key and signature strength, the PFX iteration guard, the RSA
// size cap, the certificate date range) and the chain loses a self-signed last certificate. Errors
// never contain input. value is not modified: the caller owns it and zeroes it. Every copy of the
// key this function makes is cleared before it returns; the key in the result is the caller's to
// zero (Validated.PrivateKeyDER).
func ParseKVSecret(contentType string, value []byte, now time.Time, roots *x509.CertPool) (Validated, error) {
	var scratch kvScratch
	return parseKVSecret(contentType, value, now, roots, &scratch)
}

func parseKVSecret(contentType string, value []byte, now time.Time, roots *x509.CertPool, scratch *kvScratch) (Validated, error) {
	defer scratch.wipe()
	if len(value) > MaxKVSecretSize {
		return Validated{}, ErrTooLarge
	}
	var u Upload
	switch contentType {
	case ContentTypePKCS12:
		src := bytes.TrimSpace(value)
		raw := scratch.take(base64.StdEncoding.DecodedLen(len(src)))
		n, err := base64.StdEncoding.Decode(raw, src)
		if err != nil {
			return Validated{}, invalid("the vault secret is not base64")
		}
		u = Upload{PFX: raw[:n]}
	case ContentTypePEM:
		certPEM, keyPEM, err := splitPEM(value, scratch)
		if err != nil {
			return Validated{}, err
		}
		u = Upload{CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
	default:
		return Validated{}, ErrKVContentType
	}
	v, err := ValidateUpload(u, now, roots)
	if err != nil {
		if errors.Is(err, ErrPFXPassword) && u.PFX != nil && pfxHoldsCertificatesOnly(u.PFX) {
			// A non-exportable certificate's secret: the certificates without the key. Said as such,
			// like the PEM form without a key, so the inventory can mark the certificate Monitor only.
			return Validated{}, ErrNoKey
		}
		return Validated{}, err
	}
	v.Parsed = WithoutRoot(v.Parsed)
	return v, nil
}

// errPFXKeyMissing is go-pkcs12's (v0.7.3) answer for a PFX that decrypted and authenticated with the password and
// held at least one certificate but no key bag. The library has no sentinel for it; the KV secret tests pin the
// text with a Java trust store and with an openssl -nokeys shaped file (pki.CertificatesOnlyPFX), so an upgrade that
// changes it fails there.
const errPFXKeyMissing = "pkcs12: private key missing"

// pfxHoldsCertificatesOnly reports whether data (already through the iteration guard of decodePFX) is a PFX with
// an empty password that holds certificates and no key, whatever wrote it: a Java trust store, openssl -nokeys,
// .NET, one safe or two, encrypted or not.
func pfxHoldsCertificatesOnly(data []byte) bool {
	_, _, _, err := pkcs12.DecodeChain(data, "")
	return err != nil && err.Error() == errPFXKeyMissing
}

// splitPEM sorts the PEM blocks of value into certificates (re-encoded: they are public) and key
// blocks (copied as they stand into a scratch buffer, so a block ValidateUpload refuses, an
// encrypted key for one, keeps its own error). Blocks of other types are dropped and their decoded
// bytes cleared. More certificates or keys than ValidateUpload accepts end the split early.
func splitPEM(value []byte, scratch *kvScratch) (certPEM, keyPEM []byte, err error) {
	keys := scratch.take(len(value))[:0] // never grows: the key blocks are parts of value
	nCerts, nKeys := 0, 0
	rest := bytes.TrimPrefix(value, []byte("\xef\xbb\xbf")) // a BOM before the first block; no copy
	for {
		var b *pem.Block
		start := len(value) - len(rest) // offsets stay relative to value
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			if nCerts++; nCerts > maxCertificates {
				return nil, nil, invalid("too many certificates")
			}
			certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: b.Type, Bytes: b.Bytes})...)
			continue
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			if nKeys++; nKeys > 1 {
				clear(b.Bytes)
				return nil, nil, invalid("expected exactly one private key")
			}
			keys = append(keys, value[start:len(value)-len(rest)]...)
		}
		clear(b.Bytes)
	}
	return certPEM, keys, nil
}

// WithoutRoot drops a self-signed last certificate from p's chain and re-encodes PEMChain
// (spec §11.5 item 4; include_root is not built, R40 row 18). The leaf is never dropped, and p is
// not modified.
func WithoutRoot(p Parsed) Parsed {
	n := len(p.Chain)
	if p.Leaf == nil || n == 0 || !selfSigned(p.Chain[n-1]) {
		return p
	}
	p.Chain = p.Chain[: n-1 : n-1]
	var b strings.Builder
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Leaf.Raw}))
	for _, c := range p.Chain {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	p.PEMChain = b.String()
	return p
}
