package certs

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// maxKDFIterations bounds every key-derivation iteration count a PFX may
// carry. go-pkcs12 honours whatever the file says, so a few hundred bytes with
// an iteration count of 2^40 would keep a CPU busy for hours. Real files use
// 1 to 600 000.
const maxKDFIterations = 1_000_000

// The structures mirror the ones go-pkcs12 decodes, so that whatever iteration
// count the library would use is found here first. A structure that does not
// parse here is refused (unreadable) rather than skipped: the library cannot
// parse it either, and skipping would let a structure the guard misreads reach
// the library unchecked. (This also reports a BER-encoded file, which the
// DER-only library cannot read, as unreadable instead of as a wrong password.)
type (
	guardPfx struct {
		Version  int
		AuthSafe guardContentInfo
		MacData  guardMac `asn1:"optional"`
	}
	guardContentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	guardMac struct {
		Mac        guardDigest
		MacSalt    []byte
		Iterations int `asn1:"optional,default:1"`
	}
	guardDigest struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	guardEncryptedData struct {
		Version int
		Info    guardEncryptedInfo
	}
	guardEncryptedInfo struct {
		ContentType asn1.ObjectIdentifier
		Algorithm   pkix.AlgorithmIdentifier
		Content     []byte `asn1:"tag:0,optional"`
	}
	guardSafeBag struct {
		ID         asn1.ObjectIdentifier
		Value      asn1.RawValue `asn1:"tag:0,explicit"`
		Attributes asn1.RawValue `asn1:"set,optional"`
	}
	guardShrouded struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	guardTwoAlgorithms struct{ First, Second pkix.AlgorithmIdentifier } // PBES2 (KDF, scheme) and PBMAC1 (KDF, MAC)
	guardPBKDF2        struct {
		Salt       asn1.RawValue
		Iterations int
		KeyLength  int                      `asn1:"optional"`
		Prf        pkix.AlgorithmIdentifier `asn1:"optional"`
	}
	guardPBE struct {
		Salt       []byte
		Iterations int
	}
)

var (
	oidGuardPBES2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidGuardPBMAC1  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	oidGuardEncData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidGuardData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidGuardShroud  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidGuardPBE     = []asn1.ObjectIdentifier{ // the three PKCS#12 PBEs go-pkcs12 decodes
		{1, 2, 840, 113549, 1, 12, 1, 3},
		{1, 2, 840, 113549, 1, 12, 1, 5},
		{1, 2, 840, 113549, 1, 12, 1, 6},
	}
)

func tooMany() error { return invalid("a key derivation iteration count is unreasonably high") }

func unreadable() error { return invalid("the PFX file cannot be read") }

// checkPFXIterations refuses a PFX whose MAC, encrypted content or shrouded key
// bag asks for more than maxKDFIterations. It derives nothing.
//
// Not reachable by a pre-parse: a shrouded key bag that sits inside an
// encrypted content is only visible after decryption, which needs the
// password-derived key. The encrypted content's own count is checked, and
// the files written by OpenSSL, Windows and go-pkcs12 keep the key bag in a
// plain data content.
func checkPFXIterations(pfx []byte) error {
	var p guardPfx
	if _, err := asn1.Unmarshal(pfx, &p); err != nil {
		return unreadable()
	}
	if p.MacData.Iterations > maxKDFIterations {
		return tooMany()
	}
	if p.MacData.Mac.Algorithm.Algorithm.Equal(oidGuardPBMAC1) {
		if err := checkAlgorithmIterations(p.MacData.Mac.Algorithm); err != nil {
			return err
		}
	}
	var octets asn1.RawValue
	if _, err := asn1.Unmarshal(p.AuthSafe.Content.Bytes, &octets); err != nil {
		return unreadable()
	}
	var items []guardContentInfo
	if _, err := asn1.Unmarshal(octets.Bytes, &items); err != nil {
		return unreadable()
	}
	for _, ci := range items {
		switch {
		case ci.ContentType.Equal(oidGuardEncData):
			var ed guardEncryptedData
			if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
				return unreadable()
			}
			if err := checkAlgorithmIterations(ed.Info.Algorithm); err != nil {
				return err
			}
		case ci.ContentType.Equal(oidGuardData):
			var inner []byte
			if _, err := asn1.Unmarshal(ci.Content.Bytes, &inner); err != nil {
				return unreadable()
			}
			var bags []guardSafeBag
			if _, err := asn1.Unmarshal(inner, &bags); err != nil {
				return unreadable()
			}
			for _, b := range bags {
				if !b.ID.Equal(oidGuardShroud) {
					continue
				}
				var sh guardShrouded
				if _, err := asn1.Unmarshal(b.Value.Bytes, &sh); err != nil {
					return unreadable()
				}
				if err := checkAlgorithmIterations(sh.Algorithm); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkAlgorithmIterations reads the iteration count of a PBES2, PBMAC1 or
// PKCS#12 PBE algorithm identifier. Other algorithms are not decoded by the library.
func checkAlgorithmIterations(a pkix.AlgorithmIdentifier) error {
	switch {
	case a.Algorithm.Equal(oidGuardPBES2), a.Algorithm.Equal(oidGuardPBMAC1):
		var two guardTwoAlgorithms
		if _, err := asn1.Unmarshal(a.Parameters.FullBytes, &two); err != nil {
			return unreadable()
		}
		var k guardPBKDF2
		switch _, err := asn1.Unmarshal(two.First.Parameters.FullBytes, &k); {
		case err != nil:
			return unreadable()
		case k.Iterations > maxKDFIterations:
			return tooMany()
		}
	default:
		for _, oid := range oidGuardPBE {
			if !a.Algorithm.Equal(oid) {
				continue
			}
			var pbe guardPBE
			switch _, err := asn1.Unmarshal(a.Parameters.FullBytes, &pbe); {
			case err != nil:
				return unreadable()
			case pbe.Iterations > maxKDFIterations:
				return tooMany()
			}
		}
	}
	return nil
}
