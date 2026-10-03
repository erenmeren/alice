package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/testutil/pki"
)

// Minimal copies of the PKCS#12 structures, used to re-encode a valid file with
// hostile iteration counts.
type (
	tPfx struct {
		Version  int
		AuthSafe tContentInfo
		MacData  tMac `asn1:"optional"`
	}
	tContentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	tMac struct {
		Mac        tDigest
		MacSalt    []byte
		Iterations int `asn1:"optional,default:1"`
	}
	tDigest struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	tEncryptedData struct {
		Version int
		Info    tEncryptedInfo
	}
	tEncryptedInfo struct {
		ContentType asn1.ObjectIdentifier
		Algorithm   pkix.AlgorithmIdentifier
		Content     []byte `asn1:"tag:0,optional"`
	}
	tSafeBag struct {
		ID         asn1.ObjectIdentifier
		Value      asn1.RawValue `asn1:"tag:0,explicit"`
		Attributes asn1.RawValue `asn1:"set,optional"`
	}
	tShrouded struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	tPBES2  struct{ Kdf, Scheme pkix.AlgorithmIdentifier }
	tPBKDF2 struct {
		Salt       asn1.RawValue
		Iterations int
		KeyLength  int                      `asn1:"optional"`
		Prf        pkix.AlgorithmIdentifier `asn1:"optional"`
	}
	tPBE struct {
		Salt       []byte
		Iterations int
	}
)

var (
	oidTPBES2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidTPBMAC1  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	oidTEncData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidTData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidTShroud  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
)

func mar(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	require.NoError(t, err)
	return b
}

func encode(t *testing.T, e *pkcs12.Encoder, l pki.Leaf, ca *pki.CA) []byte {
	t.Helper()
	b, err := e.Encode(l.Key, l.Cert, []*x509.Certificate{ca.Intermediate}, "pw")
	require.NoError(t, err)
	return b
}

// setIterations rewrites the iteration count inside PBES2, PBMAC1 or legacy PBE parameters.
func setIterations(t *testing.T, a *pkix.AlgorithmIdentifier, n int) {
	t.Helper()
	switch {
	case a.Algorithm.Equal(oidTPBES2), a.Algorithm.Equal(oidTPBMAC1):
		var p tPBES2 // both have two AlgorithmIdentifiers, the first is the KDF
		_, err := asn1.Unmarshal(a.Parameters.FullBytes, &p)
		require.NoError(t, err)
		var k tPBKDF2
		_, err = asn1.Unmarshal(p.Kdf.Parameters.FullBytes, &k)
		require.NoError(t, err)
		k.Iterations = n
		p.Kdf.Parameters.FullBytes = mar(t, k)
		a.Parameters.FullBytes = mar(t, p)
	default:
		var p tPBE
		_, err := asn1.Unmarshal(a.Parameters.FullBytes, &p)
		require.NoError(t, err)
		p.Iterations = n
		a.Parameters.FullBytes = mar(t, p)
	}
}

// hostilePFX re-encodes pfx with n iterations in the chosen place: "mac", "content" (the
// encrypted certificates) or "key" (the shrouded key bag).
func hostilePFX(t *testing.T, pfx []byte, where string, n int) []byte {
	t.Helper()
	var p tPfx
	_, err := asn1.Unmarshal(pfx, &p)
	require.NoError(t, err)
	if where == "mac" {
		if p.MacData.Mac.Algorithm.Algorithm.Equal(oidTPBMAC1) {
			setIterations(t, &p.MacData.Mac.Algorithm, n)
		} else {
			p.MacData.Iterations = n
		}
		return mar(t, p)
	}
	var octets asn1.RawValue
	_, err = asn1.Unmarshal(p.AuthSafe.Content.Bytes, &octets)
	require.NoError(t, err)
	var items []tContentInfo
	_, err = asn1.Unmarshal(octets.Bytes, &items)
	require.NoError(t, err)
	for i, ci := range items {
		switch {
		case where == "content" && ci.ContentType.Equal(oidTEncData):
			var ed tEncryptedData
			_, err = asn1.Unmarshal(ci.Content.Bytes, &ed)
			require.NoError(t, err)
			setIterations(t, &ed.Info.Algorithm, n)
			items[i].Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mar(t, ed)}
		case where == "key" && ci.ContentType.Equal(oidTData):
			var inner []byte
			_, err = asn1.Unmarshal(ci.Content.Bytes, &inner)
			require.NoError(t, err)
			var bags []tSafeBag
			_, err = asn1.Unmarshal(inner, &bags)
			require.NoError(t, err)
			for j, b := range bags {
				if !b.ID.Equal(oidTShroud) {
					continue
				}
				var sh tShrouded
				_, err = asn1.Unmarshal(b.Value.Bytes, &sh)
				require.NoError(t, err)
				setIterations(t, &sh.Algorithm, n)
				bags[j].Value = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mar(t, sh)}
			}
			inner = mar(t, bags)
			items[i].Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mar(t, inner)}
		}
	}
	p.AuthSafe.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: mar(t, mar(t, items))}
	return mar(t, p)
}

// A few hundred bytes must not keep a CPU busy: the file is refused before any key derivation.
func TestHostilePFXIterationsAreRefusedFast(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	encoders := map[string]*pkcs12.Encoder{"legacy": pkcs12.LegacyDES, "modern2023": pkcs12.Modern2023, "modern2026": pkcs12.Modern2026}
	for name, enc := range encoders {
		base := encode(t, enc, l, ca)
		for _, where := range []string{"mac", "content", "key"} {
			t.Run(name+"/"+where, func(t *testing.T) {
				hostile := hostilePFX(t, base, where, 1<<40)
				done := make(chan error, 1)
				go func() {
					_, err := ValidateUpload(Upload{PFX: hostile, PFXPassword: "pw"}, now, x509.NewCertPool())
					done <- err
				}()
				select {
				case err := <-done:
					assert.ErrorIs(t, err, ErrInvalid)
				case <-time.After(5 * time.Second):
					t.Fatal("a PFX with 2^40 iterations kept ValidateUpload busy")
				}
			})
		}
	}
}

func TestHostileFixtureStillDecodesWithSaneIterations(t *testing.T) {
	// Guards the test builder itself: re-encoding with a sane count yields a file the guard lets through.
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	base := encode(t, pkcs12.Modern2023, l, ca)
	for _, where := range []string{"content", "key"} {
		assert.NoError(t, checkPFXIterations(hostilePFX(t, base, where, 2048)), where)
	}
}

func TestNormalPFXIterationCountsPass(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	for _, n := range []int{2048, 10000, 600000} {
		for name, enc := range map[string]*pkcs12.Encoder{"legacy": pkcs12.LegacyDES, "modern2023": pkcs12.Modern2023, "modern2026": pkcs12.Modern2026} {
			pfx := encode(t, enc.WithIterations(n), l, ca)
			v, err := ValidateUpload(Upload{PFX: pfx, PFXPassword: "pw"}, now, rootsOf(ca))
			require.NoError(t, err, "%s %d", name, n)
			v.PrivateKeyDER.Zero()
		}
	}
}
