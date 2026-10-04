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

// The guard refuses a structure it cannot read instead of skipping it (Task 2 ledger items): a file
// in BER (indefinite lengths, which the DER-only decoder cannot read) or with a damaged inner
// structure is unreadable, not "wrong password".
func TestUnreadablePFXIsInvalidNotAWrongPassword(t *testing.T) {
	ca := pki.NewCA("Alice PFX", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	good := pki.PFX(l, ca, "pw")
	ber := append([]byte{0x30, 0x80}, append(append([]byte{}, good[2:]...), 0, 0)...) // indefinite length
	for name, data := range map[string][]byte{
		"ber":     ber,
		"garbage": []byte("not a pfx file at all"),
		"cut":     good[:len(good)/2],
	} {
		_, err := ValidateUpload(Upload{PFX: data, PFXPassword: "pw"}, now, nil)
		assert.ErrorIs(t, err, ErrInvalid, name)
	}
	_, err := ValidateUpload(Upload{PFX: good, PFXPassword: "wrong"}, now, nil)
	assert.ErrorIs(t, err, ErrPFXPassword, "a readable file with a wrong password")
	v, err := ValidateUpload(Upload{PFX: good, PFXPassword: "pw"}, now, nil)
	require.NoError(t, err)
	v.PrivateKeyDER.Zero()
}

// guardFile builds a PFX skeleton around authSafe (the bytes inside the outer content) and mac.
func guardFile(t *testing.T, authSafe []byte, mac tMac) []byte {
	t.Helper()
	return mar(t, tPfx{Version: 3, MacData: mac, AuthSafe: tContentInfo{ContentType: oidTData,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: authSafe}}})
}

func explicit0(b []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: b}
}

// Each structure the guard reads to find an iteration count is refused as unreadable when it does
// not parse, at every depth, rather than skipped (which would let the library read, with its own
// count, a structure the guard could not check). A bag that is not a shrouded key is skipped, and
// the bags after it are still checked.
func TestPFXGuardRefusesEveryUnreadableStructure(t *testing.T) {
	sha1MAC := tMac{Mac: tDigest{Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}, Digest: []byte{1}}, MacSalt: []byte{1}, Iterations: 1}
	notSequence := mar(t, 7) // an INTEGER where a structure is expected
	pbes2 := func(kdfParams []byte) pkix.AlgorithmIdentifier {
		kdf := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}, Parameters: asn1.RawValue{FullBytes: kdfParams}}
		return pkix.AlgorithmIdentifier{Algorithm: oidTPBES2, Parameters: asn1.RawValue{FullBytes: mar(t, tPBES2{Kdf: kdf, Scheme: kdf})}}
	}
	wrap := func(items ...tContentInfo) []byte { return mar(t, mar(t, items)) }
	dataWith := func(inner []byte) tContentInfo { return tContentInfo{ContentType: oidTData, Content: explicit0(inner)} }
	bagsOf := func(bags ...tSafeBag) tContentInfo { return dataWith(mar(t, mar(t, bags))) }
	shroudedWith := func(value []byte) tSafeBag { return tSafeBag{ID: oidTShroud, Value: explicit0(value)} }
	shrouded := func(a pkix.AlgorithmIdentifier) tSafeBag {
		return shroudedWith(mar(t, tShrouded{Algorithm: a, Data: []byte{1}}))
	}
	legacy := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}, Parameters: asn1.RawValue{FullBytes: notSequence}}
	certBag := tSafeBag{ID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}, Value: explicit0(mar(t, []byte("a certificate")))}
	pbmac1 := tMac{Mac: tDigest{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidTPBMAC1, Parameters: asn1.RawValue{FullBytes: notSequence}}, Digest: []byte{1}}, MacSalt: []byte{1}, Iterations: 1}

	for name, tc := range map[string]struct {
		pfx  []byte
		want error // nil: the guard lets it through
	}{
		"auth safe is not an element":             {guardFile(t, []byte{0x04, 0x7f}, sha1MAC), unreadable()},
		"auth safe octets hold no content list":   {guardFile(t, mar(t, []byte("junk")), sha1MAC), unreadable()},
		"encrypted content is not a structure":    {guardFile(t, wrap(tContentInfo{ContentType: oidTEncData, Content: explicit0(notSequence)}), sha1MAC), unreadable()},
		"data content is not an octet string":     {guardFile(t, wrap(dataWith(notSequence)), sha1MAC), unreadable()},
		"data content holds no bag list":          {guardFile(t, wrap(dataWith(mar(t, []byte("junk")))), sha1MAC), unreadable()},
		"shrouded key bag is not a structure":     {guardFile(t, wrap(bagsOf(shroudedWith(notSequence))), sha1MAC), unreadable()},
		"PBES2 parameters are not two algorithms": {guardFile(t, wrap(bagsOf(shrouded(pkix.AlgorithmIdentifier{Algorithm: oidTPBES2, Parameters: asn1.RawValue{FullBytes: notSequence}}))), sha1MAC), unreadable()},
		"PBKDF2 parameters do not parse":          {guardFile(t, wrap(bagsOf(shrouded(pbes2(notSequence)))), sha1MAC), unreadable()},
		"legacy PBE parameters do not parse":      {guardFile(t, wrap(bagsOf(shrouded(legacy))), sha1MAC), unreadable()},
		"PBMAC1 parameters do not parse":          {guardFile(t, wrap(), pbmac1), unreadable()},
		"a certificate bag is skipped, the key after it is checked": {
			guardFile(t, wrap(bagsOf(certBag, shrouded(pbes2(mar(t, tPBKDF2{Salt: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte{1}}, Iterations: 1 << 40}))))), sha1MAC), tooMany()},
		"a certificate bag alone passes": {guardFile(t, wrap(bagsOf(certBag)), sha1MAC), nil},
	} {
		err := checkPFXIterations(tc.pfx)
		if tc.want == nil {
			assert.NoError(t, err, name)
			continue
		}
		require.Error(t, err, name)
		assert.Equal(t, tc.want.Error(), err.Error(), name)
		assert.ErrorIs(t, err, ErrInvalid, name)
	}
}
