package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"alice/internal/discovery/tlsprobe"
)

var certKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// testCert returns a DER certificate named cn, valid from nb to na, self-signed by one shared key.
func testCert(t testing.TB, cn string, nb, na time.Time) []byte {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: nb, NotAfter: na,
		DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &certKey.PublicKey, certKey)
	require.NoError(t, err)
	return der
}

// presented returns a result as the scanner builds it from a chain of DER certificates.
func presented(t testing.TB, e Endpoint, der ...[]byte) Result {
	t.Helper()
	c, err := tlsprobe.ParsePresentedChain(der)
	require.NoError(t, err)
	return Result{Endpoint: e, Presented: der, Chain: c, TLSVersion: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256"}
}

func ep(a string, port uint16, sni string) Endpoint {
	return Endpoint{Address: netip.MustParseAddr(a), Port: port, SNI: sni}
}

// TestStateForMatchesTheMigrationChecks: every code maps to a state and error code pair the CHECKs of
// discovery_endpoints accept (present: no code; excluded: policy; malformed: malformed; no_tls: no_tls; unreachable:
// refused, timeout, reset or chain_too_large).
func TestStateForMatchesTheMigrationChecks(t *testing.T) {
	ok := map[string][]string{
		"present": {""}, "excluded": {"policy"}, "malformed": {"malformed"}, "no_tls": {"no_tls"},
		"unreachable": {"refused", "timeout", "reset", "chain_too_large"},
	}
	want := map[tlsprobe.Code][2]string{
		"": {"present", ""}, "refused": {"unreachable", "refused"}, "timeout": {"unreachable", "timeout"},
		"reset": {"unreachable", "reset"}, "chain_too_large": {"unreachable", "chain_too_large"}, "no_tls": {"no_tls", "no_tls"},
		"malformed": {"malformed", "malformed"}, "policy": {"excluded", "policy"}, "something new": {"unreachable", "refused"},
	}
	require.Len(t, tlsprobe.Codes, 7, "a new probe code needs a row here and in the migration")
	for _, c := range append(slices.Clone(tlsprobe.Codes), "", "something new") {
		state, code := StateFor(c)
		require.Equal(t, want[c], [2]string{state, code}, c)
		require.Contains(t, ok[state], code, c)
	}
	for _, c := range []tlsprobe.Code{"", "chain_too_large", "malformed"} {
		require.True(t, answered(c), c)
	}
	for _, c := range []tlsprobe.Code{"refused", "timeout", "reset", "no_tls", "policy"} {
		require.False(t, answered(c), c)
	}
}

// TestEndpointRowIsHonest: the chain lists every certificate presented after the leaf, a dropped one included
// (limitation L2b), the digest covers the whole chain, and values the CHECKs refuse are stored empty.
func TestEndpointRowIsHonest(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	leaf := testCert(t, "leaf.example", now.Add(-time.Hour), now.Add(time.Hour))
	inter := testCert(t, "inter.example", now.Add(-time.Hour), now.Add(time.Hour))
	bad := testCert(t, "reversed.example", now.Add(time.Hour), now.Add(-time.Hour)) // dropped by the parser
	r := presented(t, ep("10.0.0.1", 443, ""), leaf, bad, inter)
	require.Equal(t, 1, r.Chain.DroppedCerts)
	require.Len(t, r.Chain.Certificates, 2)
	row := endpointRowOf(r)
	require.Equal(t, "present", row.state)
	require.Equal(t, fingerprint(leaf), row.fp)
	require.Equal(t, []string{fingerprint(bad), fingerprint(inter)}, row.chain, "chain length 3, as presented")
	require.Equal(t, chainDigest([][]byte{leaf, bad, inter}), row.chainSHA)
	require.Equal(t, "TLS 1.3", row.tls)
	require.Equal(t, "TLS_AES_128_GCM_SHA256", row.cipher)

	r.TLSVersion, r.CipherSuite = "0x0300", "TLS-AES-?"
	row = endpointRowOf(r)
	require.Empty(t, row.tls)
	require.Empty(t, row.cipher)
	require.False(t, cipherOK(string(make([]byte, 65))))
	require.True(t, cipherOK("0x1301"))

	row = endpointRowOf(Result{Endpoint: ep("10.0.0.1", 443, ""), Code: tlsprobe.CodeTimeout})
	require.Equal(t, endpointRow{e: ep("10.0.0.1", 443, ""), chain: []string{}, state: "unreachable", code: "timeout"}, row)
}

func TestChainDigest(t *testing.T) {
	a, b := []byte("ab"), []byte("c")
	require.NotEqual(t, chainDigest([][]byte{a, b}), chainDigest([][]byte{[]byte("a"), []byte("bc")}), "lengths are part of the digest")
	require.NotEqual(t, chainDigest([][]byte{a, b}), chainDigest([][]byte{b, a}))
	require.Len(t, chainDigest(nil), 64)
}

// TestBatchesAreDeduplicated: one result per endpoint (the last), one certificate per fingerprint, leaves first, a
// certificate seen as a leaf anywhere is a leaf; the caps admit stored certificates always and new ones within budget.
func TestBatchesAreDeduplicated(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	l1 := testCert(t, "one.example", now.Add(-time.Hour), now.Add(time.Hour))
	l2 := testCert(t, "two.example", now.Add(-time.Hour), now.Add(time.Hour))
	in := testCert(t, "inter.example", now.Add(-time.Hour), now.Add(time.Hour))
	rs := dedupeResults([]Result{
		{Endpoint: ep("10.0.0.1", 443, ""), Code: tlsprobe.CodeTimeout},
		presented(t, ep("10.0.0.2", 443, ""), l2, l1),
		presented(t, ep("10.0.0.1", 443, ""), l1, in),
		{Endpoint: ep("10.0.0.1", 443, "x.example"), Code: tlsprobe.CodeReset},
		presented(t, ep("10.0.0.3", 443, ""), l2, in),
	})
	require.Len(t, rs, 4)
	require.Empty(t, rs[0].Code, "the later result of 10.0.0.1:443 replaced the earlier one, in its place")
	certs := presentedCertificates(rs)
	var fps []string
	var leaves []bool
	for _, c := range certs {
		fps, leaves = append(fps, c.fp), append(leaves, c.leaf)
	}
	require.Equal(t, []string{fingerprint(l1), fingerprint(l2), fingerprint(in)}, fps)
	require.Equal(t, []bool{true, true, false}, leaves, "l1 is an intermediate of 10.0.0.2 and a leaf of 10.0.0.1: a leaf")

	admitted, refused := admit(certs, map[string]bool{fingerprint(in): true}, 1)
	require.Len(t, admitted, 2)
	require.Equal(t, fingerprint(l1), admitted[0].fp)
	require.Equal(t, fingerprint(in), admitted[1].fp, "a stored certificate needs no budget")
	require.Equal(t, map[string]bool{fingerprint(l2): true}, refused)
}

func TestChunks(t *testing.T) {
	var sizes []int
	require.NoError(t, chunks(make([]int, 2*ingestChunk+1), func(p []int) error { sizes = append(sizes, len(p)); return nil }))
	require.Equal(t, []int{ingestChunk, ingestChunk, 1}, sizes)
	require.NoError(t, chunks([]int(nil), func([]int) error { t.Fatal("no call"); return nil }))
}
