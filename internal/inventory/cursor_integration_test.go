//go:build integration

package inventory_test

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// withValidity returns leaf's certificate re-signed by signer with the validity replaced by the
// given raw times (tag 23 UTCTime or 24 GeneralizedTime), as a PEM block: x509.CreateCertificate
// always writes UTC, so a GeneralizedTime with a zone offset is built by hand.
func withValidity(t *testing.T, leaf pki.Leaf, signer crypto.Signer, notBefore, notAfter asn1.RawValue) []byte {
	t.Helper()
	var outer struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	_, err := asn1.Unmarshal(leaf.Cert.Raw, &outer)
	require.NoError(t, err)
	var fields []asn1.RawValue
	_, err = asn1.Unmarshal(outer.TBS.FullBytes, &fields)
	require.NoError(t, err)
	require.Len(t, fields, 8, "version, serial, signature, issuer, validity, subject, key, extensions")
	validity, err := asn1.Marshal([]asn1.RawValue{notBefore, notAfter})
	require.NoError(t, err)
	fields[4] = asn1.RawValue{FullBytes: validity}
	tbs, err := asn1.Marshal(fields)
	require.NoError(t, err)
	digest := sha256.Sum256(tbs)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	der, err := asn1.Marshal(struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, outer.SigAlg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	require.NoError(t, err)
	_, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func generalized(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagGeneralizedTime, Bytes: []byte(s)}
}

func utcTime(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTCTime, Bytes: []byte(s)}
}

// AUD-13 I1, D19 with stored data: certificates whose NotAfter lies at the ends of what X.509 can
// say (a GeneralizedTime with a ±23:59 zone offset: in UTC a day outside years 0000-9999) or before
// 1970 are stored by discovery, and the certificate list pages past each one: every cursor the list
// hands out is one its decoder accepts.
func TestCertificatePagingAtTheEndsOfX509Time(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	now := h.clock.Now()
	ca := pki.NewCA("Edge", pki.ECDSA256, now)
	certs := []struct {
		cn                  string
		notBefore, notAfter asn1.RawValue
		wantAfter           time.Time
	}{
		{"edge-low.example.test", generalized("00000101000000+2359"), generalized("00000101000000+2359"), time.Date(-1, 12, 31, 0, 1, 0, 0, time.UTC)},
		{"edge-1965.example.test", utcTime("600101000000Z"), utcTime("650101000000Z"), time.Date(1965, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"edge-now.example.test", generalized("20260101000000Z"), generalized("20270101000000Z"), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"edge-high.example.test", generalized("20260101000000Z"), generalized("99991231235959-2359"), time.Date(10000, 1, 1, 23, 58, 59, 0, time.UTC)},
	}
	var found []providers.DiscoveredCertificate
	for i, c := range certs {
		leaf := ca.Issue(pki.Opts{CommonName: c.cn, SANs: []string{c.cn}}, now)
		chain := append(withValidity(t, leaf, ca.IntermediateKey, c.notBefore, c.notAfter), ca.IntermediatePEM...)
		loc := cl(fmt.Sprintf("/etc/nginx/ssl/%d.crt", i), fmt.Sprintf("/etc/nginx/ssl/%d.key", i), c.cn)
		found = append(found, providers.DiscoveredCertificate{Location: loc, PEMChain: chain, FileSHA256: sha(chain)})
	}
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: found})
	require.NoError(t, err)

	var got []string
	cursor := ""
	for range 10 {
		page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{Query: "edge-", Limit: 1, Cursor: cursor})
		require.NoError(t, err, "the cursor after %v", got)
		for _, c := range page.Items {
			got = append(got, c.SubjectCN)
			want := certs[len(got)-1].wantAfter
			assert.True(t, want.Equal(c.NotAfter), "%s: NotAfter %s, want %s", c.SubjectCN, c.NotAfter.UTC(), want)
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	assert.Equal(t, []string{"edge-low.example.test", "edge-1965.example.test", "edge-now.example.test", "edge-high.example.test"}, got,
		"every certificate once, in NotAfter order")
}
