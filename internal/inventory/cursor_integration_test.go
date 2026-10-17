//go:build integration

package inventory_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// AUD-13 (fix round 2): a server's file whose certificate says, through a GeneralizedTime zone
// offset, a time outside 0001-9999 in UTC is an unreadable certificate: the location shows
// not_a_certificate and nothing with such a time is stored, so the certificates list still encodes.
// D19 with stored data: a certificate that expired before 1970 is stored and the list pages past it.
func TestDiscoveryRefusesCertificatesOutsideYears1To9999(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := nginxTarget(t, h, admin, "web-01")
	now := h.clock.Now()
	ca := pki.NewCA("Edge", pki.ECDSA256, now)
	g, u := pki.GeneralizedTime, pki.UTCTime
	files := []struct {
		cn   string
		leaf pki.Leaf
	}{
		{"edge-low.example.test", ca.IssueRawValidity(pki.Opts{CommonName: "edge-low.example.test"}, g("00000101000000+2359"), g("00000101000000+2359"), now)},
		{"edge-high.example.test", ca.IssueRawValidity(pki.Opts{CommonName: "edge-high.example.test"}, g("20260101000000Z"), g("99991231235959-2359"), now)},
		{"edge-1965.example.test", ca.IssueRawValidity(pki.Opts{CommonName: "edge-1965.example.test"}, u("600101000000Z"), u("650101000000Z"), now)},
		{"edge-9999.example.test", ca.IssueRawValidity(pki.Opts{CommonName: "edge-9999.example.test"}, g("20260101000000Z"), g("99991231235959Z"), now)},
	}
	var found []providers.DiscoveredCertificate
	for i, f := range files {
		found = append(found, dc(cl(fmt.Sprintf("/etc/nginx/ssl/%d.crt", i), fmt.Sprintf("/etc/nginx/ssl/%d.key", i), f.cn), f.leaf))
	}
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{WebServer: nginxOK, Certificates: found})
	require.NoError(t, err)

	locs := byPath(t, h, web.ID, false)
	for _, i := range []int{0, 1} {
		l := locs[fmt.Sprintf("/etc/nginx/ssl/%d.crt", i)]
		assert.Nil(t, l.Certificate, files[i].cn)
		assert.Equal(t, []string{providers.UnsupportedFile, providers.CertProblemNotACertificate}, []string{l.UnsupportedReason, l.Problem}, files[i].cn)
	}
	assert.Zero(t, h.count(`SELECT count(*) FROM certificates
WHERE not_before < '0001-01-01T00:00:00Z' OR not_after > '9999-12-31T23:59:59Z' OR not_before > '9999-12-31T23:59:59Z' OR not_after < '0001-01-01T00:00:00Z'`))

	var got []string
	cursor := ""
	for range 10 {
		page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{Query: "edge-", Limit: 1, Cursor: cursor})
		require.NoError(t, err, "the cursor after %v", got)
		for _, c := range page.Items {
			got = append(got, c.SubjectCN)
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	assert.Equal(t, []string{"edge-1965.example.test", "edge-9999.example.test"}, got, "every stored certificate once, in NotAfter order")
}

// AUD-13 I1: the cursor code itself holds at the ends of its range. Rows written straight into the
// table (no ingestion path stores such times any more) with NotAfter a day outside years 0000-9999
// in UTC — what a GeneralizedTime zone offset can say — still page: every cursor the list hands out
// is one its decoder accepts.
func TestCertificateCursorAtTheEndsOfItsRange(t *testing.T) {
	h := newHarness(t)
	now := h.clock.Now()
	ends := []struct {
		cn       string
		notAfter time.Time
	}{
		{"end-low.example.test", time.Date(-1, 12, 31, 0, 1, 0, 0, time.UTC)},
		{"end-1965.example.test", time.Date(1965, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"end-high.example.test", time.Date(10000, 1, 1, 23, 58, 59, 0, time.UTC)},
	}
	for i, e := range ends {
		_, err := h.db.Owner.Exec(h.ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
VALUES ($1, $2, $3, $4, $4, 'ecdsa', $2, '', 'uploaded', $5, $5, $5)`, uuid.Must(uuid.NewV7()), sha([]byte(fmt.Sprint("end", i))), e.cn, e.notAfter, now)
		require.NoError(t, err)
	}
	var got []string
	cursor := ""
	for range 10 {
		page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{Query: "end-", Limit: 1, Cursor: cursor})
		require.NoError(t, err, "the cursor after %v", got)
		for _, c := range page.Items {
			got = append(got, c.SubjectCN)
			assert.True(t, ends[len(got)-1].notAfter.Equal(c.NotAfter), c.SubjectCN)
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	assert.Equal(t, []string{"end-low.example.test", "end-1965.example.test", "end-high.example.test"}, got)
}
