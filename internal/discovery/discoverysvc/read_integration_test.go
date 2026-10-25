//go:build integration

package discoverysvc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery"
)

// FX-03 (R66 ruling 7): a found certificate's detail carries its last revocation check, read by fingerprint (nil
// before the first check, a failure with its code); the list never carries it.
func TestCertificateInCarriesTheRevocationCheck(t *testing.T) {
	w := newWorld(t)
	fp := hexFP('d')
	w.insertCert(fp, "d.example", []string{"d.example"}, t0.AddDate(0, 0, 60), false)
	listHasNoCheck := func() {
		t.Helper()
		list, _, err := w.svc.ListCertificates(w.ctx, discovery.CertificateFilter{})
		require.NoError(t, err)
		require.NotEmpty(t, list)
		for _, r := range list {
			assert.Nil(t, r.Revocation, "the list carries no revocation check")
		}
	}

	// (a) Never checked.
	c, _, _, err := w.svc.Certificate(w.ctx, fp)
	require.NoError(t, err)
	assert.Nil(t, c.Revocation)
	listHasNoCheck()

	// (b) A good answer by OCSP, read in UTC.
	checked := time.Date(2026, 10, 14, 11, 0, 0, 0, time.FixedZone("TRT", 3*3600))
	w.exec(`INSERT INTO revocation_checks (fingerprint_sha256, status, method, checked_at, next_check_at)
VALUES ($1, 'good', 'ocsp', $2, $3)`, fp, checked, checked.Add(6*time.Hour))
	c, _, _, err = w.svc.Certificate(w.ctx, fp)
	require.NoError(t, err)
	require.NotNil(t, c.Revocation)
	assert.Equal(t, "good", c.Revocation.Status)
	assert.Equal(t, "ocsp", c.Revocation.Method)
	assert.Equal(t, time.UTC, c.Revocation.CheckedAt.Location())
	assert.True(t, checked.Equal(c.Revocation.CheckedAt))
	assert.Equal(t, time.UTC, c.Revocation.NextCheckAt.Location())
	assert.Nil(t, c.Revocation.RevokedAt)
	listHasNoCheck()

	// (c) A failure carries its code.
	w.exec(`UPDATE revocation_checks SET status = 'not_checkable', method = '', error_code = 'certificate.revocation_untrusted_issuer'
WHERE fingerprint_sha256 = $1`, fp)
	c, _, _, err = w.svc.Certificate(w.ctx, fp)
	require.NoError(t, err)
	require.NotNil(t, c.Revocation)
	assert.Equal(t, "not_checkable", c.Revocation.Status)
	assert.Equal(t, "certificate.revocation_untrusted_issuer", c.Revocation.ErrorCode)
	listHasNoCheck()
}
