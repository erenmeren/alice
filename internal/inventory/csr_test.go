package inventory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/testutil/pki"
)

func TestSignedWarnings(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	ca := pki.NewCA("W", pki.ECDSA256, now)
	soon := ca.Issue(pki.Opts{CommonName: "a.example.test", NotBefore: now.Add(time.Hour), NotAfter: now.AddDate(0, 1, 0)}, now)
	p, err := certs.ParseChainPEM(soon.FullchainPEM)
	require.NoError(t, err)
	assert.Equal(t, []string{"not_yet_valid"}, signedWarnings(soon.FullchainPEM, p, true, nil, now))

	// An expired extra certificate in the file (an old copy, a stale cross-sign) is flagged.
	old := ca.Issue(pki.Opts{CommonName: "old.example.test", NotBefore: now.AddDate(0, -3, 0), NotAfter: now.Add(-time.Hour)}, now)
	cur := ca.Issue(pki.Opts{CommonName: "a.example.test"}, now)
	file := append(append([]byte{}, cur.FullchainPEM...), old.CertPEM...)
	p, err = certs.ParseChainPEM(cur.FullchainPEM)
	require.NoError(t, err)
	assert.Equal(t, []string{"chain_incomplete", "chain_certificate_expired"}, signedWarnings(file, p, false, nil, now))
	assert.Equal(t, []string{}, signedWarnings(cur.FullchainPEM, p, true, nil, now))
}
