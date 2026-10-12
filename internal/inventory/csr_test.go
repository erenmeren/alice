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
	assert.Equal(t, []string{"not_yet_valid"}, signedWarnings(p, true, nil, now))

	// An expired certificate on the stored path is flagged.
	oldCA := pki.NewCA("Old", pki.ECDSA256, now.AddDate(-6, 0, 0)) // its intermediate ended a year ago
	cur := oldCA.Issue(pki.Opts{CommonName: "a.example.test", NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 1, 0)}, now)
	p, err = certs.ParseChainPEM(cur.FullchainPEM)
	require.NoError(t, err)
	assert.Equal(t, []string{"chain_incomplete", "chain_certificate_expired"}, signedWarnings(p, false, nil, now))

	// An expired extra certificate off the path (an old copy, a stale cross-sign) is dropped, not flagged (L-13).
	cur = ca.Issue(pki.Opts{CommonName: "a.example.test"}, now)
	p, err = certs.ParseChainPEM(cur.FullchainPEM)
	require.NoError(t, err)
	assert.Equal(t, []string{}, signedWarnings(p, true, nil, now))
}
