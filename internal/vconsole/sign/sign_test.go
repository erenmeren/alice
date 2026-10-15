package sign_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/vconsole/sign"
)

var fastKDF = issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

const words = "amber canyon violet orbit lantern quiet"

func newSigner(t *testing.T, keyID string) *sign.FileSigner {
	t.Helper()
	priv, _, err := issuer.GenerateKey(keyID, []byte(words), fastKDF)
	require.NoError(t, err)
	k, err := issuer.OpenKey(priv, []byte(words))
	require.NoError(t, err)
	return sign.NewFileSigner(k)
}

func payload() license.Payload {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	return license.Payload{
		LicenseID: "LIC-2026-000001", Customer: "Acme Ltd", InstallationID: license.NewInstallationID(),
		IssuedAt: now, ValidFrom: now, ValidUntil: now.AddDate(1, 0, 0), MaxTargets: 5,
		Features: []string{}, Format: license.FormatVersion,
	}
}

var _ sign.Signer = (*sign.FileSigner)(nil)

func TestFileSignerIssuesAFileThatVerifies(t *testing.T) {
	s := newSigner(t, "vk-2026-01")
	assert.Equal(t, "vk-2026-01", s.KeyID())
	raw, err := s.Issue(context.Background(), payload())
	require.NoError(t, err)
	f, err := sign.Verify(raw, s)
	require.NoError(t, err)
	assert.Equal(t, "vk-2026-01", f.KeyID)
	assert.Equal(t, "Acme Ltd", f.Payload.Customer)
}

func TestVerifyRefusesAnotherKeyAndATamperedFile(t *testing.T) {
	a, b := newSigner(t, "vk-2026-01"), newSigner(t, "vk-2026-02")
	raw, err := a.Issue(context.Background(), payload())
	require.NoError(t, err)
	_, err = sign.Verify(raw, b)
	assert.Error(t, err, "signed by another key")

	tampered := []byte(string(raw))
	for i := range tampered {
		if tampered[i] == '5' { // MaxTargets
			tampered[i] = '9'
			break
		}
	}
	_, err = sign.Verify(tampered, a)
	assert.Error(t, err)
}

func TestIssueHonoursACancelledContext(t *testing.T) {
	s := newSigner(t, "vk-2026-01")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Issue(ctx, payload())
	assert.ErrorIs(t, err, context.Canceled)
}
