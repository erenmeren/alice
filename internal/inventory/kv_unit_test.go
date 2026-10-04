package inventory

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

func TestKVSmallHelpers(t *testing.T) {
	assert.Equal(t, "inventory: the vault is deleted", kvDropped("deleted").Error())
	a, b := time.Unix(1, 0), time.Unix(2, 0)
	assert.Equal(t, &a, firstTime(&a, &b))
	assert.Equal(t, &b, firstTime(nil, &b))
	assert.Nil(t, firstTime(nil, nil))
	assert.Equal(t, -1, compareStrings("a", "b"))
	assert.Equal(t, 1, compareStrings("b", "a"))
	assert.Equal(t, 0, compareStrings("a", "a"))
	assert.True(t, validKVText("öğe", 3))
	assert.False(t, validKVText("öğe", 2))
	assert.False(t, validKVText("a\x00", 5))
	assert.False(t, validKVText("a\xff", 5))
}

// The class table is shared by a failed poll and a failed list; precedence is the order of the constants.
func TestKVClassTable(t *testing.T) {
	order := []string{"internal.unexpected", "azure.throttled", "azure.forbidden", "azure.unreachable", "azure.auth_failed"}
	for i := 1; i < len(order); i++ {
		assert.Greater(t, int(kvClassOf(order[i])), int(kvClassOf(order[i-1])), order[i])
	}
	assert.Equal(t, kvClassOf("azure.firewall"), kvClassOf("azure.forbidden"))
	assert.Equal(t, kvClassOf("azure.vault_not_found"), kvClassOf("azure.unreachable"))
	assert.Equal(t, kvClassOf("azure.clock_skew"), kvClassOf("azure.auth_failed"))
	assert.Equal(t, classOther, kvClassOf("azure.unexpected_response"))
	assert.Equal(t, KVPollFailure{Object: "vault", Reason: reasonInternal}, sanitizeKVFailure("nonsense", nil))
	_ = providers.Warning{}
}

func TestPrepareKVVersionsAreBoundedAndChecked(t *testing.T) {
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	leaf := pki.NewCA("Unit", pki.ECDSA256, now).Issue(pki.Opts{CommonName: "u.example.test"}, now)
	th := azureid.ThumbprintOf(leaf.Cert.Raw)
	cur := fmt.Sprintf("%032x", 1)
	c := providers.KVCertificate{Name: "web-cert", Thumbprint: th, Enabled: true,
		Details: &providers.KVCertificateDetails{Version: cur, Thumbprint: th, CER: leaf.Cert.Raw},
		Versions: []providers.KVCertificateVersion{
			{Version: cur, Thumbprint: th, Enabled: true},
			{Version: "bad", Thumbprint: th},                         // not a version id
			{Version: fmt.Sprintf("%032x", 2), Thumbprint: "nothex"}, // not a thumbprint
			{Version: fmt.Sprintf("%032x", 3), Thumbprint: fmt.Sprintf("%040x", 3)},
			{Version: fmt.Sprintf("%032x", 3), Thumbprint: fmt.Sprintf("%040x", 3)}, // a duplicate
		}}
	for i := 10; i < 10+maxKVVersions+5; i++ { // more than the bound
		c.Versions = append(c.Versions, providers.KVCertificateVersion{Version: fmt.Sprintf("%032x", i), Thumbprint: fmt.Sprintf("%040x", i)})
	}
	s := &Service{}
	p, err := s.prepareKV(providers.DiscoveryResult{KV: &providers.KVInventory{Certificates: []providers.KVCertificate{c}}}, now)
	assert.NoError(t, err)
	d := p.certs[0].details
	if assert.NotNil(t, d) {
		assert.Len(t, d.history, maxKVVersions-1, "bounded; the current version is one of them")
		assert.Equal(t, 2+7, p.unreadable[kvVersions], "two unusable entries and the ones over the bound")
	}
	// A leaf larger than the bound, and details whose thumbprint is not the leaf's, are not stored.
	big := c
	big.Details = &providers.KVCertificateDetails{Version: cur, Thumbprint: th, CER: make([]byte, maxKVCER+1)}
	p, _ = s.prepareKV(providers.DiscoveryResult{KV: &providers.KVInventory{Certificates: []providers.KVCertificate{big}}}, now)
	assert.Nil(t, p.certs[0].details)
	assert.Equal(t, 1, p.unreadable[kvCertificates])
}

func TestMarkMissingNamesRefusesAnUnknownTable(t *testing.T) {
	_, err := markMissingNames(nil, nil, "targets", uuid.New(), nil, time.Now())
	assert.Error(t, err)
}
