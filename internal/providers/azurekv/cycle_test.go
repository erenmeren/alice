package azurekv

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

// link is a nextLink of the vault's own host with a skiptoken the fake accepts.
func link(marker string) string {
	tok := base64.RawURLEncoding.EncodeToString([]byte(`{"NextMarker":"` + marker + `","TargetLocation":0}`))
	return "https://" + testVaultHost + ":443/certificates?api-version=" + fakekv.APIVersion + "&$skiptoken=" + tok + "&maxresults=25"
}

func listedRequests(s *fakekv.Server) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Path == "/certificates" && r.HadAuth {
			n++
		}
	}
	return n
}

func TestNextLinkCycleEnds(t *testing.T) {
	list := func(t *testing.T, s *fakekv.Server, maxPages int) (*providers.Error, int) {
		t.Helper()
		clk := nearNow()
		sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, clk)
		sess.api.(*sdkAPI).r.maxPages = maxPages
		s.ClearRequests()
		pages := 0
		err := drive(clk, func() error {
			return sess.api.ListCertificates(context.Background(), func([]*azcertificates.CertificateProperties) error { pages++; return nil })
		})
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		return pe, pages
	}
	t.Run("self-cycle", func(t *testing.T) {
		s := fakekv.Start(t, fakekv.Options{})
		s.AddBulkCertificates("bulk", 60)
		s.FailAll("/certificates", fakekv.Fault{NextLink: link("bulk-00")})
		pe, pages := list(t, s, 0)
		assert.Equal(t, "azure.unexpected_response", pe.Code)
		assert.ErrorIs(t, pe, providers.ErrUnexpectedAnswer)
		assert.Equal(t, 2, listedRequests(s), "page one, then the link once; the repeat is refused")
		assert.Equal(t, 1, pages, "the repeated page is not delivered")
	})
	t.Run("two-page cycle", func(t *testing.T) {
		s := fakekv.Start(t, fakekv.Options{})
		s.AddBulkCertificates("bulk", 60)
		a, b := link("bulk-00"), link("bulk-01")
		s.FailNext("/certificates", fakekv.Fault{NextLink: a})
		s.FailNext("/certificates", fakekv.Fault{NextLink: b})
		s.FailNext("/certificates", fakekv.Fault{NextLink: a})
		pe, _ := list(t, s, 0)
		assert.Equal(t, "azure.unexpected_response", pe.Code)
		assert.Equal(t, 3, listedRequests(s))
	})
	t.Run("page cap with distinct links", func(t *testing.T) {
		s := fakekv.Start(t, fakekv.Options{})
		s.AddBulkCertificates("bulk", 60)
		for i := range 20 {
			s.FailNext("/certificates", fakekv.Fault{NextLink: link("bulk-" + strconv.Itoa(i))})
		}
		pe, pages := list(t, s, 5)
		assert.Equal(t, "azure.unexpected_response", pe.Code)
		assert.Equal(t, 5, listedRequests(s), "no request beyond the cap")
		assert.Equal(t, 5, pages)
	})
	t.Run("the cap fits the largest vault", func(t *testing.T) {
		// 10,000 secrets (and the certificates' own managed ones) at 25 per page.
		assert.GreaterOrEqual(t, MaxListPages*25, MaxKVSecrets+MaxKVCertificates)
	})
}

// N5: a nextLink longer than any real one is refused before it is remembered or followed.
func TestNextLinkLengthIsBounded(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddBulkCertificates("bulk", 60)
	clk := nearNow()
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, clk)
	for name, n := range map[string]int{"just over the bound": MaxNextLink + 1, "huge": 3 << 20} {
		t.Run(name, func(t *testing.T) {
			s.ClearRequests()
			s.FailNext("/certificates", fakekv.Fault{NextLink: link("bulk-00") + "&pad=" + strings.Repeat("a", n)})
			pages := 0
			err := drive(clk, func() error {
				return sess.api.ListCertificates(context.Background(), func([]*azcertificates.CertificateProperties) error { pages++; return nil })
			})
			pe := asProviderError(t, err)
			assert.Equal(t, codeUnexpected, pe.Code)
			require.ErrorIs(t, pe, providers.ErrUnexpectedAnswer)
			assert.Equal(t, 1, listedRequests(s), "the link was never followed")
		})
	}
	t.Run("a link at the bound is fine", func(t *testing.T) {
		s.ClearRequests()
		l := link("bulk-00")
		s.FailNext("/certificates", fakekv.Fault{NextLink: l + "&pad=" + strings.Repeat("a", MaxNextLink-len(l)-5)})
		err := drive(clk, func() error {
			return sess.api.ListCertificates(context.Background(), func([]*azcertificates.CertificateProperties) error { return nil })
		})
		require.NoError(t, err)
	})
}
