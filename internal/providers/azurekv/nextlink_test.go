package azurekv

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

func TestForeignNextLinkIsRefused(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{ExtraHosts: []string{"evil.test", "login.microsoftonline.com.evil.test"}})
	s.AddBulkCertificates("bulk", 60) // three pages
	clk := nearNow()
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, clk)
	list := func(f func([]*azcertificates.CertificateProperties) error) error {
		return drive(clk, func() error { return sess.api.ListCertificates(context.Background(), f) })
	}
	for _, foreign := range []string{
		"https://evil.test/certificates?api-version=" + fakekv.APIVersion + "&$skiptoken=x",
		"https://login.microsoftonline.com/certificates", // the other Microsoft host: a vault never sends Alice there
		"http://" + testVaultHost + "/certificates",
		"https://" + testVaultHost + ":8443/certificates",
	} {
		s.ClearRequests()
		s.FailNext("/certificates", fakekv.Fault{NextLink: foreign})
		pages := 0
		err := list(func(p []*azcertificates.CertificateProperties) error { pages++; return nil })
		var pe *providers.Error
		require.ErrorAs(t, err, &pe, foreign)
		assert.Equal(t, "azure.unexpected_response", pe.Code, foreign)
		if strings.HasPrefix(foreign, "https://") {
			assert.ErrorIs(t, pe, errHostNotAllowed, foreign) // refused by the vault transport
		} // (an http link is refused by the SDK itself before it reaches the transport)
		assert.Equal(t, 1, pages, "the first page was delivered, the second was refused")
		for _, r := range s.Requests() {
			assert.Contains(t, []string{testVaultHost, "login.microsoftonline.com"}, r.Host, "%s: nothing reached another host", foreign)
			if r.Host != testVaultHost {
				assert.NotEqual(t, "/certificates", r.Path, "%s: the vault's link was not followed to the login host", foreign)
				assert.False(t, r.HadAuth)
			}
		}
	}
	// The log proves it for the host that would have received the token.
	s.ClearRequests()
	s.FailNext("/certificates", fakekv.Fault{NextLink: "https://evil.test/certificates"})
	_ = list(func([]*azcertificates.CertificateProperties) error { return nil })
	for _, r := range s.Requests() {
		assert.NotEqual(t, "evil.test", r.Host)
	}
}

func TestListingResumesAtTheFailedPage(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddBulkCertificates("bulk", 60) // three pages
	clk := nearNow()
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, clk)
	s.FailNext("/certificates", fakekv.Fault{}) // page one passes
	s.FailNext("/certificates", fakekv.Fault{Status: 503})
	var seen int
	err := drive(clk, func() error {
		return sess.api.ListCertificates(context.Background(), func(p []*azcertificates.CertificateProperties) error { seen += len(p); return nil })
	})
	require.NoError(t, err)
	assert.Equal(t, 60, seen, "every certificate once: the listing did not restart")
	var firstPages int
	for _, r := range s.Requests() {
		if r.Host == testVaultHost && r.Path == "/certificates" && !contains(r.Query, "$skiptoken") && r.HadAuth {
			firstPages++
		}
	}
	assert.Equal(t, 1, firstPages, "page one was asked for once")
}

func contains(keys []string, k string) bool {
	for _, x := range keys {
		if x == k {
			return true
		}
	}
	return false
}

// A listing whose later page meets an expired token: the SDK's challenge check fails on the
// port-qualified host of a nextLink. When the challenge came from the vault's own host naming the
// vault resource the failure is retryable and the page is asked again; a foreign challenge is final.
func TestExpiredTokenOnALaterPageIsRetryable(t *testing.T) {
	srvClk := clock.NewFake(time.Now())
	s := fakekv.Start(t, fakekv.Options{Now: srvClk.Now})
	s.AddBulkCertificates("bulk", 60)
	clk := nearNow()
	sess := openSession(t, testProvider(s), &idSource{id: secretIdentity(s)}, clk)
	pages := 0
	err := drive(clk, func() error {
		return sess.api.ListCertificates(context.Background(), func([]*azcertificates.CertificateProperties) error {
			pages++
			if pages == 1 {
				srvClk.Advance(2 * time.Hour) // the vault now sees the token as expired
			}
			return nil
		})
	})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "azure.unexpected_response", pe.Code)
	assert.True(t, pe.Retryable)
	second := 0
	for _, r := range s.Requests() {
		if strings.HasPrefix(r.Host, testVaultHost) && r.HadAuth && contains(r.Query, "$skiptoken") {
			second++
		}
	}
	assert.Equal(t, MaxAttempts, second, "page two was asked MaxAttempts times, and page one was not asked again")
}
