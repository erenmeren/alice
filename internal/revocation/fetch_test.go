package revocation

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr/netaddrtest"
	"alice/internal/testutil/fakerevocation"
	"alice/internal/testutil/pki"
)

// HB-13 (R64 Ruling 17, coordinator ruling C1): an OCSP or CRL address a certificate names is refused when it is not
// http or https on its own port, carries user info, or reaches Alice's host, a link-local or metadata address or any
// address netaddr refuses; the address is checked when Alice connects (a name that resolves to loopback included), and
// nothing reaches any server.
func TestFetchRefusesForbiddenAddresses(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
	ca := pki.NewCA("Forbidden", pki.ECDSA256, clk.Now())
	fake := fakerevocation.New(ca, clk)
	fake.Start(t)
	resolver := netaddrtest.Resolver(func(name string) []netip.Addr {
		switch name {
		case "loop.alice.test":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		case "loop6.alice.test":
			return []netip.Addr{netip.MustParseAddr("::1")}
		case "metadata.alice.test":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}
		}
		return nil
	})
	c := newChecker(clk, guardedDialer(resolver))
	for _, u := range []string{
		"ftp://ocsp.alice.test/", "ldap://ocsp.alice.test/", "http://u:p@ocsp.alice.test/", "http://ocsp.alice.test:8080/", "https://ocsp.alice.test:80/",
		"http://ocsp.alice.test:443/", "http:///nohost", "http://127.0.0.1/", "http://[::1]/", "http://0.0.0.0/", "http://[::]/",
		"http://169.254.169.254/", "http://[fe80::1]/", "http://[fe80::1%25eth0]/", "http://loop.alice.test/", "http://loop6.alice.test/",
		"http://metadata.alice.test/", "http://localhost/", "https://127.0.0.1/",
	} {
		for _, leaf := range []pki.Opts{{CommonName: "o", OCSPServer: []string{u}}, {CommonName: "c", CRLDistributionPoints: []string{u}}} {
			got := c.NewRun(50).Check(context.Background(), ca.Issue(leaf, clk.Now()).Cert, ca.Intermediate)
			assert.Equal(t, CodeAddressRefused, got.Code, u)
			assert.NotEqual(t, StatusRevoked, got.Status, u)
		}
	}
	assert.Zero(t, fake.Requests("/ocsp")+fake.Requests("/crl"), "nothing reached a server")
}

// HB-13: an answer over its cap (64 KiB for OCSP, 10 MiB for a CRL) is refused, not read on.
func TestFetchCapsTheAnswer(t *testing.T) {
	w := newWorld(t)
	w.fake.SetFault("/ocsp", fakerevocation.FaultHuge)
	w.fake.SetFault("/crl", fakerevocation.FaultHuge)
	assert.Equal(t, Result{Status: StatusUnavailable, Code: CodeTooLarge}, w.run(w.leaf([]string{ocspURL}, nil)))
	assert.Equal(t, Result{Status: StatusUnavailable, Code: CodeTooLarge}, w.run(w.leaf(nil, []string{crlURL})))
	assert.Equal(t, Result{Status: StatusUnavailable, Code: CodeTooLarge}, w.run(w.leaf([]string{ocspURL}, []string{crlURL})))
}

// HB-13: a redirect is never followed (it could lead anywhere); it is an unreachable responder.
func TestFetchNeverFollowsARedirect(t *testing.T) {
	w := newWorld(t)
	w.fake.SetFault("/ocsp", fakerevocation.FaultRedirect)
	w.fake.SetFault("/crl", fakerevocation.FaultRedirect)
	assert.Equal(t, Result{Status: StatusUnavailable, Code: CodeUnreachable}, w.run(w.leaf([]string{ocspURL}, []string{crlURL})))
	assert.Zero(t, w.fake.Requests("/target"))
}

// The production checker dials through the guard; a context already ended answers unreachable, never revoked.
func TestNewAndAnEndedContext(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
	ca := pki.NewCA("New", pki.ECDSA256, clk.Now())
	c := New(clk)
	require.NotNil(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	leaf := ca.Issue(pki.Opts{CommonName: "n", OCSPServer: []string{"http://127.0.0.1/"}}, clk.Now()).Cert
	assert.Equal(t, CodeAddressRefused, c.NewRun(1).Check(context.Background(), leaf, ca.Intermediate).Code)
	w := newWorld(t)
	assert.Equal(t, Result{Status: StatusUnavailable, Code: CodeUnreachable}, w.check.NewRun(5).Check(ctx, w.leaf([]string{ocspURL}, nil), w.ca.Intermediate))
}

// The freshness window and the reason names (R64 Ruling 16).
func TestFreshnessAndReasons(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	assert.True(t, ocspFresh(&ocsp.Response{ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}, now))
	assert.True(t, ocspFresh(&ocsp.Response{ThisUpdate: now.Add(4 * time.Minute)}, now), "a clock a little behind the responder's")
	assert.False(t, ocspFresh(&ocsp.Response{ThisUpdate: now.Add(6 * time.Minute)}, now), "from the future")
	assert.False(t, ocspFresh(&ocsp.Response{ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(-6 * time.Minute)}, now), "expired")
	assert.True(t, ocspFresh(&ocsp.Response{ThisUpdate: now.Add(-time.Hour)}, now), "no next update: current")
	for code, name := range map[int]string{0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged", 4: "superseded",
		5: "cessationOfOperation", 6: "certificateHold", 7: "unspecified", 8: "unspecified", 9: "privilegeWithdrawn", 10: "aACompromise", 99: "unspecified", -1: "unspecified"} {
		assert.Equal(t, name, reasonName(code), "%d", code)
	}
	assert.Equal(t, 4, rank(Result{Status: StatusRevoked}))
	assert.Equal(t, 4, rank(Result{Status: StatusOnHold}))
	assert.Less(t, rank(Result{Status: StatusUnavailable}), rank(Result{Status: StatusDeferred}))
	assert.Equal(t, "ocsp.alice.test", strings.Map(asciiLower, "OCSP.Alice.TEST"))
}
