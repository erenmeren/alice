package revocation

import (
	"context"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
	"alice/internal/testutil/fakerevocation"
	"alice/internal/testutil/pki"
)

const (
	ocspURL = "http://ocsp.alice.test/ocsp"
	crlURL  = "http://crl.alice.test/crl"
)

// world is a test CA, its fake responder and a checker whose every dial reaches the fake (the seam: the host names of
// the leaves' addresses are the fake's).
type world struct {
	clk   *clock.Fake
	ca    *pki.CA
	fake  *fakerevocation.Server
	check *Checker
}

func newWorld(t *testing.T) *world {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
	ca := pki.NewCA("Revocation", pki.ECDSA256, clk.Now())
	fake := fakerevocation.New(ca, clk)
	addr := fake.Start(t)
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return &world{clk: clk, ca: ca, fake: fake, check: newChecker(clk, dial)}
}

func (w *world) leaf(ocspURLs, crlURLs []string) *x509.Certificate {
	return w.ca.Issue(pki.Opts{CommonName: "www.example.test", OCSPServer: ocspURLs, CRLDistributionPoints: crlURLs}, w.clk.Now()).Cert
}

func (w *world) run(leaf *x509.Certificate) Result {
	return w.check.NewRun(50).Check(context.Background(), leaf, w.ca.Intermediate)
}

// HB-11 (R64 Ruling 16): only a signed, current OCSP answer decides; an answer that is not one (wrong signer, garbage,
// stale) or unknown falls to the CRL; both down is unavailable, never revoked.
func TestCheckOCSPAnswers(t *testing.T) {
	at := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		setup func(w *world, leaf *x509.Certificate)
		want  Result
	}{
		{"good", func(*world, *x509.Certificate) {}, Result{Status: StatusGood, Method: "ocsp"}},
		{"revoked", func(w *world, l *x509.Certificate) { w.fake.Revoke(l.SerialNumber, 1, at) },
			Result{Status: StatusRevoked, Method: "ocsp", RevokedAt: at, Reason: "keyCompromise"}},
		{"hold", func(w *world, l *x509.Certificate) { w.fake.Hold(l.SerialNumber, at) },
			Result{Status: StatusOnHold, Method: "ocsp", RevokedAt: at, Reason: "certificateHold"}},
		{"an unknown reason", func(w *world, l *x509.Certificate) { w.fake.Revoke(l.SerialNumber, 7, at) },
			Result{Status: StatusRevoked, Method: "ocsp", RevokedAt: at, Reason: "unspecified"}},
		{"unknown", func(w *world, _ *x509.Certificate) { w.fake.SetFault("/ocsp", fakerevocation.FaultUnknown) },
			Result{Status: StatusGood, Method: "crl"}},
		{"wrong signer", func(w *world, _ *x509.Certificate) { w.fake.SetFault("/ocsp", fakerevocation.FaultWrongSigner) },
			Result{Status: StatusGood, Method: "crl"}},
		{"garbage", func(w *world, _ *x509.Certificate) { w.fake.SetFault("/ocsp", fakerevocation.FaultGarbage) },
			Result{Status: StatusGood, Method: "crl"}},
		{"stale", func(w *world, _ *x509.Certificate) { w.fake.SetFault("/ocsp", fakerevocation.FaultStale) },
			Result{Status: StatusGood, Method: "crl"}},
		// Final review C1: a delegated responder speaks for the CA only with id-kp-OCSPSigning and while it is valid.
		{"a delegated responder", func(w *world, l *x509.Certificate) {
			w.fake.SetFault("/ocsp", fakerevocation.FaultDelegated)
			w.fake.Revoke(l.SerialNumber, 1, at)
		}, Result{Status: StatusRevoked, Method: "ocsp", RevokedAt: at, Reason: "keyCompromise"}},
		{"a delegated responder without OCSP signing", func(w *world, l *x509.Certificate) {
			w.fake.SetFault("/ocsp", fakerevocation.FaultDelegatedNoEKU)
			w.fake.SetFault("/crl", fakerevocation.FaultDown)
			w.fake.Revoke(l.SerialNumber, 1, at)
		}, Result{Status: StatusUnavailable, Code: CodeInvalidAnswer}},
		{"an expired delegated responder", func(w *world, l *x509.Certificate) {
			w.fake.SetFault("/ocsp", fakerevocation.FaultDelegatedExpired)
			w.fake.SetFault("/crl", fakerevocation.FaultDown)
			w.fake.Revoke(l.SerialNumber, 1, at)
		}, Result{Status: StatusUnavailable, Code: CodeInvalidAnswer}},
		// Final review M1: removeFromCRL (8) lifts a hold; it is never a revocation.
		{"removeFromCRL", func(w *world, l *x509.Certificate) { w.fake.Revoke(l.SerialNumber, 8, at) }, Result{Status: StatusGood, Method: "ocsp"}},
		{"both down", func(w *world, _ *x509.Certificate) {
			w.fake.SetFault("/ocsp", fakerevocation.FaultDown)
			w.fake.SetFault("/crl", fakerevocation.FaultDown)
		}, Result{Status: StatusUnavailable, Code: CodeUnreachable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			leaf := w.leaf([]string{ocspURL}, []string{crlURL})
			tc.setup(w, leaf)
			got := w.run(leaf)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("unknown without a CRL", func(t *testing.T) {
		w := newWorld(t)
		w.fake.SetFault("/ocsp", fakerevocation.FaultUnknown)
		assert.Equal(t, Result{Status: StatusUnknown, Method: "ocsp"}, w.run(w.leaf([]string{ocspURL}, nil)))
	})
}

// HB-12 (R64 Ruling 16): a CRL decides only when the issuer signed it and it names the leaf's issuer; a listed serial
// counts even in a stale CRL (revocation is permanent); not listed in a stale one is no answer; PEM is read.
func TestCheckCRL(t *testing.T) {
	at := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		setup func(w *world, leaf *x509.Certificate)
		want  Result
	}{
		{"listed", func(w *world, l *x509.Certificate) { w.fake.Revoke(l.SerialNumber, 4, at) },
			Result{Status: StatusRevoked, Method: "crl", RevokedAt: at, Reason: "superseded"}},
		{"listed on hold", func(w *world, l *x509.Certificate) { w.fake.Hold(l.SerialNumber, at) },
			Result{Status: StatusOnHold, Method: "crl", RevokedAt: at, Reason: "certificateHold"}},
		{"not listed", func(*world, *x509.Certificate) {}, Result{Status: StatusGood, Method: "crl"}},
		{"bad signature", func(w *world, _ *x509.Certificate) { w.fake.SetFault("/crl", fakerevocation.FaultWrongSigner) },
			Result{Status: StatusUnavailable, Code: CodeInvalidAnswer}},
		{"other issuer", func(w *world, _ *x509.Certificate) { w.fake.SetFault("/crl", fakerevocation.FaultOtherIssuer) },
			Result{Status: StatusUnavailable, Code: CodeInvalidAnswer}},
		{"garbage", func(w *world, _ *x509.Certificate) { w.fake.SetFault("/crl", fakerevocation.FaultGarbage) },
			Result{Status: StatusUnavailable, Code: CodeInvalidAnswer}},
		{"stale not listed", func(w *world, _ *x509.Certificate) { w.fake.SetFault("/crl", fakerevocation.FaultStale) },
			Result{Status: StatusUnavailable, Code: CodeInvalidAnswer}},
		{"stale listed", func(w *world, l *x509.Certificate) {
			w.fake.SetFault("/crl", fakerevocation.FaultStale)
			w.fake.Revoke(l.SerialNumber, 1, at)
		}, Result{Status: StatusRevoked, Method: "crl", RevokedAt: at, Reason: "keyCompromise"}},
		{"PEM", func(w *world, _ *x509.Certificate) { w.fake.SetCRLPEM(true) }, Result{Status: StatusGood, Method: "crl"}},
		// Final review M1: an entry with removeFromCRL is no revocation; a delta CRL is not read.
		{"listed with removeFromCRL", func(w *world, l *x509.Certificate) { w.fake.Revoke(l.SerialNumber, 8, at) }, Result{Status: StatusGood, Method: "crl"}},
		{"a delta CRL", func(w *world, l *x509.Certificate) {
			w.fake.SetFault("/crl", fakerevocation.FaultDeltaCRL)
			w.fake.Revoke(l.SerialNumber, 1, at)
		}, Result{Status: StatusUnavailable, Code: CodeInvalidAnswer}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			leaf := w.leaf(nil, []string{crlURL})
			tc.setup(w, leaf)
			assert.Equal(t, tc.want, w.run(leaf))
		})
	}
}

// A leaf without the issuer that signed it, or without any address, cannot be checked; nothing is fetched.
func TestCheckNotCheckable(t *testing.T) {
	w := newWorld(t)
	leaf := w.leaf([]string{ocspURL}, []string{crlURL})
	r := w.check.NewRun(5)
	assert.Equal(t, Result{Status: StatusNotCheckable, Code: CodeNoIssuer}, r.Check(context.Background(), leaf, nil))
	other := pki.NewCA("Other", pki.ECDSA256, w.clk.Now())
	assert.Equal(t, Result{Status: StatusNotCheckable, Code: CodeNoIssuer}, r.Check(context.Background(), leaf, other.Intermediate))
	assert.Equal(t, Result{Status: StatusNotCheckable, Code: CodeNoAddress}, r.Check(context.Background(), w.leaf(nil, nil), w.ca.Intermediate))
	assert.Equal(t, Result{Status: StatusNotCheckable, Code: CodeNoAddress}, r.Check(context.Background(), w.leaf(nil, []string{""}),
		w.ca.Intermediate), "an empty address is no address")
	assert.Equal(t, Result{Status: StatusNotCheckable, Code: CodeAddressRefused}, r.Check(context.Background(), w.leaf([]string{"ldap://x/"}, nil),
		w.ca.Intermediate), "an address Alice never fetches")
	assert.Zero(t, w.fake.Requests("/ocsp")+w.fake.Requests("/crl"))
}

// HB-14 (R64 Ruling 17): one run fetches a CRL once for every leaf that names it (a cache hit costs nothing), and makes
// at most perHost requests to one host: the rest fall to the CRL, or are deferred when the CRL's host is spent too.
func TestRunBudgetAndCache(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	r := w.check.NewRun(2)
	for range 5 {
		assert.Equal(t, Result{Status: StatusGood, Method: "crl"}, r.Check(ctx, w.leaf(nil, []string{crlURL}), w.ca.Intermediate))
	}
	assert.Equal(t, 1, w.fake.Requests("/crl"))

	w = newWorld(t)
	r = w.check.NewRun(2)
	var got []Result
	for range 5 {
		got = append(got, r.Check(ctx, w.leaf([]string{ocspURL}, []string{crlURL}), w.ca.Intermediate))
	}
	assert.Equal(t, 2, w.fake.Requests("/ocsp"))
	assert.Equal(t, 1, w.fake.Requests("/crl"))
	assert.Equal(t, []Result{{Status: StatusGood, Method: "ocsp"}, {Status: StatusGood, Method: "ocsp"}, {Status: StatusGood, Method: "crl"},
		{Status: StatusGood, Method: "crl"}, {Status: StatusGood, Method: "crl"}}, got)

	w = newWorld(t)
	r = w.check.NewRun(2)
	got = nil
	for range 4 {
		got = append(got, r.Check(ctx, w.leaf([]string{"http://rev.alice.test/ocsp"}, []string{"http://rev.alice.test/crl"}), w.ca.Intermediate))
	}
	assert.Equal(t, []Result{{Status: StatusGood, Method: "ocsp"}, {Status: StatusGood, Method: "ocsp"}, {Status: StatusDeferred},
		{Status: StatusDeferred}}, got, "the host is spent: OCSP and CRL are deferred")
	assert.Equal(t, 2, w.fake.Requests("/ocsp")+w.fake.Requests("/crl"))

	assert.Equal(t, 16, maxCachedCRLs)
	w = newWorld(t)
	r = w.check.NewRun(100)
	for n := range maxCachedCRLs + 2 {
		u := "http://crl.alice.test/crl?n=" + string(rune('a'+n))
		r.Check(ctx, w.leaf(nil, []string{u}), w.ca.Intermediate)
		r.Check(ctx, w.leaf(nil, []string{u}), w.ca.Intermediate)
	}
	assert.Equal(t, maxCachedCRLs+4, w.fake.Requests("/crl"), "past 16 CRLs a run caches no more")
}

// Final review C2: one run, two issuers naming the same CRL address. The CRL verified for the first issuer is never
// searched for a leaf of the second: the second fetches and verifies the answer against its own issuer.
func TestCRLCacheIsPerIssuer(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	r := w.check.NewRun(50)
	leaf := w.leaf(nil, []string{crlURL})
	assert.Equal(t, Result{Status: StatusGood, Method: "crl"}, r.Check(ctx, leaf, w.ca.Intermediate))
	other := pki.NewCA("Victim", pki.ECDSA256, w.clk.Now())
	victim := other.Issue(pki.Opts{CommonName: "victim.example.test", CRLDistributionPoints: []string{crlURL}}, w.clk.Now()).Cert
	w.fake.Revoke(victim.SerialNumber, 1, w.clk.Now().Add(-time.Hour)) // the attacker's CRL (signed by the first CA) lists the victim
	assert.Equal(t, Result{Status: StatusUnavailable, Code: CodeInvalidAnswer}, r.Check(ctx, victim, other.Intermediate),
		"the cached list of another issuer is a miss; fetched again, it fails the victim issuer's signature check")
	assert.Equal(t, 2, w.fake.Requests("/crl"))
	assert.Equal(t, Result{Status: StatusGood, Method: "crl"}, r.Check(ctx, w.leaf(nil, []string{crlURL}), w.ca.Intermediate))
	assert.Equal(t, 2, w.fake.Requests("/crl"), "the first issuer's list is still cached")
}

// Final review M2: a CRL over 1 MiB is read and used, never cached.
func TestLargeCRLsAreNotCached(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	for n := range 40000 {
		w.fake.Revoke(big.NewInt(int64(1_000_000+n)), 4, w.clk.Now().Add(-time.Hour))
	}
	r := w.check.NewRun(50)
	leaf := w.leaf(nil, []string{crlURL})
	assert.Equal(t, Result{Status: StatusGood, Method: "crl"}, r.Check(ctx, leaf, w.ca.Intermediate))
	assert.Equal(t, Result{Status: StatusGood, Method: "crl"}, r.Check(ctx, leaf, w.ca.Intermediate))
	assert.Equal(t, 2, w.fake.Requests("/crl"), "not cached")
}
