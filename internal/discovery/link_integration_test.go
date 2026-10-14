//go:build integration

package discovery

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// issuedCert returns a DER leaf named cn with the SANs, valid from nb to na, issued by a test CA (not self-signed).
func issuedCert(t *testing.T, cn string, sans []string, nb, na time.Time) []byte {
	t.Helper()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Filter Test CA"}, NotBefore: nb.AddDate(-1, 0, 0),
		NotAfter: na.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, Issuer: ca.Subject,
		NotBefore: nb, NotAfter: na, DNSNames: sans}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &certKey.PublicKey, certKey)
	require.NoError(t, err)
	return der
}

func fps(rows []CertificateRow) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, r.Fingerprint)
	}
	return out
}

// The list's filters (Task 9): a text search on the subject CN and the SANs (case-insensitive, LIKE characters taken
// literally), expired or not, expiring by a time (not expired yet), self-signed or not. Each composes with the others
// and with the keyset.
func TestCertificateFilters(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	now := t0
	expired := issuedCert(t, "old.example", []string{"old.example"}, now.AddDate(-1, 0, 0), now.Add(-time.Hour))
	soon := issuedCert(t, "soon.example", []string{"soon.example", "WWW.Shop_1.example"}, now.AddDate(0, -1, 0), now.AddDate(0, 0, 10))
	later := issuedCert(t, "later.example", []string{"100%.example"}, now.AddDate(0, -1, 0), now.AddDate(0, 0, 90))
	selfSigned := testCert(t, "self.example", now.AddDate(0, -1, 0), now.AddDate(0, 0, 20))
	p.ingestScan(t, scope, now, presented(t, ep("10.0.0.1", 443, ""), expired), presented(t, ep("10.0.0.2", 443, ""), soon),
		presented(t, ep("10.0.0.3", 443, ""), later), presented(t, ep("10.0.0.4", 443, ""), selfSigned))
	yes, no := true, false
	list := func(f CertificateFilter) []string {
		t.Helper()
		f.Now = now
		rows, err := ListCertificates(bg(), p.App, f)
		require.NoError(t, err)
		return fps(rows)
	}
	fp := fingerprint
	require.Equal(t, []string{fp(expired), fp(soon), fp(selfSigned), fp(later)}, list(CertificateFilter{}))
	require.Equal(t, []string{fp(expired)}, list(CertificateFilter{Expired: &yes}))
	require.Equal(t, []string{fp(soon), fp(selfSigned), fp(later)}, list(CertificateFilter{Expired: &no}))
	require.Equal(t, []string{fp(soon)}, list(CertificateFilter{ExpiringBy: now.AddDate(0, 0, 14)}), "expiring within 14 days, not expired")
	require.Equal(t, []string{fp(soon), fp(selfSigned)}, list(CertificateFilter{ExpiringBy: now.AddDate(0, 0, 30)}))
	require.Equal(t, []string{fp(selfSigned)}, list(CertificateFilter{SelfSigned: &yes}))
	require.Equal(t, []string{fp(expired), fp(soon), fp(later)}, list(CertificateFilter{SelfSigned: &no}))

	// Text: CN or any SAN, case-insensitive; % and _ are literal characters, not wildcards.
	require.Equal(t, []string{fp(soon)}, list(CertificateFilter{Query: "shop_1"}))
	require.Equal(t, []string{fp(soon)}, list(CertificateFilter{Query: "SOON"}))
	require.Empty(t, list(CertificateFilter{Query: "shop%1"}), "% is not a wildcard")
	require.Empty(t, list(CertificateFilter{Query: "sho__1"}), "_ is not a wildcard")
	require.Equal(t, []string{fp(later)}, list(CertificateFilter{Query: "100%"}))
	require.Empty(t, list(CertificateFilter{Query: `\`}))
	require.Equal(t, []string{fp(expired), fp(soon), fp(selfSigned), fp(later)}, list(CertificateFilter{Query: "example"}))

	// Composed with each other, the status and the keyset.
	require.Equal(t, []string{fp(soon)}, list(CertificateFilter{Query: "example", ExpiringBy: now.AddDate(0, 0, 30), SelfSigned: &no}))
	require.Equal(t, []string{fp(soon), fp(selfSigned)}, list(CertificateFilter{Status: StatusUnmanaged, Expired: &no, Limit: 2}))
	// Current: some endpoint that is not gone presents or last presented it (the summary's and the alerts' definition
	// of "still found"); the scope narrows it to that scope's endpoints.
	require.Equal(t, []string{fp(expired), fp(soon), fp(selfSigned), fp(later)}, list(CertificateFilter{Current: true}))
	_, err := p.App.Exec(bg(), `UPDATE discovery_endpoints SET state = 'gone', gone_since = now() WHERE fingerprint_sha256 = $1`, fp(later))
	require.NoError(t, err)
	other := p.scope(t, "other")
	p.ingestScan(t, other, now, presented(t, ep("10.0.1.1", 443, ""), soon))
	_, err = p.App.Exec(bg(), `UPDATE discovery_endpoints SET state = 'gone', gone_since = now() WHERE scope_id = $1`, scope)
	require.NoError(t, err)
	_, err = p.App.Exec(bg(), `UPDATE discovery_endpoints SET state = 'unreachable', last_error_code = 'timeout', gone_since = NULL WHERE fingerprint_sha256 = $1`, fp(selfSigned))
	require.NoError(t, err)
	require.Equal(t, []string{fp(soon), fp(selfSigned)}, list(CertificateFilter{Current: true}), "an unreachable endpoint is not gone")
	require.Equal(t, []string{fp(expired), fp(soon), fp(selfSigned), fp(later)}, list(CertificateFilter{}), "without Current every leaf stays listed")
	require.Equal(t, []string{fp(selfSigned)}, list(CertificateFilter{Current: true, ScopeID: scope}))
	require.Equal(t, []string{fp(soon)}, list(CertificateFilter{Current: true, ScopeID: other, Status: StatusUnmanaged}))
	_, err = p.App.Exec(bg(), `UPDATE discovery_endpoints SET state = 'present', last_error_code = '', gone_since = NULL WHERE scope_id = $1`, scope)
	require.NoError(t, err)

	first, err := ListCertificates(bg(), p.App, CertificateFilter{Now: now, Expired: &no, Limit: 1})
	require.NoError(t, err)
	require.Equal(t, []string{fp(selfSigned), fp(later)}, list(CertificateFilter{Expired: &no,
		After: &CertificateCursor{NotAfter: first[0].NotAfter, Fingerprint: first[0].Fingerprint}}))
}

// A time filter without the reference time is a programming error, not "everything".
func TestCertificateTimeFiltersNeedNow(t *testing.T) {
	p := newPG(t)
	yes := true
	_, err := ListCertificates(bg(), p.App, CertificateFilter{Expired: &yes})
	require.ErrorIs(t, err, ErrFilterNeedsNow)
	_, err = ListCertificates(bg(), p.App, CertificateFilter{ExpiringBy: t0})
	require.ErrorIs(t, err, ErrFilterNeedsNow)
}

// The finish hook (Task 9: the discovery.scan.finished audit row) runs inside FinishScan's transaction, once, only for
// the scan FinishScan actually ended; when it fails, the scan is not ended.
func TestFinishHookRunsInTheFinishTransaction(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	var seen []Finish
	var fail error
	st := NewStore(p.App).OnFinish(func(ctx context.Context, tx pgx.Tx, f Finish) error {
		var state string
		require.NoError(t, tx.QueryRow(ctx, `SELECT state FROM discovery_scans WHERE id = $1`, f.ScanID).Scan(&state))
		require.Equal(t, f.State, state, "the hook sees the ended scan in the same transaction")
		seen = append(seen, f)
		return fail
	})
	id := p.running(t, scope, t0)
	fail = errors.New("audit refused")
	err := st.FinishScan(bg(), Finish{ScanID: id, ScopeID: scope, Now: t0, State: ScanDone})
	require.ErrorIs(t, err, fail)
	require.Equal(t, ScanRunning, p.scan(t, id).State, "a failed hook rolls the end back")

	fail = nil
	require.NoError(t, st.FinishScan(bg(), Finish{ScanID: id, ScopeID: scope, Now: t0, State: ScanDone}))
	require.Equal(t, ScanDone, p.scan(t, id).State)
	require.NoError(t, st.FinishScan(bg(), Finish{ScanID: id, ScopeID: scope, Now: t0, State: ScanCancelled, ErrorCode: ReasonCancelled}))
	require.Len(t, seen, 2, "no hook for a scan that was already over")
	require.Equal(t, id, seen[1].ScanID)
	require.Equal(t, ScanDone, p.scan(t, id).State)

	// The store without a hook still ends scans.
	other := p.running(t, p.scope(t, "other"), t0)
	require.NoError(t, NewStore(p.App).FinishScan(bg(), Finish{ScanID: other, ScopeID: uuid.Nil, Now: t0, State: ScanDone}))
	require.Equal(t, ScanDone, p.scan(t, other).State)
}

// Every end of a scan inside the store runs the finish hook once in its transaction (Task 9 review 3): BeginScan's crash
// recovery and retention's sweep of stale running scans, not only FinishScan.
func TestFinishHookRunsOnEveryEndInTheStore(t *testing.T) {
	p := newPG(t)
	var seen []Finish
	st := NewStore(p.App).OnFinish(func(ctx context.Context, tx pgx.Tx, f Finish) error {
		var state string
		require.NoError(t, tx.QueryRow(ctx, `SELECT state FROM discovery_scans WHERE id = $1`, f.ScanID).Scan(&state))
		require.Equal(t, ScanFailed, state)
		seen = append(seen, f)
		return nil
	})
	scope := p.scope(t, "lab")
	crashed := p.running(t, scope, t0)
	start, err := st.BeginScan(bg(), crashed, t0.Add(2*time.Minute), 45*time.Second)
	require.NoError(t, err)
	require.False(t, start.Run)
	require.Len(t, seen, 1)
	require.Equal(t, Finish{ScanID: crashed, ScopeID: scope, Now: t0.Add(2 * time.Minute), State: ScanFailed, ErrorCode: ReasonInterrupted}, seen[0])
	_, err = st.BeginScan(bg(), crashed, t0.Add(3*time.Minute), 45*time.Second)
	require.NoError(t, err)
	require.Len(t, seen, 1, "a finished scan is not ended twice")

	other := p.scope(t, "other")
	stale := p.running(t, other, t0)
	stats, err := st.Retain(bg(), t0.Add(StaleScanAfter+time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 1, stats.Interrupted)
	require.Len(t, seen, 2)
	require.Equal(t, Finish{ScanID: stale, ScopeID: other, Now: t0.Add(StaleScanAfter + time.Minute), State: ScanFailed,
		ErrorCode: ReasonInterrupted}, seen[1])

	// A failing hook rolls the end back.
	third := p.running(t, p.scope(t, "third"), t0)
	bad := NewStore(p.App).OnFinish(func(context.Context, pgx.Tx, Finish) error { return errors.New("audit refused") })
	_, err = bad.Retain(bg(), t0.Add(StaleScanAfter+time.Minute))
	require.Error(t, err)
	require.Equal(t, ScanRunning, p.scan(t, third).State)
	_, err = bad.BeginScan(bg(), third, t0.Add(2*time.Minute), 45*time.Second)
	require.Error(t, err)
	require.Equal(t, ScanRunning, p.scan(t, third).State)
}

// An excluded place is not "still found" (it is never dialed, so what it once presented is history), nor is a place of
// a deleted scope: the list's Current filter and its endpoint counts leave both out, and retention purges a stale
// excluded endpoint.
func TestExcludedAndDeletedScopeEndpointsAreNotCurrent(t *testing.T) {
	p := newPG(t)
	now := t0
	scope, doomed := p.scope(t, "lab"), p.scope(t, "doomed")
	excluded := issuedCert(t, "ex.example", []string{"ex.example"}, now.AddDate(0, -1, 0), now.AddDate(0, 0, 10))
	gonescope := issuedCert(t, "ds.example", []string{"ds.example"}, now.AddDate(0, -1, 0), now.AddDate(0, 0, 11))
	live := issuedCert(t, "live.example", []string{"live.example"}, now.AddDate(0, -1, 0), now.AddDate(0, 0, 12))
	p.ingestScan(t, scope, now, presented(t, ep("10.0.0.1", 443, ""), excluded), presented(t, ep("10.0.0.2", 443, ""), live))
	p.ingestScan(t, doomed, now, presented(t, ep("10.0.1.1", 443, ""), gonescope))
	_, err := p.Owner.Exec(bg(), `UPDATE discovery_endpoints SET state = 'excluded', last_error_code = 'policy', last_scanned_at = $2
WHERE scope_id = $1 AND address = '10.0.0.1'`, scope, now.AddDate(0, 0, -100))
	require.NoError(t, err)
	_, err = p.Owner.Exec(bg(), `UPDATE discovery_scopes SET deleted_at = $2 WHERE id = $1`, doomed, now)
	require.NoError(t, err)

	rows, err := ListCertificates(bg(), p.App, CertificateFilter{Now: now, Current: true})
	require.NoError(t, err)
	require.Equal(t, []string{fingerprint(live)}, fps(rows))
	rows, err = ListCertificates(bg(), p.App, CertificateFilter{Now: now})
	require.NoError(t, err)
	require.Len(t, rows, 3, "without Current every leaf is listed")
	for _, r := range rows {
		want := 0
		if r.Fingerprint == fingerprint(live) {
			want = 1
		}
		require.Equal(t, want, r.SeenOn, r.Fingerprint)
	}

	st, err := p.st.Retain(bg(), now)
	require.NoError(t, err)
	require.EqualValues(t, 2, st.Endpoints, "the stale excluded endpoint and the deleted scope's")
	require.Equal(t, 1, p.count(t, `SELECT count(*) FROM discovery_endpoints WHERE scope_id = $1`, scope))
}

// A scan asked to stop stores nothing more: the batch still in flight when a scope edit marked endpoints gone must not
// bring them back.
func TestIngestDropsBatchOfCancelledScan(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	cert := issuedCert(t, "c.example", []string{"c.example"}, t0.AddDate(0, -1, 0), t0.AddDate(0, 0, 10))
	id := p.running(t, scope, t0)
	_, err := p.Owner.Exec(bg(), `UPDATE discovery_scans SET cancel_requested = true WHERE id = $1`, id)
	require.NoError(t, err)
	require.NoError(t, p.st.Ingest(bg(), Batch{ScanID: id, ScopeID: scope, Now: t0, Results: []Result{presented(t, ep("10.0.0.1", 443, ""), cert)}}))
	require.Zero(t, p.count(t, `SELECT count(*) FROM discovery_endpoints WHERE scope_id = $1`, scope))
	require.Zero(t, p.scan(t, id).Answered)
}
