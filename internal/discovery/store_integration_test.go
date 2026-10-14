//go:build integration

package discovery

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery/tlsprobe"
	"alice/internal/inventory"
	"alice/internal/platform/clock"
	"alice/internal/platform/settings"
	"alice/internal/testutil/fakefleet"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var t0 = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)

type pg struct {
	*pgtest.DB
	st *PGStore
}

func newPG(t *testing.T) *pg {
	t.Helper()
	d := pgtest.New(t)
	return &pg{DB: d, st: NewStore(d.App)}
}

func bg() context.Context { return context.Background() }

// scope inserts a scope (the API's job in production) and returns its id.
func (p *pg) scope(t *testing.T, name string, entries ...string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if len(entries) == 0 {
		entries = []string{"10.0.0.0/24"}
	}
	_, err := p.App.Exec(bg(), `INSERT INTO discovery_scopes (id, name, entries, ports, sni_names, exclusions, schedule_hours, window_start,
    window_end, window_tz, rate_per_sec, concurrency, created_at, updated_at)
VALUES ($1, $2, $3, '{443, 8443}', '{a.example}', '["10.0.0.128/25"]', 6, '22:00', '04:30', 'Europe/Istanbul', 100, 8, $4, $4)`,
		id, name, entries, t0)
	require.NoError(t, err)
	return id
}

// running queues a scan of scope and starts it at now.
func (p *pg) running(t *testing.T, scope uuid.UUID, now time.Time) uuid.UUID {
	t.Helper()
	id, err := p.st.CreateScan(bg(), scope, "schedule", nil, now)
	require.NoError(t, err)
	st, err := p.st.BeginScan(bg(), id, now, DefaultLease)
	require.NoError(t, err)
	require.True(t, st.Run)
	return id
}

func (p *pg) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, p.Owner.QueryRow(bg(), sql, args...).Scan(&n))
	return n
}

type scanRow struct {
	State, ErrorCode                                              string
	Total, Answered, Failed, Excluded, CertificatesNew, CertChurn int
	Finished                                                      *time.Time
}

func (p *pg) scan(t *testing.T, id uuid.UUID) scanRow {
	t.Helper()
	var r scanRow
	require.NoError(t, p.Owner.QueryRow(bg(), `SELECT state, error_code, endpoints_total, endpoints_answered, endpoints_failed,
    endpoints_excluded, certificates_new, cert_churn, finished_at FROM discovery_scans WHERE id = $1`, id).Scan(&r.State, &r.ErrorCode,
		&r.Total, &r.Answered, &r.Failed, &r.Excluded, &r.CertificatesNew, &r.CertChurn, &r.Finished))
	return r
}

type endpointState struct {
	State, Code, Fingerprint string
	Missed                   int
	Previous                 []string
	Chain                    []string
	GoneSince                *time.Time
	LastSeen                 *time.Time
}

func (p *pg) endpoint(t *testing.T, scope uuid.UUID, e Endpoint) endpointState {
	t.Helper()
	var s endpointState
	require.NoError(t, p.Owner.QueryRow(bg(), `SELECT state, last_error_code, coalesce(fingerprint_sha256, ''), missed_scans,
    previous_fingerprints, chain_fingerprints, gone_since, last_seen
FROM discovery_endpoints WHERE scope_id = $1 AND address = $2 AND port = $3 AND sni = $4`, scope, e.Address, int(e.Port), e.SNI).Scan(
		&s.State, &s.Code, &s.Fingerprint, &s.Missed, &s.Previous, &s.Chain, &s.GoneSince, &s.LastSeen))
	return s
}

// ingestScan runs one scan of scope at now with results, through the real ingest and finish path.
func (p *pg) ingestScan(t *testing.T, scope uuid.UUID, now time.Time, results ...Result) uuid.UUID {
	t.Helper()
	id := p.running(t, scope, now)
	x := &Expansion{}
	for _, r := range results {
		x.Dial = append(x.Dial, r.Endpoint)
	}
	x.Endpoints = len(x.Dial)
	require.NoError(t, p.st.PrepareScan(bg(), id, scope, x, now))
	require.NoError(t, chunks(results, func(part []Result) error {
		return p.st.Ingest(bg(), Batch{ScanID: id, ScopeID: scope, Now: now, Results: part})
	}))
	require.NoError(t, p.st.FinishScan(bg(), Finish{ScanID: id, ScopeID: scope, Now: now, State: ScanDone, Probed: true}))
	return id
}

func TestOneScanPerScope(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	id, err := p.st.CreateScan(bg(), scope, "manual", nil, t0)
	require.NoError(t, err)
	_, err = p.st.CreateScan(bg(), scope, "schedule", nil, t0)
	require.ErrorIs(t, err, ErrScanRunning, "ALC-DSC-0004")
	_, err = p.st.CreateScan(bg(), uuid.New(), "manual", nil, t0)
	require.ErrorIs(t, err, ErrScopeNotFound)
	other := p.scope(t, "other")
	_, err = p.st.CreateScan(bg(), other, "manual", nil, t0)
	require.NoError(t, err, "another scope scans at the same time")

	ok, err := p.st.RequestCancel(bg(), id)
	require.NoError(t, err)
	require.True(t, ok)
	st, err := p.st.BeginScan(bg(), id, t0, DefaultLease)
	require.NoError(t, err)
	require.True(t, st.CancelRequested)
	require.NoError(t, p.st.FinishScan(bg(), Finish{ScanID: id, ScopeID: scope, Now: t0, State: ScanCancelled, ErrorCode: ReasonCancelled}))
	ok, err = p.st.RequestCancel(bg(), id)
	require.NoError(t, err)
	require.False(t, ok, "a finished scan is not cancelled")
	_, err = p.st.CreateScan(bg(), scope, "manual", nil, t0)
	require.NoError(t, err, "the scope is free again")

	_, err = p.Owner.Exec(bg(), `UPDATE discovery_scopes SET deleted_at = $2 WHERE id = $1`, other, t0)
	require.NoError(t, err)
	_, err = p.st.CreateScan(bg(), other, "manual", nil, t0)
	require.ErrorIs(t, err, ErrScopeNotFound, "a deleted scope is not scanned")
}

// TestBeginScanReadsTheScope: the scope as stored, schedule and window included.
func TestBeginScanReadsTheScope(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab", "10.0.0.0/24", "web.example")
	id, err := p.st.CreateScan(bg(), scope, "schedule", nil, t0)
	require.NoError(t, err)
	st, err := p.st.BeginScan(bg(), id, t0, DefaultLease)
	require.NoError(t, err)
	require.Equal(t, ScanStart{Run: true, ScopeID: scope, StartedAt: t0, Scope: Scope{Name: "lab", Entries: []string{"10.0.0.0/24", "web.example"},
		Ports: []int{443, 8443}, SNINames: []string{"a.example"}, Exclusions: []string{"10.0.0.128/25"}, Enabled: true,
		Schedule: Schedule{Hours: 6, WindowStart: "22:00", WindowEnd: "04:30", TimeZone: "Europe/Istanbul"}, RatePerSec: 100, Concurrency: 8}}, st)
	_, err = Validate(st.Scope, Rules{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	require.NoError(t, err, "the stored scope validates as read")
	require.Equal(t, ScanRunning, p.scan(t, id).State)
	_, err = p.st.BeginScan(bg(), uuid.New(), t0, DefaultLease)
	require.ErrorIs(t, err, ErrScanNotFound)
}

// TestCrashRecovery (A5): a scan left running by a run that died is ended as interrupted when the handler runs again
// more than one lease after its start, idempotently; within the lease it is busy and left alone.
func TestCrashRecovery(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	id := p.running(t, scope, t0)
	d := Deps{Store: p.st, License: &gate{}, Clock: clockAt(t0.Add(10 * time.Second)), Lease: 45 * time.Second}
	require.ErrorIs(t, Run(bg(), d, id), ErrScanBusy)
	require.Equal(t, ScanRunning, p.scan(t, id).State)

	d.Clock = clockAt(t0.Add(2 * time.Minute))
	require.NoError(t, Run(bg(), d, id))
	r := p.scan(t, id)
	require.Equal(t, [2]string{ScanFailed, ReasonInterrupted}, [2]string{r.State, r.ErrorCode})
	require.Equal(t, t0.Add(2*time.Minute), r.Finished.UTC())

	d.Clock = clockAt(t0.Add(time.Hour))
	require.NoError(t, Run(bg(), d, id), "idempotent")
	require.Equal(t, r, p.scan(t, id))
	_, err := p.st.CreateScan(bg(), scope, "manual", nil, t0.Add(time.Hour))
	require.NoError(t, err, "the scope can be scanned again")
}

func TestReadRules(t *testing.T) {
	p := newPG(t)
	r, err := p.st.ReadRules(bg())
	require.NoError(t, err)
	require.Equal(t, RuleSettings{}, r, "absent rows: empty lists")
	require.NoError(t, settings.Set(bg(), p.App, SettingAllowedNetworks, []string{"10.0.0.0/8"}, t0))
	require.NoError(t, settings.Set(bg(), p.App, SettingExclusions, []string{"10.1.0.0/16", "10.2.0.1"}, t0))
	r, err = p.st.ReadRules(bg())
	require.NoError(t, err)
	require.Equal(t, RuleSettings{AllowedNetworks: []string{"10.0.0.0/8"}, GlobalExclusions: []string{"10.1.0.0/16", "10.2.0.1"}}, r)
	require.Error(t, decodeList([]byte(`{"not":"a list"}`), &r.AllowedNetworks))

	// A stored value that is not a list (only possible without the migration's CHECK): an error, and a scan scans nothing.
	_, err = p.Owner.Exec(bg(), `ALTER TABLE settings DROP CONSTRAINT settings_discovery_exclusions`)
	require.NoError(t, err)
	_, err = p.Owner.Exec(bg(), `UPDATE settings SET value = '{"not": "a list"}' WHERE key = $1`, SettingExclusions)
	require.NoError(t, err)
	_, err = p.st.ReadRules(bg())
	require.ErrorContains(t, err, "decode a discovery setting")
	scope := p.scope(t, "lab")
	id, err := p.st.CreateScan(bg(), scope, "manual", nil, t0)
	require.NoError(t, err)
	pol := counter()
	d := deps(nil, pol)
	d.Store, d.Clock = p.st, clockAt(t0)
	require.NoError(t, Run(bg(), d, id))
	require.Equal(t, [2]string{ScanFailed, ReasonEntryNotAllowed}, [2]string{p.scan(t, id).State, p.scan(t, id).ErrorCode})
	require.Empty(t, pol.dialed())
}

// TestScanWithoutAllowedNetworksScansNothing (ledger carry): with the real store, an absent setting and a stored empty
// list end the scan failed (entry_not_allowed) without a dial.
func TestScanWithoutAllowedNetworksScansNothing(t *testing.T) {
	for name, value := range map[string][]string{"absent": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			p := newPG(t)
			if value != nil {
				require.NoError(t, settings.Set(bg(), p.App, SettingAllowedNetworks, value, t0))
			}
			scope := p.scope(t, "lab")
			id, err := p.st.CreateScan(bg(), scope, "manual", nil, t0)
			require.NoError(t, err)
			pol := counter()
			d := deps(nil, pol)
			d.Store, d.Clock = p.st, clockAt(t0)
			require.NoError(t, Run(bg(), d, id))
			r := p.scan(t, id)
			require.Equal(t, [2]string{ScanFailed, ReasonEntryNotAllowed}, [2]string{r.State, r.ErrorCode})
			require.Empty(t, pol.dialed())
			require.Zero(t, p.count(t, `SELECT count(*) FROM discovery_endpoints`))
		})
	}
}

// fleetExpansion is the expansion of every fleet kind: one endpoint per server, the SNI server with each of its names
// and none, the many-SNI server with three of its names, and one excluded endpoint.
func fleetExpansion(t *testing.T, f *fakefleet.Fleet) *Expansion {
	x := &Expansion{}
	for _, s := range f.Servers() {
		ap := addrPort(t, s.Addr())
		names := []string{""}
		switch s.Kind() {
		case fakefleet.KindSNI:
			names = append(names, s.SNINames()...)
		case fakefleet.KindManySNI:
			names = s.SNINames()[:3]
		}
		for _, n := range names {
			x.Dial = append(x.Dial, Endpoint{Address: ap.Addr(), Port: ap.Port(), SNI: n})
		}
	}
	x.Excluded = []Endpoint{{Address: netip.MustParseAddr("10.66.0.1"), Port: 443, excluded: true}}
	x.Endpoints = len(x.Dial) + 1
	return x
}

// TestIngestEveryFleetKind runs a scan through the real store against every kind of the fleet and checks each row.
func TestIngestEveryFleetKind(t *testing.T) {
	p := newPG(t)
	require.NoError(t, settings.Set(bg(), p.App, SettingAllowedNetworks, []string{"10.0.0.0/8"}, t0))
	f := fleetOf(t, fakefleet.AllKinds...)
	scope := p.scope(t, "fleet")
	pol := counter("10.66.0.0/16")
	d := deps(nil, pol)
	d.Store = p.st // the real clock: the bucket spaces the connections
	x := fleetExpansion(t, f)
	d.expand = fixed(x, nil)
	scanOnce := func() uuid.UUID {
		id, err := p.st.CreateScan(bg(), scope, "manual", nil, time.Now())
		require.NoError(t, err)
		require.NoError(t, Run(bg(), d, id))
		settle(t, f)
		return id
	}
	id := scanOnce()
	r := p.scan(t, id)
	require.Equal(t, ScanDone, r.State)
	require.Equal(t, len(x.Dial)+1, r.Total)
	require.Equal(t, 1, r.Excluded)
	require.Equal(t, r.Total, r.Answered+r.Failed+r.Excluded)
	require.EqualValues(t, 1, f.Server(fakefleet.KindValid).Accepted())

	want := map[fakefleet.Kind][3]any{ // state, error code, chain length
		fakefleet.KindValid: {"present", "", 2}, fakefleet.KindExpired: {"present", "", 2}, fakefleet.KindNotYetValid: {"present", "", 2},
		fakefleet.KindSelfSigned: {"present", "", 1}, fakefleet.KindWrongOrder: {"present", "", 3}, fakefleet.KindMissingIntermediate: {"present", "", 1},
		fakefleet.KindSNI: {"present", "", 2}, fakefleet.KindTLS10: {"present", "", 2}, fakefleet.KindTLS12: {"present", "", 2},
		fakefleet.KindTLS13: {"present", "", 2}, fakefleet.KindRSAKeyExchange: {"present", "", 2}, fakefleet.KindSHA1: {"present", "", 2},
		fakefleet.KindManySNI: {"present", "", 2}, fakefleet.KindSlowLoris: {"unreachable", "timeout", 0},
		fakefleet.KindGiantChain: {"unreachable", "chain_too_large", 0}, fakefleet.KindHugeChain: {"unreachable", "chain_too_large", 0},
		fakefleet.KindReset: {"unreachable", "reset", 0}, fakefleet.KindPlainText: {"no_tls", "no_tls", 0},
		fakefleet.KindMalformed: {"malformed", "malformed", 0},
	}
	require.Len(t, want, len(fakefleet.AllKinds))
	for _, s := range f.Servers() {
		ap := addrPort(t, s.Addr())
		rows, err := ListEndpoints(bg(), p.App, EndpointFilter{ScopeID: scope, Limit: MaxPage})
		require.NoError(t, err)
		n := 0
		for _, e := range rows {
			if e.Address != ap.Addr() || e.Port != int(ap.Port()) {
				continue
			}
			n++
			w := want[s.Kind()]
			require.Equal(t, [3]any{w[0], w[1], w[2]}, [3]any{e.State, e.LastErrorCode, e.ChainLen}, "%s sni=%q", s.Kind(), e.SNI)
			if e.State != "present" {
				continue
			}
			chain := s.ChainFor(e.SNI)
			if chain == nil {
				chain = s.Chain()
			}
			require.Equal(t, fingerprint(chain[0]), e.Fingerprint, "%s sni=%q", s.Kind(), e.SNI)
			require.Equal(t, s.Kind() == fakefleet.KindTLS10, e.TLSVersion == "TLS 1.0", s.Kind())
			require.NotEmpty(t, e.Cipher)
		}
		wantN := 1
		if s.Kind() == fakefleet.KindSNI || s.Kind() == fakefleet.KindManySNI {
			wantN = 3
		}
		require.Equal(t, wantN, n, s.Kind())
	}
	// SNI: each name its own leaf, none the default one.
	sni := f.Server(fakefleet.KindSNI)
	ap := addrPort(t, sni.Addr())
	leaves := map[string]bool{}
	for _, n := range append([]string{""}, sni.SNINames()...) {
		e := p.endpoint(t, scope, Endpoint{Address: ap.Addr(), Port: ap.Port(), SNI: n})
		leaves[e.Fingerprint] = true
	}
	require.Len(t, leaves, 3)

	// Certificates: each leaf once with is_leaf, the shared fleet intermediate once without; PEM is the DER.
	var leafRows, interRows int
	rows, err := p.Owner.Query(bg(), `SELECT fingerprint_sha256, is_leaf, pem FROM discovery_certificates`)
	require.NoError(t, err)
	type certRowDB struct {
		FP   string
		Leaf bool
		PEM  string
	}
	certs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[certRowDB])
	require.NoError(t, err)
	for _, c := range certs {
		b, _ := pem.Decode([]byte(c.PEM))
		require.NotNil(t, b)
		_, err := x509.ParseCertificate(b.Bytes)
		require.NoError(t, err)
		require.Equal(t, c.FP, fingerprint(b.Bytes))
		if c.Leaf {
			leafRows++
		} else {
			interRows++
		}
	}
	require.Equal(t, 1, p.count(t, `SELECT count(*) FROM discovery_certificates WHERE fingerprint_sha256 = $1 AND NOT is_leaf`, fingerprint(f.CA().Intermediate.Raw)))
	require.Equal(t, 1, p.count(t, `SELECT count(*) FROM discovery_certificates WHERE fingerprint_sha256 = $1 AND NOT is_leaf`, fingerprint(f.Root().Raw)), "wrong-order presents the root")
	require.Equal(t, r.CertificatesNew, leafRows+interRows)
	ex := p.endpoint(t, scope, x.Excluded[0])
	require.Equal(t, [2]string{"excluded", "policy"}, [2]string{ex.State, ex.Code})

	// Scanning again changes no row count (dedup on the keys, sni '' included).
	counts := func() [3]int {
		return [3]int{p.count(t, `SELECT count(*) FROM discovery_endpoints`), p.count(t, `SELECT count(*) FROM discovery_certificates`),
			p.count(t, `SELECT count(*) FROM discovery_endpoints WHERE sni = ''`)}
	}
	before := counts()
	f.ClearLog()
	id2 := scanOnce()
	require.Equal(t, before, counts())
	require.Zero(t, p.scan(t, id2).CertificatesNew)
	valid := addrPort(t, f.Addr(fakefleet.KindValid))
	e := p.endpoint(t, scope, Endpoint{Address: valid.Addr(), Port: valid.Port()})
	require.Empty(t, e.Previous, "the same leaf is no rotation")
	reset := addrPort(t, f.Addr(fakefleet.KindReset))
	require.Equal(t, 2, p.endpoint(t, scope, Endpoint{Address: reset.Addr(), Port: reset.Port()}).Missed)
	require.Zero(t, p.endpoint(t, scope, Endpoint{Address: valid.Addr(), Port: valid.Port()}).Missed)
}

// TestMissesGoneAndRotation: misses count only attempted endpoints that did not answer; three make it gone; a gone
// endpoint that still does not answer stays gone with its gone_since; a scan in which nothing answered while the scope
// had answers counts nothing; an answer brings it back; previous_fingerprints keeps the last 5 leaves.
func TestMissesGoneAndRotation(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	a, b := ep("10.0.0.1", 443, ""), ep("10.0.0.2", 443, "")
	var leaves [][]byte
	for i := range 7 {
		leaves = append(leaves, testCert(t, "a"+strconv.Itoa(i)+".example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0)))
	}
	refused := func(e Endpoint) Result { return Result{Endpoint: e, Code: tlsprobe.CodeRefused} }
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Hour) }

	for i := range 3 {
		p.ingestScan(t, scope, at(i), presented(t, a, leaves[0]), refused(b))
		got := p.endpoint(t, scope, b)
		require.Equal(t, i+1, got.Missed)
		require.Equal(t, i == 2, got.State == "gone", i)
	}
	gone := p.endpoint(t, scope, b)
	require.Equal(t, at(2), gone.GoneSince.UTC())
	require.Equal(t, "refused", gone.Code)
	p.ingestScan(t, scope, at(3), presented(t, a, leaves[0]), Result{Endpoint: b, Code: tlsprobe.CodeTimeout})
	require.Equal(t, endpointState{State: "gone", Code: "timeout", Missed: 3, Previous: []string{}, Chain: []string{}, GoneSince: gone.GoneSince},
		p.endpoint(t, scope, b), "still gone, since the same time")

	// Alice's network is down: nothing answers; the scope had answers, so nothing is counted.
	id := p.ingestScan(t, scope, at(4), refused(a), refused(b))
	require.Zero(t, p.scan(t, id).Answered)
	got := p.endpoint(t, scope, a)
	require.Equal(t, [3]any{"unreachable", "refused", 0}, [3]any{got.State, got.Code, got.Missed})
	require.Equal(t, fingerprint(leaves[0]), got.Fingerprint, "the last leaf is kept")

	// Back: present, misses cleared, gone no more.
	p.ingestScan(t, scope, at(5), presented(t, a, leaves[0]), presented(t, b, leaves[1]))
	back := p.endpoint(t, scope, b)
	require.Equal(t, [3]any{"present", 0, (*time.Time)(nil)}, [3]any{back.State, back.Missed, back.GoneSince})
	require.Equal(t, at(5), back.LastSeen.UTC())

	// Rotations: the ring keeps the last five, newest first.
	for i := 1; i < 7; i++ {
		p.ingestScan(t, scope, at(5+i), presented(t, a, leaves[i]))
	}
	rot := p.endpoint(t, scope, a)
	require.Equal(t, fingerprint(leaves[6]), rot.Fingerprint)
	require.Equal(t, []string{fingerprint(leaves[5]), fingerprint(leaves[4]), fingerprint(leaves[3]), fingerprint(leaves[2]), fingerprint(leaves[1])}, rot.Previous)

	// A scope that never had an answer counts its misses.
	lone := p.scope(t, "lone")
	for i := range 3 {
		p.ingestScan(t, lone, at(20+i), refused(b))
	}
	require.Equal(t, "gone", p.endpoint(t, lone, b).State)

	// Not attempted (excluded) is no miss; an answer without a stored certificate clears the misses.
	third := p.scope(t, "third")
	p.ingestScan(t, third, at(30), refused(a), Result{Endpoint: b, Code: tlsprobe.CodePolicy}, presented(t, ep("10.0.0.3", 443, ""), leaves[0]))
	require.Equal(t, 1, p.endpoint(t, third, a).Missed)
	require.Zero(t, p.endpoint(t, third, b).Missed)
	p.ingestScan(t, third, at(31), Result{Endpoint: a, Code: tlsprobe.CodeChainTooLarge}, presented(t, ep("10.0.0.3", 443, ""), leaves[0]))
	require.Equal(t, [3]any{"unreachable", "chain_too_large", 0}, [3]any{p.endpoint(t, third, a).State, p.endpoint(t, third, a).Code, p.endpoint(t, third, a).Missed})
}

// TestEndpointsThatLeftTheScopeAreGone: an endpoint not in the new expansion is gone at once; those of a host name
// that did not resolve this time are left alone.
func TestEndpointsThatLeftTheScopeAreGone(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	leaf := testCert(t, "x.example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0))
	a, b := ep("10.0.0.1", 443, ""), ep("10.0.0.2", 443, "")
	named := Endpoint{Address: netip.MustParseAddr("10.0.0.9"), Port: 443, SNI: "web.example", Host: "web.example"}
	p.ingestScan(t, scope, t0, presented(t, a, leaf), presented(t, b, leaf), presented(t, named, leaf))
	id := p.running(t, scope, t0.Add(time.Hour))
	require.NoError(t, p.st.PrepareScan(bg(), id, scope, &Expansion{Dial: []Endpoint{a}, Unresolved: []string{"web.example"}, Endpoints: 1}, t0.Add(time.Hour)))
	require.Equal(t, "present", p.endpoint(t, scope, a).State)
	gone := p.endpoint(t, scope, b)
	require.Equal(t, "gone", gone.State)
	require.Equal(t, t0.Add(time.Hour), gone.GoneSince.UTC())
	require.Equal(t, "present", p.endpoint(t, scope, named).State, "its name did not resolve: nothing is known")
	require.Equal(t, 1, p.scan(t, id).Total)
}

// TestNewCertificateCaps (A4): at most 1,000 new fingerprints per scan and 5,000 per scope per day; beyond them only
// cert_churn grows, a new endpoint with such a leaf is not created, a stored one keeps its state and records the scan.
func TestNewCertificateCaps(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	var results []Result
	for i := range 1200 {
		der := testCert(t, "c"+strconv.Itoa(i)+".example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0))
		results = append(results, presented(t, Endpoint{Address: netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), Port: 443}, der))
	}
	id := p.ingestScan(t, scope, t0, results...)
	r := p.scan(t, id)
	require.Equal(t, [4]int{1000, 200, 1200, 0}, [4]int{r.CertificatesNew, r.CertChurn, r.Answered, r.Failed})
	require.Equal(t, 1000, p.count(t, `SELECT count(*) FROM discovery_certificates`))
	require.Equal(t, 1000, p.count(t, `SELECT count(*) FROM discovery_endpoints`))

	// A stored endpoint rotates to a leaf over the cap: state and leaf kept, the scan recorded.
	old := p.endpoint(t, scope, results[0].Endpoint)
	_, err := p.Owner.Exec(bg(), `INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, finished_at, certificates_new)
VALUES ($1, $2, 'schedule', 'done', $3, $3, $3, 5000)`, uuid.New(), scope, t0.Add(time.Minute))
	require.NoError(t, err)
	fresh := testCert(t, "fresh.example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0))
	id2 := p.ingestScan(t, scope, t0.Add(2*time.Hour), presented(t, results[0].Endpoint, fresh))
	r2 := p.scan(t, id2)
	require.Equal(t, [2]int{0, 1}, [2]int{r2.CertificatesNew, r2.CertChurn}, "the day's 5,000 are used up")
	now := p.endpoint(t, scope, results[0].Endpoint)
	require.Equal(t, old.Fingerprint, now.Fingerprint)
	require.Zero(t, p.count(t, `SELECT count(*) FROM discovery_endpoints WHERE last_scan_id = $1`, id2), "no miss can be counted for it")
	require.Equal(t, 1, p.count(t, `SELECT count(*) FROM discovery_endpoints WHERE last_scanned_at = $1`, t0.Add(2*time.Hour)), "it was scanned")

	// A day later the window has moved on.
	id3 := p.ingestScan(t, scope, t0.Add(26*time.Hour), presented(t, results[0].Endpoint, fresh))
	require.Equal(t, 1, p.scan(t, id3).CertificatesNew)
	require.Equal(t, fingerprint(fresh), p.endpoint(t, scope, results[0].Endpoint).Fingerprint)
}

// TestAnswerOverTheCapsIsAnAnswer (review fix 1): an endpoint that answers with a leaf the caps keep out answered: an
// unreachable one has its misses cleared and is present again (with its stored leaf), a gone one comes back, and the
// scan's end counts no miss for either.
func TestAnswerOverTheCapsIsAnAnswer(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	a, b, anchor := ep("10.0.0.1", 443, ""), ep("10.0.0.2", 443, ""), ep("10.0.0.3", 443, "")
	leaf := testCert(t, "old.example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0))
	refused := func(e Endpoint) Result { return Result{Endpoint: e, Code: tlsprobe.CodeRefused} }
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Hour) }
	p.ingestScan(t, scope, at(0), presented(t, a, leaf), presented(t, b, leaf), presented(t, anchor, leaf))
	p.ingestScan(t, scope, at(1), refused(a), refused(b), presented(t, anchor, leaf))
	p.ingestScan(t, scope, at(2), presented(t, a, leaf), refused(b), presented(t, anchor, leaf))
	p.ingestScan(t, scope, at(3), refused(a), refused(b), presented(t, anchor, leaf))
	require.Equal(t, [2]any{"unreachable", 1}, [2]any{p.endpoint(t, scope, a).State, p.endpoint(t, scope, a).Missed})
	require.Equal(t, "gone", p.endpoint(t, scope, b).State)

	// The day's budget is used up: the new leaves are only counted.
	_, err := p.Owner.Exec(bg(), `INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, finished_at, certificates_new)
VALUES ($1, $2, 'schedule', 'done', $3, $3, $3, 5000)`, uuid.New(), scope, at(3).Add(time.Minute))
	require.NoError(t, err)
	over := func(cn string) []byte { return testCert(t, cn, t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0)) }
	id := p.ingestScan(t, scope, at(4), presented(t, a, over("a-new.example")), presented(t, b, over("b-new.example")), presented(t, anchor, leaf))
	require.Equal(t, 2, p.scan(t, id).CertChurn)
	for _, e := range []Endpoint{a, b} {
		got := p.endpoint(t, scope, e)
		require.Equal(t, endpointState{State: "present", Fingerprint: fingerprint(leaf), Previous: []string{}, Chain: []string{}, LastSeen: got.LastSeen},
			got, e.Address)
	}
}

// TestConcurrentIngestsSharingCertificates (review fix 2): two scans storing the same new certificates in opposite
// orders at the same time both succeed (certificates are written in fingerprint order; a deadlock is retried once).
func TestConcurrentIngestsSharingCertificates(t *testing.T) {
	p := newPG(t)
	var shared [][]byte
	for i := range 40 {
		shared = append(shared, testCert(t, "shared"+strconv.Itoa(i)+".example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0)))
	}
	for round := range 5 {
		_, err := p.Owner.Exec(bg(), `DELETE FROM discovery_endpoints`)
		require.NoError(t, err)
		_, err = p.Owner.Exec(bg(), `DELETE FROM discovery_certificates`)
		require.NoError(t, err)
		var batches [2]Batch
		for k := range 2 {
			scope := p.scope(t, "s"+strconv.Itoa(round)+"-"+strconv.Itoa(k))
			id := p.running(t, scope, t0)
			b := Batch{ScanID: id, ScopeID: scope, Now: t0}
			for i := range shared {
				j := i
				if k == 1 {
					j = len(shared) - 1 - i
				}
				b.Results = append(b.Results, presented(t, Endpoint{Address: netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), Port: 443}, shared[j]))
			}
			require.NoError(t, p.st.PrepareScan(bg(), id, scope, &Expansion{Endpoints: len(b.Results)}, t0))
			batches[k] = b
		}
		errs := make(chan error, 2)
		start := make(chan struct{})
		for _, b := range batches {
			go func() {
				<-start
				errs <- p.st.Ingest(bg(), b)
			}()
		}
		close(start)
		require.NoError(t, <-errs)
		require.NoError(t, <-errs)
		require.Equal(t, len(shared), p.count(t, `SELECT count(*) FROM discovery_certificates`))
	}
	var pe pgconn.PgError
	pe.Code = "40P01"
	require.True(t, retryable(fmt.Errorf("wrapped: %w", &pe)))
	pe.Code = "23505"
	require.False(t, retryable(&pe))

	// A batch that deadlocks is retried once: the second attempt stores it.
	scope := p.scope(t, "retry")
	id := p.running(t, scope, t0)
	require.NoError(t, p.st.PrepareScan(bg(), id, scope, &Expansion{Endpoints: 2}, t0))
	fp := &faultPool{pool: p.App, fail: 4, err: &pgconn.PgError{Code: "40P01"}} // begin, counters, existing, certificates
	b := Batch{ScanID: id, ScopeID: scope, Now: t0, Results: []Result{presented(t, ep("10.9.0.1", 443, ""), shared[0])}}
	require.NoError(t, NewStore(fp).Ingest(bg(), b))
	require.Equal(t, 1, p.count(t, `SELECT endpoints_answered FROM discovery_scans WHERE id = $1`, id))
	fp.fail, fp.calls, fp.err = 4, 0, &pgconn.PgError{Code: "40001"}
	b.Results[0].Endpoint = ep("10.9.0.2", 443, "")
	require.NoError(t, NewStore(fp).Ingest(bg(), b))
	require.Equal(t, 2, p.count(t, `SELECT endpoints_answered FROM discovery_scans WHERE id = $1`, id))
}

// TestRetention deletes only what has expired, only discovery rows, with or without the license (class Always: Retain
// takes no license gate at all, so a locked installation cleans up too).
func TestRetention(t *testing.T) {
	p := newPG(t)
	now := t0.AddDate(0, 6, 0)
	target, err := seed.Target(bg(), p.Owner, "srv", "linux", "ok", nil)
	require.NoError(t, err)
	_, err = seed.Certificate(bg(), p.Owner, "managed", now.AddDate(0, 1, 0), []uuid.UUID{target})
	require.NoError(t, err)
	scope := p.scope(t, "lab")
	deleted := p.scope(t, "deleted")
	mk := func(cn string, at time.Time) []byte {
		return testCert(t, cn, at.AddDate(0, -1, 0), at.AddDate(1, 0, 0))
	}
	leafOld, inter, orphanOld, orphanNew := mk("leaf-old", t0), mk("inter", t0), mk("orphan-old", t0), mk("orphan-new", now)

	// gone 100 days ago, gone 10 days ago, present; and the deleted scope's present endpoint
	goneOld, goneNew, live := ep("10.0.0.1", 443, ""), ep("10.0.0.2", 443, ""), ep("10.0.0.3", 443, "")
	p.ingestScan(t, scope, t0, presented(t, goneOld, leafOld), presented(t, goneNew, mk("gone-new", t0)), presented(t, live, leafOld, inter))
	p.ingestScan(t, deleted, t0, presented(t, live, mk("deleted-scope", t0)))
	orph := p.scope(t, "orphans")
	p.ingestScan(t, orph, now.AddDate(0, 0, -8), presented(t, ep("10.0.0.9", 443, ""), orphanOld))
	p.ingestScan(t, orph, now.AddDate(0, 0, -1), presented(t, ep("10.0.0.10", 443, ""), orphanNew))
	_, err = p.Owner.Exec(bg(), `DELETE FROM discovery_endpoints WHERE scope_id = $1`, orph)
	require.NoError(t, err) // their certificates are orphans now
	for e, at := range map[Endpoint]time.Time{goneOld: now.AddDate(0, 0, -100), goneNew: now.AddDate(0, 0, -10)} {
		_, err := p.Owner.Exec(bg(), `UPDATE discovery_endpoints SET state = 'gone', gone_since = $3 WHERE scope_id = $1 AND address = $2`, scope, e.Address, at)
		require.NoError(t, err)
	}
	_, err = p.Owner.Exec(bg(), `UPDATE discovery_scopes SET deleted_at = $2 WHERE id = $1`, deleted, now)
	require.NoError(t, err)
	stale := p.running(t, p.scope(t, "stale"), now.Add(-StaleScanAfter-time.Minute))
	fresh := p.running(t, p.scope(t, "fresh"), now.Add(-time.Hour))
	for i := range KeepScans + 5 {
		_, err := p.Owner.Exec(bg(), `INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, finished_at)
VALUES ($1, $2, 'schedule', 'done', $3, $3, $3)`, uuid.New(), deleted, now.Add(-48*time.Hour-time.Duration(i)*time.Minute))
		require.NoError(t, err)
	}

	others := otherTableCounts(t, p)
	st, err := p.st.Retain(bg(), now)
	require.NoError(t, err)
	require.Equal(t, RetentionStats{Interrupted: 1, Endpoints: 2, Certificates: 2, Scans: 6}, st, "the deleted scope's certificate is an orphan too")
	require.Equal(t, others, otherTableCounts(t, p), "nothing outside discovery_* changes")
	require.Equal(t, 0, p.count(t, `SELECT count(*) FROM discovery_endpoints WHERE address = '10.0.0.1'`))
	require.Equal(t, 1, p.count(t, `SELECT count(*) FROM discovery_endpoints WHERE address = '10.0.0.2'`), "gone 10 days: kept (90)")
	require.Equal(t, 0, p.count(t, `SELECT count(*) FROM discovery_endpoints WHERE scope_id = $1`, deleted))
	require.Equal(t, 0, p.count(t, `SELECT count(*) FROM discovery_certificates WHERE fingerprint_sha256 = $1`, fingerprint(orphanOld)))
	require.Equal(t, 1, p.count(t, `SELECT count(*) FROM discovery_certificates WHERE fingerprint_sha256 = $1`, fingerprint(orphanNew)), "seen a day ago")
	require.Equal(t, 1, p.count(t, `SELECT count(*) FROM discovery_certificates WHERE fingerprint_sha256 = $1`, fingerprint(inter)), "in a chain")
	require.Equal(t, [2]string{ScanFailed, ReasonInterrupted}, [2]string{p.scan(t, stale).State, p.scan(t, stale).ErrorCode})
	require.Equal(t, ScanRunning, p.scan(t, fresh).State)
	require.Equal(t, KeepScans, p.count(t, `SELECT count(*) FROM discovery_scans WHERE scope_id = $1 AND state = 'done'`, deleted))

	// A shorter retention setting; a second run is idempotent.
	require.NoError(t, settings.Set(bg(), p.App, SettingRetentionDays, 7, now))
	st, err = p.st.Retain(bg(), now)
	require.NoError(t, err)
	require.Equal(t, RetentionStats{Endpoints: 1, Certificates: 1}, st, "gone 10 days, retention 7; its certificate is an orphan")
	st, err = p.st.Retain(bg(), now)
	require.NoError(t, err)
	require.Equal(t, RetentionStats{}, st)
}

// otherTableCounts counts the rows of every table that is not a discovery table.
func otherTableCounts(t *testing.T, p *pg) map[string]int {
	t.Helper()
	rows, err := p.Owner.Query(bg(), `SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename NOT LIKE 'discovery\_%'`)
	require.NoError(t, err)
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Greater(t, len(names), 20)
	out := map[string]int{}
	for _, n := range names {
		out[n] = p.count(t, `SELECT count(*) FROM `+pgx.Identifier{n}.Sanitize())
	}
	require.Positive(t, out["targets"])
	require.Positive(t, out["certificates"])
	return out
}

// TestDiscoveryNeverCountsTowardLicense (design decision 4): 5,000 discovered endpoints through the real ingest path
// leave the license's target count (inventory.Counter, what max_targets is checked against) and the targets table as
// they were.
func TestDiscoveryNeverCountsTowardLicense(t *testing.T) {
	p := newPG(t)
	for _, n := range []string{"one", "two"} {
		_, err := seed.Target(bg(), p.Owner, n, "linux", "ok", nil)
		require.NoError(t, err)
	}
	countTargets := func() [2]int {
		n, err := inventory.Counter{}.CountTargets(bg(), p.App)
		require.NoError(t, err)
		return [2]int{n, p.count(t, `SELECT count(*) FROM targets`)}
	}
	before := countTargets()
	require.Equal(t, [2]int{2, 2}, before)
	scope := p.scope(t, "big", "10.0.0.0/20")
	var certs [][]byte
	for i := range 500 {
		certs = append(certs, testCert(t, "s"+strconv.Itoa(i)+".example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0)))
	}
	var results []Result
	for i := range 5000 {
		results = append(results, presented(t, Endpoint{Address: netip.AddrFrom4([4]byte{10, 0, byte(i / 250), byte(i % 250)}), Port: 443}, certs[i%500]))
	}
	p.ingestScan(t, scope, t0, results...)
	require.Equal(t, 5000, p.count(t, `SELECT count(*) FROM discovery_endpoints`))
	require.Equal(t, before, countTargets())
}

// TestLinking: certificates are managed (in the inventory and on a live location of a live target), known (in the
// inventory, not on a live location) or unmanaged (not in the inventory: A10); endpoints link to the live target whose
// host is their address or host name, case-insensitively. Both lists page by keyset.
func TestLinking(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	at := t0.AddDate(0, 1, 0)
	mk := func(cn string, i int) []byte { return testCert(t, cn, t0.AddDate(0, -1, 0), at.AddDate(0, 0, i)) }
	unmanaged, managed, known, deadTarget := mk("unmanaged", 1), mk("managed", 2), mk("known", 3), mk("dead", 4)
	web := Endpoint{Address: netip.MustParseAddr("10.0.0.7"), Port: 443, SNI: "web.example", Host: "web.example"}
	p.ingestScan(t, scope, t0, presented(t, ep("10.0.0.5", 443, ""), unmanaged), presented(t, ep("10.0.0.6", 443, ""), managed),
		presented(t, web, known), presented(t, ep("10.0.0.8", 443, ""), deadTarget), presented(t, ep("10.0.0.9", 443, ""), unmanaged))

	// 10.0.0.9 stops answering: it still last presented the unmanaged leaf, but presents it no more.
	_, err := p.Owner.Exec(bg(), `UPDATE discovery_endpoints SET state = 'unreachable', last_error_code = 'timeout' WHERE address = '10.0.0.9'`)
	require.NoError(t, err)
	byIP, err := seed.Target(bg(), p.Owner, "by-ip", "linux", "ok", nil)
	require.NoError(t, err)
	byName, err := seed.Target(bg(), p.Owner, "by-name", "nginx", "ok", nil)
	require.NoError(t, err)
	dead, err := seed.Target(bg(), p.Owner, "dead", "linux", "ok", nil)
	require.NoError(t, err)
	for id, host := range map[uuid.UUID]string{byIP: "10.0.0.5", byName: "WEB.Example", dead: "10.0.0.8"} {
		_, err := p.Owner.Exec(bg(), `UPDATE targets SET config = jsonb_set(config, '{host}', to_jsonb($2::text)) WHERE id = $1`, id, host)
		require.NoError(t, err)
	}
	managedID := inventoryCert(t, p, managed, &byIP)
	knownID := inventoryCert(t, p, known, nil)
	deadID := inventoryCert(t, p, deadTarget, &dead)
	_, err = p.Owner.Exec(bg(), `UPDATE targets SET deleted_at = now() WHERE id = $1`, dead)
	require.NoError(t, err)

	all, err := ListCertificates(bg(), p.App, CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, all, 4)
	type got struct {
		FP, Status        string
		ID                uuid.NullUUID
		Endpoints, SeenOn int
	}
	var gs []got
	for _, c := range all {
		gs = append(gs, got{c.Fingerprint, c.Status, c.ManagedID, c.Endpoints, c.SeenOn})
	}
	require.Equal(t, []got{
		{fingerprint(unmanaged), StatusUnmanaged, uuid.NullUUID{}, 1, 2},
		{fingerprint(managed), StatusManaged, uuid.NullUUID{UUID: managedID, Valid: true}, 1, 1},
		{fingerprint(known), StatusKnown, uuid.NullUUID{UUID: knownID, Valid: true}, 1, 1},
		{fingerprint(deadTarget), StatusKnown, uuid.NullUUID{UUID: deadID, Valid: true}, 1, 1},
	}, gs, "soonest expiry first; a deleted target's location is not live; presented now vs last seen on")

	page, err := ListCertificates(bg(), p.App, CertificateFilter{Limit: 2})
	require.NoError(t, err)
	require.Len(t, page, 2)
	rest, err := ListCertificates(bg(), p.App, CertificateFilter{After: &CertificateCursor{NotAfter: page[1].NotAfter, Fingerprint: page[1].Fingerprint}})
	require.NoError(t, err)
	require.Equal(t, all[2:], rest)
	only, err := ListCertificates(bg(), p.App, CertificateFilter{Status: StatusKnown})
	require.NoError(t, err)
	require.Len(t, only, 2)
	one, err := ListCertificates(bg(), p.App, CertificateFilter{Fingerprint: fingerprint(managed), ScopeID: scope})
	require.NoError(t, err)
	require.Equal(t, all[1:2], one)
	none, err := ListCertificates(bg(), p.App, CertificateFilter{ScopeID: uuid.New()})
	require.NoError(t, err)
	require.Empty(t, none)

	eps, err := ListEndpoints(bg(), p.App, EndpointFilter{ScopeID: scope})
	require.NoError(t, err)
	require.Len(t, eps, 5)
	links := map[string]string{}
	for _, e := range eps {
		links[e.Address.String()] = e.TargetName
		require.Equal(t, e.TargetName != "", e.TargetID.Valid)
		require.Equal(t, 1, e.ChainLen)
	}
	require.Equal(t, map[string]string{"10.0.0.5": "by-ip", "10.0.0.6": "", "10.0.0.7": "by-name", "10.0.0.8": "", "10.0.0.9": ""}, links)
	first, err := ListEndpoints(bg(), p.App, EndpointFilter{Limit: 3})
	require.NoError(t, err)
	last := first[2]
	next, err := ListEndpoints(bg(), p.App, EndpointFilter{After: &EndpointCursor{Address: last.Address, Port: last.Port, SNI: last.SNI, ID: last.ID}})
	require.NoError(t, err)
	require.Equal(t, eps, append(first, next...))
	byFP, err := ListEndpoints(bg(), p.App, EndpointFilter{Fingerprint: fingerprint(unmanaged)})
	require.NoError(t, err)
	require.Len(t, byFP, 2)

	// Inside a scope the keyset is the unique key: a second scope with the same address does not interleave.
	other := p.scope(t, "other")
	p.ingestScan(t, other, t0, presented(t, ep("10.0.0.5", 443, ""), unmanaged))
	page1, err := ListEndpoints(bg(), p.App, EndpointFilter{ScopeID: scope, Limit: 2})
	require.NoError(t, err)
	c := page1[1]
	page2, err := ListEndpoints(bg(), p.App, EndpointFilter{ScopeID: scope, After: &EndpointCursor{Address: c.Address, Port: c.Port, SNI: c.SNI}})
	require.NoError(t, err)
	require.Equal(t, eps, append(page1, page2...))
	both, err := ListEndpoints(bg(), p.App, EndpointFilter{})
	require.NoError(t, err)
	require.Len(t, both, 6)
}

// inventoryCert inserts a managed certificate with der's fingerprint, on a live location of target when given.
func inventoryCert(t *testing.T, p *pg, der []byte, target *uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := p.Owner.Exec(bg(), `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
VALUES ($1, $2, 'cn', now() - interval '1 day', now() + interval '1 day', 'ecdsa', $3, '', 'uploaded', now(), now(), now())`,
		id, fingerprint(der), seed.Hex(id.String()))
	require.NoError(t, err)
	if target != nil {
		_, err = p.Owner.Exec(bg(), `INSERT INTO certificate_locations (id, target_id, kind, cert_path, certificate_id, supported, first_seen_at, last_seen_at)
VALUES ($1, $2, 'nginx_file', $3, $4, true, now(), now())`, uuid.New(), *target, "/etc/ssl/"+id.String(), id)
		require.NoError(t, err)
	}
	return id
}

func clockAt(at time.Time) clock.Clock { return clock.NewFake(at) }

// errFault is the error of an injected failure.
var errFault = errors.New("injected database failure")

// faultPool fails its fail-th call (Begin, Exec, Query, QueryRow and, inside a transaction, Commit).
type faultPool struct {
	pool  *pgxpool.Pool
	fail  int
	calls int
	err   error // the failure (nil: errFault)
}

func (f *faultPool) failure() error {
	if f.err != nil {
		return f.err
	}
	return errFault
}

func (f *faultPool) hit() bool { f.calls++; return f.calls == f.fail }

func (f *faultPool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if f.hit() {
		return pgconn.CommandTag{}, errFault
	}
	return f.pool.Exec(ctx, sql, args...)
}

func (f *faultPool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if f.hit() {
		return nil, errFault
	}
	return f.pool.Query(ctx, sql, args...)
}

func (f *faultPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if f.hit() {
		return errRow{}
	}
	return f.pool.QueryRow(ctx, sql, args...)
}

func (f *faultPool) Begin(ctx context.Context) (pgx.Tx, error) {
	if f.hit() {
		return nil, errFault
	}
	tx, err := f.pool.Begin(ctx)
	return &faultTx{Tx: tx, f: f}, err
}

type faultTx struct {
	pgx.Tx
	f *faultPool
}

func (t *faultTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if t.f.hit() {
		return pgconn.CommandTag{}, t.f.failure()
	}
	return t.Tx.Exec(ctx, sql, args...)
}

func (t *faultTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if t.f.hit() {
		return nil, errFault
	}
	return t.Tx.Query(ctx, sql, args...)
}

func (t *faultTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if t.f.hit() {
		return errRow{}
	}
	return t.Tx.QueryRow(ctx, sql, args...)
}

func (t *faultTx) Commit(ctx context.Context) error {
	if t.f.hit() {
		_ = t.Rollback(ctx)
		return errFault
	}
	return t.Tx.Commit(ctx)
}

type errRow struct{}

func (errRow) Scan(...any) error { return errFault }

// TestEveryDatabaseFailureIsReturned fails each database call of every store operation in turn: each failure is
// returned (wrapped), nothing panics, and the operation succeeds once no call fails.
func TestEveryDatabaseFailureIsReturned(t *testing.T) {
	p := newPG(t)
	scope := p.scope(t, "lab")
	leaf := testCert(t, "x.example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0))
	over := testCert(t, "over.example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0))
	stored := p.ingestScan(t, scope, t0, presented(t, ep("10.0.0.1", 443, ""), leaf))
	_ = stored
	_, err := p.Owner.Exec(bg(), `INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, finished_at, certificates_new)
VALUES ($1, $2, 'schedule', 'done', $3, $3, $3, 4999)`, uuid.New(), scope, t0.Add(time.Minute))
	require.NoError(t, err)
	fp := &faultPool{pool: p.App}
	st := NewStore(fp)
	ops := map[string]func(n int) error{
		"create": func(int) error {
			id, err := st.CreateScan(bg(), scope, "manual", nil, t0.Add(time.Hour))
			if err == nil {
				return p.st.FinishScan(bg(), Finish{ScanID: id, ScopeID: scope, Now: t0.Add(time.Hour), State: ScanCancelled})
			}
			return err
		},
		"cancel": func(int) error { _, err := st.RequestCancel(bg(), uuid.New()); return err },
		"rules":  func(int) error { _, err := st.ReadRules(bg()); return err },
		"flag":   func(int) error { _, err := st.CancelRequested(bg(), stored); return err },
		"lists": func(int) error {
			_, err1 := ListCertificates(bg(), fp, CertificateFilter{})
			if err1 != nil {
				return err1
			}
			_, err2 := ListEndpoints(bg(), fp, EndpointFilter{})
			return err2
		},
		"retain": func(int) error { _, err := st.Retain(bg(), t0); return err },
	}
	for name, op := range ops {
		failures := 0
		for n := 1; ; n++ {
			fp.fail, fp.calls = n, 0
			err := op(n)
			if fp.calls < n {
				require.NoError(t, err, name)
				break
			}
			require.ErrorIs(t, err, errFault, "%s call %d", name, n)
			failures++
		}
		require.Positive(t, failures, name)
	}
	// The scan lifecycle: begin (queued, running within and past the lease), prepare, ingest (new, stored, over the
	// caps, a stored endpoint over the caps), finish.
	life := func() error {
		id, err := p.st.CreateScan(bg(), scope, "manual", nil, t0.Add(2*time.Hour))
		if err != nil {
			return err
		}
		defer func() {
			_ = p.st.FinishScan(bg(), Finish{ScanID: id, ScopeID: scope, Now: t0.Add(3 * time.Hour), State: ScanCancelled})
		}()
		if _, err := st.BeginScan(bg(), id, t0.Add(2*time.Hour), DefaultLease); err != nil {
			return err
		}
		x := &Expansion{Dial: []Endpoint{ep("10.0.0.1", 443, ""), ep("10.0.0.2", 443, ""), ep("10.0.0.3", 443, "")}, Endpoints: 3}
		if err := st.PrepareScan(bg(), id, scope, x, t0.Add(2*time.Hour)); err != nil {
			return err
		}
		fresh := testCert(t, "fresh.example", t0.AddDate(0, -1, 0), t0.AddDate(1, 0, 0))
		b := Batch{ScanID: id, ScopeID: scope, Now: t0.Add(2 * time.Hour), Results: []Result{presented(t, ep("10.0.0.2", 443, ""), fresh, leaf),
			presented(t, ep("10.0.0.1", 443, ""), over), presented(t, ep("10.0.0.3", 443, ""), leaf)}}
		if err := st.Ingest(bg(), b); err != nil {
			return err
		}
		return st.FinishScan(bg(), Finish{ScanID: id, ScopeID: scope, Now: t0.Add(2 * time.Hour), State: ScanDone, Probed: true})
	}
	failures := 0
	for n := 1; ; n++ {
		fp.fail, fp.calls = n, 0
		err := life()
		if fp.calls < n {
			require.NoError(t, err)
			break
		}
		require.ErrorIs(t, err, errFault, "call %d", n)
		failures++
	}
	require.GreaterOrEqual(t, failures, 12)
	require.Equal(t, 2, p.count(t, `SELECT cert_churn FROM discovery_scans WHERE state = 'done' AND endpoints_answered = 3`), "the leaves over the cap were only counted")
	// A running scan within its lease, and the interrupted end.
	id := p.running(t, scope, t0.Add(4*time.Hour))
	for _, now := range []time.Time{t0.Add(4 * time.Hour), t0.Add(5 * time.Hour)} {
		for n := 1; ; n++ {
			fp.fail, fp.calls = n, 0
			_, err := st.BeginScan(bg(), id, now, DefaultLease)
			if fp.calls < n {
				break
			}
			require.ErrorIs(t, err, errFault)
		}
	}
	require.Equal(t, ScanFailed, p.scan(t, id).State)
	// Ingest refuses a scan that is not running.
	require.ErrorIs(t, p.st.Ingest(bg(), Batch{ScanID: id, ScopeID: scope, Now: t0}), ErrScanNotRunning)
}
