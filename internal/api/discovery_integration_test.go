//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
	"alice/internal/testutil/fakefleet"
	"alice/internal/testutil/seed"
)

// Network discovery over HTTP (plan 2026-10-13-network-discovery, Task 9): the real services, PostgreSQL, the
// netdisco.scan job run by the stack's runner, and a fake TLS fleet. The fleet listens on one of this machine's own
// private interface addresses (the test scan policy lets a scan dial Alice's own addresses; every other scan rule
// applies: the allowed networks, the built-in exclusions, AllowedForScan), because loopback is never scannable.

type discoWorld struct {
	*stack
	admin, op, aud          *client
	adminAcct, opAcct, audA *account
	fleet                   *fakefleet.Fleet
	ip                      netip.Addr
	ports                   []int
}

// localScanAddress is a private, non-loopback IPv4 address of this machine that the built-in scan rule accepts (the
// Docker bridge first), or the zero Addr.
func localScanAddress() netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Addr{}
	}
	var found netip.Addr
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := p.Addr().Unmap()
		if !ip.Is4() || !ip.IsPrivate() || !netaddr.AllowedForScan(ip) {
			continue
		}
		if ip == netip.MustParseAddr("172.17.0.1") {
			return ip
		}
		if !found.IsValid() {
			found = ip
		}
	}
	return found
}

func newDiscoWorld(t *testing.T) *discoWorld {
	t.Helper()
	ip := localScanAddress()
	if !ip.IsValid() {
		t.Skip("no private non-loopback IPv4 interface address to run the fake fleet on")
	}
	s, admin, adminAcct := installed(t)
	w := &discoWorld{stack: s, admin: admin, adminAcct: adminAcct, ip: ip}
	w.opAcct = s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	w.op = s.freshClient()
	s.firstSignIn(w.op, w.opAcct)
	w.audA = s.createUser(admin, adminAcct, "audrey", "auditor", "auditor-password-2026")
	w.aud = s.freshClient()
	s.firstSignIn(w.aud, w.audA)
	fleet, err := fakefleet.New(fakefleet.Options{Kinds: []fakefleet.Kind{fakefleet.KindValid, fakefleet.KindExpired, fakefleet.KindSelfSigned,
		fakefleet.KindPlainText, fakefleet.KindReset}, Bind: ip.String(), Now: s.clock.Now()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = fleet.Close() })
	w.fleet = fleet
	for _, srv := range fleet.Servers() {
		_, port, err := net.SplitHostPort(srv.Addr())
		require.NoError(t, err)
		n, err := strconv.Atoi(port)
		require.NoError(t, err)
		w.ports = append(w.ports, n)
	}
	s.mu.Lock()
	s.names = map[string][]netip.Addr{"valid.fleet.test": {ip}}
	s.mu.Unlock()
	return w
}

func leafFP(chain [][]byte) string {
	sum := sha256.Sum256(chain[0])
	return hex.EncodeToString(sum[:])
}

func (w *discoWorld) items(c *client, path string) []map[string]any {
	w.t.Helper()
	rec := c.do(http.MethodGet, path, nil)
	requireStatus(w.t, rec, http.StatusOK)
	return decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](w.t, rec).Items
}

func (w *discoWorld) auditCount(action string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.db.Owner.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n))
	return n
}

func (w *discoWorld) licensedTargets() int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.db.Owner.QueryRow(context.Background(), `SELECT count(*) FROM targets WHERE counts_toward_license`).Scan(&n))
	return n
}

// The whole journey: settings, a refused and an accepted scope, the preview, a scan run by the job against the fleet,
// the results (unmanaged, managed, the endpoint -> server link), the CSV export with its formula guard, cancel, and the
// lock: starting is refused, reading and cancelling work. Discovery never moves the licence count.
func TestDiscoveryJourneyOverHTTP(t *testing.T) {
	w := newDiscoWorld(t)
	ctx := context.Background()

	// Nothing may be scanned before an Administrator allows a network.
	rec := w.aud.do(http.MethodGet, "/api/v1/discovery/settings", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, false, decodeBody[map[string]any](t, rec)["scanning_enabled"])
	w.stepUp(w.admin, w.adminAcct)
	scope := map[string]any{"name": "Lab", "entries": []string{w.ip.String(), "valid.fleet.test"}, "ports": w.ports, "rate_per_sec": 100,
		"concurrency": 8}
	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", scope)
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-DSC-0002")
	rec = w.op.do(http.MethodPut, "/api/v1/discovery/settings", map[string]any{"allowed_networks": []string{w.ip.String() + "/32"},
		"global_exclusions": []string{}, "retention_days": 90})
	requireStatus(t, rec, http.StatusForbidden)
	rec = w.admin.do(http.MethodPut, "/api/v1/discovery/settings", map[string]any{"allowed_networks": []string{w.ip.String() + "/32"},
		"global_exclusions": []string{}, "retention_days": 90})
	requireStatus(t, rec, http.StatusOK)
	settings := decodeBody[map[string]any](t, rec)
	assert.Equal(t, true, settings["scanning_enabled"])
	assert.Equal(t, []any{w.ip.String()}, settings["allowed_networks"], "stored canonical")
	assert.Equal(t, 1, w.auditCount("discovery.exclusions.updated"))

	// The preview resolves nothing; a name that does not resolve is refused without any address.
	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes/preview", scope)
	requireStatus(t, rec, http.StatusOK)
	prev := decodeBody[map[string]any](t, rec)
	assert.EqualValues(t, 1, prev["addresses"])
	assert.EqualValues(t, 1, prev["hostnames"])
	assert.EqualValues(t, len(w.ports)*2, prev["endpoints"])
	bad := map[string]any{"name": "Bad", "entries": []string{w.ip.String(), "nowhere.fleet.test"}, "ports": []int{443}}
	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", bad)
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-DSC-0010")
	assert.Equal(t, map[string]any{"field": "entries", "index": "1"}, decodeBody[map[string]map[string]any](t, rec)["error"]["params"])
	rec = w.op.do(http.MethodPost, "/api/v1/discovery/scopes", scope)
	requireStatus(t, rec, http.StatusForbidden)
	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", scope)
	requireStatus(t, rec, http.StatusCreated)
	created := decodeBody[map[string]any](t, rec)
	scopeID := created["id"].(string)
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", scope)
	requireError(t, rec, http.StatusConflict, "ALC-DSC-0011")

	// A managed server at the fleet's address, holding the valid leaf on a live location: "managed", and the endpoint
	// links to it. Its licence count is the baseline discovery must not move.
	target, err := seed.Target(ctx, w.db.Owner, "fleet-web", "linux", "ok", nil)
	require.NoError(t, err)
	_, err = w.db.Owner.Exec(ctx, `UPDATE targets SET config = jsonb_set(config, '{host}', to_jsonb($2::text)) WHERE id = $1`, target, w.ip.String())
	require.NoError(t, err)
	validFP := leafFP(w.fleet.Server(fakefleet.KindValid).Chain())
	certID := uuid.New()
	_, err = w.db.Owner.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
VALUES ($1, $2, 'valid', now() - interval '1 day', now() + interval '1 day', 'ecdsa', $3, '', 'uploaded', now(), now(), now())`,
		certID, validFP, seed.Hex(certID.String()))
	require.NoError(t, err)
	_, err = w.db.Owner.Exec(ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, certificate_id, supported, first_seen_at, last_seen_at)
VALUES ($1, $2, 'nginx_file', '/etc/ssl/valid.pem', $3, true, now(), now())`, uuid.New(), target, certID)
	require.NoError(t, err)
	licensed := w.licensedTargets()

	// The Operator starts the scan; the job runs it against the fleet.
	rec = w.op.do(http.MethodPost, "/api/v1/discovery/scopes/"+scopeID+"/scans", nil)
	requireStatus(t, rec, http.StatusAccepted)
	scan := decodeBody[map[string]any](t, rec)
	scanID := scan["id"].(string)
	assert.Equal(t, "queued", scan["state"])
	rec = w.op.do(http.MethodPost, "/api/v1/discovery/scopes/"+scopeID+"/scans", nil)
	requireError(t, rec, http.StatusConflict, "ALC-DSC-0004")
	w.runJobs()
	rec = w.aud.do(http.MethodGet, "/api/v1/discovery/scans/"+scanID, nil)
	requireStatus(t, rec, http.StatusOK)
	scan = decodeBody[map[string]any](t, rec)
	require.Equal(t, "done", scan["state"], "%v", scan)
	assert.EqualValues(t, len(w.ports)*2, scan["endpoints_total"])
	assert.EqualValues(t, 6, scan["endpoints_answered"], "valid, expired and self-signed, by address and by name")
	assert.Nil(t, scan["error_code"])
	assert.Equal(t, 1, w.auditCount("discovery.scan.started"))
	assert.Equal(t, 1, w.auditCount("discovery.scan.finished"))
	assert.Equal(t, licensed, w.licensedTargets(), "discovery never counts toward the licence")
	assert.Zero(t, w.fleet.AppBytesAfterHandshake(), "no application byte after the handshake")

	// Results: three leaves; the valid one is managed, the others unmanaged; the expired one is expired.
	all := w.items(w.aud, "/api/v1/discovery/certificates")
	require.Len(t, all, 3)
	unmanaged := w.items(w.aud, "/api/v1/discovery/certificates?status=unmanaged")
	require.Len(t, unmanaged, 2)
	managed := w.items(w.aud, "/api/v1/discovery/certificates?status=managed")
	require.Len(t, managed, 1)
	assert.Equal(t, validFP, managed[0]["fingerprint_sha256"])
	assert.Equal(t, certID.String(), managed[0]["managed_certificate_id"])
	expired := w.items(w.aud, "/api/v1/discovery/certificates?expired=true")
	require.Len(t, expired, 1)
	assert.Equal(t, leafFP(w.fleet.Server(fakefleet.KindExpired).Chain()), expired[0]["fingerprint_sha256"])
	selfSigned := w.items(w.aud, "/api/v1/discovery/certificates?self_signed=true")
	require.Len(t, selfSigned, 1)
	rec = w.aud.do(http.MethodGet, "/api/v1/discovery/certificates/"+validFP, nil)
	requireStatus(t, rec, http.StatusOK)
	detail := decodeBody[map[string]any](t, rec)
	eps := detail["endpoints"].([]any)
	require.Len(t, eps, 2, "by address and by name")
	for _, e := range eps {
		assert.Equal(t, map[string]any{"id": target.String(), "name": "fleet-web"}, e.(map[string]any)["target"], "the endpoint links to the server")
	}

	// The endpoint list inside the scope, paged in the order of its unique key.
	var states []string
	next := ""
	for range 20 {
		path := "/api/v1/discovery/endpoints?limit=3&scope_id=" + scopeID
		if next != "" {
			path += "&cursor=" + next
		}
		rec = w.op.do(http.MethodGet, path, nil)
		requireStatus(t, rec, http.StatusOK)
		page := decodeBody[struct {
			Items []map[string]any `json:"items"`
			Next  *string          `json:"next_cursor"`
		}](t, rec)
		for _, e := range page.Items {
			states = append(states, e["state"].(string))
		}
		if page.Next == nil {
			break
		}
		next = *page.Next
	}
	assert.Len(t, states, len(w.ports)*2)
	assert.ElementsMatch(t, []string{"present", "present", "present", "present", "present", "present", "no_tls", "no_tls", "unreachable",
		"unreachable"}, states)

	// The export: a certificate whose CN is a formula is neutralised; the export is audited.
	formulaFP := strings.Repeat("ef", 32)
	_, err = w.db.Owner.Exec(ctx, `INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before, not_after,
    key_algorithm, self_signed, pem, first_seen, last_seen) VALUES ($1, true, $2, '{}', 'ca', now() - interval '1 day', now() + interval '9 days',
    'ecdsa', false, '-----BEGIN CERTIFICATE-----' || chr(10) || 'AA==' || chr(10) || '-----END CERTIFICATE-----', now(), now())`,
		formulaFP, "=cmd|' /C calc'!A0")
	require.NoError(t, err)
	rec = w.aud.do(http.MethodGet, "/api/v1/discovery/certificates/export?status=unmanaged", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(rec.Body.Bytes(), []byte("\xEF\xBB\xBF")))).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 4, "header and the three unmanaged leaves")
	var cns []string
	for _, r := range rows[1:] {
		cns = append(cns, r[1])
	}
	assert.Contains(t, cns, "'=cmd|' /C calc'!A0", "the formula is neutralised")
	assert.Equal(t, 1, w.auditCount("discovery.export"))
	var details map[string]string
	require.NoError(t, w.db.Owner.QueryRow(ctx, `SELECT details FROM audit_log WHERE action = 'discovery.export'`).Scan(&details))
	assert.Equal(t, map[string]string{"kind": "discovery_certificates", "format": "csv", "status": "unmanaged", "row_count": "3"}, details)

	// Cancel: a second scan is asked to stop before it runs; the job ends it cancelled, results kept.
	rec = w.op.do(http.MethodPost, "/api/v1/discovery/scopes/"+scopeID+"/scans", nil)
	requireStatus(t, rec, http.StatusAccepted)
	second := decodeBody[map[string]any](t, rec)["id"].(string)
	rec = w.op.do(http.MethodPost, "/api/v1/discovery/scans/"+second+"/cancel", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, true, decodeBody[map[string]any](t, rec)["cancel_requested"])
	requireStatus(t, w.op.do(http.MethodPost, "/api/v1/discovery/scans/"+second+"/cancel", nil), http.StatusOK)
	assert.Equal(t, 1, w.auditCount("discovery.scan.cancelled"), "idempotent")
	w.runJobs()
	rec = w.op.do(http.MethodGet, "/api/v1/discovery/scans/"+second, nil)
	requireStatus(t, rec, http.StatusOK)
	got := decodeBody[map[string]any](t, rec)
	assert.Equal(t, "cancelled", got["state"])
	assert.Equal(t, "ALC-DSC-0005", got["error_code"])
	assert.Len(t, w.items(w.aud, "/api/v1/discovery/certificates"), 4, "the earlier results are kept")

	// Summary of the Overview metric.
	rec = w.aud.do(http.MethodGet, "/api/v1/discovery/summary", nil)
	requireStatus(t, rec, http.StatusOK)
	sum := decodeBody[map[string]any](t, rec)
	assert.EqualValues(t, 2, sum["unmanaged_total"], "unmanaged leaves an endpoint presents (the inserted one has none)")
	assert.EqualValues(t, 1, sum["scopes"])

	// Lock: starting is refused (nothing queued); reading, cancelling and the scopes still work.
	w.clock.Advance(31 * 24 * 3600 * 1e9)
	require.NoError(t, w.license.Tick(ctx))
	require.True(t, w.license.Snapshot().Eval.Locked())
	w.signIn(w.admin, w.adminAcct)
	w.signIn(w.op, w.opAcct)
	w.signIn(w.aud, w.audA)
	var scans int
	require.NoError(t, w.db.Owner.QueryRow(ctx, `SELECT count(*) FROM discovery_scans`).Scan(&scans))
	rec = w.op.do(http.MethodPost, "/api/v1/discovery/scopes/"+scopeID+"/scans", nil)
	requireError(t, rec, http.StatusForbidden, "ALC-LIC-0001")
	var after int
	require.NoError(t, w.db.Owner.QueryRow(ctx, `SELECT count(*) FROM discovery_scans`).Scan(&after))
	assert.Equal(t, scans, after, "nothing queued in lock")
	requireStatus(t, w.op.do(http.MethodPost, "/api/v1/discovery/scans/"+second+"/cancel", nil), http.StatusOK)
	requireStatus(t, w.aud.do(http.MethodGet, "/api/v1/discovery/certificates", nil), http.StatusOK)
	requireStatus(t, w.aud.do(http.MethodGet, "/api/v1/discovery/scans", nil), http.StatusOK)
	w.stepUp(w.admin, w.adminAcct)
	requireStatus(t, w.admin.do(http.MethodPatch, "/api/v1/discovery/scopes/"+scopeID, map[string]any{"enabled": false}), http.StatusOK)
	requireStatus(t, w.admin.do(http.MethodGet, "/api/v1/discovery/certificates/export", nil), http.StatusOK)
	assert.Equal(t, licensed, w.licensedTargets())

	// No error answer of any discovery request carries an address the scan or a look-up found, or an internal text.
	for _, e := range w.recorded() {
		if !strings.HasPrefix(e.path, "/api/v1/discovery") || e.status < 400 {
			continue
		}
		body := string(e.body)
		for _, leak := range []string{w.ip.String(), "no such host", "dial", "connect:", "SQLSTATE", "pgx", "discoverysvc:", "discovery:"} {
			assert.NotContains(t, body, leak, "%s answered %d", e.key(), e.status)
		}
	}
}

// Tokens (D7): a read token never reads the network map; an operate token reads and starts scans; no token manages.
func TestDiscoveryTokensOverHTTP(t *testing.T) {
	s, admin, adminAcct := installed(t)
	s.stepUp(admin, adminAcct)
	token := func(scope string) *client {
		rec := admin.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "t-" + scope, "scope": scope, "expires_in_days": 30})
		requireStatus(t, rec, http.StatusCreated)
		c := s.freshClient()
		c.bearer = decodeBody[map[string]any](t, rec)["token"].(string)
		return c
	}
	read, operate := token("read"), token("operate")
	rec := read.do(http.MethodGet, "/api/v1/discovery/certificates", nil)
	requireError(t, rec, http.StatusForbidden, "ALC-AUTH-0002")
	requireStatus(t, operate.do(http.MethodGet, "/api/v1/discovery/certificates", nil), http.StatusOK)
	requireStatus(t, operate.do(http.MethodGet, "/api/v1/discovery/settings", nil), http.StatusOK)
	rec = operate.do(http.MethodPut, "/api/v1/discovery/settings", map[string]any{"allowed_networks": []string{}, "global_exclusions": []string{},
		"retention_days": 90})
	requireError(t, rec, http.StatusForbidden, "ALC-AUTH-0002")
	rec = operate.do(http.MethodPost, "/api/v1/discovery/scopes/"+uuid.NewString()+"/scans", nil)
	requireError(t, rec, http.StatusNotFound, "ALC-DSC-0008")
}

// discoveryRecords stores the discovery records the GET routes read (TestA06GETRoutesNeverChangeState): the settings,
// one scope, one queued scan and one discovered certificate; it returns the ids per path prefix and the fingerprint.
func discoveryRecords(t *testing.T, s *stack, c *client, admin *account) (map[string]string, string) {
	t.Helper()
	s.stepUp(c, admin)
	requireStatus(t, c.do(http.MethodPut, "/api/v1/discovery/settings", map[string]any{"allowed_networks": []string{"10.20.0.0/24"},
		"global_exclusions": []string{}, "retention_days": 90}), http.StatusOK)
	rec := c.do(http.MethodPost, "/api/v1/discovery/scopes", map[string]any{"name": "A06", "entries": []string{"10.20.0.0/28"}, "ports": []int{443}})
	requireStatus(t, rec, http.StatusCreated)
	scope := decodeBody[map[string]any](t, rec)["id"].(string)
	rec = c.do(http.MethodPost, "/api/v1/discovery/scopes/"+scope+"/scans", nil)
	requireStatus(t, rec, http.StatusAccepted)
	scan := decodeBody[map[string]any](t, rec)["id"].(string)
	fp := strings.Repeat("a1", 32)
	_, err := s.db.Owner.Exec(context.Background(), `INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn,
    not_before, not_after, key_algorithm, self_signed, pem, first_seen, last_seen) VALUES ($1, true, 'a06', '{}', 'ca', now() - interval '1 day',
    now() + interval '9 days', 'ecdsa', false, '-----BEGIN CERTIFICATE-----' || chr(10) || 'AA==' || chr(10) || '-----END CERTIFICATE-----', now(), now())`, fp)
	require.NoError(t, err)
	return map[string]string{"/api/v1/discovery/scopes/": scope, "/api/v1/discovery/scans/": scan}, fp
}
