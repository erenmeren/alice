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
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
	"alice/internal/testutil/fakefleet"
	"alice/internal/testutil/seed"
)

// Network discovery over HTTP (plan 2026-10-13-network-discovery, Task 9): the real services, PostgreSQL and the
// netdisco.scan job run by the stack's runner. TestDiscoveryOverHTTPWithoutFleet never dials and never skips; the fleet
// journey scans a fake TLS fleet listening on one of this machine's Docker bridge addresses (the test scan policy lets
// a scan dial Alice's own interface addresses; every other scan rule applies: the allowed networks, the built-in
// exclusions and AllowedForScan, so loopback is never scannable). Running alice-fakefleet as a container instead was
// not chosen: its image build downloads every module (go mod download) and is neither cheap nor offline.

// Environment switches of the fleet journey: ALICE_REQUIRE_FLEET=1 (set by make test-integration and make coverage)
// fails it instead of skipping it when no bridge address exists; ALICE_FLEET_ALLOW_LAN=1 lets it listen on another
// private (LAN) interface address when there is no bridge.
const (
	envRequireFleet  = "ALICE_REQUIRE_FLEET"
	envFleetAllowLAN = "ALICE_FLEET_ALLOW_LAN"
)

type discoWorld struct {
	*stack
	admin, op, aud          *client
	adminAcct, opAcct, audA *account
	fleet                   *fakefleet.Fleet
	ip                      netip.Addr
	ports                   []int
}

// bridgeInterface reports whether an interface is a container bridge (Docker's docker0 and br-<id> networks).
func bridgeInterface(name string) bool { return name == "docker0" || strings.HasPrefix(name, "br-") }

// fleetAddress picks the address the fleet listens on: a private IPv4 address of a container bridge that the built-in
// scan rule accepts, else (only with ALICE_FLEET_ALLOW_LAN=1) one of another interface. Without one the journey skips,
// or fails with ALICE_REQUIRE_FLEET=1.
func fleetAddress(t *testing.T) netip.Addr {
	t.Helper()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	var bridge, lan netip.Addr
	var bridgeName, lanName string
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := p.Addr().Unmap()
			if !ip.Is4() || !ip.IsPrivate() || !netaddr.AllowedForScan(ip) {
				continue
			}
			switch {
			case bridgeInterface(ifc.Name) && (!bridge.IsValid() || ifc.Name == "docker0"):
				bridge, bridgeName = ip, ifc.Name
			case !bridgeInterface(ifc.Name) && !lan.IsValid():
				lan, lanName = ip, ifc.Name
			}
		}
	}
	switch {
	case bridge.IsValid():
		t.Logf("the fake fleet listens on %s (bridge %s)", bridge, bridgeName)
		return bridge
	case lan.IsValid() && os.Getenv(envFleetAllowLAN) == "1":
		t.Logf("the fake fleet listens on %s (interface %s, allowed by %s=1)", lan, lanName, envFleetAllowLAN)
		return lan
	}
	msg := "no container bridge address to run the fake fleet on (a LAN address needs " + envFleetAllowLAN + "=1)"
	if os.Getenv(envRequireFleet) == "1" {
		t.Fatal(msg)
	}
	t.Skip(msg)
	return netip.Addr{}
}

// newDiscoUsers is an installed stack with an Administrator, an Operator and an Auditor.
func newDiscoUsers(t *testing.T) *discoWorld {
	t.Helper()
	s, admin, adminAcct := installed(t)
	w := &discoWorld{stack: s, admin: admin, adminAcct: adminAcct}
	w.opAcct = s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	w.op = s.freshClient()
	s.firstSignIn(w.op, w.opAcct)
	w.audA = s.createUser(admin, adminAcct, "audrey", "auditor", "auditor-password-2026")
	w.aud = s.freshClient()
	s.firstSignIn(w.aud, w.audA)
	return w
}

func newDiscoWorld(t *testing.T) *discoWorld {
	t.Helper()
	ip := fleetAddress(t)
	w := newDiscoUsers(t)
	w.ip = ip
	fleet, err := fakefleet.New(fakefleet.Options{Kinds: []fakefleet.Kind{fakefleet.KindValid, fakefleet.KindExpired, fakefleet.KindSelfSigned,
		fakefleet.KindPlainText, fakefleet.KindReset}, Bind: ip.String(), Now: w.clock.Now()})
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
	w.mu.Lock()
	w.names = map[string][]netip.Addr{"valid.fleet.test": {ip}}
	w.mu.Unlock()
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

func (w *discoWorld) lockNow() {
	w.t.Helper()
	w.clock.Advance(31 * 24 * time.Hour)
	require.NoError(w.t, w.license.Tick(context.Background()))
	require.True(w.t, w.license.Snapshot().Eval.Locked())
	w.signIn(w.admin, w.adminAcct)
	w.signIn(w.op, w.opAcct)
	w.signIn(w.aud, w.audA)
}

// requireNoLeaks: no error answer of a discovery request carries an address a look-up or a scan found, a name server's
// or the driver's text.
func (w *discoWorld) requireNoLeaks(addrs ...string) {
	w.t.Helper()
	for _, e := range w.recorded() {
		if !strings.HasPrefix(e.path, "/api/v1/discovery") || e.status < 400 {
			continue
		}
		body := string(e.body)
		for _, leak := range append(addrs, "no such host", "dial", "connect:", "SQLSTATE", "pgx", "discoverysvc:", "discovery:") {
			assert.NotContains(w.t, body, leak, "%s answered %d", e.key(), e.status)
		}
	}
}

const testPEM = `'-----BEGIN CERTIFICATE-----' || chr(10) || 'AA==' || chr(10) || '-----END CERTIFICATE-----'`

// The fleet-independent journey (never dials, never skips): settings, the save-time refusals, the 403s of the roles,
// starting and cancelling a scan that never runs, the lists and the export over stored rows (formula CNs neutralised,
// leaves valid until 9999-12-31 at a page boundary in the list and in the export), the lock, the licence count and the
// leak sweep.
func TestDiscoveryOverHTTPWithoutFleet(t *testing.T) {
	w := newDiscoUsers(t)
	ctx := context.Background()
	licensed := w.licensedTargets()
	resolvedTo := "10.20.0.77" // what known.test resolves to: never in an answer
	w.mu.Lock()
	w.names = map[string][]netip.Addr{"known.test": {netip.MustParseAddr(resolvedTo)}}
	w.mu.Unlock()

	rec := w.aud.do(http.MethodGet, "/api/v1/discovery/settings", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, false, decodeBody[map[string]any](t, rec)["scanning_enabled"], "nothing may be scanned before a network is allowed")
	w.stepUp(w.admin, w.adminAcct)
	scope := map[string]any{"name": "Lab", "entries": []string{"10.20.0.0/28", "known.test"}, "ports": []int{443, 8443}}
	requireError(t, w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", scope), http.StatusUnprocessableEntity, "ALC-DSC-0002")
	settings := map[string]any{"allowed_networks": []string{"10.20.0.0/24"}, "global_exclusions": []string{"10.20.0.9/32"}, "retention_days": 90}
	requireStatus(t, w.op.do(http.MethodPut, "/api/v1/discovery/settings", settings), http.StatusForbidden)
	requireStatus(t, w.aud.do(http.MethodPut, "/api/v1/discovery/settings", settings), http.StatusForbidden)
	requireStatus(t, w.admin.do(http.MethodPut, "/api/v1/discovery/settings", settings), http.StatusOK)
	rec = w.aud.do(http.MethodGet, "/api/v1/discovery/settings", nil)
	got := decodeBody[map[string]any](t, rec)
	assert.Equal(t, true, got["scanning_enabled"])
	assert.Equal(t, []any{"10.20.0.9"}, got["global_exclusions"], "stored canonical")
	assert.Equal(t, 1, w.auditCount("discovery.exclusions.updated"))

	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes/preview", scope)
	requireStatus(t, rec, http.StatusOK)
	assert.EqualValues(t, 16, decodeBody[map[string]any](t, rec)["addresses"])
	bad := map[string]any{"name": "Bad", "entries": []string{"10.20.0.1", "nowhere.test"}, "ports": []int{443}}
	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", bad)
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-DSC-0010")
	assert.Equal(t, map[string]any{"field": "entries", "index": "1"}, decodeBody[map[string]map[string]any](t, rec)["error"]["params"])
	requireStatus(t, w.op.do(http.MethodPost, "/api/v1/discovery/scopes", scope), http.StatusForbidden)
	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", scope)
	requireStatus(t, rec, http.StatusCreated)
	scopeID := decodeBody[map[string]any](t, rec)["id"].(string)
	requireError(t, w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", scope), http.StatusConflict, "ALC-DSC-0011")
	requireStatus(t, w.admin.do(http.MethodPatch, "/api/v1/discovery/scopes/"+scopeID, map[string]any{}), http.StatusUnprocessableEntity)

	// A scan is started and cancelled; it is never run here (nothing is dialed).
	requireStatus(t, w.aud.do(http.MethodPost, "/api/v1/discovery/scopes/"+scopeID+"/scans", nil), http.StatusForbidden)
	rec = w.op.do(http.MethodPost, "/api/v1/discovery/scopes/"+scopeID+"/scans", nil)
	requireStatus(t, rec, http.StatusAccepted)
	scanID := decodeBody[map[string]any](t, rec)["id"].(string)
	requireError(t, w.op.do(http.MethodPost, "/api/v1/discovery/scopes/"+scopeID+"/scans", nil), http.StatusConflict, "ALC-DSC-0004")
	requireStatus(t, w.op.do(http.MethodPost, "/api/v1/discovery/scans/"+scanID+"/cancel", nil), http.StatusOK)
	requireStatus(t, w.op.do(http.MethodPost, "/api/v1/discovery/scans/"+scanID+"/cancel", nil), http.StatusOK)
	assert.Equal(t, 1, w.auditCount("discovery.scan.started"))
	assert.Equal(t, 1, w.auditCount("discovery.scan.cancelled"), "idempotent")

	// Stored results: formula CNs, 199 ordinary leaves and two valid until 9999-12-31 (the last ones in expiry order),
	// each presented by an endpoint of the scope.
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := w.db.Owner.Exec(ctx, sql, args...)
		require.NoError(t, err, sql)
	}
	exec(`INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before, not_after, key_algorithm,
    self_signed, pem, first_seen, last_seen)
SELECT md5('leaf' || i) || md5('more' || i), true, CASE i % 4 WHEN 0 THEN '=cmd|'' /C calc''!A' || i WHEN 1 THEN '+SUM(A1)' || i
    WHEN 2 THEN '-2+3' || i ELSE '@x' || i END, '{}', 'ca', now() - interval '1 day', now() + (i || ' days')::interval, 'ecdsa', false,
    ` + testPEM + `, now(), now() FROM generate_series(1, 199) AS i`)
	farA, farB := strings.Repeat("f1", 32), strings.Repeat("f2", 32)
	exec(`INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before, not_after, key_algorithm,
    self_signed, pem, first_seen, last_seen) VALUES ($1, true, 'far-a', '{}', 'ca', now(), '9999-12-31 23:59:59.000001+00', 'ecdsa', false, `+testPEM+`, now(), now()),
    ($2, true, 'far-b', '{}', 'ca', now(), '9999-12-31 23:59:59.999999+00', 'ecdsa', false, `+testPEM+`, now(), now())`, farA, farB)
	exec(`INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, fingerprint_sha256, state, first_seen, last_seen, last_scanned_at,
    tls_version, cipher)
SELECT gen_random_uuid(), $1, ('10.20.' || (i / 250) || '.' || (i % 250 + 1))::inet, 443, '', fingerprint_sha256, 'present', now(), now(), now(),
    'TLS 1.3', 'TLS_AES_128_GCM_SHA256'
FROM (SELECT fingerprint_sha256, row_number() OVER (ORDER BY fingerprint_sha256) AS i FROM discovery_certificates) c`, scopeID)

	// The list: the far leaves at a page boundary; the next page continues after the first, not in 1816.
	page := w.items(w.aud, "/api/v1/discovery/certificates?expiring_within_days=3650&limit=200")
	require.Len(t, page, 199, "the far leaves are not within ten years")
	rec = w.aud.do(http.MethodGet, "/api/v1/discovery/certificates?limit=200", nil)
	requireStatus(t, rec, http.StatusOK)
	first := decodeBody[struct {
		Items []map[string]any `json:"items"`
		Next  *string          `json:"next_cursor"`
	}](t, rec)
	require.Len(t, first.Items, 200)
	assert.Equal(t, farA, first.Items[199]["fingerprint_sha256"], "the first far leaf ends the page")
	assert.Positive(t, first.Items[199]["days_left"])
	require.NotNil(t, first.Next)
	rest := w.items(w.aud, "/api/v1/discovery/certificates?limit=200&cursor="+*first.Next)
	require.Len(t, rest, 1)
	assert.Equal(t, farB, rest[0]["fingerprint_sha256"])

	// The export counts and streams the same pages: 201 rows, each once, formulas neutralised, audited.
	rec = w.aud.do(http.MethodGet, "/api/v1/discovery/certificates/export", nil)
	requireStatus(t, rec, http.StatusOK)
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(rec.Body.Bytes(), []byte("\xEF\xBB\xBF")))).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 202, "the header and every leaf once")
	seen := map[string]bool{}
	for _, r := range rows[1:] {
		assert.False(t, seen[r[0]], "a leaf twice: %s", r[0])
		seen[r[0]] = true
		if c := r[1]; c != "far-a" && c != "far-b" {
			assert.True(t, strings.HasPrefix(c, "'"), "formula cell %q is neutralised", c)
		}
	}
	assert.True(t, seen[farA] && seen[farB])
	var details map[string]string
	require.NoError(t, w.db.Owner.QueryRow(ctx, `SELECT details FROM audit_log WHERE action = 'discovery.export'`).Scan(&details))
	assert.Equal(t, map[string]string{"kind": "discovery_certificates", "format": "csv", "row_count": "201"}, details)
	assert.Equal(t, licensed, w.licensedTargets(), "discovery never counts toward the licence")

	// Lock: starting is refused (nothing queued); cancelling, reading, the scopes and the export work.
	w.lockNow()
	var scans int
	require.NoError(t, w.db.Owner.QueryRow(ctx, `SELECT count(*) FROM discovery_scans`).Scan(&scans))
	off := map[string]any{"name": "Other", "entries": []string{"10.20.0.32/28"}, "ports": []int{443}}
	w.stepUp(w.admin, w.adminAcct)
	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", off)
	requireStatus(t, rec, http.StatusCreated)
	otherID := decodeBody[map[string]any](t, rec)["id"].(string)
	requireError(t, w.op.do(http.MethodPost, "/api/v1/discovery/scopes/"+otherID+"/scans", nil), http.StatusForbidden, "ALC-LIC-0001")
	var after int
	require.NoError(t, w.db.Owner.QueryRow(ctx, `SELECT count(*) FROM discovery_scans`).Scan(&after))
	assert.Equal(t, scans, after, "nothing queued in lock")
	requireStatus(t, w.op.do(http.MethodPost, "/api/v1/discovery/scans/"+scanID+"/cancel", nil), http.StatusOK)
	requireStatus(t, w.aud.do(http.MethodGet, "/api/v1/discovery/certificates", nil), http.StatusOK)
	requireStatus(t, w.aud.do(http.MethodGet, "/api/v1/discovery/scans", nil), http.StatusOK)
	requireStatus(t, w.admin.do(http.MethodPatch, "/api/v1/discovery/scopes/"+scopeID, map[string]any{"enabled": false}), http.StatusOK)
	requireStatus(t, w.admin.do(http.MethodPut, "/api/v1/discovery/settings", settings), http.StatusOK)
	requireStatus(t, w.aud.do(http.MethodGet, "/api/v1/discovery/certificates/export", nil), http.StatusOK)
	assert.Equal(t, licensed, w.licensedTargets())
	w.requireNoLeaks(resolvedTo)
}

// The fleet journey: a scan run by the job against the fake fleet (on a bridge address), the results (unmanaged,
// managed, expired, self-signed, the endpoint -> server link), endpoint paging inside the scope, a cancel that the
// running job honours, the summary, and the licence count.
func TestDiscoveryFleetJourneyOverHTTP(t *testing.T) {
	w := newDiscoWorld(t)
	ctx := context.Background()
	w.stepUp(w.admin, w.adminAcct)
	scope := map[string]any{"name": "Lab", "entries": []string{w.ip.String(), "valid.fleet.test"}, "ports": w.ports, "rate_per_sec": 100,
		"concurrency": 8}
	requireStatus(t, w.admin.do(http.MethodPut, "/api/v1/discovery/settings", map[string]any{"allowed_networks": []string{w.ip.String() + "/32"},
		"global_exclusions": []string{}, "retention_days": 90}), http.StatusOK)
	rec := w.admin.do(http.MethodPost, "/api/v1/discovery/scopes/preview", scope)
	requireStatus(t, rec, http.StatusOK)
	assert.EqualValues(t, len(w.ports)*2, decodeBody[map[string]any](t, rec)["endpoints"])
	rec = w.admin.do(http.MethodPost, "/api/v1/discovery/scopes", scope)
	requireStatus(t, rec, http.StatusCreated)
	scopeID := decodeBody[map[string]any](t, rec)["id"].(string)
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
VALUES ($1, $2, 'server_file', '/etc/ssl/valid.pem', $3, true, now(), now())`, uuid.New(), target, certID)
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

	// Cancel: a second scan is asked to stop before it runs; the job ends it cancelled, results kept.
	rec = w.op.do(http.MethodPost, "/api/v1/discovery/scopes/"+scopeID+"/scans", nil)
	requireStatus(t, rec, http.StatusAccepted)
	second := decodeBody[map[string]any](t, rec)["id"].(string)
	requireStatus(t, w.op.do(http.MethodPost, "/api/v1/discovery/scans/"+second+"/cancel", nil), http.StatusOK)
	w.runJobs()
	rec = w.op.do(http.MethodGet, "/api/v1/discovery/scans/"+second, nil)
	requireStatus(t, rec, http.StatusOK)
	got := decodeBody[map[string]any](t, rec)
	assert.Equal(t, "cancelled", got["state"])
	assert.Equal(t, "ALC-DSC-0005", got["error_code"])
	assert.Len(t, w.items(w.aud, "/api/v1/discovery/certificates"), 3, "the earlier results are kept")
	assert.Equal(t, 2, w.auditCount("discovery.scan.finished"), "one row per ended scan")

	rec = w.aud.do(http.MethodGet, "/api/v1/discovery/summary", nil)
	requireStatus(t, rec, http.StatusOK)
	sum := decodeBody[map[string]any](t, rec)
	assert.EqualValues(t, 2, sum["unmanaged_total"])
	assert.EqualValues(t, 1, sum["scopes"])
	assert.Equal(t, licensed, w.licensedTargets())
	w.requireNoLeaks(w.ip.String())
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

	// The Overview's discovery metric (D2, D7): absent without a scope; with one, there for an operate token and a
	// session, never for a read token.
	overview := func(c *client) map[string]any {
		t.Helper()
		rec := c.do(http.MethodGet, "/api/v1/dashboard/summary", nil)
		requireStatus(t, rec, http.StatusOK)
		return decodeBody[map[string]any](t, rec)
	}
	assert.NotContains(t, overview(operate), "discovery", "no scope yet")
	ctx := context.Background()
	scope, err := seed.DiscoveryScope(ctx, s.db.Owner, "Lab", true)
	require.NoError(t, err)
	require.NoError(t, seed.DiscoveredCertificate(ctx, s.db.Owner, strings.Repeat("ab", 32), "soon.test", s.clock.Now().Add(72*time.Hour)))
	_, err = seed.DiscoveredEndpoint(ctx, s.db.Owner, scope, "10.20.0.5", 443, "", strings.Repeat("ab", 32), "present")
	require.NoError(t, err)
	for _, c := range []*client{operate, admin} {
		assert.Equal(t, map[string]any{"unmanaged_expiring_30d": 1.0}, overview(c)["discovery"])
	}
	assert.NotContains(t, overview(read), "discovery", "a read token never sees the network map")
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
