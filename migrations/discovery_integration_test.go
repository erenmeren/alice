//go:build integration

package migrations_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// SQLSTATE of the discovery scan freeze trigger (00014).
const scanFrozen = "Z1020" // a finished discovery scan is never rewritten

var discoveryTables = []string{"discovery_scopes", "discovery_scans", "discovery_certificates", "discovery_endpoints"}

// discoveryWorld is one scope with one finished and one running scan, a leaf and an intermediate certificate and one
// endpoint presenting them, all inserted through the application role.
type discoveryWorld struct {
	scope, done, running, endpoint uuid.UUID
	leaf, inter                    string
}

const discoveryScope = `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at)
VALUES ($1, $2, '["10.0.0.0/30"]', '{443}', now(), now())`

func seedDiscovery(t *testing.T, d *pgtest.DB) discoveryWorld {
	t.Helper()
	w := discoveryWorld{scope: uuid.New(), done: uuid.New(), running: uuid.New(), endpoint: uuid.New(), leaf: hex64("d"), inter: hex64("e")}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{discoveryScope, []any{w.scope, "Office LAN"}},
		{`INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, finished_at, endpoints_total, endpoints_answered)
VALUES ($1, $2, 'manual', 'done', now(), now(), now(), 4, 1)`, []any{w.done, w.scope}},
		{`INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before, not_after, key_algorithm, pem,
first_seen, last_seen) VALUES ($1, true, 'www.corp.example', '{www.corp.example}', 'Corp CA', now(), now() + interval '30 days', 'ecdsa',
'-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', now(), now())`, []any{w.leaf}},
		{`INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, issuer_cn, not_before, not_after, key_algorithm, pem,
first_seen, last_seen) VALUES ($1, false, 'Corp CA', 'Corp Root', now(), now() + interval '3 years', 'rsa',
'-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n', now(), now())`, []any{w.inter}},
		{`INSERT INTO discovery_endpoints (id, scope_id, address, port, fingerprint_sha256, chain_fingerprints, chain_sha256, tls_version, cipher,
state, first_seen, last_seen, last_scanned_at, last_scan_id) VALUES ($1, $2, '10.0.0.1', 443, $3, ARRAY[$4], $5, 'TLS 1.3',
'TLS_AES_128_GCM_SHA256', 'present', now(), now(), now(), $6)`, []any{w.endpoint, w.scope, w.leaf, w.inter, hex64("f"), w.done}},
		{`INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at) VALUES ($1, $2, 'schedule', 'running', now(), now())`,
			[]any{w.running, w.scope}},
	} {
		_, err := d.App.Exec(context.Background(), q.sql, q.args...)
		require.NoError(t, err, q.sql)
	}
	return w
}

func TestDiscoveryTablesExistAndAreGranted(t *testing.T) {
	d := pgtest.New(t)
	for _, tbl := range discoveryTables {
		assert.True(t, tableExists(t, d, tbl), tbl)
	}
	assert.Empty(t, grantProblems(t, d), "every discovery grant is the one the guard lists")
	ctx := context.Background()
	for _, c := range []struct {
		table, priv string
		want        bool
	}{
		{"discovery_scopes", "DELETE", false}, // soft-deleted: scans keep their scope
		{"discovery_scans", "DELETE", true},   // the last 30 per scope are kept
		{"discovery_certificates", "DELETE", true},
		{"discovery_endpoints", "DELETE", true},
		{"discovery_endpoints", "TRUNCATE", false},
	} {
		var ok bool
		require.NoError(t, d.Owner.QueryRow(ctx, "SELECT has_table_privilege('alice_app', $1, $2)", c.table, c.priv).Scan(&ok))
		assert.Equal(t, c.want, ok, "%s %s", c.priv, c.table)
	}
	seedDiscovery(t, d)
}

func TestDiscoveryConstraints(t *testing.T) {
	d := pgtest.New(t)
	w := seedDiscovery(t, d)
	ctx := context.Background()
	bad := func(name, sql string, args ...any) {
		t.Helper()
		_, err := d.App.Exec(ctx, sql, args...)
		assert.Equal(t, checkViolation, sqlState(err), name)
	}
	scope := func(col, val string) string {
		return `INSERT INTO discovery_scopes (id, name, entries, ports, ` + col + `, created_at, updated_at)
VALUES ($1, $2, '["10.0.0.1"]', '{443}', ` + val + `, now(), now())`
	}
	entries := make([]string, 257)
	for i := range entries {
		entries[i] = `"10.0.0.1"`
	}
	bad("257 entries", `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at)
VALUES ($1, 'x', '[`+strings.Join(entries, ",")+`]', '{443}', now(), now())`, uuid.New())
	bad("entries not an array", `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at)
VALUES ($1, 'x', '{"a":1}', '{443}', now(), now())`, uuid.New())
	bad("no entry", `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at) VALUES ($1, 'x', '[]', '{443}', now(), now())`, uuid.New())
	bad("empty name", scope("enabled", "true"), uuid.New(), "")
	bad("no port", `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at) VALUES ($1, 'x', '["10.0.0.1"]', '{}', now(), now())`, uuid.New())
	bad("17 ports", `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at)
VALUES ($1, 'x', '["10.0.0.1"]', '{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17}', now(), now())`, uuid.New())
	bad("port 0", `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at) VALUES ($1, 'x', '["10.0.0.1"]', '{0}', now(), now())`, uuid.New())
	bad("port 65536", `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at) VALUES ($1, 'x', '["10.0.0.1"]', '{443,65536}', now(), now())`, uuid.New())
	bad("null port", `INSERT INTO discovery_scopes (id, name, entries, ports, created_at, updated_at) VALUES ($1, 'x', '["10.0.0.1"]', '{443,NULL}', now(), now())`, uuid.New())
	snis := make([]string, 257)
	for i := range snis {
		snis[i] = "a.example"
	}
	bad("257 SNI names", scope("sni_names", "$3"), uuid.New(), "x", snis)
	bad("SNI with a space", scope("sni_names", "$3"), uuid.New(), "x", []string{"a b.example"})
	bad("SNI with a newline", scope("sni_names", "$3"), uuid.New(), "x", []string{"a.example\r\nX: y"})
	bad("upper-case SNI", scope("sni_names", "$3"), uuid.New(), "x", []string{"A.example"})
	bad("long SNI", scope("sni_names", "$3"), uuid.New(), "x", []string{strings.Repeat("a", 254)})
	bad("empty label", scope("sni_names", "$3"), uuid.New(), "x", []string{"a..b"})
	bad("label starting with a hyphen", scope("sni_names", "$3"), uuid.New(), "x", []string{"a.-b"})
	bad("label ending with a hyphen", scope("sni_names", "$3"), uuid.New(), "x", []string{"a-.b"})
	bad("64-character label", scope("sni_names", "$3"), uuid.New(), "x", []string{strings.Repeat("a", 64) + ".example"})
	bad("trailing dot", scope("sni_names", "$3"), uuid.New(), "x", []string{"a.example."})
	bad("254 characters of labels", scope("sni_names", "$3"), uuid.New(), "x",
		[]string{strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 62)})
	_, err := d.App.Exec(ctx, scope("sni_names", "$3"), uuid.New(), "Longest", []string{strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61),
		strings.Repeat("a", 63) + ".example", "a-b.c"})
	require.NoError(t, err, "253 characters and 63-character labels are names")
	bad("exclusions not an array", scope("exclusions", `'"10.0.0.0/8"'`), uuid.New(), "x")
	bad("rate 0", scope("rate_per_sec", "0"), uuid.New(), "x")
	bad("rate 101", scope("rate_per_sec", "101"), uuid.New(), "x")
	bad("concurrency 0", scope("concurrency", "0"), uuid.New(), "x")
	bad("concurrency 65", scope("concurrency", "65"), uuid.New(), "x")
	bad("schedule 0", scope("schedule_hours", "0"), uuid.New(), "x")
	bad("schedule 169", scope("schedule_hours", "169"), uuid.New(), "x")
	bad("window without a schedule", scope("window_start, window_end", "'01:00', '05:00'"), uuid.New(), "x")
	bad("window start only", scope("schedule_hours, window_start", "24, '01:00'"), uuid.New(), "x")
	bad("empty window", scope("schedule_hours, window_start, window_end", "24, '01:00', '01:00'"), uuid.New(), "x")
	bad("time zone with a space", scope("window_tz", "'Europe/ Istanbul'"), uuid.New(), "x")
	_, err = d.App.Exec(ctx, scope("schedule_hours, window_start, window_end, window_tz, rate_per_sec, concurrency, sni_names",
		"168, '22:00', '04:00', 'Europe/Istanbul', 100, 64, '{www.corp.example,xn--bcher-kva.example}'"), uuid.New(), "Full")
	require.NoError(t, err, "the limits themselves are allowed")

	// Names are unique among live scopes, case-insensitively; a deleted scope's name is free again.
	_, err = d.App.Exec(ctx, discoveryScope, uuid.New(), "office lan")
	assert.Equal(t, uniqueViolation, sqlState(err))
	require.NoError(t, exec(t, d.App, "UPDATE discovery_scopes SET deleted_at = now() WHERE id = $1", w.scope))
	require.NoError(t, exec(t, d.App, discoveryScope, uuid.New(), "Office LAN"))

	// Scans.
	scan := `INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, finished_at, error_code, endpoints_total,
endpoints_answered, endpoints_failed, endpoints_excluded, requested_by) VALUES ($1, $2, $3, $4, now(), $5, $6, $7, $8, $9, $10, $11, $12)`
	other := uuid.New()
	require.NoError(t, exec(t, d.App, discoveryScope, other, "Other"))
	type scanRow struct {
		trigger, state     string
		started, finished  any
		code               string
		total, ans, f, exc int
		by                 any
	}
	now := "2026-10-14T10:00:00Z"
	for name, r := range map[string]scanRow{
		"unknown trigger":         {"cron", "done", now, now, "", 0, 0, 0, 0, nil},
		"unknown state":           {"manual", "paused", now, now, "", 0, 0, 0, 0, nil},
		"queued with a start":     {"manual", "queued", now, nil, "", 0, 0, 0, 0, nil},
		"running without a start": {"manual", "running", nil, nil, "", 0, 0, 0, 0, nil},
		"running and finished":    {"manual", "running", now, now, "", 0, 0, 0, 0, nil},
		"done without an end":     {"manual", "done", now, nil, "", 0, 0, 0, 0, nil},
		"failed without a code":   {"manual", "failed", now, now, "", 0, 0, 0, 0, nil},
		"code with a space":       {"manual", "failed", now, now, "no tls", 0, 0, 0, 0, nil},
		"more answers than total": {"manual", "done", now, now, "", 2, 2, 1, 0, nil},
		"over 20000 endpoints":    {"manual", "done", now, now, "", 20001, 0, 0, 0, nil},
		"negative count":          {"manual", "done", now, now, "", 1, -1, 0, 0, nil},
		"ended before it started": {"manual", "done", now, "2026-10-14T09:00:00Z", "", 0, 0, 0, 0, nil},
		"queued with a code":      {"manual", "queued", nil, nil, "discovery.scan_interrupted", 0, 0, 0, 0, nil},
		"running with a code":     {"manual", "running", now, nil, "discovery.scan_interrupted", 0, 0, 0, 0, nil},
		"done with a code":        {"manual", "done", now, now, "discovery.scan_timed_out", 0, 0, 0, 0, nil},
	} {
		bad(name, scan, uuid.New(), other, r.trigger, r.state, r.started, r.finished, r.code, r.total, r.ans, r.f, r.exc, r.by)
	}
	// One scan per scope at a time (queued or running): the seeded scope has a running one.
	_, err = d.App.Exec(ctx, `INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at) VALUES ($1, $2, 'manual', 'queued', now())`,
		uuid.New(), w.scope)
	assert.Equal(t, uniqueViolation, sqlState(err), "one scan per scope at a time")
	require.NoError(t, exec(t, d.App, `INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at) VALUES ($1, $2, 'manual', 'queued', now())`,
		uuid.New(), other), "another scope may scan at the same time")

	// Certificates.
	cert := func(over map[string]any) map[string]any {
		return with(map[string]any{"fingerprint_sha256": hex64("1"), "is_leaf": true, "subject_cn": "a", "issuer_cn": "b",
			"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "key_algorithm": "ecdsa",
			"pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", "first_seen": now, "last_seen": now}, over)
	}
	for name, over := range map[string]map[string]any{
		"upper-case fingerprint": {"fingerprint_sha256": strings.Repeat("A", 64)},
		"short fingerprint":      {"fingerprint_sha256": "abc"},
		"unknown key algorithm":  {"key_algorithm": "dsa"},
		"not a PEM":              {"pem": "MIIB"},
		"PEM over 16 KiB DER":    {"pem": "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 22600) + "\n-----END CERTIFICATE-----\n"},
		"too many SANs":          {"sans": manyStrings(1001)},
		"long subject":           {"subject_cn": strings.Repeat("a", 1025)},
		"ends before it starts":  {"not_after": "2025-01-01T00:00:00Z"},
		"last seen before first": {"last_seen": "2026-10-13T10:00:00Z"},
	} {
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "discovery_certificates", cert(over))), name)
	}
	require.NoError(t, insertRow(t, d.App, "discovery_certificates", cert(nil)))

	// Endpoints: the closed sets, the states' consistency, host and SNI syntax.
	ep := func(over map[string]any) map[string]any {
		return with(map[string]any{"id": uuid.New(), "scope_id": other, "address": "10.0.0.2", "port": 443, "state": "unreachable",
			"last_error_code": "timeout", "first_seen": now, "last_scanned_at": now}, over)
	}
	for name, over := range map[string]map[string]any{
		"unknown state":              {"state": "down"},
		"unknown error":              {"last_error_code": "dial tcp 10.0.0.2:443: i/o timeout"},
		"a Go error string":          {"last_error_code": "EOF"},
		"port 0":                     {"port": 0},
		"port 65536":                 {"port": 65536},
		"a network, not an address":  {"address": "10.0.0.0/24"},
		"upper-case SNI":             {"sni": "WWW.example"},
		"SNI with a newline":         {"sni": "a.example\n"},
		"host with a space":          {"host": "a b"},
		"present without a cert":     {"state": "present", "last_error_code": ""},
		"present with an error":      {"state": "present", "fingerprint_sha256": hex64("1"), "last_error_code": "timeout"},
		"excluded without policy":    {"state": "excluded", "last_error_code": "timeout"},
		"malformed without its code": {"state": "malformed", "last_error_code": "timeout"},
		"no_tls without its code":    {"state": "no_tls", "last_error_code": "refused"},
		"unreachable without reason": {"last_error_code": ""},
		"unreachable by policy":      {"last_error_code": "policy"},
		"gone without its time":      {"state": "gone"},
		"time gone while present":    {"state": "present", "fingerprint_sha256": hex64("1"), "last_error_code": "", "gone_since": now},
		"negative misses":            {"missed_scans": -1},
		"six previous fingerprints":  {"previous_fingerprints": []string{hex64("1"), hex64("2"), hex64("3"), hex64("4"), hex64("5"), hex64("6")}},
		"a previous non-fingerprint": {"previous_fingerprints": []string{"zz"}},
		"ten intermediates":          {"chain_fingerprints": []string{hex64("1"), hex64("1"), hex64("1"), hex64("1"), hex64("1"), hex64("1"), hex64("1"), hex64("1"), hex64("1"), hex64("1")}},
		"a chain digest not hex":     {"chain_sha256": "x"},
		"unknown TLS version":        {"tls_version": "SSL 3.0"},
		"cipher with a space":        {"cipher": "TLS AES"},
	} {
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "discovery_endpoints", ep(over))), name)
	}
	for name, over := range map[string]map[string]any{
		"unreachable":  nil,
		"excluded":     {"address": "10.0.0.3", "state": "excluded", "last_error_code": "policy"},
		"malformed":    {"address": "10.0.0.4", "state": "malformed", "last_error_code": "malformed"},
		"no TLS":       {"address": "10.0.0.5", "state": "no_tls", "last_error_code": "no_tls"},
		"gone":         {"address": "10.0.0.6", "state": "gone", "last_error_code": "", "gone_since": now},
		"chain size":   {"address": "10.0.0.7", "last_error_code": "chain_too_large"},
		"IPv6 by name": {"address": "2001:db8::1", "host": "www.corp.example", "sni": "www.corp.example", "state": "present", "last_error_code": "", "fingerprint_sha256": hex64("1")},
	} {
		require.NoError(t, insertRow(t, d.App, "discovery_endpoints", ep(over)), name)
	}
	assert.Equal(t, "23503", sqlState(insertRow(t, d.App, "discovery_endpoints", ep(map[string]any{"address": "10.0.0.8", "state": "present",
		"last_error_code": "", "fingerprint_sha256": hex64("9")}))), "an endpoint presents a stored certificate")
}

// A4: sni is NOT NULL DEFAULT ”, so scanning the same SNI-less endpoint twice (an upsert on the unique key) keeps
// one row; an SNI name makes a row of its own.
func TestDiscoveryEndpointUpsertKeepsOneRow(t *testing.T) {
	d := pgtest.New(t)
	w := seedDiscovery(t, d)
	ctx := context.Background()
	upsert := `INSERT INTO discovery_endpoints (id, scope_id, address, port, state, last_error_code, first_seen, last_scanned_at)
VALUES ($1, $2, $3, 443, 'unreachable', 'timeout', now(), now())
ON CONFLICT (scope_id, address, port, sni) DO UPDATE SET missed_scans = discovery_endpoints.missed_scans + 1, last_scanned_at = EXCLUDED.last_scanned_at`
	for range 2 {
		require.NoError(t, exec(t, d.App, upsert, uuid.New(), w.scope, "10.0.0.2"))
	}
	var n, missed int
	require.NoError(t, d.App.QueryRow(ctx, "SELECT count(*), max(missed_scans) FROM discovery_endpoints WHERE address = '10.0.0.2'").Scan(&n, &missed))
	assert.Equal(t, 1, n, "a second scan finds the same row")
	assert.Equal(t, 1, missed)
	var sni string
	require.NoError(t, d.App.QueryRow(ctx, "SELECT sni FROM discovery_endpoints WHERE address = '10.0.0.2'").Scan(&sni))
	assert.Equal(t, "", sni)
	require.NoError(t, exec(t, d.App, `INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, state, last_error_code, first_seen, last_scanned_at)
VALUES ($1, $2, '10.0.0.2', 443, 'www.corp.example', 'unreachable', 'timeout', now(), now())`, uuid.New(), w.scope))
	_, err := d.App.Exec(ctx, `INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, state, last_error_code, first_seen, last_scanned_at)
VALUES ($1, $2, '10.0.0.2', 443, 'www.corp.example', 'unreachable', 'timeout', now(), now())`, uuid.New(), w.scope)
	assert.Equal(t, uniqueViolation, sqlState(err))
	_, err = d.App.Exec(ctx, `INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, state, last_error_code, first_seen, last_scanned_at)
VALUES ($1, $2, '10.0.0.2', 443, NULL, 'unreachable', 'timeout', now(), now())`, uuid.New(), w.scope)
	assert.Equal(t, "23502", sqlState(err), "no NULL SNI that would escape the unique key")
}

// Identity columns are fixed at INSERT (column grants); a scope is never deleted; a finished scan is history (Z1020) and
// only finished scans are deleted.
func TestDiscoveryImmutableColumnsAndHistory(t *testing.T) {
	d := pgtest.New(t)
	w := seedDiscovery(t, d)
	ctx := context.Background()
	for _, stmt := range []string{
		"UPDATE discovery_scopes SET created_by = NULL",
		"UPDATE discovery_scopes SET created_at = now()",
		"UPDATE discovery_scopes SET id = gen_random_uuid()",
		"DELETE FROM discovery_scopes",
		"UPDATE discovery_scans SET scope_id = scope_id",
		"UPDATE discovery_scans SET trigger = 'manual'",
		"UPDATE discovery_scans SET queued_at = now()",
		"UPDATE discovery_scans SET requested_by = NULL",
		"UPDATE discovery_certificates SET pem = pem",
		"UPDATE discovery_certificates SET not_after = now()",
		"UPDATE discovery_certificates SET subject_cn = 'x'",
		"UPDATE discovery_certificates SET first_seen = now()",
		"UPDATE discovery_endpoints SET scope_id = scope_id",
		"UPDATE discovery_endpoints SET address = '10.9.9.9'",
		"UPDATE discovery_endpoints SET port = 8443",
		"UPDATE discovery_endpoints SET sni = 'x.example'",
		"UPDATE discovery_endpoints SET host = 'x.example'",
		"UPDATE discovery_endpoints SET first_seen = now()",
		"TRUNCATE discovery_endpoints",
	} {
		_, err := d.App.Exec(ctx, stmt)
		assert.Equal(t, privilegeDenied, sqlState(err), stmt)
	}
	// What the scanner, the API and retention write.
	for _, stmt := range []string{
		"UPDATE discovery_scopes SET name = 'Office', entries = '[\"10.0.1.0/24\"]', ports = '{443,8443}', sni_names = '{a.example}', exclusions = '[\"10.0.1.1\"]', enabled = false, schedule_hours = 12, window_start = '01:00', window_end = '02:00', window_tz = 'UTC', alert_on_expiry = true, rate_per_sec = 50, concurrency = 8, last_scheduled_at = now(), version = version + 1, updated_at = now()",
		"UPDATE discovery_scans SET cancel_requested = true, endpoints_total = 4, endpoints_answered = 2, endpoints_failed = 1, endpoints_excluded = 1, certificates_new = 1, cert_churn = 0 WHERE state = 'running'",
		"UPDATE discovery_certificates SET last_seen = now(), is_leaf = true",
		"UPDATE discovery_endpoints SET fingerprint_sha256 = NULL, chain_fingerprints = '{}', chain_sha256 = '', tls_version = '', cipher = '', state = 'gone', gone_since = now(), last_error_code = 'timeout', missed_scans = 3, last_seen = now(), last_scanned_at = now(), last_scan_id = NULL, previous_fingerprints = ARRAY[fingerprint_sha256]",
	} {
		require.NoError(t, exec(t, d.App, stmt), stmt)
	}

	_, err := d.App.Exec(ctx, "UPDATE discovery_scans SET endpoints_answered = 0 WHERE id = $1", w.done)
	assert.Equal(t, scanFrozen, sqlState(err), "a finished scan's counts never change")
	_, err = d.App.Exec(ctx, "UPDATE discovery_scans SET state = 'running', finished_at = NULL WHERE id = $1", w.done)
	assert.Equal(t, scanFrozen, sqlState(err), "a finished scan never runs again")
	_, err = d.App.Exec(ctx, "DELETE FROM discovery_scans WHERE id = $1", w.running)
	assert.Equal(t, scanFrozen, sqlState(err), "a scan in flight is not deleted")
	require.NoError(t, exec(t, d.App, "UPDATE discovery_scans SET state = 'cancelled', finished_at = now() WHERE id = $1", w.running))
	require.NoError(t, exec(t, d.App, "DELETE FROM discovery_scans WHERE id = $1", w.done), "an old finished scan is pruned")

	// A certificate an endpoint presents is kept by the foreign key; an orphan is deleted.
	require.NoError(t, exec(t, d.App, "UPDATE discovery_endpoints SET fingerprint_sha256 = $1, state = 'present', gone_since = NULL, last_error_code = '' WHERE id = $2", w.leaf, w.endpoint))
	_, err = d.App.Exec(ctx, "DELETE FROM discovery_certificates WHERE fingerprint_sha256 = $1", w.leaf)
	assert.Equal(t, "23503", sqlState(err))
	require.NoError(t, exec(t, d.App, "DELETE FROM discovery_certificates WHERE fingerprint_sha256 = $1", w.inter))
	require.NoError(t, exec(t, d.App, "DELETE FROM discovery_endpoints WHERE id = $1", w.endpoint))
}

// The discovery settings (A2, design decision 3): an absent row means the default (no exclusions, 90 days, no network
// may be scanned); a stored row has the fixed shape and range.
func TestDiscoverySettingsAreChecked(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	set := `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`
	for _, c := range []struct{ key, value string }{
		{"discovery.retention_days", "6"},
		{"discovery.retention_days", "731"},
		{"discovery.retention_days", "30.5"},
		{"discovery.retention_days", `"30"`},
		{"discovery.exclusions", `"10.0.0.0/8"`},
		{"discovery.exclusions", `[` + strings.Repeat(`"10.0.0.1",`, 256) + `"10.0.0.1"]`},
		{"discovery.allowed_networks", `{}`},
		{"discovery.allowed_networks", `[` + strings.Repeat(`"10.0.0.0/24",`, 256) + `"10.0.0.0/24"]`},
		{"discovery.allowed_networks", `[1]`},
	} {
		_, err := d.App.Exec(ctx, set, c.key, c.value)
		assert.Equal(t, checkViolation, sqlState(err), "%s = %s", c.key, c.value)
	}
	for _, c := range []struct{ key, value string }{
		{"discovery.retention_days", "7"},
		{"discovery.retention_days", "730"},
		{"discovery.exclusions", `[]`},
		{"discovery.exclusions", `["192.0.2.0/24", "198.51.100.7"]`},
		{"discovery.allowed_networks", `["10.89.0.0/24"]`},
	} {
		require.NoError(t, exec(t, d.App, set, c.key, c.value), "%s = %s", c.key, c.value)
	}
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT count(*) FROM settings WHERE key LIKE 'discovery.%'").Scan(&n))
	assert.Equal(t, 3, n)
}

// Keyset pagination and the "unmanaged" join have their indexes.
func TestDiscoveryIndexes(t *testing.T) {
	d := pgtest.New(t)
	rows, err := d.Owner.Query(context.Background(), `SELECT indexname, indexdef FROM pg_indexes WHERE tablename LIKE 'discovery\_%'`)
	require.NoError(t, err)
	defer rows.Close()
	defs := map[string]string{}
	for rows.Next() {
		var n, def string
		require.NoError(t, rows.Scan(&n, &def))
		defs[n] = def
	}
	require.NoError(t, rows.Err())
	assert.Contains(t, defs["discovery_scopes_name"], "(name) WHERE (deleted_at IS NULL)")
	assert.Contains(t, defs["discovery_scans_one_active"], "(scope_id) WHERE (state = ANY (ARRAY['queued'::text, 'running'::text]))")
	assert.Contains(t, defs["discovery_scans_scope"], "(scope_id, queued_at DESC, id DESC)")
	assert.Contains(t, defs["discovery_scans_list"], "(queued_at DESC, id DESC)")
	assert.Contains(t, defs["discovery_certificates_expiry"], "(not_after, fingerprint_sha256) WHERE is_leaf")
	assert.Contains(t, defs["discovery_certificates_last_seen"], "(last_seen)")
	assert.Contains(t, defs["discovery_endpoints_key"], "UNIQUE INDEX discovery_endpoints_key ON public.discovery_endpoints USING btree (scope_id, address, port, sni)")
	assert.Contains(t, defs["discovery_endpoints_list"], "(address, port, sni, id)")
	assert.Contains(t, defs["discovery_endpoints_fingerprint"], "(fingerprint_sha256)")
	assert.Contains(t, defs["discovery_endpoints_chain"], "gin (chain_fingerprints)")
	assert.Contains(t, defs["discovery_endpoints_gone"], "(gone_since) WHERE (state = 'gone'::text)")
	assert.Contains(t, defs["discovery_endpoints_last_scan"], "(last_scan_id) WHERE (last_scan_id IS NOT NULL)")
	var host string
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT indexdef FROM pg_indexes WHERE indexname = 'discovery_targets_host'`).Scan(&host))
	assert.Contains(t, host, "ON public.targets USING btree (lower((config ->> 'host'::text))) WHERE (deleted_at IS NULL)")
}

func TestDiscoveryTablesHaveNoClockDefaults(t *testing.T) {
	d := pgtest.New(t)
	rows, err := d.Owner.Query(context.Background(), `SELECT table_name, column_name, column_default FROM information_schema.columns
WHERE table_schema = 'public' AND table_name LIKE 'discovery\_%' AND column_default IS NOT NULL`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var table, col, def string
		require.NoError(t, rows.Scan(&table, &col, &def))
		assert.NotContains(t, def, "now()", "%s.%s: the application passes the clock's time", table, col)
		assert.NotContains(t, def, "CURRENT_TIMESTAMP", "%s.%s", table, col)
	}
	require.NoError(t, rows.Err())
}

// The Down drops the discovery tables, functions and the settings CHECK and leaves 00013's grants; the Up goes through again.
func TestMigration00014DownAndUpAgain(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	seedDiscovery(t, d)
	require.NoError(t, exec(t, d.App, `INSERT INTO settings (key, value, updated_at) VALUES ('discovery.retention_days', '30', now())`))
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 13)
	require.NoError(t, err)
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(13), version)
	for _, tbl := range discoveryTables {
		assert.False(t, tableExists(t, d, tbl), tbl)
	}
	var fn, con int
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT count(*) FROM pg_proc WHERE proname LIKE 'discovery\\_%'").Scan(&fn))
	assert.Zero(t, fn, "the Down drops the discovery functions")
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT count(*) FROM pg_constraint WHERE conname LIKE 'settings_discovery%'").Scan(&con))
	assert.Zero(t, con, "the Down drops the settings CHECK")
	var idx int
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT count(*) FROM pg_indexes WHERE indexname LIKE 'discovery\\_%'").Scan(&idx))
	assert.Zero(t, idx, "the Down drops every discovery index, the one on targets included")
	var settingsLeft int
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT count(*) FROM settings WHERE key LIKE 'discovery.%'").Scan(&settingsLeft))
	assert.Zero(t, settingsLeft, "the Down deletes the discovery settings with the data they governed")
	require.NoError(t, exec(t, d.App, `INSERT INTO settings (key, value, updated_at) VALUES ('discovery.retention_days', '1', now())`),
		"no discovery rule is left")
	assert.Empty(t, grantProblems(t, d), "the Down leaves 00013's grants as they were")
	require.NoError(t, exec(t, d.App, `DELETE FROM settings WHERE key = 'discovery.retention_days'`))

	// Down, then Up again with a stored setting: the Down removes it, so the Up's CHECKs cannot meet an edited value.
	require.NoError(t, exec(t, d.App, `INSERT INTO settings (key, value, updated_at) VALUES ('discovery.allowed_networks', '["10.0.0.0/24"]', now())`))
	_, err = p.Up(ctx)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 13)
	require.NoError(t, err)
	_, err = p.Up(ctx)
	require.NoError(t, err)
	for _, tbl := range discoveryTables {
		assert.True(t, tableExists(t, d, tbl), tbl)
	}
	assert.Empty(t, grantProblems(t, d))
}
