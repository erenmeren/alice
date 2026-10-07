//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/csvx"
	"alice/internal/reports"
	"alice/internal/testutil/seed"
)

// Phase 7 over the wire (Task 16): the dashboard's counts equal the rows its links open, every export equals the list
// it was made from, and the mail settings, recipients, thresholds and the delivery state behave as F-60..F-63 say,
// against the stack's fake mail server.

// listAll reads every page of a list (limit 200, following next_cursor) and returns its items in order.
func listAll(t *testing.T, c *client, path string) []map[string]any {
	t.Helper()
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	var out []map[string]any
	cursor := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 1000, "%s does not end", path)
		p := path + sep + "limit=200"
		if cursor != "" {
			p += "&cursor=" + url.QueryEscape(cursor)
		}
		rec := c.do(http.MethodGet, p, nil)
		requireStatus(t, rec, http.StatusOK)
		page := decodeBody[struct {
			Items      []map[string]any `json:"items"`
			NextCursor *string          `json:"next_cursor"`
		}](t, rec)
		out = append(out, page.Items...)
		if page.NextCursor == nil || *page.NextCursor == "" {
			return out
		}
		cursor = *page.NextCursor
	}
}

func field(items []map[string]any, key string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		v, _ := it[key].(string)
		out = append(out, v)
	}
	return out
}

// dashboardBody is the part of DashboardSummary the tests compare.
type dashboardBody struct {
	Certificates map[string]int `json:"certificates"`
	Targets      struct {
		Total    int            `json:"total"`
		ByStatus map[string]int `json:"by_status"`
	} `json:"targets"`
	Deployments struct {
		Failed7d int `json:"failed_7d"`
		Recent   []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"recent"`
	} `json:"deployments"`
	License struct {
		Phase string `json:"phase"`
	} `json:"license"`
	Notifications *struct {
		Failing bool `json:"failing"`
	} `json:"notifications"`
	Audit *struct {
		HeadSeq int64 `json:"head_seq"`
	} `json:"audit"`
}

// §26.9 "dashboard API tests with seeded data (exact counts)", over HTTP for each role: every card equals the rows the
// list it links to shows (cumulative windows, C17 as amended: 4/7/8), the server and deployment counts equal their
// lists, and each role sees only its parts.
func TestDashboardOverTheWire(t *testing.T) {
	s, admin, adminAcct := installed(t)
	ctx := context.Background()
	now := s.clock.Now()
	want, err := seed.Dashboard(ctx, s.db.Owner, now)
	require.NoError(t, err)
	require.Equal(t, map[string]int{"monitored": 8, "expired": 1, "within_7": 4, "within_30": 7, "within_60": 8}, want.Certificates)

	olga := s.createUser(admin, adminAcct, "olga", "operator", operatorPassword)
	aud := s.createUser(admin, adminAcct, "audrey", "auditor", operatorPassword)
	op, au := s.client("198.51.100.60"), s.client("198.51.100.61")
	s.firstSignIn(op, olga)
	s.firstSignIn(au, aud)
	// The audit head is shown from the first checkpoint on.
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/audit/verify", nil), http.StatusOK)

	for _, who := range []struct {
		name                  string
		c                     *client
		notifications, audits bool
		phase                 bool
	}{{"admin", admin, true, true, true}, {"operator", op, false, false, false}, {"auditor", au, false, true, true}} {
		rec := who.c.do(http.MethodGet, "/api/v1/dashboard/summary", nil)
		requireStatus(t, rec, http.StatusOK)
		got := decodeBody[dashboardBody](t, rec)
		for k, v := range want.Certificates {
			assert.Equal(t, v, got.Certificates[k], "%s: %s", who.name, k)
		}
		assert.Zero(t, got.Certificates["kv_expired"], who.name)
		assert.Zero(t, got.Certificates["kv_within_30"], who.name)

		// Each certificate card equals the rows its link (/certificates?expiry=…) opens.
		for card, expiry := range map[string]string{"expired": "expired", "within_7": "7", "within_30": "30", "within_60": "60"} {
			assert.Len(t, listAll(t, who.c, "/api/v1/certificates?expiry="+expiry), got.Certificates[card], "%s: %s", who.name, card)
		}
		monitored := 0
		for _, c := range listAll(t, who.c, "/api/v1/certificates") {
			if c["location_count"].(float64) > 0 {
				monitored++
			}
		}
		assert.Equal(t, monitored, got.Certificates["monitored"], who.name)

		// The servers card equals the server list; each status count equals the servers with that status.
		targets := listAll(t, who.c, "/api/v1/targets")
		assert.Equal(t, want.Targets["total"], got.Targets.Total, who.name)
		assert.Len(t, targets, got.Targets.Total, who.name)
		byStatus := map[string]int{}
		for _, tg := range targets {
			byStatus[tg["status"].(string)]++
		}
		for status, n := range got.Targets.ByStatus {
			assert.Equal(t, byStatus[status], n, "%s: %s", who.name, status)
		}
		for status, n := range byStatus {
			assert.Equal(t, n, got.Targets.ByStatus[status], "%s: %s", who.name, status)
		}
		assert.Equal(t, want.Targets["host_key_changed"], got.Targets.ByStatus["host_key_changed"], who.name)
		assert.Equal(t, want.Targets["ok"], got.Targets.ByStatus["ok"], who.name)

		// The failed deployments of the last 7 days equal the deployment list's failed rows of that window.
		failed := 0
		for _, d := range listAll(t, who.c, "/api/v1/deployments") {
			at, err := time.Parse(time.RFC3339Nano, d["finished_at"].(string))
			require.NoError(t, err)
			if d["status"] == "failed" && !at.Before(now.Add(-7*24*time.Hour)) {
				failed++
			}
		}
		assert.Equal(t, want.Deployments["failed_7d"], got.Deployments.Failed7d, who.name)
		assert.Equal(t, failed, got.Deployments.Failed7d, who.name)
		require.Len(t, got.Deployments.Recent, 1, who.name)
		assert.Equal(t, "failed", got.Deployments.Recent[0].Status)

		// What each role sees (R42 row 13).
		assert.Equal(t, who.notifications, got.Notifications != nil, "%s: notifications", who.name)
		assert.Equal(t, who.audits, got.Audit != nil, "%s: audit", who.name)
		assert.Equal(t, who.phase, got.License.Phase != "", "%s: license phase", who.name)
		if !who.notifications {
			assert.Contains(t, rec.Body.String(), `"notifications":null`, who.name)
		}

		rec = who.c.do(http.MethodGet, "/api/v1/dashboard/expiring?days=30", nil)
		requireStatus(t, rec, http.StatusOK)
		items := decodeBody[struct {
			Items []struct {
				Name     string `json:"name"`
				Kind     string `json:"kind"`
				Expired  bool   `json:"expired"`
				DaysLeft int    `json:"days_left"`
				Websites []any  `json:"websites"`
				Servers  []any  `json:"servers"`
			} `json:"items"`
		}](t, rec).Items
		var names []string
		for _, it := range items {
			names = append(names, it.Name)
			assert.Equal(t, it.Name == "old.seed.test", it.Expired, "%s: %s expired (S2 AC3)", who.name, it.Name)
		}
		assert.Equal(t, want.Expiring30, names, who.name)
		require.NotEmpty(t, items)
		assert.True(t, items[0].Expired, "expired ones come first and are marked (S2 AC3)")
		assert.Zero(t, items[0].DaysLeft)
		// "www.seed.test" is the website the location serves (owner step 2).
		for _, it := range items {
			if it.Name == "www.seed.test" {
				assert.Contains(t, asJSON(t, it.Websites), "www.seed.test")
				assert.Contains(t, asJSON(t, it.Servers), "seed-web-1")
			}
		}
	}

	// The dashboard is a read: it works for every role, and an anonymous caller gets nothing.
	requireError(t, s.freshClient().do(http.MethodGet, "/api/v1/dashboard/summary", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
}

// The Key Vault line counts Key Vault keys and client secrets (Task 9 amendment); each equals what the vault pages show:
// the keys' expiry on each vault's key list and the client secret's expiry on the vault.
func TestDashboardKeyVaultLineOverTheWire(t *testing.T) {
	s, admin, _ := installed(t)
	ctx := context.Background()
	now := s.clock.Now()
	day := 24 * time.Hour
	expiredSecret, soonSecret := now.Add(-day), now.Add(10*day)
	v1, err := seed.Target(ctx, s.db.Owner, "seed-vault-1", "azure_key_vault", "ok", &expiredSecret)
	require.NoError(t, err)
	v2, err := seed.Target(ctx, s.db.Owner, "seed-vault-2", "azure_key_vault", "ok", &soonSecret)
	require.NoError(t, err)
	_, err = seed.Target(ctx, s.db.Owner, "seed-vault-3", "azure_key_vault", "ok", nil) // no client secret expiry
	require.NoError(t, err)
	for _, k := range []struct {
		vault       uuid.UUID
		name        string
		cert, key   time.Duration
		disableKey  bool
		missingKey  bool
		description string
	}{
		{v1, "a", 5 * day, -3 * day, false, false, "an expired key"},
		{v1, "b", 100 * day, 20 * day, false, false, "a key within 30 days"},
		{v2, "c", -day, 200 * day, false, false, "a key far away (an expired vault certificate is not a key)"},
		{v2, "d", 100 * day, 2 * day, true, false, "a disabled key"},
		{v2, "e", 100 * day, 3 * day, false, true, "a missing key"},
	} {
		_, keyID, err := seed.KeyVault(ctx, s.db.Owner, k.vault, "cert-"+k.name, now.Add(k.cert), nil, "key-"+k.name, now.Add(k.key))
		require.NoError(t, err, k.description)
		if k.disableKey {
			_, err = s.db.Owner.Exec(ctx, `UPDATE kv_keys SET enabled = false WHERE id = $1`, keyID)
			require.NoError(t, err)
		}
		if k.missingKey {
			_, err = s.db.Owner.Exec(ctx, `UPDATE kv_keys SET missing_since = $2 WHERE id = $1`, keyID, now)
			require.NoError(t, err)
		}
	}

	got := decodeBody[dashboardBody](t, admin.do(http.MethodGet, "/api/v1/dashboard/summary", nil))
	// What the vault pages show: each vault's client secret expiry and its live, enabled keys' expiry.
	var expired, within30 int
	count := func(at time.Time) {
		if !at.After(now) {
			expired++
		}
		if at.Before(now.Add(30 * day)) {
			within30++
		}
	}
	vaults := listAll(t, admin, "/api/v1/targets?type=azure_key_vault")
	require.Len(t, vaults, 3)
	for _, v := range vaults {
		vault := v["vault"].(map[string]any)
		if raw, ok := vault["secret_expires_on"].(string); ok {
			at, err := time.Parse(time.RFC3339, raw)
			require.NoError(t, err)
			count(at)
		}
		for _, k := range listAll(t, admin, "/api/v1/targets/"+v["id"].(string)+"/kv/keys") {
			if k["enabled"] == true && k["missing_since"] == nil && k["expires"] != nil {
				at, err := time.Parse(time.RFC3339, k["expires"].(string))
				require.NoError(t, err)
				count(at)
			}
		}
	}
	assert.Equal(t, 2, expired, "the expired client secret and the expired key")
	assert.Equal(t, 4, within30, "both client secrets and the two keys within 30 days")
	assert.Equal(t, expired, got.Certificates["kv_expired"])
	assert.Equal(t, within30, got.Certificates["kv_within_30"])
	// The certificate cards are not changed by Key Vault certificates that are no certificate rows.
	assert.Zero(t, got.Certificates["expired"])
}

// asJSON is in keyvault_wire_integration_test.go.

// csvRows checks the download headers and the BOM of an export answer and returns its records.
func csvRows(t *testing.T, rec *httptest.ResponseRecorder, kind string, now time.Time) [][]string {
	t.Helper()
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="alice-`+kind+`-`+now.UTC().Format("2006-01-02")+`.csv"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	body := rec.Body.Bytes()
	require.True(t, bytes.HasPrefix(body, []byte("\xEF\xBB\xBF")), "the export starts with the UTF-8 BOM")
	rows, err := csv.NewReader(bytes.NewReader(body[3:])).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	return rows
}

// seedExportRows adds n uploaded certificates on seed-web-2 and n SSH keys on seed-web-1 and seed-web-2, some of
// whose texts start like a spreadsheet formula, so every export spans several list pages (200 rows) and exercises
// csvx's escaping.
func seedExportRows(t *testing.T, s *stack, n int) {
	t.Helper()
	ctx := context.Background()
	_, err := s.db.Owner.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
SELECT gen_random_uuid(), encode(sha256(('fp' || i)::bytea), 'hex'),
       (ARRAY['=HYPERLINK("http://evil")', '+cmd', '-2+3', '@SUM(A1)', 'bulk'])[1 + i % 5] || '-' || i || '.export.test',
       $1::timestamptz - interval '90 days', $1::timestamptz + (i % 90) * interval '1 day', 'ecdsa',
       encode(sha256(('pk' || i)::bytea), 'hex'), '', 'uploaded', now(), now(), now()
FROM generate_series(1, $2::int) AS i`, s.clock.Now(), n)
	require.NoError(t, err)
	_, err = s.db.Owner.Exec(ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported,
servers, first_seen_at, last_seen_at)
SELECT gen_random_uuid(), t.id, 'nginx_file', '/etc/nginx/ssl/' || c.id || '.crt', '/etc/nginx/ssl/' || c.id || '.key', c.id, true, '[]',
       now(), now()
FROM certificates c, targets t WHERE c.subject_cn LIKE '%.export.test' AND t.name = 'seed-web-2'`)
	require.NoError(t, err)
	_, err = s.db.Owner.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, first_seen_at, created_at)
SELECT gen_random_uuid(), 'SHA256:' || substr(encode(sha256(('key' || i)::bytea), 'base64'), 1, 43), 'ssh-ed25519', 256,
       'ssh-ed25519 AAAA' || i, $1::timestamptz - (i * interval '1 minute'), now()
FROM generate_series(1, $2::int) AS i`, s.clock.Now(), n)
	require.NoError(t, err)
	_, err = s.db.Owner.Exec(ctx, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, comment, flags,
first_seen_at, last_seen_at)
SELECT gen_random_uuid(), k.id, t.id, CASE WHEN row_number() OVER () % 2 = 0 THEN 'root' ELSE 'deploy' END, '/home/x/.ssh/authorized_keys', 1,
       (ARRAY['=1+1 ops', 'plain ops', '@admin'])[1 + (row_number() OVER ())::int % 3],
       CASE WHEN row_number() OVER () % 4 = 0 THEN ARRAY['weak'] ELSE ARRAY[]::text[] END, now(), now()
FROM ssh_keys k, targets t WHERE k.public_key LIKE 'ssh-ed25519 AAAA%' AND t.name IN ('seed-web-1', 'seed-web-2')`)
	require.NoError(t, err)
}

// Review Focus 4, owner step 3: an export over HTTP has exactly the rows the list shows for the same filter, in the
// list's order, page by page, with every cell csvx-safe and one inventory.exported row naming the filter.
func TestExportOverTheWireEqualsFilteredRows(t *testing.T) {
	s, admin, _ := installed(t)
	ctx := context.Background()
	now := s.clock.Now()
	want, err := seed.Dashboard(ctx, s.db.Owner, now)
	require.NoError(t, err)
	seedExportRows(t, s, 230)
	var web1 string
	require.NoError(t, s.db.Owner.QueryRow(ctx, `SELECT id::text FROM targets WHERE name = 'seed-web-1'`).Scan(&web1))

	// The brief's case: one server and the 30-day window is C17's server filter.
	q := "?expiry=30&target_id=" + web1
	rows := csvRows(t, admin.do(http.MethodGet, "/api/v1/certificates/export"+q, nil), "certificates", now)
	var fromCSV []string
	for _, r := range rows[1:] {
		fromCSV = append(fromCSV, r[1])
	}
	assert.Equal(t, want.ServerFilter.Expiry30, fromCSV)
	assert.Equal(t, field(listAll(t, admin, "/api/v1/certificates"+q), "subject_cn"), fromCSV)

	certFilters := []string{"", "?expiry=30&target_id=" + web1, "?expiry=expired", "?expiry=7", "?expiry=60", "?q=export",
		"?q=seed&expiry=90", "?source=uploaded", "?source=discovered"}
	keyFilters := []string{"", "?target_id=" + web1, "?os_user=root", "?flag=weak", "?q=ops", "?missing=true"}
	header := map[string][]string{
		"certificates": {"id", "subject_cn", "label", "sans", "issuer", "serial", "not_before", "not_after", "days_left", "source",
			"key_algorithm", "key_bits", "self_signed", "chain_complete", "fingerprint", "location_count"},
		"ssh-keys": {"id", "fingerprint", "key_type", "bits", "comment", "managed", "platform_key", "weak", "location_count",
			"target_count", "missing", "retired", "first_seen_at"},
	}
	formulas := 0
	for _, x := range []struct {
		kind, list, label string
		filters           []string
		cell              map[string]string // CSV column -> list field
	}{
		{"certificates", "/api/v1/certificates", "certificates", certFilters, map[string]string{"id": "id", "subject_cn": "subject_cn"}},
		{"ssh-keys", "/api/v1/ssh-keys", "ssh_keys", keyFilters, map[string]string{"id": "id", "fingerprint": "fingerprint", "comment": "comment"}},
	} {
		for _, f := range x.filters {
			s.api.ResetLimits() // 10 exports a minute per user (limitExport) is tested elsewhere
			list := listAll(t, admin, x.list+f)
			seqBefore := s.maxAuditSeq()
			rows := csvRows(t, admin.do(http.MethodGet, "/api/v1/"+x.kind+"/export"+f, nil), x.kind, now)
			require.Equal(t, header[x.kind], rows[0], "%s%s header", x.kind, f)
			require.Len(t, rows[1:], len(list), "%s%s: the export has the list's rows", x.kind, f)
			for col, key := range x.cell {
				i := slices.Index(rows[0], col)
				for n, r := range rows[1:] {
					v, _ := list[n][key].(string)
					require.Equal(t, csvx.Safe(v), r[i], "%s%s row %d column %s", x.kind, f, n, col)
					if csvx.Safe(v) != v {
						formulas++
					}
				}
			}
			// Exactly one audit row, naming the kind and the filter given.
			require.Equal(t, seqBefore+1, s.maxAuditSeq(), "%s%s: one audit row", x.kind, f)
			var action string
			var details map[string]string
			var raw []byte
			require.NoError(t, s.db.Owner.QueryRow(ctx, `SELECT action, details FROM audit_log WHERE seq = $1`, seqBefore+1).Scan(&action, &raw))
			require.NoError(t, json.Unmarshal(raw, &details))
			assert.Equal(t, "inventory.exported", action)
			assert.Equal(t, x.label, details["kind"])
			assert.Equal(t, "csv", details["format"])
			assert.Equal(t, strconv.Itoa(len(list)), details["row_count"])
			vals, err := url.ParseQuery(strings.TrimPrefix(f, "?"))
			require.NoError(t, err)
			for k := range vals {
				assert.Equal(t, vals.Get(k), details[k], "%s%s: audit detail %s", x.kind, f, k)
			}
		}
	}
	assert.Greater(t, formulas, 100, "the seeded formula-like cells were escaped")
	all := listAll(t, admin, "/api/v1/certificates")
	assert.Greater(t, len(all), 200, "the unfiltered export spans more than one list page")
	assert.Greater(t, len(listAll(t, admin, "/api/v1/ssh-keys")), 200)

	// A refused export (a bad filter, a page parameter) writes and audits nothing.
	seq := s.maxAuditSeq()
	requireError(t, admin.do(http.MethodGet, "/api/v1/certificates/export?expiry=45", nil), http.StatusUnprocessableEntity, "ALC-SYS-0006")
	requireError(t, admin.do(http.MethodGet, "/api/v1/certificates/export?limit=10", nil), http.StatusUnprocessableEntity, "ALC-SYS-0006")
	requireError(t, admin.do(http.MethodGet, "/api/v1/ssh-keys/export?cursor=x", nil), http.StatusUnprocessableEntity, "ALC-SYS-0006")
	assert.Equal(t, seq, s.maxAuditSeq())
}

// blockingWriter is a client that reads nothing until it is released: the first byte of the answer blocks.
type blockingWriter struct {
	*httptest.ResponseRecorder
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.started)
		<-b.release
	})
	return b.ResponseRecorder.Write(p)
}

// rawGET sends a GET as c (its cookies and address) to a ResponseWriter of the caller's choice.
func (c *client) rawGET(path string, w http.ResponseWriter) {
	req := httptest.NewRequest(http.MethodGet, "https://alice.test"+path, nil)
	req.RemoteAddr = c.ip + ":40000"
	req.Header.Set("Accept", "text/csv")
	req.Header.Set(activityHeader, "1")
	for name, value := range c.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	c.s.handler.ServeHTTP(w, req)
}

// R42 row 16 and S-10 over the wire: the audit row is committed before the first byte; one export at a time per user
// (ALC-RPT-0004, retryable, Retry-After 5), while another user exports at the same time.
func TestExportAuditedBeforeTheFirstByteAndOneAtATime(t *testing.T) {
	s, admin, adminAcct := installed(t)
	_, err := seed.Dashboard(context.Background(), s.db.Owner, s.clock.Now())
	require.NoError(t, err)
	olga := s.createUser(admin, adminAcct, "olga", "operator", operatorPassword)
	op := s.client("198.51.100.62")
	s.firstSignIn(op, olga)

	before := s.countWhere("audit_log", "action = 'inventory.exported'")
	w := &blockingWriter{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		admin.rawGET("/api/v1/certificates/export", w)
	}()
	select {
	case <-w.started:
	case <-time.After(30 * time.Second):
		t.Fatal("the export never wrote")
	}
	// The first byte is being written: the audit row is already committed.
	assert.Equal(t, before+1, s.countWhere("audit_log", "action = 'inventory.exported'"), "audited before the first byte")

	// The same user cannot start a second export meanwhile, by either list.
	for _, path := range []string{"/api/v1/certificates/export", "/api/v1/ssh-keys/export"} {
		rec := admin.do(http.MethodGet, path, nil)
		requireError(t, rec, http.StatusConflict, "ALC-RPT-0004")
		assert.Equal(t, "5", rec.Header().Get("Retry-After"))
		e := decodeBody[map[string]map[string]any](t, rec)["error"]
		assert.Equal(t, true, e["retryable"])
	}
	// Another user can.
	rows := csvRows(t, op.do(http.MethodGet, "/api/v1/certificates/export", nil), "certificates", s.clock.Now())
	assert.Len(t, rows, 1+9)
	assert.Equal(t, before+2, s.countWhere("audit_log", "action = 'inventory.exported'"), "a refused export is not audited")

	close(w.release)
	<-done
	assert.Equal(t, http.StatusOK, w.Code)
	got, err := csv.NewReader(bytes.NewReader(w.Body.Bytes()[3:])).ReadAll()
	require.NoError(t, err)
	assert.Len(t, got, 1+9)
	// The slot is free again.
	csvRows(t, admin.do(http.MethodGet, "/api/v1/certificates/export", nil), "certificates", s.clock.Now())
}

// The 50,000-row cap (ALC-RPT-0001, params max) refuses before anything is written or audited; a narrower filter
// exports. HEAD on an export is 405 (ALC-SYS-0009) and runs nothing. The export limit is 10 a minute per user.
func TestExportCapHeadAndLimitOverTheWire(t *testing.T) {
	s, admin, _ := installed(t)
	ctx := context.Background()
	_, err := s.db.Owner.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
SELECT gen_random_uuid(), encode(sha256(('cap' || i)::bytea), 'hex'), CASE WHEN i <= 3 THEN 'narrow-' ELSE 'cap-' END || i || '.test',
       $1::timestamptz, $1::timestamptz + interval '400 days', 'ecdsa', encode(sha256(('cappk' || i)::bytea), 'hex'), '', 'uploaded',
       now(), now(), now()
FROM generate_series(1, $2::int) AS i`, s.clock.Now(), reports.MaxExportRows+1)
	require.NoError(t, err)

	seq := s.maxAuditSeq()
	rec := admin.do(http.MethodGet, "/api/v1/certificates/export", nil)
	requireError(t, rec, http.StatusConflict, "ALC-RPT-0001")
	assert.Equal(t, strconv.Itoa(reports.MaxExportRows), decodeBody[apiError](t, rec).Error.Params["max"])
	assert.NotContains(t, rec.Header().Get("Content-Type"), "text/csv")
	assert.Empty(t, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, seq, s.maxAuditSeq(), "a refused export is not audited")

	rows := csvRows(t, admin.do(http.MethodGet, "/api/v1/certificates/export?q=narrow", nil), "certificates", s.clock.Now())
	assert.Len(t, rows, 1+3)
	assert.Equal(t, seq+1, s.maxAuditSeq())

	// HEAD runs nothing (no audit row, no file) and names GET.
	for _, path := range []string{"/api/v1/certificates/export", "/api/v1/ssh-keys/export", "/api/v1/audit/export"} {
		rec := admin.do(http.MethodHead, path, nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, path)
		assert.Equal(t, "GET", rec.Header().Get("Allow"), path)
	}
	assert.Equal(t, seq+1, s.maxAuditSeq(), "HEAD wrote nothing")

	// 10 exports a minute per user; the 11th is 429 and is not audited.
	s.api.ResetLimits()
	for i := 0; i < 10; i++ {
		requireStatus(t, admin.do(http.MethodGet, "/api/v1/ssh-keys/export", nil), http.StatusOK)
	}
	seq = s.maxAuditSeq()
	requireError(t, admin.do(http.MethodGet, "/api/v1/ssh-keys/export", nil), http.StatusTooManyRequests, "ALC-SYS-0005")
	assert.Equal(t, seq, s.maxAuditSeq())
}

// fieldErrors maps each field of a 422 answer to its validation code.
func fieldErrors(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-SYS-0006")
	var body struct {
		Error struct {
			Details []struct {
				Field string `json:"field"`
				Code  string `json:"code"`
			} `json:"details"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	out := map[string]string{}
	for _, d := range body.Error.Details {
		out[d.Field] = d.Code
	}
	return out
}

// smtpView is the part of the SMTP answer the tests read.
type smtpView struct {
	Configured  bool `json:"configured"`
	HasPassword bool `json:"has_password"`
	Trusted     *struct {
		Fingerprint string `json:"fingerprint"`
		Subject     string `json:"subject"`
		TrustedBy   string `json:"trusted_by"`
	} `json:"trusted_certificate"`
}

// F-62 and F-63 over HTTP against the stack's fake mail server: the settings answer never carries the password; a user
// name needs a password; the untrusted certificate is shown with its fingerprint and only that certificate, seen on that
// server within the hour, can be trusted; wrong credentials, a refused recipient and an unreachable server each get
// their own code and no text of the server; the working settings deliver the test e-mail over TLS with AUTH.
func TestMailSettingsOverTheWire(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	s.stepUp(admin, adminAcct)
	const wrong = "CANARY-wrong-smtp-pass-91d3"
	test := func(to string) *httptest.ResponseRecorder {
		s.api.ResetLimits() // the 5 a minute of limitTestMail is checked at the end
		return admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": to})
	}

	rec := admin.do(http.MethodGet, "/api/v1/settings/smtp", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, `"0"`, rec.Header().Get("ETag"))
	assert.False(t, decodeBody[smtpView](t, rec).Configured)
	requireError(t, test("ops@example.com"), http.StatusConflict, "ALC-NTF-0002")

	// A user name needs a password (C7 amendment): nothing is stored.
	assert.Equal(t, map[string]string{"password": "validation.required"},
		fieldErrors(t, admin.do(http.MethodPut, "/api/v1/settings/smtp", s.mailBody(nil), ifMatchOf("0"))))
	assert.Equal(t, map[string]string{"password": "validation.required"},
		fieldErrors(t, admin.do(http.MethodPut, "/api/v1/settings/smtp", s.mailBody(""), ifMatchOf("0"))))
	assert.Equal(t, 0, s.countWhere("settings", "key = 'notify.smtp'"))

	rec = admin.do(http.MethodPut, "/api/v1/settings/smtp", s.mailBody(wrong), ifMatchOf("0"))
	requireStatus(t, rec, http.StatusOK)
	assert.NotContains(t, rec.Body.String(), wrong)
	assert.NotContains(t, rec.Body.String(), `"password"`)
	assert.True(t, decodeBody[smtpView](t, rec).HasPassword)
	version := etagVersion(t, rec)

	// F-62: the self-signed certificate is not trusted; the answer shows what to compare.
	rec = test("ops@example.com")
	requireError(t, rec, http.StatusBadGateway, "ALC-NTF-0005")
	params := decodeBody[apiError](t, rec).Error.Params
	fp := params["fingerprint"]
	assert.Equal(t, s.smtp.Fingerprint(), fp)
	assert.Equal(t, "CN=127.0.0.1", params["subject"])
	_, err := time.Parse(time.RFC3339, params["not_after"])
	require.NoError(t, err)
	assert.Empty(t, s.smtp.Messages())

	// Only the certificate the test saw can be trusted, at the version read.
	requireError(t, admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/trust", map[string]string{"fingerprint": strings.Repeat("ab", 32)},
		ifMatchOf(version)), http.StatusConflict, "ALC-NTF-0008")
	requireError(t, admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/trust", map[string]string{"fingerprint": fp},
		ifMatchOf("0")), http.StatusPreconditionFailed, "ALC-SYS-0008")
	rec = admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/trust", map[string]string{"fingerprint": fp}, ifMatchOf(version))
	requireStatus(t, rec, http.StatusOK)
	view := decodeBody[smtpView](t, rec)
	require.NotNil(t, view.Trusted)
	assert.Equal(t, fp, view.Trusted.Fingerprint)
	assert.Equal(t, "ada", view.Trusted.TrustedBy)
	version = etagVersion(t, rec)

	// F-63: the server refuses the credentials; nothing of the password or of the server's text leaks.
	rec = test("ops@example.com")
	requireError(t, rec, http.StatusBadGateway, "ALC-NTF-0006")
	assert.NotContains(t, rec.Body.String(), wrong)
	assert.NotContains(t, s.logs.String(), wrong)

	// An absent password keeps the stored one; then the right password is stored and the test e-mail is delivered.
	rec = admin.do(http.MethodPut, "/api/v1/settings/smtp", s.mailBody(nil), ifMatchOf(version))
	requireStatus(t, rec, http.StatusOK)
	assert.True(t, decodeBody[smtpView](t, rec).HasPassword)
	requireError(t, test("ops@example.com"), http.StatusBadGateway, "ALC-NTF-0006")
	rec = admin.do(http.MethodPut, "/api/v1/settings/smtp", s.mailBody(stackSMTPPassword), ifMatchOf(etagVersion(t, rec)))
	requireStatus(t, rec, http.StatusOK)
	version = etagVersion(t, rec)
	require.NotNil(t, decodeBody[smtpView](t, rec).Trusted, "the trust stays while the server is the same")
	rec = test("ops@example.com")
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"sent":true}`, rec.Body.String())
	msgs := s.smtp.Messages()
	require.Len(t, msgs, 1)
	assert.Equal(t, []string{"ops@example.com"}, msgs[0].To)
	assert.True(t, msgs[0].Secure, "STARTTLS")
	assert.True(t, msgs[0].Authed, "AUTH PLAIN")
	assert.Contains(t, msgs[0].From, "alice@example.com")
	assert.NotEmpty(t, msgs[0].Subject)
	assert.NotContains(t, msgs[0].Raw, stackSMTPPassword)

	// A refused recipient and an unreachable server.
	s.smtp.RejectRecipient("bad@example.com")
	requireError(t, test("bad@example.com"), http.StatusBadGateway, "ALC-NTF-0007")
	s.smtp.RejectRecipient("")
	s.smtp.Down()
	rec = test("ops@example.com")
	requireError(t, rec, http.StatusBadGateway, "ALC-NTF-0003")
	assert.Equal(t, true, decodeBody[map[string]map[string]any](t, rec)["error"]["retryable"])
	require.NoError(t, s.smtp.Up())
	requireStatus(t, test("ops@example.com"), http.StatusOK)

	// Untrust: the certificate is shown again. S-6: a certificate seen on one port cannot be trusted for another.
	rec = admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/untrust", nil, ifMatchOf(version))
	requireStatus(t, rec, http.StatusOK)
	assert.Nil(t, decodeBody[smtpView](t, rec).Trusted)
	version = etagVersion(t, rec)
	requireError(t, test("ops@example.com"), http.StatusBadGateway, "ALC-NTF-0005")
	moved := s.mailBody(nil)
	moved["port"] = moved["port"].(int) + 1
	rec = admin.do(http.MethodPut, "/api/v1/settings/smtp", moved, ifMatchOf(version))
	requireStatus(t, rec, http.StatusOK)
	requireError(t, admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/trust", map[string]string{"fingerprint": fp},
		ifMatchOf(etagVersion(t, rec))), http.StatusConflict, "ALC-NTF-0008")

	// Every test is audited with its result; the trust names the certificate.
	assert.Equal(t, 8, s.countWhere("audit_log", "action = 'settings.smtp_tested'"))
	assert.Equal(t, 2, s.countWhere("audit_log", "action = 'settings.smtp_tested' AND details->>'result' = 'sent'"))
	assert.Equal(t, 2, s.countWhere("audit_log", "action = 'settings.smtp_tested' AND details->>'reason' = 'smtp.auth'"))
	assert.Equal(t, 2, s.countWhere("audit_log", "action = 'settings.smtp_tested' AND details->>'fingerprint' = '"+fp+"'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'settings.smtp_trusted' AND details->>'fingerprint' = '"+fp+"'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'settings.smtp_untrusted'"))

	// The test e-mail is limited to 5 a minute per Administrator.
	s.api.ResetLimits()
	for i := 0; i < 5; i++ {
		requireError(t, admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"}),
			http.StatusBadGateway, "ALC-NTF-0003") // the moved port has no server
	}
	requireError(t, admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"}),
		http.StatusTooManyRequests, "ALC-SYS-0005")

	// Removing the settings.
	rec = admin.do(http.MethodGet, "/api/v1/settings/smtp", nil)
	requireStatus(t, admin.do(http.MethodDelete, "/api/v1/settings/smtp", nil, ifMatchOf(etagVersion(t, rec))), http.StatusNoContent)
	assert.False(t, decodeBody[smtpView](t, admin.do(http.MethodGet, "/api/v1/settings/smtp", nil)).Configured)
	assert.Equal(t, 0, s.countWhere("setting_secrets", "true"))
}

// F-61 over the wire: who receives e-mails, the thresholds and the general settings, each with If-Match, validation and
// an audit row; the alert scan then e-mails exactly the configured recipients.
func TestRecipientsThresholdsAndGeneralOverTheWire(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	s.stepUp(admin, adminAcct)
	ctx := context.Background()

	rec := admin.do(http.MethodGet, "/api/v1/settings/notifications", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"administrators":true,"addresses":[],"version":0}`, rec.Body.String())
	assert.Equal(t, map[string]string{"addresses": "validation.required"}, fieldErrors(t, admin.do(http.MethodPut,
		"/api/v1/settings/notifications", map[string]any{"administrators": false, "addresses": []any{}}, ifMatchOf("0"))))
	assert.Contains(t, fieldErrors(t, admin.do(http.MethodPut, "/api/v1/settings/notifications", map[string]any{"administrators": true,
		"addresses": []map[string]string{{"email": "not an address", "locale": "en"}}}, ifMatchOf("0"))), "addresses.0.email")
	requireError(t, admin.do(http.MethodPut, "/api/v1/settings/notifications", map[string]any{"administrators": true,
		"addresses": []map[string]string{{"email": "ops@example.com", "locale": "en", "x": "y"}}}, ifMatchOf("0")), http.StatusBadRequest, "ALC-SYS-0004")
	rec = admin.do(http.MethodPut, "/api/v1/settings/notifications", map[string]any{"administrators": false,
		"addresses": []map[string]string{{"email": "ops@example.com", "locale": "tr"}}}, ifMatchOf("0"))
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	requireError(t, admin.do(http.MethodPut, "/api/v1/settings/notifications", map[string]any{"administrators": true, "addresses": []any{}},
		ifMatchOf("0")), http.StatusPreconditionFailed, "ALC-SYS-0008")
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'settings.recipients_changed' AND details->>'administrators' = 'false' AND "+
		"details->>'addresses' = 'ops@example.com'"))

	rec = admin.do(http.MethodGet, "/api/v1/settings/alerts", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"thresholds_days":[60,30,14,7,1],"version":0}`, rec.Body.String())
	for body, field := range map[string]string{`[0]`: "validation.out_of_range", `[400]`: "validation.out_of_range", `[7,7]`: "validation.duplicate",
		`[1,2,3,4,5,6,7,8,9,10,11]`: "validation.too_long"} {
		var days []int
		require.NoError(t, json.Unmarshal([]byte(body), &days))
		assert.Equal(t, map[string]string{"thresholds_days": field}, fieldErrors(t, admin.do(http.MethodPut, "/api/v1/settings/alerts",
			map[string]any{"thresholds_days": days}, ifMatchOf("0"))), body)
	}
	rec = admin.do(http.MethodPut, "/api/v1/settings/alerts", map[string]any{"thresholds_days": []int{7, 30}}, ifMatchOf("0"))
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"thresholds_days":[30,7],"version":1}`, rec.Body.String())
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'settings.thresholds_changed' AND details->>'thresholds' = '30,7'"))

	rec = admin.do(http.MethodGet, "/api/v1/settings/general", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"public_url":"","retired_key_retention_days":30,"version":0}`, rec.Body.String())
	for _, bad := range []string{"http://alice.test", "https://alice.test/path", "https://user@alice.test", "https://alice.test/?q=1"} {
		assert.Contains(t, fieldErrors(t, admin.do(http.MethodPut, "/api/v1/settings/general",
			map[string]any{"public_url": bad, "retired_key_retention_days": 30}, ifMatchOf("0"))), "public_url", bad)
	}
	assert.Contains(t, fieldErrors(t, admin.do(http.MethodPut, "/api/v1/settings/general",
		map[string]any{"public_url": "", "retired_key_retention_days": 0}, ifMatchOf("0"))), "retired_key_retention_days")
	rec = admin.do(http.MethodPut, "/api/v1/settings/general", map[string]any{"public_url": "https://alice.test:8443", "retired_key_retention_days": 90},
		ifMatchOf("0"))
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"public_url":"https://alice.test:8443","retired_key_retention_days":90,"version":1}`, rec.Body.String())
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'settings.general_changed' AND details->>'public_url' = 'https://alice.test:8443'"))

	// Settings are an Administrator's, with step-up; an Operator is refused.
	olga := s.createUser(admin, adminAcct, "olga", "operator", operatorPassword)
	op := s.client("198.51.100.63")
	s.firstSignIn(op, olga)
	for _, path := range []string{"/api/v1/settings/smtp", "/api/v1/settings/notifications", "/api/v1/settings/alerts", "/api/v1/settings/general"} {
		requireError(t, op.do(http.MethodGet, path, nil), http.StatusForbidden, "ALC-AUTH-0002")
	}

	// The scan e-mails exactly the configured recipient (the Administrator is switched off), in its language, and only
	// at the configured thresholds.
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)
	s.configureMail(admin)
	_, err := seed.Dashboard(ctx, s.db.Owner, s.clock.Now())
	require.NoError(t, err)
	_, err = s.alerts.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, s.countWhere("notifications_outbox", "to_address <> 'ops@example.com'"))
	queued := s.countWhere("notifications_outbox", "to_address = 'ops@example.com' AND locale = 'tr'")
	require.Positive(t, queued)
	assert.Equal(t, 0, s.countWhere("alerts", "threshold_days NOT IN (30, 7, 0)"), "only the configured thresholds (and expired)")
	assert.Equal(t, queued, s.drainMail())
	for _, m := range s.smtp.Messages() {
		assert.Equal(t, []string{"ops@example.com"}, m.To)
	}
	assert.Len(t, s.smtp.Messages(), queued)
}

// notificationStatus signs a in again on c (the clock moved hours: the session is idle-expired) and reads
// GET /notifications/status.
func (s *stack) notificationStatus(c *client, a *account) map[string]any {
	t := s.t
	t.Helper()
	s.signIn(c, a)
	rec := c.do(http.MethodGet, "/api/v1/notifications/status", nil)
	requireStatus(t, rec, http.StatusOK)
	return decodeBody[map[string]any](t, rec)
}

// F-60 over the stack: alerts queued during an outage are delivered once after it; meanwhile the failing state is
// shown on the status, on the dashboard and as a condition that needs attention; a second scan queues nothing again.
func TestF60OverTheWire(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	ctx := context.Background()
	s.stepUp(admin, adminAcct)
	// B11: the Administrator has an address, and one explicit recipient is set too.
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)
	requireStatus(t, admin.do(http.MethodPut, "/api/v1/settings/notifications", map[string]any{"administrators": true,
		"addresses": []map[string]string{{"email": "ops@example.com", "locale": "en"}}}, ifMatchOf("0")), http.StatusOK)
	s.configureMail(admin)
	olga := s.createUser(admin, adminAcct, "olga", "operator", operatorPassword)
	_, err := seed.Dashboard(ctx, s.db.Owner, s.clock.Now())
	require.NoError(t, err)

	s.smtp.Down()
	_, err = s.alerts.Scan(ctx)
	require.NoError(t, err)
	queued := s.count("notifications_outbox")
	require.Positive(t, queued)
	assert.Equal(t, queued/2, s.countWhere("notifications_outbox", "to_address = 'ada@example.com'"))
	assert.Equal(t, queued/2, s.countWhere("notifications_outbox", "to_address = 'ops@example.com'"))
	for i := 0; i < 3; i++ {
		assert.Equal(t, queued, s.drainMail())
		s.clock.Advance(time.Hour)
	}
	st := s.notificationStatus(admin, adminAcct)
	assert.Equal(t, true, st["failing"])
	assert.EqualValues(t, 3*queued, st["consecutive_failures"])
	assert.Equal(t, "smtp.connect", st["last_failure_code"])
	assert.EqualValues(t, queued, st["pending"])
	assert.EqualValues(t, 0, st["failed_24h"])
	sum := decodeBody[dashboardBody](t, admin.do(http.MethodGet, "/api/v1/dashboard/summary", nil))
	require.NotNil(t, sum.Notifications)
	assert.True(t, sum.Notifications.Failing)
	assert.Contains(t, admin.do(http.MethodGet, "/api/v1/alerts", nil).Body.String(), `"kind":"notifications_failing"`)
	assert.Empty(t, s.smtp.Messages())
	// Only an Administrator sees the delivery state (R42 row 13).
	op := s.client("198.51.100.64")
	s.firstSignIn(op, olga)
	assert.JSONEq(t, `{"failing":false}`, op.do(http.MethodGet, "/api/v1/notifications/status", nil).Body.String())
	assert.Contains(t, op.do(http.MethodGet, "/api/v1/dashboard/summary", nil).Body.String(), `"notifications":null`)
	assert.NotContains(t, op.do(http.MethodGet, "/api/v1/alerts", nil).Body.String(), "notifications_failing")

	require.NoError(t, s.smtp.Up())
	s.clock.Advance(time.Hour)
	assert.Equal(t, queued, s.drainMail())
	assert.Len(t, s.smtp.Messages(), queued)
	assert.Equal(t, queued, s.countWhere("notifications_outbox", "status = 'sent' AND attempts = 4"))
	// Exactly once: another drain and another scan send nothing more.
	s.clock.Advance(time.Hour)
	assert.Zero(t, s.drainMail())
	_, err = s.alerts.Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, queued, s.count("notifications_outbox"))
	assert.Zero(t, s.drainMail())
	assert.Len(t, s.smtp.Messages(), queued, "exactly once")
	st = s.notificationStatus(admin, adminAcct)
	assert.Equal(t, false, st["failing"])
	assert.EqualValues(t, 0, st["pending"])
	assert.NotContains(t, admin.do(http.MethodGet, "/api/v1/alerts", nil).Body.String(), `"kind":"notifications_failing"`)
}

// F-60, the 24-hour retry state (R42 row 7): a message is retried (30 s doubling up to an hour) for 24 hours after it
// was queued, then it is failed and never sent, even once the server is back; the status counts it.
func TestF60GivesUpAfter24Hours(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	ctx := context.Background()
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)
	s.configureMail(admin)
	_, err := seed.Dashboard(ctx, s.db.Owner, s.clock.Now())
	require.NoError(t, err)
	s.smtp.Down()
	_, err = s.alerts.Scan(ctx)
	require.NoError(t, err)
	queued := s.count("notifications_outbox")
	require.Positive(t, queued)

	for h := 0; h < 23; h++ {
		s.drainMail()
		s.clock.Advance(time.Hour)
	}
	st := s.notificationStatus(admin, adminAcct)
	assert.EqualValues(t, queued, st["pending"], "still retried within 24 hours")
	assert.EqualValues(t, 0, st["failed_24h"])
	s.clock.Advance(2 * time.Hour)
	assert.Equal(t, queued, s.drainMail())
	assert.Equal(t, queued, s.countWhere("notifications_outbox", "status = 'failed'"))
	assert.Contains(t, s.logs.String(), "notify.gave_up")
	st = s.notificationStatus(admin, adminAcct)
	assert.Equal(t, true, st["failing"])
	assert.EqualValues(t, 0, st["pending"])
	assert.EqualValues(t, queued, st["failed_24h"])

	require.NoError(t, s.smtp.Up())
	s.clock.Advance(time.Hour)
	assert.Zero(t, s.drainMail())
	assert.Empty(t, s.smtp.Messages(), "a given-up e-mail is never sent")
	// failed_24h counts rows queued within 48 hours (Task 7 amendment): two days later they are no longer counted.
	s.clock.Advance(48 * time.Hour)
	assert.EqualValues(t, 0, s.notificationStatus(admin, adminAcct)["failed_24h"])
}
