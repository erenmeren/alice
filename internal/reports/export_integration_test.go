//go:build integration

package reports_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/platform/clock"
	"alice/internal/reports"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func exportWorld(t *testing.T) (*reports.Service, *inventory.Service, *pgtest.DB, uuid.UUID) {
	t.Helper()
	w := newWorld(t, false)
	clk := clock.NewFake(t0)
	inv := inventory.New(inventory.Config{Pool: w.d.App, Clock: clk, Audit: audit.New(clk)})
	svc := reports.New(reports.Config{Pool: w.d.App, Clock: clk, Audit: audit.New(clk), Inventory: inv,
		Alerts: alerts.New(alerts.Config{Pool: w.d.App, Audit: audit.New(clk), Clock: clk, License: lic{}}), License: lic{}})
	return svc, inv, w.d, w.web1
}

func parse(t *testing.T, b []byte) [][]string {
	t.Helper()
	require.True(t, bytes.HasPrefix(b, []byte("\xEF\xBB\xBF")))
	rows, err := csv.NewReader(bytes.NewReader(b[3:])).ReadAll()
	require.NoError(t, err)
	return rows
}

// Review Focus 4, owner step 3: the export is exactly the list's rows for the same filter, in the same order.
func TestExportEqualsTheListPages(t *testing.T) {
	svc, inv, _, web1 := exportWorld(t)
	ctx := context.Background()
	admin := audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Name: "ada"}
	for _, f := range []inventory.CertificateFilter{{}, {Expiry: "30"}, {Expiry: "30", TargetID: web1}, {Query: "seed"}, {Expiry: "expired"},
		{Query: "nothing-matches"}} {
		var b bytes.Buffer
		n, err := svc.ExportCertificates(ctx, admin, f, &b)
		require.NoError(t, err)
		rows := parse(t, b.Bytes())
		assert.Equal(t, []string{"id", "subject_cn", "label", "sans", "issuer", "serial", "not_before", "not_after", "days_left", "source",
			"key_algorithm", "key_bits", "self_signed", "chain_complete", "fingerprint", "location_count"}, rows[0])
		var want []string
		f.Limit = 2 // page through the list with tiny pages
		for {
			page, err := inv.ListCertificates(ctx, f)
			require.NoError(t, err)
			for _, c := range page.Items {
				want = append(want, c.ID.String())
			}
			if page.NextCursor == "" {
				break
			}
			f.Cursor = page.NextCursor
		}
		var got []string
		for _, r := range rows[1:] {
			got = append(got, r[0])
		}
		assert.Equal(t, want, got, "%+v", f)
		assert.Equal(t, len(want), n)
	}
}

func TestExportServerFilterMatchesC17(t *testing.T) {
	svc, _, _, web1 := exportWorld(t)
	var b bytes.Buffer
	_, err := svc.ExportCertificates(context.Background(), audit.SystemActor("t"), inventory.CertificateFilter{Expiry: "30", TargetID: web1}, &b)
	require.NoError(t, err)
	var cns []string
	for _, r := range parse(t, b.Bytes())[1:] {
		cns = append(cns, r[1])
	}
	assert.Equal(t, []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test"}, cns)
}

// auditCheckingWriter counts the committed inventory.exported rows when the first byte arrives.
type auditCheckingWriter struct {
	t               *testing.T
	d               *pgtest.DB
	started         bool
	rowsAtFirstByte int
	b               bytes.Buffer
}

func (w *auditCheckingWriter) Write(p []byte) (int, error) {
	if !w.started {
		w.started = true
		require.NoError(w.t, w.d.Owner.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_log WHERE action = 'inventory.exported'`).Scan(&w.rowsAtFirstByte))
	}
	return w.b.Write(p)
}

// Review Focus 4: the audit row is committed before the first byte; a refused export writes nothing.
func TestExportAuditsBeforeTheFirstByte(t *testing.T) {
	svc, _, d, web1 := exportWorld(t)
	ctx := context.Background()
	w := &auditCheckingWriter{t: t, d: d}
	_, err := svc.ExportCertificates(ctx, audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Name: "aud"},
		inventory.CertificateFilter{Expiry: "30", TargetID: web1, Query: "=cmd"}, w)
	require.NoError(t, err)
	assert.Equal(t, 1, w.rowsAtFirstByte, "committed before the first byte")
	var details string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT details::text FROM audit_log WHERE action = 'inventory.exported'`).Scan(&details))
	assert.Contains(t, details, `"kind": "certificates"`)
	assert.Contains(t, details, `"expiry": "30"`)
	assert.Contains(t, details, `"row_count": "`)
	assert.Contains(t, details, `"q": "=cmd"`, "the filter is recorded as given (audit details are data, never a CSV)")
}

func TestExportRefusesTooManyRows(t *testing.T) {
	if testing.Short() {
		t.Skip("inserts 50,001 rows")
	}
	svc, _, d, _ := exportWorld(t)
	ctx := context.Background()
	_, err := d.Owner.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
SELECT gen_random_uuid(), md5(i::text) || md5((i + 1)::text), 'bulk-' || i, now(), now() + interval '1 year', 'ecdsa',
md5('k' || i) || md5('l' || i), '', 'uploaded', now(), now(), now() FROM generate_series(1, $1) AS i`, reports.MaxExportRows+1)
	require.NoError(t, err)
	var b bytes.Buffer
	_, err = svc.ExportCertificates(ctx, audit.SystemActor("t"), inventory.CertificateFilter{}, &b)
	assert.ErrorIs(t, err, reports.ErrTooLarge)
	assert.Zero(t, b.Len(), "nothing written")
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'inventory.exported'`).Scan(&n))
	assert.Zero(t, n, "a refused export is not an export")
}

// Review Focus 4: hostile cell values are neutralised; the SSH key export has its own columns.
func TestExportNeutralisesFormulas(t *testing.T) {
	svc, _, d, web1 := exportWorld(t)
	ctx := context.Background()
	_, err := seed.Certificate(ctx, d.Owner, "=HYPERLINK(\"http://evil\")", t0.Add(10*24*time.Hour), []uuid.UUID{web1})
	require.NoError(t, err)
	var b bytes.Buffer
	_, err = svc.ExportCertificates(ctx, audit.SystemActor("t"), inventory.CertificateFilter{Query: "hyperlink"}, &b)
	require.NoError(t, err)
	rows := parse(t, b.Bytes())
	require.Len(t, rows, 2)
	assert.Equal(t, "'=HYPERLINK(\"http://evil\")", rows[1][1])
	b.Reset()
	_, err = svc.ExportSSHKeys(ctx, audit.SystemActor("t"), inventory.KeyFilter{}, &b)
	require.NoError(t, err)
	assert.Equal(t, []string{"id", "fingerprint", "key_type", "bits", "comment", "managed", "platform_key", "weak", "location_count",
		"target_count", "missing", "retired", "first_seen_at"}, parse(t, b.Bytes())[0])
}

// blockingWriter holds the export after its first write until released.
type blockingWriter struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started); <-w.release })
	return len(p), nil
}

// S-10: one export at a time per user; another user is not held up.
func TestExportIsOneAtATimePerUser(t *testing.T) {
	svc, _, _, _ := exportWorld(t)
	ctx := context.Background()
	ada := audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Name: "ada"}
	bob := audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Name: "bob"}
	w := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := svc.ExportCertificates(ctx, ada, inventory.CertificateFilter{}, w); done <- err }()
	<-w.started
	_, err := svc.ExportCertificates(ctx, ada, inventory.CertificateFilter{}, &bytes.Buffer{})
	assert.ErrorIs(t, err, reports.ErrExportBusy)
	_, err = svc.ExportSSHKeys(ctx, ada, inventory.KeyFilter{}, &bytes.Buffer{})
	assert.ErrorIs(t, err, reports.ErrExportBusy, "one export of any kind")
	_, err = svc.ExportCertificates(ctx, bob, inventory.CertificateFilter{}, &bytes.Buffer{})
	assert.NoError(t, err)
	close(w.release)
	require.NoError(t, <-done)
	_, err = svc.ExportCertificates(ctx, ada, inventory.CertificateFilter{}, &bytes.Buffer{})
	assert.NoError(t, err, "released")
}

// An export longer than one page is streamed page by page and still equals the list.
func TestExportSpansPages(t *testing.T) {
	svc, inv, d, _ := exportWorld(t)
	ctx := context.Background()
	_, err := d.Owner.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
SELECT gen_random_uuid(), md5(i::text) || md5((i + 1)::text), 'bulk-' || i, now(), now() + interval '1 year', 'ecdsa',
md5('k' || i) || md5('l' || i), '', 'uploaded', now(), now(), now() FROM generate_series(1, 450) AS i`)
	require.NoError(t, err)
	var b bytes.Buffer
	n, err := svc.ExportCertificates(ctx, audit.SystemActor("t"), inventory.CertificateFilter{Query: "bulk-"}, &b)
	require.NoError(t, err)
	assert.Equal(t, 450, n)
	rows := parse(t, b.Bytes())
	require.Len(t, rows, 451)
	f := inventory.CertificateFilter{Query: "bulk-", Limit: 200}
	var want []string
	for {
		page, err := inv.ListCertificates(ctx, f)
		require.NoError(t, err)
		for _, c := range page.Items {
			want = append(want, c.ID.String())
		}
		if page.NextCursor == "" {
			break
		}
		f.Cursor = page.NextCursor
	}
	var got []string
	for _, r := range rows[1:] {
		got = append(got, r[0])
	}
	assert.Equal(t, want, got)
}

// The SSH key export equals the key list for the same filter.
func TestExportSSHKeysEqualsTheList(t *testing.T) {
	svc, inv, d, web1 := exportWorld(t)
	ctx := context.Background()
	for i, fp := range []string{"SHA256:" + strings.Repeat("A", 43), "SHA256:" + strings.Repeat("B", 43)} {
		k := uuid.New()
		_, err := d.Owner.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 256, 'ssh-ed25519 AAAA', now(), now())`, k, fp)
		require.NoError(t, err)
		_, err = d.Owner.Exec(ctx, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, comment, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, 'root', '/root/.ssh/authorized_keys', $4, '=evil', now(), now())`, uuid.New(), k, web1, i+1)
		require.NoError(t, err)
	}
	for _, f := range []inventory.KeyFilter{{}, {TargetID: web1}, {OSUser: "root"}, {Query: "evil"}} {
		var b bytes.Buffer
		n, err := svc.ExportSSHKeys(ctx, audit.SystemActor("t"), f, &b)
		require.NoError(t, err)
		page, err := inv.ListSSHKeys(ctx, inventory.KeyFilter{TargetID: f.TargetID, OSUser: f.OSUser, Query: f.Query, Limit: 200})
		require.NoError(t, err)
		rows := parse(t, b.Bytes())
		require.Len(t, rows, len(page.Items)+1)
		assert.Equal(t, len(page.Items), n)
		if f.Query == "evil" {
			require.NotEmpty(t, page.Items)
			assert.Equal(t, "'=evil", rows[1][4])
		}
		for i, k := range page.Items {
			assert.Equal(t, k.ID.String(), rows[i+1][0])
			assert.Equal(t, strings.Replace(k.Comment, "=", "'=", 1), rows[i+1][4], "comments are neutralised: %q", k.Comment)
		}
	}
	assert.Equal(t, 4, func() int {
		var n int
		require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='inventory.exported' AND details->>'kind'='ssh_keys'`).Scan(&n))
		return n
	}())
}
