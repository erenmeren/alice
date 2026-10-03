//go:build integration

package migrations_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
	"alice/internal/testutil/pgtest"
)

const (
	checkViolation  = "23514"
	privilegeDenied = "42501"
	uniqueViolation = "23505"
	// SQLSTATEs of the triggers (the application maps them to specific errors).
	keyMismatch = "Z1001" // the private key does not belong to the certificate
	keyAttached = "Z1002" // a certificate's key is never replaced or detached
	doneFrozen  = "Z1003" // a finished deployment is never rewritten
)

func hex64(c string) string { return strings.Repeat(c, 64) }

// insertRow inserts one row built from cols (column -> value) as the given pool and returns the
// error. Test-only helper: the table and column names are literals of the tests.
func insertRow(t *testing.T, pool *pgxpool.Pool, table string, cols map[string]any) error {
	t.Helper()
	names := make([]string, 0, len(cols))
	for c := range cols {
		names = append(names, c)
	}
	sort.Strings(names)
	args := make([]any, 0, len(names))
	holders := make([]string, 0, len(names))
	for i, c := range names {
		args = append(args, cols[c])
		holders = append(holders, fmt.Sprintf("$%d", i+1))
	}
	_, err := pool.Exec(context.Background(), "INSERT INTO "+table+" ("+strings.Join(names, ", ")+") VALUES ("+strings.Join(holders, ", ")+")", args...)
	return err
}

func with(base map[string]any, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if v == omit {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

type omitted struct{}

var omit = omitted{}

// world is the rows a test needs: a target, a certificate, a location and a managed key.
type world struct {
	target, cert, loc, key uuid.UUID
}

func seedWorld(t *testing.T, d *pgtest.DB) world {
	t.Helper()
	target, cert, loc := seedCertWorld(t, d)
	return world{target: target, cert: cert, loc: loc, key: seedManagedKey(t, d)}
}

// seedCertWorld inserts, as the owner role, a credential (dummy envelope bytes), an Nginx
// target, a certificate and one location of it.
func seedCertWorld(t *testing.T, d *pgtest.DB) (target, cert, loc uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	cred, target, cert, loc := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, []any{cred}},
		{`INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'web-01', 'nginx', '{"host":"10.0.0.1","port":22,"username":"alice-svc"}', $2, 'ok', now(), now())`, []any{target, cred}},
		{`INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256, pem_chain, source,
first_seen_at, last_seen_at, created_at) VALUES ($1, $2, now(), now() + interval '90 days', 'ecdsa', $3, '', 'discovered', now(), now(), now())`,
			[]any{cert, hex64("a"), hex64("b")}},
		{`INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported, first_seen_at, last_seen_at)
VALUES ($1, $2, 'nginx_file', '/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', $3, true, now(), now())`, []any{loc, target, cert}},
	} {
		_, err := d.Owner.Exec(ctx, q.sql, q.args...)
		require.NoError(t, err)
	}
	return target, cert, loc
}

// seedManagedKey inserts a managed key row with dummy envelope bytes as the owner role. Its
// public key hash is 'c' x 64 (the certificate of seedCertWorld has 'b' x 64).
func seedManagedKey(t *testing.T, d *pgtest.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256,
ciphertext, nonce, wrapped_dek, key_version, created_at) VALUES ($1, 'csr', 'ecdsa', 256, $2, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`,
		id, hex64("c"))
	require.NoError(t, err)
	return id
}

func TestOneActiveDeploymentPerLocation(t *testing.T) {
	d := pgtest.New(t)
	target, cert, loc := seedCertWorld(t, d)
	insert := func(state, status string, finished *time.Time) error {
		_, err := d.App.Exec(context.Background(), `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state,
status, new_fingerprint, cert_path, key_path, created_at, finished_at) VALUES ($1, $2, $3, $4, 'manual', $5, $6, $7, '/a.crt', '/a.key', now(), $8)`,
			uuid.New(), cert, loc, target, state, status, hex64("a"), finished)
		return err
	}
	now := time.Now()
	require.NoError(t, insert("done", "succeeded", &now))
	require.NoError(t, insert("queued", "pending", nil))
	assert.True(t, db.IsUniqueViolation(insert("deploying", "running", nil)), "F-15: one active deployment per location")
	assert.Error(t, insert("done", "running", &now), "a finished deployment has a terminal status")
	assert.Error(t, insert("deploying", "succeeded", nil), "an unfinished deployment has no terminal status")
	assert.Error(t, insert("done", "succeeded", nil), "a finished deployment has finished_at")
}

func TestNeedsAttentionIsUnfinished(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	base := deploymentRow(w)
	require.NoError(t, insertRow(t, d.App, "deployments", with(base, map[string]any{"state": "recovering", "status": "needs_attention"})))
	now := time.Now()
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployments", with(base, map[string]any{
		"id": uuid.New(), "state": "done", "status": "needs_attention", "finished_at": now}))), "a deployment needing attention is not done")
}

func TestCertificateConstraints(t *testing.T) {
	d := pgtest.New(t)
	_, cert, _ := seedCertWorld(t, d)
	ctx := context.Background()
	_, err := d.App.Exec(ctx, `UPDATE certificates SET fingerprint_sha256 = $2 WHERE id = $1`, cert, hex64("b"))
	assert.Equal(t, privilegeDenied, sqlState(err), "identity columns are never updated")
	_, err = d.App.Exec(ctx, `DELETE FROM certificates WHERE id = $1`, cert)
	assert.Equal(t, privilegeDenied, sqlState(err), "certificates are never deleted")
	_, err = d.App.Exec(ctx, `UPDATE certificates SET label = 'x' WHERE id = $1`, cert)
	assert.NoError(t, err)
	_, err = d.App.Exec(ctx, `UPDATE managed_private_keys SET ciphertext = '\x01'`)
	assert.Equal(t, privilegeDenied, sqlState(err), "managed keys are append-only")
	_, err = d.App.Exec(ctx, `UPDATE deployment_steps SET status = 'ok'`)
	assert.Equal(t, privilegeDenied, sqlState(err), "steps are append-only")
	_, err = d.App.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256,
pem_chain, source, first_seen_at, last_seen_at, created_at) VALUES ($1, 'SHA256:x', now(), now(), 'rsa', $2, '', 'uploaded', now(), now(), now())`,
		uuid.New(), hex64("c"))
	assert.Equal(t, checkViolation, sqlState(err), "fingerprints are hex SHA-256")
}

func certRow() map[string]any {
	now := time.Now()
	return map[string]any{"id": uuid.New(), "fingerprint_sha256": hex64("d"), "not_before": now, "not_after": now.Add(time.Hour),
		"key_algorithm": "rsa", "public_key_sha256": hex64("e"), "pem_chain": "", "source": "uploaded",
		"first_seen_at": now, "last_seen_at": now, "created_at": now}
}

func TestCertificateColumnsAreChecked(t *testing.T) {
	d := pgtest.New(t)
	seedCertWorld(t, d)
	require.NoError(t, insertRow(t, d.App, "certificates", certRow()))
	for name, over := range map[string]map[string]any{
		"upper-case hex":          {"fingerprint_sha256": strings.Repeat("D", 64)},
		"short public key hash":   {"public_key_sha256": "abc"},
		"unknown algorithm":       {"key_algorithm": "dsa"},
		"unknown source":          {"source": "pasted"},
		"negative key bits":       {"key_bits": -1},
		"label over 100":          {"label": strings.Repeat("l", 101)},
		"pem chain over 1 MiB":    {"pem_chain": strings.Repeat("p", 1<<20+1)},
		"unknown key algorithm 2": {"key_algorithm": ""},
	} {
		row := with(certRow(), over)
		row["fingerprint_sha256"] = fmt.Sprintf("%064x", uuid.New().ID())
		if v, ok := over["fingerprint_sha256"]; ok {
			row["fingerprint_sha256"] = v
		}
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "certificates", row)), name)
	}
	for _, alg := range []string{"rsa", "ecdsa", "ed25519", "other"} {
		row := certRow()
		row["key_algorithm"], row["fingerprint_sha256"] = alg, fmt.Sprintf("%064x", uuid.New().ID())
		assert.NoError(t, insertRow(t, d.App, "certificates", row), alg)
	}
	for _, src := range []string{"discovered", "csr", "azure_kv"} {
		row := certRow()
		row["source"], row["fingerprint_sha256"] = src, fmt.Sprintf("%064x", uuid.New().ID())
		assert.NoError(t, insertRow(t, d.App, "certificates", row), src)
	}
	dup := certRow()
	assert.Equal(t, uniqueViolation, sqlState(insertRow(t, d.App, "certificates", dup)), "one row per leaf fingerprint")
}

func manyStrings(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("h%d.example.test", i)
	}
	return out
}

func TestManagedKeysAreEnvelopesOnly(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	rows, err := d.Owner.Query(ctx, `SELECT column_name, data_type FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'managed_private_keys'`)
	require.NoError(t, err)
	cols := map[string]string{}
	for rows.Next() {
		var c, ty string
		require.NoError(t, rows.Scan(&c, &ty))
		cols[c] = ty
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, "bytea", cols["ciphertext"])
	assert.Equal(t, "bytea", cols["nonce"])
	assert.Equal(t, "bytea", cols["wrapped_dek"])
	for c, ty := range cols {
		if ty == "text" || ty == "jsonb" {
			assert.Contains(t, []string{"owner_type", "algorithm", "public_key_sha256"}, c, "a text column could hold plaintext key material")
		}
	}

	base := func() map[string]any {
		return map[string]any{"id": uuid.New(), "owner_type": "certificate", "algorithm": "rsa", "bits": 2048, "public_key_sha256": hex64("1"),
			"ciphertext": []byte{1}, "nonce": make([]byte, 12), "wrapped_dek": []byte{2}, "key_version": 1, "created_at": time.Now()}
	}
	require.NoError(t, insertRow(t, d.App, "managed_private_keys", base()))
	for name, over := range map[string]map[string]any{
		"unknown owner":          {"owner_type": "user"},
		"ed25519":                {"algorithm": "ed25519"},
		"weak rsa":               {"bits": 1024},
		"zero bits":              {"bits": 0},
		"odd ecdsa curve":        {"algorithm": "ecdsa", "bits": 521},
		"rsa with curve":         {"algorithm": "rsa", "bits": 256},
		"short nonce":            {"nonce": make([]byte, 11)},
		"long nonce":             {"nonce": make([]byte, 13)},
		"bad key hash":           {"public_key_sha256": "x"},
		"key version zero":       {"key_version": 0},
		"empty ciphertext":       {"ciphertext": []byte{}},
		"empty wrapped dek":      {"wrapped_dek": []byte{}},
		"ciphertext over 300000": {"ciphertext": make([]byte, 300001)},
		"wrapped dek over 1 KiB": {"wrapped_dek": make([]byte, 1025)},
	} {
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "managed_private_keys", with(base(), over))), name)
	}
	assert.NoError(t, insertRow(t, d.App, "managed_private_keys", with(base(), map[string]any{"algorithm": "ecdsa", "bits": 384})))
	assert.NoError(t, insertRow(t, d.App, "managed_private_keys", with(base(), map[string]any{"bits": 4096})), "a renewal may reuse a key hash")
	assert.NoError(t, insertRow(t, d.App, "managed_private_keys", with(base(), map[string]any{"bits": 16384})))

	for _, stmt := range []string{
		"UPDATE managed_private_keys SET ciphertext = '\\x01'",
		"UPDATE managed_private_keys SET wrapped_dek = '\\x01'",
		"UPDATE managed_private_keys SET key_version = 2",
		"UPDATE managed_private_keys SET owner_type = 'csr'",
		"DELETE FROM managed_private_keys",
		"TRUNCATE managed_private_keys",
	} {
		assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, stmt)), stmt)
	}
}

func TestCompletedCSRNamesItsCertificate(t *testing.T) {
	d := pgtest.New(t)
	_, cert, _ := seedCertWorld(t, d)
	key := seedManagedKey(t, d)
	_, err := d.App.Exec(context.Background(), `INSERT INTO csr_requests (id, private_key_id, common_name, csr_pem, status, created_at)
VALUES ($1, $2, 'a.example.test', 'x', 'completed', now())`, uuid.New(), key)
	assert.Equal(t, checkViolation, sqlState(err), "completed without a certificate")
	_, err = d.App.Exec(context.Background(), `INSERT INTO csr_requests (id, private_key_id, common_name, csr_pem, status, certificate_id,
created_at, finished_at) VALUES ($1, $2, 'a.example.test', 'x', 'completed', $3, now(), now())`, uuid.New(), key, cert)
	assert.NoError(t, err)
}

func csrRow(key uuid.UUID) map[string]any {
	return map[string]any{"id": uuid.New(), "private_key_id": key, "common_name": "a.example.test", "csr_pem": "x", "status": "pending", "created_at": time.Now()}
}

func TestCSRConstraints(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	// X.509 caps the common name at 64 characters (ub-common-name); the application refuses longer
	// names before the INSERT (field common_name, max 64).
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "csr_requests", with(csrRow(w.key), map[string]any{"common_name": strings.Repeat("a", 65)}))))
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "csr_requests", with(csrRow(w.key), map[string]any{"common_name": ""}))))
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "csr_requests", with(csrRow(w.key), map[string]any{"status": "failed"}))))
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "csr_requests", with(csrRow(w.key), map[string]any{"status": "cancelled", "certificate_id": w.cert}))),
		"only a completed request names a certificate")
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "csr_requests", with(csrRow(w.key), map[string]any{"csr_pem": strings.Repeat("p", 65537)}))))
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "csr_requests", with(csrRow(w.key), map[string]any{"sans": manyStrings(101)}))))
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "csr_requests", with(csrRow(w.key), map[string]any{"finished_at": time.Now()}))), "a pending request is not finished")
	assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "csr_requests", with(csrRow(w.key), map[string]any{"status": "cancelled"}))), "a cancelled request has finished_at")
	require.NoError(t, insertRow(t, d.App, "csr_requests", with(csrRow(w.key), map[string]any{"common_name": strings.Repeat("a", 64)})))
	assert.Equal(t, uniqueViolation, sqlState(insertRow(t, d.App, "csr_requests", csrRow(w.key))), "one request per key")
	for _, stmt := range []string{
		"UPDATE csr_requests SET common_name = 'b'", "UPDATE csr_requests SET csr_pem = 'y'", "UPDATE csr_requests SET private_key_id = private_key_id",
		"UPDATE csr_requests SET sans = '{}'", "DELETE FROM csr_requests",
	} {
		assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, stmt)), stmt)
	}
	require.NoError(t, exec(t, d.App, "UPDATE csr_requests SET status = 'completed', certificate_id = $1, finished_at = now()", w.cert))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE csr_requests SET status = 'pending'")), "completed needs a certificate; pending cannot keep one")
}

func locationRow(w world, path string) map[string]any {
	now := time.Now()
	return map[string]any{"id": uuid.New(), "target_id": w.target, "kind": "nginx_file", "cert_path": path, "supported": true,
		"first_seen_at": now, "last_seen_at": now}
}

func TestLocationConstraints(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	n := 0
	row := func(over map[string]any) map[string]any {
		n++
		return with(locationRow(w, fmt.Sprintf("/etc/nginx/ssl/%d.crt", n)), over)
	}
	require.NoError(t, insertRow(t, d.App, "certificate_locations", row(nil)))
	for name, over := range map[string]map[string]any{
		"unknown kind":            {"kind": "azure"},
		"empty cert path":         {"cert_path": ""},
		"cert path over 16400":    {"cert_path": strings.Repeat("a", 16401)},
		"key path over 16400":     {"key_path": strings.Repeat("a", 16401)},
		"resolved path over 4096": {"resolved_cert_path": "/" + strings.Repeat("a", 4096)},
		"key type":                {"key_type": "dsa"},
		"bad cert file hash":      {"cert_file_sha256": "abc"},
		"bad deployed hash":       {"deployed_fingerprint": "abc"},
		"port zero":               {"verify_port": 0},
		"port 65536":              {"verify_port": 65536},
		"sni empty":               {"verify_sni": ""},
		"sni with space":          {"verify_sni": "a b.example.test"},
		"sni upper case":          {"verify_sni": "WWW.example.test"},
		"sni over 253":            {"verify_sni": strings.Repeat("a", 254)},
		"servers not an array":    {"servers": `{"a":1}`},
		"version zero":            {"version": 0},
		"reason on supported":     {"supported": true, "unsupported_reason": "stream"},
		"reason with caps":        {"supported": false, "unsupported_reason": "Stream"},
		"reason too long":         {"supported": false, "unsupported_reason": strings.Repeat("a", 41)},
		"problem with space":      {"problem": "not a certificate"},
		"key problem with digit":  {"key_problem": "x1"},
		"key mode letters":        {"key_mode": "rw-"},
		"key mode too long":       {"key_mode": "000640"},
		"owner over 64":           {"key_owner": strings.Repeat("o", 65)},
		"group over 64":           {"key_group": strings.Repeat("g", 65)},
		"warning with caps":       {"warnings": []string{"Key_mode_open"}},
		"warning with comma":      {"warnings": []string{"a,b"}},
		"warning empty":           {"warnings": []string{""}},
		"warning null":            {"warnings": []*string{nil}},
		"warning over 40":         {"warnings": []string{strings.Repeat("w", 41)}},
		"too many warnings":       {"warnings": manyWarnings(33)},
	} {
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "certificate_locations", row(over))), name)
	}
	// Whatever the helper may report is storable: an unknown reason and problem, every key type,
	// a path the helper refused (it is shown, never deployed), an IPv6-free SNI with underscore.
	for name, over := range map[string]map[string]any{
		"unknown reason":    {"supported": false, "unsupported_reason": "unknown"},
		"file problem":      {"supported": false, "unsupported_reason": "file_problem", "problem": "special_filesystem", "key_problem": "too_large"},
		"future reason":     {"supported": false, "unsupported_reason": "some_new_reason"},
		"all fields":        {"key_type": "ecdsa", "key_mode": "0640", "key_owner": "root", "key_group": "ssl-cert", "verify_port": 8443, "verify_sni": "www.example.test", "warnings": []string{"key_group_open", "list_truncated", "certificate_block_dropped"}, "servers": `[{"names":["a"],"listens":[]}]`, "deployed_fingerprint": hex64("a"), "cert_file_sha256": hex64("f")},
		"unusual path":      {"cert_path": "/etc/nginx/ssl/with space/$var.crt"},
		"key path 16400":    {"key_path": strings.Repeat("a", 16400)},
		"servers 300 KiB":   {"servers": `["` + strings.Repeat("s", 300<<10) + `"]`},
		"no sni, no port":   {"verify_port": nil, "verify_sni": nil},
		"mode without zero": {"key_mode": "640"},
	} {
		assert.NoError(t, insertRow(t, d.App, "certificate_locations", row(over)), name)
	}
	assert.Equal(t, uniqueViolation, sqlState(insertRow(t, d.App, "certificate_locations", with(locationRow(w, "/etc/nginx/ssl/www.crt"), nil))),
		"one location per target, kind and certificate path")
}

// A path the helper refused is shown as strconv.QuoteToASCII of its first 4096 bytes: at most
// 4*4096+2 = 16386 characters (an invalid byte becomes \xNN). It must be storable, and so must a
// 4096-byte path that does not compress, and the uniqueness must not depend on btree entry size.
func TestLongLocationPathsAreStorableAndUnique(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	ctx := context.Background()
	insert := func(path string) error {
		return insertRow(t, d.App, "certificate_locations", locationRow(w, path))
	}
	random := func(n int) string {
		b := make([]byte, n)
		_, err := rand.Read(b)
		require.NoError(t, err)
		return "/" + hex.EncodeToString(b)[:n-1]
	}
	incompressible := random(4096)
	require.Len(t, incompressible, 4096)
	require.NoError(t, insert(incompressible), "a random 4096-byte path (a btree entry on the raw text would not fit)")
	assert.Equal(t, uniqueViolation, sqlState(insert(incompressible)), "and it is still unique")

	quoted := strconv.QuoteToASCII(strings.Repeat("\xff", 4096)) // invalid UTF-8 bytes: 4 characters each
	require.Len(t, quoted, 16386)
	require.NoError(t, insert(quoted), "the longest shown path of a path_not_allowed location")
	assert.Equal(t, uniqueViolation, sqlState(insert(quoted)))
	require.NoError(t, insert(strconv.QuoteToASCII(strings.Repeat("é", 2048))), "non-ASCII is expanded 3x")

	base := random(4000)
	require.NoError(t, insert(base+"a"))
	require.NoError(t, insert(base+"b"), "paths that differ only after byte 3000 are different paths")
	assert.Equal(t, uniqueViolation, sqlState(insert(base+"a")))
	// The same path on another target is another location.
	other := w
	other.target = uuid.New()
	_, err := d.Owner.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
SELECT $1, 'web-02', 'nginx', '{"host":"10.0.0.2","port":22}', credential_id, 'ok', now(), now() FROM targets LIMIT 1`, other.target)
	require.NoError(t, err)
	require.NoError(t, insertRow(t, d.App, "certificate_locations", locationRow(other, incompressible)))

	// The conflict target and the lookup both use the hash expression.
	var id uuid.UUID
	require.NoError(t, d.App.QueryRow(ctx, `SELECT id FROM certificate_locations
WHERE target_id = $1 AND kind = 'nginx_file' AND certificate_location_path_hash(cert_path) = certificate_location_path_hash($2) AND cert_path = $2`, w.target, incompressible).Scan(&id))
	tag, err := d.App.Exec(ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, supported, first_seen_at, last_seen_at)
VALUES (gen_random_uuid(), $1, 'nginx_file', $2, true, now(), now())
ON CONFLICT (target_id, kind, certificate_location_path_hash(cert_path)) DO UPDATE SET last_seen_at = now()`, w.target, incompressible)
	require.NoError(t, err)
	assert.EqualValues(t, 1, tag.RowsAffected())
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE tablename = 'certificate_locations' AND indexdef LIKE '%cert_path%' AND indexdef NOT LIKE '%certificate_location_path_hash(cert_path)%'`).Scan(&n))
	assert.Zero(t, n, "no index holds the raw path text")
}

// The Nginx provider keeps at most 500 servers per location, 100 names and 100 listens each; the
// helper's whole answer is capped at 16 MiB, so a location's servers never exceed that. The bound
// is 32 MiB.
func TestLocationServersBound(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	insert := func(path, expr string) error {
		_, err := d.App.Exec(context.Background(), `INSERT INTO certificate_locations (id, target_id, kind, cert_path, supported, servers, first_seen_at, last_seen_at)
SELECT gen_random_uuid(), $1, 'nginx_file', $2, true, `+expr+`, now(), now()`, w.target, path)
		return err
	}
	// 500 servers x 100 names of 253 characters x 100 listens: about 15 MB.
	require.NoError(t, insert("/big.crt", `(SELECT jsonb_agg(jsonb_build_object('names', (SELECT jsonb_agg(repeat('n', 253)) FROM generate_series(1, 100)),
'listens', (SELECT jsonb_agg(jsonb_build_object('addr', repeat('a', 20), 'port', 443, 'default_server', false)) FROM generate_series(1, 100)),
'file', repeat('f', 4096), 'line', 1)) FROM generate_series(1, 500))`))
	assert.Equal(t, checkViolation, sqlState(insert("/huge.crt", `jsonb_build_array(repeat('s', 33 * 1024 * 1024))`)), "a bound exists")
}

func manyWarnings(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "w"
	}
	return out
}

func TestLocationGrants(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	for _, stmt := range []string{
		"UPDATE certificate_locations SET cert_path = '/x'", "UPDATE certificate_locations SET target_id = target_id",
		"UPDATE certificate_locations SET kind = kind", "UPDATE certificate_locations SET first_seen_at = now()",
		"UPDATE certificate_locations SET id = gen_random_uuid()", "DELETE FROM certificate_locations", "TRUNCATE certificate_locations",
	} {
		assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, stmt)), stmt)
	}
	require.NoError(t, exec(t, d.App, `UPDATE certificate_locations SET key_path = '/k', certificate_id = NULL, key_type = 'rsa', servers = '[]',
supported = false, unsupported_reason = 'unknown', problem = 'unknown', key_problem = 'unknown', inherited = true, custom_location = true,
symlinked = true, resolved_cert_path = '/r', cert_file_sha256 = $1, key_exists = true, key_mode = '0600', key_owner = 'root', key_group = 'root',
warnings = '{a}', deployed_fingerprint = $1, changed_outside_at = now(), verify_port = 443, verify_sni = 'a.test', skip_verify = true,
last_seen_at = now(), missing_since = now(), version = 2 WHERE id = $2`, hex64("a"), w.loc))
}

func deploymentRow(w world) map[string]any {
	return map[string]any{"id": uuid.New(), "certificate_id": w.cert, "location_id": w.loc, "target_id": w.target, "trigger": "manual",
		"state": "queued", "status": "pending", "new_fingerprint": hex64("a"), "cert_path": "/etc/nginx/ssl/www.crt", "key_path": "/etc/nginx/ssl/www.key",
		"created_at": time.Now()}
}

func TestDeploymentConstraints(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	now := time.Now()
	// The helper's journal says what happened; a record that was deployed then verified, rolled
	// back and ended uncertain keeps every field of that story.
	for name, over := range map[string]map[string]any{
		"unknown trigger":         {"trigger": "cron"},
		"unknown state":           {"state": "failed"},
		"unknown status":          {"status": "cancelled"},
		"unknown verified":        {"verified": "maybe"},
		"unknown result":          {"result": "failed"},
		"unknown phase":           {"phase": "rolling"},
		"bad new fingerprint":     {"new_fingerprint": "abc"},
		"bad previous":            {"previous_fingerprint": "abc"},
		"bad expect hash":         {"expect_cert_sha256": "abc"},
		"negative new chain":      {"new_chain_length": -1},
		"negative prev chain":     {"previous_chain_length": -1},
		"cert path relative":      {"cert_path": "etc/a.crt"},
		"cert path with space":    {"cert_path": "/etc/a b.crt"},
		"cert path over 4096":     {"cert_path": "/" + strings.Repeat("a", 4096)},
		"key path empty":          {"key_path": ""},
		"key path with dollar":    {"key_path": "/etc/$k.key"},
		"failed step caps":        {"failed_step": "Verify"},
		"failed step too long":    {"failed_step": strings.Repeat("a", 41)},
		"cause step digit":        {"cause_step": "a1"},
		"helper error caps":       {"helper_error": "File_Changed"},
		"verify reason space":     {"verify_failed_reason": "verify failed"},
		"verify port zero":        {"verify_failed_port": 0},
		"verify port 70000":       {"verify_failed_port": 70000},
		"error code space":        {"error_code": "a b"},
		"error code over 100":     {"error_code": strings.Repeat("a", 101)},
		"error params array":      {"error_params": `[]`},
		"error params over 4 KiB": {"error_params": `{"a":"` + strings.Repeat("p", 4096) + `"}`},
		"rollback info scalar":    {"rollback_info": `1`},
		"rollback info huge":      {"rollback_info": `{"dir":"` + strings.Repeat("d", 4096) + `"}`},
		"attempts negative":       {"recovery_attempts": -1},
		"phase on done w/o fin":   {"state": "done", "status": "succeeded"},
	} {
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployments", with(deploymentRow(w), over))), name)
	}
	for _, status := range []string{"succeeded", "unchanged", "failed", "rolled_back", "rollback_failed"} {
		row := with(deploymentRow(w), map[string]any{"state": "done", "status": status, "finished_at": now})
		assert.NoError(t, insertRow(t, d.App, "deployments", row), status)
	}
	for _, res := range []string{"", "committed", "unchanged", "no_change", "rolled_back", "rollback_failed", "uncertain"} {
		assert.NoError(t, insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"state": "done", "status": "failed", "finished_at": now, "result": res})), res)
	}
	for _, ph := range []string{"", "none", "prepared", "writing", "committed", "unchanged", "restoring", "restored", "restore_failed"} {
		assert.NoError(t, insertRow(t, d.App, "deployments", with(deploymentRow(w), map[string]any{"state": "done", "status": "failed", "finished_at": now, "phase": ph})), ph)
	}
	opID := uuid.New()
	uncertain := with(deploymentRow(w), map[string]any{
		"state": "recovering", "status": "running", "result": "uncertain", "operation_id": opID, "phase": "",
		"expect_cert_sha256": hex64("9"), "previous_fingerprint": hex64("8"), "previous_chain_length": 2, "new_chain_length": 3,
		"failed_step": "verify", "cause_step": "", "helper_error": "", "verified": "",
		"error_code": "ALC-DEPLOY-0007", "error_params": `{"reason":"ssh.timeout"}`,
		"verify_failed_reason": "deployment.verify_failed", "verify_failed_port": 8443,
		"rollback_info": `{"operation_id":"` + opID.String() + `","dir":"/var/lib/alice-helper/backups/` + opID.String() + `"}`,
		"recover_after": now, "recovery_attempts": 2, "started_at": now})
	require.NoError(t, insertRow(t, d.App, "deployments", uncertain))
	var reason string
	var port, attempts int
	require.NoError(t, d.App.QueryRow(context.Background(), `SELECT verify_failed_reason, verify_failed_port, recovery_attempts FROM deployments WHERE operation_id = $1`, opID).Scan(&reason, &port, &attempts))
	assert.Equal(t, "deployment.verify_failed", reason)
	assert.Equal(t, 8443, port)
	assert.Equal(t, 2, attempts)
	assert.Equal(t, uniqueViolation, sqlState(insertRow(t, d.Owner, "deployments", with(deploymentRow(w), map[string]any{
		"state": "done", "status": "failed", "finished_at": now, "operation_id": opID}))), "an operation id names one deployment")
}

func TestDeploymentGrants(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	require.NoError(t, insertRow(t, d.App, "deployments", deploymentRow(w)))
	for _, stmt := range []string{
		"UPDATE deployments SET certificate_id = certificate_id", "UPDATE deployments SET location_id = location_id",
		"UPDATE deployments SET target_id = target_id", "UPDATE deployments SET trigger = 'retry'", "UPDATE deployments SET requested_by = NULL",
		"UPDATE deployments SET new_fingerprint = new_fingerprint", "UPDATE deployments SET cert_path = '/x'", "UPDATE deployments SET key_path = '/x'",
		"UPDATE deployments SET created_at = now()", "UPDATE deployments SET confirm_incomplete_chain = true",
		"UPDATE deployments SET id = gen_random_uuid()",
		"DELETE FROM deployments", "TRUNCATE deployments",
	} {
		assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, stmt)), stmt)
	}
	now := time.Now()
	require.NoError(t, exec(t, d.App, `UPDATE deployments SET job_id = NULL, state = 'recovering', status = 'running', result = 'uncertain', phase = '',
previous_fingerprint = $1, previous_chain_length = 2, new_chain_length = 3, expect_cert_sha256 = $1, operation_id = $2, rollback_info = '{}', verified = 'local', error_code = 'x',
error_params = '{}', failed_step = 'verify', cause_step = 'verify', helper_error = 'file_changed', verify_failed_reason = 'x', verify_failed_port = 443,
recover_after = $3, recovery_attempts = 1, started_at = $3`, hex64("a"), uuid.New(), now))
	require.NoError(t, exec(t, d.App, `UPDATE deployments SET state = 'done', status = 'rolled_back', finished_at = $1`, now))
}

func TestStepConstraints(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	dep := deploymentRow(w)
	require.NoError(t, insertRow(t, d.App, "deployments", dep))
	step := func(n int, over map[string]any) map[string]any {
		return with(map[string]any{"id": uuid.New(), "deployment_id": dep["id"], "n": n, "name": "backup", "status": "started", "at": time.Now()}, over)
	}
	require.NoError(t, insertRow(t, d.App, "deployment_steps", step(1, nil)))
	for name, over := range map[string]map[string]any{
		"unknown status": {"status": "running"}, "n zero": {"n": 0}, "name caps": {"name": "Backup"}, "name digit": {"name": "a1"},
		"name 41": {"name": strings.Repeat("a", 41)}, "name empty": {"name": ""}, "params array": {"params": `[]`},
		"params over 4 KiB": {"params": `{"a":"` + strings.Repeat("p", 4096) + `"}`},
	} {
		assert.Equal(t, checkViolation, sqlState(insertRow(t, d.App, "deployment_steps", step(2, over))), name)
	}
	assert.Equal(t, uniqueViolation, sqlState(insertRow(t, d.App, "deployment_steps", step(1, nil))), "one event per sequence number")
	for i, name := range []string{"write_key", "write_cert", "config_test", "reload", "journal", "restore", "rollback_config_test", "rollback_reload", "verify", "verify_old"} {
		for j, st := range []string{"started", "ok", "failed", "skipped"} {
			require.NoError(t, insertRow(t, d.App, "deployment_steps", step(2+i*4+j, map[string]any{"name": name, "status": st})), name+" "+st)
		}
	}
	for _, stmt := range []string{"UPDATE deployment_steps SET status = 'ok'", "UPDATE deployment_steps SET params = '{}'", "DELETE FROM deployment_steps", "TRUNCATE deployment_steps"} {
		assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, stmt)), stmt)
	}
}

// A certificate's private key must be the key of that certificate, whoever writes the row, and
// attaching a key is permanent.
func TestCertificateKeyAttachmentIsChecked(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	w := seedWorld(t, d) // the key hashes to 'c', the discovered certificate to 'b'
	assert.Equal(t, keyMismatch, sqlState(exec(t, d.App, "UPDATE certificates SET private_key_id = $1 WHERE id = $2", w.key, w.cert)), "a key of another public key")
	assert.Equal(t, keyMismatch, sqlState(exec(t, d.Owner, "UPDATE certificates SET private_key_id = $1 WHERE id = $2", w.key, w.cert)), "the owner role too")
	matching := certRow()
	matching["public_key_sha256"], matching["private_key_id"] = hex64("c"), w.key
	require.NoError(t, insertRow(t, d.App, "certificates", matching), "a key of the same public key")
	other := certRow()
	other["fingerprint_sha256"], other["public_key_sha256"], other["private_key_id"] = hex64("7"), hex64("c"), w.key
	assert.Equal(t, uniqueViolation, sqlState(insertRow(t, d.App, "certificates", other)), "one certificate per key")
	wrong := certRow()
	wrong["fingerprint_sha256"], wrong["private_key_id"] = hex64("6"), uuid.New()
	assert.NotEmpty(t, sqlState(insertRow(t, d.App, "certificates", wrong)), "an unknown key")
	mismatch := certRow()
	mismatch["fingerprint_sha256"], mismatch["private_key_id"] = hex64("5"), seedManagedKey(t, d)
	assert.Equal(t, keyMismatch, sqlState(insertRow(t, d.App, "certificates", mismatch)), "an inserted row is checked too")

	// Attach, then never change or detach.
	second := seedManagedKey(t, d)
	plain := uuid.New()
	row := certRow()
	row["id"], row["fingerprint_sha256"], row["public_key_sha256"] = plain, hex64("4"), hex64("c")
	require.NoError(t, insertRow(t, d.App, "certificates", row))
	require.NoError(t, exec(t, d.App, "UPDATE certificates SET private_key_id = $1 WHERE id = $2", second, plain))
	third := seedManagedKey(t, d)
	assert.Equal(t, keyAttached, sqlState(exec(t, d.App, "UPDATE certificates SET private_key_id = $1 WHERE id = $2", third, plain)), "no replacement")
	assert.Equal(t, keyAttached, sqlState(exec(t, d.App, "UPDATE certificates SET private_key_id = NULL WHERE id = $1", plain)), "no detaching")
	require.NoError(t, exec(t, d.App, "UPDATE certificates SET label = 'x', last_seen_at = now(), chain_complete = true, pem_chain = 'y' WHERE id = $1", plain))
	var fn string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT array_to_string(p.proconfig, ',') FROM pg_proc p WHERE p.proname = 'certificates_check_key'`).Scan(&fn))
	assert.Contains(t, fn, "search_path=pg_catalog, pg_temp", "the trigger pins its search path")
}

// maintenance.cleanup prunes old jobs: a deployment keeps its row and loses only the job link.
func TestPrunedJobLeavesTheDeployment(t *testing.T) {
	d := pgtest.New(t)
	target, cert, loc := seedCertWorld(t, d)
	ctx := context.Background()
	job, dep := uuid.New(), uuid.New()
	_, err := d.Owner.Exec(ctx, `INSERT INTO jobs (id, type, class, kind, payload_mac, target_id, status, run_at, max_attempts, created_at)
VALUES ($1, 'certificate.deploy', 'change', 'user', $2, $3, 'succeeded', now(), 3, now())`, job, make([]byte, 32), target)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, job_id, trigger, state, status,
new_fingerprint, cert_path, key_path, created_at, finished_at) VALUES ($1, $2, $3, $4, $5, 'manual', 'done', 'succeeded', $6,
'/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', now(), now())`, dep, cert, loc, target, job, hex64("a"))
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `DELETE FROM jobs WHERE id = $1`, job)
	require.NoError(t, err)
	var jobID *uuid.UUID
	require.NoError(t, d.App.QueryRow(ctx, `SELECT job_id FROM deployments WHERE id = $1`, dep).Scan(&jobID))
	assert.Nil(t, jobID)
}

func TestCertificateTablesHaveNoPlaintextOrNow(t *testing.T) {
	d := pgtest.New(t)
	rows, err := d.Owner.Query(context.Background(), `SELECT table_name, column_name, column_default FROM information_schema.columns
WHERE table_schema = 'public' AND table_name IN ('managed_private_keys', 'certificates', 'csr_requests', 'certificate_locations', 'deployments', 'deployment_steps')
  AND column_default IS NOT NULL`)
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

func TestDeploymentIndexes(t *testing.T) {
	d := pgtest.New(t)
	rows, err := d.Owner.Query(context.Background(), `SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'deployments'`)
	require.NoError(t, err)
	defer rows.Close()
	defs := map[string]string{}
	for rows.Next() {
		var n, def string
		require.NoError(t, rows.Scan(&n, &def))
		defs[n] = def
	}
	require.NoError(t, rows.Err())
	assert.Contains(t, defs["deployments_job"], "(job_id) WHERE (job_id IS NOT NULL)", "the foreign key of a pruned job")
	assert.Contains(t, defs["deployments_location"], "(location_id, created_at DESC, id DESC)")
}

// A finished deployment is history: nothing but the link to a pruned job changes.
func TestFinishedDeploymentIsFrozen(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	ctx := context.Background()
	job := uuid.New()
	_, err := d.Owner.Exec(ctx, `INSERT INTO jobs (id, type, class, kind, payload_mac, target_id, status, run_at, max_attempts, created_at)
VALUES ($1, 'certificate.deploy', 'change', 'user', $2, $3, 'succeeded', now(), 3, now())`, job, make([]byte, 32), w.target)
	require.NoError(t, err)
	now := time.Now()
	row := with(deploymentRow(w), map[string]any{"state": "done", "status": "failed", "finished_at": now, "job_id": job, "error_code": "ALC-X"})
	require.NoError(t, insertRow(t, d.App, "deployments", row))
	id := row["id"]
	for _, stmt := range []string{
		"UPDATE deployments SET status = 'succeeded', error_code = '' WHERE id = $1",
		"UPDATE deployments SET state = 'recovering', status = 'running', finished_at = NULL WHERE id = $1",
		"UPDATE deployments SET state = 'queued', status = 'pending', finished_at = NULL WHERE id = $1",
		"UPDATE deployments SET verified = 'remote' WHERE id = $1",
		"UPDATE deployments SET result = 'committed' WHERE id = $1",
		"UPDATE deployments SET phase = 'committed' WHERE id = $1",
		"UPDATE deployments SET finished_at = now() + interval '1 day' WHERE id = $1",
		"UPDATE deployments SET previous_fingerprint = '' , new_chain_length = 9 WHERE id = $1",
		"UPDATE deployments SET error_params = '{\"a\":\"b\"}' WHERE id = $1",
		"UPDATE deployments SET job_id = gen_random_uuid() WHERE id = $1", // not an existing job: refused by the trigger first
	} {
		assert.Equal(t, doneFrozen, sqlState(exec(t, d.App, stmt, id)), stmt)
	}
	assert.Equal(t, doneFrozen, sqlState(exec(t, d.Owner, "UPDATE deployments SET status = 'succeeded' WHERE id = $1", id)), "the owner role too")
	require.NoError(t, exec(t, d.App, "UPDATE deployments SET error_code = error_code WHERE id = $1", id), "an update that changes nothing")
	_, err = d.App.Exec(ctx, "DELETE FROM jobs WHERE id = $1", job)
	require.NoError(t, err, "the job is pruned: the foreign key sets job_id to NULL on a finished deployment")
	var jobID *uuid.UUID
	var code string
	require.NoError(t, d.App.QueryRow(ctx, "SELECT job_id, error_code FROM deployments WHERE id = $1", id).Scan(&jobID, &code))
	assert.Nil(t, jobID)
	assert.Equal(t, "ALC-X", code)
	assert.Equal(t, doneFrozen, sqlState(exec(t, d.App, "UPDATE deployments SET job_id = $2 WHERE id = $1", id, uuid.New())), "a job link is never added to a finished deployment")

	// An unfinished one stays writable, and becomes done in one update.
	open := deploymentRow(w)
	require.NoError(t, exec(t, d.App, "UPDATE deployments SET state = state WHERE id = $1", id))
	require.NoError(t, insertRow(t, d.App, "deployments", open))
	require.NoError(t, exec(t, d.App, "UPDATE deployments SET state = 'done', status = 'succeeded', finished_at = now(), result = 'committed' WHERE id = $1", open["id"]))
}
