//go:build integration

package dump_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/backup/dump"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var ctx = context.Background()

// dumpDB dumps d through the app pool in one REPEATABLE READ READ ONLY transaction and returns the payload (M, the
// tables, Q, Z) and the counts read at the start of the transaction.
func dumpDB(t *testing.T, pool *pgxpool.Pool) ([]byte, map[string]int64) {
	t.Helper()
	var b bytes.Buffer
	counts := dumpTo(t, pool, &b)
	return b.Bytes(), counts
}

func dumpTo(t *testing.T, pool *pgxpool.Pool, w io.Writer) map[string]int64 {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	tables, err := dump.Tables(ctx, tx)
	require.NoError(t, err)
	counts, err := dump.Counts(ctx, tx, tables)
	require.NoError(t, err)
	enc := dump.NewEncoder(w)
	require.NoError(t, enc.JSON(dump.Manifest, "manifest.json", map[string]any{"tables": counts}))
	st, err := dump.Dump(ctx, tx, enc, tables)
	require.NoError(t, err)
	assert.Equal(t, len(tables), st.Tables)
	assert.Equal(t, counts, st.Rows)
	require.NoError(t, enc.JSON(dump.End, "end", map[string]int{"tables": st.Tables, "files": 0}))
	require.NoError(t, enc.Flush())
	require.NoError(t, tx.Commit(ctx))
	return counts
}

// load loads payload into the database of pool as the owner under session_replication_role = replica, inside one
// transaction that commits only when commit is true and Load succeeded.
func load(t *testing.T, pool *pgxpool.Pool, payload []byte, commit bool) (dump.Stats, error) {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "SET LOCAL session_replication_role = replica")
	require.NoError(t, err)
	dec := dump.NewDecoder(bytes.NewReader(payload))
	m, err := dec.Next()
	require.NoError(t, err)
	require.Equal(t, dump.Manifest, m.Kind)
	first, err := dec.Next()
	if err != nil {
		return dump.Stats{}, err
	}
	st, err := dump.Load(ctx, tx.Conn(), dec, first)
	if err != nil {
		return st, err
	}
	if commit {
		require.NoError(t, tx.Commit(ctx))
	}
	return st, nil
}

// rewrite decodes payload and re-encodes it with every frame replaced by what fn returns.
func rewrite(t *testing.T, payload []byte, fn func(f dump.Frame) []dump.Frame) []byte {
	t.Helper()
	dec := dump.NewDecoder(bytes.NewReader(payload))
	var out bytes.Buffer
	enc := dump.NewEncoder(&out)
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		for _, g := range fn(f) {
			require.NoError(t, enc.Frame(g.Kind, g.Name, g.Data))
		}
	}
	require.NoError(t, enc.Flush())
	return out.Bytes()
}

func tableNames(t *testing.T, q db.Querier) []string {
	t.Helper()
	tables, err := dump.Tables(ctx, q)
	require.NoError(t, err)
	names := make([]string, len(tables))
	for i, tb := range tables {
		names[i] = tb.Name
	}
	return names
}

func rowCounts(t *testing.T, q db.Querier) map[string]int64 {
	t.Helper()
	tables, err := dump.Tables(ctx, q)
	require.NoError(t, err)
	c, err := dump.Counts(ctx, q, tables)
	require.NoError(t, err)
	return c
}

func requireEmpty(t *testing.T, d *pgtest.DB) {
	t.Helper()
	for name, n := range rowCounts(t, d.Owner) {
		require.Zerof(t, n, "table %s of the fresh database has rows", name)
	}
}

// tableDigest is the md5 of every row of table as text, in text order.
func tableDigest(t *testing.T, q db.Querier, table string) string {
	t.Helper()
	var sum string
	//nolint:gosec // G202: the table name comes from pg_catalog and is quoted by pgx.Identifier
	require.NoError(t, q.QueryRow(ctx, "SELECT md5(coalesce(string_agg(t::text, ',' ORDER BY t::text), '')) FROM "+
		pgx.Identifier{"public", table}.Sanitize()+" t").Scan(&sum))
	return sum
}

func TestTablesListsEveryOrdinaryTable(t *testing.T) {
	d := pgtest.New(t)
	_, err := d.Owner.Exec(ctx, `CREATE TABLE public.with_generated (a int, dropped int, b int GENERATED ALWAYS AS (a * 2) STORED, c text);
ALTER TABLE public.with_generated DROP COLUMN dropped;
CREATE VIEW public.a_view AS SELECT 1 AS x;
CREATE SCHEMA other; CREATE TABLE other.hidden (x int);`)
	require.NoError(t, err)

	got, err := dump.Tables(ctx, d.App)
	require.NoError(t, err)

	rows, err := d.Owner.Query(ctx, `SELECT c.table_name::text, array_agg(c.column_name::text ORDER BY c.ordinal_position)
FROM information_schema.columns c JOIN information_schema.tables t USING (table_schema, table_name)
WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE' AND c.table_name <> 'goose_db_version' AND c.is_generated = 'NEVER'
GROUP BY c.table_name`)
	require.NoError(t, err)
	var want []dump.Table
	for rows.Next() {
		var tb dump.Table
		require.NoError(t, rows.Scan(&tb.Name, &tb.Columns))
		want = append(want, tb)
	}
	require.NoError(t, rows.Err())
	sort.Slice(want, func(i, j int) bool { return want[i].Name < want[j].Name })
	assert.Equal(t, want, got)
	assert.Contains(t, got, dump.Table{Name: "with_generated", Columns: []string{"a", "c"}})
	assert.Greater(t, len(got), 30, "every table of the schema")
}

// fill puts at least one row into every table the setup and seed helpers can fill.
func fill(t *testing.T, d *pgtest.DB) {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	kr, err := secrets.LoadOrCreateMasterKey(ctx, d.App, t.TempDir(), clk.Now())
	require.NoError(t, err)
	h := auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	log := audit.New(clk)
	a := auth.NewService(auth.Config{Pool: d.App, Keyring: kr, Audit: log, Clock: clk, Hasher: h, RecoveryHasher: h})
	s := setup.New(setup.Config{Pool: d.App, Auth: a, Keyring: kr, Audit: log, Clock: clk, Hasher: h,
		BackupKDF: secrets.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}})
	code, err := s.ResetToken(ctx)
	require.NoError(t, err)
	meta := auth.Meta{RequestID: "fill"}
	token, err := s.StartSession(ctx, code, meta)
	require.NoError(t, err)
	enr, err := s.BeginAdminEnrollment(ctx, token, setup.AdminInput{Username: "admin", DisplayName: "Ayşe", Password: "correct horse battery staple"})
	require.NoError(t, err)
	totpCode, err := totp.GenerateCode(enr.Secret, clk.Now())
	require.NoError(t, err)
	res, err := s.CreateAdmin(ctx, token, totpCode, meta)
	require.NoError(t, err)
	p, err := a.Authenticate(ctx, res.Token)
	require.NoError(t, err)
	require.NoError(t, s.SetRecoveryPassphrase(ctx, p, meta, "a long and safe recovery passphrase", "a long and safe recovery passphrase"))
	_, err = seed.Dashboard(ctx, d.Owner, clk.Now())
	require.NoError(t, err)
	vault, err := seed.Target(ctx, d.Owner, "vault1", "azure_key_vault", "ok", nil)
	require.NoError(t, err)
	_, _, err = seed.KeyVault(ctx, d.Owner, vault, "cert1", clk.Now().Add(90*24*time.Hour), nil, "key1", clk.Now().Add(90*24*time.Hour))
	require.NoError(t, err)
	insertJob(t, d.App)
	appendAudit(t, d.App, log, "fill.done")
}

func insertJob(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO jobs (id, type, class, kind, payload, payload_mac, status, run_at, max_attempts, created_at)
VALUES ($1, 'test.job', 'always', 'system', '{"x":1}', $2, 'queued', now(), 3, now())`, uuid.New(), bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
}

func appendAudit(t *testing.T, pool *pgxpool.Pool, log *audit.Log, action string) {
	t.Helper()
	require.NoError(t, db.InTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := log.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("test"), Action: action, Result: audit.Success})
		return err
	}))
}

func TestDumpLoadRoundTripsEveryTable(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	countsA := rowCounts(t, a.Owner)
	for _, name := range []string{"users", "user_mfa", "sessions", "settings", "setting_secrets", "audit_log", "master_key_versions",
		"targets", "credentials", "certificates", "certificate_locations", "deployments", "kv_certificates",
		"kv_certificate_versions", "kv_keys", "jobs"} {
		require.Positivef(t, countsA[name], "table %s was filled", name)
	}
	payload, counts := dumpDB(t, a.App)
	assert.Equal(t, countsA, counts)

	b := pgtest.New(t)
	requireEmpty(t, b) // migrations seed nothing; TRUNCATE is refused by audit_log_no_truncate (M-26)
	st, err := load(t, b.Owner, payload, true)
	require.NoError(t, err)
	assert.Equal(t, dump.End, st.Next.Kind, "Load returns at the first frame after Q")
	assert.Equal(t, len(countsA), st.Tables)
	assert.Equal(t, countsA, st.Rows)

	for _, name := range tableNames(t, a.Owner) {
		assert.Equalf(t, tableDigest(t, a.Owner, name), tableDigest(t, b.Owner, name), "table %s", name)
	}
	seqs := func(q db.Querier) map[string]*int64 {
		rows, err := q.Query(ctx, "SELECT sequencename::text, last_value FROM pg_sequences WHERE schemaname = 'public'")
		require.NoError(t, err)
		m := map[string]*int64{}
		for rows.Next() {
			var n string
			var v *int64
			require.NoError(t, rows.Scan(&n, &v))
			m[n] = v
		}
		require.NoError(t, rows.Err())
		return m
	}
	sa, sb := seqs(a.App), seqs(b.App)
	assert.Len(t, sb, len(sa))
	for n, v := range sa {
		if v != nil {
			assert.Equalf(t, *v, *sb[n], "sequence %s", n)
		}
	}

	ra, err := audit.Verify(ctx, a.App)
	require.NoError(t, err)
	rb, err := audit.Verify(ctx, b.App)
	require.NoError(t, err)
	assert.True(t, rb.Intact)
	assert.Equal(t, ra.HeadSeq, rb.HeadSeq)
	assert.Equal(t, ra.HeadHash, rb.HeadHash)
}

// TestF86ConsistentSnapshot: rows committed while the dump runs are not in the payload.
func TestF86ConsistentSnapshot(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	// A first table large enough that its copy blocks on the pipe while the writers commit.
	_, err := a.Owner.Exec(ctx, `CREATE TABLE public.aaa_big (id int PRIMARY KEY, pad text NOT NULL);
INSERT INTO public.aaa_big SELECT g, repeat('x', 200) FROM generate_series(1, 20000) g;
GRANT SELECT ON public.aaa_big TO alice_app`)
	require.NoError(t, err)
	log := audit.New(clock.NewFake(time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)))

	pr, pw := io.Pipe()
	var payload bytes.Buffer
	var counts map[string]int64
	dumped := make(chan struct{})
	go func() {
		defer close(dumped)
		counts = dumpTo(t, a.App, pw)
		_ = pw.Close()
	}()
	// Read the first bytes: the dump is inside the first table now, and blocks on the pipe.
	first := make([]byte, 64<<10)
	n, err := io.ReadFull(pr, first)
	require.NoError(t, err)
	payload.Write(first[:n])

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			appendAudit(t, a.App, log, "concurrent.append")
			insertJob(t, a.App)
		})
	}
	wg.Wait()
	_, err = io.Copy(&payload, pr)
	require.NoError(t, err)
	<-dumped

	after := rowCounts(t, a.Owner)
	assert.Equal(t, counts["audit_log"]+50, after["audit_log"], "the writers committed while the dump ran")
	assert.Equal(t, counts["jobs"]+50, after["jobs"])

	rows := map[string]int64{}
	dec := dump.NewDecoder(bytes.NewReader(payload.Bytes()))
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if f.Kind == dump.TableEnd {
			var e struct{ Rows int64 }
			require.NoError(t, json.Unmarshal(f.Data, &e))
			rows[f.Name] = e.Rows
		}
	}
	assert.Equal(t, counts, rows, "the payload holds exactly the snapshot taken at the start")

	b := pgtest.New(t)
	_, err = b.Owner.Exec(ctx, `CREATE TABLE public.aaa_big (id int PRIMARY KEY, pad text NOT NULL)`)
	require.NoError(t, err)
	_, err = load(t, b.Owner, payload.Bytes(), true)
	require.NoError(t, err)
	rep, err := audit.Verify(ctx, b.App)
	require.NoError(t, err)
	assert.True(t, rep.Intact, "no half-appended chain")
	assert.Equal(t, counts["audit_log"], rep.Checked)
}

// tableJSON is the data of a T frame.
type tableJSON struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

func TestLoadRefusesASchemaMismatch(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	payload, _ := dumpDB(t, a.App)
	for name, change := range map[string]func([]string) []string{
		"unknown column": func(c []string) []string { return append(c, "extra") },
		"missing column": func(c []string) []string { return c[:len(c)-1] },
		"other order":    func(c []string) []string { return append([]string{c[len(c)-1]}, c[:len(c)-1]...) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := rewrite(t, payload, func(f dump.Frame) []dump.Frame {
				if f.Kind == dump.TableStart && f.Name == "settings" {
					var tj tableJSON
					require.NoError(t, json.Unmarshal(f.Data, &tj))
					tj.Columns = change(tj.Columns)
					f.Data, _ = json.Marshal(tj)
				}
				return []dump.Frame{f}
			})
			b := pgtest.New(t)
			_, err := load(t, b.Owner, bad, true)
			require.ErrorIs(t, err, dump.ErrSchemaMismatch)
			requireEmpty(t, b)
		})
	}
	t.Run("name differs from the frame", func(t *testing.T) {
		bad := rewrite(t, payload, func(f dump.Frame) []dump.Frame {
			if f.Kind == dump.TableStart && f.Name == "settings" {
				f.Data = []byte(`{"name":"users","columns":["key"]}`)
			}
			return []dump.Frame{f}
		})
		b := pgtest.New(t)
		_, err := load(t, b.Owner, bad, true)
		require.ErrorIs(t, err, dump.ErrPayload)
		requireEmpty(t, b)
	})
	t.Run("row count differs from the end frame", func(t *testing.T) {
		bad := rewrite(t, payload, func(f dump.Frame) []dump.Frame {
			if f.Kind == dump.TableEnd && f.Name == "users" {
				f.Data = []byte(`{"rows":99}`)
			}
			return []dump.Frame{f}
		})
		b := pgtest.New(t)
		_, err := load(t, b.Owner, bad, true)
		require.ErrorIs(t, err, dump.ErrPayload)
		requireEmpty(t, b)
	})
	t.Run("damaged copy data", func(t *testing.T) {
		bad := rewrite(t, payload, func(f dump.Frame) []dump.Frame {
			if f.Kind == dump.Data && len(f.Data) > 30 {
				f.Data = f.Data[:len(f.Data)-7]
			}
			return []dump.Frame{f}
		})
		b := pgtest.New(t)
		_, err := load(t, b.Owner, bad, true)
		require.Error(t, err)
		requireEmpty(t, b)
	})
}

func TestLoadRefusesMissingDuplicateOrUnorderedTables(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	payload, _ := dumpDB(t, a.App)
	// Collect each table's frames, so the cases can drop, repeat or swap whole tables.
	var head, tail []dump.Frame
	var tables [][]dump.Frame
	dec := dump.NewDecoder(bytes.NewReader(payload))
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		switch f.Kind {
		case dump.Manifest:
			head = append(head, f)
		case dump.TableStart:
			tables = append(tables, []dump.Frame{f})
		case dump.Data, dump.TableEnd:
			tables[len(tables)-1] = append(tables[len(tables)-1], f)
		default:
			tail = append(tail, f)
		}
	}
	build := func(ts [][]dump.Frame) []byte {
		var out bytes.Buffer
		enc := dump.NewEncoder(&out)
		for _, f := range head {
			require.NoError(t, enc.Frame(f.Kind, f.Name, f.Data))
		}
		for _, tb := range ts {
			for _, f := range tb {
				require.NoError(t, enc.Frame(f.Kind, f.Name, f.Data))
			}
		}
		for _, f := range tail {
			require.NoError(t, enc.Frame(f.Kind, f.Name, f.Data))
		}
		require.NoError(t, enc.Flush())
		return out.Bytes()
	}
	n := len(tables)
	cases := map[string]struct {
		tables [][]dump.Frame
		err    error
	}{
		"first missing":  {tables[1:], dump.ErrSchemaMismatch},
		"middle missing": {append(append([][]dump.Frame{}, tables[:n/2]...), tables[n/2+1:]...), dump.ErrSchemaMismatch},
		"last missing":   {tables[:n-1], dump.ErrSchemaMismatch},
		"repeated":       {append(append([][]dump.Frame{}, tables[:2]...), tables[1:]...), dump.ErrPayload},
		"unordered":      {append([][]dump.Frame{tables[1], tables[0]}, tables[2:]...), dump.ErrSchemaMismatch},
		"unknown table": {append(append([][]dump.Frame{}, tables...), []dump.Frame{
			{Kind: dump.TableStart, Name: "zzz_unknown", Data: []byte(`{"name":"zzz_unknown","columns":["a"]}`)},
			{Kind: dump.TableEnd, Name: "zzz_unknown", Data: []byte(`{"rows":0}`)}}), dump.ErrSchemaMismatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := pgtest.New(t)
			_, err := load(t, b.Owner, build(c.tables), true)
			require.ErrorIs(t, err, c.err)
			requireEmpty(t, b)
		})
	}
	t.Run("control", func(t *testing.T) {
		b := pgtest.New(t)
		_, err := load(t, b.Owner, build(tables), true)
		require.NoError(t, err)
	})
}

func TestLoadRefusesMissingSequences(t *testing.T) {
	const ddl = `CREATE SEQUENCE public.extra_seq; GRANT USAGE, SELECT ON SEQUENCE public.extra_seq TO alice_app`
	a := pgtest.New(t)
	_, err := a.Owner.Exec(ctx, ddl)
	require.NoError(t, err)
	_, err = a.Owner.Exec(ctx, "SELECT setval('public.extra_seq', 41)")
	require.NoError(t, err)
	payload, _ := dumpDB(t, a.App)

	var q map[string]*int64
	_ = rewrite(t, payload, func(f dump.Frame) []dump.Frame {
		if f.Kind == dump.Sequences {
			require.NoError(t, json.Unmarshal(f.Data, &q))
		}
		return []dump.Frame{f}
	})
	require.NotNil(t, q["public.extra_seq"])
	assert.Equal(t, int64(41), *q["public.extra_seq"])

	withQ := func(m map[string]*int64) []byte {
		return rewrite(t, payload, func(f dump.Frame) []dump.Frame {
			if f.Kind == dump.Sequences {
				f.Data, _ = json.Marshal(m)
			}
			return []dump.Frame{f}
		})
	}
	without := map[string]*int64{}
	for k, v := range q {
		if k != "public.extra_seq" {
			without[k] = v
		}
	}
	ghost := map[string]*int64{"public.ghost_seq": nil}
	for k, v := range q {
		ghost[k] = v
	}
	noPrefix := map[string]*int64{}
	for k, v := range q {
		noPrefix[k] = v
	}
	delete(noPrefix, "public.extra_seq")
	noPrefix["extra_seq"] = nil

	for name, stream := range map[string][]byte{"lacks one": withQ(without), "names an unknown one": withQ(ghost),
		"without schema": withQ(noPrefix)} {
		t.Run(name, func(t *testing.T) {
			b := pgtest.New(t)
			_, err := b.Owner.Exec(ctx, ddl)
			require.NoError(t, err)
			_, err = load(t, b.Owner, stream, true)
			require.ErrorIs(t, err, dump.ErrSchemaMismatch)
		})
	}
	t.Run("control", func(t *testing.T) {
		b := pgtest.New(t)
		_, err := b.Owner.Exec(ctx, ddl)
		require.NoError(t, err)
		_, err = load(t, b.Owner, payload, true)
		require.NoError(t, err)
		var v int64
		require.NoError(t, b.Owner.QueryRow(ctx, "SELECT last_value FROM public.extra_seq").Scan(&v))
		assert.Equal(t, int64(41), v)
	})
	t.Run("a sequence the target lacks", func(t *testing.T) {
		b := pgtest.New(t)
		_, err := load(t, b.Owner, payload, true)
		require.ErrorIs(t, err, dump.ErrSchemaMismatch)
	})
}

func TestCopyStatementsQuoteIdentifiers(t *testing.T) {
	const ddl = `CREATE TABLE public."odd ""table"" name" ("col ""x""" text)`
	odd := dump.Table{Name: `odd "table" name`, Columns: []string{`col "x"`}}
	assert.Equal(t, `COPY "public"."odd ""table"" name" ("col ""x""") TO STDOUT (FORMAT binary)`, dump.CopyOut(odd))
	assert.Equal(t, `COPY "public"."odd ""table"" name" ("col ""x""") FROM STDIN (FORMAT binary)`, dump.CopyIn(odd))

	a := pgtest.New(t)
	_, err := a.Owner.Exec(ctx, ddl+`; INSERT INTO public."odd ""table"" name" VALUES ('it''s "quoted"');
GRANT SELECT ON public."odd ""table"" name" TO alice_app`)
	require.NoError(t, err)
	payload, counts := dumpDB(t, a.App)
	assert.Equal(t, int64(1), counts[odd.Name])

	b := pgtest.New(t)
	_, err = b.Owner.Exec(ctx, ddl)
	require.NoError(t, err)
	_, err = load(t, b.Owner, payload, true)
	require.NoError(t, err)
	assert.Equal(t, tableDigest(t, a.Owner, odd.Name), tableDigest(t, b.Owner, odd.Name))
	var v string
	require.NoError(t, b.Owner.QueryRow(ctx, `SELECT "col ""x""" FROM public."odd ""table"" name"`).Scan(&v))
	assert.Equal(t, `it's "quoted"`, v)
}

// failAfter fails every write after n bytes.
type failAfter struct{ n int }

func (w *failAfter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		return 0, errors.New("no space left on device")
	}
	w.n -= len(p)
	return len(p), nil
}

func TestDumpReportsWriteErrors(t *testing.T) {
	a := pgtest.New(t)
	fill(t, a)
	_, err := a.Owner.Exec(ctx, `CREATE TABLE public.aaa_big (id int PRIMARY KEY, pad text NOT NULL);
INSERT INTO public.aaa_big SELECT g, repeat('x', 200) FROM generate_series(1, 20000) g;
GRANT SELECT ON public.aaa_big TO alice_app`)
	require.NoError(t, err)
	for _, limit := range []int{0, 100 << 10, 2 << 20} {
		tx, err := a.App.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		tables, err := dump.Tables(ctx, tx)
		require.NoError(t, err)
		enc := dump.NewEncoder(&failAfter{n: limit})
		_, err = dump.Dump(ctx, tx, enc, tables)
		if err == nil {
			err = enc.Flush()
		}
		require.ErrorContainsf(t, err, "no space left on device", "limit %d", limit)
		_ = tx.Rollback(ctx)
	}
}

func TestCatalogErrorsAreReported(t *testing.T) {
	a := pgtest.New(t)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := dump.Tables(cancelled, a.App)
	require.Error(t, err)
	_, err = dump.Counts(cancelled, a.App, []dump.Table{{Name: "users"}})
	require.Error(t, err)
	_, err = dump.Counts(ctx, a.App, []dump.Table{{Name: "no_such_table"}})
	require.Error(t, err)
}
