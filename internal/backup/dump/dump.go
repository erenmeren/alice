package dump

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// ErrSchemaMismatch means the payload's tables, columns or sequences differ from the target database's.
var ErrSchemaMismatch = errors.New("dump: the backup does not match the database schema")

// schema is the only schema Alice uses; gooseTable is goose's bookkeeping, which the target's own migrations write.
const (
	schema     = "public"
	gooseTable = "goose_db_version"
)

// Table is one ordinary table of the public schema and its copied columns (not dropped, not generated) in attnum
// order.
type Table struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

// Stats describes a dump or a load. Next is the first frame after the sequences (Load only).
type Stats struct {
	Tables int
	Rows   map[string]int64
	Next   Frame
}

// tableEnd is the data of an E frame.
type tableEnd struct {
	Rows int64 `json:"rows"`
}

// Tables lists every ordinary or partitioned table of the public schema except goose_db_version, sorted by name in
// byte order, with its columns.
func Tables(ctx context.Context, q db.Querier) ([]Table, error) {
	rows, err := q.Query(ctx, `SELECT c.relname::text, array_agg(a.attname::text ORDER BY a.attnum)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
WHERE n.nspname = $1 AND c.relkind IN ('r', 'p') AND c.relname <> $2
  AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = ''
GROUP BY c.relname
ORDER BY c.relname COLLATE "C"`, schema, gooseTable)
	if err != nil {
		return nil, fmt.Errorf("dump: list the tables: %w", err)
	}
	tables, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Table, error) {
		var t Table
		err := r.Scan(&t.Name, &t.Columns)
		return t, err
	})
	if err != nil {
		return nil, fmt.Errorf("dump: list the tables: %w", err)
	}
	return tables, nil
}

// Counts returns the number of rows of every table.
func Counts(ctx context.Context, q db.Querier, tables []Table) (map[string]int64, error) {
	counts := make(map[string]int64, len(tables))
	for _, t := range tables {
		var n int64
		if err := q.QueryRow(ctx, statement(countRows, t)).Scan(&n); err != nil {
			return nil, fmt.Errorf("dump: count the rows of %s: %w", t.Name, err)
		}
		counts[t.Name] = n
	}
	return counts, nil
}

type verb int

const (
	countRows verb = iota
	copyTo
	copyFrom
)

// statement builds the only SQL text of the package that contains identifiers: table and column names read from
// pg_catalog (or checked against it), each quoted by pgx.Identifier. No value is ever interpolated.
func statement(v verb, t Table) string {
	table := pgx.Identifier{schema, t.Name}.Sanitize()
	if v == countRows {
		return "SELECT count(*) FROM " + table
	}
	cols := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		cols[i] = pgx.Identifier{c}.Sanitize()
	}
	dir := "TO STDOUT"
	if v == copyFrom {
		dir = "FROM STDIN"
	}
	//nolint:gosec // G202: identifiers are read from pg_catalog and quoted by pgx.Identifier; no value is interpolated
	return "COPY " + table + " (" + strings.Join(cols, ", ") + ") " + dir + " (FORMAT binary)"
}

func copyOut(t Table) string { return statement(copyTo, t) }
func copyIn(t Table) string  { return statement(copyFrom, t) }

// dataWriter cuts a COPY stream into D frames of at most MaxData bytes.
type dataWriter struct {
	enc   *Encoder
	table string
	buf   []byte
}

func (w *dataWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		k := min(MaxData-len(w.buf), len(p))
		w.buf = append(w.buf, p[:k]...)
		p = p[k:]
		if len(w.buf) == MaxData {
			if err := w.flush(); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

func (w *dataWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	err := w.enc.Frame(Data, w.table, w.buf)
	w.buf = w.buf[:0]
	return err
}

// Dump writes, for every table, T (its name and columns), the binary COPY of its rows as D frames and E (its row
// count), then Q (the last value of every sequence of the public schema). tx must be the caller's REPEATABLE READ
// transaction, so every table is read from the same snapshot (F-86). The manifest and the end frame are the caller's.
func Dump(ctx context.Context, tx pgx.Tx, enc *Encoder, tables []Table) (Stats, error) {
	st := Stats{Rows: make(map[string]int64, len(tables))}
	w := &dataWriter{enc: enc, buf: make([]byte, 0, MaxData)}
	for _, t := range tables {
		if err := enc.JSON(TableStart, t.Name, t); err != nil {
			return st, err
		}
		w.table = t.Name
		tag, err := tx.Conn().PgConn().CopyTo(ctx, w, copyOut(t))
		if err == nil {
			err = w.flush()
		}
		if err != nil {
			return st, fmt.Errorf("dump: copy table %s: %w", t.Name, err)
		}
		if err := enc.JSON(TableEnd, t.Name, tableEnd{Rows: tag.RowsAffected()}); err != nil {
			return st, err
		}
		st.Tables++
		st.Rows[t.Name] = tag.RowsAffected()
	}
	seqs, err := sequences(ctx, tx)
	if err != nil {
		return st, err
	}
	return st, enc.JSON(Sequences, "sequences.json", seqs)
}

// sequences returns the last value of every sequence of the public schema, keyed "public.<name>"; the value is nil
// when the sequence was never used or the role may not read it.
func sequences(ctx context.Context, q db.Querier) (map[string]*int64, error) {
	rows, err := q.Query(ctx, `SELECT sequencename::text, last_value FROM pg_catalog.pg_sequences WHERE schemaname = $1 ORDER BY 1`, schema)
	if err != nil {
		return nil, fmt.Errorf("dump: read the sequences: %w", err)
	}
	m := map[string]*int64{}
	var name string
	var v *int64
	_, err = pgx.ForEachRow(rows, []any{&name, &v}, func() error {
		m[schema+"."+name] = v
		v = nil
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("dump: read the sequences: %w", err)
	}
	return m, nil
}
