package dump

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Load consumes the tables (T D* E …) and the sequences frame (Q) of a payload, starting with first, and copies them
// into the database of conn. It checks every table against Tables of the target: the names must be strictly ascending,
// each must exist with the same columns in the same order, and no target table may be left out; the Q keys must be
// exactly the target's public sequences. Any difference is ErrSchemaMismatch (S-14). A row count that differs from
// the E frame is ErrPayload. Load returns at the first frame after Q, which Stats.Next holds.
//
// The target is a freshly migrated database; the rows a migration seeds there (00025: the environments, the Default
// service and its first policy) are replaced by the backup's: a table that holds rows is emptied before its rows are
// copied (under the caller's session_replication_role = replica no trigger and no foreign key action runs).
//
// Load runs in the caller's transaction and never changes the connection's settings: the caller sets
// session_replication_role and decides whether to commit. Nothing it copied is visible before that commit.
func Load(ctx context.Context, conn *pgx.Conn, dec *Decoder, first Frame) (Stats, error) {
	st := Stats{Rows: map[string]int64{}}
	target, err := Tables(ctx, conn)
	if err != nil {
		return st, err
	}
	byName := make(map[string]Table, len(target))
	for _, t := range target {
		byName[t.Name] = t
	}
	f, prev := first, ""
	for f.Kind == TableStart {
		t, err := checkTable(f, byName, prev)
		if err != nil {
			return st, err
		}
		prev = t.Name
		if err := clearSeeded(ctx, conn, t); err != nil {
			return st, err
		}
		rows, err := copyTable(ctx, conn, dec, t)
		if err != nil {
			return st, err
		}
		st.Tables++
		st.Rows[t.Name] = rows
		if f, err = dec.Next(); err != nil {
			return st, err
		}
	}
	if f.Kind != Sequences {
		return st, fmt.Errorf("%w: frame %q where the sequences were expected", ErrPayload, f.Kind)
	}
	if st.Tables != len(target) {
		for _, t := range target {
			if _, ok := st.Rows[t.Name]; !ok {
				return st, fmt.Errorf("%w: table %s is not in the backup", ErrSchemaMismatch, t.Name)
			}
		}
	}
	if err := setSequences(ctx, conn, f.Data); err != nil {
		return st, err
	}
	if st.Next, err = dec.Next(); err != nil {
		return st, err
	}
	return st, nil
}

// clearSeeded empties a target table that holds rows before the backup's are copied into it (see Load).
func clearSeeded(ctx context.Context, conn *pgx.Conn, t Table) error {
	name := pgx.Identifier{"public", t.Name}.Sanitize()
	var seeded bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+name+")").Scan(&seeded); err != nil {
		return fmt.Errorf("dump: read table %s: %w", t.Name, err)
	}
	if !seeded {
		return nil
	}
	if _, err := conn.Exec(ctx, "DELETE FROM "+name); err != nil {
		return fmt.Errorf("dump: empty table %s: %w", t.Name, err)
	}
	return nil
}

// checkTable parses a T frame and compares it with the target.
func checkTable(f Frame, target map[string]Table, prev string) (Table, error) {
	var t Table
	if err := json.Unmarshal(f.Data, &t); err != nil || t.Name != f.Name {
		return Table{}, fmt.Errorf("%w: table frame %q is invalid", ErrPayload, f.Name)
	}
	if prev != "" && t.Name <= prev {
		return Table{}, fmt.Errorf("%w: table %s follows %s", ErrSchemaMismatch, t.Name, prev)
	}
	want, ok := target[t.Name]
	if !ok {
		return Table{}, fmt.Errorf("%w: table %s does not exist in this database", ErrSchemaMismatch, t.Name)
	}
	if !slices.Equal(want.Columns, t.Columns) {
		return Table{}, fmt.Errorf("%w: the columns of table %s differ", ErrSchemaMismatch, t.Name)
	}
	return want, nil
}

// frameReader yields the D frames of one table to CopyFrom and stops at its E frame.
type frameReader struct {
	dec *Decoder
	cur []byte
	end *Frame
	err error
}

func (r *frameReader) Read(p []byte) (int, error) {
	for len(r.cur) == 0 {
		if r.end != nil {
			return 0, io.EOF
		}
		f, err := r.dec.Next() // inside a table the decoder yields only D or E, or an error (never io.EOF)
		if err != nil {
			r.err = err
			return 0, err
		}
		if f.Kind == TableEnd {
			r.end = &f
			return 0, io.EOF
		}
		r.cur = f.Data
	}
	n := copy(p, r.cur)
	r.cur = r.cur[n:]
	return n, nil
}

// copyTable feeds the table's D frames to COPY FROM and checks the copied row count against its E frame.
func copyTable(ctx context.Context, conn *pgx.Conn, dec *Decoder, t Table) (int64, error) {
	r := &frameReader{dec: dec}
	tag, err := conn.PgConn().CopyFrom(ctx, r, copyIn(t))
	if r.err != nil {
		return 0, r.err
	}
	if err != nil {
		return 0, fmt.Errorf("dump: load table %s: %w", t.Name, err)
	}
	var e tableEnd
	if err := json.Unmarshal(r.end.Data, &e); err != nil {
		return 0, fmt.Errorf("%w: end frame of table %s is invalid", ErrPayload, t.Name)
	}
	if e.Rows != tag.RowsAffected() {
		return 0, fmt.Errorf("%w: table %s has %d rows, its end frame says %d", ErrPayload, t.Name, tag.RowsAffected(), e.Rows)
	}
	return e.Rows, nil
}

// setSequences checks the Q frame against the target's sequences and sets every non-null value.
func setSequences(ctx context.Context, conn *pgx.Conn, data []byte) error {
	var in map[string]*int64
	if err := json.Unmarshal(data, &in); err != nil {
		return fmt.Errorf("%w: the sequences frame is invalid", ErrPayload)
	}
	have, err := sequences(ctx, conn)
	if err != nil {
		return err
	}
	if len(in) != len(have) {
		return fmt.Errorf("%w: the backup has %d sequences, this database %d", ErrSchemaMismatch, len(in), len(have))
	}
	for key := range in {
		if _, ok := have[key]; !ok {
			return fmt.Errorf("%w: sequence %s does not exist in this database", ErrSchemaMismatch, key)
		}
	}
	for _, key := range slices.Sorted(func(yield func(string) bool) {
		for k := range in {
			if !yield(k) {
				return
			}
		}
	}) {
		v := in[key]
		if v == nil {
			continue
		}
		name := strings.TrimPrefix(key, schema+".")
		if _, err := conn.Exec(ctx, "SELECT setval($1::regclass, $2, true)", pgx.Identifier{schema, name}.Sanitize(), *v); err != nil {
			return fmt.Errorf("dump: set sequence %s: %w", key, err)
		}
	}
	return nil
}
