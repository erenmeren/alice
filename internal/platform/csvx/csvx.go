// Package csvx writes CSV files that spreadsheet programs open safely: UTF-8 with a byte order mark (spec §10.5)
// and every cell that a spreadsheet would read as a formula prefixed with an apostrophe (formula injection; R42
// row 16). It is used by the audit export and the inventory exports.
package csvx

import (
	"encoding/csv"
	"io"
)

const bom = "\xEF\xBB\xBF"

// Safe neutralises spreadsheet formula injection: a value that starts with = + - @ TAB, CR or LF is prefixed with an
// apostrophe. Other values are returned unchanged.
func Safe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n':
		return "'" + v
	}
	return v
}

// Writer writes formula-safe CSV records.
type Writer struct{ cw *csv.Writer }

// NewWriter writes the byte order mark to w and returns a writer for the records.
func NewWriter(w io.Writer) (*Writer, error) {
	if _, err := io.WriteString(w, bom); err != nil {
		return nil, err
	}
	return &Writer{cw: csv.NewWriter(w)}, nil
}

// Write writes one record, every cell passed through Safe.
func (w *Writer) Write(record []string) error {
	safe := make([]string, len(record))
	for i, v := range record {
		safe[i] = Safe(v)
	}
	return w.cw.Write(safe)
}

// Flush writes buffered records and reports any write error.
func (w *Writer) Flush() error {
	w.cw.Flush()
	return w.cw.Error()
}
