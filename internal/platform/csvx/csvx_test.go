package csvx

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Review Focus 4: every formula prefix a spreadsheet evaluates is neutralised; nothing else changes.
func TestSafeNeutralisesFormulaPrefixes(t *testing.T) {
	for in, want := range map[string]string{
		"=1+1": "'=1+1", "+1": "'+1", "-1": "'-1", "@SUM(A1)": "'@SUM(A1)", "\tx": "'\tx", "\rx": "'\rx", "\nx": "'\nx", "\n=1": "'\n=1",
		"=HYPERLINK(\"http://x\")": "'=HYPERLINK(\"http://x\")",
		"admin":                    "admin", "": "", "İzmir": "İzmir", " =1": " =1", "a=1": "a=1", "'quoted": "'quoted",
	} {
		assert.Equal(t, want, Safe(in), "%q", in)
	}
}

// Review Focus 4: a BOM, then RFC 4180 records with quotes, commas and newlines intact and every cell made safe.
func TestWriterQuotesAndBOM(t *testing.T) {
	var b bytes.Buffer
	w, err := NewWriter(&b)
	require.NoError(t, err)
	require.NoError(t, w.Write([]string{"id", "label"}))
	require.NoError(t, w.Write([]string{"1", "=cmd|' /C calc'!A0"}))
	require.NoError(t, w.Write([]string{"2", "a,b \"c\"\nd"}))
	require.NoError(t, w.Write([]string{"3", "Iğdır İç Ağ"}))
	require.NoError(t, w.Flush())
	out := b.Bytes()
	require.True(t, bytes.HasPrefix(out, []byte("\xEF\xBB\xBF")), "UTF-8 byte order mark first")
	rows, err := csv.NewReader(bytes.NewReader(out[3:])).ReadAll()
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"id", "label"}, {"1", "'=cmd|' /C calc'!A0"}, {"2", "a,b \"c\"\nd"}, {"3", "Iğdır İç Ağ"}}, rows)
	assert.True(t, strings.HasSuffix(string(out), "\n"))
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}
	f.after--
	return len(p), nil
}

func TestWriterReportsWriteErrors(t *testing.T) {
	_, err := NewWriter(&failWriter{after: 0})
	assert.Error(t, err, "the BOM write fails")
	w, err := NewWriter(&failWriter{after: 1})
	require.NoError(t, err)
	require.NoError(t, w.Write([]string{"x"})) // buffered
	assert.Error(t, w.Flush())
}
