package dump_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"alice/internal/backup/dump"
)

// FuzzDecoder: whatever the input, the decoder never panics, never returns a frame above MaxData or with a name above
// MaxName, and once Next failed it keeps failing.
func FuzzDecoder(f *testing.F) {
	f.Add(encode(f, manifest, frame{dump.TableStart, "users", []byte(`{"name":"users","columns":["id"]}`)},
		frame{dump.Data, "users", []byte("PGCOPY")}, frame{dump.TableEnd, "users", []byte(`{"rows":0}`)}, seqs,
		frame{dump.File, "keys/master.key", []byte("k")}, end))
	f.Add(encode(f, manifest, seqs, end))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		dec := dump.NewDecoder(bytes.NewReader(b))
		for range 10_000 {
			fr, err := dec.Next()
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, dump.ErrPayload) {
					t.Fatalf("undocumented error %v", err)
				}
				if _, again := dec.Next(); again == nil {
					t.Fatal("Next succeeded after an error")
				}
				return
			}
			if len(fr.Data) > dump.MaxData || len(fr.Name) > dump.MaxName {
				t.Fatalf("frame above the bounds: %d data bytes, %d name bytes", len(fr.Data), len(fr.Name))
			}
		}
	})
}
