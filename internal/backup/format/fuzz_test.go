package format_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"alice/internal/backup/format"
)

// FuzzBackupHeader (§25.6): any input either parses within the bounds of C7 or is refused with one of the
// documented errors; never a panic, never a header longer than MaxHeaderLen read into memory.
func FuzzBackupHeader(f *testing.F) {
	w := wrapped(f)
	file := seal(f, w, payload(10))
	f.Add(file)
	f.Add(file[:20])
	f.Add([]byte("ALICEBK1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := format.ReadHeader(bytes.NewReader(b))
		if err != nil {
			if !errors.Is(err, format.ErrNotBackup) && !errors.Is(err, format.ErrNewerFormat) && !errors.Is(err, format.ErrHeader) {
				t.Fatalf("undocumented error %v", err)
			}
			return
		}
		k := h.WrappedKey.KDF
		if k.MemoryKiB < format.MinKDFMemoryKiB || k.MemoryKiB > format.MaxKDFMemoryKiB || k.Time > format.MaxKDFTime ||
			k.Threads > format.MaxKDFThreads || h.ChunkSize != format.ChunkSize {
			t.Fatalf("header outside the bounds was accepted: %+v", k)
		}
	})
}

// FuzzBackupStream: whatever happens to a valid file, Open either fails or returns exactly the original payload;
// what a failing Reader returned before its error is always a prefix of the original payload.
func FuzzBackupStream(f *testing.F) {
	w := wrapped(f)
	priv, err := w.w.Unwrap(pass)
	require.NoError(f, err)
	plain := payload(2*format.ChunkSize + 77)
	file := seal(f, w, plain)
	f.Add(file, uint32(0), byte(0), uint32(len(file)))
	f.Add([]byte{}, uint32(0), byte(0), uint32(len(file)))
	f.Add([]byte{}, uint32(len(file)-1), byte(1), uint32(len(file)))
	f.Add([]byte{}, uint32(0), byte(0), uint32(len(file)-17))
	f.Fuzz(func(t *testing.T, base []byte, pos uint32, xor byte, cut uint32) {
		b := append([]byte{}, file...)
		if len(base) > 0 { // let the fuzzer also try arbitrary files
			b = append([]byte{}, base...)
		}
		if len(b) > 0 {
			b[int(pos)%len(b)] ^= xor
			b = b[:int(cut)%(len(b)+1)]
		}
		r, _, err := format.OpenWithKey(bytes.NewReader(b), priv, w.s.PublicKey())
		if err != nil {
			return
		}
		got, err := io.ReadAll(r)
		if err == nil && !bytes.Equal(got, plain) {
			t.Fatalf("a modified file decrypted to other data (%d bytes)", len(got))
		}
		if !bytes.HasPrefix(plain, got) {
			t.Fatalf("a failing reader returned data that is not the original's prefix (%d bytes)", len(got))
		}
	})
}
