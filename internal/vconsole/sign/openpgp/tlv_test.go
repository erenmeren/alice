package openpgp

import (
	"testing"
)

// parseTLVs never panics and never returns a value that reaches outside its input.
func FuzzParseTLVs(f *testing.F) {
	for _, seed := range [][]byte{
		{0x6E, 0x03, 0x73, 0x01, 0x00},
		{0x7F, 0x49, 0x22, 0x86, 0x20},
		{0x6E, 0x81, 0x02, 0xC4, 0x00},
		{0x6E, 0x82, 0x00, 0x02, 0xC4, 0x00},
		{0x6E, 0x83, 0x00, 0x00, 0x01},
		{0x5F, 0xFF, 0xFF, 0xFF},
		{0x7F},
		{},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		objs, err := parseTLVs(b)
		if err != nil {
			return
		}
		total := 0
		for _, o := range objs {
			total += len(o.value)
			if o.constructed {
				_, _ = parseTLVs(o.value)
			}
		}
		if total > len(b) {
			t.Fatalf("values of %d bytes from %d input bytes", total, len(b))
		}
	})
}
