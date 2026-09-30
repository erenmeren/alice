// Package breached answers "is this password on the list of the 100,000 most
// used passwords?" fully offline (SEC-003). The list is the NCSC top-100k from
// SecLists, stored as sorted 8-byte SHA-256 prefixes; regenerate it with
// tools/breachlist.
package breached

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"sort"
)

//go:embed ncsc-100k.bin
var list []byte

// Len returns the number of entries in the embedded list.
func Len() int { return len(list) / 8 }

func at(i int) uint64 { return binary.BigEndian.Uint64(list[8*i : 8*i+8]) }

// Contains reports whether password (compared exactly, byte for byte) is on the list.
func Contains(password string) bool {
	sum := sha256.Sum256([]byte(password))
	want := binary.BigEndian.Uint64(sum[:8])
	n := Len()
	i := sort.Search(n, func(i int) bool { return at(i) >= want })
	return i < n && at(i) == want
}
