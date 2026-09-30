// Command breachlist converts the pinned NCSC top-100k password list into the
// compact lookup file embedded by internal/auth/breached: sorted, de-duplicated
// big-endian uint64 values, each the first 8 bytes of SHA-256(password).
//
// Usage: go run ./tools/breachlist -in <list.txt> -out internal/auth/breached/ncsc-100k.bin
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
)

// sourceSHA256 pins SecLists commit 1a7bb9127eca9e6ff2fc0301c597fe6e16a0cb56,
// Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt (MIT licence).
const sourceSHA256 = "c2e5696882c603b76bb67a47ee970897e5a76fc4c3f5547abe3d0ca340c576e0"

func main() {
	in := flag.String("in", "", "path of the downloaded password list")
	out := flag.String("out", "", "path of the .bin file to write")
	flag.Parse()
	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: breachlist -in <list.txt> -out <file.bin>")
		os.Exit(2)
	}
	n, err := run(*in, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "breachlist:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "wrote %d entries to %s\n", n, *out)
}

func run(inPath, outPath string) (int, error) {
	data, err := os.ReadFile(inPath) //nolint:gosec // G304: developer tool, path from the command line
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != sourceSHA256 {
		return 0, fmt.Errorf("source list has sha256 %s, want %s (wrong or modified file)", got, sourceSHA256)
	}
	values, err := hashes(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	buf := make([]byte, 8*len(values))
	for i, v := range values {
		binary.BigEndian.PutUint64(buf[8*i:], v)
	}
	if err := os.WriteFile(outPath, buf, 0o644); err != nil { //nolint:gosec // G306: public, non-secret data file
		return 0, err
	}
	return len(values), nil
}

// hashes returns the sorted, de-duplicated 8-byte SHA-256 prefixes of every
// non-empty line. Lines are used exactly as written (a trailing CR is removed).
func hashes(r io.Reader) ([]uint64, error) {
	var out []uint64
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := bytes.TrimSuffix(sc.Bytes(), []byte("\r"))
		if len(line) == 0 {
			continue
		}
		sum := sha256.Sum256(line)
		out = append(out, binary.BigEndian.Uint64(sum[:8]))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
