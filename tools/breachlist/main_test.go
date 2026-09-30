package main

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func prefix(s string) uint64 {
	sum := sha256.Sum256([]byte(s))
	return binary.BigEndian.Uint64(sum[:8])
}

func TestHashesAreSortedUniqueAndSkipBlankLines(t *testing.T) {
	got, err := hashes(strings.NewReader("banana\r\napple\n\napple\ncherry"))
	require.NoError(t, err)
	assert.Len(t, got, 3)
	assert.IsIncreasing(t, got)
	assert.Contains(t, got, prefix("banana"), "trailing CR is stripped")
	assert.Contains(t, got, prefix("apple"))
	assert.Contains(t, got, prefix("cherry"))
}

func TestRunRejectsUnexpectedSource(t *testing.T) {
	dir := t.TempDir()
	in := dir + "/list.txt"
	require.NoError(t, os.WriteFile(in, []byte("password\n"), 0o600))
	_, err := run(in, dir+"/out.bin")
	assert.ErrorContains(t, err, "wrong or modified file")
}
