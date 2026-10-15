package license_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/secrets"
)

func keyring(t *testing.T, b byte) *secrets.Keyring {
	t.Helper()
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{b}, 32))
	require.NoError(t, err)
	return k
}

func TestHWMRecordRoundTrip(t *testing.T) {
	c := license.NewHWMCodec(keyring(t, 1))
	at := time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	raw, err := c.Encode(license.HWMRecord{At: at, Seq: 42})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "2026", "the time is not readable in the record")
	got, err := c.Decode(raw)
	require.NoError(t, err)
	assert.True(t, got.At.Equal(at))
	assert.Equal(t, uint64(42), got.Seq)
}

// L-54: a damaged or forged record is treated as missing, never as valid.
func TestHWMRecordRejectsTampering(t *testing.T) {
	c := license.NewHWMCodec(keyring(t, 1))
	raw, err := c.Encode(license.HWMRecord{At: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Seq: 1})
	require.NoError(t, err)
	other, err := c.Encode(license.HWMRecord{At: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Seq: 9})
	require.NoError(t, err)
	var w, o map[string]any
	require.NoError(t, json.Unmarshal(raw, &w))
	require.NoError(t, json.Unmarshal(other, &o))

	flipped := []byte(w["data"].(string))
	flipped[5] ^= 0x01
	swapMAC, err := json.Marshal(map[string]any{"v": 1, "data": w["data"], "mac": o["mac"]})
	require.NoError(t, err)
	flipData, err := json.Marshal(map[string]any{"v": 1, "data": string(flipped), "mac": w["mac"]})
	require.NoError(t, err)
	v2, err := json.Marshal(map[string]any{"v": 2, "data": w["data"], "mac": w["mac"]})
	require.NoError(t, err)

	for name, bad := range map[string][]byte{
		"bit flip in data":    flipData,
		"MAC of other record": swapMAC,
		"unknown version":     v2,
		"garbage":             []byte("not json"),
		"empty object":        []byte("{}"),
		"extra field":         []byte(`{"v":1,"data":"","mac":"","x":1}`),
		"trailing bytes":      append(append([]byte(nil), raw...), []byte(" {}")...),
		"trailing brace":      append(append([]byte(nil), raw...), '}'),
	} {
		_, err := c.Decode(bad)
		assert.ErrorIs(t, err, license.ErrHWMInvalid, name)
	}
	_, err = license.NewHWMCodec(keyring(t, 2)).Decode(raw)
	assert.ErrorIs(t, err, license.ErrHWMInvalid, "a record from another installation's master key")
}

func TestFileHWMStore(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	s := license.FileHWMStore{Path: filepath.Join(dir, license.HWMFileName)}
	got, err := s.Load(ctx)
	require.NoError(t, err)
	assert.Nil(t, got, "missing file = no record")

	require.NoError(t, s.Save(ctx, []byte(`{"v":1}`)))
	require.NoError(t, s.Save(ctx, []byte(`{"v":1,"n":2}`)))
	got, err = s.Load(ctx)
	require.NoError(t, err)
	assert.Equal(t, `{"v":1,"n":2}`, string(got))
	info, err := os.Stat(s.Path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary files are left behind")
	assert.Equal(t, "file", s.Name())
}

// A huge or unreadable file on the state volume never exhausts memory and is never a valid record.
func TestFileHWMStoreBoundsAndErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := license.FileHWMStore{Path: filepath.Join(dir, license.HWMFileName)}
	require.NoError(t, os.WriteFile(s.Path, bytes.Repeat([]byte("x"), 1<<20), 0o600))
	got, err := s.Load(ctx)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(got), 4097, "the read is bounded")
	_, err = license.NewHWMCodec(keyring(t, 1)).Decode(got)
	assert.ErrorIs(t, err, license.ErrHWMInvalid)

	_, err = license.FileHWMStore{Path: dir}.Load(ctx)
	require.Error(t, err, "a directory is not a missing record")

	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	err = license.FileHWMStore{Path: filepath.Join(blocker, license.HWMFileName)}.Save(ctx, []byte("{}"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "{}", "the record is never part of an error")
}

func TestHWMRecordRejectsTimesBefore1970(t *testing.T) {
	_, err := license.NewHWMCodec(keyring(t, 1)).Encode(license.HWMRecord{At: time.Unix(-1, 0)})
	require.Error(t, err)
}
