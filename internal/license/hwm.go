package license

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/secrets"
)

// HWMRecord is the persisted time high-water mark (spec §16.5).
type HWMRecord struct {
	At  time.Time // whole seconds, UTC
	Seq uint64    // grows with every save, so a replayed older record loses (L-55)
}

// ErrHWMInvalid means a stored record did not decrypt or its MAC did not match. Such a
// record is treated as missing, never as valid, and the finding is audited (L-54).
var ErrHWMInvalid = errors.New("license: the time record is damaged")

// Where the record lives.
const (
	HWMSettingKey = "time.hwm"
	HWMFileName   = "hwm.dat"
	hwmAAD        = "alice/hwm-record/v1"
	maxHWMRecord  = 4096
)

// HWMCodec encrypts and MACs HWM records with keys derived from the master key.
type HWMCodec struct{ keyring *secrets.Keyring }

// NewHWMCodec returns a codec for the installation's master key.
func NewHWMCodec(k *secrets.Keyring) HWMCodec { return HWMCodec{keyring: k} }

// hwmWire is the stored form {v:1, data, mac}: data is AES-GCM(hwm || seq) under
// alice/hwm-enc/v1 (confidentiality is a convenience) and mac is
// HMAC-SHA256(K_hwm, "v1" || hwm || seq) with K_hwm = HKDF(master, "alice/hwm/v1").
type hwmWire struct {
	V    int    `json:"v"`
	Data string `json:"data"`
	MAC  string `json:"mac"`
}

// Encode seals r.
func (c HWMCodec) Encode(r HWMRecord) ([]byte, error) {
	secs := r.At.Unix()
	if secs < 0 {
		return nil, errors.New("license: time record before 1970")
	}
	plain := make([]byte, 16)
	binary.BigEndian.PutUint64(plain, uint64(secs)) //nolint:gosec // G115: secs is checked non-negative above
	binary.BigEndian.PutUint64(plain[8:], r.Seq)
	sealed, err := c.keyring.SealWith(secrets.LabelHWMEnc, []byte(hwmAAD), plain)
	if err != nil {
		return nil, err
	}
	return json.Marshal(hwmWire{
		V:    1,
		Data: base64.StdEncoding.EncodeToString(sealed),
		MAC:  base64.StdEncoding.EncodeToString(c.mac(plain)),
	})
}

// Decode opens a record. Every failure is ErrHWMInvalid.
func (c HWMCodec) Decode(raw []byte) (HWMRecord, error) {
	if len(raw) > maxHWMRecord {
		return HWMRecord{}, ErrHWMInvalid
	}
	var w hwmWire
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || w.V != 1 {
		return HWMRecord{}, ErrHWMInvalid
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return HWMRecord{}, ErrHWMInvalid // trailing bytes after the object
	}
	sealed, err1 := base64.StdEncoding.DecodeString(w.Data)
	mac, err2 := base64.StdEncoding.DecodeString(w.MAC)
	if err1 != nil || err2 != nil {
		return HWMRecord{}, ErrHWMInvalid
	}
	plain, err := c.keyring.OpenWith(secrets.LabelHWMEnc, []byte(hwmAAD), sealed)
	if err != nil || len(plain) != 16 || !hmac.Equal(mac, c.mac(plain)) {
		return HWMRecord{}, ErrHWMInvalid
	}
	secs := binary.BigEndian.Uint64(plain[:8])
	if secs > math.MaxInt64 {
		return HWMRecord{}, ErrHWMInvalid
	}
	return HWMRecord{At: time.Unix(int64(secs), 0).UTC(), Seq: binary.BigEndian.Uint64(plain[8:])}, nil //nolint:gosec // G115: bounded above
}

func (c HWMCodec) mac(plain []byte) []byte {
	key := c.keyring.Derive(secrets.LabelHWM)
	defer clear(key)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("v1"))
	m.Write(plain)
	return m.Sum(nil)
}

// HWMStore is one place the record is kept. Load returns nil, nil when there is none.
type HWMStore interface {
	Name() string
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, record []byte) error
}

// SettingsHWMStore keeps the record in settings (key time.hwm).
type SettingsHWMStore struct {
	Q     db.Querier
	Clock clock.Clock
}

// Name implements HWMStore.
func (SettingsHWMStore) Name() string { return "settings" }

// Load implements HWMStore.
func (s SettingsHWMStore) Load(ctx context.Context) ([]byte, error) {
	var raw json.RawMessage
	found, err := settings.Get(ctx, s.Q, HWMSettingKey, &raw)
	if err != nil || !found {
		return nil, err
	}
	return raw, nil
}

// Save implements HWMStore.
func (s SettingsHWMStore) Save(ctx context.Context, record []byte) error {
	return settings.Set(ctx, s.Q, HWMSettingKey, json.RawMessage(record), s.Clock.Now())
}

// FileHWMStore keeps the record in a file on the state volume, written atomically.
type FileHWMStore struct{ Path string }

// Name implements HWMStore.
func (FileHWMStore) Name() string { return "file" }

// Load implements HWMStore. Only a regular file is read: a symlink is not followed and a
// FIFO or device is not waited on. It reads at most one byte more than a valid record
// can have, so an oversized file is rejected by Decode without being read into memory.
func (f FileHWMStore) Load(context.Context) ([]byte, error) {
	file, err := os.OpenFile(f.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the path comes from ALICE_STATE_DIR, not from a request
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the time record: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("read the time record: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("read the time record: not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(file, maxHWMRecord+1))
	if err != nil {
		return nil, fmt.Errorf("read the time record: %w", err)
	}
	return b, nil
}

// Save implements HWMStore: temporary file (mode 0600), fsync, rename, directory fsync.
func (f FileHWMStore) Save(_ context.Context, record []byte) error {
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create the state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".hwm-*.tmp")
	if err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op after a successful rename
	if _, err := tmp.Write(record); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the time record: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the time record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	if err := os.Rename(name, f.Path); err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	return syncDir(dir)
}

// syncDir makes a completed rename durable.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the directory of the configured record path
	if err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	return nil
}
