package backup

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"time"

	"alice/internal/backup/dump"
	"alice/internal/backup/format"
)

// ManifestFormat is the version of the manifest frame.
const ManifestFormat = 1

// ErrDamaged means the file opened as a backup but its payload is wrong: a wrong passphrase, a failed chunk tag,
// truncation, trailing data, a malformed payload or a payload that disagrees with its manifest. It wraps the cause.
var ErrDamaged = errors.New("backup: the passphrase is wrong or the file is damaged")

// Manifest is the first frame of the payload (C7). The row counts and the audit head are read inside the dump's
// snapshot.
type Manifest struct {
	Format         int              `json:"format"`
	AliceVersion   string           `json:"alice_version"`
	SchemaVersion  int64            `json:"schema_version"`
	CreatedAt      time.Time        `json:"created_at"`
	Kind           Kind             `json:"kind"`
	Reason         string           `json:"reason"`
	InstallationID string           `json:"installation_id"`
	Hostname       string           `json:"hostname"`
	Tables         map[string]int64 `json:"tables"`
	AuditHead      AuditHead        `json:"audit_head"`
	Files          []string         `json:"files"`
}

// AuditHead is the newest audit row at the snapshot: its sequence number and hash (hex). Zero on an empty log.
type AuditHead struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// payloadFile is one file of the payload: its F-frame name and where it lives (C7's fixed four-entry table).
type payloadFile struct {
	Name     string
	InKeys   bool // in KeysDir, else in StateDir
	File     string
	Optional bool
}

// payloadFiles is the only mapping between F-frame names and files: a name is never joined into a path.
var payloadFiles = []payloadFile{
	{Name: "keys/master.key", InKeys: true, File: "master.key"},
	{Name: "keys/tls.crt", InKeys: true, File: "tls.crt", Optional: true},
	{Name: "keys/tls.key", InKeys: true, File: "tls.key", Optional: true},
	{Name: "state/hwm.dat", File: "hwm.dat", Optional: true},
}

// endFrame is the data of the Z frame.
type endFrame struct {
	Tables int `json:"tables"`
	Files  int `json:"files"`
}

// damaged wraps err in ErrDamaged, except the two errors that are not about the payload: not a backup at all, and a
// backup of a newer format.
func damaged(err error) error {
	if errors.Is(err, format.ErrNotBackup) || errors.Is(err, format.ErrNewerFormat) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrDamaged, err)
}

// readPayload decrypts and decodes a whole backup file with the passphrase and checks that the payload agrees with
// its manifest: every table's E row count equals the manifest's, the files are the manifest's in its order and only
// names of the fixed table, each once, and the end frame counts both. It reads to the end of the encrypted stream,
// because a payload is complete only at io.EOF. visit, when not nil, sees every frame after the manifest.
func readPayload(path string, passphrase []byte, visit func(dump.Frame) error) (Manifest, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path of a backup the operator named
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Manifest{}, ErrNotFound
		}
		return Manifest{}, fmt.Errorf("backup: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	rd, _, err := format.Open(bufio.NewReader(f), passphrase)
	if err != nil {
		return Manifest{}, damaged(err)
	}
	gz, err := gzip.NewReader(rd)
	if err != nil {
		return Manifest{}, damaged(err)
	}
	m, err := decodePayload(dump.NewDecoder(gz), visit)
	if err != nil {
		return Manifest{}, damaged(err)
	}
	// The decoder ended at io.EOF of the gzip stream, which gzip reports only after the container did; reading the
	// container to its end once more makes "complete only at io.EOF" explicit (no decompression happens here).
	if _, err := io.Copy(io.Discard, rd); err != nil {
		return Manifest{}, damaged(err)
	}
	return m, nil
}

var errMismatch = errors.New("backup: the payload does not match its manifest")

func decodePayload(dec *dump.Decoder, visit func(dump.Frame) error) (Manifest, error) {
	var m Manifest
	first, err := dec.Next()
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(first.Data, &m); err != nil {
		return m, fmt.Errorf("%w: the manifest is not JSON", dump.ErrPayload)
	}
	rows := map[string]int64{}
	var files []string
	var end *endFrame
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, err
		}
		switch f.Kind {
		case dump.TableEnd:
			var e struct {
				Rows int64 `json:"rows"`
			}
			if err := json.Unmarshal(f.Data, &e); err != nil {
				return m, fmt.Errorf("%w: end frame of table %s", dump.ErrPayload, f.Name)
			}
			rows[f.Name] = e.Rows
		case dump.File:
			if !slices.ContainsFunc(payloadFiles, func(p payloadFile) bool { return p.Name == f.Name }) || slices.Contains(files, f.Name) {
				return m, fmt.Errorf("%w: file frame %q", errMismatch, f.Name)
			}
			files = append(files, f.Name)
		case dump.End:
			end = &endFrame{}
			if err := json.Unmarshal(f.Data, end); err != nil {
				return m, fmt.Errorf("%w: the end frame is not JSON", dump.ErrPayload)
			}
		}
		if visit != nil {
			if err := visit(f); err != nil {
				return m, err
			}
		}
	}
	switch {
	case !maps.Equal(rows, m.Tables):
		return m, fmt.Errorf("%w: table row counts", errMismatch)
	case !slices.Equal(files, m.Files):
		return m, fmt.Errorf("%w: files", errMismatch)
	case end == nil || end.Tables != len(rows) || end.Files != len(files):
		return m, fmt.Errorf("%w: end frame", errMismatch)
	}
	return m, nil
}
