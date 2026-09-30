package license

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// FileInfo is one stored upload as the License page lists it.
type FileInfo struct {
	ID         uuid.UUID
	Seq        int64
	UploadedAt time.Time
	Status     string // current | pending | superseded | invalid
	KeyID      string
	Payload    *Payload // nil when the file no longer verifies
}

// HistoryEntry is one license_history row.
type HistoryEntry struct {
	At        time.Time
	Event     string
	LicenseID string
	FromState string
	ToState   string
	Notice    string
	Details   map[string]string
}

// Detail is everything the License page shows.
type Detail struct {
	Snapshot Snapshot
	Files    []FileInfo     // newest first
	History  []HistoryEntry // newest first, at most historyLimit
}

const historyLimit = 100

// Detail reads the stored files and the recent history. It writes nothing.
func (s *Service) Detail(ctx context.Context) (Detail, error) {
	snap := s.Snapshot()
	if !snap.Ready {
		return Detail{}, ErrNoInstallation
	}
	files, err := loadFiles(ctx, s.pool)
	if err != nil {
		return Detail{}, err
	}
	d := Detail{Snapshot: snap, Files: []FileInfo{}, History: []HistoryEntry{}}
	for i := len(files) - 1; i >= 0; i-- {
		f := files[i]
		// Evaluate chooses independently of upload order, so any file that is neither in
		// force nor the pending one is superseded (also a later upload that started earlier).
		info := FileInfo{ID: f.ID, Seq: f.Seq, UploadedAt: f.UploadedAt, Status: "superseded"}
		in, err := s.verifyStored(f, snap.InstallationID)
		switch {
		case err != nil:
			info.Status = "invalid"
		case f.Seq == snap.Eval.CurrentSeq:
			info.Status = "current"
		case f.Seq == snap.Eval.PendingSeq:
			info.Status = "pending"
		}
		if err == nil {
			p := in.Payload
			info.Payload, info.KeyID = &p, in.KeyID
		}
		d.Files = append(d.Files, info)
	}
	rows, err := s.pool.Query(ctx, `SELECT at, event, license_id, from_state, to_state, coalesce(notice, ''), details
FROM license_history ORDER BY at DESC, id DESC LIMIT $1`, historyLimit)
	if err != nil {
		return Detail{}, fmt.Errorf("read license history: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h HistoryEntry
		var raw []byte
		if err := rows.Scan(&h.At, &h.Event, &h.LicenseID, &h.FromState, &h.ToState, &h.Notice, &raw); err != nil {
			return Detail{}, fmt.Errorf("read license history: %w", err)
		}
		h.At = h.At.UTC()
		if err := json.Unmarshal(raw, &h.Details); err != nil {
			return Detail{}, fmt.Errorf("read license history: %w", err)
		}
		d.History = append(d.History, h)
	}
	return d, rows.Err()
}
