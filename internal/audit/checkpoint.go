package audit

import (
	"context"
	"fmt"
	"time"

	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// Checkpoint is the last verified chain head (R16: the dashboard shows it for offline recording).
type Checkpoint struct {
	Seq  int64
	Hash string // hex
	At   time.Time
}

// LastCheckpoint reads the stored checkpoint; ok is false before the first verification.
func LastCheckpoint(ctx context.Context, q db.Querier) (Checkpoint, bool, error) {
	var cp checkpoint
	ok, err := settings.Get(ctx, q, checkpointKey, &cp)
	if err != nil {
		return Checkpoint{}, false, fmt.Errorf("audit: read checkpoint: %w", err)
	}
	if !ok {
		return Checkpoint{}, false, nil
	}
	at, err := time.Parse(time.RFC3339, cp.At)
	if err != nil {
		return Checkpoint{}, false, fmt.Errorf("audit: read checkpoint: %w", err)
	}
	return Checkpoint{Seq: cp.Seq, Hash: cp.Hash, At: at.UTC()}, true, nil
}
