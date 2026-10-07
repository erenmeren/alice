package settings

import (
	"context"

	"alice/internal/platform/db"
)

// GeneralKey holds Alice's own address and the retired-key retention (R42 row 30).
const (
	GeneralKey                     = "general"
	DefaultRetiredKeyRetentionDays = 30
)

// General is the general settings record.
type General struct {
	PublicURL               string `json:"public_url"`                 // "" or an https:// origin
	RetiredKeyRetentionDays int    `json:"retired_key_retention_days"` // 1..3650
	Version                 int    `json:"version"`                    // 0 = never saved
}

// GetGeneral reads the general settings, with the defaults when they were never saved.
func GetGeneral(ctx context.Context, q db.Querier) (General, error) {
	g := General{RetiredKeyRetentionDays: DefaultRetiredKeyRetentionDays}
	if _, err := Get(ctx, q, GeneralKey, &g); err != nil {
		return General{}, err
	}
	if g.RetiredKeyRetentionDays < 1 {
		g.RetiredKeyRetentionDays = DefaultRetiredKeyRetentionDays
	}
	return g, nil
}
