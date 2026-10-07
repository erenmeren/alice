package alerts

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"alice/internal/alerts/expiry"
	"alice/internal/audit"
	"alice/internal/notify"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

type thresholdRecord struct {
	Days    []int `json:"days"`
	Version int   `json:"version"`
}

// Thresholds reads the thresholds setting; never saved, it is the defaults at version 0.
func (s *Service) Thresholds(ctx context.Context) (ThresholdSettings, error) {
	return readThresholds(ctx, s.pool)
}

func readThresholds(ctx context.Context, q db.Querier) (ThresholdSettings, error) {
	var rec thresholdRecord
	ok, err := settings.Get(ctx, q, ThresholdsKey, &rec)
	if err != nil {
		return ThresholdSettings{}, err
	}
	if !ok || len(rec.Days) == 0 {
		return ThresholdSettings{Days: slices.Clone(expiry.DefaultThresholds), Version: rec.Version}, nil
	}
	// Stored values that no longer pass the rules (edited by hand) must not fail every item of every scan.
	days, err := expiry.Normalize(rec.Days)
	if err != nil {
		return ThresholdSettings{Days: slices.Clone(expiry.DefaultThresholds), Version: rec.Version}, nil
	}
	return ThresholdSettings{Days: days, Version: rec.Version}, nil
}

// SaveThresholds validates and stores the thresholds at version (0 = never saved).
func (s *Service) SaveThresholds(ctx context.Context, a audit.Actor, version int, days []int) (ThresholdSettings, error) {
	var v validate.Errors
	switch {
	case len(days) == 0:
		v.Add("thresholds_days", validate.Required, nil)
	case len(days) > expiry.MaxThresholds:
		v.Add("thresholds_days", validate.TooLong, map[string]string{"max": strconv.Itoa(expiry.MaxThresholds)})
	default:
		for i, d := range days {
			switch {
			case d < 1 || d > expiry.MaxThresholdDays:
				v.Add("thresholds_days", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(expiry.MaxThresholdDays)})
			case slices.Contains(days[:i], d):
				v.Add("thresholds_days", validate.Duplicate, nil)
			}
			if len(v) > 0 {
				break
			}
		}
	}
	if err := v.Err(); err != nil {
		return ThresholdSettings{}, err
	}
	norm, err := expiry.Normalize(days)
	if err != nil {
		return ThresholdSettings{}, validate.Errors{{Field: "thresholds_days", Code: validate.OutOfRange}}
	}
	var out ThresholdSettings
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, ThresholdsKey); err != nil {
			return fmt.Errorf("alerts: lock the thresholds: %w", err)
		}
		cur, err := readThresholds(ctx, tx)
		if err != nil {
			return err
		}
		if cur.Version != version {
			return notify.ErrVersion
		}
		out = ThresholdSettings{Days: norm, Version: version + 1}
		if err := settings.Set(ctx, tx, ThresholdsKey, thresholdRecord(out), s.clock.Now()); err != nil {
			return err
		}
		parts := make([]string, len(norm))
		for i, d := range norm {
			parts[i] = strconv.Itoa(d)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "settings.thresholds_changed", ObjectType: "setting",
			ObjectID: ThresholdsKey, Result: audit.Success, Details: map[string]string{"thresholds": strings.Join(parts, ",")}})
		return err
	})
	return out, err
}
