// Package expiry decides which expiry notice is due (spec §26.9, R2; R42 rows 4 and 5). It is pure: the caller
// passes every time and the thresholds; nothing is read or written. One rule gives both "no duplicates" and
// "catch-up after downtime": only the most urgent reached level is ever due, and only when no notice at that level
// or a more urgent one was sent for the same expiry instant.
package expiry

import (
	"errors"
	"slices"
	"time"
)

// DefaultThresholds are the days before an expiry at which a notice is sent (R2).
var DefaultThresholds = []int{60, 30, 14, 7, 1}

const (
	// MaxThresholds and MaxThresholdDays bound the thresholds setting.
	MaxThresholds    = 10
	MaxThresholdDays = 365
	// Expired is the level of the notice sent once an item has expired; it is more urgent than every threshold.
	Expired = 0

	day = 24 * time.Hour
)

// ErrThresholds refuses a thresholds setting.
var ErrThresholds = errors.New("expiry: thresholds must be 1 to 10 different whole days from 1 to 365")

// Normalize validates days and returns a new slice sorted from the largest to the smallest.
func Normalize(days []int) ([]int, error) {
	if len(days) == 0 || len(days) > MaxThresholds {
		return nil, ErrThresholds
	}
	out := slices.Clone(days)
	slices.Sort(out)
	for i, d := range out {
		if d < 1 || d > MaxThresholdDays || (i > 0 && out[i-1] == d) {
			return nil, ErrThresholds
		}
	}
	slices.Reverse(out)
	return out, nil
}

// Level is the most urgent level an item that expires at expiresAt has reached at now: Expired once
// expiresAt <= now, else the smallest threshold t with expiresAt - now <= t days. ok is false when the item
// has reached no threshold yet.
func Level(expiresAt, now time.Time, thresholds []int) (level int, ok bool) {
	left := expiresAt.Sub(now)
	if left <= 0 {
		return Expired, true
	}
	for _, t := range thresholds {
		if left <= time.Duration(t)*day && (!ok || t < level) {
			level, ok = t, true
		}
	}
	return level, ok
}

// Due returns the notice to send at now. sent holds the levels already recorded for the same expiry instant.
// Nothing is due when a notice at the reached level or a more urgent one (a smaller number) was sent: after
// downtime the skipped, less urgent notices are never sent, and no level is sent twice.
func Due(expiresAt, now time.Time, thresholds, sent []int) (int, bool) {
	level, ok := Level(expiresAt, now, thresholds)
	if !ok {
		return 0, false
	}
	for _, s := range sent {
		if s <= level {
			return 0, false
		}
	}
	return level, true
}

// DaysLeft is the number of whole days left, rounded up (6 days and 1 hour is 7), and 0 once expired.
func DaysLeft(expiresAt, now time.Time) int {
	left := expiresAt.Sub(now)
	if left <= 0 {
		return 0
	}
	return int((left + day - 1) / day)
}

// Horizon is how far ahead a scan must look: the largest threshold.
func Horizon(thresholds []int) time.Duration {
	if len(thresholds) == 0 {
		return 0
	}
	return time.Duration(slices.Max(thresholds)) * day
}

// Bucket is the dashboard group of an expiry; the windows exclude each other (R42 row 14).
type Bucket string

// Dashboard buckets.
const (
	BucketExpired Bucket = "expired"
	Bucket7       Bucket = "7"
	Bucket30      Bucket = "30"
	Bucket60      Bucket = "60"
	BucketLater   Bucket = "later"
)

// BucketOf places an expiry in its dashboard bucket.
func BucketOf(expiresAt, now time.Time) Bucket {
	switch left := expiresAt.Sub(now); {
	case left <= 0:
		return BucketExpired
	case left <= 7*day:
		return Bucket7
	case left <= 30*day:
		return Bucket30
	case left <= 60*day:
		return Bucket60
	default:
		return BucketLater
	}
}
