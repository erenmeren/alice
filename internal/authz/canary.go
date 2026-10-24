package authz

// The canary policy key (R65, design docs/superpowers/specs/2026-10-24-canary-deployment-design.md §5, §7): a service
// may ask that every multi-website deployment of its keys goes to a small subset first (wave 1), is observed for a
// hold time, and only then goes to the rest (wave 2). This file holds the key's document form, its validation and
// normalization (called from Policy.normalize), the effective settings a rollout snapshots, and the pure wave split.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"alice/internal/platform/validate"
)

// The values of canary.override.
const (
	CanaryOverrideAllowed   = "allowed"
	CanaryOverrideForbidden = "forbidden"
)

// Bounds and defaults of the canary key (design §5.1).
const (
	MinCanaryCount         = 1
	MaxCanaryCount         = 10
	MinCanaryPercent       = 1
	MaxCanaryPercent       = 50
	MaxCanaryFirst         = 20
	MinCanaryHold          = time.Minute
	MaxCanaryHold          = 24 * time.Hour
	MinCanaryInterval      = 15 * time.Second
	MaxCanaryInterval      = 10 * time.Minute
	MinCanaryFailures      = 1
	MaxCanaryFailures      = 10
	MaxCanaryPathBytes     = 512
	MaxCanaryHostBytes     = 253
	MaxCanaryExpectStatus  = 10
	MinCanaryTimeout       = time.Second
	MaxCanaryTimeout       = 10 * time.Second
	DefaultCanaryCount     = 1
	DefaultCanaryHold      = 10 * time.Minute
	DefaultCanaryInterval  = 30 * time.Second
	DefaultCanaryFailures  = 2
	DefaultCanaryTimeout   = 5 * time.Second
	DefaultCanaryStatusOK  = 200
	minCanaryStatus        = 100
	maxCanaryStatus        = 599
	maxCanaryPort          = 65535
	canaryDurationPatternS = `^[1-9][0-9]{0,4}(s|m|h)$`
)

var (
	policyOverride         = []string{CanaryOverrideAllowed, CanaryOverrideForbidden}
	canaryDurationPattern  = regexp.MustCompile(canaryDurationPatternS)
	errCanaryDurationValue = errors.New("authz: not a canary duration")
)

// CanaryPolicy is the canary key as stored: absent fields are the defaults (design §5.1), and explicit defaults are
// dropped by the normalization so that equal policies have equal documents.
type CanaryPolicy struct {
	Enabled  bool          `json:"enabled"`
	Subset   *CanarySubset `json:"subset,omitempty"`
	First    []uuid.UUID   `json:"first,omitempty"`
	Hold     string        `json:"hold,omitempty"`
	Interval string        `json:"interval,omitempty"`
	Failures *int          `json:"failures,omitempty"`
	Check    *CanaryCheck  `json:"check,omitempty"`
	Override string        `json:"override,omitempty"`
}

// CanarySubset is the size of wave 1: exactly one of a count or a percentage of the destinations.
type CanarySubset struct {
	Count   *int `json:"count,omitempty"`
	Percent *int `json:"percent,omitempty"`
}

// CanaryCheck is the optional HTTP application check (design §9.3): a request target, an optional server name and
// port. The address dialed is never part of it (decision 12).
type CanaryCheck struct {
	Path         string `json:"path"`
	Host         string `json:"host,omitempty"`
	Port         int    `json:"port,omitempty"`
	ExpectStatus []int  `json:"expect_status,omitempty"`
	Timeout      string `json:"timeout,omitempty"`
}

// CanarySettings are the effective canary values, defaults filled in: what a rollout snapshots (design §5.3). Exactly
// one of Count and Percent is set. Check, when set, carries its effective statuses and timeout too.
type CanarySettings struct {
	Count, Percent  int
	First           []uuid.UUID
	Hold, Interval  time.Duration
	Timeout         time.Duration
	Failures        int
	Check           *CanaryCheck
	OverrideAllowed bool
}

// canarySettingsJSON is the stored form of CanarySettings (durations written as the policy writes them).
type canarySettingsJSON struct {
	Count           int          `json:"count"`
	Percent         int          `json:"percent"`
	First           []uuid.UUID  `json:"first"`
	Hold            string       `json:"hold"`
	Interval        string       `json:"interval"`
	Failures        int          `json:"failures"`
	Check           *CanaryCheck `json:"check"`
	Timeout         string       `json:"timeout"`
	OverrideAllowed bool         `json:"override_allowed"`
}

// MarshalJSON writes the settings with readable durations.
func (s CanarySettings) MarshalJSON() ([]byte, error) {
	first := s.First
	if first == nil {
		first = []uuid.UUID{}
	}
	return json.Marshal(canarySettingsJSON{Count: s.Count, Percent: s.Percent, First: first, Hold: formatCanaryDuration(s.Hold),
		Interval: formatCanaryDuration(s.Interval), Failures: s.Failures, Check: s.Check, Timeout: formatCanaryDuration(s.Timeout),
		OverrideAllowed: s.OverrideAllowed})
}

// UnmarshalJSON reads what MarshalJSON wrote.
func (s *CanarySettings) UnmarshalJSON(b []byte) error {
	var j canarySettingsJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	out := CanarySettings{Count: j.Count, Percent: j.Percent, First: j.First, Failures: j.Failures, Check: j.Check,
		OverrideAllowed: j.OverrideAllowed}
	for _, f := range []struct {
		in  string
		out *time.Duration
	}{{j.Hold, &out.Hold}, {j.Interval, &out.Interval}, {j.Timeout, &out.Timeout}} {
		d, err := readSettingsDuration(f.in)
		if err != nil {
			return err
		}
		*f.out = d
	}
	*s = out
	return nil
}

func readSettingsDuration(s string) (time.Duration, error) {
	if s == "" || s == "0s" {
		return 0, nil
	}
	d, ok := parseCanaryDuration(s)
	if !ok {
		return 0, errCanaryDurationValue
	}
	return d, nil
}

// parseCanaryDuration reads a duration of the canary key: a decimal number without leading zero and one unit.
func parseCanaryDuration(s string) (time.Duration, bool) {
	if !canaryDurationPattern.MatchString(s) {
		return 0, false
	}
	n, _ := strconv.Atoi(s[:len(s)-1]) // the pattern admits 1..99999
	unit := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour}[s[len(s)-1]]
	return time.Duration(n) * unit, true
}

// formatCanaryDuration writes a whole number of seconds in the largest unit that divides it.
func formatCanaryDuration(d time.Duration) string {
	sec := int64(d / time.Second)
	switch {
	case sec != 0 && sec%3600 == 0:
		return strconv.FormatInt(sec/3600, 10) + "h"
	case sec != 0 && sec%60 == 0:
		return strconv.FormatInt(sec/60, 10) + "m"
	}
	return strconv.FormatInt(sec, 10) + "s"
}

// canaryDuration validates and normalizes one optional duration field; it answers the effective value and whether it
// is valid (an absent field is valid and answers def).
func canaryDuration(v *validate.Errors, field string, in *string, def, lo, hi time.Duration) (time.Duration, bool) {
	if *in == "" {
		return def, true
	}
	d, ok := parseCanaryDuration(*in)
	if !ok {
		v.Add(field, validate.Pattern, nil)
		return def, false
	}
	if d < lo || d > hi {
		v.Add(field, validate.OutOfRange, map[string]string{"min": formatCanaryDuration(lo), "max": formatCanaryDuration(hi)})
		return def, false
	}
	*in = formatCanaryDuration(d)
	if d == def {
		*in = ""
	}
	return d, true
}

func intRange(v *validate.Errors, field string, n, lo, hi int) bool {
	if n < lo || n > hi {
		v.Add(field, validate.OutOfRange, map[string]string{"min": strconv.Itoa(lo), "max": strconv.Itoa(hi)})
		return false
	}
	return true
}

// normalize validates the canary key (fields named prefix + the key's path) and drops its defaults; it answers false
// when the key is to be dropped (switched off with nothing else set).
func (c *CanaryPolicy) normalize(v *validate.Errors, prefix string) bool {
	if s := c.Subset; s != nil {
		switch {
		case (s.Count == nil) == (s.Percent == nil):
			v.Add(prefix+".subset", validate.OneOf, map[string]string{"values": "count, percent"})
		case s.Count != nil:
			if intRange(v, prefix+".subset.count", *s.Count, MinCanaryCount, MaxCanaryCount) && *s.Count == DefaultCanaryCount {
				c.Subset = nil
			}
		default:
			intRange(v, prefix+".subset.percent", *s.Percent, MinCanaryPercent, MaxCanaryPercent)
		}
	}
	if len(c.First) > MaxCanaryFirst {
		v.Add(prefix+".first", validate.TooLong, map[string]string{"max": strconv.Itoa(MaxCanaryFirst)})
	} else {
		for i, id := range c.First {
			field := prefix + ".first." + strconv.Itoa(i)
			switch {
			case id == uuid.Nil:
				v.Add(field, validate.Required, nil)
			case slices.Contains(c.First[:i], id):
				v.Add(field, validate.Duplicate, nil)
			}
		}
	}
	if len(c.First) == 0 {
		c.First = nil
	}
	hold, holdOK := canaryDuration(v, prefix+".hold", &c.Hold, DefaultCanaryHold, MinCanaryHold, MaxCanaryHold)
	interval, intervalOK := canaryDuration(v, prefix+".interval", &c.Interval, DefaultCanaryInterval, MinCanaryInterval, MaxCanaryInterval)
	if holdOK && intervalOK && interval > hold {
		v.Add(prefix+".interval", validate.OutOfRange, map[string]string{"min": formatCanaryDuration(MinCanaryInterval),
			"max": formatCanaryDuration(hold)})
		intervalOK = false
	}
	if c.Failures != nil && intRange(v, prefix+".failures", *c.Failures, MinCanaryFailures, MaxCanaryFailures) &&
		*c.Failures == DefaultCanaryFailures {
		c.Failures = nil
	}
	if ch := c.Check; ch != nil {
		ch.normalize(v, prefix+".check", interval, intervalOK)
	}
	closedValue(v, prefix+".override", c.Override, policyOverride)
	if c.Override == CanaryOverrideAllowed {
		c.Override = ""
	}
	return c.Enabled || c.Subset != nil || c.First != nil || c.Hold != "" || c.Interval != "" || c.Failures != nil ||
		c.Check != nil || c.Override != ""
}

func (ch *CanaryCheck) normalize(v *validate.Errors, prefix string, interval time.Duration, intervalOK bool) {
	switch {
	case ch.Path == "":
		v.Add(prefix+".path", validate.Required, nil)
	case len(ch.Path) > MaxCanaryPathBytes:
		v.Add(prefix+".path", validate.TooLong, map[string]string{"max": strconv.Itoa(MaxCanaryPathBytes)})
	case !validCheckPath(ch.Path):
		v.Add(prefix+".path", validate.Pattern, nil)
	}
	if ch.Host != "" {
		ch.Host = foldASCII(ch.Host)
		if !validCheckHost(ch.Host) {
			v.Add(prefix+".host", validate.Pattern, nil)
		}
	}
	intRange(v, prefix+".port", ch.Port, 0, maxCanaryPort)
	if ch.ExpectStatus != nil {
		switch {
		case len(ch.ExpectStatus) == 0:
			v.Add(prefix+".expect_status", validate.TooShort, map[string]string{"min": "1"})
		case len(ch.ExpectStatus) > MaxCanaryExpectStatus:
			v.Add(prefix+".expect_status", validate.TooLong, map[string]string{"max": strconv.Itoa(MaxCanaryExpectStatus)})
		default:
			for i, code := range ch.ExpectStatus {
				field := prefix + ".expect_status." + strconv.Itoa(i)
				if intRange(v, field, code, minCanaryStatus, maxCanaryStatus) && slices.Contains(ch.ExpectStatus[:i], code) {
					v.Add(field, validate.Duplicate, nil)
				}
			}
			if len(ch.ExpectStatus) == 1 && ch.ExpectStatus[0] == DefaultCanaryStatusOK {
				ch.ExpectStatus = nil
			}
		}
	}
	timeout, ok := canaryDuration(v, prefix+".timeout", &ch.Timeout, DefaultCanaryTimeout, MinCanaryTimeout, MaxCanaryTimeout)
	if ok && intervalOK && timeout >= interval {
		v.Add(prefix+".timeout", validate.OutOfRange, map[string]string{"min": formatCanaryDuration(MinCanaryTimeout),
			"max": formatCanaryDuration(interval - time.Second)})
	}
}

// validCheckPath accepts an origin-form request target: "/" then RFC 3986 path and query characters (unreserved,
// sub-delims, ":", "@", "/", "?" and well-formed percent-encodings); no fragment, space, control or non-ASCII byte.
func validCheckPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/?", c) >= 0:
		case c == '%':
			if i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// validCheckHost accepts a DNS name in its A-label (ASCII) form: no wildcard, no IP literal, at most 253 bytes.
func validCheckHost(h string) bool {
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return false
	}
	return len(h) <= MaxCanaryHostBytes && !strings.HasPrefix(h, "*") && validDNSName(h)
}

// CanaryEnabled reports whether the policy asks for canary deployment.
func (p Policy) CanaryEnabled() bool { return p.Canary != nil && p.Canary.Enabled }

// CanarySettings answers the effective canary settings, defaults filled in, and false when the policy has no enabled
// canary key.
func (p Policy) CanarySettings() (CanarySettings, bool) {
	if !p.CanaryEnabled() {
		return CanarySettings{}, false
	}
	c := p.Canary
	s := CanarySettings{Count: DefaultCanaryCount, First: slices.Clone(c.First), Hold: DefaultCanaryHold,
		Interval: DefaultCanaryInterval, Timeout: DefaultCanaryTimeout, Failures: DefaultCanaryFailures,
		OverrideAllowed: c.Override != CanaryOverrideForbidden}
	if c.Subset != nil {
		switch {
		case c.Subset.Count != nil:
			s.Count = *c.Subset.Count
		case c.Subset.Percent != nil:
			s.Count, s.Percent = 0, *c.Subset.Percent
		}
	}
	if d, ok := parseCanaryDuration(c.Hold); ok {
		s.Hold = d
	}
	if d, ok := parseCanaryDuration(c.Interval); ok {
		s.Interval = d
	}
	if c.Failures != nil {
		s.Failures = *c.Failures
	}
	if ch := c.Check; ch != nil {
		check := *ch
		check.ExpectStatus = slices.Clone(ch.ExpectStatus)
		if len(check.ExpectStatus) == 0 {
			check.ExpectStatus = []int{DefaultCanaryStatusOK}
		}
		if d, ok := parseCanaryDuration(ch.Timeout); ok {
			s.Timeout = d
		}
		check.Timeout = formatCanaryDuration(s.Timeout)
		s.Check = &check
	}
	return s, true
}

// CanaryWaves splits the destinations of one request into wave 1 and wave 2 (design §7): the destinations named by
// s.First in its order, then the others by UUID byte order; wave 1 is the first k (count, or the ceiling of the
// percentage, at least 1), and wave 2 is never empty. Fewer than two destinations answer nil, nil. The input is not
// changed; distinct destinations are assumed (a request names each location once).
func CanaryWaves(dests []uuid.UUID, s CanarySettings) (wave1, wave2 []uuid.UUID) {
	n := len(dests)
	if n < 2 {
		return nil, nil
	}
	order := make([]uuid.UUID, 0, n)
	for _, id := range s.First {
		if slices.Contains(dests, id) && !slices.Contains(order, id) {
			order = append(order, id)
		}
	}
	rest := make([]uuid.UUID, 0, n)
	for _, id := range dests {
		if !slices.Contains(order, id) {
			rest = append(rest, id)
		}
	}
	slices.SortFunc(rest, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	order = append(order, rest...)
	k := s.Count
	if s.Percent > 0 {
		k = (n*s.Percent + 99) / 100
	}
	k = max(1, min(k, n-1))
	return order[:k:k], slices.Clone(order[k:])
}
