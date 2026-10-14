package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/discovery"
	"alice/internal/discovery/discoverysvc"
	"alice/internal/i18n"
	"alice/locales"
)

// discoveryTable is the pinned table of the network discovery codes (area DSC): code, reason, HTTP status, retryable.
// An export that finds another export running answers the existing ALC-RPT-0004 (export.busy); it has no DSC code.
var discoveryTable = []struct {
	code, reason string
	status       int
	retry        bool
}{
	{"ALC-DSC-0001", "discovery.scope_too_large", 422, false},
	{"ALC-DSC-0002", "discovery.entry_not_allowed", 422, false},
	{"ALC-DSC-0003", "discovery.entry_invalid", 422, false},
	{"ALC-DSC-0004", "discovery.scan_running", 409, true},
	{"ALC-DSC-0005", "discovery.scan_cancelled", 409, false},
	{"ALC-DSC-0006", "discovery.scan_timed_out", 504, false},
	{"ALC-DSC-0007", "discovery.too_many_scans", 409, true},
	{"ALC-DSC-0008", "discovery.scope_not_found", 404, false},
	{"ALC-DSC-0009", "discovery.schedule_invalid", 422, false},
	{"ALC-DSC-0010", "discovery.name_unresolved", 422, false},
	{"ALC-DSC-0011", "discovery.name_taken", 409, false},
	{"ALC-DSC-0012", "discovery.scan_interrupted", 409, false},
	{"ALC-DSC-0013", "discovery.scope_disabled", 409, false},
}

// Every discovery code is registered as the table says, translated in English and Turkish without placeholders, and has
// a troubleshooting section headed by its English title, with its HTTP status and reason, a cause and a remedy.
func TestDiscoveryErrorCodesAreCatalogued(t *testing.T) {
	all := map[string]ErrorCode{}
	for _, c := range AllErrorCodes() {
		all[c.Code] = c
	}
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	n := 0
	for _, c := range all {
		if strings.HasPrefix(c.Code, "ALC-DSC-") {
			n++
		}
	}
	assert.Equal(t, len(discoveryTable), n, "no discovery code outside the pinned table")
	for _, row := range discoveryTable {
		c, ok := all[row.code]
		if !assert.True(t, ok, row.code) {
			continue
		}
		assert.Equal(t, row.reason, c.Reason, row.code)
		assert.Equal(t, row.status, c.Status, row.code)
		assert.Equal(t, row.retry, c.Retryable, row.code)
		assert.Equal(t, c, codeForReason(row.reason), row.code)

		title := cat.T("en", "errors."+c.Reason+".title", nil)
		assert.Contains(t, string(doc), "\n## "+c.Code+": "+strings.TrimSuffix(title, ".")+"\n", c.Code)
		retry := ""
		if c.Retryable {
			retry = "; retryable"
		}
		assert.Regexp(t, regexp.MustCompile(`(?m)^## `+c.Code+`: .+\n\n\*\*Meaning\.\*\* .*\(HTTP `+strconv.Itoa(c.Status)+`, reason `+"`"+
			regexp.QuoteMeta(c.Reason)+"`"+regexp.QuoteMeta(retry)+`\.\)$`), string(doc), c.Code)
		section := troubleshootingSection(string(doc), c.Code)
		assert.Regexp(t, `(?m)^\*\*Likely cause\.\*\* \S`, section, c.Code)
		assert.Regexp(t, `(?m)^\*\*What to do\.\*\* \S`, section, c.Code)
		for _, lang := range []string{"en", "tr"} {
			for _, part := range []string{"title", "cause", "action"} {
				key := "errors." + c.Reason + "." + part
				text := cat.T(lang, key, nil)
				assert.NotEqual(t, key, text, "%s %s", lang, key)
				assert.NotContains(t, text, "{{", "%s %s", lang, key)
			}
		}
		assert.NotEqual(t, title, cat.T("tr", "errors."+c.Reason+".title", nil), "%s is translated", c.Code)
	}
	// The export of discovery results reuses the one-export-at-a-time refusal.
	assert.Equal(t, "ALC-RPT-0004", codeForReason("export.busy").Code)
}

// The texts never show an address or a name the scan refused (the address map of the network is sensitive and
// ALC-DSC-0010 must not confirm what a name resolves to): no placeholder at all, checked above, and no wording that
// promises one.
func TestDiscoveryTextsRevealNoAddresses(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for _, lang := range []string{"en", "tr"} {
		for _, part := range []string{"title", "cause", "action"} {
			text := cat.T(lang, "errors.discovery.name_unresolved."+part, nil)
			assert.NotRegexp(t, `\d+\.\d+\.\d+\.\d+`, text, lang)
		}
	}
	assert.Contains(t, cat.T("en", "errors.discovery.entry_not_allowed.action", nil), "Allowed scan networks")
	assert.Contains(t, cat.T("en", "errors.discovery.scan_running.action", nil), "Scans")
}

// The discovery service's and the validator's refusals map onto the DSC codes (Task 9). A validator refusal names the
// field and the element's index (never its value); an unresolved name names only the entry's index; an unknown error is
// a 500 without its text (an address in it never leaves); a stale If-Match is 412.
func TestDiscoveryErrorsMapToTheirCodes(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		params map[string]any
		retry  string
	}{
		{&discovery.Error{Kind: discovery.ErrTooLarge, Field: "entries", Index: -1}, "ALC-DSC-0001", map[string]any{"field": "entries"}, ""},
		{fmt.Errorf("wrapped: %w", &discovery.Error{Kind: discovery.ErrNotAllowed, Field: "entries", Index: 2, Value: "10.9.9.9"}), "ALC-DSC-0002",
			map[string]any{"field": "entries", "index": "2"}, ""},
		{&discovery.Error{Kind: discovery.ErrInvalid, Field: "ports", Index: 0, Value: "0"}, "ALC-DSC-0003", map[string]any{"field": "ports", "index": "0"}, ""},
		{&discovery.Error{Kind: discovery.ErrSchedule, Field: "window_tz", Index: -1}, "ALC-DSC-0009", map[string]any{"field": "window_tz"}, ""},
		{&discovery.Error{Kind: errors.New("odd"), Field: "x", Index: -1}, "ALC-SYS-0003", nil, ""},
		{&discoverysvc.NameUnresolvedError{Index: 4}, "ALC-DSC-0010", map[string]any{"field": "entries", "index": "4"}, ""},
		{discovery.ErrScanRunning, "ALC-DSC-0004", nil, "30"},
		{discoverysvc.ErrTooManyScans, "ALC-DSC-0007", nil, "30"},
		{discovery.ErrScopeNotFound, "ALC-DSC-0008", nil, ""},
		{discoverysvc.ErrNameTaken, "ALC-DSC-0011", nil, ""},
		{discoverysvc.ErrScopeDisabled, "ALC-DSC-0013", nil, ""},
		{discoverysvc.ErrNotFound, "ALC-SYS-0001", nil, ""},
		{discoverysvc.ErrVersion, ErrPreconditionFailed.Code, nil, ""},
		{fmt.Errorf("dial 10.20.30.40:443: %w", errors.New("boom")), "ALC-SYS-0003", nil, ""},
	} {
		var logs strings.Builder
		rec := failRecorder(t, tc.err, &logs)
		var body struct {
			Error map[string]any `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		e := body.Error
		assert.Equal(t, tc.code, e["code"], "%v", tc.err)
		if tc.params == nil {
			assert.Nil(t, e["params"], "%v", tc.err)
		} else {
			assert.Equal(t, tc.params, e["params"], "%v", tc.err)
		}
		assert.Equal(t, tc.retry, rec.Header().Get("Retry-After"), "%v", tc.err)
		for _, leak := range []string{"10.9.9.9", "10.20.30.40", "boom", "wrapped"} {
			assert.NotContains(t, rec.Body.String(), leak, "%v", tc.err)
			assert.NotContains(t, logs.String(), leak, "the log has fixed labels only: %v", tc.err)
		}
	}
	assert.Equal(t, "ALC-SYS-0001", ErrNotFound.Code)
}
