package api

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
