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

// windowsTable is the pinned table of the Windows codes (area WIN, R60).
var windowsTable = []struct {
	code, reason string
	status       int
}{
	{"ALC-WIN-0001", "windows.helper_missing", 502},
	{"ALC-WIN-0002", "windows.helper_outdated", 502},
	{"ALC-WIN-0003", "windows.not_elevated", 502},
}

// Each Windows code is registered as the table says, has EN and TR texts without placeholders (the provider sends
// different params for helper_outdated depending on where it was found, so no text may need one) and a
// troubleshooting section.
func TestWindowsErrorCodes(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	n := 0
	all := map[string]ErrorCode{}
	for _, c := range AllErrorCodes() {
		all[c.Code] = c
		if strings.HasPrefix(c.Code, "ALC-WIN-") {
			n++
		}
	}
	assert.Equal(t, len(windowsTable), n, "no Windows code outside the pinned table")
	for _, row := range windowsTable {
		c, ok := all[row.code]
		if !assert.True(t, ok, row.code) {
			continue
		}
		assert.Equal(t, row.reason, c.Reason, row.code)
		assert.Equal(t, row.status, c.Status, row.code)
		assert.False(t, c.Retryable, row.code)
		assert.Equal(t, c, codeForReason(row.reason), row.code)
		title := cat.T("en", "errors."+c.Reason+".title", nil)
		assert.Regexp(t, regexp.MustCompile(`(?m)^## `+c.Code+`: .+\n\n\*\*Meaning\.\*\* .*\(HTTP `+strconv.Itoa(c.Status)+`, reason `+"`"+
			regexp.QuoteMeta(c.Reason)+"`"+`\.\)$`), string(doc), c.Code)
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
}
