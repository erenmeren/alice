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

// phase8Table is C12's table of the Phase 8 codes: code, reason, HTTP status, retryable.
var phase8Table = []struct {
	code, reason string
	status       int
	retry        bool
}{
	{"ALC-BAK-0001", "backup.running", 409, true}, {"ALC-BAK-0002", "backup.not_configured", 409, false},
	{"ALC-BAK-0003", "backup.not_found", 404, false}, {"ALC-BAK-0004", "backup.write_failed", 500, true},
	{"ALC-TLS-0001", "tls.key_mismatch", 422, false}, {"ALC-TLS-0002", "tls.not_valid_now", 422, false},
	{"ALC-TLS-0003", "tls.weak_key", 422, false}, {"ALC-TLS-0004", "tls.pfx_password", 422, false},
	{"ALC-TLS-0005", "tls.unreadable", 422, false},
	{"ALC-AUD-0002", "audit.forwarding_address_refused", 422, false}, {"ALC-AUD-0003", "audit.forwarding_unreachable", 502, true},
	{"ALC-AUD-0004", "audit.forwarding_untrusted", 502, false},
	{"ALC-SET-0010", "setup.passphrase_too_weak", 422, false},
}

// Every Phase 8 code is registered as C12 says, translated in English and Turkish without placeholders, and has a
// troubleshooting section headed by its English title, with its HTTP status and reason, a cause and a remedy.
func TestPhase8ErrorCodesAreCatalogued(t *testing.T) {
	all := map[string]ErrorCode{}
	for _, c := range AllErrorCodes() {
		all[c.Code] = c
	}
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for _, row := range phase8Table {
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
		assert.NotEqual(t, cat.T("en", "errors."+c.Reason+".title", nil), cat.T("tr", "errors."+c.Reason+".title", nil), "%s is translated", c.Code)
	}
}
