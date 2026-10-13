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

// acmeTable is the pinned table of the ACME codes (area ACM): code, reason, HTTP status, retryable.
var acmeTable = []struct {
	code, reason string
	status       int
	retry        bool
}{
	{"ALC-ACM-0001", "acme.provider_unreachable", 502, true}, {"ALC-ACM-0002", "acme.directory_invalid", 502, false},
	{"ALC-ACM-0003", "acme.terms_not_accepted", 422, false}, {"ALC-ACM-0004", "acme.account_rejected", 422, false},
	{"ALC-ACM-0005", "acme.ca_rate_limited", 503, true}, {"ALC-ACM-0006", "acme.validation_failed_dns", 422, false},
	{"ALC-ACM-0007", "acme.validation_failed_http", 422, false}, {"ALC-ACM-0008", "acme.hook_refused", 502, false},
	{"ALC-ACM-0009", "acme.identifier_refused", 422, false}, {"ALC-ACM-0010", "acme.not_issued_in_time", 504, true},
	{"ALC-ACM-0011", "acme.key_policy_not_allowed", 422, false}, {"ALC-ACM-0012", "acme.provider_in_use", 409, false},
	{"ALC-ACM-0013", "acme.tls_trust_failed", 502, false}, {"ALC-ACM-0014", "acme.rollover_unsupported", 422, false},
	{"ALC-ACM-0015", "acme.name_not_allowed", 422, false}, {"ALC-ACM-0016", "acme.order_running", 409, true},
	{"ALC-ACM-0017", "acme.challenge_unavailable", 422, false}, {"ALC-ACM-0018", "acme.key_type_locked", 409, false},
}

// Every ACME code is registered as the table says, translated in English and Turkish without placeholders, and has a
// troubleshooting section headed by its English title, with its HTTP status and reason, a cause and a remedy.
func TestACMEErrorCodesAreCatalogued(t *testing.T) {
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
		if strings.HasPrefix(c.Code, "ALC-ACM-") {
			n++
		}
	}
	assert.Equal(t, len(acmeTable), n, "no ACME code outside the pinned table")
	for _, row := range acmeTable {
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
