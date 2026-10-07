package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts/expiry"
	"alice/internal/auth"
	"alice/internal/i18n"
	"alice/internal/notify"
	"alice/internal/reports"
	"alice/locales"
)

// phase7Table is C15's table for the codes of Task 14 (the reason of ALC-USR-0003 is user.sso_user, cosmetic
// ruling C-s4-07) and ALC-RPT-0004, the one-export-at-a-time refusal Task 10 added (reports.ErrExportBusy).
var phase7Table = []struct {
	code, reason string
	status       int
	retry        bool
}{
	{"ALC-NTF-0002", "notify.smtp_not_configured", 409, false}, {"ALC-NTF-0003", "notify.smtp_connect", 502, true},
	{"ALC-NTF-0004", "notify.smtp_tls", 502, false}, {"ALC-NTF-0005", "notify.smtp_untrusted", 502, false},
	{"ALC-NTF-0006", "notify.smtp_auth", 502, false}, {"ALC-NTF-0007", "notify.smtp_rejected", 502, false},
	{"ALC-NTF-0008", "notify.certificate_not_seen", 409, false}, {"ALC-NTF-0009", "notify.smtp_address_refused", 409, false},
	{"ALC-RPT-0001", "export.too_large", 409, false}, {"ALC-RPT-0002", "views.limit_reached", 409, false},
	{"ALC-RPT-0003", "views.name_taken", 409, false}, {"ALC-RPT-0004", "export.busy", 409, true},
	{"ALC-USR-0003", "user.sso_user", 409, false},
}

func TestPhase7CodeTable(t *testing.T) {
	all := map[string]ErrorCode{}
	for _, c := range AllErrorCodes() {
		all[c.Code] = c
	}
	for _, row := range phase7Table {
		c, ok := all[row.code]
		if assert.True(t, ok, row.code) {
			assert.Equal(t, row.reason, c.Reason, row.code)
			assert.Equal(t, row.status, c.Status, row.code)
			assert.Equal(t, row.retry, c.Retryable, row.code)
			assert.Equal(t, c, codeForReason(row.reason), row.code)
		}
	}
}

// Every Phase 7 sentinel answers its C15 code; an untrusted certificate is matched before the TLS failure it also is.
func TestPhase7SentinelMapping(t *testing.T) {
	cases := []struct {
		err    error
		code   string
		params map[string]string
	}{
		{notify.ErrNotConfigured, "ALC-NTF-0002", nil},
		{fmt.Errorf("send: %w", notify.ErrSMTPConnect), "ALC-NTF-0003", nil},
		{notify.ErrSMTPTLS, "ALC-NTF-0004", nil},
		{notify.ErrSMTPUntrusted, "ALC-NTF-0005", nil},
		{&notify.CertError{}, "ALC-NTF-0005", nil},
		{notify.ErrSMTPAuth, "ALC-NTF-0006", nil},
		{notify.ErrSMTPRejected, "ALC-NTF-0007", nil},
		{notify.ErrCertNotSeen, "ALC-NTF-0008", nil},
		{notify.ErrAddressRefused, "ALC-NTF-0009", nil},
		{notify.ErrVersion, "ALC-SYS-0008", nil},
		{reports.ErrTooLarge, "ALC-RPT-0001", map[string]string{"max": strconv.Itoa(reports.MaxExportRows)}},
		{reports.ErrViewLimit, "ALC-RPT-0002", map[string]string{"max": strconv.Itoa(reports.MaxViewsPerUser)}},
		{reports.ErrViewName, "ALC-RPT-0003", nil},
		{reports.ErrExportBusy, "ALC-RPT-0004", nil},
		{reports.ErrNotFound, "ALC-SYS-0001", nil},
		{auth.ErrSSOUser, "ALC-USR-0003", nil},
	}
	for _, c := range cases {
		ec, params, ok := classify(c.err)
		require.True(t, ok, c.code)
		assert.Equal(t, c.code, ec.Code, "%v", c.err)
		assert.Equal(t, c.params, params, c.code)
	}
}

// C15: expiry.ErrThresholds is a 422 on thresholds_days; a busy export says when to try again.
func TestPhase7FailSpecialCases(t *testing.T) {
	s := newServer(testDeps(t, nil))
	rec := httptest.NewRecorder()
	s.fail(rec, httptest.NewRequest(http.MethodPut, "/api/v1/settings/alerts", nil), fmt.Errorf("save: %w", expiry.ErrThresholds))
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	body := decodeMap(t, rec.Body.Bytes())["error"].(map[string]any)
	details := body["details"].([]any)
	require.Len(t, details, 1)
	d := details[0].(map[string]any)
	assert.Equal(t, "thresholds_days", d["field"])
	assert.Equal(t, "validation.out_of_range", d["code"])
	assert.Equal(t, map[string]any{"min": "1", "max": "365"}, d["params"])

	rec = httptest.NewRecorder()
	s.fail(rec, httptest.NewRequest(http.MethodGet, "/api/v1/certificates/export", nil), errors.Join(reports.ErrExportBusy))
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "5", rec.Header().Get("Retry-After"))
}

// Every Phase 7 code has a section headed by its English title, with its HTTP status and reason, a cause and a remedy;
// the texts with {{max}} render with the param their error carries.
func TestPhase7CodesHaveTroubleshootingSections(t *testing.T) {
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for _, row := range phase7Table {
		ec := codeForReason(row.reason)
		title := cat.T("en", "errors."+ec.Reason+".title", nil)
		assert.Contains(t, string(doc), "\n## "+ec.Code+": "+strings.TrimSuffix(title, ".")+"\n", ec.Code)
		assert.Regexp(t, regexp.MustCompile(`(?m)^## `+ec.Code+`: .+\n\n\*\*Meaning\.\*\* .*\(HTTP `+strconv.Itoa(ec.Status)+`, reason `+"`"+
			regexp.QuoteMeta(ec.Reason)+"`"), string(doc), ec.Code)
		section := troubleshootingSection(string(doc), ec.Code)
		assert.Regexp(t, `(?m)^\*\*Likely cause\.\*\* \S`, section, ec.Code)
		assert.Regexp(t, `(?m)^\*\*What to do\.\*\* \S`, section, ec.Code)
		_, params, _ := classify(sentinelOf(ec))
		for _, lang := range []string{"en", "tr"} {
			for _, part := range []string{"title", "cause", "action"} {
				text := cat.T(lang, "errors."+ec.Reason+"."+part, params)
				assert.NotContains(t, text, "{{", "%s %s.%s", lang, ec.Reason, part)
			}
		}
	}
}

// sentinelOf is the errorMap entry's error of a code (nil when none).
func sentinelOf(ec ErrorCode) error {
	for _, m := range errorMap {
		if m.code == ec {
			return m.err
		}
	}
	return nil
}
