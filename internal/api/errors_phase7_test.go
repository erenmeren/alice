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
	"alice/internal/auth/oidc"
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
	// Task 15: single sign-on.
	{"ALC-SSO-0001", "sso.discovery_failed", 502, true}, {"ALC-SSO-0002", "sso.admin_mapping_disabled", 409, false},
	{"ALC-SSO-0003", "sso.admin_mappings_exist", 409, false}, {"ALC-SSO-0004", "sso.public_url_missing", 409, false},
	{"ALC-SSO-0005", "sso.provider_in_use", 409, false}, {"ALC-SSO-0006", "sso.no_access", 403, false},
	{"ALC-SSO-0007", "sso.groups_overage", 403, false}, {"ALC-SSO-0008", "sso.email_in_use", 403, false},
	{"ALC-SSO-0009", "sso.idp_unreachable", 502, true}, {"ALC-SSO-0010", "sso.login_invalid", 401, false},
	{"ALC-SSO-0011", "sso.login_expired", 401, false}, {"ALC-SSO-0012", "sso.user_disabled", 403, false},
	{"ALC-SSO-0013", "sso.provider_disabled", 403, false}, {"ALC-SSO-0014", "sso.stepup_other_user", 403, false},
	{"ALC-SSO-0015", "sso.idp_error", 401, false}, {"ALC-SSO-0016", "sso.not_sso_user", 409, false},
}

// phase7Params are the params the texts with a placeholder are rendered with.
var phase7Params = map[string]map[string]string{"ALC-RPT-0001": {"max": "50000"}, "ALC-RPT-0002": {"max": "50"},
	"ALC-SSO-0001": {"cause": "tls"}}

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
		{&oidc.DiscoveryError{Cause: "issuer_mismatch"}, "ALC-SSO-0001", map[string]string{"cause": "issuer_mismatch"}},
		{&oidc.DiscoveryError{Cause: "Not a code"}, "ALC-SSO-0001", nil},
		{oidc.ErrAdminMappingDisabled, "ALC-SSO-0002", nil},
		{oidc.ErrAdminMappingsExist, "ALC-SSO-0003", nil},
		{oidc.ErrPublicURLMissing, "ALC-SSO-0004", nil},
		{oidc.ErrProviderInUse, "ALC-SSO-0005", nil},
		{&oidc.LoginError{Reason: "no_access"}, "ALC-SSO-0006", nil},
		{&oidc.LoginError{Reason: "groups_overage"}, "ALC-SSO-0007", nil},
		{&oidc.LoginError{Reason: "email_in_use"}, "ALC-SSO-0008", nil},
		{&oidc.LoginError{Reason: "idp_unreachable"}, "ALC-SSO-0009", nil},
		{&oidc.LoginError{Reason: "login_invalid"}, "ALC-SSO-0010", nil},
		{&oidc.LoginError{Reason: "login_expired"}, "ALC-SSO-0011", nil},
		{&oidc.LoginError{Reason: "user_disabled"}, "ALC-SSO-0012", nil},
		{&oidc.LoginError{Reason: "provider_disabled"}, "ALC-SSO-0013", nil},
		{&oidc.LoginError{Reason: "stepup_other_user"}, "ALC-SSO-0014", nil},
		{&oidc.LoginError{Reason: "idp_error"}, "ALC-SSO-0015", nil},
		{&oidc.LoginError{Reason: "unknown"}, "ALC-SSO-0010", nil},
		{&oidc.LoginError{Reason: "provider_in_use"}, "ALC-SSO-0010", nil},
		{auth.ErrNotSSOUser, "ALC-SSO-0016", nil},
		{auth.ErrOIDCEmailInUse, "ALC-SSO-0008", nil},
		{auth.ErrOIDCUserDisabled, "ALC-SSO-0012", nil},
		{auth.ErrOIDCOtherUser, "ALC-SSO-0014", nil},
		{auth.ErrOIDCIdentityInvalid, "ALC-SSO-0010", nil},
		{oidc.ErrNotFound, "ALC-SYS-0001", nil},
		{oidc.ErrVersion, "ALC-SYS-0008", nil},
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
		params := phase7Params[ec.Code]
		for _, lang := range []string{"en", "tr"} {
			for _, part := range []string{"title", "cause", "action"} {
				text := cat.T(lang, "errors."+ec.Reason+"."+part, params)
				assert.NotContains(t, text, "{{", "%s %s.%s", lang, ec.Reason, part)
			}
		}
	}
}
