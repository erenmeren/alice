package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/providers/windows"
	"alice/locales"
)

// windowsTable is the pinned table of the Windows codes (area WIN: R60 0001-0003, R61 0004-0012, R62 0013-0014, R68
// 0015-0020).
var windowsTable = []struct {
	code, reason string
	status       int
	retryable    bool
}{
	{"ALC-WIN-0001", "windows.helper_missing", 502, false},
	{"ALC-WIN-0002", "windows.helper_outdated", 502, false},
	{"ALC-WIN-0003", "windows.not_elevated", 502, false},
	{"ALC-WIN-0004", "windows.binding_changed", 409, true},
	{"ALC-WIN-0005", "windows.binding_not_found", 409, false},
	{"ALC-WIN-0006", "windows.busy", 409, true},
	{"ALC-WIN-0007", "windows.io_error", 502, true},
	{"ALC-WIN-0008", "windows.store_error", 502, false},
	{"ALC-WIN-0009", "windows.key_unusable", 502, false},
	{"ALC-WIN-0010", "windows.backup_missing", 502, false},
	{"ALC-WIN-0011", "windows.location_unsupported", 409, false},
	{"ALC-WIN-0012", "windows.helper_refused", 502, false},
	{"ALC-WIN-0013", "windows.drift_not_repairable", 409, false},
	{"ALC-WIN-0014", "windows.cleanup_outcome_unknown", 502, true},
	{"ALC-WIN-0015", "windows.ccs_disabled", 409, false},
	{"ALC-WIN-0016", "windows.ccs_path_changed", 409, false},
	{"ALC-WIN-0017", "windows.ccs_password_mismatch", 409, false},
	{"ALC-WIN-0018", "windows.ccs_password_missing", 409, false},
	{"ALC-WIN-0019", "windows.ccs_password_invalid", 422, false},
	{"ALC-WIN-0020", "windows.ccs_file_not_found", 409, false},
}

// Each Windows code is registered as the table says, has EN and TR texts without placeholders (the provider sends
// different params for helper_outdated depending on where it was found, and a W2 reason comes from several helper
// answers with different params, so no text may need one) and a troubleshooting section.
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
		assert.Equal(t, row.retryable, c.Retryable, row.code)
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

// Every reason the Windows provider produces is a registered code: its own reasons, and the engine's reasons its
// helper codes map to (R61 Ruling 6).
func TestWindowsProviderReasonsAreRegistered(t *testing.T) {
	for _, reason := range []string{windows.ReasonHelperMissing, windows.ReasonHelperOutdated, windows.ReasonNotElevated,
		windows.ReasonBindingChanged, windows.ReasonBindingNotFound, windows.ReasonBusy, windows.ReasonIOError,
		windows.ReasonStoreError, windows.ReasonKeyUnusable, windows.ReasonBackupMissing, windows.ReasonLocationUnsupported,
		windows.ReasonHelperRefused, "deployment.recovery_pending", "deployment.interrupted", "deployment.superseded",
		"deployment.unknown_operation", "deployment.rollback_failed", "deployment.rollback_forbidden",
		"deployment.nothing_to_restore", "deployment.verify_unreachable", "certificate.invalid"} {
		assert.NotEqual(t, ErrUnexpected, codeForReason(reason), reason)
	}
	// And every reason-shaped string literal of the provider's source, so the list above cannot drift from the
	// provider's unexported constants.
	files, err := filepath.Glob("../providers/windows/*.go")
	require.NoError(t, err)
	reasonRE := regexp.MustCompile(`^(windows|deployment|certificate|ssh|target)\.[a-z][a-z0-9_]*$`)
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		require.NoError(t, err, f)
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			// target.invalid_config (W1, as linuxssh's Open) is unregistered: the API validated the stored
			// configuration before Open reads it, so it never reaches a client.
			if err == nil && reasonRE.MatchString(v) && v != "target.invalid_config" {
				seen++
				assert.NotEqual(t, ErrUnexpected, codeForReason(v), "%s: %s", f, v)
			}
			return true
		})
	}
	assert.Greater(t, seen, 20, "the provider's reasons were found")
}

// The params of the Windows errors pass the allowlist with their value rules (R61 Rulings 3 and 17): the helper's
// version and the version Alice needs, the store and SHA-1 of the previous certificate. A value outside its rule is
// dropped with its key.
func TestWindowsErrorParams(t *testing.T) {
	sha1 := strings.Repeat("ab", 20)
	assert.Equal(t, map[string]string{"helper_version": "0.1.0", "required_version": "0.2.0"},
		providerParams(map[string]string{"helper_version": "0.1.0", "required_version": "0.2.0"}))
	assert.Equal(t, map[string]string{"helper_version": "0.2.0-rc1"}, providerParams(map[string]string{"helper_version": "0.2.0-rc1"}))
	assert.Equal(t, map[string]string{"store": "WebHosting", "previous_sha1": sha1},
		providerParams(map[string]string{"store": "WebHosting", "previous_sha1": sha1}))
	assert.Equal(t, map[string]string{"store": "My"}, providerParams(map[string]string{"store": "My", "previous_sha1": strings.Repeat("AB", 20)}))
	for k, v := range map[string]string{
		"helper_version": "", "required_version": "v0.2.0", "store": `My\..`, "previous_sha1": sha1 + "00",
	} {
		assert.Nil(t, providerParams(map[string]string{k: v}), "%s=%q", k, v)
	}
	assert.Nil(t, providerParams(map[string]string{"helper_version": strings.Repeat("1", 33)}))
	assert.Nil(t, providerParams(map[string]string{"helper_version": "0.1.0 <script>"}))
	assert.Nil(t, providerParams(map[string]string{"store": strings.Repeat("a", 65)}))
	assert.Nil(t, providerParams(map[string]string{"store": "Call 555 0100 for support"}), "only the stores Alice deploys to")
	assert.Nil(t, providerParams(map[string]string{"store": "Root"}))
	assert.Equal(t, map[string]string{"store": "MY"}, providerParams(map[string]string{"store": "MY"}), "a NULL store reads MY")
}
