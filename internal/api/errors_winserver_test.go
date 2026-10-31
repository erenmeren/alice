package api

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers/windows"
	"alice/internal/secrets"
	"alice/locales"
)

// windowsTable is the pinned table of the Windows codes (area WIN: R60 0001-0003, R61 0004-0012, R62 0013-0014, R68
// 0015-0020, R69 0021-0023, R71 0024-0028).
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
	{"ALC-WIN-0021", "windows.rdp_disabled", 409, false},
	{"ALC-WIN-0022", "windows.rdp_tls_off", 409, false},
	{"ALC-WIN-0023", "windows.rdp_key_acl_failed", 409, false},
	{"ALC-WIN-0024", "windows.winrm_auth_refused", 502, false},
	{"ALC-WIN-0025", "windows.winrm_password_missing", 409, false},
	{"ALC-WIN-0026", "windows.winrm_fault", 502, false},
	{"ALC-WIN-0027", "windows.transport_immutable", 409, false},
	{"ALC-WIN-0028", "windows.winrm_password_invalid", 422, false},
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
	assert.Nil(t, providerParams(map[string]string{"store": "Remote  Desktop"}))
	assert.Equal(t, map[string]string{"store": "Remote Desktop"}, providerParams(map[string]string{"store": "Remote Desktop"}),
		"W6: the listener's self-signed store")
	assert.Equal(t, map[string]string{"store": "MY"}, providerParams(map[string]string{"store": "MY"}), "a NULL store reads MY")
}

// R71 Ruling 7: PUT /targets/{id}/winrm-password, W5's CCS password route exactly: an Administrator with step-up sets the
// WinRM password of a Windows server whose transport is winrm; the answer is the target, with the date and never the
// password.
func TestSetWinRMPasswordHandler(t *testing.T) {
	h, inv, aud := ccsDeps(t)
	path := "/api/v1/targets/" + targetID.String() + "/winrm-password"
	pw := ccsSecret()
	at := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	winrm := func(setAt *time.Time) inventory.Target {
		tg := sampleWindows(nil)
		tg.Port, tg.Transport, tg.WinRMPasswordSetAt = 5986, inventory.TransportWinRM, setAt
		return tg
	}
	var (
		got   []byte
		given secrets.Plaintext
		ver   int
		id    uuid.UUID
		calls int
	)
	inv.SetWinRMPasswordFn = func(_ context.Context, _ inventory.Actor, target uuid.UUID, v int, p secrets.Plaintext) (inventory.Target, error) {
		calls++
		got, given, ver, id = bytes.Clone(p.Bytes()), p, v, target
		return winrm(&at), nil
	}
	body := `{"password":"` + pw + `"}`
	hdr := map[string]string{"If-Match": `"7"`}

	rec := callWith(h, http.MethodPut, path, "admin", body, hdr)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, "an Administrator needs a fresh step-up")
	assert.Equal(t, http.StatusForbidden, callWith(h, http.MethodPut, path, "alice_operate_admin", body, hdr).Code, "never an API token")
	assert.Equal(t, http.StatusForbidden, callWith(h, http.MethodPut, path, "operator-stepup", body, hdr).Code, "an Operator")
	assert.Zero(t, calls, "no refusal reached the inventory")

	rec = callWith(h, http.MethodPut, path, "admin-stepup", body, hdr)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []byte(pw), got)
	assert.Equal(t, make([]byte, len(pw)), given.Bytes(), "the handler zeroes the password after the call")
	assert.Equal(t, 7, ver)
	assert.Equal(t, targetID, id)
	assert.Equal(t, `"7"`, rec.Header().Get("ETag"))
	obj := jsonObj(t, rec)
	assert.Equal(t, "2026-10-31T09:00:00Z", obj["winrm_password_set_at"])
	assert.Equal(t, "winrm", obj["transport"])
	assert.Equal(t, targetID.String(), obj["id"], "the answer is the target")
	assert.NotContains(t, obj, "password")
	assert.NotContains(t, rec.Body.String(), pw)

	// A WinRM server without a password says null; an SSH Windows server and a Linux server have no such field.
	inv.SetWinRMPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
		return winrm(nil), nil
	}
	obj = jsonObj(t, callWith(h, http.MethodPut, path, "admin-stepup", body, hdr))
	v, ok := obj["winrm_password_set_at"]
	assert.True(t, ok)
	assert.Nil(t, v)
	ssh := sampleWindows(nil)
	ssh.Transport = inventory.TransportSSH
	assert.NotContains(t, mustJSON(targetJSON(ssh, serviceRefs{})), "winrm_password_set_at", "an SSH Windows server has no WinRM password")
	assert.Contains(t, mustJSON(targetJSON(ssh, serviceRefs{})), `"transport":"ssh"`)
	assert.NotContains(t, mustJSON(targetJSON(sampleTarget(), serviceRefs{})), "transport", "a Linux server has no transport")

	// If-Match is required; a stale one is 412; another member or a number is refused before the inventory.
	assert.Equal(t, "ALC-SYS-0008", decodeErr(t, call(h, http.MethodPut, path, "admin-stepup", body)).Error.Code)
	inv.SetWinRMPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
		return inventory.Target{}, inventory.ErrVersionMismatch
	}
	assert.Equal(t, "ALC-SYS-0008", decodeErr(t, callWith(h, http.MethodPut, path, "admin-stepup", body, hdr)).Error.Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPut, path, "admin-stepup", `{"password":"`+pw+`","x":1}`, hdr).Code)
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPut, path, "admin-stepup", `{"password":123456789012}`, hdr).Code)
	assert.Equal(t, http.StatusRequestEntityTooLarge,
		callWith(h, http.MethodPut, path, "admin-stepup", `{"password":"`+strings.Repeat("a", 5000)+`"}`, hdr).Code)

	for err, want := range map[error]string{inventory.ErrWinRMPasswordInvalid: "ALC-WIN-0028", inventory.ErrNotWindowsTarget: "ALC-WIN-0011",
		fmt.Errorf("%w: its transport is not winrm", inventory.ErrNotWindowsTarget): "ALC-WIN-0011"} {
		inv.SetWinRMPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
			return inventory.Target{}, err
		}
		rec := callWith(h, http.MethodPut, path, "admin-stepup", body, hdr)
		assert.Equal(t, want, decodeErr(t, rec).Error.Code, "%v", err)
		assert.NotContains(t, rec.Body.String(), pw)
	}
	inv.SetWinRMPasswordFn = func(context.Context, inventory.Actor, uuid.UUID, int, secrets.Plaintext) (inventory.Target, error) {
		return inventory.Target{}, inventory.ErrNotFound
	}
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodPut, path, "admin-stepup", body, hdr).Code)
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodPut, "/api/v1/targets/x/winrm-password", "admin-stepup", body, hdr).Code)
	for _, e := range aud.Events() {
		assert.NotContains(t, mustJSON(e), pw, e.Action)
	}
}

// R71 Ruling 19: GET /targets/{id}/winrm-setup answers the WinRM setup script of a WinRM Windows server to a target
// reader; any other target is the code of ErrNotWindowsTarget.
func TestWinRMSetupHandler(t *testing.T) {
	h, inv, _ := ccsDeps(t)
	path := "/api/v1/targets/" + targetID.String() + "/winrm-setup"
	want, err := windows.SetupScriptWinRM(`.\alice`, "", true)
	require.NoError(t, err)
	var froms []string
	inv.WinRMSetupFn = func(_ context.Context, id uuid.UUID, from string) (inventory.WinRMSetup, error) {
		froms = append(froms, from)
		if id != targetID {
			return inventory.WinRMSetup{}, inventory.ErrNotFound
		}
		return inventory.WinRMSetup{User: `.\alice`, Script: want}, nil
	}
	rec := call(h, http.MethodGet, path, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	obj := jsonObj(t, rec)
	require.Len(t, obj, 1)
	script, _ := obj["script"].(string)
	assert.Equal(t, want, script, "the inventory's script, as it is")
	assert.NotEmpty(t, script)

	// ?from= (fix round 1): an IP address reaches the inventory; anything else is the field error, nothing asked.
	rec = call(h, http.MethodGet, path+"?from=192.0.2.10", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"", "192.0.2.10"}, froms)
	rec = call(h, http.MethodGet, path+"?from=web-01", "auditor", "")
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Len(t, froms, 2, "an invalid from never reaches the inventory")

	inv.WinRMSetupFn = func(context.Context, uuid.UUID, string) (inventory.WinRMSetup, error) {
		return inventory.WinRMSetup{}, fmt.Errorf("%w: its transport is not winrm", inventory.ErrNotWindowsTarget)
	}
	rec = call(h, http.MethodGet, path, "auditor", "")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-WIN-0011", decodeErr(t, rec).Error.Code)
	inv.WinRMSetupFn = func(context.Context, uuid.UUID, string) (inventory.WinRMSetup, error) {
		return inventory.WinRMSetup{}, inventory.ErrNotFound
	}
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, path, "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/targets/x/winrm-setup", "auditor", "").Code)
}

// R71 Rulings 2 and 3: a Windows server is created with its transport, and a change that names another transport is
// ALC-WIN-0027.
func TestTargetTransportHandlers(t *testing.T) {
	d, inv := inventoryDeps(t)
	h := NewHandler(d)
	var in inventory.NewTarget
	inv.CreateTargetFn = func(_ context.Context, _ inventory.Actor, n inventory.NewTarget) (inventory.Target, uuid.UUID, error) {
		in = n
		tg := sampleWindows(nil)
		tg.Transport = n.Transport
		return tg, uuid.New(), nil
	}
	rec := call(h, http.MethodPost, "/api/v1/targets", "admin", `{"name":"iis-01","type":"windows","host":"iis-01.corp.example","transport":"winrm"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.TransportWinRM, in.Transport)

	var patch inventory.TargetPatch
	inv.UpdateTargetFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, _ int, p inventory.TargetPatch) (inventory.Target, error) {
		patch = p
		return inventory.Target{}, inventory.ErrTransportImmutable
	}
	rec = callWith(h, http.MethodPatch, "/api/v1/targets/"+targetID.String(), "admin", `{"name":"x","transport":"ssh"}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-WIN-0027", decodeErr(t, rec).Error.Code)
	require.NotNil(t, patch.Transport)
	assert.Equal(t, "ssh", *patch.Transport)

	// A transport alone reaches the inventory, which answers the conflict for another one and the empty patch for the
	// target's own.
	patch = inventory.TargetPatch{}
	rec = callWith(h, http.MethodPatch, "/api/v1/targets/"+targetID.String(), "admin", `{"transport":"ssh"}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, "ALC-WIN-0027", decodeErr(t, rec).Error.Code)
	require.NotNil(t, patch.Transport)
	assert.Nil(t, patch.Name)
	inv.UpdateTargetFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.TargetPatch) (inventory.Target, error) {
		var errs validate.Errors
		errs.Add("name", validate.Required, nil)
		return inventory.Target{}, errs
	}
	rec = callWith(h, http.MethodPatch, "/api/v1/targets/"+targetID.String(), "admin", `{"transport":"winrm"}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
}

// R71 Ruling 13: a WinRM target's errors carry transport (the web shows "(WinRM)" from it) and a fault's numeric
// wsman_code; any other value is dropped with its key.
func TestWinRMErrorParams(t *testing.T) {
	in := map[string]string{"subcommand": "win-facts", "transport": "winrm", "wsman_code": "2150859173"}
	assert.Equal(t, in, providerParams(in))
	assert.Equal(t, map[string]string{"transport": "ssh"}, providerParams(map[string]string{"transport": "ssh"}))
	for k, v := range map[string]string{
		"transport": "WinRM", "wsman_code": "", "wsman_code ": "5",
	} {
		assert.Nil(t, providerParams(map[string]string{k: v}), "%s=%q", k, v)
	}
	assert.Nil(t, providerParams(map[string]string{"wsman_code": "12345678901"}), "at most 10 digits")
	assert.Nil(t, providerParams(map[string]string{"wsman_code": "0x80338012"}), "the number only, never the fault's text")
}
