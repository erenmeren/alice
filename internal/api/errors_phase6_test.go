package api

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/platform/logging"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/plan"
	"alice/locales"
)

// phase6Table is the contract's table (C11: ALC-KEY-0006..0013, ALC-ROT-0001..0016) and the codes added after it for
// what the service built (never renumbered).
var phase6Table = []struct {
	code, reason string
	status       int
	retryable    bool
}{
	{"ALC-KEY-0006", "sshkey.not_managed", 409, false},
	{"ALC-KEY-0007", "sshkey.retired", 409, false},
	{"ALC-KEY-0008", "sshkey.private_key_destroyed", 410, false},
	{"ALC-KEY-0009", "sshkey.connection_account", 409, false},
	{"ALC-KEY-0010", "sshkey.login_failed", 502, false},
	{"ALC-KEY-0011", "sshkey.generate_busy", 503, true},
	{"ALC-KEY-0012", "sshkey.add_undo_failed", 502, false},
	{"ALC-KEY-0013", "sshkey.not_a_key_file", 409, false},
	{"ALC-KEY-0014", "sshkey.connection_files_unknown", 409, false},
	{"ALC-KEY-0015", "sshkey.clock_behind", 503, true},
	{"ALC-KEY-0016", "sshkey.add_uncertain", 502, true},
	{"ALC-KEY-0017", "sshkey.connection_account_file", 409, false},
	{"ALC-KEY-0018", "sshkey.in_rotation", 409, false},
	{"ALC-NTF-0001", "notify.queue_failed", 503, true},
	{"ALC-ROT-0001", "rotation.policy_exists", 409, false},
	{"ALC-ROT-0002", "rotation.in_progress", 409, false},
	{"ALC-ROT-0003", "rotation.plan_changed", 409, false},
	{"ALC-ROT-0004", "rotation.nothing_to_rotate", 409, false},
	{"ALC-ROT-0005", "rotation.not_waiting", 409, false},
	{"ALC-ROT-0006", "rotation.add_failed", 502, false},
	{"ALC-ROT-0007", "rotation.verify_failed", 502, false},
	{"ALC-ROT-0008", "rotation.undo_failed", 502, false},
	{"ALC-ROT-0009", "rotation.remove_incomplete", 502, false},
	{"ALC-ROT-0010", "rotation.decision_timeout", 409, false},
	{"ALC-ROT-0011", "rotation.paused_license", 409, false},
	{"ALC-ROT-0012", "rotation.cancelled_license", 409, false},
	{"ALC-ROT-0013", "rotation.stopped", 409, false},
	{"ALC-ROT-0014", "rotation.policy_off", 409, false},
	{"ALC-ROT-0015", "rotation.new_key_failed", 502, false},
	{"ALC-ROT-0016", "rotation.retries_exhausted", 502, false},
	{"ALC-ROT-0017", "rotation.notice_undelivered", 409, false},
	{"ALC-ROT-0018", "rotation.old_key_gone", 409, false},
	{"ALC-ROT-0019", "rotation.plan_too_large", 409, false},
	{"ALC-ROT-0020", "rotation.start_failed", 409, false},
	{"ALC-ROT-0021", "rotation.notice_pending", 409, true},
	{"ALC-ROT-0022", "rotation.late_result", 409, false},
	{"ALC-ROT-0023", "rotation.guard_refused", 409, false},
	{"ALC-ROT-0024", "rotation.skipped_at_send", 409, false},
	{"ALC-ROT-0025", "rotation.listing_incomplete", 409, false},
}

// phase6Codes are the codes of the area ROT, ALC-NTF-0001 (the later NTF codes are Phase 7's) and KEY from 0006 on
// (AllErrorCodes order).
func phase6Codes() []ErrorCode {
	var out []ErrorCode
	for _, ec := range AllErrorCodes() {
		if strings.HasPrefix(ec.Code, "ALC-ROT-") || ec.Code == "ALC-NTF-0001" ||
			(strings.HasPrefix(ec.Code, "ALC-KEY-") && ec.Code >= "ALC-KEY-0006") {
			out = append(out, ec)
		}
	}
	return out
}

func TestPhase6CodeTable(t *testing.T) {
	got := phase6Codes()
	require.Len(t, got, len(phase6Table))
	for i, row := range phase6Table {
		ec := got[i]
		assert.Equal(t, row.code, ec.Code)
		assert.Equal(t, row.reason, ec.Reason, row.code)
		assert.Equal(t, row.status, ec.Status, row.code)
		assert.Equal(t, row.retryable, ec.Retryable, row.code)
		assert.Equal(t, ec, codeForReason(row.reason), row.code)
	}
}

// Every Phase 6 code has a section headed by its English title, with its HTTP status and reason, a cause and a
// remedy; no Phase 6 text uses a placeholder (the reasons are stored without params).
func TestPhase6CodesHaveTroubleshootingSections(t *testing.T) {
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for _, ec := range phase6Codes() {
		title := cat.T("en", "errors."+ec.Reason+".title", nil)
		assert.Contains(t, string(doc), "\n## "+ec.Code+": "+strings.TrimSuffix(title, ".")+"\n", ec.Code)
		assert.Regexp(t, regexp.MustCompile(`(?m)^## `+ec.Code+`: .+\n\n\*\*Meaning\.\*\* .*\(HTTP `+strconv.Itoa(ec.Status)+`, reason `+"`"+regexp.QuoteMeta(ec.Reason)+"`"), string(doc), ec.Code)
		section := troubleshootingSection(string(doc), ec.Code)
		assert.Regexp(t, `(?m)^\*\*Likely cause\.\*\* \S`, section, ec.Code)
		assert.Regexp(t, `(?m)^\*\*What to do\.\*\* \S`, section, ec.Code)
		for _, lang := range []string{"en", "tr"} {
			for _, part := range []string{"title", "cause", "action"} {
				text := cat.T(lang, "errors."+ec.Reason+"."+part, nil)
				assert.NotContains(t, text, "{{", "%s %s.%s", lang, ec.Reason, part)
				assert.NotContains(t, text, "  ", "%s %s.%s", lang, ec.Reason, part)
			}
		}
	}
}

// stringConsts returns the package-level string constants of dir's non-test sources whose name has prefix.
func stringConsts(t *testing.T, dir, prefix string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	require.NoError(t, err)
	fset := token.NewFileSet()
	out := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if !strings.HasPrefix(n.Name, prefix) || i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						out[n.Name], _ = strconv.Unquote(lit.Value)
					}
				}
			}
		}
	}
	return out
}

// Every result and error reason the rotation service exports has a registered code (a stored reason is shown
// through its code, never bare): rotations.result_code, rotation_locations.error_code, the mails' code param.
func TestEveryRotationReasonHasACode(t *testing.T) {
	reasons := stringConsts(t, "../sshkeys", "Reason")
	require.Greater(t, len(reasons), 15, "the scan must find the reason constants")
	for name, reason := range reasons {
		assert.NotEqual(t, ErrUnexpected, codeForReason(reason), "sshkeys.%s = %q has no code", name, reason)
	}
}

// storeOnlySentinels reach only the location jobs (the store's "stop here" answers); a request that met one is
// answered ALC-SYS-0003. The selector sentinels are the inventory's (TestEveryInventorySentinelHasACode).
// ErrNoJobClaim and ErrNoSendOnRecord are the deploy job's caller bugs (a missing claim, a send not on record).
var storeOnlySentinels = []string{"ErrNotYourTurn", "ErrPaused", "ErrNoJobClaim", "ErrNoSendOnRecord"}

// Every exported error of the rotation service and of the planner maps to a documented, translated code, except the
// store-only ones.
func TestEverySSHKeysSentinelHasACode(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	sentinels := map[string]error{
		"ErrNotFound": sshkeys.ErrNotFound, "ErrNotManaged": sshkeys.ErrNotManaged, "ErrRetired": sshkeys.ErrRetired,
		"ErrDestroyed": sshkeys.ErrDestroyed, "ErrConnectionAccount": sshkeys.ErrConnectionAccount, "ErrNotAKeyFile": sshkeys.ErrNotAKeyFile,
		"ErrGenerateBusy": sshkeys.ErrGenerateBusy, "ErrConnectionFilesUnknown": sshkeys.ErrConnectionFilesUnknown,
		"ErrClockBehind": sshkeys.ErrClockBehind, "ErrPolicyExists": sshkeys.ErrPolicyExists, "ErrRotationInProgress": sshkeys.ErrRotationInProgress,
		"ErrPlanChanged": sshkeys.ErrPlanChanged, "ErrNothingToRotate": sshkeys.ErrNothingToRotate, "ErrNotWaiting": sshkeys.ErrNotWaiting,
		"ErrPlanTooLarge": sshkeys.ErrPlanTooLarge, "ErrVersionMismatch": sshkeys.ErrVersionMismatch, "ErrOwnKeyProtected": sshkeys.ErrOwnKeyProtected,
		"ErrNotYourTurn": sshkeys.ErrNotYourTurn, "ErrPaused": sshkeys.ErrPaused, "ErrBadCursor": sshkeys.ErrBadCursor,
		"ErrNoticePending": sshkeys.ErrNoticePending, "ErrInRotation": sshkeys.ErrInRotation,
		"ErrNoJobClaim": sshkeys.ErrNoJobClaim, "ErrNoSendOnRecord": sshkeys.ErrNoSendOnRecord,
	}
	planSentinels := map[string]error{"ErrNotManaged": plan.ErrNotManaged, "ErrOwnKey": plan.ErrOwnKey, "ErrRetired": plan.ErrRetired,
		"ErrNothingToRotate": plan.ErrNothingToRotate, "ErrNewKeyType": plan.ErrNewKeyType}
	for dir, table := range map[string]map[string]error{"../sshkeys": sentinels, "../sshkeys/plan": planSentinels} {
		names := exportedErrorVars(t, dir)
		known := make([]string, 0, len(table))
		for n := range table {
			known = append(known, n)
		}
		slices.Sort(known)
		assert.Equal(t, names, known, "%s: the table must list every exported error (and only those)", dir)
		for name, sentinel := range table {
			ec, _, ok := classify(fmt.Errorf("wrapped: %w", sentinel))
			if dir == "../sshkeys" && slices.Contains(storeOnlySentinels, name) {
				assert.False(t, ok, "%s is store-only; if the API can now receive it, give it a code", name)
				continue
			}
			require.True(t, ok, "%s %s has no errorMap entry", dir, name)
			assert.NotEqual(t, ErrUnexpected, ec, name)
			assert.Contains(t, AllErrorCodes(), ec, name)
			assert.NotEqual(t, "errors."+ec.Reason+".title", cat.T("tr", "errors."+ec.Reason+".title", nil), name)
		}
	}
	// The contract's mapping (C11), and inventory's disabled server (Task 6).
	for err, want := range map[error]ErrorCode{
		sshkeys.ErrNotManaged: ErrKeyNotManaged, sshkeys.ErrRetired: ErrKeyRetired, sshkeys.ErrDestroyed: ErrKeyDestroyed,
		sshkeys.ErrConnectionAccount: ErrKeyConnectionAccount, sshkeys.ErrGenerateBusy: ErrKeyGenerateBusy, sshkeys.ErrNotAKeyFile: ErrKeyNotAKeyFile,
		sshkeys.ErrPolicyExists: ErrRotPolicyExists, sshkeys.ErrRotationInProgress: ErrRotInProgress, sshkeys.ErrPlanChanged: ErrRotPlanChanged,
		sshkeys.ErrNothingToRotate: ErrRotNothingToRotate, sshkeys.ErrNotWaiting: ErrRotNotWaiting, sshkeys.ErrVersionMismatch: ErrPreconditionFailed,
		sshkeys.ErrOwnKeyProtected: ErrOwnKeyProtected, sshkeys.ErrClockBehind: ErrKeyClockBehind, inventory.ErrTargetDisabled: ErrTargetDisabled,
		sshkeys.ErrConnectionFilesUnknown: ErrKeyConnectionFilesUnknown, sshkeys.ErrPlanTooLarge: ErrRotPlanTooLarge,
		sshkeys.ErrNoticePending: ErrRotNoticePending, sshkeys.ErrInRotation: ErrKeyInRotation,
	} {
		ec, _, ok := classify(err)
		require.True(t, ok)
		assert.Equal(t, want, ec, err.Error())
	}
	assert.Equal(t, http.StatusServiceUnavailable, ErrKeyClockBehind.Status, "a clock step back is retryable, never a 500")
	assert.True(t, ErrKeyClockBehind.Retryable)
}

// Every skip reason the planner exports has its text in both languages under rotation.skip.<reason> and a line in the
// troubleshooting guide's rotation section.
func TestEverySkipReasonHasATextAndAnExplanation(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	skips := stringConsts(t, "../sshkeys/plan", "Skip")
	require.GreaterOrEqual(t, len(skips), 14, "the scan must find the skip reasons")
	for name, reason := range skips {
		for _, lang := range []string{"en", "tr"} {
			key := "rotation.skip." + reason
			assert.NotEqual(t, key, cat.T(lang, key, nil), "plan.%s: %s missing in %s", name, key, lang)
		}
		assert.Contains(t, string(doc), "(`"+reason+"`)", "plan.%s: not explained in docs/troubleshooting.md", name)
	}
	for _, reason := range []string{plan.SkipDuplicateLines, plan.SkipOptionsUnreadable, plan.SkipSharedFile, plan.SkipRootForcedCommands} {
		assert.Contains(t, skips, map[string]string{
			plan.SkipDuplicateLines: "SkipDuplicateLines", plan.SkipOptionsUnreadable: "SkipOptionsUnreadable",
			plan.SkipSharedFile: "SkipSharedFile", plan.SkipRootForcedCommands: "SkipRootForcedCommands"}[reason])
	}
}

// A rotation step the database refused (*sshkeys.GuardRefusal, a store bug) is the generic internal error to the
// client; the log names the SQLSTATE and the constraint, never the guard's message (which can name row values).
func TestGuardRefusalIsInternal(t *testing.T) {
	var logs bytes.Buffer
	d := testDeps(t, nil)
	d.Log = logging.New(&logs, slog.LevelDebug)
	s := newServer(d)
	err := fmt.Errorf("decide: %w", &sshkeys.GuardRefusal{Code: "Z1011", Constraint: "rotation_locations_guard", Message: "row SECRET-ROW-VALUE"})
	_, _, ok := classify(err)
	assert.False(t, ok)
	rec := httptest.NewRecorder()
	s.fail(rec, httptest.NewRequest(http.MethodPost, "/api/v1/rotation/runs/x/actions/keep-old", nil), err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "ALC-SYS-0003", decodeErr(t, rec).Error.Code)
	assert.NotContains(t, rec.Body.String(), "SECRET-ROW-VALUE")
	assert.NotContains(t, rec.Body.String(), "rotation_locations_guard")
	assert.Contains(t, logs.String(), `"guard_sqlstate":"Z1011"`)
	assert.Contains(t, logs.String(), `"guard_constraint":"rotation_locations_guard"`)
	assert.NotContains(t, logs.String(), "SECRET-ROW-VALUE")
}
