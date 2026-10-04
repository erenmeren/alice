package api

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
	"alice/locales"
)

// inventorySentinels are the inventory's exported error values by name. The test below parses the
// package and fails when it exports one that is not listed here, so a new refusal cannot reach the
// API without a code.
var inventorySentinels = map[string]error{
	"ErrNotFound": inventory.ErrNotFound, "ErrDuplicateTarget": inventory.ErrDuplicateTarget,
	"ErrVersionMismatch": inventory.ErrVersionMismatch, "ErrHostKeyUnconfirmed": inventory.ErrHostKeyUnconfirmed,
	"ErrHostKeyChanged": inventory.ErrHostKeyChanged, "ErrHostKeyStale": inventory.ErrHostKeyStale,
	"ErrHostKeyState": inventory.ErrHostKeyState, "ErrOwnKeyProtected": inventory.ErrOwnKeyProtected,
	"ErrLastRootKey": inventory.ErrLastRootKey, "ErrKeysManagedElsewhere": inventory.ErrKeysManagedElsewhere,
	"ErrNotRemovable": inventory.ErrNotRemovable, "ErrSSHDUnreadable": inventory.ErrSSHDUnreadable,
	"ErrJobConflict": inventory.ErrJobConflict, "ErrNoSetupScript": inventory.ErrNoSetupScript,
	"ErrNoPlatformKey": inventory.ErrNoPlatformKey, "ErrCertificateDuplicate": inventory.ErrCertificateDuplicate,
	"ErrCSRNotPending": inventory.ErrCSRNotPending, "ErrLocationUnsupported": inventory.ErrLocationUnsupported,
	"ErrPFXBusy": inventory.ErrPFXBusy, "ErrCertificateInvalid": inventory.ErrCertificateInvalid,
	"ErrKeyMismatch": inventory.ErrKeyMismatch, "ErrCertificateExpired": inventory.ErrCertificateExpired,
	"ErrKeyEncrypted": inventory.ErrKeyEncrypted, "ErrPFXPassword": inventory.ErrPFXPassword,
	"ErrWeakCertificate": inventory.ErrWeakCertificate, "ErrUnsupportedKey": inventory.ErrUnsupportedKey,
	"ErrCSRMismatch": inventory.ErrCSRMismatch, "ErrCertificateTooLarge": inventory.ErrCertificateTooLarge,
	"ErrDeploymentInProgress": inventory.ErrDeploymentInProgress, "ErrRecoveryPending": inventory.ErrRecoveryPending,
	"ErrNoPrivateKey": inventory.ErrNoPrivateKey, "ErrKeyTypeMismatch": inventory.ErrKeyTypeMismatch,
	"ErrChainUnconfirmed": inventory.ErrChainUnconfirmed, "ErrNginxConfigInvalid": inventory.ErrNginxConfigInvalid,
	"ErrTargetNotReady": inventory.ErrTargetNotReady, "ErrDeploymentState": inventory.ErrDeploymentState,
	"ErrCertificateNotYetValid": inventory.ErrCertificateNotYetValid, "ErrLocationNeedsDiscovery": inventory.ErrLocationNeedsDiscovery,
	"ErrClaimLost": inventory.ErrClaimLost,
}

// engineOnlySentinels are returned only by the methods the deployment engine calls (StartDeployment,
// FinishDeployment, RecordDeploymentStep, RecordOutcome, CheckClaim, ...), never by a method of
// InventoryService: the engine reads the record again and follows it. They have no code on purpose.
var engineOnlySentinels = []string{"ErrDeploymentState", "ErrClaimLost"}

// exportedErrorVars returns the names of the package-level exported variables of dir's non-test
// sources whose value is errors.New(...) or a selector (a re-exported sentinel such as certs.ErrX).
func exportedErrorVars(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	require.NoError(t, err)
	fset := token.NewFileSet()
	var out []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if !n.IsExported() || !strings.HasPrefix(n.Name, "Err") || i >= len(vs.Values) {
						continue
					}
					switch v := vs.Values[i].(type) {
					case *ast.CallExpr:
						if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "New" {
							out = append(out, n.Name)
						}
					case *ast.SelectorExpr:
						out = append(out, n.Name)
					}
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// Binding requirement 1: every exported inventory sentinel maps to a documented, translated code
// through fail (none falls through to internal.unexpected), except the engine-only ones.
func TestEveryInventorySentinelHasACode(t *testing.T) {
	names := exportedErrorVars(t, "../inventory")
	require.Greater(t, len(names), 30, "the scan must find the sentinels")
	known := make([]string, 0, len(inventorySentinels))
	for n := range inventorySentinels {
		known = append(known, n)
	}
	slices.Sort(known)
	assert.Equal(t, names, known, "inventorySentinels must list every exported inventory error (and only those)")
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for name, sentinel := range inventorySentinels {
		ec, _, ok := classify(sentinel)
		if slices.Contains(engineOnlySentinels, name) {
			assert.False(t, ok, "%s is engine-only; if the API can now receive it, give it a code", name)
			continue
		}
		require.True(t, ok, "%s has no errorMap entry", name)
		assert.NotEqual(t, ErrUnexpected, ec, name)
		assert.Contains(t, AllErrorCodes(), ec, name)
		assert.NotEqual(t, "errors."+ec.Reason+".title", cat.T("tr", "errors."+ec.Reason+".title", nil), name)
		// Wrapped as the services wrap them, the code stays.
		ec2, _, ok := classify(&inventory.LocationRefusalError{LocationID: uuid.New(), Err: sentinel})
		assert.True(t, ok, name)
		assert.Equal(t, ec, ec2, name)
	}
}

// Every reason refineReason can produce, and every reason a Phase 4 provider, engine or inventory
// stores (TestJobResultReasonsAreRegistered scans them), is registered.
func TestRefinedReasonsAreRegistered(t *testing.T) {
	for _, phase := range []string{"", providers.PhaseRestored, providers.PhaseRestoreFailed} {
		for _, class := range []string{"", providers.DeployErrFileChanged, providers.ConfigErrSyntax} {
			r := refineReason(ErrDeployRollbackFailed.Reason, phase, class)
			assert.NotEqual(t, ErrUnexpected, codeForReason(r), r)
		}
	}
	assert.Equal(t, "deployment.verify_failed", refineReason("deployment.verify_failed", providers.PhaseRestored, ""))
}

var placeholderRE = regexp.MustCompile(`\{\{(\w+)\}\}`)

// phase4Codes are the codes added for Phase 4 (areas NGX, CRT, DEP).
func phase4Codes() []ErrorCode {
	var out []ErrorCode
	for _, ec := range AllErrorCodes() {
		if strings.HasPrefix(ec.Code, "ALC-NGX-") || strings.HasPrefix(ec.Code, "ALC-CRT-") || strings.HasPrefix(ec.Code, "ALC-DEP-") {
			out = append(out, ec)
		}
	}
	return out
}

// Binding requirement 2: every placeholder of a Phase 4 text (and of the texts it rewrote) is a
// param the API lets through, EN and TR use the same ones, and no placeholder carries a suffix.
func TestPhase4TextPlaceholdersAreAllowlisted(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	codes := phase4Codes()
	require.Len(t, codes, 45)
	for _, ec := range codes {
		for _, part := range []string{"title", "cause", "action"} {
			key := "errors." + ec.Reason + "." + part
			en, tr := cat.T("en", key, nil), cat.T("tr", key, nil)
			enP, trP := placeholderRE.FindAllStringSubmatch(en, -1), placeholderRE.FindAllStringSubmatch(tr, -1)
			assert.Len(t, trP, len(enP), key)
			for _, m := range append(enP, trP...) {
				assert.True(t, providerParamKeys[m[1]], "%s uses {{%s}}, which the API never lets through", key, m[1])
			}
			assert.NotRegexp(t, `\}\}[\p{L}'’]`, tr, "%s: a suffix attached to a placeholder", key)
			assert.NotContains(t, en, "write_failed")
		}
	}
}

// renderAll renders the three parts of ec in both languages with params and fails on a leftover
// placeholder.
func renderAll(t *testing.T, cat *i18n.Catalog, ec ErrorCode, params map[string]string, source string) {
	t.Helper()
	for _, lang := range []string{"en", "tr"} {
		for _, part := range []string{"title", "cause", "action"} {
			out := cat.T(lang, "errors."+ec.Reason+"."+part, params)
			assert.NotContains(t, out, "{{", "%s %s %s rendered from %s: %q", ec.Code, lang, part, source, out)
		}
	}
}

// Binding requirement 2: every Phase 4 text renders without a leftover placeholder with the params
// its source provides, through the API's own paths: classify (request refusals and provider
// errors), deploymentError (stored deployment errors) and jobJSON (stored job errors).
func TestPhase4ErrorTextsRenderWithTheirParams(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	// What each producer puts in the params (see the reasons' producers: nginx verify.go/deploy.go
	// for port and backup_dir, provider.go for profile_missing, inventory's KeyTypeMismatchError).
	provided := map[string]map[string]string{
		"deployment.verify_unreachable": {"port": "443"},
		"deployment.verify_chain":       {"port": "8443"},
		"deployment.rollback_failed":    {"backup_dir": inventory.BackupRoot + "/" + uuid.NewString()},
		"nginx.profile_missing":         {"subcommand": "nginx-dump", "profile": "nginx"},
	}
	// requestOnly reasons are answered to a request only (from a typed inventory error that carries
	// their params), never stored by a provider, the engine or the inventory.
	requestOnly := []string{ErrCertKeyTypeMismatch.Reason}
	for _, dir := range []string{"../providers/nginx", "../jobs/deployjobs", "../inventory", "../jobs"} {
		for reason := range storedReasons(t, dir) {
			assert.NotContains(t, requestOnly, reason, "%s is stored by %s: render it from records too", reason, dir)
		}
	}
	for _, ec := range phase4Codes() {
		params := provided[ec.Reason]
		if slices.Contains(requestOnly, ec.Reason) {
			continue
		}
		// A request refusal or a provider error answered by the API.
		got, p, ok := classify(providers.NewError(ec.Reason, false, errors.New("cause"), params))
		require.True(t, ok, ec.Code)
		renderAll(t, cat, got, p, "a provider error")
		// A stored deployment error, with nothing but the code stored (the recovery's rollback
		// records the verification's port in verify_failed_port, not in the params).
		port := 443
		dto := deploymentError(inventory.Deployment{ErrorCode: ec.Reason, ErrorParams: params, VerifyFailedPort: &port})
		require.NotNil(t, dto)
		renderAll(t, cat, codeForReason(dto.Reason), dto.Params, "a deployment")
		dto = deploymentError(inventory.Deployment{ErrorCode: ec.Reason, VerifyFailedPort: &port})
		renderAll(t, cat, codeForReason(dto.Reason), dto.Params, "a deployment without params")
		// A stored job error (deployjobs keeps port, failed_step, phase, helper_code, subcommand, exit_code).
		jp := map[string]string{}
		for k, v := range params {
			if slices.Contains([]string{"port", "failed_step", "phase", "helper_code", "subcommand", "exit_code"}, k) {
				jp[k] = v
			}
		}
		j := jobJSON(jobs.View{LastErrorCode: ec.Reason, ErrorParams: jp})
		renderAll(t, cat, codeForReason(j.Error.Reason), j.Error.Params, "a job")
	}
	// The key type refusal comes with its two types.
	got, p, ok := classify(&inventory.KeyTypeMismatchError{Expected: "rsa", Actual: "ecdsa"})
	require.True(t, ok)
	renderAll(t, cat, got, p, "RequestDeployment")
	assert.Contains(t, cat.T("en", "errors.certificate.key_type_mismatch.cause", p), "here: rsa. Key type of this certificate: ecdsa.")
}

// The rewritten texts say what the as-built code does (carries): RSA up to 16384 bits, no
// "connection lost" claim for an interruption, a restore failure that may have had the files back,
// and nginx.io_error (not the retired nginx.write_failed) as ALC-NGX-0009.
func TestPhase4TextsAreTruthfulForEveryCause(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	en := func(key string) string { return cat.T("en", key, nil) }
	assert.Contains(t, en("errors.certificate.unsupported_key.action"), "2048 to 16384 bits")
	assert.NotContains(t, en("errors.deployment.interrupted.cause"), "onnection was lost")
	assert.Contains(t, en("errors.deployment.rollback_failed.cause"), "could not be confirmed")
	assert.Equal(t, "nginx.io_error", ErrNginxIOError.Reason)
	assert.Equal(t, "ALC-NGX-0009", ErrNginxIOError.Code)
	assert.Equal(t, ErrUnexpected, codeForReason("nginx.write_failed"), "retired: never produced")
	for _, r := range []string{"deployment.verify_failed", "deployment.verify_other", "deployment.reload_failed",
		"deployment.config_test_failed", "certificate.key_mismatch"} {
		assert.NotContains(t, en("errors."+r+".cause"), "Your server was restored", r)
	}
	// The existing SSH text that Nginx dumps now share no longer names SSH files only.
	assert.Contains(t, en("errors.ssh.output_too_large.action"), "Nginx")
}

// Every Phase 4 code is in the troubleshooting guide with its reason.
func TestPhase4CodesHaveTroubleshootingSections(t *testing.T) {
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	for _, ec := range phase4Codes() {
		assert.Regexp(t, regexp.MustCompile(`(?m)^## `+ec.Code+`: .+\n\n\*\*Meaning\.\*\* .*reason `+"`"+regexp.QuoteMeta(ec.Reason)+"`"), string(doc), ec.Code)
	}
}
