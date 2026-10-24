package api

import (
	"bytes"
	"errors"
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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/platform/logging"
	"alice/internal/providers"
	"alice/internal/revocation"
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
	"ErrRevocationSettingsVersion": inventory.ErrRevocationSettingsVersion, // the revocation check switch (R64): 412
	"ErrNoPrivateKey":              inventory.ErrNoPrivateKey, "ErrKeyTypeMismatch": inventory.ErrKeyTypeMismatch,
	"ErrChainUnconfirmed": inventory.ErrChainUnconfirmed, "ErrNginxConfigInvalid": inventory.ErrNginxConfigInvalid,
	"ErrTargetNotReady": inventory.ErrTargetNotReady, "ErrDeploymentState": inventory.ErrDeploymentState,
	"ErrCertificateNotYetValid": inventory.ErrCertificateNotYetValid, "ErrLocationNeedsDiscovery": inventory.ErrLocationNeedsDiscovery,
	"ErrDriftNotBound": inventory.ErrDriftNotBound, "ErrDriftNotDrifted": inventory.ErrDriftNotDrifted, "ErrDriftNotRepairable": inventory.ErrDriftNotRepairable,
	"ErrDriftRepairSuperseded": inventory.ErrDriftRepairSuperseded, "ErrDriftRepairOff": inventory.ErrDriftRepairOff,
	"ErrClaimLost": inventory.ErrClaimLost, "ErrCSRBusy": inventory.ErrCSRBusy, "ErrTooManyPendingCSRs": inventory.ErrTooManyPendingCSRs,
	// Phase 5 (Tasks 10-14)
	"ErrVaultHasBindings": inventory.ErrVaultHasBindings, "ErrNotAVault": inventory.ErrNotAVault, "ErrNotAServer": inventory.ErrNotAServer,
	"ErrClientCertificateInvalid": inventory.ErrClientCertificateInvalid, "ErrNotExportable": inventory.ErrNotExportable,
	"ErrVersionNotDeployable": inventory.ErrVersionNotDeployable, "ErrCredentialNotTheTargets": inventory.ErrCredentialNotTheTargets,
	"ErrLocationBound": inventory.ErrLocationBound, "ErrBindingExists": inventory.ErrBindingExists, "ErrVersionDisabled": inventory.ErrVersionDisabled,
	"ErrKVCertificateMissing": inventory.ErrKVCertificateMissing, "ErrHeldNeedsAdmin": inventory.ErrHeldNeedsAdmin,
	"ErrAdminRequired": inventory.ErrAdminRequired, "ErrVersionNotHeld": inventory.ErrVersionNotHeld, "ErrSecretUnreadable": inventory.ErrSecretUnreadable,
	"ErrSecretMismatch": inventory.ErrSecretMismatch, "ErrBindingGone": inventory.ErrBindingGone, "ErrAutoDeployOff": inventory.ErrAutoDeployOff,
	"ErrVersionHeld": inventory.ErrVersionHeld, "ErrVaultUnavailable": inventory.ErrVaultUnavailable,
	"ErrVersionSuperseded": inventory.ErrVersionSuperseded, "ErrWaveStopped": inventory.ErrWaveStopped,
	"ErrHeldNeedsStepUp": inventory.ErrHeldNeedsStepUp, "ErrAutoDeployNeedsStepUp": inventory.ErrAutoDeployNeedsStepUp,
	"ErrImportConfirmNeeded": inventory.ErrImportConfirmNeeded, "ErrImportInProgress": inventory.ErrImportInProgress,
	"ErrImportState": inventory.ErrImportState, "ErrImportChanged": inventory.ErrImportChanged,
	"ErrVaultCredentialUnreadable": inventory.ErrVaultCredentialUnreadable,
	// Phase 6 (Task 6)
	"ErrTargetDisabled": inventory.ErrTargetDisabled,
	// ACME (Tasks 8 and 9)
	"ErrACMEOrderNotRunning": inventory.ErrACMEOrderNotRunning, "ErrACMEPendingKey": inventory.ErrACMEPendingKey,
	"ErrACMEChainMismatch": inventory.ErrACMEChainMismatch, "ErrACMEErrorCode": inventory.ErrACMEErrorCode,
	"ErrACMEProviderInUse": inventory.ErrACMEProviderInUse, "ErrACMEHookInUse": inventory.ErrACMEHookInUse,
	"ErrACMENameTaken": inventory.ErrACMENameTaken, "ErrACMEDirectoryChange": inventory.ErrACMEDirectoryChange,
	"ErrACMESecretUnreadable": inventory.ErrACMESecretUnreadable, "ErrACMEAccountExists": inventory.ErrACMEAccountExists,
	"ErrACMEAccountState": inventory.ErrACMEAccountState, "ErrACMERolloverPending": inventory.ErrACMERolloverPending,
	"ErrACMEProviderBusy": inventory.ErrACMEProviderBusy,
	// Revocation and key-compromise incidents (2026-10-20)
	"ErrCertificateRevoked": inventory.ErrCertificateRevoked, "ErrCertificateCompromised": inventory.ErrCertificateCompromised,
	"ErrNotACMEVersion": inventory.ErrNotACMEVersion, "ErrIncidentOpen": inventory.ErrIncidentOpen,
	"ErrIncidentState": inventory.ErrIncidentState, "ErrIncidentReplacement": inventory.ErrIncidentReplacement,
	"ErrIncidentNotRevocable": inventory.ErrIncidentNotRevocable,
	// ACME (Task 10)
	"ErrACMENameNotAllowed": inventory.ErrACMENameNotAllowed, "ErrACMEOrderRunning": inventory.ErrACMEOrderRunning,
	"ErrACMEChallengeUnavailable": inventory.ErrACMEChallengeUnavailable, "ErrACMEKeyTypeLocked": inventory.ErrACMEKeyTypeLocked,
	// The CA asked to wait (R47).
	"ErrACMECAWait": inventory.ErrACMECAWait,
	// ACME (Task 12): bindings and Deploy now, and the refusals of a queued automatic deployment judged again (the
	// engine ends it with their reasons; the API maps them too, so none can become a 500).
	"ErrACMENotIssued": inventory.ErrACMENotIssued, "ErrACMELocationBound": inventory.ErrACMELocationBound,
	"ErrACMELocationNotBound": inventory.ErrACMELocationNotBound, "ErrACMEBindingGone": inventory.ErrACMEBindingGone,
	"ErrACMEAutoDeployOff": inventory.ErrACMEAutoDeployOff, "ErrACMESuperseded": inventory.ErrACMESuperseded,
	"ErrACMEDeployStopped": inventory.ErrACMEDeployStopped, "ErrACMEDeployHeld": inventory.ErrACMEDeployHeld,
	"ErrACMENoBindings": inventory.ErrACMENoBindings, "ErrACMETooManyBindings": inventory.ErrACMETooManyBindings,
	// Scoped access (R49): a deployment, binding, import or key deploy across services without a trust.
	"ErrServiceUntrusted": inventory.ErrServiceUntrusted,
}

// engineOnlySentinels are returned only by the methods the deployment engine calls (StartDeployment,
// FinishDeployment, RecordDeploymentStep, RecordOutcome, CheckClaim, ...), never by a method of
// InventoryService: the engine reads the record again and follows it. They have no code on purpose.
//
// Phase 5: ErrBindingGone, ErrAutoDeployOff and ErrVersionHeld come from KVDeployPrecheck/KVDeployMaterial (the
// engine ends the deployment with kv.binding_gone, kv.auto_deploy_off, kv.version_held); ErrImportState and
// ErrImportChanged are what an import job meets; ErrCredentialNotTheTargets is the database refusing what correct
// code never sends (Z1006); ReplaceVaultCredentials can return it, and it answers ALC-SYS-0003 on purpose (a
// programming error nobody can act on). A request that somehow met any of these is answered ALC-SYS-0003.
//
// ACME (Task 8): the order record's ErrACMEOrderNotRunning, ErrACMEPendingKey, ErrACMEChainMismatch and ErrACMEErrorCode
// reach only the acme.issue job (Begin/Finish/Abort/LoadPendingKey), which records an order error code instead.
var engineOnlySentinels = []string{"ErrDeploymentState", "ErrClaimLost", "ErrBindingGone", "ErrAutoDeployOff", "ErrVersionHeld",
	"ErrImportState", "ErrImportChanged", "ErrCredentialNotTheTargets", "ErrVersionSuperseded", "ErrWaveStopped",
	"ErrACMEOrderNotRunning", "ErrACMEPendingKey", "ErrACMEChainMismatch", "ErrACMEErrorCode"}

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
	// Every ALC-NGX/CRT/DEP code, derived from AllErrorCodes: the Phase 4 reasons scanned from the
	// sources (TestJobResultReasonsAreRegistered) and the request refusals all land here.
	for _, ec := range AllErrorCodes() {
		if strings.HasPrefix(ec.Reason, "nginx.") || strings.HasPrefix(ec.Reason, "certificate.") || strings.HasPrefix(ec.Reason, "csr.") ||
			strings.HasPrefix(ec.Reason, "deployment.") {
			assert.Contains(t, codes, ec, "%s is a Phase 4 reason outside the NGX/CRT/DEP areas", ec.Reason)
		}
	}
	require.NotEmpty(t, codes)
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
		"deployment.verify_untrusted":   {"port": "443", "trust_error": "wrong_intermediate"},
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
	// Fix round 1: the configuration refusal covers untrusted and unsupported configurations (where
	// nginx -t passes); the helper forgets finished operations after 7 days; no endpoint to probe is
	// unreachable too; a missing location is unsupported; no Nginx jargon; key mismatch and invalid
	// cover upload and deployment; a weak chain certificate counts.
	assert.Contains(t, en("errors.nginx.config_invalid.cause"), "cannot safely read")
	assert.NotContains(t, en("errors.nginx.config_invalid.cause"), "fails")
	assert.Contains(t, en("errors.deployment.unknown_operation.cause"), "after 7 days or more")
	assert.Contains(t, en("errors.deployment.verify_unreachable.cause"), "no HTTPS address")
	assert.Contains(t, en("errors.nginx.location_unsupported.cause"), "no longer uses this file")
	assert.Contains(t, en("errors.nginx.no_space.title"), "enough")
	assert.Contains(t, en("errors.certificate.weak.title"), "in its chain")
	assert.Contains(t, en("errors.deployment.target_not_ready.cause"), "host key fingerprint")
	for _, ec := range phase4Codes() {
		for _, part := range []string{"title", "cause", "action"} {
			for _, lang := range []string{"en", "tr"} {
				text := cat.T(lang, "errors."+ec.Reason+"."+part, nil)
				for _, jargon := range []string{"journal", "günlük", "server block", "server bloğ", "Scan for SSH keys", "SSH anahtarlarını tara"} {
					assert.NotContains(t, text, jargon, "%s %s %s", ec.Code, lang, part)
				}
			}
		}
	}
	// Fix round 2: a second upload of a held certificate is refused (ALC-CRT-0008), so the deployment
	// advice must not ask for one; the configuration refusal is about deploying, not editing Nginx.
	assert.NotContains(t, en("errors.certificate.invalid.action"), "upload the certificate again")
	assert.Contains(t, en("errors.certificate.invalid.action"), "corrected certificate")
	assert.Contains(t, en("errors.certificate.invalid.action"), "request ID")
	assert.Contains(t, cat.T("tr", "errors.certificate.invalid.action", nil), "düzeltilmiş bir sertifika")
	assert.Contains(t, en("errors.nginx.config_invalid.title"), "will not deploy to this server until it is fixed")
	for _, lang := range []string{"en", "tr"} {
		raw, err := locales.FS.ReadFile("common/" + lang + ".json")
		require.NoError(t, err)
		flat, err := i18n.Flatten(raw)
		require.NoError(t, err)
		emails := 0
		for k, text := range flat {
			if !strings.HasPrefix(k, "email.deployment.") {
				continue
			}
			emails++
			for _, jargon := range []string{"journal", "günlük", "server block", "server bloğ", "Scan for SSH keys", "SSH anahtarlarını tara"} {
				assert.NotContains(t, text, jargon, "%s %s", lang, k)
			}
		}
		assert.Greater(t, emails, 10, "the Phase 4 emails were checked")
	}
	for _, r := range []string{"certificate.key_mismatch", "certificate.invalid"} {
		assert.Contains(t, en("errors."+r+".action"), "When uploading", r)
		assert.Contains(t, en("errors."+r+".action"), "After a deployment", r)
	}
	// C-I2: after another program changed a file, Alice put back at most what it wrote, so the pair may
	// not belong together: the action has the reader run nginx -t at once, in both languages.
	for _, lang := range []string{"en", "tr"} {
		assert.Contains(t, cat.T(lang, "errors.deployment.rollback_file_changed.action", nil), "nginx -t", lang)
	}
	assert.NotContains(t, en("errors.deployment.rollback_file_changed.cause"), "did not put the previous files back")
	assert.Contains(t, en("errors.deployment.rollback_file_changed.cause"), "may not belong together")
	// C m4: a deployment an Administrator cancelled is not reported as a failure of the server.
	assert.Contains(t, en("errors.deployment.cancelled.cause"), "sent nothing")
	assert.Contains(t, en("errors.deployment.cancelled.title"), "before anything was sent to the server")
	assert.Contains(t, cat.T("tr", "errors.deployment.cancelled.title", nil), "hiçbir şey gönderilmeden önce")
	assert.Contains(t, en("errors.csr.too_many_pending.cause"), "whole installation")
	// The existing SSH text that Nginx dumps now share no longer names SSH files only.
	assert.Contains(t, en("errors.ssh.output_too_large.action"), "Nginx")
}

// Every Phase 4 code is in the troubleshooting guide with its reason.
func TestPhase4CodesHaveTroubleshootingSections(t *testing.T) {
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	for _, ec := range phase4Codes() {
		assert.Regexp(t, regexp.MustCompile(`(?m)^## `+ec.Code+`: .+\n\n\*\*Meaning\.\*\* .*reason `+"`"+regexp.QuoteMeta(ec.Reason)+"`"), string(doc), ec.Code)
		// The section also says what causes it and what to do about it.
		section := troubleshootingSection(string(doc), ec.Code)
		assert.Regexp(t, `(?m)^\*\*Likely cause\.\*\* \S`, section, ec.Code)
		assert.Regexp(t, `(?m)^\*\*What to do\.\*\* \S`, section, ec.Code)
	}
}

// troubleshootingSection returns the text of the "## <code>: …" section, up to the next "## " heading.
func troubleshootingSection(doc, code string) string {
	start := strings.Index(doc, "\n## "+code+": ")
	if start < 0 {
		return ""
	}
	rest := doc[start+1:]
	if end := strings.Index(rest[3:], "\n## "); end >= 0 {
		return rest[:end+3]
	}
	return rest
}

// discoverKeys are the common-locale keys that tell the reader to choose the Nginx server page's
// scan action, labelled Discover / Keşfet (controller ruling; Task 22 creates the control with
// exactly this label and should pin it against this list).
var discoverKeys = []string{
	"errors.nginx.config_invalid.action", "errors.certificate.revocation_no_issuer.action",
	"errors.apache.config_invalid.action", "errors.haproxy.config_invalid.action", "errors.nginx.config_changed.action", "errors.nginx.file_changed.action",
	"errors.nginx.location_unsupported.action", "errors.deployment.verify_other.action", "errors.deployment.superseded.action",
	"errors.deployment.unknown_operation.action", "errors.deployment.recovery_exhausted.action",
	"errors.deployment.outcome_unknown.action", "errors.deployment.rollback_file_changed.action",
	"errors.deployment.rescan_needed.action", "email.deployment.superseded.body", "email.deployment.pending_change_restored.body", "errors.deployment.pending_change_restored.action",
	// R61: the Windows texts of the same e-mails
	"email.deployment.superseded_windows.body", "email.deployment.pending_change_restored_windows.body",
}

// Every text that names the control names it the same way in both languages, and no other text does.
func TestDiscoverIsNamedConsistently(t *testing.T) {
	en := map[string]string{}
	tr := map[string]string{}
	for lang, dst := range map[string]map[string]string{"en": en, "tr": tr} {
		raw, err := locales.FS.ReadFile("common/" + lang + ".json")
		require.NoError(t, err)
		flat, err := i18n.Flatten(raw)
		require.NoError(t, err)
		for k, v := range flat {
			dst[k] = v
		}
	}
	var got []string
	for k, v := range en {
		if strings.Contains(v, "Discover") {
			got = append(got, k)
			assert.Contains(t, tr[k], "Keşfet", k)
		}
	}
	for k, v := range tr {
		if strings.Contains(v, "Keşfet") {
			assert.Contains(t, en[k], "Discover", k)
		}
	}
	assert.ElementsMatch(t, discoverKeys, got)
}

// quotedTitle is a quoted error title followed by its code in the troubleshooting guide, for example
// "Alice already has this certificate with its key." (`ALC-CRT-0008`).
var quotedTitle = regexp.MustCompile("\"([^\"]+)\"\\s*\\(`(ALC-(?:NGX|CRT|DEP)-[0-9]{4})`\\)")

// Every Phase 4 error title the troubleshooting guide quotes is the catalogue's English title (a
// placeholder such as {{port}} stands for any word; the final period may be left out).
func TestTroubleshootingQuotesTheRealTitles(t *testing.T) {
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	reasons := map[string]string{}
	for _, ec := range phase4Codes() {
		reasons[ec.Code] = ec.Reason
	}
	matches := quotedTitle.FindAllStringSubmatch(string(doc), -1)
	require.NotEmpty(t, matches)
	for _, m := range matches {
		quote := strings.Join(strings.Fields(m[1]), " ")
		reason, ok := reasons[m[2]]
		if !assert.True(t, ok, "%s is not a Phase 4 code", m[2]) {
			continue
		}
		title := cat.T("en", "errors."+reason+".title", nil)
		pattern := regexp.MustCompile(`\\\{\\\{[a-z_]+\\}\\}`).ReplaceAllString(regexp.QuoteMeta(strings.TrimSuffix(title, ".")), `\S+`)
		assert.Regexp(t, "^"+pattern+`\.?$`, quote, "%s: the guide quotes %q, the title is %q", m[2], quote, title)
	}
}

// phase5Codes are the codes added for Phase 5 (area AKV).
func phase5Codes() []ErrorCode {
	var out []ErrorCode
	for _, ec := range AllErrorCodes() {
		if strings.HasPrefix(ec.Code, "ALC-AKV-") {
			out = append(out, ec)
		}
	}
	return out
}

// phase5Table is the contract's table (ALC-AKV-0001..0027) with the English and Turkish titles it fixes,
// then the codes added after it (R40 candidates; their titles are this task's).
var phase5Table = []struct {
	code, reason, titleEN, titleTR string
	status                         int
	retryable                      bool
}{
	{"ALC-AKV-0001", "azure.auth_failed", "Azure sign-in refused", "Azure oturum açmayı reddetti", 502, false},
	{"ALC-AKV-0002", "azure.credentials_expired", "Azure sign-in secret expired", "Azure oturum açma gizli anahtarının süresi doldu", 502, false},
	{"ALC-AKV-0003", "azure.forbidden", "Missing permission in the vault", "Kasada eksik izin", 502, false},
	{"ALC-AKV-0004", "azure.firewall", "Vault firewall blocks Alice", "Kasanın güvenlik duvarı Alice'i engelliyor", 502, false},
	{"ALC-AKV-0005", "azure.vault_not_found", "Vault not found", "Kasa bulunamadı", 502, false},
	{"ALC-AKV-0006", "azure.unreachable", "Cannot reach Azure", "Azure'a ulaşılamıyor", 502, true},
	{"ALC-AKV-0007", "azure.throttled", "Azure asked Alice to slow down", "Azure, Alice'ten yavaşlamasını istedi", 503, true},
	{"ALC-AKV-0008", "azure.unexpected_response", "Unexpected answer from Azure", "Azure'dan beklenmeyen yanıt", 502, true},
	{"ALC-AKV-0009", "azure.clock_skew", "Server clock rejected by Azure", "Sunucu saati Azure tarafından reddedildi", 502, false},
	{"ALC-AKV-0010", "azure.managed_identity_unavailable", "Managed identity not available", "Yönetilen kimlik kullanılamıyor", 502, false},
	{"ALC-AKV-0011", "azure.address_not_allowed", "Azure address not allowed", "Azure adresine izin verilmiyor", 502, false},
	{"ALC-AKV-0012", "azure.tls_untrusted", "Azure's certificate is not trusted", "Azure sertifikasına güvenilmiyor", 502, false},
	{"ALC-AKV-0013", "kv.not_exportable", "Private key not exportable", "Özel anahtar dışa aktarılamıyor", 422, false},
	{"ALC-AKV-0014", "kv.version_disabled", "Version disabled in Key Vault", "Sürüm Key Vault'ta devre dışı", 409, false},
	{"ALC-AKV-0015", "kv.certificate_not_found", "Certificate no longer in the vault", "Sertifika artık kasada yok", 409, false},
	{"ALC-AKV-0016", "kv.secret_unreadable", "Certificate data could not be read", "Sertifika verileri okunamadı", 502, false},
	{"ALC-AKV-0017", "kv.secret_mismatch", "Vault data does not match the version", "Kasa verileri sürümle eşleşmiyor", 502, false},
	{"ALC-AKV-0018", "kv.location_bound", "Website already connected", "Web sitesi zaten bağlı", 409, false},
	{"ALC-AKV-0019", "kv.binding_exists", "Certificate already connected", "Sertifika zaten bağlı", 409, false},
	{"ALC-AKV-0020", "kv.vault_has_bindings", "Vault still has connected websites", "Kasada hâlâ bağlı web siteleri var", 409, false},
	{"ALC-AKV-0021", "kv.version_not_deployable", "Version cannot be deployed", "Sürüm dağıtılamaz", 409, false},
	{"ALC-AKV-0022", "kv.held_needs_admin", "An administrator must deploy this version", "Bu sürümü bir yönetici dağıtmalı", 403, false},
	{"ALC-AKV-0023", "kv.import_confirm_needed", "Name already used in the vault", "Ad kasada zaten kullanılıyor", 409, false},
	{"ALC-AKV-0024", "kv.import_in_progress", "Import already running", "İçe aktarma zaten sürüyor", 409, true},
	{"ALC-AKV-0025", "kv.import_rejected", "Key Vault refused the import", "Key Vault içe aktarmayı reddetti", 502, false},
	{"ALC-AKV-0026", "kv.import_outcome_unknown", "Import outcome unknown", "İçe aktarmanın sonucu bilinmiyor", 502, false},
	{"ALC-AKV-0027", "kv.client_certificate_invalid", "Sign-in certificate not usable", "Oturum açma sertifikası kullanılamıyor", 422, false},
	{"ALC-AKV-0028", "kv.vault_duplicate", "Vault already added", "Kasa zaten eklenmiş", 409, false},
	{"ALC-AKV-0029", "kv.import_name_exists", "A certificate with this name exists in the vault", "Bu ada sahip bir sertifika kasada var", 409, false},
	{"ALC-AKV-0030", "kv.import_invalid", "Certificate cannot be imported", "Sertifika içe aktarılamıyor", 422, false},
	{"ALC-AKV-0031", "kv.binding_gone", "Website is no longer connected", "Web sitesinin bağlantısı kaldırıldı", 409, false},
	{"ALC-AKV-0032", "kv.auto_deploy_off", "Automatic deployment was switched off", "Otomatik dağıtım kapatıldı", 409, false},
	{"ALC-AKV-0033", "kv.vault_unavailable", "Vault is disabled or removed", "Kasa devre dışı ya da kaldırılmış", 409, false},
	{"ALC-AKV-0034", "kv.version_held", "Version is held", "Sürüm bekletiliyor", 409, false},
	{"ALC-AKV-0035", "kv.version_not_held", "Version is not held", "Sürüm bekletilmiyor", 409, false},
	{"ALC-AKV-0036", "kv.version_superseded", "A newer version replaced this one", "Daha yeni bir sürüm bunun yerini aldı", 409, false},
	{"ALC-AKV-0037", "kv.wave_stopped", "Automatic deployment of this version was stopped", "Bu sürümün otomatik dağıtımı durduruldu", 409, false},
	{"ALC-AKV-0038", "kv.import_vault_deleted", "Vault was removed before the import was sent", "Kasa, içe aktarma gönderilmeden önce kaldırıldı", 409, false},
	{"ALC-AKV-0039", "kv.import_cancelled", "Import cancelled before it was sent", "İçe aktarma gönderilmeden önce iptal edildi", 409, false},
	{"ALC-AKV-0040", "kv.import_admin_required", "The person who requested the import is no longer an administrator", "İçe aktarmayı isteyen kişi artık yönetici değil", 403, false},
	{"ALC-AKV-0041", "kv.credential_unreadable", "Alice cannot read this vault's stored credentials", "Alice bu kasanın kayıtlı kimlik bilgilerini okuyamıyor", 409, false},
}

// The 27 codes of the contract keep their numbers, reasons, statuses, retry flags and exact titles; the
// codes after them are numbered in order and none is renumbered.
func TestPhase5CodeTable(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	got := phase5Codes()
	require.Len(t, got, len(phase5Table))
	for i, row := range phase5Table {
		ec := got[i]
		assert.Equal(t, row.code, ec.Code)
		assert.Equal(t, row.reason, ec.Reason, row.code)
		assert.Equal(t, row.status, ec.Status, row.code)
		assert.Equal(t, row.retryable, ec.Retryable, row.code)
		assert.Equal(t, row.titleEN, cat.T("en", "errors."+ec.Reason+".title", nil), row.code)
		assert.Equal(t, row.titleTR, cat.T("tr", "errors."+ec.Reason+".title", nil), row.code)
		assert.Equal(t, ec, codeForReason(row.reason), row.code)
		assert.Equal(t, fmt.Sprintf("ALC-AKV-%04d", i+1), ec.Code, "numbers run without a gap")
	}
}

// Every placeholder of a Phase 5 text is a param the API lets through, EN and TR use the same ones, and no
// placeholder carries a suffix.
func TestPhase5TextPlaceholdersAreAllowlisted(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for _, ec := range phase5Codes() {
		for _, part := range []string{"title", "cause", "action"} {
			key := "errors." + ec.Reason + "." + part
			en, tr := cat.T("en", key, nil), cat.T("tr", key, nil)
			enP, trP := placeholderRE.FindAllStringSubmatch(en, -1), placeholderRE.FindAllStringSubmatch(tr, -1)
			assert.Len(t, trP, len(enP), key)
			for _, m := range append(enP, trP...) {
				assert.True(t, providerParamKeys[m[1]], "%s uses {{%s}}, which the API never lets through", key, m[1])
			}
			assert.NotRegexp(t, `\}\}[\p{L}'’]`, tr, "%s: a suffix attached to a placeholder", key)
			assert.NotContains(t, en, "  ", key)
		}
	}
}

// What each producer puts in the params of a Phase 5 code (the contract's table and the provider's closed table).
var phase5Params = map[string]map[string]string{
	"azure.auth_failed":         {"aadsts": "7000215", "reason": "tenant_mismatch", "azure_request_id": "0192b000-0000-7000-8000-0000000000a1", "azure_code": "InvalidAuthenticationToken"},
	"azure.credentials_expired": {"aadsts": "7000222"},
	"azure.clock_skew":          {"aadsts": "700024"},
	"azure.forbidden":           {"role": "Key Vault Secrets User", "model": "rbac", "azure_code": "ForbiddenByRbac"},
	"azure.firewall":            {"client_address": "203.0.113.7"},
	"kv.import_rejected":        {"azure_code": "BadParameter", "azure_request_id": "0192b000-0000-7000-8000-0000000000a1"},
	"kv.import_confirm_needed":  {"certificate_name": "web-cert"},
	"kv.location_bound":         {"location_id": "0192b000-0000-7000-8000-0000000000a1"},
}

// Binding requirement: every Phase 5 text renders without a leftover placeholder with the params its source
// provides, through the API's own paths: classify (request refusals and provider errors), deploymentError
// (stored deployment errors), jobJSON (stored job errors) and the vault's last error.
func TestPhase5TextsRenderWithTheirParams(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for _, ec := range phase5Codes() {
		params := phase5Params[ec.Reason]
		got, p, ok := classify(providers.NewError(ec.Reason, ec.Retryable, errors.New("cause"), params))
		require.True(t, ok, ec.Code)
		assert.Equal(t, ec, got)
		renderAll(t, cat, got, p, "a provider error")
		for k := range p {
			assert.Contains(t, params, k)
		}
		dto := deploymentError(inventory.Deployment{ErrorCode: ec.Reason, ErrorParams: params})
		require.NotNil(t, dto)
		renderAll(t, cat, codeForReason(dto.Reason), dto.Params, "a deployment")
		j := jobJSON(jobs.View{LastErrorCode: ec.Reason, ErrorParams: params})
		renderAll(t, cat, codeForReason(j.Error.Reason), j.Error.Params, "a job")
		// A stored reason without params (a vault's last error, an old record) still renders completely.
		ref := errorRef(ec.Reason, nil)
		require.NotNil(t, ref)
		renderAll(t, cat, codeForReason(ref.Reason), ref.Params, "a record without params")
	}
	// No rendered message may contain a raw placeholder, whatever params the source had: none, or only some.
	for _, ec := range phase5Codes() {
		sets := []map[string]string{nil, {}, {"reason": "x"}}
		for k := range phase5Params[ec.Reason] {
			sets = append(sets, map[string]string{k: phase5Params[ec.Reason][k]})
		}
		for _, params := range sets {
			got, p, ok := classify(providers.NewError(ec.Reason, ec.Retryable, errors.New("cause"), params))
			require.True(t, ok, ec.Code)
			renderAll(t, cat, got, p, "a provider error with partial params")
		}
	}
	got, p, ok := classify(providers.NewError("azure.forbidden", false, errors.New("cause"), nil))
	require.True(t, ok)
	assert.Equal(t, ErrAzureForbidden, got)
	assert.Equal(t, "Key Vault Reader", p["role"], "a request-path forbidden answer names a role")
}

// Every Phase 5 code is in the troubleshooting guide with its reason, cause and remedy.
func TestPhase5CodesHaveTroubleshootingSections(t *testing.T) {
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for _, ec := range phase5Codes() {
		title := cat.T("en", "errors."+ec.Reason+".title", nil)
		assert.Contains(t, string(doc), "\n## "+ec.Code+": "+title+"\n", ec.Code)
		assert.Regexp(t, regexp.MustCompile(`(?m)^## `+ec.Code+`: .+\n\n\*\*Meaning\.\*\* .*\(HTTP `+strconv.Itoa(ec.Status)+`, reason `+"`"+regexp.QuoteMeta(ec.Reason)+"`"), string(doc), ec.Code)
		section := troubleshootingSection(string(doc), ec.Code)
		assert.Regexp(t, `(?m)^\*\*Likely cause\.\*\* \S`, section, ec.Code)
		assert.Regexp(t, `(?m)^\*\*What to do\.\*\* \S`, section, ec.Code)
	}
	// F-41 and the roles: the guide names the three roles untranslated, with the commands to assign them.
	section := troubleshootingSection(string(doc), "ALC-AKV-0003")
	for _, role := range []string{"Key Vault Reader", "Key Vault Secrets User", "Key Vault Certificates Officer"} {
		assert.Contains(t, section, role)
	}
	assert.Contains(t, section, "az role assignment create")
}

// The texts say what the code does (binding wording requirements of the controller's rulings).
func TestPhase5TextsAreTruthfulAndWorded(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	en := func(key string) string { return cat.T("en", key, nil) }
	tr := func(key string) string { return cat.T("tr", key, nil) }
	// azure.address_not_allowed is also what a region or SDK-logging variable produces: say so, by name, in both languages.
	for _, text := range []string{en("errors.azure.address_not_allowed.cause") + en("errors.azure.address_not_allowed.action"),
		tr("errors.azure.address_not_allowed.cause") + tr("errors.azure.address_not_allowed.action")} {
		for _, name := range []string{"AZURE_REGIONAL_AUTHORITY_NAME", "MSAL_FORCE_REGION", "AZURE_SDK_GO_LOGGING"} {
			assert.Contains(t, text, name)
		}
	}
	assert.Contains(t, en("errors.azure.address_not_allowed.cause"), "region")
	assert.Contains(t, en("errors.azure.address_not_allowed.cause"), "SDK-logging")
	// The duplicate message names the vault first and says it can be a vault or a server that has the name
	// (names are unique across both): the EN and TR texts say so.
	assert.Contains(t, en("errors.kv.vault_duplicate.title"), "Vault")
	assert.Contains(t, tr("errors.kv.vault_duplicate.title"), "Kasa")
	assert.Contains(t, en("errors.kv.vault_duplicate.cause"), "a vault with this address")
	assert.Contains(t, en("errors.kv.vault_duplicate.action"), "vault or server")
	// The role is named from the param, in Azure's spelling, in both languages (F-41: "Alice needs the role").
	assert.Contains(t, cat.T("en", "errors.azure.forbidden.action", map[string]string{"role": "Key Vault Secrets User"}), "role Key Vault Secrets User")
	assert.Contains(t, cat.T("tr", "errors.azure.forbidden.action", map[string]string{"role": "Key Vault Secrets User"}), "Key Vault Secrets User rolünü")
	// "Key Vault" is the product's name in Turkish too; no translated role names; no jargon from the sign-in protocol.
	for _, ec := range phase5Codes() {
		for _, part := range []string{"title", "cause", "action"} {
			for lang, text := range map[string]string{"en": en("errors." + ec.Reason + "." + part), "tr": tr("errors." + ec.Reason + "." + part)} {
				for _, bad := range []string{"Anahtar Kasası", "Key Vault Okuyucu", "Key Vault Gizli", "Key Vault Sertifika Görevlisi", "AADSTS", "MSAL", "SDK"} {
					if ec.Reason == "azure.address_not_allowed" && (bad == "MSAL" || bad == "SDK") {
						continue
					}
					assert.NotContains(t, text, bad, "%s %s %s", ec.Code, lang, part)
				}
			}
		}
	}
	// Terminology of the contract's UI copy: Deploy now, Check now, Connected websites, Automatic deployment.
	assert.Contains(t, en("errors.kv.auto_deploy_off.action"), "Deploy now")
	assert.Contains(t, tr("errors.kv.auto_deploy_off.action"), "Şimdi dağıt")
	assert.Contains(t, en("errors.kv.secret_mismatch.action"), "Check now")
	assert.Contains(t, tr("errors.kv.secret_mismatch.action"), "Şimdi denetle")
	// Fix round 1 (I1): no advice that is false.
	for lang, text := range map[string]string{"en": en("errors.kv.auto_deploy_off.action"), "tr": tr("errors.kv.auto_deploy_off.action")} {
		assert.NotContains(t, text, "or switch automatic deployment on again", lang)
		assert.NotContains(t, text, "yeniden açın", lang)
		assert.Contains(t, text, map[string]string{"en": "only to versions Alice finds afterwards", "tr": "yalnızca Alice'in bundan sonra bulacağı"}[lang])
	}
	assert.NotContains(t, en("errors.kv.held_needs_admin.cause"), "expired")
	assert.NotContains(t, tr("errors.kv.held_needs_admin.cause"), "süresi dol")
	assert.Contains(t, en("errors.kv.vault_duplicate.cause"), "or server")
	assert.Contains(t, tr("errors.kv.vault_duplicate.cause"), "kasa veya sunucu")
	assert.NotContains(t, en("errors.kv.version_disabled.cause"), "expired")
	assert.NotContains(t, tr("errors.kv.version_disabled.cause"), "süresi dol")
	assert.NotContains(t, en("errors.kv.version_disabled.title"), "expired")
	assert.Contains(t, en("errors.kv.import_outcome_unknown.cause"), "no later check of the vault showed it")
	assert.Contains(t, en("errors.kv.import_invalid.cause"), "changed in Alice after the import was requested")
	assert.Contains(t, tr("errors.kv.import_invalid.cause"), "içe aktarma istendikten sonra Alice'te değişti")
	// Turkish names the action "içe aktarma", never a bare "aktarma" (the label "Key Vault'a aktar" is the button's).
	for _, ec := range phase5Codes() {
		if !strings.HasPrefix(ec.Reason, "kv.import_") {
			continue
		}
		for _, part := range []string{"title", "cause", "action"} {
			text := tr("errors." + ec.Reason + "." + part)
			for _, m := range regexp.MustCompile(`\p{L}*aktar\p{L}*`).FindAllStringIndex(text, -1) {
				before := text[:m[0]]
				assert.True(t, strings.HasSuffix(before, "içe ") || strings.HasSuffix(before, "İçe ") || strings.HasSuffix(before, "dışa "),
					"%s %s: a bare \"aktar\" in %q", ec.Code, part, text)
			}
		}
	}
	// The variables are described truthfully: logging prints Azure's answers, the region ones send sign-in elsewhere.
	cause := en("errors.azure.address_not_allowed.cause")
	assert.Contains(t, cause, "print Azure's answers")
	assert.NotContains(t, cause, "would send Azure traffic somewhere else")
	assert.Contains(t, en("errors.azure.address_not_allowed.action"), "restart Alice")
	assert.Contains(t, tr("errors.azure.address_not_allowed.action"), "yeniden başlat")
	assert.Equal(t, "Azure oturum açmayı reddetti", tr("errors.azure.auth_failed.title"))
	assert.Equal(t, "Kasanın güvenlik duvarı Alice'i engelliyor", tr("errors.azure.firewall.title"))
	assert.Equal(t, "Web sitesi sertifikayı izleyecekse onu yeniden bağlayın.", tr("errors.kv.binding_gone.action"))
	// Nothing was sent / changed where that is true.
	assert.Contains(t, en("errors.kv.secret_unreadable.cause"), "Nothing was changed on your servers")
	assert.Contains(t, en("errors.kv.import_invalid.cause"), "Nothing was sent")
	// The first deployment that meets a non-exportable key answers ALC-AKV-0016: its text covers that case and says
	// what Alice did (Monitor only) and what to do (a new version with an exportable key).
	for lang, want := range map[string][]string{"en": {"not exportable", "Monitor only", "Exportable private key"},
		"tr": {"dışa aktarılamaz", "Yalnızca izleme", "Dışa aktarılabilir özel anahtar"}} {
		text := cat.T(lang, "errors.kv.secret_unreadable.cause", nil) + " " + cat.T(lang, "errors.kv.secret_unreadable.action", nil)
		for _, w := range want {
			assert.Contains(t, text, w, lang)
		}
	}
	// A vault whose sealed credential cannot be opened: the way out is to replace the vault's credentials.
	assert.Contains(t, en("errors.kv.credential_unreadable.action"), "Replace credentials")
	assert.Contains(t, tr("errors.kv.credential_unreadable.action"), "Kimlik bilgilerini değiştir")
	assert.Contains(t, en("errors.kv.credential_unreadable.cause"), "Nothing was changed on your servers")
	// The mails point to screens and controls that exist (final review C-I3): the import history on the certificate's
	// page, and the "Removed from Key Vault" mark the vault page always shows.
	for _, lang := range []string{"en", "tr"} {
		body := func(key string) string { return cat.T(lang, key, map[string]string{"count": "3"}) }
		assert.Contains(t, body("email.kv.import_failed.body"), map[string]string{"en": "its import history", "tr": "içe aktarma geçmişi"}[lang])
		for _, key := range []string{"email.kv.certificates_removed_more.body", "email.kv.certificates_removed_more_one.body"} {
			// The chip's text in web/src/locales (kv.removed).
			assert.Contains(t, body(key), map[string]string{"en": "Removed from Key Vault", "tr": "Key Vault'tan kaldırıldı"}[lang], "%s %s names the mark", lang, key)
			assert.NotContains(t, body(key), map[string]string{"en": "choose to show", "tr": "göstermeyi seçin"}[lang])
		}
	}
	// C-M1/C-M2: the Monitor only mark is named as something to look for, and not-exportable names Alice's own mark.
	assert.Contains(t, en("errors.kv.secret_unreadable.action"), "If the certificate's page now shows Monitor only")
	assert.Contains(t, en("errors.kv.not_exportable.cause"), "returned it without its key")
	assert.Contains(t, tr("errors.kv.not_exportable.cause"), "anahtarı olmadan döndürdü")
	// certificate.pfx_busy also ends a Key Vault deployment's vault step, where nothing was uploaded (final review B M-3).
	for lang, words := range map[string][]string{"en": {"upload"}, "tr": {"yükle"}} {
		for _, part := range []string{"cause", "action"} {
			for _, w := range words {
				assert.NotContains(t, cat.T(lang, "errors.certificate.pfx_busy."+part, nil), w, lang)
			}
		}
	}
}

// The complete map of what the API answers for each Phase 5 sentinel (the task's report lists it).
func TestPhase5SentinelMapping(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want ErrorCode
	}{
		{inventory.ErrVaultHasBindings, ErrKVVaultHasBindings},
		{inventory.ErrNotAVault, ErrNotFound},
		{inventory.ErrNotAServer, ErrNotFound},
		{inventory.ErrClientCertificateInvalid, ErrKVClientCertInvalid},
		{inventory.ErrNotExportable, ErrKVNotExportable},
		{inventory.ErrVersionNotDeployable, ErrKVVersionNotDeployable},
		{inventory.ErrLocationBound, ErrKVLocationBound},
		{inventory.ErrBindingExists, ErrKVBindingExists},
		{inventory.ErrVersionDisabled, ErrKVVersionDisabled},
		{inventory.ErrKVCertificateMissing, ErrKVCertificateNotFound},
		{inventory.ErrHeldNeedsAdmin, ErrKVHeldNeedsAdmin},
		{inventory.ErrAdminRequired, ErrForbidden},
		{inventory.ErrVersionNotHeld, ErrKVVersionNotHeld},
		{inventory.ErrSecretUnreadable, ErrKVSecretUnreadable},
		{inventory.ErrSecretMismatch, ErrKVSecretMismatch},
		{inventory.ErrVaultCredentialUnreadable, ErrKVCredentialUnreadable},
		{inventory.ErrVaultUnavailable, ErrKVVaultUnavailable},
		{inventory.ErrImportConfirmNeeded, ErrKVImportConfirmNeeded},
		{inventory.ErrImportInProgress, ErrKVImportInProgress},
		{inventory.ErrHeldNeedsStepUp, ErrStepUpRequired},
		{inventory.ErrAutoDeployNeedsStepUp, ErrStepUpRequired},
	} {
		got, _, ok := classify(tc.err)
		require.True(t, ok, tc.err.Error())
		assert.Equal(t, tc.want, got, tc.err.Error())
	}
	// The typed errors carry their param; the location comes from fail (D23: location_id is not a provider param).
	_, p, ok := classify(&inventory.ImportConfirmError{CertificateName: "web-cert"})
	require.True(t, ok)
	assert.Equal(t, map[string]string{"certificate_name": "web-cert", "auto_deploy_follows": "false", "bound": "false"}, p)
	_, p, _ = classify(&inventory.ImportConfirmError{CertificateName: "web-cert", AutoDeploy: true, Bound: true})
	assert.Equal(t, "true", p["auto_deploy_follows"], "the dialog learns that automatic deployment will follow")
	assert.Equal(t, "true", p["bound"])
	_, p, _ = classify(&inventory.ImportConfirmError{CertificateName: "not a name {{x}}"})
	assert.NotContains(t, p, "certificate_name", "a name outside the grammar is never shown")
	assert.NotContains(t, providerParamRules, "location_id")
	assert.NotContains(t, providerParamKeys, "location_id")
}

// internal.unexpected from a provider is answered with the generic code (and logged), never with its text.
func TestInternalUnexpectedProviderErrorMapsToTheGenericCode(t *testing.T) {
	var logs bytes.Buffer
	d := testDeps(t, nil)
	d.Log = logging.New(&logs, slog.LevelDebug)
	s := newServer(d)
	perr := providers.NewError("internal.unexpected", false, errors.New("secret-canary-text"), map[string]string{"reason": "x"})
	ec, _, ok := classify(perr)
	require.True(t, ok)
	assert.Equal(t, ErrUnexpected, ec)
	rec := httptest.NewRecorder()
	s.fail(rec, httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil), perr)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, logs.String(), `"msg":"request failed"`)
	assert.NotContains(t, logs.String(), "secret-canary-text")
	assert.NotContains(t, rec.Body.String(), "secret-canary-text")
}

// The Phase 5 params pass only in their strict shapes; Azure's own text never gets through (S4).
func TestPhase5ParamsAreStrict(t *testing.T) {
	ok := map[string]string{
		"role": "Key Vault Reader", "model": "access_policy", "client_address": "2001:db8::1", "aadsts": "90002",
		"azure_code": "ForbiddenByFirewall", "azure_request_id": "0192B000-0000-7000-8000-0000000000A1", "certificate_name": "web-cert-1",
	}
	assert.Equal(t, ok, providerParams(ok))
	bad := map[string]string{
		"role": "Key Vault Administrator", "model": "other", "client_address": "999.1.1.1", "aadsts": "AADSTS7000215",
		"azure_code": "Forbidden by policy: Client address: 203.0.113.7", "azure_request_id": "not-a-guid", "certificate_name": "web cert",
		"message": "AADSTS7000215: Invalid client secret provided",
	}
	assert.Empty(t, providerParams(bad))
	for _, role := range []string{"Key Vault Secrets User", "Key Vault Certificates Officer"} {
		assert.Equal(t, map[string]string{"role": role}, providerParams(map[string]string{"role": role}))
	}
	assert.Empty(t, providerParams(map[string]string{"client_address": "1.2.3"}), "characters alone are not an address")
}

// ErrCredentialNotTheTargets can come out of ReplaceVaultCredentials (the database trigger refuses a credential that is
// not the target's) but only when Alice's own code is wrong: it answers the internal error on purpose and is logged
// with its type, never rendered.
func TestCredentialNotTheTargetsAnswersTheInternalError(t *testing.T) {
	var logs bytes.Buffer
	d := testDeps(t, nil)
	d.Log = logging.New(&logs, slog.LevelDebug)
	s := newServer(d)
	_, _, ok := classify(inventory.ErrCredentialNotTheTargets)
	assert.False(t, ok)
	rec := httptest.NewRecorder()
	s.fail(rec, httptest.NewRequest(http.MethodPut, "/api/v1/targets/x/vault-credentials", nil), inventory.ErrCredentialNotTheTargets)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, ErrUnexpected.Code, decodeErr(t, rec).Error.Code)
	assert.Contains(t, logs.String(), `"msg":"request failed"`)
}

// The revocation check's codes (R64, D5): stored reasons of a check, shown through errorRef; each equals the checker's
// closed code and has its English and Turkish texts.
func TestRevocationCheckCodeTable(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	for i, row := range []struct {
		ec     ErrorCode
		reason string
		status int
	}{
		{ErrCertRevocationUnreachable, revocation.CodeUnreachable, http.StatusBadGateway},
		{ErrCertRevocationInvalidAnswer, revocation.CodeInvalidAnswer, http.StatusBadGateway},
		{ErrCertRevocationAddressRefused, revocation.CodeAddressRefused, http.StatusUnprocessableEntity},
		{ErrCertRevocationNoIssuer, revocation.CodeNoIssuer, http.StatusUnprocessableEntity},
		{ErrCertRevocationNoAddress, revocation.CodeNoAddress, http.StatusUnprocessableEntity},
		{ErrCertRevocationTooLarge, revocation.CodeTooLarge, http.StatusBadGateway},
	} {
		assert.Equal(t, fmt.Sprintf("ALC-CRT-%04d", 20+i), row.ec.Code)
		assert.Equal(t, row.reason, row.ec.Reason)
		assert.Equal(t, row.status, row.ec.Status, row.ec.Code)
		assert.Equal(t, row.ec, codeForReason(row.reason), "registered")
		for _, lang := range []string{"en", "tr"} {
			for _, part := range []string{"title", "cause", "action"} {
				key := "errors." + row.reason + "." + part
				assert.NotEqual(t, key, cat.T(lang, key, nil), "%s %s", lang, key)
			}
		}
	}
	ec, _, ok := classify(inventory.ErrRevocationSettingsVersion)
	require.True(t, ok)
	assert.Equal(t, ErrPreconditionFailed, ec)
}
