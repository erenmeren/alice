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
	"ErrClaimLost": inventory.ErrClaimLost, "ErrCSRBusy": inventory.ErrCSRBusy, "ErrTooManyPendingCSRs": inventory.ErrTooManyPendingCSRs,
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
	"errors.nginx.config_invalid.action", "errors.nginx.config_changed.action", "errors.nginx.file_changed.action",
	"errors.nginx.location_unsupported.action", "errors.deployment.verify_other.action", "errors.deployment.superseded.action",
	"errors.deployment.unknown_operation.action", "errors.deployment.recovery_exhausted.action",
	"errors.deployment.outcome_unknown.action", "errors.deployment.rollback_file_changed.action",
	"errors.deployment.rescan_needed.action", "email.deployment.superseded.body", "errors.deployment.pending_change_restored.action",
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
