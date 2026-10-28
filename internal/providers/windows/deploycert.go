package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"slices"
	"strconv"

	"github.com/google/uuid"

	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
)

// Reasons of a deployment besides mapHelper's and the verification's.
const (
	reasonInvalidCertificate = "certificate.invalid" // the chain or key cannot be sent (no certificate, not ASCII PEM text, too large)
)

// deployedClasses are the error classes of the helper's own restore after a failed step, with the
// reason the rolled-back outcome carries (W2 Rulings 6, 10).
var deployedClasses = map[string]string{
	winproto.ErrKeyUnusable: ReasonKeyUnusable,     // http.sys's 1312 at the bind, or the import's key
	winproto.ErrStore:       ReasonStoreError,      // an import into a store failed
	winproto.ErrReadBack:    reasonInterrupted,     // the record read back differs from what was written
	winproto.ErrIO:          ReasonIOError,         // the update failed, or the committed journal could not be written
	winproto.ErrKeyACL:      ReasonRDPKeyACLFailed, // rdp-deploy's grant_key_read failed, the listener untouched (W6 Ruling 9)
}

// DeployCertificate deploys a certificate and its key to an http.sys SSL binding in one helper
// transaction (iis-deploy: intermediates into CA, the certificate with a non-exportable machine key
// into the binding's store, one whole-record update that changes only the hash, read back, journal),
// verifies that the endpoints serve the new certificate (VerifyDeployment, the served chain compared
// with what the helper built: W2 Ruling 16) and, when they do not, restores the previous certificate
// right away (iis-restore of the same operation, under the guard read again) and verifies that the
// previous certificate is served again. It mirrors the Nginx provider's DeployCertificate; every return
// is a legal shape (providers.CheckDeployReturn; TestDeployOutcomeTable has a row for each):
//
//   - a refusal before anything was sent (closed session, a location that is not a supported
//     win_sslbinding or whose locator Alice does not deploy to (W2 Ruling 5: windows.location_unsupported),
//     a chain without a certificate or a pair that cannot be sent (certificate.invalid), a fingerprint
//     that is not the chain's leaf, no operation id or token, a guard the helper would refuse
//     (internal.unexpected), a helper below 0.2.0 (windows.helper_outdated), a context ended before the
//     send) and every well-formed helper refusal of deployRefusals but OPERATION_EXISTS: DeployNoChange
//     with a *providers.Error and no phase or steps;
//   - committed or unchanged and verified: DeployCommitted / DeployUnchanged, Verified and Trust the
//     verification's (R51 level by Verified and Trust); unchanged and not verified: DeployNoChange,
//     Phase unchanged, FailedStep verify, a *providers.Error;
//   - the helper's own restore after a failed step (restored: failed_step = cause_step = the step,
//     reason by the class: windows.key_unusable, windows.store_error, deployment.interrupted for a
//     read-back that differed, windows.io_error), then the previous certificate verified (verify_old):
//     DeployRolledBack, or DeployRollbackFailed when another certificate is served;
//   - the helper's restore_forbidden (R48): rollback_failed deployment.rollback_forbidden; its
//     restore_failed: rollback_failed with the reason of its class;
//   - a failed verification of a committed deployment: the inline rollback (rollBack), whose outcome is
//     rolled_back with the verification's reason, rollback_failed, or uncertain with the verification's
//     reason and Params["failed_step"] = verify;
//   - anything else, OUTCOME_UNKNOWN and OPERATION_EXISTS among them (an earlier send of the same
//     operation may have changed the binding): DeployUncertain with a non-nil error and no Phase,
//     FailedStep, CauseStep or Error; the engine reads DeploymentStatus.
//
// Backup is BackupRef{OperationID, Store, PreviousSHA1, PreviousSHA256} (W2 Ruling 17): from the
// location's details and the request's token before an answer, from the helper's answer after one.
//
// A win_ccs_file location (W5, R68) takes the same table through ccs-deploy (deployCCS): its steps are
// import_chain and write_file, its refusals add the CCS codes (windows.ccs_*, a folder Alice does not
// manage windows.location_unsupported), the CCS password goes on standard input with the key, and its
// Backup stays BackupRef{OperationID, PreviousSHA256} (W5 Ruling 21).
//
// The win_rdp location (W6, R69) takes the same table through rdp-deploy (deployRDP): its steps are import_chain,
// import_certificate, grant_key_read and set_listener, its refusals add windows.rdp_disabled and windows.rdp_tls_off,
// a failed grant is rolled back windows.rdp_key_acl_failed, and its Backup names the previous certificate's own store
// (My, or Remote Desktop for the self-signed certificate: W6 Ruling 19).
//
// The private key goes from req.PrivateKeyPEM into the input JSON (built by hand, without a string copy
// of the key) and from there only onto the command's standard input: the command line is exactly
// "iis-deploy --op <id>" (W2 Ruling 4). Both buffers are cleared after the send; a command is never kept
// or re-sent.
func (s *session) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	d := deployment{s: s, req: req, log: log, sub: winproto.SubIISDeploy, out: providers.DeployOutcome{Backup: requestBackup(req)}}
	if !s.caps.Has(providers.CapDeployCertificate) {
		return providers.DeployOutcome{}, providers.ErrUnsupported
	}
	if err := s.open(); err != nil {
		return d.refuse(asProviderError(err))
	}
	var (
		loc winproto.Locator
		cl  ccsLocator
		ok  bool
	)
	switch req.Location.Kind {
	case providers.LocationWinSSLBinding:
		loc, ok = locatorOf(req.Location)
	case providers.LocationWinCCSFile:
		cl, ok = ccsLocatorOf(req.Location)
		d.sub = winproto.SubCCSDeploy
	case providers.LocationWinRDP:
		ok = rdpPortOf(req.Location) != 0
		d.sub = winproto.SubRDPDeploy
	}
	if !req.Location.Supported || !ok {
		return d.refuse(providers.NewError(ReasonLocationUnsupported, false, nil, nil))
	}
	leaf, ok := leafFingerprint(req.CertificatePEM)
	switch {
	case !ok:
		return d.refuse(providers.NewError(reasonInvalidCertificate, false, nil, nil))
	case req.Fingerprint != "" && req.Fingerprint != leaf:
		return d.refuse(providers.NewError(reasonUnexpected, false, errors.New("windows: the fingerprint is not the chain's leaf"), nil))
	case req.OperationID == uuid.Nil || !isHexSHA256(req.ExpectCertSHA256):
		return d.refuse(providers.NewError(reasonUnexpected, false, errors.New("windows: a deployment needs an operation id and the binding's token"), nil))
	case !validGuard(req.Guard):
		return d.refuse(providers.NewError(reasonUnexpected, false, errors.New("windows: the rollback guard is not a list the helper takes"), nil))
	case !req.Guard.SatisfiedBy(s.p.RollbackTraits(), guardsRollback):
		return d.refuse(providers.NewError(reasonUnexpected, false, errors.New("windows: the rollback guard cannot be satisfied"), nil))
	}
	d.fingerprint = leaf
	if err := s.writeReady(); err != nil {
		return d.refuse(asProviderError(err))
	}
	switch d.sub {
	case winproto.SubCCSDeploy:
		return d.deployCCS(ctx, cl)
	case winproto.SubRDPDeploy:
		return d.deployRDP(ctx)
	}
	input, ok := deployInput(loc, req.ExpectCertSHA256, req.CertificatePEM, req.PrivateKeyPEM.Bytes(), req.Guard)
	defer clear(input)
	if inputHook != nil {
		inputHook(input)
	}
	if !ok || len(input) > winproto.MaxDeployInput {
		return d.refuse(providers.NewError(reasonInvalidCertificate, false, nil, nil))
	}
	c := runWrite[winproto.DeployResponse](ctx, s, winproto.SubIISDeploy, input, deployRefusals, winproto.ArgOp, req.OperationID.String())
	clear(input)
	return d.sent(ctx, c)
}

// sent maps a sent iis-deploy or ccs-deploy: uncertain, OPERATION_EXISTS (uncertain), another refusal, or the answer.
func (d *deployment) sent(ctx context.Context, c writeCall[winproto.DeployResponse]) (providers.DeployOutcome, error) {
	switch {
	case c.uncertain != nil:
		return d.uncertain(c.uncertain)
	case c.refusal != nil && c.code == winproto.CodeOperationExists:
		// The helper knows this operation: an earlier send may have changed the binding (the
		// journal decides, not this refusal).
		return d.uncertain(c.refusal)
	case c.refusal != nil:
		return d.refuse(c.refusal)
	}
	return d.answer(ctx, c.answer)
}

// inputHook, when set, sees the deployment input buffer (a test seam: TestDeployKeyIsNeverOutsideStdin
// checks the buffer is cleared after the send; nil in production).
var inputHook func([]byte)

// requestBackup is the deployment's BackupRef before the helper answered: the previous certificate as
// the request names it (the location's store and thumbprint, the token), each only when well-formed.
func requestBackup(req providers.DeployRequest) providers.BackupRef {
	b := providers.BackupRef{OperationID: req.OperationID}
	p := backupParams(providers.BackupRef{}, req.Location)
	b.Store, b.PreviousSHA1 = p["store"], p["previous_sha1"]
	if isHexSHA256(req.ExpectCertSHA256) {
		b.PreviousSHA256 = req.ExpectCertSHA256
	}
	return b
}

// leafFingerprint is the hex SHA-256 of the DER of the chain's first CERTIFICATE block; ok is false
// when there is none.
func leafFingerprint(p []byte) (string, bool) {
	for rest := p; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return "", false
		}
		if b.Type == "CERTIFICATE" {
			sum := sha256.Sum256(b.Bytes)
			return hex.EncodeToString(sum[:]), true
		}
	}
}

// chainLength counts the CERTIFICATE blocks of a PEM chain.
func chainLength(p []byte) int {
	n := 0
	for rest := p; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return n
		}
		if b.Type == "CERTIFICATE" {
			n++
		}
	}
}

// deployInput is the JSON of winproto.DeployInput, built in one allocation of its final size and
// without a string copy of the key (a Go string cannot be wiped; json.Marshal of the struct would make
// one and grow buffers it leaves behind). The caller clears it. Both forbidden lists are always present
// (empty arrays for none): the helper requires them and checks them on every restore (W2 Ruling 11).
// ok is false for an empty or non-ASCII PEM text (the helper would refuse it as BAD_CONTENT).
func deployInput(loc winproto.Locator, expect string, chain, key []byte, g providers.RollbackGuard) ([]byte, bool) {
	cn, ok1 := jsonStringLen(chain)
	kn, ok2 := jsonStringLen(key)
	if !ok1 || !ok2 || len(chain) == 0 || len(key) == 0 {
		return nil, false
	}
	locJSON, _ := json.Marshal(loc) // strings and an int: cannot fail
	spki, _ := json.Marshal(nonNil(g.ForbiddenSPKI))
	leaves, _ := json.Marshal(nonNil(g.ForbiddenLeaf))
	const (
		head = `{"locator":`
		exp  = `,"expect_sha256":`
		ch   = `,"chain_pem":`
		ky   = `,"key_pem":`
		fs   = `,"forbidden_spki_sha256":`
		fl   = `,"forbidden_leaf_sha256":`
		tail = `}`
	)
	n := len(head) + len(locJSON) + len(exp) + len(expect) + 2 + len(ch) + cn + len(ky) + kn + len(fs) + len(spki) + len(fl) + len(leaves) + len(tail)
	out := make([]byte, 0, n)
	out = append(out, head...)
	out = append(out, locJSON...)
	out = append(out, exp...)
	out = strconv.AppendQuote(out, expect) // hex digits
	out = append(out, ch...)
	out = appendJSONString(out, chain)
	out = append(out, ky...)
	out = appendJSONString(out, key)
	out = append(out, fs...)
	out = append(out, spki...)
	out = append(out, fl...)
	out = append(out, leaves...)
	return append(out, tail...), true
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

const hexDigits = "0123456789abcdef"

// jsonStringLen is the length of b as a JSON string literal (quotes included); ok is false for a byte
// outside ASCII.
func jsonStringLen(b []byte) (int, bool) {
	n := 2
	for _, c := range b {
		switch {
		case c >= 0x80:
			return 0, false
		case c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t':
			n += 2
		case c < 0x20:
			n += 6
		default:
			n++
		}
	}
	return n, true
}

// appendJSONString appends b (ASCII, see jsonStringLen) as a JSON string literal.
func appendJSONString(dst, b []byte) []byte {
	dst = append(dst, '"')
	for _, c := range b {
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}

// deployment is one DeployCertificate call while it maps the helper's answers.
type deployment struct {
	s           *session
	req         providers.DeployRequest
	fingerprint string // the leaf of req.CertificatePEM (hex SHA-256)
	sub         string // iis-deploy, or ccs-deploy for a CCS file
	log         providers.StepLogger
	out         providers.DeployOutcome
}

// refuse is DeployNoChange for a refusal: nothing changed, no phase and no steps.
func (d *deployment) refuse(e *providers.Error) (providers.DeployOutcome, error) {
	return providers.DeployOutcome{Result: providers.DeployNoChange, Reason: e.Code, Params: maps.Clone(e.Params), Backup: d.out.Backup}, e
}

// uncertain is DeployUncertain: the steps known so far are kept; phase, failed and cause step and error
// class are cleared (the caller reads DeploymentStatus).
func (d *deployment) uncertain(err error) (providers.DeployOutcome, error) {
	return providers.DeployOutcome{Result: providers.DeployUncertain, Steps: d.out.Steps, Backup: d.out.Backup}, err
}

// uncertainAfterVerify is DeployUncertain after the new certificate's verification failed: Reason and
// Params say why (its reason and port), Params["failed_step"] = verify that it had failed before the
// outcome became uncertain (the journal may still read committed; the engine verifies again).
func (d *deployment) uncertainAfterVerify(reason string, params map[string]string, err error) (providers.DeployOutcome, error) {
	o, err := d.uncertain(err)
	o.Reason, o.Params = reason, maps.Clone(params)
	if o.Params == nil {
		o.Params = map[string]string{}
	}
	o.Params["failed_step"] = providers.StepNameVerify
	return o, err
}

// backupParams are the params of a rollback failure: the previous certificate of the outcome's backup.
func (d *deployment) backupParams() map[string]string {
	return backupParams(d.out.Backup, providers.CertLocation{})
}

// identity checks the answer's names of the new and the previous certificate against the request (the
// new leaf, the token) and the protocol (thumbprints, store, the built chain's bound) and takes them
// into the backup.
//
// A CCS file's answer names no store and no import (W5 Ruling 14), and its backup stays BackupRef{OperationID,
// PreviousSHA256} (Ruling 21: the helper's journal names the backup file).
func (d *deployment) identity(a winproto.DeployResponse) bool {
	ccs := d.sub == winproto.SubCCSDeploy
	store := winproto.ValidStore(a.Store)
	if ccs {
		store = a.Store == "" && !a.AliceImported
	}
	if a.NewSHA256 != d.fingerprint || a.PreviousSHA256 != d.req.ExpectCertSHA256 || !winproto.ValidSHA1(a.NewSHA1) ||
		!winproto.ValidSHA1(a.PreviousSHA1) || !store || a.BuiltChainLength < 0 || a.BuiltChainLength > winproto.MaxChainCerts+1 {
		return false
	}
	switch {
	case ccs:
	case d.sub == winproto.SubRDPDeploy:
		// The answer's store is the import's (My, Ruling 6): the previous certificate's is the location's, kept only
		// while the location names the certificate the helper replaced.
		if d.out.Backup.PreviousSHA1 != a.PreviousSHA1 {
			d.out.Backup.Store = ""
		}
		d.out.Backup.PreviousSHA1, d.out.Backup.PreviousSHA256 = a.PreviousSHA1, a.PreviousSHA256
	default:
		d.out.Backup.Store, d.out.Backup.PreviousSHA1, d.out.Backup.PreviousSHA256 = a.Store, a.PreviousSHA1, a.PreviousSHA256
	}
	return true
}

// answer maps a completed iis-deploy or ccs-deploy (exit 0) by its phase (the table of DeployCertificate).
func (d *deployment) answer(ctx context.Context, a winproto.DeployResponse) (providers.DeployOutcome, error) {
	sub := d.sub
	steps, ok := toSteps(a.Steps)
	switch {
	case !ok:
		return d.uncertain(protocolError(sub, "steps outside the helper's vocabulary"))
	case !d.identity(a):
		return d.uncertain(protocolError(sub, "an answer naming other certificates than the deployment's"))
	}
	switch a.Phase {
	case winproto.PhaseCommitted, winproto.PhaseUnchanged:
		if a.FailedStep != "" || a.CauseStep != "" || a.Error != "" || anyFailed(steps) {
			return d.uncertain(protocolError(sub, "a successful phase with a failure"))
		}
		d.out.Steps = steps
		logSteps(d.log, steps, refreshedStep(a.CCSRefreshFailed, winproto.StepWriteFile), aclLeftStep(a.RDPKeyACLLeft, steps))
		return d.verifyNew(ctx, a.Phase, a.BuiltChainLength)
	case winproto.PhaseRestored:
		// The helper restored the record itself (or never changed it) after the step that failed.
		reason, known := deployedClasses[a.Error]
		if !slices.Contains(causeSteps, a.FailedStep) || a.CauseStep != a.FailedStep || !known {
			return d.uncertain(protocolError(sub, "a restored answer without the step that failed"))
		}
		d.out.Steps = steps
		logSteps(d.log, steps, refreshedStep(a.CCSRefreshFailed, winproto.StepWriteFile), aclLeftStep(a.RDPKeyACLLeft, steps))
		d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
			providers.DeployRolledBack, providers.PhaseRestored, a.FailedStep, a.CauseStep, a.Error
		d.out.Reason = reason
		return d.verifyOld(ctx)
	case winproto.PhaseRestoreForbidden:
		if !forbiddenShape(a.FailedStep, a.CauseStep, a.Error) || a.CauseStep == "" {
			return d.uncertain(protocolError(sub, "a restore_forbidden answer outside the helper's contract"))
		}
		d.out.Steps = steps
		logSteps(d.log, steps, refreshedStep(a.CCSRefreshFailed, winproto.StepWriteFile), aclLeftStep(a.RDPKeyACLLeft, steps))
		return d.forbidden(providers.PhaseRestoreForbidden, a.CauseStep)
	case winproto.PhaseRestoreFailed:
		if !restoreFailedShape(a.FailedStep, a.CauseStep, a.Error) || a.CauseStep == "" {
			return d.uncertain(protocolError(sub, "a restore_failed answer outside the helper's contract"))
		}
		d.out.Steps = steps
		logSteps(d.log, steps, refreshedStep(a.CCSRefreshFailed, winproto.StepWriteFile), aclLeftStep(a.RDPKeyACLLeft, steps))
		d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
			providers.DeployRollbackFailed, providers.PhaseRestoreFailed, a.FailedStep, a.CauseStep, a.Error
		d.out.Reason, d.out.Params = restoreFailedReason(a.Error), d.backupParams()
		return d.out, nil
	}
	return d.uncertain(protocolError(sub, "an unknown phase"))
}

// verifyNew verifies the new certificate after a committed or unchanged answer. The served chain is
// compared with comparedChain's length: for a binding the chain Windows built after the imports (built,
// W2 Ruling 16; the deployed chain when the helper could not read it), and when the two differ the verify
// step's params carry chain_differs true, deployed_chain and built_chain; for a CCS file the PFX's own
// chain (F18). The trust check (R51) decides as usual.
func (d *deployment) verifyNew(ctx context.Context, phase string, built int) (providers.DeployOutcome, error) {
	req := d.req
	deployed := req.ChainLength
	if deployed <= 0 {
		deployed = chainLength(req.CertificatePEM)
	}
	compare, extra := comparedChain(req.Location.Kind, deployed, built)
	params := func(vr providers.VerifyResult) map[string]string {
		p := vr.StepParams()
		maps.Copy(p, extra)
		if vr.OK && vr.Params[ccsUnlinkedParam] != "" {
			p[ccsUnlinkedParam] = vr.Params[ccsUnlinkedParam] // W5 Ruling 8: verified by the helper's read-back only
		}
		return p
	}
	step(d.log, providers.StepNameVerify, providers.StepStarted, nil)
	vr, verr := d.s.VerifyDeployment(ctx, providers.VerifyRequest{Location: req.Location, Fingerprint: d.fingerprint, ChainLength: compare,
		PreviousFingerprint: req.OldFingerprint, SANs: req.SANs, KeyType: req.KeyType, Verify: req.Verify, Trust: req.Trust})
	if verr != nil && ctx.Err() != nil {
		// The call's context ended during the verification: interrupted, not a failed check.
		step(d.log, providers.StepNameVerify, providers.StepFailed, map[string]string{"error": "interrupted"})
		d.out.Steps = append(d.out.Steps, providers.DeployStep{Name: providers.StepNameVerify, Status: providers.StepFailed})
		if phase == winproto.PhaseUnchanged {
			return d.uncertain(providers.NewError(reasonInterrupted, true, verr, nil))
		}
		return d.uncertainAfterVerify(reasonInterrupted, nil, verr)
	}
	if verr != nil {
		// The check could not be made (the SSH connection failed during a server-side probe).
		vr = unverifiable(req.Location, req.Verify, req.SANs)
	}
	if vr.OK {
		status := providers.StepOK
		if vr.Mode == "skipped" {
			status = providers.StepSkipped
		}
		step(d.log, providers.StepNameVerify, status, params(vr))
		d.out.Steps = append(d.out.Steps, providers.DeployStep{Name: providers.StepNameVerify, Status: status})
		d.out.Result, d.out.Phase, d.out.Verified, d.out.Trust = providers.DeployCommitted, providers.PhaseCommitted, vr.Mode, vr.Trust
		if phase == winproto.PhaseUnchanged {
			d.out.Result, d.out.Phase = providers.DeployUnchanged, providers.PhaseUnchanged
		}
		return d.out, nil
	}
	step(d.log, providers.StepNameVerify, providers.StepFailed, params(vr))
	d.out.Steps = append(d.out.Steps, providers.DeployStep{Name: providers.StepNameVerify, Status: providers.StepFailed})
	d.out.Trust = vr.Trust
	if phase == winproto.PhaseUnchanged {
		// This operation changed nothing (the record already named the certificate): nothing to roll back.
		d.out.Result, d.out.Phase, d.out.FailedStep = providers.DeployNoChange, providers.PhaseUnchanged, providers.StepNameVerify
		d.out.Reason, d.out.Params = vr.Reason, vr.Params
		return d.out, providers.NewError(vr.Reason, false, verr, maps.Clone(vr.Params))
	}
	return d.rollBack(ctx, vr)
}

// rollBack restores the previous record of a committed operation whose verification failed (iis-restore
// of the same operation) and verifies the previous certificate; the verification's reason and params
// stay the outcome's when the rollback succeeds. The guard is read again first (req.RecheckGuard, R48;
// an error restores nothing: uncertain with the verification's reason); the helper checks it with its
// journal's lists. BUSY is retried: restoreAttempts sends in all, restoreWait apart on the session
// clock. BACKUP_MISSING (the previous certificate is not in its store with a usable key, nothing
// written) is rollback_failed windows.backup_missing. Every other refusal (still BUSY, IO_ERROR,
// SUPERSEDED, UNKNOWN_OP, a context ended before the send) and anything uncertain is DeployUncertain
// with the verification's reason: the new certificate may still be bound, unverified, and the engine's
// recovery reads the journal and finishes the rollback.
func (d *deployment) rollBack(ctx context.Context, vr providers.VerifyResult) (providers.DeployOutcome, error) {
	guard := d.req.Guard
	if d.req.RecheckGuard != nil {
		g, err := d.req.RecheckGuard(ctx)
		if err != nil {
			return d.uncertainAfterVerify(vr.Reason, vr.Params, providers.NewError(reasonUnexpected, true, err, nil))
		}
		guard = g
	}
	r, err := d.restoreRetryingBusy(ctx, guard)
	if err != nil {
		return d.uncertainAfterVerify(vr.Reason, vr.Params, err)
	}
	switch {
	case r.refusal != nil && r.code == winproto.CodeBackupMissing:
		d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
			providers.DeployRollbackFailed, "", providers.StepNameRestore, providers.StepNameVerify, winproto.ErrBackupMissing
		d.out.Reason, d.out.Params = ReasonBackupMissing, d.backupParams()
		return d.out, nil
	case r.refusal != nil:
		return d.uncertainAfterVerify(vr.Reason, vr.Params, r.refusal)
	}
	d.out.Steps = append(d.out.Steps, r.steps...)
	switch r.phase {
	case winproto.PhaseRestoreForbidden:
		return d.forbidden(providers.PhaseRestoreForbidden, providers.StepNameVerify)
	case winproto.PhaseRestored:
		d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
			providers.DeployRolledBack, providers.PhaseRestored, providers.StepNameVerify, providers.StepNameVerify, ""
		d.out.Reason, d.out.Params = vr.Reason, maps.Clone(vr.Params)
		return d.verifyOld(ctx)
	case winproto.PhaseRestoreFailed:
		d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
			providers.DeployRollbackFailed, providers.PhaseRestoreFailed, r.failedStep, providers.StepNameVerify, r.class
		d.out.Reason, d.out.Params = restoreFailedReason(r.class), d.backupParams()
		return d.out, nil
	}
	// prepared or unchanged ("nothing to restore") cannot follow a committed answer.
	return d.uncertainAfterVerify(vr.Reason, vr.Params, protocolError(winproto.SubIISRestore, "nothing to restore after a committed deployment"))
}

// forbidden is rollback_failed deployment.rollback_forbidden (R48): the guard refused the restore, the
// previous certificate was not put back. No store or thumbprint: binding it by hand would put the
// forbidden certificate back.
func (d *deployment) forbidden(phase, cause string) (providers.DeployOutcome, error) {
	d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
		providers.DeployRollbackFailed, phase, providers.StepNameRestore, cause, providers.DeployErrForbidden
	d.out.Reason, d.out.Params = providers.ReasonRollbackForbidden, map[string]string{}
	return d.out, nil
}

// restoreRetryingBusy is restore for the inline rollback, sent again while the helper answers BUSY.
func (d *deployment) restoreRetryingBusy(ctx context.Context, guard providers.RollbackGuard) (restoreResult, error) {
	for attempt := 1; ; attempt++ {
		r, err := d.s.restore(ctx, d.req.OperationID, guard, d.log)
		if err != nil || r.code != winproto.CodeBusy || attempt >= d.s.p.restoreAttempts {
			return r, err
		}
		select {
		case <-ctx.Done():
			return r, nil
		case <-d.s.clock.After(d.s.p.restoreWait):
		}
	}
}

// verifyOld checks the previous certificate after a rollback (the helper's own or the inline one);
// d.out is rolled_back. Another certificate served makes it rollback_failed with Phase restored and
// FailedStep verify_old; a website that cannot be checked leaves it rolled_back with Verified "".
func (d *deployment) verifyOld(ctx context.Context) (providers.DeployOutcome, error) {
	req := d.req
	v, ok := d.s.checkOld(ctx, d.log, providers.VerifyRequest{Location: req.Location, Fingerprint: req.OldFingerprint,
		SANs: req.OldSANs, KeyType: req.KeyType, Verify: req.Verify})
	d.out.Steps = append(d.out.Steps, v.step)
	if !ok {
		d.out.Result, d.out.FailedStep = providers.DeployRollbackFailed, providers.StepNameVerifyOld
		d.out.Reason, d.out.Params = reasonRollbackFailed, d.backupParams()
		return d.out, nil
	}
	d.out.Verified = v.mode
	return d.out, nil
}
