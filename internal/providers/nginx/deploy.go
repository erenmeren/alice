package nginx

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
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
)

// Outcome reasons of DeployCertificate and RollbackDeployment besides the verification reasons
// (verify.go) and mapHelper's refusal reasons. reasonNothingToRestore, reasonSuperseded and
// reasonUnknownOperation are additions to the plan's contract (RollbackDeployment's no_change).
const (
	reasonKeyMismatch          = "certificate.key_mismatch"      // the helper's nginx -t failed with key_mismatch
	reasonInvalidCertificate   = "certificate.invalid"           // the pair cannot be sent (empty or not PEM text)
	reasonConfigTestFailed     = "deployment.config_test_failed" // the helper's nginx -t failed with another class
	reasonReloadFailed         = "deployment.reload_failed"      // the helper's reload failed
	reasonInterrupted          = "deployment.interrupted"        // a write or the journal failed in the helper's transaction, or ctx ended during the verification
	reasonRollbackFailed       = "deployment.rollback_failed"    // param backup_dir
	reasonRollbackReloadFailed = "deployment.rollback_reload_failed"
	reasonNothingToRestore     = "deployment.nothing_to_restore"
	reasonSuperseded           = "deployment.superseded"
	reasonUnknownOperation     = "deployment.unknown_operation"
	reasonLocationUnsupported  = "nginx.location_unsupported"
	reasonUnexpected           = "internal.unexpected"
)

// Refusal codes per subcommand with the exit status the helper gives each (cmd/alice-helper
// deploy.go, run.go; the Task 6 contract). Only such an answer (well-formed JSON, ok false, a code
// of this table at its exit status) is a refusal that changed nothing; any other code, or a known
// code at another exit status, is an answer Alice does not understand: uncertain. OUTCOME_UNKNOWN
// (the helper's guard after a rename) is in no table on purpose.
var (
	deployRefusals = map[string]int{
		helperproto.CodeUsage: helperproto.ExitRefused, helperproto.CodeUnknownSubcommand: helperproto.ExitRefused,
		helperproto.CodeNotRoot: helperproto.ExitRefused, helperproto.CodeInvalidArgument: helperproto.ExitRefused,
		helperproto.CodeTooLarge: helperproto.ExitRefused, helperproto.CodeBadContent: helperproto.ExitRefused,
		helperproto.CodeUnsafeFile: helperproto.ExitRefused, helperproto.CodeNotRegularFile: helperproto.ExitRefused,
		helperproto.CodePathNotAllowed:  helperproto.ExitRefused,
		helperproto.CodeContentMismatch: helperproto.ExitPrecondition, helperproto.CodeNginxNotFound: helperproto.ExitPrecondition,
		helperproto.CodeConfigInvalid: helperproto.ExitPrecondition, helperproto.CodeConfigChanged: helperproto.ExitPrecondition,
		helperproto.CodeNotFound: helperproto.ExitPrecondition, helperproto.CodeHashMismatch: helperproto.ExitPrecondition,
		helperproto.CodeNoSpace: helperproto.ExitPrecondition, helperproto.CodeSuperseded: helperproto.ExitPrecondition,
		helperproto.CodeRecoveryPending: helperproto.ExitPrecondition, helperproto.CodeNginxNotRunning: helperproto.ExitPrecondition,
		helperproto.CodeFenced: helperproto.ExitPrecondition,
		helperproto.CodeBusy:   helperproto.ExitFailed, helperproto.CodeIOError: helperproto.ExitFailed,
	}
	restoreRefusals = map[string]int{
		helperproto.CodeUsage: helperproto.ExitRefused, helperproto.CodeUnknownSubcommand: helperproto.ExitRefused,
		helperproto.CodeNotRoot: helperproto.ExitRefused, helperproto.CodeInvalidArgument: helperproto.ExitRefused,
		helperproto.CodeUnknownOp: helperproto.ExitPrecondition, helperproto.CodeHashMismatch: helperproto.ExitPrecondition,
		helperproto.CodeSuperseded: helperproto.ExitPrecondition,
		helperproto.CodeBusy:       helperproto.ExitFailed, helperproto.CodeIOError: helperproto.ExitFailed,
	}
)

// The helper's vocabulary of a transaction answer (Task 6 contract): step names, the steps that
// can start a rollback, the steps a rollback fails at, and the error classes (nginx -t's classes,
// file_changed, or "").
var (
	helperSteps = []string{helperproto.StepBackup, helperproto.StepWriteKey, helperproto.StepWriteCert, helperproto.StepConfigTest,
		helperproto.StepReload, helperproto.StepJournal, helperproto.StepRestore, helperproto.StepRollbackConfigTest, helperproto.StepRollbackReload}
	causeSteps    = []string{helperproto.StepWriteKey, helperproto.StepWriteCert, helperproto.StepConfigTest, helperproto.StepReload, helperproto.StepJournal}
	rollbackSteps = []string{helperproto.StepRestore, helperproto.StepRollbackConfigTest, helperproto.StepRollbackReload}
	nginxClasses  = []string{helperproto.ConfigErrKeyMismatch, helperproto.ConfigErrFileMissing, helperproto.ConfigErrCertLoad,
		helperproto.ConfigErrKeyLoad, helperproto.ConfigErrSyntax}
	helperPhases = []string{helperproto.PhaseNone, helperproto.PhasePrepared, helperproto.PhaseWriting, helperproto.PhaseCommitted,
		helperproto.PhaseUnchanged, helperproto.PhaseRestoring, helperproto.PhaseRestored, helperproto.PhaseRestoreFailed, helperproto.PhaseFenced,
		helperproto.PhaseRestoreForbidden}
)

// maxAnswerSteps bounds the steps of one answer (the helper trims its journal's list to 64).
const maxAnswerSteps = 64

// knownClass: an nginx -t class or ""; with restore true also a restore's own classes (file_changed,
// and the rollback guard's forbidden, protocol 10).
func knownClass(c string, restore bool) bool {
	return c == "" || slices.Contains(nginxClasses, c) || (restore && (c == helperproto.RestoreErrFileChanged || c == helperproto.RestoreErrForbidden))
}

// forbiddenShape: the helper's guard refused a restore (protocol 10, R48): failed_step restore,
// error forbidden, the cause any step of the transaction or "" (a restore of a committed operation).
func forbiddenShape(failed, cause, class string) bool {
	return failed == helperproto.StepRestore && class == helperproto.RestoreErrForbidden && (cause == "" || slices.Contains(causeSteps, cause))
}

// guardNeeded reports a rollback guard the provider must act on: it forbids something, or the
// deployment requires a helper that checks it.
func guardNeeded(g providers.RollbackGuard) bool { return g.Required || !g.Empty() }

// validGuard: the lists are what the helper accepts (helperproto.ValidForbidden).
func validGuard(g providers.RollbackGuard) bool {
	return helperproto.ValidForbidden(g.ForbiddenSPKI) && helperproto.ValidForbidden(g.ForbiddenLeaf)
}

// appendHashList appends `,"name":["h",...]` (hashes already ValidForbidden: hex, nothing to escape);
// nothing for an empty list.
func appendHashList(dst []byte, name string, list []string) []byte {
	if len(list) == 0 {
		return dst
	}
	dst = append(append(append(dst, `,"`...), name...), `":[`...)
	for i, h := range list {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(append(append(dst, '"'), h...), '"')
	}
	return append(dst, ']')
}

// restoreInput is the JSON of helperproto.NginxRestoreInput for a guard (both members, possibly
// empty lists).
func restoreInput(g providers.RollbackGuard) []byte {
	spki, leaf := g.ForbiddenSPKI, g.ForbiddenLeaf
	if spki == nil {
		spki = []string{}
	}
	if leaf == nil {
		leaf = []string{}
	}
	raw, _ := json.Marshal(helperproto.NginxRestoreInput{ForbiddenSPKI: spki, ForbiddenLeaf: leaf}) // strings only: cannot fail
	return raw
}

// protocolError is the error of an answer that breaks the helper's contract: uncertain.
func protocolError(sub, why string) *providers.Error {
	return providers.NewError("ssh.protocol_error", false, errors.New("nginx: "+why), map[string]string{"subcommand": sub})
}

// asProviderError returns err as a *providers.Error (every error this package maps is one).
func asProviderError(err error) *providers.Error {
	var pe *providers.Error
	if errors.As(err, &pe) {
		return pe
	}
	return providers.NewError(reasonUnexpected, false, err, nil)
}

// call is a helper transaction command's result sorted into the three situations: an answer
// (exit 0, decoded), a well-formed refusal (refusal != nil: nothing changed) or an uncertain outcome
// (uncertain != nil).
type call[T any] struct {
	answer    T
	code      string           // the refusal's helper code
	refusal   *providers.Error // as DecodeHelper gives it, not mapped yet
	uncertain error
}

// decodeCall sorts what Conn.Run returned for sub (nginx-deploy or nginx-restore, the two commands
// that write). A refusal is only the helper's JSON error with a code of refusals at the exit
// status the table gives it. Everything else that is not an exit-0 answer is uncertain: a
// transport error, a timeout or cancellation after the command was sent, a signal, exit 137 or any
// other status without JSON (ssh.helper_missing), malformed JSON (ssh.protocol_error), an unknown
// code, or a known code at the wrong exit status.
//
// Exit 1 with nothing on stdout is uncertain too (final review): it is what sudo's own refusal
// looks like, before the helper starts (the helper never exits 1), but with "Defaults log_output"
// sudo can also fail after the command ran (its I/O log) and forward nothing; and whether stdin
// reached the helper cannot be known on Alice's side (the bytes are written to the channel
// whether or not sudo consumed them). Only for these two commands does the difference matter, so
// only here is it uncertain (the error is still mapped: nginx.profile_missing names the likely
// cause); the read-only commands keep sudo's refusal as nginx.profile_missing.
func decodeCall[T any](res linuxssh.Result, runErr error, sub string, refusals map[string]int) call[T] {
	if runErr != nil {
		return call[T]{uncertain: runErr}
	}
	v, err := linuxssh.DecodeHelper[T](res, sub)
	if err == nil {
		return call[T]{answer: v}
	}
	pe := asProviderError(err)
	code := pe.Params["helper_code"]
	switch {
	case pe.Code == "ssh.helper_missing" && pe.Params["exit_code"] == "1" && len(res.Stdout) == 0:
		return call[T]{uncertain: mapHelper(pe, sub)}
	case code == "":
		return call[T]{uncertain: pe}
	case refusals[code] != res.ExitCode:
		u := protocolError(sub, "a refusal outside the helper's contract")
		u.Params["helper_code"] = code
		u.Cause = pe
		return call[T]{uncertain: u}
	}
	return call[T]{code: code, refusal: pe}
}

// toSteps checks the steps of an answer against the helper's vocabulary and converts them.
func toSteps(in []helperproto.NginxStep) ([]providers.DeployStep, bool) {
	if len(in) > maxAnswerSteps {
		return nil, false
	}
	out := make([]providers.DeployStep, 0, len(in))
	for _, st := range in {
		var status providers.StepStatus
		switch st.Status {
		case "ok":
			status = providers.StepOK
		case "failed":
			status = providers.StepFailed
		default:
			return nil, false
		}
		if !slices.Contains(helperSteps, st.Name) || !knownClass(st.Error, true) {
			return nil, false
		}
		out = append(out, providers.DeployStep{Name: st.Name, Status: status, Error: st.Error})
	}
	return out, true
}

func anyFailed(steps []providers.DeployStep) bool {
	return slices.ContainsFunc(steps, func(st providers.DeployStep) bool { return st.Status == providers.StepFailed })
}

// step reports one step to the logger (nil: none).
func step(log providers.StepLogger, name string, status providers.StepStatus, params map[string]string) {
	if log != nil {
		log.Step(name, status, params)
	}
}

// logSteps reports the steps of a helper answer, each once with its final status (param error =
// its class when it has one).
func logSteps(log providers.StepLogger, steps []providers.DeployStep) {
	for _, st := range steps {
		var params map[string]string
		if st.Error != "" {
			params = map[string]string{"error": st.Error}
		}
		step(log, st.Name, st.Status, params)
	}
}

// deployInput is the JSON of helperproto.NginxDeployInput ({"cert_pem":"…","key_pem":"…"}, and the
// rollback guard's lists when not empty: protocol 10, R48), built in one allocation of its final size
// and without a string copy of the key (a Go string cannot be wiped; json.Marshal would make one and
// grow buffers it leaves behind). The caller clears it. ok is false for an empty or non-ASCII PEM
// text (the helper would refuse it as BAD_CONTENT).
func deployInput(cert, key []byte, spki, leaf []string) ([]byte, bool) {
	cn, ok1 := jsonStringLen(cert)
	kn, ok2 := jsonStringLen(key)
	if !ok1 || !ok2 || len(cert) == 0 || len(key) == 0 {
		return nil, false
	}
	const head, mid, tail = `{"cert_pem":`, `,"key_pem":`, `}`
	lists := 0
	for _, l := range [][]string{spki, leaf} {
		if len(l) > 0 {
			lists += len(`,"forbidden_spki_sha256":[]`) + len(l)*(64+2) + len(l) - 1 // both names are as long; quotes and commas
		}
	}
	out := make([]byte, 0, len(head)+cn+len(mid)+kn+lists+len(tail))
	out = append(out, head...)
	out = appendJSONString(out, cert)
	out = append(out, mid...)
	out = appendJSONString(out, key)
	out = appendHashList(out, "forbidden_spki_sha256", spki)
	out = appendHashList(out, "forbidden_leaf_sha256", leaf)
	return append(out, tail...), true
}

const hexDigits = "0123456789abcdef"

// jsonStringLen is the length of b as a JSON string literal (quotes included); ok is false for a
// byte outside ASCII.
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

// leafFingerprint is the hex SHA-256 of the DER of the chain's first CERTIFICATE block (the leaf
// the website must serve); ok is false when there is none.
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

func backupDir(op uuid.UUID) string { return helperproto.BackupRoot + "/" + op.String() }

// DeployCertificate deploys a certificate and its key to an Nginx location in one helper
// transaction (nginx-deploy), verifies that the website serves the new certificate (spec §12.8;
// VerifyDeployment) and, when it does not, restores the previous files right away (nginx-restore of
// the same operation) and verifies that the previous certificate is served again (spec §6.3 item
// 3). Every return is one of the legal shapes of providers/outcome.go:
//
//   - a refusal before anything was sent (closed session, unsupported location, a pair that cannot
//     be sent, a context cancelled before the command was sent) or a well-formed helper refusal
//     (decodeCall): DeployNoChange with a *providers.Error and no phase or steps;
//   - committed or unchanged and verified: DeployCommitted / DeployUnchanged, Phase as the helper's;
//   - unchanged and not verified: DeployNoChange, Phase unchanged, FailedStep verify, a *Error;
//   - the helper's own rollback (restored, restore_failed) and the inline rollback after a failed
//     verification: DeployRolledBack / DeployRollbackFailed with a nil error (see TestDeployOutcomeTable
//     in deploy_test.go for every row);
//   - anything else: DeployUncertain with a non-nil error and no Phase, FailedStep, CauseStep or
//     Error (the caller reads DeploymentStatus).
//
// Verification is not done before the change here: the deploy engine's precheck (VerifyDeployment
// with the current fingerprint) refuses a website Alice cannot check or that serves another
// certificate, before anything is written. After the change, a verification that cannot be made
// (unreachable both ways, or a failure of the SSH connection during the server-side probe) is a
// failed verification and is rolled back. The helper's own restore_failed is reported as it is
// (not retried here): the engine decides about another nginx-restore (RollbackDeployment).
//
// The leaf compared is the one of req.CertificatePEM (its first CERTIFICATE block), computed here: a
// verification after a deployment is never vacuous. A request whose Fingerprint names another leaf
// is refused (internal.unexpected) before anything is sent.
//
// With req.Trust (R51) the verification also checks the trust of every served chain: a chain that
// does not verify against a known anchor is a failed verification (deployment.verify_untrusted,
// params port and trust_error) and is rolled back like the others; otherwise it is a warning. The
// outcome's Trust is what the verification found (also for a failed one).
//
// An uncertain outcome with a Reason, and Params["failed_step"] = "verify", means the new
// certificate's verification had failed (Reason: deployment.verify_failed, verify_other,
// verify_chain, verify_untrusted or verify_unreachable, Params["port"]; or deployment.interrupted when the call's
// context ended during it) before the rollback could be done or confirmed. The journal may then read
// committed. A deploy engine must store that reason, and must never treat a journal reading
// committed as success without verifying again (VerifyDeployment with the same fingerprint and chain
// length); when that verification fails it rolls back (RollbackDeployment). An uncertain outcome
// without a Reason carries no such knowledge.
//
// A context cancelled before the command is sent is told apart from one cancelled after by
// checking ctx right before Conn.Run: once Run is called the command may have reached the helper,
// so any failure from there on is uncertain (a cancellation that races into Run's own pre-send
// check is reported uncertain too, the safe side).
//
// The private key goes from req.PrivateKeyPEM into the input JSON and from there only onto the
// command's stdin; both are wiped after the send, and a command is never kept or re-sent (the
// same operation is only ever sent again with a newly built command). The helper's steps reach
// log only after nginx-deploy has returned (one SSH exec answers once): a caller sees no live
// progress inside the helper's transaction, only the steps that follow (verify, restore,
// verify_old) as they happen.
//
// The rollback guard (R48, req.Guard): a helper of RollbackGuardMinProtocol gets the forbidden lists
// in the input, keeps them in the operation's journal and checks every restore of the operation
// against them itself (its own after a failed nginx -t or reload answers restore_forbidden:
// rollback_failed deployment.rollback_forbidden). A deployment whose guard is Required is refused on
// an older helper before anything is sent (ssh.helper_outdated_rollback_guard): such a helper would
// put the backup back unchecked. The inline rollback after a failed verification reads the guard
// again (req.RecheckGuard) and restores nothing that it forbids.
func (s *session) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	d := deployment{s: s, req: req, log: log, out: providers.DeployOutcome{Backup: providers.BackupRef{OperationID: req.OperationID}}}
	if req.OperationID != uuid.Nil {
		d.out.Backup.Dir = backupDir(req.OperationID)
	}
	if err := s.Live(); err != nil {
		return d.refuse(asProviderError(err))
	}
	if !req.Location.Supported {
		return d.refuse(providers.NewError(reasonLocationUnsupported, false, nil, nil))
	}
	// The verification compares the leaf of the chain sent, never nothing: the provider computes it,
	// and a request that names another leaf is a caller's error, refused before anything is sent.
	leaf, ok := leafFingerprint(req.CertificatePEM)
	switch {
	case !ok:
		return d.refuse(providers.NewError(reasonInvalidCertificate, false, nil, nil))
	case req.Fingerprint != "" && req.Fingerprint != leaf:
		return d.refuse(providers.NewError(reasonUnexpected, false, errors.New("nginx: the fingerprint is not the chain's leaf"), nil))
	}
	d.fingerprint = leaf
	var spki, leaves []string
	if guardNeeded(req.Guard) {
		if !validGuard(req.Guard) {
			return d.refuse(providers.NewError(reasonUnexpected, false, errors.New("nginx: the rollback guard is not a list the helper takes"), nil))
		}
		guarded, p, err := s.Conn().GuardsRollback(ctx)
		switch {
		case err != nil:
			// The version is read before anything is sent: nothing changed.
			return d.refuse(asProviderError(err))
		case guarded:
			spki, leaves = req.Guard.ForbiddenSPKI, req.Guard.ForbiddenLeaf
		case req.Guard.Required:
			return d.refuse(linuxssh.RollbackGuardOutdated(p))
		}
	}
	input, ok := deployInput(req.CertificatePEM, req.PrivateKeyPEM.Bytes(), spki, leaves)
	defer clear(input)
	if !ok {
		return d.refuse(providers.NewError(reasonInvalidCertificate, false, nil, nil))
	}
	cmd, err := linuxssh.CmdNginxDeploy(req.OperationID, req.Location.CertPath, req.Location.KeyPath, req.ExpectCertSHA256, input)
	clear(input)
	if err != nil {
		return d.refuse(d.buildRefusal(err))
	}
	defer cmd.WipeInput()
	if err := ctx.Err(); err != nil {
		return d.refuse(providers.NewError("ssh.timeout", true, err, map[string]string{"subcommand": helperproto.SubNginxDeploy}))
	}
	res, runErr := s.Conn().Run(ctx, cmd)
	cmd.WipeInput()
	c := decodeCall[helperproto.NginxDeployResponse](res, runErr, helperproto.SubNginxDeploy, deployRefusals)
	switch {
	case c.uncertain != nil:
		return d.uncertain(c.uncertain)
	case c.refusal != nil:
		return d.refuse(asProviderError(mapHelper(c.refusal, helperproto.SubNginxDeploy)))
	}
	return d.answer(ctx, c.answer)
}

// buildRefusal is the refusal when no command could be built: a pair path or the input outside the
// helper's vocabulary or bounds (the location or the pair is not deployable), or a request a caller
// should never send (no operation id, no certificate hash).
func (d *deployment) buildRefusal(cause error) *providers.Error {
	loc := d.req.Location
	switch {
	case !helperproto.ValidPath(loc.CertPath) || !helperproto.ValidPath(loc.KeyPath) || loc.CertPath == "/" || loc.KeyPath == "/" ||
		loc.CertPath == loc.KeyPath:
		return providers.NewError(reasonLocationUnsupported, false, cause, nil)
	case d.req.OperationID == uuid.Nil || !isHexSHA256(d.req.ExpectCertSHA256):
		return providers.NewError(reasonUnexpected, false, cause, nil)
	}
	return providers.NewError(reasonInvalidCertificate, false, cause, nil) // larger than the helper takes
}

// deployment is one DeployCertificate call while it maps the helper's answers.
type deployment struct {
	s           *session
	req         providers.DeployRequest
	fingerprint string // the leaf of req.CertificatePEM (hex SHA-256)
	log         providers.StepLogger
	out         providers.DeployOutcome
}

// refuse is DeployNoChange for a refusal: nothing changed, no phase and no steps.
func (d *deployment) refuse(e *providers.Error) (providers.DeployOutcome, error) {
	o := providers.DeployOutcome{Result: providers.DeployNoChange, Reason: e.Code, Params: maps.Clone(e.Params), Backup: d.out.Backup}
	return o, e
}

// uncertain is DeployUncertain: the steps known so far are kept; phase, failed and cause step and
// error class are cleared (the caller reads DeploymentStatus).
func (d *deployment) uncertain(err error) (providers.DeployOutcome, error) {
	return providers.DeployOutcome{Result: providers.DeployUncertain, Steps: d.out.Steps, Backup: d.out.Backup}, err
}

// uncertainAfterVerify is DeployUncertain after the new certificate's verification failed: Reason
// and Params say why the verification failed (its reason and port) and Params["failed_step"] =
// verify says that it had failed before the outcome became uncertain. The journal may still read
// committed (see DeployCertificate).
func (d *deployment) uncertainAfterVerify(reason string, params map[string]string, err error) (providers.DeployOutcome, error) {
	o, err := d.uncertain(err)
	o.Reason, o.Params = reason, maps.Clone(params)
	if o.Params == nil {
		o.Params = map[string]string{}
	}
	o.Params["failed_step"] = providers.StepNameVerify
	return o, err
}

// answer maps a completed nginx-deploy (exit 0) by its phase (the table of DeployCertificate).
func (d *deployment) answer(ctx context.Context, a helperproto.NginxDeployResponse) (providers.DeployOutcome, error) {
	const sub = helperproto.SubNginxDeploy
	steps, ok := toSteps(a.Steps)
	if !ok {
		return d.uncertain(protocolError(sub, "steps outside the helper's vocabulary"))
	}
	switch a.Phase {
	case helperproto.PhaseCommitted, helperproto.PhaseUnchanged:
		if a.FailedStep != "" || a.CauseStep != "" || a.Error != "" || anyFailed(steps) {
			return d.uncertain(protocolError(sub, "a successful phase with a failure"))
		}
		d.out.Steps = steps
		logSteps(d.log, steps)
		return d.verifyNew(ctx, a.Phase)
	case helperproto.PhaseRestored:
		// failed_step = cause_step = the step that started the helper's own rollback. An empty
		// failed_step is the answer to a re-sent operation that was recovered or restored before
		// (Task 9 finding 1): it has no legal rolled_back shape, so the journal must decide.
		if !slices.Contains(causeSteps, a.FailedStep) || a.CauseStep != a.FailedStep || !knownClass(a.Error, false) {
			return d.uncertain(protocolError(sub, "a restored answer without the step that failed"))
		}
		d.out.Steps = steps
		logSteps(d.log, steps)
		d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
			providers.DeployRolledBack, providers.PhaseRestored, a.FailedStep, a.CauseStep, a.Error
		d.out.Reason = failedReason(a.FailedStep, a.Error)
		return d.verifyOld(ctx)
	case helperproto.PhaseRestoreForbidden:
		// R48: the helper's own rollback found the backup forbidden and restored nothing.
		if !forbiddenShape(a.FailedStep, a.CauseStep, a.Error) {
			return d.uncertain(protocolError(sub, "a restore_forbidden answer outside the helper's contract"))
		}
		d.out.Steps = steps
		logSteps(d.log, steps)
		return d.forbidden(providers.PhaseRestoreForbidden, a.CauseStep)
	case helperproto.PhaseRestoreFailed:
		if !restoreFailedShape(a.FailedStep, a.CauseStep, a.Error) {
			return d.uncertain(protocolError(sub, "a restore_failed answer outside the helper's contract"))
		}
		d.out.Steps = steps
		logSteps(d.log, steps)
		d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
			providers.DeployRollbackFailed, providers.PhaseRestoreFailed, a.FailedStep, a.CauseStep, a.Error
		d.out.Reason, d.out.Params = rollbackReason(a.FailedStep), map[string]string{"backup_dir": d.out.Backup.Dir}
		return d.out, nil
	}
	return d.uncertain(protocolError(sub, "an unknown phase"))
}

// restoreFailedShape: the rollback failed at one of its own steps (the cause any step of the
// transaction, or "" for a re-sent interrupted operation), or a file someone else changed was left
// (error file_changed, failed_step = cause_step = the step that started the rollback).
func restoreFailedShape(failed, cause, class string) bool {
	switch {
	case !knownClass(class, true) || class == helperproto.RestoreErrForbidden || (cause != "" && !slices.Contains(causeSteps, cause)):
		return false
	case slices.Contains(rollbackSteps, failed):
		return true
	}
	return class == helperproto.RestoreErrFileChanged && slices.Contains(causeSteps, failed) && cause == failed
}

// verifyNew verifies the new certificate after a committed or unchanged answer.
func (d *deployment) verifyNew(ctx context.Context, phase string) (providers.DeployOutcome, error) {
	req := d.req
	chain := req.ChainLength
	if chain <= 0 {
		chain = chainLength(req.CertificatePEM)
	}
	step(d.log, providers.StepNameVerify, providers.StepStarted, nil)
	vr, verr := d.s.VerifyDeployment(ctx, providers.VerifyRequest{Location: req.Location, Fingerprint: d.fingerprint, ChainLength: chain,
		PreviousFingerprint: req.OldFingerprint, SANs: req.SANs, KeyType: req.KeyType, Verify: req.Verify, Trust: req.Trust})
	if verr != nil && ctx.Err() != nil {
		// The call's context ended during the verification: interrupted, not a failed check. The
		// step status vocabulary has no "interrupted": the step is failed with param error =
		// interrupted, the outcome's reason deployment.interrupted.
		step(d.log, providers.StepNameVerify, providers.StepFailed, map[string]string{"error": "interrupted"})
		d.out.Steps = append(d.out.Steps, providers.DeployStep{Name: providers.StepNameVerify, Status: providers.StepFailed})
		if phase == helperproto.PhaseUnchanged {
			// B2 m2: not a failed check either: uncertain, so the recovery reads the journal
			// (unchanged) and verifies again, instead of a failed deployment and its email.
			return d.uncertain(providers.NewError(reasonInterrupted, true, verr, nil))
		}
		// Cancelled after the change: no rollback can be sent. The journal says committed.
		return d.uncertainAfterVerify(reasonInterrupted, nil, verr)
	}
	if verr != nil {
		// The check could not be made (the SSH connection failed during a server-side probe): a
		// failed verification, a website Alice cannot check.
		vr = unverifiable(req.Location, req.Verify, req.SANs)
	}
	if vr.OK {
		status := providers.StepOK
		if vr.Mode == "skipped" {
			status = providers.StepSkipped
		}
		step(d.log, providers.StepNameVerify, status, verifyStepParams(vr))
		d.out.Steps = append(d.out.Steps, providers.DeployStep{Name: providers.StepNameVerify, Status: status})
		d.out.Result, d.out.Phase, d.out.Verified, d.out.Trust = providers.DeployCommitted, providers.PhaseCommitted, vr.Mode, vr.Trust
		if phase == helperproto.PhaseUnchanged {
			d.out.Result, d.out.Phase = providers.DeployUnchanged, providers.PhaseUnchanged
		}
		return d.out, nil
	}
	// The reason goes with the step: the step is recorded before the rollback is sent, so a deploy
	// engine that dies during the rollback can still tell why it was rolled back.
	step(d.log, providers.StepNameVerify, providers.StepFailed, verifyStepParams(vr))
	d.out.Steps = append(d.out.Steps, providers.DeployStep{Name: providers.StepNameVerify, Status: providers.StepFailed})
	d.out.Trust = vr.Trust // a chain that did not verify (deployment.verify_untrusted) stays on the record
	if phase == helperproto.PhaseUnchanged {
		// This operation changed nothing (the files already were the new ones): nothing to roll back.
		d.out.Result, d.out.Phase, d.out.FailedStep = providers.DeployNoChange, providers.PhaseUnchanged, providers.StepNameVerify
		d.out.Reason, d.out.Params = vr.Reason, vr.Params
		return d.out, providers.NewError(vr.Reason, false, verr, maps.Clone(vr.Params))
	}
	return d.rollBack(ctx, vr)
}

// verifyStepParams are the params of the verify step: mode, and the trust status when measured (with
// its reason when untrusted) for a passed verification; port and reason (and trust_error) for a
// failed one.
func verifyStepParams(vr providers.VerifyResult) map[string]string {
	if !vr.OK {
		p := map[string]string{"port": vr.Params["port"], "reason": vr.Reason}
		if te := vr.Params["trust_error"]; te != "" {
			p["trust_error"] = te
		}
		return p
	}
	p := map[string]string{"mode": vr.Mode}
	if vr.Trust.Status != "" {
		p["trust"] = vr.Trust.Status
	}
	if vr.Trust.Error != "" {
		p["trust_error"] = vr.Trust.Error
	}
	return p
}

// unverifiable is the result of a verification that could not be made.
func unverifiable(loc providers.CertLocation, v providers.VerifyOptions, sans []string) providers.VerifyResult {
	port := v.Port
	if eps := Endpoints(loc, v, sans); len(eps) > 0 {
		port = eps[0].Port
	}
	if port == 0 {
		port = 443
	}
	return providers.VerifyResult{Reason: reasonVerifyUnreachable, Params: map[string]string{"port": strconv.Itoa(port)}, Failure: providers.VerifyFailureNetwork}
}

// rollBack restores the files of a committed operation whose verification failed (nginx-restore
// of the same operation) and verifies the previous certificate. The verification's reason and
// params stay the outcome's when the rollback succeeds.
//
// The rollback guard is read again first (req.RecheckGuard, R48; an error restores nothing: uncertain
// with the verification's reason). A restore the guard refuses (the helper's restore_forbidden, or
// nothing sent to a helper that cannot check it) is rollback_failed deployment.rollback_forbidden:
// the new files stay, unverified.
//
// The restore's answer decides: restored (then the old certificate is verified) or restore_failed
// and HASH_MISMATCH (someone else's file) are known outcomes. BUSY (another deployment on the server
// holds the helper's lock) is retried: s.p.restoreAttempts sends in all, s.p.restoreWait apart on
// the session clock (3 and 10 s: at most 20 s of waiting by Alice; each BUSY answer itself comes
// after the helper's own lock wait of up to 30 s). Every other outcome of the restore (still BUSY,
// IO_ERROR, sudo's refusal, a context ended before it was sent, SUPERSEDED and UNKNOWN_OP, which
// cannot happen for the operation just committed, and anything uncertain) is DeployUncertain with
// the verification's reason: the new files may still be live, unverified, and the deploy engine's
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
	failed := func(phase, failedStep, class string) (providers.DeployOutcome, error) {
		d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
			providers.DeployRollbackFailed, phase, failedStep, providers.StepNameVerify, class
		d.out.Reason, d.out.Params = rollbackReason(failedStep), map[string]string{"backup_dir": d.out.Backup.Dir}
		return d.out, nil
	}
	switch {
	case r.forbidden:
		// R48: nothing was sent; the new files stay, unverified.
		return d.forbidden("", providers.StepNameVerify)
	case r.refusal != nil && r.code == helperproto.CodeHashMismatch:
		// Someone else's file is in place: nothing was restored.
		return failed("", providers.StepNameRestore, providers.DeployErrFileChanged)
	case r.refusal != nil:
		return d.uncertainAfterVerify(vr.Reason, vr.Params, restoreRefusalError(r))
	}
	d.out.Steps = append(d.out.Steps, r.steps...)
	switch r.phase {
	case helperproto.PhaseRestoreForbidden:
		return d.forbidden(providers.PhaseRestoreForbidden, providers.StepNameVerify)
	case helperproto.PhaseRestored:
		d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
			providers.DeployRolledBack, providers.PhaseRestored, providers.StepNameVerify, providers.StepNameVerify, ""
		d.out.Reason, d.out.Params = vr.Reason, maps.Clone(vr.Params)
		return d.verifyOld(ctx)
	case helperproto.PhaseRestoreFailed:
		return failed(providers.PhaseRestoreFailed, r.failedStep, r.class)
	}
	// prepared or unchanged ("nothing to restore") cannot follow a committed answer.
	return d.uncertainAfterVerify(vr.Reason, vr.Params, protocolError(helperproto.SubNginxRestore, "nothing to restore after a committed deployment"))
}

// forbidden is rollback_failed deployment.rollback_forbidden (R48): the guard refused the restore,
// nothing of the backup was put back (phase restore_forbidden: the helper recorded it; "": nothing
// was sent). No backup_dir: restoring the backup by hand would put the forbidden key back.
func (d *deployment) forbidden(phase, cause string) (providers.DeployOutcome, error) {
	d.out.Result, d.out.Phase, d.out.FailedStep, d.out.CauseStep, d.out.Error =
		providers.DeployRollbackFailed, phase, providers.StepNameRestore, cause, providers.DeployErrForbidden
	d.out.Reason, d.out.Params = providers.ReasonRollbackForbidden, map[string]string{}
	return d.out, nil
}

// restoreRetryingBusy is restore for the inline rollback, sent again while the helper answers BUSY
// (see rollBack for the bound).
func (d *deployment) restoreRetryingBusy(ctx context.Context, guard providers.RollbackGuard) (restoreResult, error) {
	for attempt := 1; ; attempt++ {
		r, err := d.s.restore(ctx, d.req.OperationID, guard, d.log)
		if err != nil || r.code != helperproto.CodeBusy || attempt >= d.s.p.restoreAttempts {
			return r, err
		}
		select {
		case <-ctx.Done():
			return r, nil
		case <-d.s.clock.After(d.s.p.restoreWait):
		}
	}
}

// restoreRefusalError is the *providers.Error of a well-formed nginx-restore refusal.
func restoreRefusalError(r restoreResult) *providers.Error {
	switch r.code {
	case helperproto.CodeUnknownOp:
		return providers.NewError(reasonUnknownOperation, false, r.refusal, nil)
	case helperproto.CodeSuperseded:
		return providers.NewError(reasonSuperseded, false, r.refusal, nil)
	}
	return asProviderError(mapHelper(r.refusal, helperproto.SubNginxRestore))
}

// verifyOld checks the previous certificate after a rollback (the helper's own or the inline one);
// d.out is rolled_back. A wrong certificate served makes it rollback_failed with Phase restored and
// FailedStep verify_old (the files are back, the website does not serve them); a website that
// cannot be checked leaves it rolled_back with Verified "" (the helper restored and reloaded). A
// DeployRequest has no previous chain length, so only the previous leaf is compared.
func (d *deployment) verifyOld(ctx context.Context) (providers.DeployOutcome, error) {
	req := d.req
	v, ok := d.s.checkOld(ctx, d.log, providers.VerifyRequest{Location: req.Location, Fingerprint: req.OldFingerprint,
		SANs: req.OldSANs, KeyType: req.KeyType, Verify: req.Verify})
	d.out.Steps = append(d.out.Steps, v.step)
	if !ok {
		d.out.Result, d.out.FailedStep = providers.DeployRollbackFailed, providers.StepNameVerifyOld
		d.out.Reason, d.out.Params = reasonRollbackFailed, map[string]string{"backup_dir": d.out.Backup.Dir}
		return d.out, nil
	}
	d.out.Verified = v.mode
	return d.out, nil
}

// oldCheck is the result of checking the previous certificate after a rollback.
type oldCheck struct {
	step providers.DeployStep
	mode string // Verified: "remote", "local", "skipped" or "" (not checked)
}

// checkOld verifies the previous certificate (step verify_old). ok is false only when the website
// serves another certificate; nothing to compare (no previous fingerprint), a skipped verification
// and a website that cannot be checked are ok with mode "skipped" or "".
func (s *session) checkOld(ctx context.Context, log providers.StepLogger, vreq providers.VerifyRequest) (oldCheck, bool) {
	if vreq.Fingerprint == "" {
		step(log, providers.StepNameVerifyOld, providers.StepSkipped, nil)
		return oldCheck{step: providers.DeployStep{Name: providers.StepNameVerifyOld, Status: providers.StepSkipped}}, true
	}
	step(log, providers.StepNameVerifyOld, providers.StepStarted, nil)
	vr, err := s.VerifyDeployment(ctx, vreq)
	if err != nil {
		vr = unverifiable(vreq.Location, vreq.Verify, vreq.SANs) // not checkable: the port it would have probed
	}
	switch {
	case !vr.OK && vr.Reason == reasonVerifyUnreachable:
		step(log, providers.StepNameVerifyOld, providers.StepFailed, map[string]string{"port": vr.Params["port"]})
		return oldCheck{step: providers.DeployStep{Name: providers.StepNameVerifyOld, Status: providers.StepFailed}}, true
	case !vr.OK:
		step(log, providers.StepNameVerifyOld, providers.StepFailed, map[string]string{"port": vr.Params["port"]})
		return oldCheck{step: providers.DeployStep{Name: providers.StepNameVerifyOld, Status: providers.StepFailed}}, false
	case vr.Mode == "skipped":
		step(log, providers.StepNameVerifyOld, providers.StepSkipped, nil)
		return oldCheck{step: providers.DeployStep{Name: providers.StepNameVerifyOld, Status: providers.StepSkipped}, mode: vr.Mode}, true
	}
	step(log, providers.StepNameVerifyOld, providers.StepOK, map[string]string{"mode": vr.Mode})
	return oldCheck{step: providers.DeployStep{Name: providers.StepNameVerifyOld, Status: providers.StepOK}, mode: vr.Mode}, true
}

// failedReason is the reason of the helper's own rollback by the step that started it.
func failedReason(step, class string) string {
	switch {
	case step == helperproto.StepConfigTest && class == helperproto.ConfigErrKeyMismatch:
		return reasonKeyMismatch // F-01's message
	case step == helperproto.StepConfigTest:
		return reasonConfigTestFailed
	case step == helperproto.StepReload:
		return reasonReloadFailed
	}
	return reasonInterrupted // write_key, write_cert or journal failed inside the transaction
}

// rollbackReason is the reason of a rollback that failed at step.
func rollbackReason(step string) string {
	if step == helperproto.StepRollbackReload {
		return reasonRollbackReloadFailed // F-04: files back, Nginx not reloaded
	}
	return reasonRollbackFailed
}

// restoreResult is one nginx-restore sorted: a refusal (refusal != nil, code), or an answer (phase,
// failedStep, causeStep and class as the helper gave them, this call's steps), or forbidden: the
// rollback guard refused it before anything was sent (R48). An uncertain call is restore's error.
type restoreResult struct {
	forbidden                    bool
	refusal                      *providers.Error
	code                         string
	phase                        string
	failedStep, causeStep, class string
	steps                        []providers.DeployStep
}

// restore runs nginx-restore for op once (a newly built command) and checks the answer against the
// helper's contract; the error is an uncertain outcome. The steps are reported to log.
//
// The rollback guard (R48): a helper of RollbackGuardMinProtocol gets the lists on stdin and checks
// the backup itself (restore_forbidden); an older one gets the plain command, unless the guard
// refuses an unchecked restore (forbidden: nothing is sent).
func (s *session) restore(ctx context.Context, op uuid.UUID, guard providers.RollbackGuard, log providers.StepLogger) (restoreResult, error) {
	const sub = helperproto.SubNginxRestore
	cmd, err := linuxssh.CmdNginxRestore(op)
	if guardNeeded(guard) {
		if !validGuard(guard) {
			return restoreResult{refusal: providers.NewError(reasonUnexpected, false, errors.New("nginx: the rollback guard is not a list the helper takes"), nil)}, nil
		}
		guarded, _, perr := s.Conn().GuardsRollback(ctx)
		switch {
		case perr != nil:
			return restoreResult{}, perr // nothing was restored; the caller does not know more than before
		case guarded && !guard.Empty():
			cmd, err = linuxssh.CmdNginxRestoreGuarded(op, restoreInput(guard))
		case !guarded && guard.RefusesUnchecked():
			return restoreResult{forbidden: true}, nil
		}
	}
	if err != nil {
		return restoreResult{refusal: providers.NewError(reasonUnexpected, false, err, nil)}, nil
	}
	if err := ctx.Err(); err != nil {
		return restoreResult{refusal: providers.NewError("ssh.timeout", true, err, map[string]string{"subcommand": sub})}, nil
	}
	res, runErr := s.Conn().Run(ctx, cmd)
	c := decodeCall[helperproto.NginxRestoreResponse](res, runErr, sub, restoreRefusals)
	switch {
	case c.uncertain != nil:
		return restoreResult{}, c.uncertain
	case c.refusal != nil:
		return restoreResult{refusal: c.refusal, code: c.code}, nil
	}
	a := c.answer
	steps, ok := toSteps(a.Steps)
	if !ok {
		return restoreResult{}, protocolError(sub, "steps outside the helper's vocabulary")
	}
	switch a.Phase {
	case helperproto.PhaseFenced:
		// Fenced by a recovery (AUD-05): the operation never ran, nothing was restored (as for an
		// unknown operation: a refusal, never "nothing to restore" of a journal that exists).
		if len(steps) > 0 {
			return restoreResult{}, protocolError(sub, "a fenced operation with steps")
		}
		return restoreResult{refusal: providers.NewError(reasonUnknownOperation, false, nil, nil), code: helperproto.CodeUnknownOp}, nil
	case helperproto.PhasePrepared, helperproto.PhaseUnchanged:
		if len(steps) > 0 {
			return restoreResult{}, protocolError(sub, "nothing to restore, with steps")
		}
	case helperproto.PhaseRestored:
		// failed_step, cause_step and error echo the deployment's journal: not this call's.
		if anyFailed(steps) {
			return restoreResult{}, protocolError(sub, "restored with a failed step")
		}
	case helperproto.PhaseRestoreFailed:
		if !restoreFailedShape(a.FailedStep, a.CauseStep, a.Error) {
			return restoreResult{}, protocolError(sub, "a restore_failed answer outside the helper's contract")
		}
	case helperproto.PhaseRestoreForbidden:
		// R48: the guard refused the restore (now, or in an earlier call: answered as recorded).
		if !forbiddenShape(a.FailedStep, a.CauseStep, a.Error) || slices.ContainsFunc(steps, func(st providers.DeployStep) bool { return st.Status != providers.StepFailed }) {
			return restoreResult{}, protocolError(sub, "a restore_forbidden answer outside the helper's contract")
		}
	default:
		return restoreResult{}, protocolError(sub, "an unknown phase")
	}
	logSteps(log, steps)
	return restoreResult{phase: a.Phase, failedStep: a.FailedStep, causeStep: a.CauseStep, class: a.Error, steps: steps}, nil
}

// RollbackDeployment restores the files an operation replaced (nginx-restore) and verifies the
// previous certificate (req.OldFingerprint, req.OldChainLength). It is idempotent: a restored
// operation answers restored again without a reload. Every return is a legal shape
// (providers.RollbackOutcome.Validate, CheckRollbackReturn):
//
//   - restored, the previous certificate verified (or not checkable): rolled_back, Phase restored,
//     no failed_step, cause_step or error (the helper echoes the deployment's; they are dropped);
//   - restored, another certificate served: rollback_failed, Phase restored, FailedStep verify_old;
//   - restore_failed: rollback_failed, Phase restore_failed, the helper's failed_step, cause_step
//     and error (failed_step restore with error file_changed: a file was put back, then the other
//     one was found changed by someone else, A1-I2: partly restored);
//   - HASH_MISMATCH (someone else's file found before any rename; nothing restored):
//     rollback_failed, Phase "", FailedStep restore, Error file_changed;
//   - the rollback guard refused (R48; req.Guard): rollback_failed deployment.rollback_forbidden,
//     failed_step restore, error forbidden, Phase restore_forbidden (the helper's answer, cause_step
//     the journal's) or "" (nothing was sent to a helper that cannot check the guard itself);
//   - nothing to restore (prepared, unchanged): no_change with that Phase and a nil error;
//   - UNKNOWN_OP, SUPERSEDED and every other well-formed refusal, and a refusal before sending:
//     no_change, Phase "", a *providers.Error ("nothing was restored", not "files unchanged");
//   - anything else: uncertain with the error.
func (s *session) RollbackDeployment(ctx context.Context, req providers.RollbackRequest, log providers.StepLogger) (providers.RollbackOutcome, error) {
	refuse := func(e *providers.Error) (providers.RollbackOutcome, error) {
		return providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: e.Code, Params: maps.Clone(e.Params)}, e
	}
	if err := s.Live(); err != nil {
		return refuse(asProviderError(err))
	}
	r, err := s.restore(ctx, req.OperationID, req.Guard, log)
	if err != nil {
		return providers.RollbackOutcome{Result: providers.DeployUncertain}, err
	}
	if r.forbidden || r.phase == helperproto.PhaseRestoreForbidden {
		out := providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: providers.StepNameRestore, Error: providers.DeployErrForbidden,
			Reason: providers.ReasonRollbackForbidden, Params: map[string]string{}}
		if !r.forbidden {
			out.Phase, out.CauseStep, out.Steps = providers.PhaseRestoreForbidden, r.causeStep, r.steps
		}
		return out, nil
	}
	backup := map[string]string{"backup_dir": backupDir(req.OperationID)}
	if r.refusal != nil {
		switch r.code {
		case helperproto.CodeHashMismatch:
			return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: providers.StepNameRestore,
				Error: providers.DeployErrFileChanged, Reason: reasonRollbackFailed, Params: backup}, nil
		}
		return refuse(restoreRefusalError(r))
	}
	switch r.phase {
	case helperproto.PhasePrepared, helperproto.PhaseUnchanged:
		return providers.RollbackOutcome{Result: providers.DeployNoChange, Phase: r.phase, Reason: reasonNothingToRestore}, nil
	case helperproto.PhaseRestoreFailed:
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: r.failedStep,
			CauseStep: r.causeStep, Error: r.class, Steps: r.steps, Reason: rollbackReason(r.failedStep), Params: backup}, nil
	}
	out := providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Steps: r.steps}
	v, ok := s.checkOld(ctx, log, providers.VerifyRequest{Location: req.Location, Fingerprint: req.OldFingerprint, ChainLength: req.OldChainLength,
		SANs: req.OldSANs, KeyType: req.KeyType, Verify: req.Verify})
	out.Steps = append(out.Steps, v.step)
	if !ok {
		out.Result, out.FailedStep, out.Reason, out.Params = providers.DeployRollbackFailed, providers.StepNameVerifyOld, reasonRollbackFailed, backup
		return out, nil
	}
	out.Verified = v.mode
	return out, nil
}

// DeploymentStatus reads an operation's journal on the server (nginx-status). The answer is checked
// against the helper's vocabulary and DeploymentState.Validate; one that breaks them is an
// ssh.protocol_error, never a state. Phase none carries nothing but Active (the helper still names
// the backup directory then); every other phase's BackupDir is the operation's directory.
func (s *session) DeploymentStatus(ctx context.Context, op uuid.UUID) (providers.DeploymentState, error) {
	const sub = helperproto.SubNginxStatus
	if err := s.Live(); err != nil {
		return providers.DeploymentState{}, err
	}
	cmd, err := linuxssh.CmdNginxStatus(op)
	if err != nil {
		return providers.DeploymentState{}, providers.NewError(reasonUnexpected, false, err, nil)
	}
	return s.stateCall(ctx, sub, cmd, op)
}

// FenceDeployment fences an operation on the server (nginx-fence, AUD-05): under the helper's lock
// an operation without a journal, or with a prepared one, gets a tombstone, after which
// nginx-deploy of it refuses without writing. The answer is checked like nginx-status's. Only
// PhaseFenced with a nil error proves that the operation wrote nothing and never will; any error
// (transport, BUSY, sudo's refusal of a server whose sudoers lacks the line, a protocol error) proves
// nothing. A helper older than protocol 5 never gets here: Open refuses it (ssh.helper_outdated).
func (s *session) FenceDeployment(ctx context.Context, op uuid.UUID) (providers.DeploymentState, error) {
	const sub = helperproto.SubNginxFence
	if err := s.Live(); err != nil {
		return providers.DeploymentState{}, err
	}
	cmd, err := linuxssh.CmdNginxFence(op)
	if err != nil {
		return providers.DeploymentState{}, providers.NewError(reasonUnexpected, false, err, nil)
	}
	st, err := s.stateCall(ctx, sub, cmd, op)
	if err == nil && st.Active && st.Phase == providers.PhaseFenced {
		return providers.DeploymentState{}, protocolError(sub, "a fence answered while another helper held the lock")
	}
	return st, err
}

// stateCall runs nginx-status or nginx-fence and checks the answer (see DeploymentStatus).
func (s *session) stateCall(ctx context.Context, sub string, cmd linuxssh.HelperCommand, op uuid.UUID) (providers.DeploymentState, error) {
	res, err := s.Conn().Run(ctx, cmd)
	if err != nil {
		return providers.DeploymentState{}, err
	}
	r, err := linuxssh.DecodeHelper[helperproto.NginxStatusResponse](res, sub)
	if err != nil {
		return providers.DeploymentState{}, mapHelper(err, sub)
	}
	switch {
	case !slices.Contains(helperPhases, r.Phase):
		return providers.DeploymentState{}, protocolError(sub, "an unknown phase")
	case r.Phase == helperproto.PhaseNone:
		return providers.DeploymentState{Phase: providers.PhaseNone, Active: r.Active}, nil
	case r.Phase == helperproto.PhaseFenced:
		if r.FailedStep != "" || r.CauseStep != "" || r.Error != "" || r.NewCertSHA256 != "" || r.CurrentCertSHA256 != "" {
			return providers.DeploymentState{}, protocolError(sub, "a fenced operation with a journal's fields")
		}
		return providers.DeploymentState{Phase: providers.PhaseFenced, Active: r.Active, BackupDir: backupDir(op)}, nil
	case (r.FailedStep != "" && !slices.Contains(helperSteps, r.FailedStep)) || (r.CauseStep != "" && !slices.Contains(helperSteps, r.CauseStep)) ||
		!knownClass(r.Error, true) || !isHexSHA256(r.NewCertSHA256) || (r.CurrentCertSHA256 != "" && !isHexSHA256(r.CurrentCertSHA256)):
		return providers.DeploymentState{}, protocolError(sub, "a journal outside the helper's vocabulary")
	}
	st := providers.DeploymentState{Phase: r.Phase, Active: r.Active, FailedStep: r.FailedStep, CauseStep: r.CauseStep, Error: r.Error,
		NewCertSHA256: r.NewCertSHA256, CurrentCertSHA256: r.CurrentCertSHA256, BackupDir: backupDir(op)}
	if err := st.Validate(); err != nil {
		return providers.DeploymentState{}, protocolError(sub, "a journal state that breaks the invariants")
	}
	return st, nil
}
