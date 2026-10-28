package windows

import (
	"errors"
	"maps"
	"time"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/windows/winproto"
)

// The reasons of the Windows provider: W1's three (ALC-WIN-0001..0003) and W2's (ALC-WIN-0004..0012, R61
// Ruling 6). Every helper code has a reason of its own (mapHelper); nothing of the Windows provider is
// ssh.helper_refused any more.
const (
	ReasonHelperMissing  = "windows.helper_missing"
	ReasonHelperOutdated = "windows.helper_outdated"
	ReasonNotElevated    = "windows.not_elevated"

	ReasonBindingChanged      = "windows.binding_changed"      // HASH_MISMATCH: the record names another certificate than expected (retryable: rediscover)
	ReasonBindingNotFound     = "windows.binding_not_found"    // BINDING_NOT_FOUND: http.sys holds no record for the locator
	ReasonBusy                = "windows.busy"                 // BUSY: another helper process held helper.lock (retryable)
	ReasonIOError             = "windows.io_error"             // IO_ERROR, JOURNAL_FAILED (retryable)
	ReasonStoreError          = "windows.store_error"          // STORE_ERROR: a certificate store could not be opened
	ReasonKeyUnusable         = "windows.key_unusable"         // KEY_UNUSABLE, and http.sys's 1312 at the bind
	ReasonBackupMissing       = "windows.backup_missing"       // BACKUP_MISSING: the previous certificate is not in its store with a usable key
	ReasonLocationUnsupported = "windows.location_unsupported" // a locator Alice does not deploy to (W2 Ruling 5)
	ReasonHelperRefused       = "windows.helper_refused"       // every other helper code; param helper_code

	// ReasonCleanupOutcomeUnknown (W3, ALC-WIN-0014): iis-cleanup answered OUTCOME_UNKNOWN (its budget
	// ended after its first durable write); retryable, the next plan settles it (R62 Ruling 12).
	ReasonCleanupOutcomeUnknown = "windows.cleanup_outcome_unknown"

	// The Centralized Certificate Store's reasons (W5, R68: ALC-WIN-0015..0018 and 0020). CCS_PATH_UNSUPPORTED
	// is windows.location_unsupported: the folder is not one Alice deploys to.
	ReasonCCSDisabled         = "windows.ccs_disabled"          // CCS_DISABLED: IIS has CCS off now
	ReasonCCSPathChanged      = "windows.ccs_path_changed"      // CCS_PATH_CHANGED: the registry names another folder (rediscover)
	ReasonCCSPasswordMismatch = "windows.ccs_password_mismatch" // CCS_PASSWORD_MISMATCH: Alice's password does not open the file
	ReasonCCSPasswordMissing  = "windows.ccs_password_missing"  // Alice holds no CCS password of the server (refused before sending)
	ReasonCCSFileNotFound     = "windows.ccs_file_not_found"    // CCS_FILE_NOT_FOUND: the folder holds no file for the host

	// The Remote Desktop listener's reasons (W6, R69: ALC-WIN-0021..0023).
	ReasonRDPDisabled     = "windows.rdp_disabled"       // RDP_DISABLED: Remote Desktop is off now
	ReasonRDPTLSOff       = "windows.rdp_tls_off"        // RDP_TLS_OFF: the listener's security layer offers no TLS
	ReasonRDPKeyACLFailed = "windows.rdp_key_acl_failed" // error class key_acl: NETWORK SERVICE could not be given read access to the key
)

// The engine's own reasons the helper's codes map to (Ruling 6), so its recovery paths work unchanged.
const (
	reasonRecoveryPending  = "deployment.recovery_pending" // param operation_id
	reasonInterrupted      = "deployment.interrupted"
	reasonSuperseded       = "deployment.superseded"
	reasonUnknownOperation = "deployment.unknown_operation"
	reasonUnexpected       = "internal.unexpected"
)

// helperReasons names the reason of each helper code with its retryability (W2 Ruling 6).
var helperReasons = map[string]struct {
	reason    string
	retryable bool
}{
	winproto.CodeUnknownSubcommand: {ReasonHelperOutdated, false},
	winproto.CodeNotElevated:       {ReasonNotElevated, false},
	winproto.CodeHashMismatch:      {ReasonBindingChanged, true},
	winproto.CodeBindingNotFound:   {ReasonBindingNotFound, false},
	winproto.CodeBusy:              {ReasonBusy, true},
	winproto.CodeIOError:           {ReasonIOError, true},
	winproto.CodeJournalFailed:     {ReasonIOError, true},
	winproto.CodeStoreError:        {ReasonStoreError, false},
	winproto.CodeKeyUnusable:       {ReasonKeyUnusable, false},
	winproto.CodeBackupMissing:     {ReasonBackupMissing, false},
	winproto.CodeRecoveryPending:   {reasonRecoveryPending, false},
	winproto.CodeFenced:            {reasonInterrupted, false},
	winproto.CodeSuperseded:        {reasonSuperseded, false},
	winproto.CodeUnknownOp:         {reasonUnknownOperation, false},

	winproto.CodeCCSDisabled:         {ReasonCCSDisabled, false},
	winproto.CodeCCSPathChanged:      {ReasonCCSPathChanged, false},
	winproto.CodeCCSPathUnsupported:  {ReasonLocationUnsupported, false},
	winproto.CodeCCSPasswordMismatch: {ReasonCCSPasswordMismatch, false},
	winproto.CodeCCSFileNotFound:     {ReasonCCSFileNotFound, false},

	winproto.CodeRDPDisabled: {ReasonRDPDisabled, false},
	winproto.CodeRDPTLSOff:   {ReasonRDPTLSOff, false},
}

// mapHelper names the Windows conditions in an error of the shared SSH layer: an exit that is no
// helper exit (cmd.exe's "not recognized", or sshd without the forced command) is helper_missing; a
// helper refusal (DecodeHelper's ssh.helper_refused, or ssh.file_changed for HASH_MISMATCH) gets the
// reason of its code (helperReasons, W2 Ruling 6), every other code windows.helper_refused with
// helper_code. The params are the shared error's (subcommand, helper_code), except RECOVERY_PENDING's:
// operation_id only, as the engine's pending-operation path reads it. The shared error stays the
// cause; anything else (the transport's ssh.* codes, a plain error) is returned unchanged.
func mapHelper(err error) error {
	var pe *providers.Error
	if !errors.As(err, &pe) {
		return err
	}
	code := pe.Params["helper_code"]
	switch {
	case pe.Code == "ssh.helper_missing":
		return providers.NewError(ReasonHelperMissing, false, err, maps.Clone(pe.Params))
	case (pe.Code != "ssh.helper_refused" && pe.Code != "ssh.file_changed") || code == "":
		return err
	case code == winproto.CodeRecoveryPending:
		var params map[string]string
		if op := pe.Params["operation_id"]; op != "" {
			params = map[string]string{"operation_id": op}
		}
		return providers.NewError(reasonRecoveryPending, false, err, params)
	}
	r, ok := helperReasons[code]
	if !ok {
		r.reason = ReasonHelperRefused
	}
	return providers.NewError(r.reason, r.retryable, err, maps.Clone(pe.Params))
}

// asProviderError returns err as a *providers.Error (every error this package maps is one).
func asProviderError(err error) *providers.Error {
	var pe *providers.Error
	if errors.As(err, &pe) {
		return pe
	}
	return providers.NewError(reasonUnexpected, false, err, nil)
}

// protocolError is the error of an answer that breaks the helper's contract: uncertain for a write, an
// error (never a state) for a status.
func protocolError(sub, why string) *providers.Error {
	return providers.NewError("ssh.protocol_error", false, errors.New("windows: "+why), map[string]string{"subcommand": sub})
}

// budget is a command's time budget and output bound.
type budget struct {
	timeout   time.Duration
	maxOutput int64
}

// budgets of the subcommands. iis-dump's helper gives up after winproto.HelperBudget (50 s), before
// Alice's 60 s cut the connection; iis-deploy and iis-restore wait up to winproto.LockWait for the lock
// and finish under winproto.WriteGrace within the long budget too; iis-status takes no lock and
// iis-fence waits at most LockWait, inside the default budget. iis-cleanup's helper runs under
// winproto.HelperBudget (lock wait included) and answers OUTCOME_UNKNOWN when it ends, before Alice's
// long budget cuts the connection; a plan lists at most 256 candidates and as many verdicts as the watch
// list allows, well inside 1 MiB.
var budgets = map[string]budget{
	winproto.SubIISCleanup: {linuxssh.LongCommandTimeout, 1 << 20},
	winproto.SubVersion:    {linuxssh.DefaultCommandTimeout, 64 << 10},
	winproto.SubWinFacts:   {linuxssh.DefaultCommandTimeout, 64 << 10},
	winproto.SubIISDump:    {linuxssh.LongCommandTimeout, winproto.DumpOutput},
	winproto.SubTLSProbe:   {linuxssh.DefaultCommandTimeout, 128 << 10},
	winproto.SubIISDeploy:  {linuxssh.LongCommandTimeout, 64 << 10},
	winproto.SubIISRestore: {linuxssh.LongCommandTimeout, 64 << 10},
	winproto.SubIISStatus:  {linuxssh.DefaultCommandTimeout, 64 << 10},
	winproto.SubIISFence:   {linuxssh.DefaultCommandTimeout, 64 << 10},
	// ccs-dump runs under winproto.HelperBudget like iis-dump; its answer (at most MaxCCSFiles files with their
	// chains) has no bound of its own, so it shares iis-dump's: a longer answer is a failed ccs-dump (Ruling 18).
	winproto.SubCCSDump:   {linuxssh.LongCommandTimeout, winproto.DumpOutput},
	winproto.SubCCSDeploy: {linuxssh.LongCommandTimeout, 64 << 10},
	// rdp-dump reads the listener and at most one certificate with its chain, without a lock (W6 Ruling 18).
	winproto.SubRDPDump:   {linuxssh.DefaultCommandTimeout, 1 << 20},
	winproto.SubRDPDeploy: {linuxssh.LongCommandTimeout, 64 << 10},
}

// cmd builds the forced command line of a subcommand with its standard input (nil for none): the
// protocol's own line check (winproto.JoinCommandLine), then linuxssh's one audited constructor, which
// copies stdin into the command (the caller clears its own buffer; WipeInput clears the copy). A
// subcommand without a budget or a token outside the vocabulary is linuxssh.ErrInvalidArgument.
func cmd(sub string, stdin []byte, args ...string) (linuxssh.HelperCommand, error) {
	b, ok := budgets[sub]
	tokens := append([]string{sub}, args...)
	if _, valid := winproto.JoinCommandLine(tokens); !ok || !valid {
		return linuxssh.HelperCommand{}, linuxssh.ErrInvalidArgument
	}
	return linuxssh.ForcedCommand(tokens, stdin, b.timeout, b.maxOutput)
}
