package inventory_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
)

func okSteps(names ...string) []providers.DeployStep {
	var out []providers.DeployStep
	for _, n := range names {
		out = append(out, providers.DeployStep{Name: n, Status: providers.StepOK})
	}
	return out
}

func failed(name, class string) providers.DeployStep {
	return providers.DeployStep{Name: name, Status: providers.StepFailed, Error: class}
}

// rec is the part of an OutcomeRecord a row of the tables below names.
type rec struct {
	terminal      bool
	retryRollback bool
	status        string
	result        string
	phase         string
	failedStep    string
	causeStep     string
	helperError   string
	verified      string
	errorCode     string
	verifyReason  string
	verifyPort    int
}

func recOf(r inventory.OutcomeRecord) rec {
	out := rec{terminal: r.Terminal, retryRollback: r.RetryRollback, status: r.Finish.Status, result: r.Finish.Result, phase: r.Finish.Phase,
		failedStep: r.Finish.FailedStep, causeStep: r.Finish.CauseStep, helperError: r.Finish.HelperError, verified: r.Finish.Verified,
		errorCode: r.Finish.ErrorCode, verifyReason: r.Finish.VerifyFailedReason}
	if r.Finish.VerifyFailedPort != nil {
		out.verifyPort = *r.Finish.VerifyFailedPort
	}
	return out
}

// Every legal DeployOutcome shape (outcome.go's table and Task 11's mapping) has exactly one record;
// only committed or unchanged with a verification is a success; an uncertain shape is never
// terminal.
func TestDeployOutcomeRecordCoversEveryLegalShape(t *testing.T) {
	refusal := providers.NewError("nginx.no_space", false, nil, nil)
	unsupported := providers.NewError("nginx.location_unsupported", false, nil, nil)
	verifyFailed := providers.NewError("deployment.verify_failed", false, nil, map[string]string{"port": "443"})
	lost := errors.New("connection lost")
	base := okSteps("backup", "write_key", "write_cert", "config_test", "reload")
	uncertain := rec{status: "", result: "uncertain", errorCode: "deployment.interrupted"}
	for name, tc := range map[string]struct {
		o    providers.DeployOutcome
		err  error
		want rec
	}{
		"1 provider-side refusal": {providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.location_unsupported"}, unsupported,
			rec{terminal: true, status: "failed", result: "no_change", errorCode: "nginx.location_unsupported"}},
		"2 helper refusal": {providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.no_space"}, refusal,
			rec{terminal: true, status: "failed", result: "no_change", errorCode: "nginx.no_space"}},
		"3 committed, verified": {providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted,
			Steps: append(append([]providers.DeployStep{}, base...), okSteps("verify")...), Verified: "remote"}, nil,
			rec{terminal: true, status: "succeeded", result: "committed", phase: "committed", verified: "remote"}},
		"3 committed, verification skipped by the Administrator": {providers.DeployOutcome{Result: providers.DeployCommitted,
			Phase: providers.PhaseCommitted, Verified: "skipped"}, nil,
			rec{terminal: true, status: "succeeded", result: "committed", phase: "committed", verified: "skipped"}},
		"3 committed without a verification: uncertain": {providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted},
			nil, uncertain},
		"3b unchanged, verified": {providers.DeployOutcome{Result: providers.DeployUnchanged, Phase: providers.PhaseUnchanged,
			Steps: okSteps("backup", "verify"), Verified: "local"}, nil,
			rec{terminal: true, status: "unchanged", result: "unchanged", phase: "unchanged", verified: "local"}},
		"3b unchanged without a verification: uncertain": {providers.DeployOutcome{Result: providers.DeployUnchanged}, nil, uncertain},
		"3c unchanged, verification failed: nothing changed": {providers.DeployOutcome{Result: providers.DeployNoChange, Phase: providers.PhaseUnchanged,
			FailedStep: "verify", Reason: "deployment.verify_failed", Params: map[string]string{"port": "443"},
			Steps: append(okSteps("backup"), failed("verify", ""))}, verifyFailed,
			rec{terminal: true, status: "failed", result: "no_change", phase: "unchanged", failedStep: "verify", errorCode: "deployment.verify_failed",
				verifyReason: "deployment.verify_failed", verifyPort: 443}},
		"4 committed, verify failed, rolled back": {providers.DeployOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored,
			FailedStep: "verify", CauseStep: "verify", Reason: "deployment.verify_failed", Params: map[string]string{"port": "8443"}, Verified: "remote"}, nil,
			rec{terminal: true, status: "rolled_back", result: "rolled_back", phase: "restored", failedStep: "verify", causeStep: "verify",
				verified: "remote", errorCode: "deployment.verify_failed", verifyReason: "deployment.verify_failed", verifyPort: 8443}},
		"5 files back, old does not verify": {providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestored,
			FailedStep: "verify_old", CauseStep: "verify", Reason: "deployment.rollback_failed"}, nil,
			rec{terminal: true, status: "rollback_failed", result: "rollback_failed", phase: "restored", failedStep: "verify_old", causeStep: "verify",
				errorCode: "deployment.rollback_failed"}},
		"6 helper restored after its config test": {providers.DeployOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored,
			FailedStep: "config_test", CauseStep: "config_test", Error: providers.ConfigErrKeyMismatch, Reason: "certificate.key_mismatch"}, nil,
			rec{terminal: true, status: "rolled_back", result: "rolled_back", phase: "restored", failedStep: "config_test", causeStep: "config_test",
				helperError: "key_mismatch", errorCode: "certificate.key_mismatch"}},
		"6b helper restored after a killed nginx": {providers.DeployOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored,
			FailedStep: "reload", CauseStep: "reload", Reason: "deployment.reload_failed"}, nil,
			rec{terminal: true, status: "rolled_back", result: "rolled_back", phase: "restored", failedStep: "reload", causeStep: "reload",
				errorCode: "deployment.reload_failed"}},
		"7a restore_failed, file changed": {providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed,
			FailedStep: "reload", CauseStep: "reload", Error: providers.DeployErrFileChanged, Reason: "deployment.rollback_file_changed"}, nil,
			rec{terminal: true, retryRollback: true, status: "rollback_failed", result: "rollback_failed", phase: "restore_failed", failedStep: "reload",
				causeStep: "reload", helperError: "file_changed", errorCode: "deployment.rollback_file_changed"}},
		"7b restore_failed, restore step": {providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed,
			FailedStep: "restore", CauseStep: "config_test", Reason: "deployment.rollback_failed"}, nil,
			rec{terminal: true, retryRollback: true, status: "rollback_failed", result: "rollback_failed", phase: "restore_failed", failedStep: "restore",
				causeStep: "config_test", errorCode: "deployment.rollback_failed"}},
		"7c restore_failed, rollback reload": {providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed,
			FailedStep: "rollback_reload", CauseStep: "reload", Reason: "deployment.rollback_reload_failed"}, nil,
			rec{terminal: true, retryRollback: true, status: "rollback_failed", result: "rollback_failed", phase: "restore_failed",
				failedStep: "rollback_reload", causeStep: "reload", errorCode: "deployment.rollback_reload_failed"}},
		"7d restore_failed, rollback config test": {providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed,
			FailedStep: "rollback_config_test", CauseStep: "reload", Error: providers.ConfigErrSyntax, Reason: "deployment.rollback_config_invalid"}, nil,
			rec{terminal: true, retryRollback: true, status: "rollback_failed", result: "rollback_failed", phase: "restore_failed",
				failedStep: "rollback_config_test", causeStep: "reload", helperError: "syntax", errorCode: "deployment.rollback_config_invalid"}},
		"rollback_failed, phase blank (hash mismatch on restore)": {providers.DeployOutcome{Result: providers.DeployRollbackFailed,
			FailedStep: "restore", CauseStep: "verify", Error: providers.DeployErrFileChanged, Reason: "deployment.rollback_failed"}, nil,
			rec{terminal: true, status: "rollback_failed", result: "rollback_failed", failedStep: "restore", causeStep: "verify",
				helperError: "file_changed", errorCode: "deployment.rollback_failed"}},
		"8 uncertain": {providers.DeployOutcome{Result: providers.DeployUncertain, Steps: okSteps("backup")}, lost, uncertain},
		"8 uncertain with the provider's reason": {providers.DeployOutcome{Result: providers.DeployUncertain},
			providers.NewError("ssh.timeout", true, nil, nil), rec{result: "uncertain", errorCode: "ssh.timeout"}},
		// A killed helper, a dropped connection and a malformed answer reach Alice as protocol errors
		// or "helper missing" (no JSON at an exit status): neither text is true of a deployment being
		// recovered, so the record says only that the outcome is not known.
		"8 uncertain, lost or malformed answer": {providers.DeployOutcome{Result: providers.DeployUncertain},
			providers.NewError("ssh.protocol_error", false, nil, map[string]string{"subcommand": "nginx-deploy"}),
			rec{result: "uncertain", errorCode: "deployment.interrupted"}},
		"8 uncertain, killed helper (exit 137)": {providers.DeployOutcome{Result: providers.DeployUncertain},
			providers.NewError("ssh.helper_missing", false, nil, map[string]string{"exit_code": "137"}),
			rec{result: "uncertain", errorCode: "deployment.interrupted"}},
		"8 uncertain, unreachable": {providers.DeployOutcome{Result: providers.DeployUncertain},
			providers.NewError("ssh.unreachable", true, nil, nil), rec{result: "uncertain", errorCode: "ssh.unreachable"}},
		"8 uncertain after a failed verification": {providers.DeployOutcome{Result: providers.DeployUncertain, Reason: "deployment.verify_other",
			Params: map[string]string{"port": "443", "failed_step": "verify"}}, providers.NewError("nginx.busy", true, nil, nil),
			rec{result: "uncertain", errorCode: "deployment.verify_other", verifyReason: "deployment.verify_other", verifyPort: 443}},
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, providers.CheckDeployReturn(tc.o, tc.err), "the row is a legal shape")
			got := inventory.DeployOutcomeRecord(tc.o, tc.err, false)
			assert.Equal(t, tc.want, recOf(got))
			assert.NotNil(t, got.Finish.Params)
			if got.Terminal && (got.Finish.Status == "succeeded" || got.Finish.Status == "unchanged") {
				assert.NotEmpty(t, got.Finish.Verified, "success only when verified")
			}
		})
	}
}

// On a re-sent operation no_change means "this call changed nothing", not "nothing changed":
// uncertain. An invalid outcome, an illegal pairing with the error or ErrUnsupported is uncertain.
func TestDeployOutcomeRecordTreatsTheUnknownAsUncertain(t *testing.T) {
	refusal := providers.NewError("nginx.no_space", false, nil, nil)
	noChange := providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.no_space"}
	r := inventory.DeployOutcomeRecord(noChange, refusal, true)
	assert.False(t, r.Terminal)
	assert.Equal(t, "uncertain", r.Finish.Result)
	for name, tc := range map[string]struct {
		o   providers.DeployOutcome
		err error
	}{
		"zero":                              {providers.DeployOutcome{}, nil},
		"unknown result":                    {providers.DeployOutcome{Result: "done"}, nil},
		"committed with an error":           {providers.DeployOutcome{Result: providers.DeployCommitted, Verified: "remote"}, errors.New("x")},
		"refusal without an error":          {noChange, nil},
		"refusal with a plain error":        {noChange, errors.New("x")},
		"committed with a failed step":      {providers.DeployOutcome{Result: providers.DeployCommitted, FailedStep: "reload", Verified: "remote"}, nil},
		"rolled back without a failed step": {providers.DeployOutcome{Result: providers.DeployRolledBack, Reason: "r"}, nil},
		"unsupported":                       {providers.DeployOutcome{}, providers.ErrUnsupported},
		"uncertain without an error":        {providers.DeployOutcome{Result: providers.DeployUncertain}, nil},
	} {
		r := inventory.DeployOutcomeRecord(tc.o, tc.err, false)
		assert.False(t, r.Terminal, name)
		assert.Empty(t, r.Finish.Status, name)
		assert.Equal(t, "uncertain", r.Finish.Result, name)
		assert.Equal(t, "deployment.interrupted", r.Finish.ErrorCode, name)
	}
}

func TestRollbackOutcomeRecordCoversEveryLegalShape(t *testing.T) {
	cause := "deployment.verify_failed"
	pe := func(code string) error { return providers.NewError(code, code == "nginx.busy", nil, nil) }
	uncertain := rec{result: "uncertain", errorCode: "deployment.interrupted"}
	for name, tc := range map[string]struct {
		o    providers.RollbackOutcome
		err  error
		want rec
	}{
		"restored and verified": {providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Verified: "remote"}, nil,
			rec{terminal: true, status: "rolled_back", result: "rolled_back", phase: "restored", verified: "remote", errorCode: cause}},
		"restored, old not checkable": {providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}, nil,
			rec{terminal: true, status: "rolled_back", result: "rolled_back", phase: "restored", errorCode: cause}},
		"restored, old does not verify": {providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestored,
			FailedStep: "verify_old", Reason: "deployment.rollback_failed"}, nil,
			rec{terminal: true, status: "rollback_failed", result: "rollback_failed", phase: "restored", failedStep: "verify_old",
				errorCode: "deployment.rollback_failed"}},
		"hash mismatch on restore": {providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore",
			Error: providers.DeployErrFileChanged, Reason: "deployment.rollback_failed"}, nil,
			rec{terminal: true, status: "rollback_failed", result: "rollback_failed", failedStep: "restore", helperError: "file_changed",
				errorCode: "deployment.rollback_failed"}},
		"restore_failed": {providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed,
			FailedStep: "rollback_reload", CauseStep: "reload", Reason: "deployment.rollback_reload_failed"}, nil,
			rec{terminal: true, retryRollback: true, status: "rollback_failed", result: "rollback_failed", phase: "restore_failed",
				failedStep: "rollback_reload", causeStep: "reload", errorCode: "deployment.rollback_reload_failed"}},
		"nothing to restore, prepared: nothing was written": {providers.RollbackOutcome{Result: providers.DeployNoChange, Phase: providers.PhasePrepared,
			Reason: "deployment.nothing_to_restore"}, nil,
			rec{terminal: true, status: "failed", result: "no_change", phase: "prepared", errorCode: cause}},
		"nothing to restore, unchanged: the files held the new certificate before": {providers.RollbackOutcome{Result: providers.DeployNoChange,
			Phase: providers.PhaseUnchanged, Reason: "deployment.nothing_to_restore"}, nil,
			rec{terminal: true, status: "failed", result: "no_change", phase: "unchanged", errorCode: cause}},
		"superseded is final": {providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "deployment.superseded"}, pe("deployment.superseded"),
			rec{terminal: true, status: "rollback_failed", result: "no_change", errorCode: "deployment.superseded"}},
		"unknown operation: the journal decides": {providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "deployment.unknown_operation"},
			pe("deployment.unknown_operation"), rec{result: "uncertain", errorCode: "deployment.unknown_operation"}},
		"busy: nothing was restored, retried": {providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "nginx.busy"}, pe("nginx.busy"),
			rec{result: "uncertain", errorCode: "nginx.busy"}},
		"sudo refused": {providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "nginx.profile_missing"}, pe("nginx.profile_missing"),
			rec{result: "uncertain", errorCode: "nginx.profile_missing"}},
		"uncertain": {providers.RollbackOutcome{Result: providers.DeployUncertain}, errors.New("lost"), uncertain},
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, providers.CheckRollbackReturn(tc.o, tc.err), "the row is a legal shape")
			got := inventory.RollbackOutcomeRecord(tc.o, tc.err, cause)
			assert.Equal(t, tc.want, recOf(got))
			assert.NotEqual(t, "succeeded", got.Finish.Status)
		})
	}
	for i, tc := range []struct {
		o   providers.RollbackOutcome
		err error
	}{
		{providers.RollbackOutcome{}, nil},
		{providers.RollbackOutcome{Result: providers.DeployCommitted}, nil},
		{providers.RollbackOutcome{Result: providers.DeployRolledBack}, errors.New("x")},
		{providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "deployment.superseded"}, nil},
		{providers.RollbackOutcome{Result: providers.DeployNoChange, Phase: providers.PhasePrepared, Reason: "r"}, providers.NewError("x", false, nil, nil)},
		{providers.RollbackOutcome{}, providers.ErrUnsupported},
	} {
		r := inventory.RollbackOutcomeRecord(tc.o, tc.err, cause)
		assert.False(t, r.Terminal, fmt.Sprint(i))
		assert.Equal(t, "uncertain", r.Finish.Result, fmt.Sprint(i))
	}
	r := inventory.RollbackOutcomeRecord(providers.RollbackOutcome{Result: providers.DeployRolledBack}, nil, "")
	assert.Equal(t, "deployment.interrupted", r.Finish.ErrorCode, "a rollback without a recorded cause was an interruption")
}

// The statuses keep the meanings the changed-outside check relies on (aliceFingerprints): every
// terminal status a record can carry is one of the five it knows.
func TestOutcomeStatusesAreKnownToDiscovery(t *testing.T) {
	known := map[string]bool{"succeeded": true, "unchanged": true, "failed": true, "rolled_back": true, "rollback_failed": true}
	for _, s := range inventory.TerminalStatuses() {
		assert.True(t, known[s], s)
	}
	assert.Len(t, inventory.TerminalStatuses(), 5)
}
