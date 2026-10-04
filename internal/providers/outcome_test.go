package providers_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
)

func steps(names ...string) []providers.DeployStep {
	var out []providers.DeployStep
	for _, n := range names {
		out = append(out, providers.DeployStep{Name: n, Status: providers.StepOK})
	}
	return out
}

func TestDeployOutcomeValidate(t *testing.T) {
	valid := []struct {
		name string
		o    providers.DeployOutcome
	}{
		{"committed", providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted, Steps: steps("backup"), Verified: "remote"}},
		{"committed without phase", providers.DeployOutcome{Result: providers.DeployCommitted}},
		{"unchanged", providers.DeployOutcome{Result: providers.DeployUnchanged, Phase: providers.PhaseUnchanged, Verified: "local"}},
		{"no change", providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.no_space"}},
		{"rolled back", providers.DeployOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, FailedStep: "config_test", CauseStep: "config_test", Error: providers.ConfigErrKeyMismatch, Reason: "certificate.key_mismatch", Steps: steps("backup", "restore")}},
		{"rollback failed", providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "restore", Error: providers.DeployErrFileChanged, Reason: "deployment.rollback_failed"}},
		{"uncertain", providers.DeployOutcome{Result: providers.DeployUncertain, Steps: steps("backup")}},
	}
	for _, tc := range valid {
		t.Run("valid "+tc.name, func(t *testing.T) { assert.NoError(t, tc.o.Validate()) })
	}
	invalid := []struct {
		name string
		o    providers.DeployOutcome
		want string
	}{
		{"zero value", providers.DeployOutcome{}, "blank or unknown result"},
		{"unknown result", providers.DeployOutcome{Result: "done"}, "blank or unknown result"},
		{"committed with failed step", providers.DeployOutcome{Result: providers.DeployCommitted, FailedStep: "reload"}, "committed: failed_step"},
		{"committed with reason", providers.DeployOutcome{Result: providers.DeployCommitted, Reason: "x"}, "committed: reason"},
		{"committed wrong phase", providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseRestored}, "committed: phase"},
		{"unchanged with error", providers.DeployOutcome{Result: providers.DeployUnchanged, Error: "syntax"}, "unchanged: error"},
		{"unchanged wrong phase", providers.DeployOutcome{Result: providers.DeployUnchanged, Phase: providers.PhaseCommitted}, "unchanged: phase"},
		{"no change with steps", providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "r", Steps: steps("backup")}, "no_change: steps"},
		{"no change with phase", providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "r", Phase: providers.PhaseWriting}, "no_change: phase"},
		{"no change with failed step", providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "r", FailedStep: "backup"}, "no_change: failed_step"},
		{"no change without reason", providers.DeployOutcome{Result: providers.DeployNoChange}, "no_change: reason is required"},
		{"rolled back without failed step", providers.DeployOutcome{Result: providers.DeployRolledBack, Reason: "r"}, "rolled_back: failed_step is required"},
		{"rolled back without reason", providers.DeployOutcome{Result: providers.DeployRolledBack, FailedStep: "reload"}, "rolled_back: reason is required"},
		{"rolled back wrong phase", providers.DeployOutcome{Result: providers.DeployRolledBack, FailedStep: "reload", Reason: "r", Phase: providers.PhaseCommitted}, "rolled_back: phase"},
		{"rollback failed without failed step", providers.DeployOutcome{Result: providers.DeployRollbackFailed, Reason: "r"}, "rollback_failed: failed_step is required"},
		{"rollback failed wrong phase", providers.DeployOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore", Reason: "r", Phase: providers.PhaseCommitted}, "rollback_failed: phase"},
		{"rollback failed without reason", providers.DeployOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore"}, "rollback_failed: reason is required"},
		{"uncertain with phase", providers.DeployOutcome{Result: providers.DeployUncertain, Phase: providers.PhaseWriting}, "uncertain: phase"},
		{"uncertain with failed step", providers.DeployOutcome{Result: providers.DeployUncertain, FailedStep: "reload"}, "uncertain: failed_step"},
		{"step without name", providers.DeployOutcome{Result: providers.DeployCommitted, Steps: []providers.DeployStep{{Status: providers.StepOK}}}, "step 0: no name"},
		{"step with unknown status", providers.DeployOutcome{Result: providers.DeployCommitted, Steps: []providers.DeployStep{{Name: "backup", Status: "weird"}}}, "step 0: unknown status"},
	}
	for _, tc := range invalid {
		t.Run("invalid "+tc.name, func(t *testing.T) {
			err := tc.o.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestRollbackOutcomeValidate(t *testing.T) {
	valid := []providers.RollbackOutcome{
		{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Verified: "remote", Steps: steps("restore")},
		{Result: providers.DeployRolledBack},
		{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "rollback_reload", CauseStep: "reload", Reason: "deployment.rollback_reload_failed"},
		{Result: providers.DeployNoChange, Phase: providers.PhasePrepared, Reason: "deployment.nothing_to_restore"},
		{Result: providers.DeployNoChange, Phase: providers.PhaseUnchanged, Reason: "deployment.nothing_to_restore"},
		{Result: providers.DeployNoChange, Reason: "deployment.superseded"},
		{Result: providers.DeployUncertain},
	}
	for i, o := range valid {
		assert.NoError(t, o.Validate(), "valid %d", i)
	}
	invalid := []struct {
		name string
		o    providers.RollbackOutcome
		want string
	}{
		{"zero value", providers.RollbackOutcome{}, "blank or unknown result"},
		{"committed", providers.RollbackOutcome{Result: providers.DeployCommitted}, "not a rollback result"},
		{"unchanged", providers.RollbackOutcome{Result: providers.DeployUnchanged}, "not a rollback result"},
		{"rolled back with failed step", providers.RollbackOutcome{Result: providers.DeployRolledBack, FailedStep: "restore"}, "rolled_back: failed_step"},
		{"rolled back with reason", providers.RollbackOutcome{Result: providers.DeployRolledBack, Reason: "r"}, "rolled_back: reason"},
		{"rolled back wrong phase", providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseWriting}, "rolled_back: phase"},
		{"rollback failed without step", providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Reason: "r"}, "rollback_failed: failed_step is required"},
		{"rollback failed without reason", providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore"}, "rollback_failed: reason is required"},
		{"rollback failed wrong phase", providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore", Reason: "r", Phase: providers.PhaseCommitted}, "rollback_failed: phase"},
		{"no change with steps", providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "r", Steps: steps("restore")}, "no_change: steps"},
		{"no change wrong phase", providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "r", Phase: providers.PhaseWriting}, "no_change: phase"},
		{"no change without reason", providers.RollbackOutcome{Result: providers.DeployNoChange}, "no_change: reason is required"},
		{"no change with failed step", providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "r", FailedStep: "x"}, "no_change: failed_step"},
		{"uncertain with phase", providers.RollbackOutcome{Result: providers.DeployUncertain, Phase: providers.PhaseRestoring}, "uncertain: phase"},
		{"uncertain with error class", providers.RollbackOutcome{Result: providers.DeployUncertain, Error: "syntax"}, "uncertain: error"},
		{"step without name", providers.RollbackOutcome{Result: providers.DeployRolledBack, Steps: []providers.DeployStep{{Status: providers.StepOK}}}, "rollback outcome: step 0: no name"},
		{"step with unknown status", providers.RollbackOutcome{Result: providers.DeployUncertain, Steps: []providers.DeployStep{{Name: "restore", Status: "weird"}}}, "rollback outcome: step 0: unknown status"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.o.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestDeploymentStateValidate(t *testing.T) {
	for _, p := range []string{providers.PhaseNone, providers.PhasePrepared, providers.PhaseWriting, providers.PhaseCommitted,
		providers.PhaseUnchanged, providers.PhaseRestoring, providers.PhaseRestored, providers.PhaseRestoreFailed} {
		assert.NoError(t, providers.DeploymentState{Phase: p, Active: p == providers.PhaseWriting}.Validate(), p)
	}
	assert.NoError(t, providers.DeploymentState{Phase: providers.PhaseNone, Active: true}.Validate(), "another operation holds the lock")
	assert.NoError(t, providers.DeploymentState{Phase: providers.PhaseRestored, FailedStep: "reload", CauseStep: "reload", Error: "syntax", NewCertSHA256: "a", BackupDir: "/b"}.Validate())
	// A tombstone is a bare marker: it may name the backup directory it sits in and may be held
	// by the lock, but carries no step, error or hash.
	assert.NoError(t, providers.DeploymentState{Phase: providers.PhaseFenced}.Validate())
	assert.NoError(t, providers.DeploymentState{Phase: providers.PhaseFenced, BackupDir: "/b", Active: true}.Validate())
	for name, tc := range map[string]struct {
		s    providers.DeploymentState
		want string
	}{
		"blank phase":                {providers.DeploymentState{}, "blank or unknown phase"},
		"unknown phase":              {providers.DeploymentState{Phase: "done"}, "blank or unknown phase"},
		"none with a hash":           {providers.DeploymentState{Phase: providers.PhaseNone, NewCertSHA256: "a"}, "none: no journal"},
		"none with backup dir":       {providers.DeploymentState{Phase: providers.PhaseNone, BackupDir: "/b"}, "none: no journal"},
		"none with failed step":      {providers.DeploymentState{Phase: providers.PhaseNone, FailedStep: "x"}, "none: no journal"},
		"committed with failed step": {providers.DeploymentState{Phase: providers.PhaseCommitted, FailedStep: "reload"}, "committed: failed_step"},
		"unchanged with error":       {providers.DeploymentState{Phase: providers.PhaseUnchanged, Error: "syntax"}, "unchanged: error"},
		"fenced with failed step":    {providers.DeploymentState{Phase: providers.PhaseFenced, FailedStep: "reload"}, "fenced: a tombstone"},
		"fenced with cause step":     {providers.DeploymentState{Phase: providers.PhaseFenced, CauseStep: "reload"}, "fenced: a tombstone"},
		"fenced with error":          {providers.DeploymentState{Phase: providers.PhaseFenced, Error: "syntax"}, "fenced: a tombstone"},
		"fenced with new hash":       {providers.DeploymentState{Phase: providers.PhaseFenced, NewCertSHA256: "a"}, "fenced: a tombstone"},
		"fenced with current hash":   {providers.DeploymentState{Phase: providers.PhaseFenced, CurrentCertSHA256: "a"}, "fenced: a tombstone"},
	} {
		err := tc.s.Validate()
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), tc.want, name)
	}
}

func TestCheckDeployReturn(t *testing.T) {
	refusal := providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.no_space"}
	pe := providers.NewError("nginx.no_space", false, nil, nil)
	committed := providers.DeployOutcome{Result: providers.DeployCommitted}
	uncertain := providers.DeployOutcome{Result: providers.DeployUncertain}
	for name, tc := range map[string]struct {
		o    providers.DeployOutcome
		err  error
		want string // "" = valid
	}{
		"committed":                   {committed, nil, ""},
		"refusal with provider error": {refusal, pe, ""},
		"uncertain with error":        {uncertain, errors.New("lost"), ""},
		"refusal without error":       {refusal, nil, "no_change without an error"},
		"refusal with plain error":    {refusal, errors.New("x"), "no_change needs a *providers.Error"},
		"uncertain without error":     {uncertain, nil, "uncertain without an error"},
		"committed with error":        {committed, errors.New("x"), "a known change is an outcome"},
		"invalid outcome":             {providers.DeployOutcome{}, nil, "blank or unknown result"},
		"invalid outcome with error":  {providers.DeployOutcome{}, errors.New("x"), "blank or unknown result"},
		"unsupported":                 {providers.DeployOutcome{}, providers.ErrUnsupported, "ErrUnsupported"},
		"rolled back with error":      {providers.DeployOutcome{Result: providers.DeployRolledBack, FailedStep: "reload", Reason: "r"}, errors.New("x"), "a known change is an outcome"},
		"rollback failed without err": {providers.DeployOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore", Reason: "r"}, nil, ""},
	} {
		err := providers.CheckDeployReturn(tc.o, tc.err)
		if tc.want == "" {
			assert.NoError(t, err, name)
			continue
		}
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), tc.want, name)
	}
}

func TestCheckRollbackReturn(t *testing.T) {
	pe := providers.NewError("deployment.superseded", false, nil, nil)
	superseded := providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "deployment.superseded"}
	nothing := providers.RollbackOutcome{Result: providers.DeployNoChange, Phase: providers.PhasePrepared, Reason: "deployment.nothing_to_restore"}
	rolled := providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored}
	uncertain := providers.RollbackOutcome{Result: providers.DeployUncertain}
	for name, tc := range map[string]struct {
		o    providers.RollbackOutcome
		err  error
		want string
	}{
		"rolled back":                   {rolled, nil, ""},
		"superseded refusal":            {superseded, pe, ""},
		"nothing to restore answer":     {nothing, nil, ""},
		"uncertain with error":          {uncertain, errors.New("lost"), ""},
		"refusal without error":         {superseded, nil, "refusal needs a *providers.Error"},
		"refusal with plain error":      {superseded, errors.New("x"), "refusal needs a *providers.Error"},
		"nothing to restore with error": {nothing, pe, "nothing to restore is an answer"},
		"uncertain without error":       {uncertain, nil, "uncertain without an error"},
		"rolled back with error":        {rolled, errors.New("x"), "a known change is an outcome"},
		"invalid":                       {providers.RollbackOutcome{}, nil, "blank or unknown result"},
		"unsupported":                   {providers.RollbackOutcome{}, providers.ErrUnsupported, "ErrUnsupported"},
	} {
		err := providers.CheckRollbackReturn(tc.o, tc.err)
		if tc.want == "" {
			assert.NoError(t, err, name)
			continue
		}
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), tc.want, name)
	}
}

func failedStep(name, class string) providers.DeployStep {
	return providers.DeployStep{Name: name, Status: providers.StepFailed, Error: class}
}

// The legal shape of every situation the Nginx provider maps (Task 11), each as returned with its
// error by DeployCertificate: the Result, Phase, FailedStep, CauseStep, Error and error.
func TestLegalDeployShapesForEverySituation(t *testing.T) {
	refusal := providers.NewError("nginx.no_space", false, nil, nil)
	lost := errors.New("connection lost")
	verifyFailed := providers.NewError("deployment.verify_failed", false, nil, nil)
	base := steps("backup", "write_key", "write_cert", "config_test", "reload")
	for name, tc := range map[string]struct {
		o   providers.DeployOutcome
		err error
	}{
		"1 provider-side refusal before the helper": {providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.location_unsupported"}, refusal},
		"2 helper refusal":                          {providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.no_space"}, refusal},
		"3 committed, verification passes": {providers.DeployOutcome{Result: providers.DeployCommitted, Phase: providers.PhaseCommitted,
			Steps: append(append([]providers.DeployStep{}, base...), steps("verify")...), Verified: "remote"}, nil},
		"3b helper unchanged, verification passes": {providers.DeployOutcome{Result: providers.DeployUnchanged, Phase: providers.PhaseUnchanged,
			Steps: steps("backup", "verify"), Verified: "remote"}, nil},
		"3c helper unchanged, verification fails: nothing changed, the site does not serve it": {providers.DeployOutcome{
			Result: providers.DeployNoChange, Phase: providers.PhaseUnchanged, FailedStep: providers.StepNameVerify, Reason: "deployment.verify_failed",
			Steps: append(steps("backup"), failedStep("verify", ""))}, verifyFailed},
		"4 committed, verification fails, rolled back, old certificate verifies": {providers.DeployOutcome{
			Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, FailedStep: "verify", CauseStep: "verify", Reason: "deployment.verify_failed",
			Steps:    append(append(append([]providers.DeployStep{}, base...), failedStep("verify", "")), steps("restore", "rollback_config_test", "rollback_reload", "verify_old")...),
			Verified: "remote"}, nil},
		"5 rollback done, the old certificate does not verify: files are back": {providers.DeployOutcome{
			Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestored, FailedStep: "verify_old", CauseStep: "verify", Reason: "deployment.rollback_verify_failed",
			Steps: append(append(append([]providers.DeployStep{}, base...), failedStep("verify", "")), append(steps("restore", "rollback_config_test", "rollback_reload"), failedStep("verify_old", ""))...)}, nil},
		"6 helper restored after its own config test failed": {providers.DeployOutcome{
			Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, FailedStep: "config_test", CauseStep: "config_test", Error: providers.ConfigErrKeyMismatch,
			Reason: "certificate.key_mismatch", Steps: append(steps("backup", "write_key", "write_cert"), failedStep("config_test", providers.ConfigErrKeyMismatch))}, nil},
		"6b helper restored after a killed nginx": {providers.DeployOutcome{
			Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, FailedStep: "reload", CauseStep: "reload", Error: "",
			Reason: "deployment.reload_failed"}, nil},
		"7a restore_failed: a file changed under the rollback": {providers.DeployOutcome{
			Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "reload", CauseStep: "reload", Error: providers.DeployErrFileChanged,
			Reason: "deployment.rollback_file_changed"}, nil},
		"7b restore_failed: the restore step failed": {providers.DeployOutcome{
			Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "restore", CauseStep: "config_test",
			Reason: "deployment.rollback_failed"}, nil},
		"7c restore_failed: the rollback reload failed": {providers.DeployOutcome{
			Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "rollback_reload", CauseStep: "reload",
			Reason: "deployment.rollback_reload_failed"}, nil},
		"7d restore_failed: the rollback config test failed": {providers.DeployOutcome{
			Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "rollback_config_test", CauseStep: "reload",
			Error: providers.ConfigErrSyntax, Reason: "deployment.rollback_config_invalid"}, nil},
		"8 uncertain": {providers.DeployOutcome{Result: providers.DeployUncertain, Steps: steps("backup")}, lost},
	} {
		assert.NoError(t, providers.CheckDeployReturn(tc.o, tc.err), name)
	}
}

func TestNoChangeWithPhaseUnchangedIsOnlyAFailedVerification(t *testing.T) {
	verifyFailed := providers.NewError("deployment.verify_failed", false, nil, nil)
	good := providers.DeployOutcome{Result: providers.DeployNoChange, Phase: providers.PhaseUnchanged, FailedStep: "verify",
		Reason: "deployment.verify_failed", Steps: append(steps("backup"), failedStep("verify", ""))}
	require.NoError(t, providers.CheckDeployReturn(good, verifyFailed))
	assert.Error(t, providers.CheckDeployReturn(good, nil), "a refusal needs a *providers.Error")

	for name, tc := range map[string]struct {
		mod  func(o *providers.DeployOutcome)
		want string
	}{
		"failed step is not verify": {func(o *providers.DeployOutcome) { o.FailedStep = "reload" }, "no_change with phase unchanged: failed_step must be verify"},
		"no failed step":            {func(o *providers.DeployOutcome) { o.FailedStep = "" }, "no_change with phase unchanged: failed_step must be verify"},
		"no failed verify step":     {func(o *providers.DeployOutcome) { o.Steps = steps("backup", "verify") }, "no_change with phase unchanged: steps must hold the failed verify step"},
		"no steps":                  {func(o *providers.DeployOutcome) { o.Steps = nil }, "no_change with phase unchanged: steps must hold the failed verify step"},
		"cause step":                {func(o *providers.DeployOutcome) { o.CauseStep = "verify" }, "no_change with phase unchanged: cause_step"},
		"error class":               {func(o *providers.DeployOutcome) { o.Error = "syntax" }, "no_change with phase unchanged: error"},
		"no reason":                 {func(o *providers.DeployOutcome) { o.Reason = "" }, "no_change: reason is required"},
		"another phase":             {func(o *providers.DeployOutcome) { o.Phase = providers.PhaseCommitted }, "no_change: phase"},
	} {
		o := good
		tc.mod(&o)
		err := o.Validate()
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), tc.want, name)
	}
	// Without the phase, steps and a failed step stay forbidden.
	err := providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "r", FailedStep: "verify", Steps: steps("verify")}.Validate()
	require.Error(t, err)
}

func TestRollbackFailedWithPhaseRestoredIsOnlyAFailedOldVerification(t *testing.T) {
	ok := providers.DeployOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestored, FailedStep: "verify_old", Reason: "r"}
	require.NoError(t, ok.Validate())
	for _, step := range []string{"restore", "rollback_reload", "verify", ""} {
		o := ok
		o.FailedStep = step
		err := o.Validate()
		require.Error(t, err, step)
		assert.Contains(t, err.Error(), "rollback_failed with phase restored: failed_step must be verify_old", step)
	}
	r := providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestored, FailedStep: "verify_old", Reason: "r"}
	require.NoError(t, r.Validate())
	r.FailedStep = "restore"
	err := r.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rollback_failed with phase restored: failed_step must be verify_old")
}

func TestLegalRollbackShapes(t *testing.T) {
	pe := providers.NewError("deployment.unknown_operation", false, nil, nil)
	for name, tc := range map[string]struct {
		o   providers.RollbackOutcome
		err error
	}{
		"unknown operation":     {providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "deployment.unknown_operation"}, pe},
		"superseded":            {providers.RollbackOutcome{Result: providers.DeployNoChange, Reason: "deployment.superseded"}, pe},
		"nothing to restore":    {providers.RollbackOutcome{Result: providers.DeployNoChange, Phase: providers.PhasePrepared, Reason: "deployment.nothing_to_restore"}, nil},
		"restored and verified": {providers.RollbackOutcome{Result: providers.DeployRolledBack, Phase: providers.PhaseRestored, Verified: "remote"}, nil},
		"restored, old certificate does not verify": {providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestored,
			FailedStep: "verify_old", Reason: "deployment.rollback_verify_failed"}, nil},
		"hash mismatch on restore": {providers.RollbackOutcome{Result: providers.DeployRollbackFailed, FailedStep: "restore", Error: providers.DeployErrFileChanged,
			Reason: "ssh.file_changed"}, nil},
		"restore_failed": {providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: providers.PhaseRestoreFailed, FailedStep: "rollback_reload",
			CauseStep: "reload", Reason: "deployment.rollback_reload_failed"}, nil},
		"uncertain": {providers.RollbackOutcome{Result: providers.DeployUncertain}, errors.New("lost")},
	} {
		assert.NoError(t, providers.CheckRollbackReturn(tc.o, tc.err), name)
	}
}
