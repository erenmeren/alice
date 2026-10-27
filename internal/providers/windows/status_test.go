package windows

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
)

// Every journal phase the helper can leave maps to a DeploymentState that passes Validate; a Windows
// state names no backup directory (W2 Ruling 17).
func TestStatusAndFenceStates(t *testing.T) {
	restore := func(t *testing.T, w *wenv, op uuid.UUID, leaf ...string) {
		t.Helper()
		in, err := json.Marshal(winproto.RestoreInput{ForbiddenSPKI: []string{}, ForbiddenLeaf: append([]string{}, leaf...)})
		require.NoError(t, err)
		w.model.Handler()(winproto.SubIISRestore+" --op "+op.String(), in)
	}
	type want struct {
		phase, failed, cause, cls string
		newCert, current          string // "new", "old", "third" or ""
		active                    bool
	}
	rows := []struct {
		name string
		prep func(t *testing.T, w *wenv, op uuid.UUID) (newLeaf []byte)
		want want
	}{
		{"none", func(*testing.T, *wenv, uuid.UUID) []byte { return nil }, want{phase: "none"}},
		{"none, another helper holds the lock", func(t *testing.T, w *wenv, _ uuid.UUID) []byte {
			t.Cleanup(w.model.HoldLock())
			return nil
		}, want{phase: "none", active: true}},
		{"prepared", func(t *testing.T, w *wenv, op uuid.UUID) []byte {
			nl := w.issue()
			w.model.KillAt("deploy.prepared")
			w.deploy(t, op, w.old.Cert.Raw, nl)
			return nl.Cert.Raw
		}, want{phase: "prepared", newCert: "new", current: "old"}},
		{"writing", func(t *testing.T, w *wenv, op uuid.UUID) []byte {
			nl := w.issue()
			w.model.KillAt("deploy.bound")
			w.deploy(t, op, w.old.Cert.Raw, nl)
			return nl.Cert.Raw
		}, want{phase: "writing", newCert: "new", current: "new"}},
		{"committed", func(t *testing.T, w *wenv, op uuid.UUID) []byte { return w.commit(t, op).Cert.Raw },
			want{phase: "committed", newCert: "new", current: "new"}},
		{"unchanged", func(t *testing.T, w *wenv, op uuid.UUID) []byte {
			nl := w.commit(t, uuid.New())
			require.Equal(t, winproto.PhaseUnchanged, w.deploy(t, op, nl.Cert.Raw, nl).Phase)
			return nl.Cert.Raw
		}, want{phase: "unchanged", newCert: "new", current: "new"}},
		{"restoring", func(t *testing.T, w *wenv, op uuid.UUID) []byte {
			nl := w.commit(t, op)
			w.model.KillAt("restore.restoring")
			restore(t, w, op)
			return nl.Cert.Raw
		}, want{phase: "restoring", newCert: "new", current: "new"}},
		{"restored", func(t *testing.T, w *wenv, op uuid.UUID) []byte {
			nl := w.commit(t, op)
			restore(t, w, op)
			return nl.Cert.Raw
		}, want{phase: "restored", newCert: "new", current: "old"}},
		{"restored by the helper itself: the cause is kept", func(t *testing.T, w *wenv, op uuid.UUID) []byte {
			nl := w.issue()
			w.model.CorruptReadBack(true)
			require.Equal(t, winproto.PhaseRestored, w.deploy(t, op, w.old.Cert.Raw, nl).Phase)
			return nl.Cert.Raw
		}, want{phase: "restored", failed: "bind", cause: "bind", cls: "read_back", newCert: "new", current: "old"}},
		{"restore_failed", func(t *testing.T, w *wenv, op uuid.UUID) []byte {
			nl := w.commit(t, op)
			third := w.issue()
			rec, ok := w.model.Binding(w.loc)
			require.True(t, ok)
			rec.CertSHA1 = w.model.AddCertificate("My", third.CertPEM, third.KeyPEM, wintest.CertOptions{})
			require.NoError(t, w.model.Host().UpdateBinding(context.Background(), rec))
			restore(t, w, op)
			return nl.Cert.Raw
		}, want{phase: "restore_failed", failed: "restore", cls: "file_changed", newCert: "new", current: "served"}},
		{"restore_forbidden", func(t *testing.T, w *wenv, op uuid.UUID) []byte {
			nl := w.commit(t, op)
			restore(t, w, op, derSHA256(w.old.Cert.Raw))
			return nl.Cert.Raw
		}, want{phase: "restore_forbidden", failed: "restore", cls: "forbidden", newCert: "new", current: "new"}},
		{"fenced", func(t *testing.T, w *wenv, op uuid.UUID) []byte {
			require.Equal(t, 0, w.model.Handler()(winproto.SubIISFence+" --op "+op.String(), nil).Exit)
			return nil
		}, want{phase: "fenced"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			w := newWEnv(t)
			op := uuid.New()
			newLeaf := row.prep(t, w, op)
			st, err := w.session(t).DeploymentStatus(context.Background(), op)
			require.NoError(t, err)
			require.NoError(t, st.Validate())
			hash := func(which string) string {
				switch which {
				case "new":
					return derSHA256(newLeaf)
				case "old":
					return derSHA256(w.old.Cert.Raw)
				case "served":
					return w.served()
				}
				return ""
			}
			assert.Equal(t, providers.DeploymentState{Phase: row.want.phase, Active: row.want.active, FailedStep: row.want.failed,
				CauseStep: row.want.cause, Error: row.want.cls, NewCertSHA256: hash(row.want.newCert), CurrentCertSHA256: hash(row.want.current)}, st)
			assert.Empty(t, st.BackupDir, "a Windows backup is a certificate in a store, not a directory")
		})
	}
}

func TestFenceDeployment(t *testing.T) {
	w := newWEnv(t)
	s := w.session(t)
	ctx := context.Background()

	// No journal: a tombstone; a later deploy of that operation is FENCED.
	op := uuid.New()
	st, err := s.FenceDeployment(ctx, op)
	require.NoError(t, err)
	assert.Equal(t, providers.DeploymentState{Phase: providers.PhaseFenced}, st)
	require.NoError(t, st.Validate())
	st, err = s.FenceDeployment(ctx, op)
	require.NoError(t, err, "fencing twice is fenced again")
	assert.Equal(t, providers.PhaseFenced, st.Phase)
	r := w.deployRaw(t, op, w.old.Cert.Raw, w.issue())
	assert.Equal(t, winproto.ExitPrecondition, r.Exit)
	assert.Contains(t, string(r.Stdout), winproto.CodeFenced)
	st, err = s.DeploymentStatus(ctx, op)
	require.NoError(t, err)
	assert.Equal(t, providers.DeploymentState{Phase: providers.PhaseFenced}, st)

	// Prepared: handed back and fenced; the binding still names the previous certificate.
	op = uuid.New()
	w.model.KillAt("deploy.prepared")
	w.deploy(t, op, w.old.Cert.Raw, w.issue())
	st, err = s.FenceDeployment(ctx, op)
	require.NoError(t, err)
	assert.Equal(t, providers.PhaseFenced, st.Phase)
	assert.Equal(t, derSHA256(w.old.Cert.Raw), w.served())

	// Committed: the state as it is, nothing fenced.
	op = uuid.New()
	nl := w.commit(t, op)
	st, err = s.FenceDeployment(ctx, op)
	require.NoError(t, err)
	assert.Equal(t, providers.DeploymentState{Phase: providers.PhaseCommitted, NewCertSHA256: derSHA256(nl.Cert.Raw),
		CurrentCertSHA256: derSHA256(nl.Cert.Raw)}, st)

	// BUSY proves nothing: an error, never a state.
	release := w.model.HoldLock()
	st, err = s.FenceDeployment(ctx, uuid.New())
	release()
	pe := providerErr(t, err)
	assert.Equal(t, "windows.busy", pe.Code)
	assert.True(t, pe.Retryable)
	assert.Zero(t, st)
}

// Answers that break the helper's contract are ssh.protocol_error, never a state.
func TestStatusAnswersOutsideTheContract(t *testing.T) {
	hex := strings.Repeat("a", 64)
	for name, tc := range map[string]struct {
		a     winproto.StatusResponse
		fence bool
	}{
		"an unknown phase":                 {a: winproto.StatusResponse{OK: true, Phase: "rolled_back", NewCertSHA256: hex}},
		"a blank phase":                    {a: winproto.StatusResponse{OK: true}},
		"a new hash that is not hex":       {a: winproto.StatusResponse{OK: true, Phase: "committed", NewCertSHA256: "XYZ"}},
		"an upper-case new hash":           {a: winproto.StatusResponse{OK: true, Phase: "committed", NewCertSHA256: strings.Repeat("A", 64)}},
		"no new hash":                      {a: winproto.StatusResponse{OK: true, Phase: "committed"}},
		"a current hash that is not hex":   {a: winproto.StatusResponse{OK: true, Phase: "committed", NewCertSHA256: hex, CurrentCertSHA256: "zz"}},
		"none with a hash":                 {a: winproto.StatusResponse{OK: true, Phase: "none", NewCertSHA256: hex}},
		"none with a step":                 {a: winproto.StatusResponse{OK: true, Phase: "none", FailedStep: "bind"}},
		"fenced with a hash":               {a: winproto.StatusResponse{OK: true, Phase: "fenced", CurrentCertSHA256: hex}},
		"fenced with an error":             {a: winproto.StatusResponse{OK: true, Phase: "fenced", Error: "io_error"}},
		"a step outside the vocabulary":    {a: winproto.StatusResponse{OK: true, Phase: "restored", FailedStep: "reload", NewCertSHA256: hex}},
		"a cause outside the vocabulary":   {a: winproto.StatusResponse{OK: true, Phase: "restored", CauseStep: "reload", NewCertSHA256: hex}},
		"a class outside the vocabulary":   {a: winproto.StatusResponse{OK: true, Phase: "restore_failed", FailedStep: "restore", Error: "syntax", NewCertSHA256: hex}},
		"committed with a failed step":     {a: winproto.StatusResponse{OK: true, Phase: "committed", FailedStep: "bind", NewCertSHA256: hex}},
		"a fence answered while locked":    {a: winproto.StatusResponse{OK: true, Phase: "fenced", Active: true}, fence: true},
		"a fence answering an unknown one": {a: winproto.StatusResponse{OK: true, Phase: "gone"}, fence: true},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWEnv(t)
			b, err := json.Marshal(tc.a)
			require.NoError(t, err)
			sub := winproto.SubIISStatus
			if tc.fence {
				sub = winproto.SubIISFence
			}
			w.script(sub, func([]byte) linuxsshtest.Response { return linuxsshtest.Response{Stdout: append(b, '\n')} })
			s := w.session(t)
			var st providers.DeploymentState
			if tc.fence {
				st, err = s.FenceDeployment(context.Background(), uuid.New())
			} else {
				st, err = s.DeploymentStatus(context.Background(), uuid.New())
			}
			pe := providerErr(t, err)
			assert.Equal(t, "ssh.protocol_error", pe.Code)
			assert.Equal(t, sub, pe.Params["subcommand"])
			assert.Zero(t, st)
		})
	}
	// A status (not a fence) that names another helper's lock is fine.
	w := newWEnv(t)
	b, _ := json.Marshal(winproto.StatusResponse{OK: true, Phase: "fenced", Active: true})
	w.script(winproto.SubIISStatus, func([]byte) linuxsshtest.Response { return linuxsshtest.Response{Stdout: append(b, '\n')} })
	st, err := w.session(t).DeploymentStatus(context.Background(), uuid.New())
	require.NoError(t, err)
	assert.Equal(t, providers.DeploymentState{Phase: providers.PhaseFenced, Active: true}, st)
}

// W1 Ruling 5 for the write half: status, fence and restore each open a fresh connection (Windows
// OpenSSH would answer a reused one with its first command), and none stays open.
func TestEveryWriteCallUsesItsOwnConnection(t *testing.T) {
	w := newWEnv(t)
	op := uuid.New()
	nl := w.commit(t, op)
	s := w.session(t)
	assert.Equal(t, 1, w.srv.Connections())
	ctx := context.Background()
	st, err := s.DeploymentStatus(ctx, op)
	require.NoError(t, err, "a reused connection would answer iis-status as version")
	assert.Equal(t, derSHA256(nl.Cert.Raw), st.NewCertSHA256)
	assert.Equal(t, 2, w.srv.Connections())
	_, err = s.FenceDeployment(ctx, op)
	require.NoError(t, err)
	assert.Equal(t, 3, w.srv.Connections())
	out, err := s.RollbackDeployment(ctx, w.rollbackReq(op), nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result)
	assert.Equal(t, 4, w.srv.Connections(), "one connection per helper call")
	assert.Equal(t, []string{"version", "iis-status --op " + op.String(), "iis-fence --op " + op.String(), "iis-restore --op " + op.String()},
		w.srv.Commands(), "the command line carries the subcommand and --op only (W2 Ruling 4)")
	w.waitNoOpenConnections(t)
}

// The write subcommands' budgets (W2 Task 7) and their forced lines.
func TestWriteCommandsAreForcedLines(t *testing.T) {
	op := uuid.New().String()
	for _, tc := range []struct {
		sub  string
		want budget
	}{
		{winproto.SubIISDeploy, budget{linuxssh.LongCommandTimeout, 64 << 10}},
		{winproto.SubIISRestore, budget{linuxssh.LongCommandTimeout, 64 << 10}},
		{winproto.SubIISStatus, budget{linuxssh.DefaultCommandTimeout, 64 << 10}},
		{winproto.SubIISFence, budget{linuxssh.DefaultCommandTimeout, 64 << 10}},
		{winproto.SubCCSDeploy, budget{linuxssh.LongCommandTimeout, 64 << 10}},
		{winproto.SubCCSDump, budget{linuxssh.LongCommandTimeout, winproto.DumpOutput}},
	} {
		assert.Equal(t, tc.want, budgets[tc.sub], tc.sub)
		c, err := cmd(tc.sub, []byte(`{"x":1}`), winproto.ArgOp, op)
		require.NoError(t, err, tc.sub)
		assert.Equal(t, tc.sub+" --op "+op, c.Line())
		assert.NotContains(t, c.Line(), "x", "stdin never reaches the line")
	}
	// The refusal tables are the helper's exit statuses (W2 Task 3); OUTCOME_UNKNOWN is in none.
	refusedAt := func(exit int, codes ...string) map[string]int {
		m := map[string]int{}
		for _, c := range codes {
			m[c] = exit
		}
		return m
	}
	input := withCodes(withCodes(refusedAt(2, winproto.CodeUsage, winproto.CodeUnknownSubcommand, winproto.CodeInvalidArgument,
		winproto.CodeBadContent, winproto.CodeTooLarge, winproto.CodeNotElevated), 4, winproto.CodeBusy, winproto.CodeJournalFailed,
		winproto.CodeIOError, winproto.CodeStoreError), 3)
	assert.Equal(t, input, inputRefusals)
	assert.Equal(t, withCodes(input, 3, winproto.CodeHashMismatch, winproto.CodeFenced, winproto.CodeOperationExists,
		winproto.CodeRecoveryPending, winproto.CodeBindingNotFound, winproto.CodeKeyUnusable), deployRefusals)
	// W5: a restore refuses a CCS journal's folder that became a reparse point (CCS_PATH_UNSUPPORTED, nothing written);
	// ccs-deploy adds the CCS preconditions to iis-deploy's table.
	assert.Equal(t, withCodes(input, 3, winproto.CodeUnknownOp, winproto.CodeSuperseded, winproto.CodeBackupMissing,
		winproto.CodeCCSPathUnsupported), restoreRefusals)
	assert.Equal(t, withCodes(deployRefusals, 3, winproto.CodeCCSDisabled, winproto.CodeCCSPathChanged, winproto.CodeCCSPathUnsupported,
		winproto.CodeCCSPasswordMismatch, winproto.CodeCCSFileNotFound), ccsDeployRefusals)
	for _, table := range []map[string]int{deployRefusals, restoreRefusals, ccsDeployRefusals} {
		assert.NotContains(t, table, winproto.CodeOutcomeUnknown)
	}
	assert.Less(t, winproto.LockWait, linuxssh.DefaultCommandTimeout, "a fence waits for the lock inside its budget")
	assert.Less(t, winproto.LockWait+winproto.WriteGrace, linuxssh.LongCommandTimeout, "a restore's lock wait and grace end before Alice cuts it")
}
