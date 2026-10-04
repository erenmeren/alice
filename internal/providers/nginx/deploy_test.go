package nginx

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/providertest"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// wantDeploy is the exact outcome of one DeployCertificate call.
type wantDeploy struct {
	result                    providers.DeployResult
	phase, failed, cause, cls string
	verified                  string
	steps                     []string // stepList(out.Steps)
	reason                    string
	params                    map[string]string // nil: none or empty
	errCode                   string            // "" = nil error
	retryable                 bool
	files                     string // "old" | "new" | "" (not checked)
	noDeploySent, noRestore   bool
	restoreSent               bool
	restores                  int               // nginx-restore commands sent (0: not checked)
	logParams                 map[string]string // params of the last logged step (nil: not checked)
}

// stepList renders steps as "name:status" or "name:status:class".
func stepList(steps []providers.DeployStep) []string {
	var out []string
	for _, st := range steps {
		s := st.Name + ":" + string(st.Status)
		if st.Error != "" {
			s += ":" + st.Error
		}
		out = append(out, s)
	}
	return out
}

var (
	helperOK = []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok"}
	restored = []string{"restore:ok", "rollback_config_test:ok", "rollback_reload:ok"}
)

func cat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// deployRow is one situation: setup changes the server or the request (after the request was built
// from a discovery of the fixture); ctx, when set, is the call's context.
type deployRow struct {
	name  string
	setup func(t *testing.T, e *env, nw pki.Leaf, req *providers.DeployRequest)
	ctx   func(t *testing.T) context.Context
	want  wantDeploy
}

func answerJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func deployAnswer(t *testing.T, a helperproto.NginxDeployResponse) linuxsshtest.Response {
	a.OK = true
	return linuxsshtest.Response{Stdout: answerJSON(t, a)}
}

func refusal(t *testing.T, exit int, code string) linuxsshtest.Response {
	return linuxsshtest.Response{Exit: exit, Stdout: answerJSON(t, helperproto.ErrorResponse{OK: false, Code: code, Message: "m"})}
}

func okSteps(names ...string) []helperproto.NginxStep {
	var out []helperproto.NginxStep
	for _, n := range names {
		out = append(out, helperproto.NginxStep{Name: n, Status: "ok"})
	}
	return out
}

func failedHelperStep(name, class string) helperproto.NginxStep {
	return helperproto.NginxStep{Name: name, Status: "failed", Error: class}
}

func withDeadline(d time.Duration) func(t *testing.T) context.Context {
	return func(t *testing.T) context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		t.Cleanup(cancel)
		return ctx
	}
}

// The mapping of every helper answer and transport condition to its outcome (one row per shape of
// outcome.go's table): each row drives the emulator (or scripts the helper's raw answer where the
// emulator cannot produce it) and asserts the whole outcome; providertest.CheckDeployOutcome runs
// on every return.
func TestDeployOutcomeTable(t *testing.T) {
	const deploySub, restoreSub = helperproto.SubNginxDeploy, helperproto.SubNginxRestore
	backupDirParam := func(e *env) map[string]string {
		return map[string]string{"backup_dir": helperproto.BackupRoot + "/" + e.op.String()}
	}
	rows := []deployRow{
		// Refusals before anything is sent.
		{"provider: location unsupported", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) { r.Location.Supported = false },
			nil, wantDeploy{result: providers.DeployNoChange, reason: "nginx.location_unsupported", errCode: "nginx.location_unsupported", files: "old", noDeploySent: true}},
		{"provider: path outside the helper's vocabulary", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) { r.Location.KeyPath = "ssl/www.key" },
			nil, wantDeploy{result: providers.DeployNoChange, reason: "nginx.location_unsupported", errCode: "nginx.location_unsupported", files: "old", noDeploySent: true}},
		{"provider: no operation id", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) { r.OperationID = uuid.Nil },
			nil, wantDeploy{result: providers.DeployNoChange, reason: "internal.unexpected", errCode: "internal.unexpected", files: "old", noDeploySent: true}},
		{"provider: input too large", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) {
			r.CertificatePEM = append(append([]byte{}, r.CertificatePEM...), []byte(strings.Repeat("\n", helperproto.MaxDeployInput))...)
		}, nil, wantDeploy{result: providers.DeployNoChange, reason: "certificate.invalid", errCode: "certificate.invalid", files: "old", noDeploySent: true}},
		{"provider: key that is not PEM text", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) {
			copy(r.PrivateKeyPEM.Bytes()[40:], []byte{0xff})
		}, nil, wantDeploy{result: providers.DeployNoChange, reason: "certificate.invalid", errCode: "certificate.invalid", files: "old", noDeploySent: true}},
		{"provider: cancelled before the send", nil, func(t *testing.T) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, wantDeploy{result: providers.DeployNoChange, reason: "ssh.timeout", params: map[string]string{"subcommand": deploySub}, errCode: "ssh.timeout",
			retryable: true, files: "old", noDeploySent: true}},

		// Helper refusals (well-formed JSON, a known code at its exit status): nothing changed.
		{"F-01 the new certificate with another certificate's key: BAD_CONTENT", func(_ *testing.T, e *env, _ pki.Leaf, r *providers.DeployRequest) {
			other := e.ca.Issue(pki.Opts{CommonName: "x"}, e.now)
			copy(r.PrivateKeyPEM.Bytes(), other.KeyPEM) // same size: both P-256 PKCS#8
		}, nil, wantDeploy{result: providers.DeployNoChange, reason: "certificate.invalid", errCode: "certificate.invalid", files: "old"}},
		{"F-02 configuration already broken", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.SetConfigInvalid(helperproto.ConfigErrSyntax)
		},
			nil, wantDeploy{result: providers.DeployNoChange, reason: "nginx.config_invalid", errCode: "nginx.config_invalid", files: "old"}},
		{"F-10 no space", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.SetFreeBytes(1) },
			nil, wantDeploy{result: providers.DeployNoChange, reason: "nginx.no_space", errCode: "nginx.no_space", files: "old"}},
		{"F-12 directory not writable", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.FailWriteIn("/etc/nginx/ssl")
		},
			nil, wantDeploy{result: providers.DeployNoChange, reason: "nginx.io_error", errCode: "nginx.io_error", retryable: true, files: "old"}},
		{"changed since discovery", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.SetNginxFile(wwwCert, e.leaf.CertPEM)
		},
			nil, wantDeploy{result: providers.DeployNoChange, reason: "nginx.file_changed", errCode: "nginx.file_changed"}},
		{"pair no longer in the configuration", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) {
			r.Location.CertPath = "/etc/nginx/ssl/gone.crt"
		},
			nil, wantDeploy{result: providers.DeployNoChange, reason: "nginx.config_changed", errCode: "nginx.config_changed", files: "old"}},
		{"F-14 profile missing (sudo refuses, exit 1)", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.SetNginxProfile(false) },
			nil, wantDeploy{result: providers.DeployNoChange, reason: "nginx.profile_missing", params: map[string]string{"subcommand": deploySub, "profile": "nginx"},
				errCode: "nginx.profile_missing", files: "old"}},
		{"busy", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.HoldLock(true) },
			nil, wantDeploy{result: providers.DeployNoChange, reason: "nginx.busy", errCode: "nginx.busy", retryable: true, files: "old"}},

		// Committed.
		{"committed, verified from Alice", nil, nil, wantDeploy{result: providers.DeployCommitted, phase: "committed", verified: "remote",
			steps: cat(helperOK, []string{"verify:ok"}), files: "new"}},
		{"committed, verified from the server", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.prober.set(true, false) },
			nil, wantDeploy{result: providers.DeployCommitted, phase: "committed", verified: "local", steps: cat(helperOK, []string{"verify:ok"}), files: "new"}},
		{"committed, verification skipped", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) { r.Verify.Skip = true },
			nil, wantDeploy{result: providers.DeployCommitted, phase: "committed", verified: "skipped", steps: cat(helperOK, []string{"verify:skipped"}), files: "new"}},

		// Committed, verification fails: the inline rollback.
		{"F-05 old certificate still served: rolled back", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.NoopReload(true) },
			nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify", verified: "remote",
				steps: cat(helperOK, []string{"verify:failed"}, restored, []string{"verify_old:ok"}), reason: "deployment.verify_failed",
				params: map[string]string{"port": "443"}, files: "old", restoreSent: true}},
		{"F-06 another certificate after the reload: rolled back", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.ServeOtherAfterReload(443, strings.Repeat("c", 64))
		}, nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify", verified: "remote",
			steps: cat(helperOK, []string{"verify:failed"}, restored, []string{"verify_old:ok"}), reason: "deployment.verify_other",
			params: map[string]string{"port": "443"}, files: "old", restoreSent: true}},
		{"F-07 unreachable both ways after the write: rolled back, old not checkable", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.prober.set(true, false)
			e.emu.LocalProbeFails(true)
		}, nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify",
			steps: cat(helperOK, []string{"verify:failed"}, restored, []string{"verify_old:failed"}), reason: "deployment.verify_unreachable",
			params: map[string]string{"port": "443"}, files: "old", restoreSent: true}},
		{"§12.8 item 5 the new leaf with another chain length: rolled back", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) { r.ChainLength = 3 },
			nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify", verified: "remote",
				steps: cat(helperOK, []string{"verify:failed"}, restored, []string{"verify_old:ok"}), reason: "deployment.verify_chain",
				params: map[string]string{"port": "443"}, files: "old", restoreSent: true}},
		{"verification error (SSH lost during tls-probe): the rollback cannot be sent, uncertain", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.prober.set(true, false)
			hangUpOn(e, helperproto.SubTLSProbe)
		}, nil, wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.verify_unreachable",
			params: map[string]string{"port": "443", "failed_step": "verify"}, errCode: "ssh.unreachable", retryable: true, files: "new"}},
		{"old certificate not served after the restore: rollback_failed, phase restored", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.ServeOther(443, strings.Repeat("c", 64))
		}, nil, wantDeploy{result: providers.DeployRollbackFailed, phase: "restored", failed: "verify_old", cause: "verify",
			steps: cat(helperOK, []string{"verify:failed"}, restored, []string{"verify_old:failed"}), reason: "deployment.rollback_failed",
			files: "old", restoreSent: true}},
		{"inline restore: rollback reload fails", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			e.emu.FailReload(1)
			e.emu.ArmFaultsFor(restoreSub)
		}, nil, wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "rollback_reload", cause: "verify",
			steps:  cat(helperOK, []string{"verify:failed", "restore:ok", "rollback_config_test:ok", "rollback_reload:failed"}),
			reason: "deployment.rollback_reload_failed", files: "old", restoreSent: true}},
		{"inline restore: a file cannot be written", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			e.emu.FailRestoreFile(wwwKey)
			e.emu.ArmFaultsFor(restoreSub)
		}, nil, wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "restore", cause: "verify",
			steps: cat(helperOK, []string{"verify:failed", "restore:failed"}), reason: "deployment.rollback_failed", restoreSent: true}},
		{"inline restore: someone else's file (HASH_MISMATCH)", func(_ *testing.T, e *env, nw pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			other := e.ca.Issue(pki.Opts{CommonName: "www.example.test", Key: nw.Key}, e.now)
			beforeOn(e, restoreSub, func() { e.emu.SetNginxFile(wwwCert, other.FullchainPEM) })
		}, nil, wantDeploy{result: providers.DeployRollbackFailed, failed: "restore", cause: "verify", cls: "file_changed",
			steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.rollback_failed", restoreSent: true}},
		{"inline restore: the key changed between the restore's renames (A1-I2): restore_failed, partly restored", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			e.emu.InterfereAt("renamed "+".alice-"+e.op.String()+"-cert", wwwKey, []byte("someone else's key"))
			e.emu.ArmFaultsFor(restoreSub)
		}, nil, wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "restore", cause: "verify", cls: "file_changed",
			steps: cat(helperOK, []string{"verify:failed", "restore:failed"}), reason: "deployment.rollback_failed", restoreSent: true}},
		{"inline restore BUSY once: retried, rolled back", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			scriptOn(e, restoreSub, refusal(t, 4, helperproto.CodeBusy))
		}, nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify", verified: "remote",
			steps: cat(helperOK, []string{"verify:failed"}, restored, []string{"verify_old:ok"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443"}, files: "old", restores: 2}},
		{"inline restore BUSY throughout: uncertain after the bounded retries", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			beforeOn(e, restoreSub, func() { e.emu.HoldLock(true) })
		}, nil, wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443", "failed_step": "verify"}, errCode: "nginx.busy", retryable: true, files: "new", restores: 3}},
		{"inline restore IO_ERROR: uncertain", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			scriptOn(e, restoreSub, refusal(t, 4, helperproto.CodeIOError))
		}, nil, wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443", "failed_step": "verify"}, errCode: "ssh.helper_refused", retryable: true, files: "new", restores: 1}},
		{"inline restore refused by sudo: uncertain", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			beforeOn(e, restoreSub, func() { e.emu.SetNginxProfile(false) })
		}, nil, wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443", "failed_step": "verify"}, errCode: "nginx.profile_missing", files: "new", restores: 1}},
		{"inline restore SUPERSEDED (cannot happen for the operation just committed): uncertain", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			scriptOn(e, restoreSub, refusal(t, 3, helperproto.CodeSuperseded))
		}, nil, wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443", "failed_step": "verify"}, errCode: "deployment.superseded", files: "new", restores: 1}},
		{"inline restore UNKNOWN_OP (cannot happen): uncertain", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			scriptOn(e, restoreSub, refusal(t, 3, helperproto.CodeUnknownOp))
		}, nil, wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443", "failed_step": "verify"}, errCode: "deployment.unknown_operation", files: "new", restores: 1}},
		{"inline restore killed: uncertain", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			e.emu.KillAt(helperproto.StepRestore)
			e.emu.ArmFaultsFor(restoreSub)
		}, nil, wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443", "failed_step": "verify"}, errCode: "ssh.protocol_error", restoreSent: true}},
		{"inline restore: a malformed answer is uncertain", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			scriptOn(e, restoreSub, linuxsshtest.Response{Stdout: []byte(`{"ok":true,"phase":"restored","steps":[{"name":"rm -rf","status":"ok"}]}`)})
		}, nil, wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443", "failed_step": "verify"}, errCode: "ssh.protocol_error", files: "new", restoreSent: true}},
		{"inline restore answers nothing to restore: uncertain", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			scriptOn(e, restoreSub, linuxsshtest.Response{Stdout: answerJSON(t, helperproto.NginxRestoreResponse{OK: true, Phase: "prepared", Steps: []helperproto.NginxStep{}})})
		}, nil, wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443", "failed_step": "verify"}, errCode: "ssh.protocol_error", files: "new", restoreSent: true}},
		{"cancelled during the verification: uncertain (no rollback can be sent)", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.prov.retryWait = 10 * time.Second
			e.emu.NoopReload(true)
		}, withDeadline(300 * time.Millisecond), wantDeploy{result: providers.DeployUncertain, steps: cat(helperOK, []string{"verify:failed"}),
			reason: "deployment.interrupted", params: map[string]string{"failed_step": "verify"}, errCode: "ssh.timeout",
			retryable: true, files: "new", noRestore: true, logParams: map[string]string{"error": "interrupted"}}},

		// Important 2: the verification is never vacuous.
		{"no fingerprint in the request: the leaf's is computed and compared", func(_ *testing.T, e *env, _ pki.Leaf, r *providers.DeployRequest) {
			r.Fingerprint = ""
			e.emu.NoopReload(true)
		}, nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify", verified: "remote",
			steps: cat(helperOK, []string{"verify:failed"}, restored, []string{"verify_old:ok"}), reason: "deployment.verify_failed",
			params: map[string]string{"port": "443"}, files: "old", restoreSent: true}},
		{"provider: a fingerprint that is not the leaf's", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) {
			r.Fingerprint = strings.Repeat("a", 64)
		},
			nil, wantDeploy{result: providers.DeployNoChange, reason: "internal.unexpected", errCode: "internal.unexpected", files: "old", noDeploySent: true}},
		{"provider: no certificate in the chain", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.DeployRequest) { r.CertificatePEM = []byte("x") },
			nil, wantDeploy{result: providers.DeployNoChange, reason: "certificate.invalid", errCode: "certificate.invalid", files: "old", noDeploySent: true}},
		{"exit 1 with output is not sudo's refusal: uncertain", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, linuxsshtest.Response{Exit: 1, Stdout: []byte("something\n")})
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.helper_missing", files: "old"}},

		// The helper's own rollback (restored).
		{"helper restored: config test failed", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.FailConfigTest(1) },
			nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "config_test", cause: "config_test", cls: "syntax", verified: "remote",
				steps: cat(helperOK[:3], []string{"config_test:failed:syntax"}, restored, []string{"verify_old:ok"}), reason: "deployment.config_test_failed",
				files: "old"}},
		{"F-03 helper restored: reload failed", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.FailReload(1) },
			nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "reload", cause: "reload", verified: "remote",
				steps: cat(helperOK[:4], []string{"reload:failed"}, restored, []string{"verify_old:ok"}), reason: "deployment.reload_failed", files: "old"}},
		{"helper restored: the journal could not record the commit", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.FailJournalWrite(helperproto.PhaseCommitted)
		}, nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "journal", cause: "journal", verified: "remote",
			steps: cat(helperOK, []string{"journal:failed"}, restored, []string{"verify_old:ok"}), reason: "deployment.interrupted", files: "old"}},
		{"helper restored: key_mismatch (scripted)", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, deployAnswer(t, helperproto.NginxDeployResponse{Phase: "restored", FailedStep: "config_test", CauseStep: "config_test",
				Error: "key_mismatch", Steps: append(okSteps("backup", "write_key", "write_cert"), failedHelperStep("config_test", "key_mismatch"))}))
		}, nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "config_test", cause: "config_test", cls: "key_mismatch", verified: "remote",
			steps: cat(helperOK[:3], []string{"config_test:failed:key_mismatch", "verify_old:ok"}), reason: "certificate.key_mismatch", files: "old"}},
		{"helper restored: a killed nginx, empty class (scripted)", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, deployAnswer(t, helperproto.NginxDeployResponse{Phase: "restored", FailedStep: "reload", CauseStep: "reload",
				Steps: append(okSteps("backup", "write_key", "write_cert", "config_test"), failedHelperStep("reload", ""))}))
		}, nil, wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "reload", cause: "reload", verified: "remote",
			steps: cat(helperOK[:4], []string{"reload:failed", "verify_old:ok"}), reason: "deployment.reload_failed", files: "old"}},
		{"helper restored, the old certificate is not served: rollback_failed, phase restored", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.FailReload(1)
			e.emu.ServeOtherAfterReload(443, strings.Repeat("c", 64)) // the rollback's reload is the next successful one
		}, nil, wantDeploy{result: providers.DeployRollbackFailed, phase: "restored", failed: "verify_old", cause: "reload",
			steps: cat(helperOK[:4], []string{"reload:failed"}, restored, []string{"verify_old:failed"}), reason: "deployment.rollback_failed", files: "old"}},

		// The helper's own rollback failed (restore_failed).
		{"F-04 restore_failed: the rollback reload fails too", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.FailReload(2) },
			nil, wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "rollback_reload", cause: "reload",
				steps:  cat(helperOK[:4], []string{"reload:failed", "restore:ok", "rollback_config_test:ok", "rollback_reload:failed"}),
				reason: "deployment.rollback_reload_failed", files: "old"}},
		{"restore_failed: the rollback config test fails", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.FailConfigTest(2) },
			nil, wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "rollback_config_test", cause: "config_test", cls: "syntax",
				steps:  cat(helperOK[:3], []string{"config_test:failed:syntax", "restore:ok", "rollback_config_test:failed:syntax"}),
				reason: "deployment.rollback_failed", files: "old"}},
		{"restore_failed: the restore itself fails", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.FailReload(1)
			e.emu.FailRestoreFile(wwwKey)
		}, nil, wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "restore", cause: "reload",
			steps: cat(helperOK[:4], []string{"reload:failed", "restore:failed"}), reason: "deployment.rollback_failed"}},
		{"restore_failed: someone else changed a file during the deployment", func(_ *testing.T, e *env, nw pki.Leaf, _ *providers.DeployRequest) {
			other := e.ca.Issue(pki.Opts{CommonName: "www.example.test", Key: nw.Key}, e.now)
			e.emu.InterfereAt(helperproto.StepWriteKey, wwwCert, other.FullchainPEM)
		}, nil, wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "write_cert", cause: "write_cert", cls: "file_changed",
			steps: []string{"backup:ok", "write_key:ok", "write_cert:failed", "restore:ok"}, reason: "deployment.rollback_failed"}},

		// Unchanged.
		{"unchanged, verified", func(t *testing.T, e *env, nw pki.Leaf, r *providers.DeployRequest) {
			first := *r
			first.OperationID = uuid.New()
			first.PrivateKeyPEM = cloneKey(nw)
			out, err := e.open(t).DeployCertificate(context.Background(), first, nil)
			require.NoError(t, err)
			require.Equal(t, providers.DeployCommitted, out.Result)
			r.ExpectCertSHA256 = hexSHA(nw.FullchainPEM)
		}, nil, wantDeploy{result: providers.DeployUnchanged, phase: "unchanged", verified: "remote", steps: []string{"verify:ok"}, files: "new"}},
		{"unchanged, not served: no_change with phase unchanged, no rollback", func(t *testing.T, e *env, nw pki.Leaf, r *providers.DeployRequest) {
			e.emu.SetNginxFile(wwwCert, nw.FullchainPEM) // the files hold the new pair, Nginx still serves the old one
			e.emu.SetNginxFile(wwwKey, nw.KeyPEM)
			r.ExpectCertSHA256 = hexSHA(nw.FullchainPEM)
		}, nil, wantDeploy{result: providers.DeployNoChange, phase: "unchanged", failed: "verify", steps: []string{"verify:failed"},
			reason: "deployment.verify_failed", params: map[string]string{"port": "443"}, errCode: "deployment.verify_failed", files: "new", noRestore: true}},

		// Re-sent operations answer from the journal.
		{"re-sent restored operation without a failed step: uncertain", func(t *testing.T, e *env, nw pki.Leaf, r *providers.DeployRequest) {
			e.emu.KillAt(helperproto.StepWriteCert)
			first := *r
			first.PrivateKeyPEM = cloneKey(nw)
			out, err := e.open(t).DeployCertificate(context.Background(), first, nil)
			require.Error(t, err)
			require.Equal(t, providers.DeployUncertain, out.Result)
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"re-sent committed operation: committed again, verified", func(t *testing.T, e *env, nw pki.Leaf, r *providers.DeployRequest) {
			first := *r
			first.PrivateKeyPEM = cloneKey(nw)
			out, err := e.open(t).DeployCertificate(context.Background(), first, nil)
			require.NoError(t, err)
			require.Equal(t, providers.DeployCommitted, out.Result)
		}, nil, wantDeploy{result: providers.DeployCommitted, phase: "committed", verified: "remote", steps: cat(helperOK, []string{"verify:ok"}), files: "new"}},

		// Transport and answers Alice cannot read: uncertain, everything cleared.
		{"killed by a signal", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.KillAt(helperproto.StepWriteCert)
		},
			nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error"}},
		{"killed, exit 137 without JSON", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.KillAtWithExit137(helperproto.StepWriteCert)
		},
			nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.helper_missing"}},
		{"F-08 connection lost after the reload", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.HangupAfter(helperproto.StepReload)
		},
			nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "new"}},
		{"timeout or cancellation after the send", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			h := e.emu.Handler()
			e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
				if strings.Contains(cmd, " "+deploySub+" ") {
					time.Sleep(400 * time.Millisecond)
				}
				return h(cmd, stdin)
			})
		}, withDeadline(150 * time.Millisecond), wantDeploy{result: providers.DeployUncertain, errCode: "ssh.timeout", retryable: true}},
		{"malformed JSON", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, linuxsshtest.Response{Stdout: []byte(`{"ok":true,"phase":`)})
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"exit 2 without JSON (a panic)", func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, linuxsshtest.Response{Exit: 2, Stdout: []byte("panic: boom\n")})
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"an unknown code", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, refusal(t, 3, "NEW_CODE"))
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"a known code at another exit status", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, refusal(t, 4, helperproto.CodeConfigInvalid))
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"an unknown phase", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, deployAnswer(t, helperproto.NginxDeployResponse{Phase: "writing", Steps: okSteps("backup")}))
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"committed with a failed step", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, deployAnswer(t, helperproto.NginxDeployResponse{Phase: "committed", Steps: append(okSteps("backup"), failedHelperStep("reload", ""))}))
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"unchanged with a failed step name", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, deployAnswer(t, helperproto.NginxDeployResponse{Phase: "unchanged", FailedStep: "reload"}))
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"a step outside the vocabulary", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, deployAnswer(t, helperproto.NginxDeployResponse{Phase: "committed", Steps: okSteps("backup", "chmod")}))
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"restored with an unknown class", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, deployAnswer(t, helperproto.NginxDeployResponse{Phase: "restored", FailedStep: "reload", CauseStep: "reload", Error: "nginx: [emerg] x"}))
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
		{"restore_failed without a failed step", func(t *testing.T, e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, deploySub, deployAnswer(t, helperproto.NginxDeployResponse{Phase: "restore_failed", CauseStep: "reload"}))
		}, nil, wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "old"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e := newEnv(t)
			nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
			req := e.req(t, nw)
			if row.setup != nil {
				row.setup(t, e, nw, &req)
			}
			ctx := context.Background()
			if row.ctx != nil {
				ctx = row.ctx(t)
			}
			before := len(e.srv.Commands())
			log := &steps{}
			out, err := e.session(t).DeployCertificate(ctx, req, log)
			providertest.CheckDeployOutcome(t, out, err)
			w := row.want
			assert.Equal(t, w.result, out.Result, "result")
			assert.Equal(t, w.phase, out.Phase, "phase")
			assert.Equal(t, w.failed, out.FailedStep, "failed step")
			assert.Equal(t, w.cause, out.CauseStep, "cause step")
			assert.Equal(t, w.cls, out.Error, "error class")
			assert.Equal(t, w.verified, out.Verified, "verified")
			assert.Equal(t, w.steps, stepList(out.Steps), "steps")
			assert.Equal(t, w.reason, out.Reason, "reason")
			wantParams := w.params
			if w.result == providers.DeployRollbackFailed {
				wantParams = backupDirParam(e)
			}
			if len(wantParams) == 0 {
				assert.Empty(t, out.Params, "params")
			} else {
				assert.Equal(t, wantParams, out.Params, "params")
			}
			assert.Equal(t, providers.BackupRef{OperationID: req.OperationID, Dir: backupDirOf(req.OperationID)}, out.Backup)
			if w.errCode == "" {
				assert.NoError(t, err)
			} else {
				pe := providerErr(t, err)
				assert.Equal(t, w.errCode, pe.Code, "error code")
				assert.Equal(t, w.retryable, pe.Retryable, "retryable")
			}
			switch w.files {
			case "old":
				assert.Equal(t, string(e.leaf.FullchainPEM), string(e.emu.NginxFile(wwwCert)), "the old certificate file is in place")
				assert.Equal(t, string(e.leaf.KeyPEM), string(e.emu.NginxFile(wwwKey)), "the old key file is in place")
			case "new":
				assert.Equal(t, string(nw.FullchainPEM), string(e.emu.NginxFile(wwwCert)), "the new certificate file is in place")
				assert.Equal(t, string(nw.KeyPEM), string(e.emu.NginxFile(wwwKey)), "the new key file is in place")
			}
			cmds := strings.Join(e.srv.Commands()[before:], "\n")
			if w.noDeploySent {
				assert.NotContains(t, cmds, deploySub, "nothing was sent")
			}
			if w.noRestore {
				assert.NotContains(t, cmds, restoreSub)
			}
			if w.restoreSent {
				assert.Contains(t, cmds, restoreSub)
			}
			if w.restores > 0 {
				assert.Equal(t, w.restores, strings.Count(cmds, restoreSub), "nginx-restore sent")
			}
			if w.logParams != nil {
				require.NotEmpty(t, log.params)
				assert.Equal(t, w.logParams, log.params[len(log.params)-1])
			}
			// The logger saw every final step of the outcome, in order (plus "started" entries).
			var logged []string
			for _, l := range log.list() {
				if !strings.HasSuffix(l, ":started") {
					logged = append(logged, l)
				}
			}
			var outSteps []string
			for _, st := range out.Steps {
				outSteps = append(outSteps, st.Name+":"+string(st.Status))
			}
			assert.Equal(t, outSteps, logged, "logged steps")
		})
	}
}

func backupDirOf(op uuid.UUID) string {
	if op == uuid.Nil {
		return ""
	}
	return helperproto.BackupRoot + "/" + op.String()
}

// Every refusal code of nginx-deploy at its exit status is no_change with its mapped reason;
// the same code at another exit status, and an unknown code, are uncertain.
func TestDeployRefusalCodes(t *testing.T) {
	want := map[string]string{
		helperproto.CodeUsage: "ssh.helper_refused", helperproto.CodeUnknownSubcommand: "ssh.helper_refused", helperproto.CodeNotRoot: "ssh.helper_refused",
		helperproto.CodeInvalidArgument: "ssh.helper_refused", helperproto.CodeTooLarge: "nginx.location_unsupported",
		helperproto.CodeBadContent: "certificate.invalid", helperproto.CodeUnsafeFile: "nginx.location_unsupported",
		helperproto.CodeNotRegularFile: "nginx.location_unsupported", helperproto.CodePathNotAllowed: "nginx.location_unsupported",
		helperproto.CodeContentMismatch: "ssh.helper_refused", helperproto.CodeNginxNotFound: "nginx.not_found",
		helperproto.CodeConfigInvalid: "nginx.config_invalid", helperproto.CodeConfigChanged: "nginx.config_changed",
		helperproto.CodeNotFound: "nginx.location_unsupported", helperproto.CodeHashMismatch: "nginx.file_changed",
		helperproto.CodeNoSpace: "nginx.no_space", helperproto.CodeSuperseded: "ssh.helper_refused",
		helperproto.CodeBusy: "nginx.busy", helperproto.CodeIOError: "nginx.io_error",
		helperproto.CodeRecoveryPending: "deployment.recovery_pending", helperproto.CodeNginxNotRunning: "nginx.not_running",
	}
	require.Len(t, deployRefusals, len(want))
	assert.NotContains(t, deployRefusals, helperproto.CodeOutcomeUnknown, "the helper's guard after a rename is never a refusal")
	assert.NotContains(t, restoreRefusals, helperproto.CodeOutcomeUnknown)
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test"}, e.now)
	s := e.session(t) // a scripted refusal keeps the connection
	for code, exit := range deployRefusals {
		require.Contains(t, want, code)
		for _, x := range []int{helperproto.ExitRefused, helperproto.ExitPrecondition, helperproto.ExitFailed} {
			req := e.req(t, nw)
			scriptOn(e, helperproto.SubNginxDeploy, refusal(t, x, code))
			out, err := s.DeployCertificate(context.Background(), req, nil)
			providertest.CheckDeployOutcome(t, out, err)
			if x == exit {
				assert.Equal(t, providers.DeployNoChange, out.Result, code)
				assert.Equal(t, want[code], out.Reason, code)
				assert.Equal(t, want[code], providerErr(t, err).Code, code)
			} else {
				assert.Equal(t, providers.DeployUncertain, out.Result, "%s at exit %d", code, x)
				pe := providerErr(t, err)
				assert.Equal(t, "ssh.protocol_error", pe.Code)
				assert.Equal(t, code, pe.Params["helper_code"])
			}
		}
	}
	assert.Equal(t, []string{"BUSY", "IO_ERROR"}, codesAt(deployRefusals, helperproto.ExitFailed))
}

func codesAt(m map[string]int, exit int) []string {
	var out []string
	for c, x := range m {
		if x == exit {
			out = append(out, c)
		}
	}
	return sorted(out)
}

func cloneKey(l pki.Leaf) secrets.Plaintext {
	return secrets.NewPlaintext(append([]byte(nil), l.KeyPEM...))
}

func TestDeployCommitsAndVerifies(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	log := &steps{}
	out, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), log)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, "remote", out.Verified)
	assert.Equal(t, helperproto.BackupRoot+"/"+e.op.String(), out.Backup.Dir)
	assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok", "verify:started", "verify:ok"}, log.list())
	assert.Equal(t, pki.Fingerprint(nw.Cert), e.emu.Served(443, "www.example.test"))
	for _, line := range e.srv.Commands() {
		assert.NotContains(t, line, string(nw.KeyPEM[30:60]), "the key never travels on a command line")
	}
	stdins := e.emu.DeployStdins()
	require.Len(t, stdins, 1)
	assert.Contains(t, string(stdins[0]), "PRIVATE KEY", "the key travels only on stdin")
	var in helperproto.NginxDeployInput
	require.NoError(t, json.Unmarshal(stdins[0], &in))
	assert.Equal(t, string(nw.FullchainPEM), in.CertPEM)
	assert.Equal(t, string(nw.KeyPEM), in.KeyPEM, "the hand-built JSON is the helper's input")
}

// §26.6 "deploy idempotence test (run twice)" and §12.9 "Same cert already deployed".
func TestDeployTwiceIsIdempotent(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	req := e.req(t, nw)
	out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	require.Equal(t, providers.DeployCommitted, out.Result)
	out, err = e.open(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result, "the same operation answers from the helper's journal")
	assert.Equal(t, 1, e.emu.Reloads())

	again := e.req(t, nw) // a new operation with the files already in place
	again.OperationID = uuid.New()
	again.ExpectCertSHA256 = hexSHA(nw.FullchainPEM)
	out, err = e.open(t).DeployCertificate(context.Background(), again, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployUnchanged, out.Result)
	assert.Equal(t, 1, e.emu.Reloads(), "no reload when nothing changed")
}

// F-08: the connection drops after the helper finished; the provider reports uncertainty and the
// journal (DeploymentStatus on a new connection) tells the truth.
func TestDeployConnectionDropIsUncertain(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test"}, e.now)
	e.emu.HangupAfter(helperproto.StepReload)
	out, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
	require.Error(t, err)
	assert.Equal(t, providers.DeployUncertain, out.Result)
	st, err := e.open(t).DeploymentStatus(context.Background(), e.op)
	providertest.CheckDeploymentState(t, st, err)
	require.NoError(t, err)
	assert.Equal(t, providers.PhaseCommitted, st.Phase)
	assert.Equal(t, hexSHA(nw.FullchainPEM), st.NewCertSHA256)
	assert.Equal(t, hexSHA(nw.FullchainPEM), st.CurrentCertSHA256)
	assert.Equal(t, helperproto.BackupRoot+"/"+e.op.String(), st.BackupDir)
}

// A command is never re-sent: after an uncertain outcome the same operation goes again only as a
// newly built command, whose stdin is the key again (a wiped one would be zeros: CONTENT_MISMATCH).
func TestDeployResendBuildsANewCommand(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	req := e.req(t, nw)
	e.emu.HangupAfter(helperproto.StepBackup)
	out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
	require.Error(t, err)
	require.Equal(t, providers.DeployUncertain, out.Result)
	out, err = e.open(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	stdins := e.emu.DeployStdins()
	require.Len(t, stdins, 2)
	assert.Equal(t, string(stdins[0]), string(stdins[1]), "the same input, not zeros")
	assert.Contains(t, string(stdins[1]), "PRIVATE KEY")
}

func TestDeployInputEncoding(t *testing.T) {
	cert := []byte("-----BEGIN CERTIFICATE-----\nMII\"\\\t\r\x01/\n-----END CERTIFICATE-----\n")
	key := []byte("k\x1f")
	b, ok := deployInput(cert, key)
	require.True(t, ok)
	assert.Equal(t, cap(b), len(b), "one allocation of the final size")
	var in helperproto.NginxDeployInput
	require.NoError(t, json.Unmarshal(b, &in))
	assert.Equal(t, string(cert), in.CertPEM)
	assert.Equal(t, string(key), in.KeyPEM)
	assert.Equal(t, `{"cert_pem":"-----BEGIN CERTIFICATE-----\nMII\"\\\t\r\u0001/\n-----END CERTIFICATE-----\n","key_pem":"k\u001f"}`, string(b))
	for _, bad := range [][2][]byte{{nil, key}, {cert, nil}, {cert, []byte("k\xc3\xa9")}, {[]byte("\x80"), key}} {
		_, ok := deployInput(bad[0], bad[1])
		assert.False(t, ok)
	}
	l := pki.NewCA("C", pki.ECDSA256, unitNow).Issue(pki.Opts{CommonName: "c"}, unitNow)
	assert.Equal(t, 2, chainLength(l.FullchainPEM))
	assert.Equal(t, 1, chainLength(append(append([]byte{}, l.CertPEM...), l.KeyPEM...)), "only CERTIFICATE blocks count")
	assert.Equal(t, 0, chainLength([]byte("no pem")))
}

// Without a ChainLength in the request the provider counts the deployed chain's certificates.
func TestDeployCountsTheChainWhenTheRequestDoesNot(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	req := e.req(t, nw)
	req.ChainLength = 0
	req.CertificatePEM = nw.CertPEM // the leaf alone: the website then serves one certificate
	out, err := e.session(t).DeployCertificate(context.Background(), req, nil)
	providertest.CheckDeployOutcome(t, out, err)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
}

func TestDeployOnAClosedSessionSendsNothing(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test"}, e.now)
	req := e.req(t, nw)
	s := e.open(t)
	require.NoError(t, s.Close())
	before := len(e.srv.Commands())
	out, err := s.DeployCertificate(context.Background(), req, nil)
	providertest.CheckDeployOutcome(t, out, err)
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	rb, err := s.RollbackDeployment(context.Background(), providers.RollbackRequest{OperationID: e.op}, nil)
	providertest.CheckRollbackOutcome(t, rb, err)
	assert.Equal(t, providers.DeployNoChange, rb.Result)
	_, err = s.DeploymentStatus(context.Background(), e.op)
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	assert.Len(t, e.srv.Commands(), before)
}

func TestDeployResultFormatsWithoutTheKey(t *testing.T) {
	assert.NotContains(t, fmt.Sprintf("%v", providers.DeployRequest{PrivateKeyPEM: secrets.NewPlaintext([]byte("SECRETKEY"))}), "SECRETKEY")
}

// wantRollback is the exact outcome of one RollbackDeployment call.
type wantRollback struct {
	result                    providers.DeployResult
	phase, failed, cause, cls string
	verified                  string
	steps                     []string
	reason                    string
	backupDir                 bool
	errCode                   string
	retryable                 bool
	files                     string // "old" | "new" | ""
}

// The mapping of every nginx-restore answer (RollbackDeployment), each row after a deployment the
// row's prepare makes (or none); providertest.CheckRollbackOutcome runs on every return.
func TestRollbackOutcomeTable(t *testing.T) {
	const restoreSub = helperproto.SubNginxRestore
	commit := func(t *testing.T, e *env, nw pki.Leaf) {
		out, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
		require.NoError(t, err)
		require.Equal(t, providers.DeployCommitted, out.Result)
	}
	afterCommit := func(more func(*testing.T, *env, pki.Leaf, *providers.RollbackRequest)) func(*testing.T, *env, pki.Leaf, *providers.RollbackRequest) {
		return func(t *testing.T, e *env, nw pki.Leaf, r *providers.RollbackRequest) {
			commit(t, e, nw)
			if more != nil {
				more(t, e, nw, r)
			}
		}
	}
	verifiedRestore := cat(restored, []string{"verify_old:ok"})
	rows := []struct {
		name string
		prep func(t *testing.T, e *env, nw pki.Leaf, r *providers.RollbackRequest)
		ctx  func(t *testing.T) context.Context
		want wantRollback
	}{
		{"restored after a commit, old certificate verified", afterCommit(nil), nil,
			wantRollback{result: providers.DeployRolledBack, phase: "restored", verified: "remote", steps: verifiedRestore, files: "old"}},
		{"restored twice: the second answers from the journal", afterCommit(func(t *testing.T, e *env, _ pki.Leaf, r *providers.RollbackRequest) {
			out, err := e.open(t).RollbackDeployment(context.Background(), *r, nil)
			require.NoError(t, err)
			require.Equal(t, providers.DeployRolledBack, out.Result)
		}), nil, wantRollback{result: providers.DeployRolledBack, phase: "restored", verified: "remote", steps: []string{"verify_old:ok"}, files: "old"}},
		{"restored after the helper's own rollback: its failed step is not this call's", func(t *testing.T, e *env, nw pki.Leaf, _ *providers.RollbackRequest) {
			e.emu.FailReload(1)
			out, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
			require.NoError(t, err)
			require.Equal(t, providers.DeployRolledBack, out.Result)
		}, nil, wantRollback{result: providers.DeployRolledBack, phase: "restored", verified: "remote", steps: []string{"verify_old:ok"}, files: "old"}},
		{"restored, verification skipped", afterCommit(func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.RollbackRequest) { r.Verify.Skip = true }), nil,
			wantRollback{result: providers.DeployRolledBack, phase: "restored", verified: "skipped", steps: cat(restored, []string{"verify_old:skipped"}), files: "old"}},
		{"restored, no previous certificate to compare", afterCommit(func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.RollbackRequest) { r.OldFingerprint = "" }), nil,
			wantRollback{result: providers.DeployRolledBack, phase: "restored", steps: cat(restored, []string{"verify_old:skipped"}), files: "old"}},
		{"restored, the website cannot be checked", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			e.prober.set(true, false)
			e.emu.LocalProbeFails(true)
		}), nil, wantRollback{result: providers.DeployRolledBack, phase: "restored", steps: cat(restored, []string{"verify_old:failed"}), files: "old"}},
		{"restored, another certificate served: rollback_failed, phase restored", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			e.emu.ServeOtherAfterReload(443, strings.Repeat("c", 64))
		}), nil, wantRollback{result: providers.DeployRollbackFailed, phase: "restored", failed: "verify_old", steps: cat(restored, []string{"verify_old:failed"}),
			reason: "deployment.rollback_failed", backupDir: true, files: "old"}},
		{"restored, the old leaf with another chain length: rollback_failed", afterCommit(func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.RollbackRequest) {
			r.OldChainLength = 3
		}), nil, wantRollback{result: providers.DeployRollbackFailed, phase: "restored", failed: "verify_old", steps: cat(restored, []string{"verify_old:failed"}),
			reason: "deployment.rollback_failed", backupDir: true, files: "old"}},
		{"restore_failed: the reload fails", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) { e.emu.FailReload(1) }), nil,
			wantRollback{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "rollback_reload",
				steps: []string{"restore:ok", "rollback_config_test:ok", "rollback_reload:failed"}, reason: "deployment.rollback_reload_failed", backupDir: true, files: "old"}},
		{"restore_failed: the restore fails", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) { e.emu.FailRestoreFile(wwwKey) }), nil,
			wantRollback{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "restore", steps: []string{"restore:failed"},
				reason: "deployment.rollback_failed", backupDir: true}},
		{"HASH_MISMATCH: someone else's file, nothing restored", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			e.emu.SetNginxFile(wwwCert, []byte("someone else"))
		}), nil, wantRollback{result: providers.DeployRollbackFailed, failed: "restore", cls: "file_changed", reason: "deployment.rollback_failed", backupDir: true}},
		{"partly restored: the key changed between the restore's renames (A1-I2)", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			e.emu.InterfereAt("renamed "+".alice-"+e.op.String()+"-cert", wwwKey, []byte("someone else's key"))
		}), nil, wantRollback{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "restore", cls: "file_changed",
			steps: []string{"restore:failed"}, reason: "deployment.rollback_failed", backupDir: true}},
		{"nothing to restore: prepared", func(t *testing.T, e *env, nw pki.Leaf, _ *providers.RollbackRequest) {
			e.emu.KillAt("pair record renamed")
			_, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
			require.Error(t, err)
			require.Equal(t, helperproto.PhasePrepared, e.emu.NginxPhase(e.op.String()))
		}, nil, wantRollback{result: providers.DeployNoChange, phase: "prepared", reason: "deployment.nothing_to_restore", files: "old"}},
		{"nothing to restore: unchanged", func(t *testing.T, e *env, nw pki.Leaf, r *providers.RollbackRequest) {
			commit(t, e, nw)
			again := e.req(t, nw)
			again.OperationID = uuid.New()
			again.ExpectCertSHA256 = hexSHA(nw.FullchainPEM)
			out, err := e.open(t).DeployCertificate(context.Background(), again, nil)
			require.NoError(t, err)
			require.Equal(t, providers.DeployUnchanged, out.Result)
			r.OperationID = again.OperationID
		}, nil, wantRollback{result: providers.DeployNoChange, phase: "unchanged", reason: "deployment.nothing_to_restore", files: "new"}},
		{"unknown operation", nil, nil, wantRollback{result: providers.DeployNoChange, reason: "deployment.unknown_operation", errCode: "deployment.unknown_operation", files: "old"}},
		{"superseded by a later deployment", func(t *testing.T, e *env, nw pki.Leaf, _ *providers.RollbackRequest) {
			commit(t, e, nw)
			later := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
			req := e.req(t, later)
			req.OperationID = uuid.New()
			req.ExpectCertSHA256 = hexSHA(nw.FullchainPEM)
			req.OldFingerprint = pki.Fingerprint(nw.Cert)
			out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
			require.NoError(t, err)
			require.Equal(t, providers.DeployCommitted, out.Result)
		}, nil, wantRollback{result: providers.DeployNoChange, reason: "deployment.superseded", errCode: "deployment.superseded"}},
		{"busy", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) { e.emu.HoldLock(true) }), nil,
			wantRollback{result: providers.DeployNoChange, reason: "nginx.busy", errCode: "nginx.busy", retryable: true, files: "new"}},
		{"profile missing", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) { e.emu.SetNginxProfile(false) }), nil,
			wantRollback{result: providers.DeployNoChange, reason: "nginx.profile_missing", errCode: "nginx.profile_missing", files: "new"}},
		{"cancelled before the send", afterCommit(nil), func(t *testing.T) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, wantRollback{result: providers.DeployNoChange, reason: "ssh.timeout", errCode: "ssh.timeout", retryable: true, files: "new"}},
		{"killed by a signal", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			e.emu.KillAt(helperproto.StepRestore)
		}), nil,
			wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error"}},
		{"killed, exit 137", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			e.emu.KillAtWithExit137(helperproto.StepRestore)
		}), nil, wantRollback{result: providers.DeployUncertain, errCode: "ssh.helper_missing"}},
		{"connection lost", afterCommit(func(_ *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) { hangUpOn(e, restoreSub) }), nil,
			wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "new"}},
		{"an unknown code", afterCommit(func(t *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			scriptOn(e, restoreSub, refusal(t, 3, "GONE"))
		}), nil,
			wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "new"}},
		{"an unknown phase", afterCommit(func(t *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			scriptOn(e, restoreSub, linuxsshtest.Response{Stdout: answerJSON(t, helperproto.NginxRestoreResponse{OK: true, Phase: "restoring"})})
		}), nil, wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "new"}},
		{"restored with a failed step", afterCommit(func(t *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			scriptOn(e, restoreSub, linuxsshtest.Response{Stdout: answerJSON(t, helperproto.NginxRestoreResponse{OK: true, Phase: "restored",
				Steps: []helperproto.NginxStep{failedHelperStep("restore", "")}})})
		}), nil, wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "new"}},
		{"nothing to restore with steps", afterCommit(func(t *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			scriptOn(e, restoreSub, linuxsshtest.Response{Stdout: answerJSON(t, helperproto.NginxRestoreResponse{OK: true, Phase: "prepared", Steps: okSteps("restore")})})
		}), nil, wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "new"}},
		{"restore_failed at a step a rollback does not have", afterCommit(func(t *testing.T, e *env, _ pki.Leaf, _ *providers.RollbackRequest) {
			scriptOn(e, restoreSub, linuxsshtest.Response{Stdout: answerJSON(t, helperproto.NginxRestoreResponse{OK: true, Phase: "restore_failed", FailedStep: "backup"})})
		}), nil, wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error", files: "new"}},
		{"no operation id", func(_ *testing.T, _ *env, _ pki.Leaf, r *providers.RollbackRequest) { r.OperationID = uuid.Nil }, nil,
			wantRollback{result: providers.DeployNoChange, reason: "internal.unexpected", errCode: "internal.unexpected", files: "old"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e := newEnv(t)
			nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
			rb := providers.RollbackRequest{OperationID: e.op, Location: e.location(t), OldFingerprint: pki.Fingerprint(e.leaf.Cert), OldChainLength: 2,
				OldSANs: e.leaf.Cert.DNSNames, KeyType: "ecdsa"}
			if row.prep != nil {
				row.prep(t, e, nw, &rb)
			}
			ctx := context.Background()
			if row.ctx != nil {
				ctx = row.ctx(t)
			}
			log := &steps{}
			out, err := e.session(t).RollbackDeployment(ctx, rb, log)
			providertest.CheckRollbackOutcome(t, out, err)
			w := row.want
			assert.Equal(t, w.result, out.Result, "result")
			assert.Equal(t, w.phase, out.Phase, "phase")
			assert.Equal(t, w.failed, out.FailedStep, "failed step")
			assert.Equal(t, w.cause, out.CauseStep, "cause step")
			assert.Equal(t, w.cls, out.Error, "error class")
			assert.Equal(t, w.verified, out.Verified, "verified")
			assert.Equal(t, w.steps, stepList(out.Steps), "steps")
			assert.Equal(t, w.reason, out.Reason, "reason")
			if w.backupDir {
				assert.Equal(t, map[string]string{"backup_dir": helperproto.BackupRoot + "/" + rb.OperationID.String()}, out.Params)
			} else if w.errCode == "" || w.result == providers.DeployUncertain {
				assert.Empty(t, out.Params)
			}
			if w.errCode == "" {
				assert.NoError(t, err)
			} else {
				pe := providerErr(t, err)
				assert.Equal(t, w.errCode, pe.Code, "error code")
				assert.Equal(t, w.retryable, pe.Retryable, "retryable")
			}
			switch w.files {
			case "old":
				assert.Equal(t, string(e.leaf.FullchainPEM), string(e.emu.NginxFile(wwwCert)))
				assert.Equal(t, string(e.leaf.KeyPEM), string(e.emu.NginxFile(wwwKey)))
			case "new":
				assert.Equal(t, string(nw.FullchainPEM), string(e.emu.NginxFile(wwwCert)))
				assert.Equal(t, string(nw.KeyPEM), string(e.emu.NginxFile(wwwKey)))
			}
			var logged []string
			for _, l := range log.list() {
				if !strings.HasSuffix(l, ":started") {
					logged = append(logged, l)
				}
			}
			var outSteps []string
			for _, st := range out.Steps {
				outSteps = append(outSteps, st.Name+":"+string(st.Status))
			}
			assert.Equal(t, outSteps, logged, "logged steps")
		})
	}
}

func TestRollbackDeployment(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	_, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
	require.NoError(t, err)
	rb := providers.RollbackRequest{OperationID: e.op, Location: e.location(t), OldFingerprint: pki.Fingerprint(e.leaf.Cert), KeyType: "ecdsa"}
	log := &steps{}
	out, err := e.open(t).RollbackDeployment(context.Background(), rb, log)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result)
	assert.Equal(t, "remote", out.Verified)
	assert.Equal(t, []string{"restore:ok", "rollback_config_test:ok", "rollback_reload:ok", "verify_old:started", "verify_old:ok"}, log.list())
	out, err = e.open(t).RollbackDeployment(context.Background(), rb, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result, "idempotent")
	assert.Equal(t, 2, e.emu.Reloads(), "the second call restores nothing and does not reload")
}

// The engine (jobs may not import helperproto) uses providers.Phase* and StepName*; they must be
// the helper's names.
func TestPhaseAndStepNamesMatchTheHelper(t *testing.T) {
	assert.Equal(t, []string{helperproto.PhaseNone, helperproto.PhasePrepared, helperproto.PhaseWriting, helperproto.PhaseCommitted,
		helperproto.PhaseUnchanged, helperproto.PhaseRestoring, helperproto.PhaseRestored, helperproto.PhaseRestoreFailed},
		[]string{providers.PhaseNone, providers.PhasePrepared, providers.PhaseWriting, providers.PhaseCommitted,
			providers.PhaseUnchanged, providers.PhaseRestoring, providers.PhaseRestored, providers.PhaseRestoreFailed})
	assert.Equal(t, helperPhases, []string{providers.PhaseNone, providers.PhasePrepared, providers.PhaseWriting, providers.PhaseCommitted,
		providers.PhaseUnchanged, providers.PhaseRestoring, providers.PhaseRestored, providers.PhaseRestoreFailed})
	assert.Equal(t, []string{helperproto.StepBackup, helperproto.StepWriteKey, helperproto.StepWriteCert, helperproto.StepConfigTest, helperproto.StepReload,
		helperproto.StepJournal, helperproto.StepRestore, helperproto.StepRollbackConfigTest, helperproto.StepRollbackReload},
		[]string{providers.StepNameBackup, providers.StepNameWriteKey, providers.StepNameWriteCert, providers.StepNameConfigTest, providers.StepNameReload,
			providers.StepNameJournal, providers.StepNameRestore, providers.StepNameRollbackConfigTest, providers.StepNameRollbackReload})
	assert.Equal(t, helperproto.RestoreErrFileChanged, providers.DeployErrFileChanged)
	helper, _ := sources(t)
	assert.Equal(t, withPrefix(helper, "Step"), sorted(helperSteps), "helperproto.Step* -> helperSteps")
	assert.Equal(t, withPrefix(helper, "Phase"), sorted(helperPhases), "helperproto.Phase* -> helperPhases")
	var classes []string
	for _, c := range withPrefix(helper, "ConfigErr") {
		if c != helperproto.ConfigErrUntrusted && c != helperproto.ConfigErrUnsupported {
			classes = append(classes, c)
		}
	}
	assert.Equal(t, classes, sorted(nginxClasses), "nginx -t's classes")
}

func TestDeploymentStatusPhases(t *testing.T) {
	e := newEnv(t)
	status := func() (providers.DeploymentState, error) {
		s := e.open(t)
		defer func() { _ = s.Close() }()
		st, err := s.DeploymentStatus(context.Background(), e.op)
		providertest.CheckDeploymentState(t, st, err)
		return st, err
	}
	st, err := status()
	require.NoError(t, err)
	assert.Equal(t, providers.DeploymentState{Phase: providers.PhaseNone}, st, "no journal: the helper's backup_dir is not passed on")

	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	e.emu.KillAt(helperproto.StepWriteCert)
	_, _ = e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
	st, err = status()
	require.NoError(t, err)
	assert.Equal(t, helperproto.PhaseWriting, st.Phase)
	assert.False(t, st.Active)
	assert.Equal(t, hexSHA(nw.FullchainPEM), st.NewCertSHA256)
	assert.Equal(t, hexSHA(nw.FullchainPEM), st.CurrentCertSHA256, "killed after the certificate's rename (the write_cert point)")
	assert.Equal(t, helperproto.BackupRoot+"/"+e.op.String(), st.BackupDir)

	e.emu.HoldLock(true)
	st, err = status()
	require.NoError(t, err)
	assert.True(t, st.Active)
	e.emu.HoldLock(false)

	e.emu.FailReload(1)
	e.emu.ArmFaultsFor(helperproto.SubNginxRestore)
	rb, err := e.open(t).RollbackDeployment(context.Background(), providers.RollbackRequest{OperationID: e.op}, nil)
	providertest.CheckRollbackOutcome(t, rb, err)
	require.NoError(t, err)
	st, err = status()
	require.NoError(t, err)
	assert.Equal(t, providers.DeploymentState{Phase: providers.PhaseRestoreFailed, FailedStep: "rollback_reload", NewCertSHA256: hexSHA(nw.FullchainPEM),
		CurrentCertSHA256: hexSHA(e.leaf.FullchainPEM), BackupDir: helperproto.BackupRoot + "/" + e.op.String()}, st)

	// Answers outside the helper's contract are errors, never states.
	ok := helperproto.NginxStatusResponse{OK: true, Phase: "committed", NewCertSHA256: strings.Repeat("a", 64), BackupDir: "/x"}
	for name, r := range map[string]helperproto.NginxStatusResponse{
		"unknown phase":            {OK: true, Phase: "done"},
		"committed with a failure": func() helperproto.NginxStatusResponse { c := ok; c.FailedStep = "reload"; return c }(),
		"unknown step":             func() helperproto.NginxStatusResponse { c := ok; c.Phase = "restored"; c.FailedStep = "rm"; return c }(),
		"unknown cause":            func() helperproto.NginxStatusResponse { c := ok; c.Phase = "restored"; c.CauseStep = "rm"; return c }(),
		"raw text as a class": func() helperproto.NginxStatusResponse {
			c := ok
			c.Phase = "restored"
			c.Error = "nginx: [emerg]"
			return c
		}(),
		"bad new hash":     func() helperproto.NginxStatusResponse { c := ok; c.NewCertSHA256 = "absent"; return c }(),
		"bad current hash": func() helperproto.NginxStatusResponse { c := ok; c.CurrentCertSHA256 = "zz"; return c }(),
	} {
		scriptOn(e, helperproto.SubNginxStatus, linuxsshtest.Response{Stdout: answerJSON(t, r)})
		_, err := status()
		assert.Equal(t, "ssh.protocol_error", providerErr(t, err).Code, name)
	}
	scriptOn(e, helperproto.SubNginxStatus, linuxsshtest.Response{Stdout: answerJSON(t, ok)})
	st, err = status()
	require.NoError(t, err)
	assert.Equal(t, helperproto.BackupRoot+"/"+e.op.String(), st.BackupDir, "the operation's directory, not the remote text")
	scriptOn(e, helperproto.SubNginxStatus, refusal(t, 4, helperproto.CodeIOError))
	_, err = status()
	assert.Equal(t, "IO_ERROR", providerErr(t, err).Params["helper_code"])
	_, err = e.open(t).DeploymentStatus(context.Background(), uuid.Nil)
	assert.Equal(t, "internal.unexpected", providerErr(t, err).Code)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = e.open(t).DeploymentStatus(ctx, e.op)
	assert.ErrorIs(t, err, context.Canceled)
}

// keyRenderings is the private key of l the ways it could leak: its PEM text and a piece of its
// base64 body, its DER as hex, as decimal bytes (fmt's %v of a []byte) and as base64.
func keyRenderings(t *testing.T, l pki.Leaf) []string {
	t.Helper()
	block, _ := pem.Decode(l.KeyPEM)
	require.NotNil(t, block)
	body := strings.Join(strings.Split(string(l.KeyPEM), "\n")[1:2], "")
	der := block.Bytes
	return []string{
		string(l.KeyPEM), body[10:42], "PRIVATE KEY",
		hex.EncodeToString(der[:24]), strings.Trim(fmt.Sprintf("%d", der[:24]), "[]"),
		base64.StdEncoding.EncodeToString(der)[8:40], base64.StdEncoding.EncodeToString(l.KeyPEM)[8:40],
	}
}

// Requirement: the key goes only onto nginx-deploy's stdin. Through every outcome (refusal before
// and by the helper, committed, rolled back inline and by the helper, rollback failed, no change
// with phase unchanged, and uncertain by kill, exit 137, hangup and a malformed answer) neither
// the outcome, the error (its whole chain), the logged steps and params, nor a command line
// carries any rendering of the key.
func TestDeployNeverLeaksTheKey(t *testing.T) {
	for name, setup := range map[string]func(e *env, nw pki.Leaf, r *providers.DeployRequest){
		"refused before the helper": func(_ *env, _ pki.Leaf, r *providers.DeployRequest) { r.Location.Supported = false },
		"refused by the helper":     func(e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.SetFreeBytes(1) },
		"bad content":               func(_ *env, _ pki.Leaf, r *providers.DeployRequest) { r.CertificatePEM = []byte("x") },
		"committed":                 func(*env, pki.Leaf, *providers.DeployRequest) {},
		"rolled back inline":        func(e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.NoopReload(true) },
		"rolled back by the helper": func(e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.FailReload(1) },
		"rollback failed":           func(e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.FailReload(2) },
		"unchanged, not served": func(e *env, nw pki.Leaf, r *providers.DeployRequest) {
			e.emu.SetNginxFile(wwwCert, nw.FullchainPEM)
			e.emu.SetNginxFile(wwwKey, nw.KeyPEM)
			r.ExpectCertSHA256 = hexSHA(nw.FullchainPEM)
		},
		"killed": func(e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.KillAt(helperproto.StepWriteCert) },
		"killed, exit 137": func(e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.KillAtWithExit137(helperproto.StepWriteKey)
		},
		"hangup": func(e *env, _ pki.Leaf, _ *providers.DeployRequest) { e.emu.HangupAfter(helperproto.StepReload) },
		"malformed answer": func(e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			scriptOn(e, helperproto.SubNginxDeploy, linuxsshtest.Response{Stdout: []byte("{")})
		},
		"inline restore lost": func(e *env, _ pki.Leaf, _ *providers.DeployRequest) {
			e.emu.NoopReload(true)
			hangUpOn(e, helperproto.SubNginxRestore)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
			req := e.req(t, nw)
			setup(e, nw, &req)
			log := &steps{}
			out, err := e.session(t).DeployCertificate(context.Background(), req, log)
			providertest.CheckDeployOutcome(t, out, err)
			secretTexts := keyRenderings(t, nw)
			values := []any{out, err, log.list()}
			for _, p := range log.params {
				values = append(values, p)
			}
			providertest.CheckNoSecrets(t, secretTexts, values...)
			lines := strings.Join(e.srv.Commands(), "\n")
			for _, s := range secretTexts {
				assert.NotContains(t, lines, s, "a command line")
			}
		})
	}
}

func TestAnswerValidators(t *testing.T) {
	_, ok := toSteps(make([]helperproto.NginxStep, maxAnswerSteps+1))
	assert.False(t, ok, "too many steps")
	_, ok = toSteps([]helperproto.NginxStep{{Name: "backup", Status: "started"}})
	assert.False(t, ok, "a status the helper does not answer")
	_, ok = toSteps([]helperproto.NginxStep{{Name: "reload", Status: "failed", Error: "raw text"}})
	assert.False(t, ok, "a class outside the vocabulary")
	st, ok := toSteps([]helperproto.NginxStep{{Name: "restore", Status: "ok", Error: "file_changed"}})
	assert.True(t, ok)
	assert.Equal(t, []providers.DeployStep{{Name: "restore", Status: providers.StepOK, Error: "file_changed"}}, st)

	for _, tc := range []struct {
		failed, cause, class string
		ok                   bool
	}{
		{"rollback_reload", "reload", "", true},
		{"rollback_config_test", "config_test", "syntax", true},
		{"restore", "", "", true},
		{"restore", "write_cert", "file_changed", true},
		{"write_cert", "write_cert", "file_changed", true},
		{"write_cert", "write_cert", "", false},
		{"write_cert", "reload", "file_changed", false},
		{"restore", "verify", "", false},
		{"rollback_reload", "reload", "raw", false},
		{"", "reload", "", false},
	} {
		assert.Equal(t, tc.ok, restoreFailedShape(tc.failed, tc.cause, tc.class), "%+v", tc)
	}

	assert.Equal(t, map[string]string{"port": "443"}, unverifiable(providers.CertLocation{}, providers.VerifyOptions{}, nil).Params)
	assert.Equal(t, map[string]string{"port": "8443"}, unverifiable(providers.CertLocation{}, providers.VerifyOptions{Port: 8443}, nil).Params)
	assert.Equal(t, "internal.unexpected", asProviderError(fmt.Errorf("plain")).Code)
}

// Important 3: a context that ends before the inline restore is sent is uncertain (the new files
// stay live, unverified; the engine's recovery finishes the rollback), carrying the verification's
// reason. Driven on the unexported step because the verification itself would see the cancelled
// context first.
func TestInlineRestoreNotSentIsUncertain(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	s := e.session(t)
	d := deployment{s: s, req: e.req(t, nw), out: providers.DeployOutcome{Steps: []providers.DeployStep{{Name: "verify", Status: providers.StepFailed}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := len(e.srv.Commands())
	out, err := d.rollBack(ctx, providers.VerifyResult{Reason: "deployment.verify_other", Params: map[string]string{"port": "443"}})
	providertest.CheckDeployOutcome(t, out, err)
	assert.Equal(t, providers.DeployUncertain, out.Result)
	assert.Equal(t, "deployment.verify_other", out.Reason)
	assert.Equal(t, map[string]string{"port": "443", "failed_step": "verify"}, out.Params)
	pe := providerErr(t, err)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Len(t, e.srv.Commands(), before, "nothing was sent")
}

// Minor 3: a check of the old certificate that cannot be made logs the port it would have probed.
func TestCheckOldLogsThePortOnAnError(t *testing.T) {
	e := newEnv(t)
	s := e.session(t)
	log := &steps{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, ok := s.checkOld(ctx, log, providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert)})
	assert.True(t, ok, "not checkable is not a wrong certificate")
	assert.Equal(t, providers.StepFailed, c.step.Status)
	assert.Equal(t, []string{"verify_old:started", "verify_old:failed"}, log.list())
	assert.Equal(t, map[string]string{"port": "443"}, log.params[1])
}

// Task 16 M-3: the failed verification's reason travels on its step, which the caller records
// before the rollback is sent.
func TestFailedVerificationStepCarriesItsReason(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	e.emu.NoopReload(true)
	log := &steps{}
	out, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), log)
	require.NoError(t, err)
	require.Equal(t, providers.DeployRolledBack, out.Result)
	i := slices.Index(log.list(), "verify:failed")
	require.GreaterOrEqual(t, i, 0)
	assert.Equal(t, map[string]string{"port": "443", "reason": "deployment.verify_failed"}, log.params[i])
	assert.Equal(t, "verify:failed", log.list()[i])
	assert.Less(t, i, slices.Index(log.list(), "restore:ok"), "logged before the rollback")
}
