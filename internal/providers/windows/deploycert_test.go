package windows

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/providertest"
	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// deployReq is a deployment of nl to the wenv's binding, which names the old certificate now.
func (w *wenv) deployReq(nl pki.Leaf) providers.DeployRequest {
	return providers.DeployRequest{OperationID: uuid.New(), Location: w.loc2, ExpectCertSHA256: derSHA256(w.old.Cert.Raw),
		CertificatePEM: nl.FullchainPEM, PrivateKeyPEM: providers.NewSecret(append([]byte(nil), nl.KeyPEM...)),
		Fingerprint: derSHA256(nl.Cert.Raw), SANs: []string{wHost}, KeyType: "ecdsa", OldFingerprint: derSHA256(w.old.Cert.Raw),
		OldSANs: []string{wHost}, ChainLength: 2}
}

// oldBackup is the BackupRef of a deployment over the wenv's old certificate.
func (w *wenv) oldBackup(op uuid.UUID) providers.BackupRef {
	return providers.BackupRef{OperationID: op, Store: "My", PreviousSHA1: w.oldSHA1, PreviousSHA256: derSHA256(w.old.Cert.Raw)}
}

func (w *wenv) countSent(sub string) int {
	n := 0
	for _, c := range w.srv.Commands() {
		if s, _, _ := strings.Cut(c, " "); s == sub {
			n++
		}
	}
	return n
}

func deployResponse(a winproto.DeployResponse) linuxsshtest.Response {
	a.OK = true
	b, _ := json.Marshal(a)
	return linuxsshtest.Response{Stdout: append(b, '\n')}
}

// stepLines renders steps as "name:status".
type wantDeploy struct {
	result                    providers.DeployResult
	phase, failed, cause, cls string
	verified                  string
	level                     int
	trust                     string
	steps                     []string
	reason                    string
	params                    map[string]string // nil: none
	errCode                   string            // "" = nil error
	retryable                 bool
	serves                    string // "old", "new" or "" (not checked)
	noDeploySent              bool
	restores                  int  // iis-restore commands sent
	answered                  bool // Backup is the helper's (previous certificate as it answered)
}

var (
	deployedOK = []string{"import_chain:ok", "import_certificate:ok", "bind:ok"}
	rootPool   = func(ca *pki.CA) *x509.CertPool { p := x509.NewCertPool(); p.AddCert(ca.Root); return p }
)

// The shape table of DeployCertificate (mirror of nginx's TestDeployOutcomeTable): each row drives the
// emulated host (or scripts the helper's raw answer where the emulator cannot produce it), asserts the
// whole outcome, and runs providers.CheckDeployReturn on every return.
func TestDeployOutcomeTable(t *testing.T) {
	backup := func(w *wenv) map[string]string { return map[string]string{"store": "My", "previous_sha1": w.oldSHA1} }
	type row struct {
		name  string
		setup func(t *testing.T, w *wenv, nl pki.Leaf, r *providers.DeployRequest)
		ctx   func(t *testing.T) context.Context
		want  func(w *wenv) wantDeploy
	}
	refused := func(reason string, retryable bool) func(*wenv) wantDeploy {
		return func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployNoChange, reason: reason, errCode: reason, retryable: retryable, serves: "old"}
		}
	}
	notSent := func(reason string) func(*wenv) wantDeploy {
		return func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployNoChange, reason: reason, errCode: reason, serves: "old", noDeploySent: true}
		}
	}
	rows := []row{
		// Committed and verified, at each R51 level.
		{"committed, level 3: a chain the trust policy holds", func(_ *testing.T, w *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Trust = &providers.TrustPolicy{Roots: rootPool(w.ca), Store: providers.TrustStoreSystem, Enforce: true}
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployCommitted, phase: "committed", verified: "remote", level: providers.LevelTrusted,
				trust: providers.TrustTrusted, steps: append(deployedOK, "verify:ok"), serves: "new", answered: true}
		}},
		{"committed, level 2: a private CA, not enforced (a warning)", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Trust = &providers.TrustPolicy{Roots: x509.NewCertPool(), Store: providers.TrustStoreSystem}
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployCommitted, phase: "committed", verified: "remote", level: providers.LevelServed,
				trust: providers.TrustUntrusted, steps: append(deployedOK, "verify:ok"), serves: "new", answered: true}
		}},
		{"committed, level 1: verification skipped", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Verify.Skip = true
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployCommitted, phase: "committed", verified: "skipped", level: providers.LevelInstalled,
				steps: append(deployedOK, "verify:skipped"), serves: "new", answered: true}
		}},
		{"unchanged: the binding names the certificate already", func(t *testing.T, w *wenv, nl pki.Leaf, r *providers.DeployRequest) {
			d := w.deploy(t, uuid.New(), w.old.Cert.Raw, nl)
			require.Equal(t, winproto.PhaseCommitted, d.Phase)
			r.ExpectCertSHA256 = derSHA256(nl.Cert.Raw)
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUnchanged, phase: "unchanged", verified: "remote", level: providers.LevelServed,
				steps: []string{"import_chain:ok", "import_certificate:ok", "verify:ok"}, serves: "new"}
		}},
		{"unchanged, then the verification fails: no_change, nothing to roll back", func(t *testing.T, w *wenv, nl pki.Leaf, r *providers.DeployRequest) {
			d := w.deploy(t, uuid.New(), w.old.Cert.Raw, nl)
			require.Equal(t, winproto.PhaseCommitted, d.Phase)
			r.ExpectCertSHA256 = derSHA256(nl.Cert.Raw)
			r.Trust = &providers.TrustPolicy{Roots: x509.NewCertPool(), Store: providers.TrustStoreSystem, Enforce: true}
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployNoChange, phase: "unchanged", failed: "verify", trust: providers.TrustUntrusted,
				steps: []string{"import_chain:ok", "import_certificate:ok", "verify:failed"}, reason: "deployment.verify_untrusted",
				params: map[string]string{"port": "443", "trust_error": providers.TrustErrUnknownAuthority}, errCode: "deployment.verify_untrusted", serves: "new"}
		}},

		// The helper's refusals: nothing changed.
		{"HASH_MISMATCH: the binding names another certificate than the token", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.ExpectCertSHA256 = strings.Repeat("ab", 32)
		}, nil, refused("windows.binding_changed", true)},
		{"BINDING_NOT_FOUND", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Location.Locator = providers.Locator{"type": "hostnameport", "host": "api.example.test", "port": 443, "app_id": winproto.AppIDIIS}
		}, nil, refused("windows.binding_not_found", false)},
		{"BUSY: another helper holds the lock", func(t *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			t.Cleanup(w.model.HoldLock())
		}, nil, refused("windows.busy", true)},
		{"JOURNAL_FAILED: a data directory the helper cannot trust", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.SetDataDirUnsafe(true)
		}, nil, refused("windows.io_error", true)},
		{"FENCED: the recovery ended this operation before it ran", func(t *testing.T, w *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			res := w.model.Handler()(winproto.SubIISFence+" --op "+r.OperationID.String(), nil)
			require.Equal(t, 0, res.Exit, "%s", res.Stdout)
		}, nil, refused("deployment.interrupted", false)},
		{"RECOVERY_PENDING: the binding's latest operation was interrupted", func(t *testing.T, w *wenv, nl pki.Leaf, _ *providers.DeployRequest) {
			w.model.KillAt("deploy.writing")
			w.deployRaw(t, uuid.New(), w.old.Cert.Raw, nl)
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployNoChange, reason: "deployment.recovery_pending", errCode: "deployment.recovery_pending", serves: "old"}
		}},
		{"a W1 helper's UNKNOWN_SUBCOMMAND: outdated", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.script(winproto.SubIISDeploy, func([]byte) linuxsshtest.Response { return refusalResponse(2, winproto.CodeUnknownSubcommand) })
		}, nil, refused("windows.helper_outdated", false)},

		// Refusals before anything is sent.
		{"provider: location unsupported", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) { r.Location.Supported = false },
			nil, notSent("windows.location_unsupported")},
		{"provider: a location of another kind", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Location.Kind = providers.LocationServerFile
		}, nil, notSent("windows.location_unsupported")},
		{"provider: a ccs locator", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Location.Locator = providers.Locator{"type": "ccs", "port": 443, "app_id": winproto.AppIDIIS}
		}, nil, notSent("windows.location_unsupported")},
		{"provider: no certificate in the chain", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.CertificatePEM = []byte("not pem")
		}, nil, notSent("certificate.invalid")},
		{"provider: a key that is not ASCII PEM text", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			copy(r.PrivateKeyPEM.Bytes()[40:], []byte{0xff})
		}, nil, notSent("certificate.invalid")},
		{"provider: an input larger than the helper takes", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.CertificatePEM = append(append([]byte{}, r.CertificatePEM...), bytes.Repeat([]byte("\n"), winproto.MaxDeployInput)...)
		}, nil, notSent("certificate.invalid")},
		{"provider: a fingerprint that is not the chain's leaf", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Fingerprint = strings.Repeat("cd", 32)
		}, nil, notSent("internal.unexpected")},
		{"provider: no operation id", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) { r.OperationID = uuid.Nil },
			nil, notSent("internal.unexpected")},
		{"provider: no token", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) { r.ExpectCertSHA256 = "" },
			nil, notSent("internal.unexpected")},
		{"provider: a guard the helper would refuse", func(_ *testing.T, _ *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Guard = providers.RollbackGuard{ForbiddenLeaf: []string{"nope"}}
		}, nil, notSent("internal.unexpected")},
		{"provider: cancelled before the send", nil, func(*testing.T) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployNoChange, reason: "ssh.timeout", errCode: "ssh.timeout", retryable: true, serves: "old", noDeploySent: true}
		}},

		// The helper's own restore after a failed step.
		{"key_unusable: http.sys's 1312 at the bind, nothing written", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.FailUpdate(winhelper.ErrKeyUnusable)
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "bind", cause: "bind", cls: "key_unusable",
				reason: "windows.key_unusable", verified: "remote", steps: []string{"import_chain:ok", "import_certificate:ok", "bind:failed", "verify_old:ok"},
				serves: "old", answered: true}
		}},
		{"read_back: the record read back differs, the helper restored it", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.CorruptReadBack(true)
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "bind", cause: "bind", cls: "read_back",
				reason: "deployment.interrupted", verified: "remote",
				steps: []string{"import_chain:ok", "import_certificate:ok", "bind:failed", "restore:ok", "verify_old:ok"}, serves: "old", answered: true}
		}},
		{"import failure: the store refused the certificate", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.FailImport(true)
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "import_certificate", cause: "import_certificate", cls: "store_error",
				reason: "windows.store_error", verified: "remote", steps: []string{"import_chain:ok", "import_certificate:failed", "verify_old:ok"},
				serves: "old", answered: true}
		}},
		{"the helper's restore is forbidden by the guard (R48)", func(_ *testing.T, w *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			w.model.CorruptReadBack(true)
			r.Guard = providers.RollbackGuard{ForbiddenLeaf: []string{derSHA256(w.old.Cert.Raw)}, TargetForbidden: true}
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_forbidden", failed: "restore", cause: "bind", cls: "forbidden",
				reason: "deployment.rollback_forbidden", params: map[string]string{},
				steps: []string{"import_chain:ok", "import_certificate:ok", "bind:failed", "restore:failed"}, serves: "new", answered: true}
		}},
		{"the helper's restore failed", func(_ *testing.T, w *wenv, nl pki.Leaf, _ *providers.DeployRequest) {
			w.script(winproto.SubIISDeploy, func([]byte) linuxsshtest.Response {
				return deployResponse(winproto.DeployResponse{Phase: "restore_failed", FailedStep: "restore", CauseStep: "bind", Error: "io_error",
					Steps:   []winproto.Step{{Name: "bind", Status: "failed", Error: "io_error"}, {Name: "restore", Status: "failed", Error: "io_error"}},
					NewSHA1: sha1Hex(nl.Cert.Raw), NewSHA256: derSHA256(nl.Cert.Raw), PreviousSHA1: w.oldSHA1, PreviousSHA256: derSHA256(w.old.Cert.Raw),
					Store: "My", BuiltChainLength: 2})
			})
		}, nil, func(w *wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "restore", cause: "bind", cls: "io_error",
				reason: "deployment.rollback_failed", params: backup(w), steps: []string{"bind:failed", "restore:failed"}, answered: true}
		}},

		{"io_error: the update failed, the helper restored the record", func(_ *testing.T, w *wenv, nl pki.Leaf, _ *providers.DeployRequest) {
			w.script(winproto.SubIISDeploy, func([]byte) linuxsshtest.Response {
				return deployResponse(winproto.DeployResponse{Phase: "restored", FailedStep: "bind", CauseStep: "bind", Error: "io_error",
					Steps: []winproto.Step{{Name: "import_chain", Status: "ok"}, {Name: "import_certificate", Status: "ok"},
						{Name: "bind", Status: "failed", Error: "io_error"}, {Name: "restore", Status: "ok"}},
					NewSHA1: sha1Hex(nl.Cert.Raw), NewSHA256: derSHA256(nl.Cert.Raw), PreviousSHA1: w.oldSHA1, PreviousSHA256: derSHA256(w.old.Cert.Raw),
					Store: "My", BuiltChainLength: 2})
			})
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "bind", cause: "bind", cls: "io_error",
				reason: "windows.io_error", verified: "remote",
				steps: []string{"import_chain:ok", "import_certificate:ok", "bind:failed", "restore:ok", "verify_old:ok"}, serves: "old", answered: true}
		}},

		// A failed verification of a committed deployment: the inline rollback.
		{"verification fails (StaleTLS): rolled back, the previous leaf served", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.StaleTLS(true)
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRolledBack, phase: "restored", failed: "verify", cause: "verify", reason: "deployment.verify_failed",
				params: map[string]string{"port": "443"}, verified: "remote", steps: append(deployedOK, "verify:failed", "restore:ok", "verify_old:ok"),
				serves: "old", restores: 1, answered: true}
		}},
		{"verification fails and the old leaf is not served either: rollback_failed verify_old", func(_ *testing.T, w *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			r.Trust = &providers.TrustPolicy{Roots: x509.NewCertPool(), Store: providers.TrustStoreSystem, Enforce: true}
			// A restore that answers restored while the website keeps the new certificate.
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response {
				b, _ := json.Marshal(winproto.RestoreResponse{OK: true, Phase: "restored", Steps: []winproto.Step{{Name: "restore", Status: "ok"}}})
				return linuxsshtest.Response{Stdout: append(b, '\n')}
			})
		}, nil, func(w *wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRollbackFailed, phase: "restored", failed: "verify_old", cause: "verify",
				reason: "deployment.rollback_failed", params: backup(w), trust: providers.TrustUntrusted,
				steps: append(deployedOK, "verify:failed", "restore:ok", "verify_old:failed"), serves: "new", restores: 1, answered: true}
		}},
		{"a forbidden backup after a failed verification: rollback_failed forbidden", func(_ *testing.T, w *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			w.model.StaleTLS(true)
			r.RecheckGuard = func(context.Context) (providers.RollbackGuard, error) {
				return providers.RollbackGuard{ForbiddenLeaf: []string{derSHA256(w.old.Cert.Raw)}, TargetForbidden: true}, nil
			}
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_forbidden", failed: "restore", cause: "verify", cls: "forbidden",
				reason: "deployment.rollback_forbidden", params: map[string]string{}, steps: append(deployedOK, "verify:failed", "restore:failed"),
				restores: 1, answered: true}
		}},
		{"the guard cannot be read again: uncertain with the verification's reason", func(_ *testing.T, w *wenv, _ pki.Leaf, r *providers.DeployRequest) {
			w.model.StaleTLS(true)
			r.RecheckGuard = func(context.Context) (providers.RollbackGuard, error) {
				return providers.RollbackGuard{}, fmt.Errorf("db down")
			}
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUncertain, reason: "deployment.verify_failed", params: map[string]string{"port": "443", "failed_step": "verify"},
				errCode: "internal.unexpected", retryable: true, steps: append(deployedOK, "verify:failed"), answered: true}
		}},
		{"BUSY on the inline restore three times: uncertain with the verification's reason", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.StaleTLS(true)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return refusalResponse(4, winproto.CodeBusy) })
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUncertain, reason: "deployment.verify_failed", params: map[string]string{"port": "443", "failed_step": "verify"},
				errCode: "windows.busy", retryable: true, steps: append(deployedOK, "verify:failed"), restores: 3, answered: true}
		}},
		{"BACKUP_MISSING on the inline restore: rollback_failed", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.StaleTLS(true)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return refusalResponse(3, winproto.CodeBackupMissing) })
		}, nil, func(w *wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRollbackFailed, failed: "restore", cause: "verify", cls: "backup_missing", reason: "windows.backup_missing",
				params: backup(w), steps: append(deployedOK, "verify:failed"), restores: 1, answered: true}
		}},
		{"the inline restore's restore_failed", func(t *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.StaleTLS(true)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response {
				b, _ := json.Marshal(winproto.RestoreResponse{OK: true, Phase: "restore_failed", FailedStep: "restore", Error: "file_changed",
					Steps: []winproto.Step{{Name: "restore", Status: "failed", Error: "file_changed"}}})
				return linuxsshtest.Response{Stdout: append(b, '\n')}
			})
		}, nil, func(w *wenv) wantDeploy {
			return wantDeploy{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "restore", cause: "verify", cls: "file_changed",
				reason: "deployment.rollback_failed", params: backup(w), steps: append(deployedOK, "verify:failed", "restore:failed"), restores: 1, answered: true}
		}},
		{"nothing to restore after a committed answer: uncertain", func(t *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.StaleTLS(true)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response {
				b, _ := json.Marshal(winproto.RestoreResponse{OK: true, Phase: "unchanged"})
				return linuxsshtest.Response{Stdout: append(b, '\n')}
			})
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUncertain, reason: "deployment.verify_failed", params: map[string]string{"port": "443", "failed_step": "verify"},
				errCode: "ssh.protocol_error", steps: append(deployedOK, "verify:failed"), restores: 1, answered: true}
		}},
		{"the context ends during the verification: interrupted, uncertain", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.probe.block = true
		}, func(t *testing.T) context.Context {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			t.Cleanup(cancel)
			return ctx
		}, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUncertain, reason: "deployment.interrupted", params: map[string]string{"failed_step": "verify"},
				errCode: "ssh.timeout", retryable: true, steps: append(deployedOK, "verify:failed"), serves: "new", answered: true}
		}},

		// Uncertain: the send happened and Alice does not know the outcome.
		{"a transport failure after the send", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.script(winproto.SubIISDeploy, func([]byte) linuxsshtest.Response { return linuxsshtest.Response{Hangup: true} })
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error"}
		}},
		{"killed after the bind: no answer", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.model.KillAt("deploy.bound")
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUncertain, errCode: "windows.helper_missing", serves: "new"}
		}},
		{"OPERATION_EXISTS: an earlier send of this operation may have changed the binding", func(t *testing.T, w *wenv, nl pki.Leaf, r *providers.DeployRequest) {
			d := w.deploy(t, r.OperationID, w.old.Cert.Raw, nl)
			require.Equal(t, winproto.PhaseCommitted, d.Phase)
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUncertain, errCode: "windows.helper_refused", serves: "new"}
		}},
		{"a known code at another exit status", func(_ *testing.T, w *wenv, _ pki.Leaf, _ *providers.DeployRequest) {
			w.script(winproto.SubIISDeploy, func([]byte) linuxsshtest.Response { return refusalResponse(4, winproto.CodeHashMismatch) })
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", serves: "old"}
		}},
	}
	// Answers outside the helper's contract.
	for name, a := range map[string]func(w *wenv, nl pki.Leaf) winproto.DeployResponse{
		"an unknown phase": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "writing"}
		},
		"committed with a failed step": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "committed", Steps: []winproto.Step{{Name: "bind", Status: "failed", Error: "io_error"}}}
		},
		"committed with a failure class": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "committed", Error: "io_error"}
		},
		"a step outside the vocabulary": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "committed", Steps: []winproto.Step{{Name: "reload", Status: "ok"}}}
		},
		"restored with an unknown class": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "restored", FailedStep: "bind", CauseStep: "bind", Error: "file_changed"}
		},
		"restored with another cause": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "restored", FailedStep: "bind", CauseStep: "import_chain", Error: "read_back"}
		},
		"restore_forbidden without a cause": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "restore_forbidden", FailedStep: "restore", Error: "forbidden"}
		},
		"restore_failed with forbidden": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "restore_failed", FailedStep: "restore", CauseStep: "bind", Error: "forbidden"}
		},
		"restore_failed without a cause": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "restore_failed", FailedStep: "restore", Error: "io_error"}
		},
		"another new certificate": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "committed", NewSHA256: strings.Repeat("ef", 32)}
		},
		"another previous certificate": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "committed", PreviousSHA256: strings.Repeat("ef", 32)}
		},
		"a store outside the vocabulary": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "committed", Store: "My\\..\\Root"}
		},
		"a built chain over the bound": func(w *wenv, nl pki.Leaf) winproto.DeployResponse {
			return winproto.DeployResponse{Phase: "committed", BuiltChainLength: winproto.MaxChainCerts + 2}
		},
	} {
		rows = append(rows, row{"contract: " + name, func(_ *testing.T, w *wenv, nl pki.Leaf, _ *providers.DeployRequest) {
			good := winproto.DeployResponse{NewSHA1: sha1Hex(nl.Cert.Raw), NewSHA256: derSHA256(nl.Cert.Raw), PreviousSHA1: w.oldSHA1,
				PreviousSHA256: derSHA256(w.old.Cert.Raw), Store: "My", BuiltChainLength: 2}
			bad := a(w, nl)
			for _, f := range []struct {
				dst *string
				src string
			}{{&bad.NewSHA1, good.NewSHA1}, {&bad.NewSHA256, good.NewSHA256}, {&bad.PreviousSHA1, good.PreviousSHA1},
				{&bad.PreviousSHA256, good.PreviousSHA256}, {&bad.Store, good.Store}} {
				if *f.dst == "" {
					*f.dst = f.src
				}
			}
			if bad.BuiltChainLength == 0 {
				bad.BuiltChainLength = 2
			}
			w.script(winproto.SubIISDeploy, func([]byte) linuxsshtest.Response { return deployResponse(bad) })
		}, nil, func(*wenv) wantDeploy {
			return wantDeploy{result: providers.DeployUncertain, errCode: "ssh.protocol_error", serves: "old"}
		}})
	}

	for _, rw := range rows {
		t.Run(rw.name, func(t *testing.T) {
			w := newWEnv(t)
			nl := w.issue()
			req := w.deployReq(nl)
			if rw.setup != nil {
				rw.setup(t, w, nl, &req)
			}
			ctx := context.Background()
			if rw.ctx != nil {
				ctx = rw.ctx(t)
			}
			s := w.session(t)
			before := len(w.srv.Commands())
			log := &stepLog{}
			out, err := s.DeployCertificate(ctx, req, log)
			providertest.CheckDeployOutcome(t, out, err)
			want := rw.want(w)
			assert.Equal(t, want.result, out.Result, "result %+v %v", out, err)
			assert.Equal(t, want.phase, out.Phase, "phase")
			assert.Equal(t, want.failed, out.FailedStep, "failed step")
			assert.Equal(t, want.cause, out.CauseStep, "cause step")
			assert.Equal(t, want.cls, out.Error, "error class")
			assert.Equal(t, want.verified, out.Verified, "verified")
			if out.Result == providers.DeployCommitted || out.Result == providers.DeployUnchanged {
				assert.Equal(t, want.level, providers.VerificationLevel(out.Verified, out.Trust.Status), "level")
			}
			assert.Equal(t, want.trust, out.Trust.Status, "trust")
			assert.Equal(t, want.reason, out.Reason, "reason")
			if want.steps == nil {
				assert.Empty(t, out.Steps, "steps")
			} else {
				assert.Equal(t, want.steps, stepWords(out.Steps), "steps")
			}
			switch {
			case want.params != nil:
				assert.Equal(t, want.params, out.Params, "params")
			case out.Result != providers.DeployNoChange: // a refusal carries its error's params
				assert.Empty(t, out.Params, "params")
			}
			if want.answered {
				assert.Equal(t, w.oldBackup(req.OperationID), out.Backup, "backup")
			} else {
				assert.Equal(t, req.OperationID, out.Backup.OperationID, "backup's operation")
			}
			if want.errCode == "" {
				assert.NoError(t, err)
			} else {
				pe := providerErr(t, err)
				assert.Equal(t, want.errCode, pe.Code, "error code")
				assert.Equal(t, want.retryable, pe.Retryable, "retryable")
				assert.NotEqual(t, "ssh.helper_refused", pe.Code, "Ruling 6")
			}
			switch want.serves {
			case "old":
				assert.Equal(t, derSHA256(w.old.Cert.Raw), w.served(), "the previous certificate is served")
			case "new":
				assert.Equal(t, derSHA256(nl.Cert.Raw), w.served(), "the new certificate is served")
			}
			cmds := strings.Join(w.srv.Commands()[before:], "\n")
			if want.noDeploySent {
				assert.NotContains(t, cmds, winproto.SubIISDeploy, "nothing was sent")
			}
			assert.Equal(t, want.restores, strings.Count(cmds, winproto.SubIISRestore), "iis-restore sent")
			// The logger saw every final step of the outcome, in order (plus "started" entries).
			var logged []string
			for _, l := range log.lines() {
				name, _, _ := strings.Cut(l, " ")
				if !strings.HasSuffix(name, ":started") {
					logged = append(logged, name)
				}
			}
			assert.Equal(t, stepWordsOrNil(out.Steps), logged, "logged steps")
		})
	}
}

func stepWordsOrNil(steps []providers.DeployStep) []string {
	if len(steps) == 0 {
		return nil
	}
	return stepWords(steps)
}

// Review Focus 1: the helper's OUTCOME_UNKNOWN (the budget ended after its first durable write) is
// uncertain, never a refusal; DeploymentStatus afterwards reads what the journal says.
func TestDeployOutcomeUnknownIsUncertain(t *testing.T) {
	w := newWEnv(t)
	inner := w.model.Handler()
	w.record(func(cmd string, stdin []byte) linuxsshtest.Response {
		if s, _, _ := strings.Cut(cmd, " "); s == winproto.SubIISDeploy {
			inner(cmd, stdin) // the deployment ran on the host; its answer is lost to the budget
			return refusalResponse(4, winproto.CodeOutcomeUnknown)
		}
		return inner(cmd, stdin)
	})
	nl := w.issue()
	req := w.deployReq(nl)
	s := w.session(t)
	out, err := s.DeployCertificate(context.Background(), req, nil)
	providertest.CheckDeployOutcome(t, out, err)
	assert.Equal(t, providers.DeployUncertain, out.Result)
	assert.Equal(t, "ssh.protocol_error", providerErr(t, err).Code)
	assert.Equal(t, "OUTCOME_UNKNOWN", providerErr(t, err).Params["helper_code"])
	assert.Empty(t, out.Phase)
	st, err := s.DeploymentStatus(context.Background(), req.OperationID)
	require.NoError(t, err)
	assert.Equal(t, providers.PhaseCommitted, st.Phase)
	assert.Equal(t, derSHA256(nl.Cert.Raw), st.NewCertSHA256)
	assert.Equal(t, derSHA256(nl.Cert.Raw), st.CurrentCertSHA256)
}

// W2 Ruling 5: a host that is not an ASCII lower-case name (an IDN U-label) is refused before anything
// is sent.
func TestDeployRefusesNonASCIIHost(t *testing.T) {
	w := newWEnv(t)
	req := w.deployReq(w.issue())
	for _, loc := range []providers.Locator{
		{"type": "hostnameport", "host": "bücher.example", "port": 443, "app_id": winproto.AppIDIIS},
		{"type": "hostnameport", "host": "WWW.example.test", "port": 443, "app_id": winproto.AppIDIIS},
		{"type": "ipport", "ip": "::ffff:10.0.0.5", "port": 443, "app_id": winproto.AppIDIIS},
		{"type": "ipport", "ip": "0.0.0.0", "port": 70000, "app_id": winproto.AppIDIIS},
	} {
		r := req
		r.Location.Locator = loc
		out, err := w.session(t).DeployCertificate(context.Background(), r, nil)
		providertest.CheckDeployOutcome(t, out, err)
		assert.Equal(t, providers.DeployNoChange, out.Result, "%v", loc)
		assert.Equal(t, "windows.location_unsupported", providerErr(t, err).Code, "%v", loc)
	}
	assert.Zero(t, w.countSent(winproto.SubIISDeploy), "nothing sent")
}

// R61 Task 11 review: the location as inventory stores and hands it over (providers.ParseLocator of the stored JSON:
// the port is a json.Number) is deployed to and verified, not refused as unsupported.
func TestDeployTakesTheStoredLocator(t *testing.T) {
	w := newWEnv(t)
	nl := w.issue()
	req := w.deployReq(nl)
	stored, err := providers.ParseLocator([]byte(`{"app_id":"` + winproto.AppIDIIS + `","host":"` + wHost + `","port":443,"type":"hostnameport"}`))
	require.NoError(t, err)
	_, isNumber := stored["port"].(json.Number)
	require.True(t, isNumber, "the stored form")
	req.Location.Locator = stored
	req.Trust = &providers.TrustPolicy{Roots: rootPool(w.ca), Store: providers.TrustStoreSystem, Enforce: true}
	out, err := w.session(t).DeployCertificate(context.Background(), req, nil)
	providertest.CheckDeployOutcome(t, out, err)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, "remote", out.Verified)
	assert.Equal(t, derSHA256(nl.Cert.Raw), w.served())
	assert.Equal(t, 1, w.countSent(winproto.SubIISDeploy))
}

// Review Focus 5: the key travels only on standard input. The command line is exactly
// "iis-deploy --op <id>", neither Format of the request nor the session's logs show the key, and the
// input buffer is cleared after the send.
func TestDeployKeyIsNeverOutsideStdin(t *testing.T) {
	w := newWEnv(t)
	nl := w.issue()
	req := w.deployReq(nl)
	var logs bytes.Buffer
	sess, err := w.prov.Open(context.Background(), w.ref, w.cred, providers.Env{Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	require.NoError(t, err)
	s := sess.(*session)
	w.probe.setDown(true) // the verification's one warning path runs too
	keyBody := strings.Split(string(nl.KeyPEM), "\n")[1]
	var captured []byte
	inner := w.model.Handler()
	w.record(func(cmd string, stdin []byte) linuxsshtest.Response {
		if strings.HasPrefix(cmd, winproto.SubIISDeploy) {
			captured = stdin // the server's copy; the provider's buffer is checked below
		}
		return inner(cmd, stdin)
	})
	var buffers [][]byte
	inputHook = func(b []byte) { buffers = append(buffers, b) }
	t.Cleanup(func() { inputHook = nil })
	log := &stepLog{}
	out, derr := s.DeployCertificate(context.Background(), req, log)
	providertest.CheckDeployOutcome(t, out, derr)
	require.Len(t, buffers, 1)
	assert.NotEmpty(t, buffers[0])
	assert.Equal(t, make([]byte, len(buffers[0])), buffers[0], "the input buffer is cleared after the send")
	var lines []string
	for _, c := range w.srv.Commands() {
		if strings.HasPrefix(c, winproto.SubIISDeploy) {
			lines = append(lines, c)
		}
	}
	assert.Equal(t, []string{"iis-deploy --op " + req.OperationID.String()}, lines)
	assert.Contains(t, string(captured), keyBody, "the key was on stdin")
	for _, text := range []string{fmt.Sprintf("%v", req), fmt.Sprintf("%+v", req), fmt.Sprintf("%#v", req), logs.String(),
		strings.Join(log.lines(), "\n"), fmt.Sprintf("%+v", out), fmt.Sprint(derr)} {
		assert.NotContains(t, text, keyBody)
		assert.NotContains(t, text, "PRIVATE KEY")
	}
	providertest.CheckNoSecrets(t, []string{keyBody, string(nl.KeyPEM)}, out, derr)

	// The input is the protocol's JSON, built in one allocation of its final size.
	input, ok := deployInput(w.loc, req.ExpectCertSHA256, req.CertificatePEM, req.PrivateKeyPEM.Bytes(), req.Guard)
	require.True(t, ok)
	assert.Equal(t, cap(input), len(input))
	var d winproto.DeployInput
	require.NoError(t, json.Unmarshal(input, &d))
	assert.Equal(t, string(nl.KeyPEM), d.KeyPEM)
	assert.Equal(t, []string{}, d.ForbiddenSPKI)
	assert.Equal(t, []string{}, d.ForbiddenLeaf)
	assert.Equal(t, w.loc, d.Locator)
	_, ok = deployInput(w.loc, req.ExpectCertSHA256, nil, req.PrivateKeyPEM.Bytes(), req.Guard)
	assert.False(t, ok, "an empty chain")
	_, ok = deployInput(w.loc, req.ExpectCertSHA256, []byte("a\x01\"\\\t\r"), []byte("é"), req.Guard)
	assert.False(t, ok, "a key outside ASCII")
	in, ok := deployInput(w.loc, req.ExpectCertSHA256, []byte("a\x01\"\\\t\r"), []byte("k"), req.Guard)
	require.True(t, ok)
	require.NoError(t, json.Unmarshal(in, &d))
	assert.Equal(t, "a\x01\"\\\t\r", d.ChainPEM)
}

// W2 Ruling 16: Windows serves the chain it built (one longer here, a cross-signed certificate): the
// verification compares with built_chain_length and the verify step carries chain_differs.
func TestDeployChainDiffers(t *testing.T) {
	w := newWEnv(t)
	cross := pki.NewCA("Cross", pki.ECDSA256, time.Now())
	w.model.ChainDiffers(cross.IntermediatePEM)
	nl := w.issue()
	req := w.deployReq(nl)
	var log paramLog
	out, err := w.session(t).DeployCertificate(context.Background(), req, &log)
	providertest.CheckDeployOutcome(t, out, err)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, map[string]string{"mode": "remote", "chain_differs": "true", "deployed_chain": "2", "built_chain": "3"}, log.of("verify:ok"))
	_, n, _ := w.model.Served("127.0.0.1", 443, wHost)
	assert.Equal(t, 3, n)

	// Without a difference the verify step carries none.
	w2 := newWEnv(t)
	var log2 paramLog
	out, err = w2.session(t).DeployCertificate(context.Background(), w2.deployReq(w2.issue()), &log2)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, map[string]string{"mode": "remote"}, log2.of("verify:ok"))
}

// paramLog keeps each step's params by "name:status".
type paramLog struct {
	stepLog
	params map[string]map[string]string
}

func (p *paramLog) Step(name string, status providers.StepStatus, params map[string]string) {
	p.stepLog.Step(name, status, params)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.params == nil {
		p.params = map[string]map[string]string{}
	}
	p.params[name+":"+string(status)] = params
}

func (p *paramLog) of(key string) map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.params[key]
}

// A closed session and a session without the capability send nothing.
func TestDeployOnAClosedSessionSendsNothing(t *testing.T) {
	w := newWEnv(t)
	s := w.session(t)
	require.NoError(t, s.Close())
	out, err := s.DeployCertificate(context.Background(), w.deployReq(w.issue()), nil)
	providertest.CheckDeployOutcome(t, out, err)
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	_, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: w.loc2})
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	assert.Equal(t, []string{"version"}, w.srv.Commands())

	// A W1 helper is named outdated before anything is sent.
	w = newWEnv(t)
	w.script(winproto.SubVersion, func([]byte) linuxsshtest.Response {
		b, _ := json.Marshal(winproto.VersionResponse{OK: true, Helper: "0.1.0", Protocol: 1})
		return linuxsshtest.Response{Stdout: append(b, '\n')}
	})
	out, err = w.session(t).DeployCertificate(context.Background(), w.deployReq(w.issue()), nil)
	providertest.CheckDeployOutcome(t, out, err)
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.Equal(t, map[string]string{"helper_version": "0.1.0", "required_version": "0.2.0"}, out.Params)
	assert.Equal(t, "windows.helper_outdated", providerErr(t, err).Code)
	assert.Equal(t, []string{"version"}, w.srv.Commands())
}

// The guard goes into the input always (the helper keeps it in the journal and checks every restore).
func TestDeploySendsTheGuard(t *testing.T) {
	w := newWEnv(t)
	req := w.deployReq(w.issue())
	spki, leaf := strings.Repeat("a", 64), strings.Repeat("b", 64)
	req.Guard = providers.RollbackGuard{ForbiddenSPKI: []string{spki}, ForbiddenLeaf: []string{leaf}, Required: true}
	out, err := w.session(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result, "a Required guard is satisfied: the helper checks it")
	in := w.stdinsOf(winproto.SubIISDeploy)
	require.Len(t, in, 1)
	var d winproto.DeployInput
	require.NoError(t, json.Unmarshal(in[0], &d))
	assert.Equal(t, []string{spki}, d.ForbiddenSPKI)
	assert.Equal(t, []string{leaf}, d.ForbiddenLeaf)
	assert.Equal(t, derSHA256(w.old.Cert.Raw), d.ExpectSHA256)
	j, ok := w.model.Journal(req.OperationID.String())
	require.True(t, ok)
	assert.Contains(t, string(j), leaf, "the journal keeps the guard")
	assert.NotContains(t, string(j), "PRIVATE KEY")
}

// A request without its chain length has the chain counted; an answer without built_chain_length (the
// helper could not read what Windows built) is compared with the chain deployed.
func TestDeployCountsTheChainWhenTheRequestDoesNot(t *testing.T) {
	w := newWEnv(t)
	nl := w.issue()
	req := w.deployReq(nl)
	req.ChainLength = 0
	assert.Equal(t, 2, chainLength(req.CertificatePEM))
	assert.Equal(t, 0, chainLength([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")))
	out, err := w.session(t).DeployCertificate(context.Background(), req, nil)
	providertest.CheckDeployOutcome(t, out, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)

	w = newWEnv(t)
	nl = w.issue()
	inner := w.model.Handler()
	w.record(func(cmd string, stdin []byte) linuxsshtest.Response {
		r := inner(cmd, stdin)
		if strings.HasPrefix(cmd, winproto.SubIISDeploy) {
			var a winproto.DeployResponse
			require.NoError(t, json.Unmarshal(r.Stdout, &a))
			a.BuiltChainLength = 0
			return deployResponse(a)
		}
		return r
	})
	var log paramLog
	out, err = w.session(t).DeployCertificate(context.Background(), w.deployReq(nl), &log)
	providertest.CheckDeployOutcome(t, out, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, map[string]string{"mode": "remote"}, log.of("verify:ok"), "no chain_differs without a built length")
}
