package windows

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

const wHost = "www.example.test"

// wenv is env on a model with one IIS SNI binding (www.example.test:443) that names the "old"
// certificate in My, and helpers to deploy on the model directly (iis-deploy is Task 8's provider
// method; these tests drive the helper's own code through the model's handler).
type wenv struct {
	*env
	ca      *pki.CA
	old     pki.Leaf
	oldSHA1 string
	loc     winproto.Locator
	loc2    providers.CertLocation

	mu     sync.Mutex
	stdins map[string][][]byte // what the server received on stdin, by subcommand
}

func newWEnv(t *testing.T) *wenv {
	t.Helper()
	now := time.Now()
	m := wintest.NewModel()
	ca := pki.NewCA("Rollback", pki.ECDSA256, now)
	m.AddIntermediate(ca.IntermediatePEM)
	old := ca.Issue(pki.Opts{CommonName: wHost, SANs: []string{wHost}}, now)
	sha1 := m.AddCertificate("My", old.CertPEM, old.KeyPEM, wintest.CertOptions{FriendlyName: "old"})
	m.AddBinding(winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: wHost, Port: 443, AppID: winproto.AppIDIIS,
		CertSHA1: sha1, Store: "My", Flags: 0x42})
	m.SetLockWait(50 * time.Millisecond)
	w := &wenv{env: newEnvWith(t, m), ca: ca, old: old, oldSHA1: sha1, stdins: map[string][][]byte{},
		loc: winproto.Locator{Type: winproto.BindingHostnamePort, Host: wHost, Port: 443, AppID: winproto.AppIDIIS}}
	w.loc2 = providers.CertLocation{Kind: providers.LocationWinSSLBinding,
		Locator:  providers.Locator{"type": winproto.BindingHostnamePort, "host": wHost, "port": 443, "app_id": winproto.AppIDIIS},
		CertPath: "http.sys/hostnameport/" + wHost + ":443", Supported: true,
		Details: map[string]any{"store": "My", "cert_sha1": sha1, "application": "iis"}}
	w.record(m.Handler())
	serve(t, m)
	return w
}

// record installs h as the server's handler, keeping every stdin.
func (w *wenv) record(h linuxsshtest.Handler) {
	w.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		sub, _, _ := strings.Cut(cmd, " ")
		w.mu.Lock()
		w.stdins[sub] = append(w.stdins[sub], append([]byte(nil), stdin...))
		w.mu.Unlock()
		return h(cmd, stdin)
	})
}

// script answers sub with r; every other command goes to the model.
func (w *wenv) script(sub string, r func(stdin []byte) linuxsshtest.Response) {
	inner := w.model.Handler()
	w.record(func(cmd string, stdin []byte) linuxsshtest.Response {
		if s, _, _ := strings.Cut(cmd, " "); s == sub {
			return r(stdin)
		}
		return inner(cmd, stdin)
	})
}

func (w *wenv) stdinsOf(sub string) [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.stdins[sub]...)
}

func (w *wenv) issue() pki.Leaf {
	return w.ca.Issue(pki.Opts{CommonName: wHost, SANs: []string{wHost}}, time.Now())
}

// deployRaw runs iis-deploy of op on the model (not through the provider: DeployCertificate is Task 8's)
// expecting the binding to name expect.
func (w *wenv) deployRaw(t *testing.T, op uuid.UUID, expect []byte, l pki.Leaf) linuxsshtest.Response {
	t.Helper()
	in, err := json.Marshal(winproto.DeployInput{Locator: w.loc, ExpectSHA256: derSHA256(expect), ChainPEM: string(l.FullchainPEM),
		KeyPEM: string(l.KeyPEM), ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}})
	require.NoError(t, err)
	return w.model.Handler()(winproto.SubIISDeploy+" --op "+op.String(), in)
}

// deploy is deployRaw's answer (zero when there is none).
func (w *wenv) deploy(t *testing.T, op uuid.UUID, expect []byte, l pki.Leaf) winproto.DeployResponse {
	t.Helper()
	r := w.deployRaw(t, op, expect, l)
	var d winproto.DeployResponse
	if len(r.Stdout) > 0 {
		require.NoError(t, json.Unmarshal(r.Stdout, &d), "%s", r.Stdout)
	}
	return d
}

// commit deploys a new certificate under op and requires committed.
func (w *wenv) commit(t *testing.T, op uuid.UUID) pki.Leaf {
	t.Helper()
	nl := w.issue()
	d := w.deploy(t, op, w.old.Cert.Raw, nl)
	require.Equal(t, winproto.PhaseCommitted, d.Phase)
	return nl
}

// served is the leaf the binding serves now ("" when a handshake fails).
func (w *wenv) served() string {
	s, _, _ := w.model.Served("127.0.0.1", 443, wHost)
	return s
}

// session opens a session (its verification probes the model's listeners through env.probe and the
// helper's tls-probe).
func (w *wenv) session(t *testing.T) *session {
	t.Helper()
	s, ok := w.open(t).(*session)
	require.True(t, ok)
	return s
}

func (w *wenv) rollbackReq(op uuid.UUID) providers.RollbackRequest {
	return providers.RollbackRequest{OperationID: op, Location: w.loc2, OldFingerprint: derSHA256(w.old.Cert.Raw), OldSANs: []string{wHost}, KeyType: "ecdsa"}
}

func stepWords(steps []providers.DeployStep) []string {
	out := make([]string, 0, len(steps))
	for _, st := range steps {
		out = append(out, st.Name+":"+string(st.Status))
	}
	return out
}

func refusalResponse(exit int, code string) linuxsshtest.Response {
	b, _ := json.Marshal(winproto.ErrorResponse{Code: code, Message: "scripted"})
	return linuxsshtest.Response{Stdout: append(b, '\n'), Exit: exit}
}

type wantRollback struct {
	result    providers.DeployResult
	phase     string
	failed    string
	cause     string
	cls       string
	reason    string
	errCode   string // the returned error's code ("" = nil error)
	retryable bool
	params    map[string]string
	steps     []string
	verified  string
	serves    string // "old", "new" or "" (not checked)
}

func TestRollbackOutcomes(t *testing.T) {
	backup := func(w *wenv) map[string]string { return map[string]string{"store": "My", "previous_sha1": w.oldSHA1} }
	rows := []struct {
		name string
		prep func(t *testing.T, w *wenv, op uuid.UUID, r *providers.RollbackRequest) // nil: commit only
		ctx  func() context.Context
		want func(w *wenv) wantRollback
	}{
		{"restored and verified", nil, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployRolledBack, phase: "restored", steps: []string{"restore:ok", "verify_old:ok"}, verified: "remote", serves: "old"}
		}},
		{"restored twice: the second answers from the journal", func(t *testing.T, w *wenv, op uuid.UUID, r *providers.RollbackRequest) {
			w.commit(t, op)
			out, err := w.session(t).RollbackDeployment(context.Background(), *r, nil)
			require.NoError(t, err)
			require.Equal(t, providers.DeployRolledBack, out.Result)
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployRolledBack, phase: "restored", steps: []string{"verify_old:ok"}, verified: "remote", serves: "old"}
		}},
		{"restored after the helper's own restore: its cause is not this call's", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.model.CorruptReadBack(true)
			d := w.deploy(t, op, w.old.Cert.Raw, w.issue())
			require.Equal(t, winproto.PhaseRestored, d.Phase)
			require.Equal(t, winproto.ErrReadBack, d.Error)
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployRolledBack, phase: "restored", steps: []string{"verify_old:ok"}, verified: "remote", serves: "old"}
		}},
		{"restored, verification skipped", func(t *testing.T, w *wenv, op uuid.UUID, r *providers.RollbackRequest) {
			w.commit(t, op)
			r.Verify.Skip = true
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployRolledBack, phase: "restored", steps: []string{"restore:ok", "verify_old:skipped"}, verified: "skipped", serves: "old"}
		}},
		{"restored, no previous certificate to compare", func(t *testing.T, w *wenv, op uuid.UUID, r *providers.RollbackRequest) {
			w.commit(t, op)
			r.OldFingerprint = ""
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployRolledBack, phase: "restored", steps: []string{"restore:ok", "verify_old:skipped"}, serves: "old"}
		}},
		{"restored, the old leaf is not served: rollback_failed verify_old", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			w.model.StaleTLS(true)
		}, nil, func(w *wenv) wantRollback {
			return wantRollback{result: providers.DeployRollbackFailed, phase: "restored", failed: "verify_old", reason: "deployment.rollback_failed",
				params: backup(w), steps: []string{"restore:ok", "verify_old:failed"}, serves: "new"}
		}},
		{"restore_failed: the binding names a third certificate", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			third := w.issue()
			sha1 := w.model.AddCertificate("My", third.CertPEM, third.KeyPEM, wintest.CertOptions{})
			rec, ok := w.model.Binding(w.loc)
			require.True(t, ok)
			rec.CertSHA1 = sha1
			require.NoError(t, w.model.Host().UpdateBinding(context.Background(), rec))
		}, nil, func(w *wenv) wantRollback {
			return wantRollback{result: providers.DeployRollbackFailed, phase: "restore_failed", failed: "restore", cls: "file_changed",
				reason: "deployment.rollback_failed", params: backup(w), steps: []string{"restore:failed"}}
		}},
		{"BACKUP_MISSING: the previous certificate is gone from its store", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			w.model.RemoveCertificate("My", w.oldSHA1)
		}, nil, func(w *wenv) wantRollback {
			return wantRollback{result: providers.DeployRollbackFailed, failed: "restore", cls: "backup_missing", reason: "windows.backup_missing",
				params: backup(w), serves: ""}
		}},
		{"restore_forbidden: the guard lists the previous leaf", func(t *testing.T, w *wenv, op uuid.UUID, r *providers.RollbackRequest) {
			w.commit(t, op)
			r.Guard = providers.RollbackGuard{ForbiddenLeaf: []string{derSHA256(w.old.Cert.Raw)}, TargetForbidden: true}
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployRollbackFailed, phase: "restore_forbidden", failed: "restore", cls: "forbidden",
				reason: "deployment.rollback_forbidden", params: map[string]string{}, steps: []string{"restore:failed"}, serves: "new"}
		}},
		{"SUPERSEDED: a later deployment changed the binding", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			nl := w.commit(t, op)
			d := w.deploy(t, uuid.New(), nl.Cert.Raw, w.issue())
			require.Equal(t, winproto.PhaseCommitted, d.Phase)
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployNoChange, reason: "deployment.superseded", errCode: "deployment.superseded"}
		}},
		{"UNKNOWN_OP", func(*testing.T, *wenv, uuid.UUID, *providers.RollbackRequest) {}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployNoChange, reason: "deployment.unknown_operation", errCode: "deployment.unknown_operation", serves: "old"}
		}},
		{"fenced: the operation never ran", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			r := w.model.Handler()(winproto.SubIISFence+" --op "+op.String(), nil)
			require.Equal(t, 0, r.Exit, "%s", r.Stdout)
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployNoChange, reason: "deployment.unknown_operation", errCode: "deployment.unknown_operation", serves: "old"}
		}},
		{"nothing to restore: prepared", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.model.KillAt("deploy.prepared")
			w.deploy(t, op, w.old.Cert.Raw, w.issue())
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployNoChange, phase: "prepared", reason: "deployment.nothing_to_restore", serves: "old"}
		}},
		{"nothing to restore: unchanged", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			nl := w.commit(t, uuid.New())
			d := w.deploy(t, op, nl.Cert.Raw, nl)
			require.Equal(t, winproto.PhaseUnchanged, d.Phase)
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployNoChange, phase: "unchanged", reason: "deployment.nothing_to_restore", serves: "new"}
		}},
		{"BUSY: another process holds the lock", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			t.Cleanup(w.model.HoldLock())
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployNoChange, reason: "windows.busy", errCode: "windows.busy", retryable: true, serves: "new"}
		}},
		{"a W1 helper answers UNKNOWN_SUBCOMMAND: outdated, nothing changed", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return refusalResponse(2, winproto.CodeUnknownSubcommand) })
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployNoChange, reason: "windows.helper_outdated", errCode: "windows.helper_outdated", serves: "new"}
		}},
		{"cancelled before the send", nil, func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployNoChange, reason: "ssh.timeout", errCode: "ssh.timeout", retryable: true, serves: "new"}
		}},
		{"killed during the restore: no answer, uncertain", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			w.model.KillAt("restore.bound")
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployUncertain, errCode: "windows.helper_missing"}
		}},
		{"OUTCOME_UNKNOWN: in no refusal table, uncertain", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return refusalResponse(4, winproto.CodeOutcomeUnknown) })
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error", serves: "new"}
		}},
		{"a known code at another exit status: uncertain", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return refusalResponse(4, winproto.CodeUnknownOp) })
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error", serves: "new"}
		}},
		{"an unknown code: uncertain", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return refusalResponse(3, "GONE") })
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error", serves: "new"}
		}},
		{"garbage on exit 0: uncertain", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return linuxsshtest.Response{Stdout: []byte("garbage\n")} })
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error"}
		}},
		{"connection lost: uncertain", func(t *testing.T, w *wenv, op uuid.UUID, _ *providers.RollbackRequest) {
			w.commit(t, op)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return linuxsshtest.Response{Hangup: true} })
		}, nil, func(*wenv) wantRollback {
			return wantRollback{result: providers.DeployUncertain, errCode: "ssh.protocol_error"}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			w := newWEnv(t)
			op := uuid.New()
			r := w.rollbackReq(op)
			if row.prep == nil {
				w.commit(t, op)
			} else {
				row.prep(t, w, op, &r)
			}
			ctx := context.Background()
			if row.ctx != nil {
				ctx = row.ctx()
			}
			s := w.session(t)
			out, err := s.RollbackDeployment(ctx, r, nil)
			require.NoError(t, providers.CheckRollbackReturn(out, err), "%+v %v", out, err)
			want := row.want(w)
			assert.Equal(t, want.result, out.Result, "%+v %v", out, err)
			assert.Equal(t, want.phase, out.Phase)
			assert.Equal(t, want.failed, out.FailedStep)
			assert.Equal(t, want.cause, out.CauseStep)
			assert.Equal(t, want.cls, out.Error)
			assert.Equal(t, want.reason, out.Reason)
			assert.Equal(t, want.verified, out.Verified)
			if want.params != nil {
				assert.Equal(t, want.params, out.Params)
			}
			if want.steps == nil {
				assert.Empty(t, out.Steps)
			} else {
				assert.Equal(t, want.steps, stepWords(out.Steps))
			}
			if want.errCode == "" {
				assert.NoError(t, err)
			} else {
				pe := providerErr(t, err)
				assert.Equal(t, want.errCode, pe.Code)
				assert.Equal(t, want.retryable, pe.Retryable)
				assert.NotEqual(t, "ssh.helper_refused", pe.Code, "Ruling 6")
			}
			switch want.serves {
			case "old":
				assert.Equal(t, derSHA256(w.old.Cert.Raw), w.served())
			case "new":
				assert.NotEqual(t, derSHA256(w.old.Cert.Raw), w.served())
			}
		})
	}
}

// A website that cannot be checked after the restore leaves it rolled_back, unverified.
func TestRollbackUnverifiable(t *testing.T) {
	w := newWEnv(t)
	op := uuid.New()
	w.commit(t, op)
	s := w.session(t)
	// Neither Alice's probe nor the helper's tls-probe completes a handshake.
	w.probe.setDown(true)
	w.script(winproto.SubTLSProbe, func([]byte) linuxsshtest.Response { return refusalResponse(4, winproto.CodeProbeFailed) })
	var log stepLog
	out, err := s.RollbackDeployment(context.Background(), w.rollbackReq(op), &log)
	require.NoError(t, providers.CheckRollbackReturn(out, err))
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result)
	assert.Empty(t, out.Verified)
	assert.Equal(t, []string{"restore:ok", "verify_old:failed"}, stepWords(out.Steps))
	assert.Equal(t, []string{"restore:ok", "verify_old:started", "verify_old:failed port=443"}, log.lines())
	assert.Equal(t, derSHA256(w.old.Cert.Raw), w.served())

	// A verification that errs (here: the session is closed) is a website that cannot be checked, as on
	// Nginx: ok, verify_old failed, with the port of the first endpoint (the Administrator's port first).
	require.NoError(t, s.Close())
	var log2 stepLog
	v, ok := s.checkOld(context.Background(), &log2, providers.VerifyRequest{Location: w.loc2, Fingerprint: derSHA256(w.old.Cert.Raw),
		Verify: providers.VerifyOptions{Port: 8443}})
	assert.True(t, ok)
	assert.Equal(t, providers.StepFailed, v.step.Status)
	assert.Empty(t, v.mode)
	assert.Equal(t, []string{"verify_old:started", "verify_old:failed port=8443"}, log2.lines())
}

// stepLog is a StepLogger that keeps "name:status k=v" lines.
type stepLog struct {
	mu sync.Mutex
	l  []string
}

func (s *stepLog) Step(name string, status providers.StepStatus, params map[string]string) {
	line := name + ":" + string(status)
	for _, k := range []string{"error", "port", "mode"} {
		if v, ok := params[k]; ok {
			line += " " + k + "=" + v
		}
	}
	s.mu.Lock()
	s.l = append(s.l, line)
	s.mu.Unlock()
}

func (s *stepLog) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.l...)
}

// W2 Ruling 11: the server checks the guard on every restore, so the restore input always carries
// both lists, empty arrays when the guard is empty (never null, never left out).
func TestRollbackSendsTheGuardAlways(t *testing.T) {
	w := newWEnv(t)
	op := uuid.New()
	w.commit(t, op)
	s := w.session(t)
	out, err := s.RollbackDeployment(context.Background(), w.rollbackReq(op), nil)
	require.NoError(t, err)
	require.Equal(t, providers.DeployRolledBack, out.Result)
	in := w.stdinsOf(winproto.SubIISRestore)
	require.Len(t, in, 1)
	assert.JSONEq(t, `{"forbidden_spki_sha256":[],"forbidden_leaf_sha256":[]}`, string(in[0]))

	spki, leaf := strings.Repeat("a", 64), strings.Repeat("b", 64)
	r := w.rollbackReq(op)
	r.Guard = providers.RollbackGuard{ForbiddenSPKI: []string{spki}, ForbiddenLeaf: []string{leaf}, TargetUnknown: true}
	out, err = s.RollbackDeployment(context.Background(), r, nil)
	require.NoError(t, err)
	require.Equal(t, providers.DeployRolledBack, out.Result, "the hashes do not name the previous certificate")
	in = w.stdinsOf(winproto.SubIISRestore)
	require.Len(t, in, 2)
	assert.JSONEq(t, `{"forbidden_spki_sha256":["`+spki+`"],"forbidden_leaf_sha256":["`+leaf+`"]}`, string(in[1]))

	// A guard the helper would refuse is refused before anything is sent.
	r.Guard = providers.RollbackGuard{ForbiddenLeaf: []string{"not a hash"}}
	out, err = s.RollbackDeployment(context.Background(), r, nil)
	require.NoError(t, providers.CheckRollbackReturn(out, err))
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.Equal(t, "internal.unexpected", providerErr(t, err).Code)
	assert.Len(t, w.stdinsOf(winproto.SubIISRestore), 2, "nothing sent")
}

// W2 Ruling 3: a helper older than 0.2.0 is named outdated before any write subcommand is sent.
func TestWriteNeedsHelper020(t *testing.T) {
	for _, version := range []string{"0.1.0", "", "v0.2.0", "0.2.0-rc1"} {
		t.Run("version "+version, func(t *testing.T) {
			w := newWEnv(t)
			w.script(winproto.SubVersion, func([]byte) linuxsshtest.Response {
				b, _ := json.Marshal(winproto.VersionResponse{OK: true, Helper: version, Protocol: 1})
				return linuxsshtest.Response{Stdout: append(b, '\n')}
			})
			s := w.session(t)
			want := map[string]string{"helper_version": version, "required_version": "0.2.0"}
			check := func(err error) {
				t.Helper()
				pe := providerErr(t, err)
				assert.Equal(t, "windows.helper_outdated", pe.Code)
				assert.Equal(t, want, pe.Params)
				assert.False(t, pe.Retryable)
			}
			op := uuid.New()
			out, err := s.RollbackDeployment(context.Background(), w.rollbackReq(op), nil)
			require.NoError(t, providers.CheckRollbackReturn(out, err))
			assert.Equal(t, providers.DeployNoChange, out.Result)
			assert.Equal(t, "windows.helper_outdated", out.Reason)
			assert.Equal(t, want, out.Params)
			check(err)
			st, err := s.DeploymentStatus(context.Background(), op)
			check(err)
			assert.Zero(t, st)
			st, err = s.FenceDeployment(context.Background(), op)
			check(err)
			assert.Zero(t, st)
			assert.Error(t, s.writeReady())
			assert.Equal(t, []string{"version"}, w.srv.Commands(), "nothing but version was sent")
		})
	}

	// A helper that says 0.2.0 or later but does not know the subcommand (the backstop).
	w := newWEnv(t)
	op := uuid.New()
	w.commit(t, op)
	w.record(func(cmd string, stdin []byte) linuxsshtest.Response {
		switch s, _, _ := strings.Cut(cmd, " "); s {
		case winproto.SubIISRestore, winproto.SubIISStatus, winproto.SubIISFence:
			return refusalResponse(2, winproto.CodeUnknownSubcommand)
		}
		return w.model.Handler()(cmd, stdin)
	})
	s := w.session(t)
	out, err := s.RollbackDeployment(context.Background(), w.rollbackReq(op), nil)
	require.NoError(t, providers.CheckRollbackReturn(out, err))
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.Equal(t, "windows.helper_outdated", out.Reason)
	assert.Equal(t, "windows.helper_outdated", providerErr(t, err).Code)
	st, err := s.DeploymentStatus(context.Background(), op)
	assert.Equal(t, "windows.helper_outdated", providerErr(t, err).Code, "an error, never a state")
	assert.Zero(t, st)
	st, err = s.FenceDeployment(context.Background(), op)
	assert.Equal(t, "windows.helper_outdated", providerErr(t, err).Code, "an error, never a state")
	assert.Zero(t, st)

	for v, ok := range map[string]bool{"0.2.0": true, "0.10.0": true, "1.0.0": true, "0.1.9": false} {
		s := &session{version: winproto.VersionResponse{Helper: v, Protocol: 1}}
		assert.Equal(t, ok, s.writeReady() == nil, v)
	}
}

// W2 Ruling 11: the helper checks the guard on every restore path, so a Required guard is satisfied.
func TestRollbackTraits(t *testing.T) {
	p := newEnv(t).prov
	traits := providers.TraitsOf(p)
	assert.Equal(t, providers.RollbackTraits{Backup: providers.BackupOnTarget, SelfRestores: true}, traits)
	require.NoError(t, traits.Validate())
	assert.True(t, guardsRollback)
	assert.True(t, providers.RollbackGuard{Required: true}.SatisfiedBy(traits, guardsRollback))
	var _ providers.RollbackModel = p
}

// A closed session sends nothing.
func TestAClosedSessionWritesNothing(t *testing.T) {
	w := newWEnv(t)
	s := w.session(t)
	require.NoError(t, s.Close())
	out, err := s.RollbackDeployment(context.Background(), w.rollbackReq(uuid.New()), nil)
	require.NoError(t, providers.CheckRollbackReturn(out, err))
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	_, err = s.DeploymentStatus(context.Background(), uuid.New())
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	_, err = s.FenceDeployment(context.Background(), uuid.New())
	assert.Equal(t, "ssh.unreachable", providerErr(t, err).Code)
	assert.Equal(t, []string{"version"}, w.srv.Commands())
}

// A target that cannot be dialled for the restore: nothing was sent, so nothing changed.
func TestRollbackDialFailureChangesNothing(t *testing.T) {
	w := newWEnv(t)
	op := uuid.New()
	w.commit(t, op)
	s := w.session(t)
	w.srv.DisablePublicKeyAuth()
	out, err := s.RollbackDeployment(context.Background(), w.rollbackReq(op), nil)
	require.NoError(t, providers.CheckRollbackReturn(out, err))
	assert.Equal(t, providers.DeployNoChange, out.Result)
	assert.NotEmpty(t, providerErr(t, err).Code)
	assert.Equal(t, []string{"version"}, w.srv.Commands())
}

// Answers that break the helper's contract are uncertain, never an outcome.
func TestRollbackAnswersOutsideTheContract(t *testing.T) {
	steps := func(s ...winproto.Step) []winproto.Step { return s }
	ok := winproto.Step{Name: "restore", Status: "ok"}
	bad := winproto.Step{Name: "restore", Status: "failed", Error: "file_changed"}
	for name, a := range map[string]winproto.RestoreResponse{
		"an unknown phase":                     {OK: true, Phase: "committed"},
		"fenced with steps":                    {OK: true, Phase: "fenced", Steps: steps(ok)},
		"prepared with steps":                  {OK: true, Phase: "prepared", Steps: steps(ok)},
		"restored with a failed step":          {OK: true, Phase: "restored", Steps: steps(bad)},
		"a step outside the vocabulary":        {OK: true, Phase: "restored", Steps: steps(winproto.Step{Name: "reload", Status: "ok"})},
		"a status outside the vocabulary":      {OK: true, Phase: "restored", Steps: steps(winproto.Step{Name: "restore", Status: "started"})},
		"a class outside the vocabulary":       {OK: true, Phase: "restore_failed", FailedStep: "restore", Error: "syntax", Steps: steps(bad)},
		"restore_failed at an unknown step":    {OK: true, Phase: "restore_failed", FailedStep: "reload", Error: "file_changed"},
		"restore_failed without a step":        {OK: true, Phase: "restore_failed", Error: "file_changed"},
		"restore_failed with forbidden":        {OK: true, Phase: "restore_failed", FailedStep: "restore", Error: "forbidden"},
		"restore_failed with an unknown cause": {OK: true, Phase: "restore_failed", FailedStep: "restore", CauseStep: "reload", Error: "io_error"},
		"restore_forbidden at another step":    {OK: true, Phase: "restore_forbidden", FailedStep: "bind", Error: "forbidden"},
		"restore_forbidden with another class": {OK: true, Phase: "restore_forbidden", FailedStep: "restore", Error: "file_changed"},
		"restore_forbidden with an ok step":    {OK: true, Phase: "restore_forbidden", FailedStep: "restore", Error: "forbidden", Steps: steps(ok)},
		"too many steps":                       {OK: true, Phase: "restored", Steps: make([]winproto.Step, maxAnswerSteps+1)},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWEnv(t)
			b, err := json.Marshal(a)
			require.NoError(t, err)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return linuxsshtest.Response{Stdout: append(b, '\n')} })
			out, err := w.session(t).RollbackDeployment(context.Background(), w.rollbackReq(uuid.New()), nil)
			require.NoError(t, providers.CheckRollbackReturn(out, err))
			assert.Equal(t, providers.DeployUncertain, out.Result)
			assert.Equal(t, "ssh.protocol_error", providerErr(t, err).Code)
		})
	}
	// Shapes inside the contract the emulator does not produce on its own.
	for name, tc := range map[string]struct {
		a    winproto.RestoreResponse
		want providers.RollbackOutcome
	}{
		"restore_failed at the bind (the binding vanished during the deploy)": {
			winproto.RestoreResponse{OK: true, Phase: "restore_failed", FailedStep: "bind", CauseStep: "bind", Error: "file_changed"},
			providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: "restore_failed", FailedStep: "bind", CauseStep: "bind",
				Error: "file_changed", Reason: "deployment.rollback_failed", Params: map[string]string{"store": "My"}}},
		"restore_failed: the previous key is unusable": {
			winproto.RestoreResponse{OK: true, Phase: "restore_failed", FailedStep: "restore", Error: "key_unusable", Steps: steps(winproto.Step{Name: "restore", Status: "failed", Error: "key_unusable"})},
			providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: "restore_failed", FailedStep: "restore",
				Error: "key_unusable", Reason: "windows.key_unusable", Steps: []providers.DeployStep{{Name: "restore", Status: providers.StepFailed, Error: "key_unusable"}},
				Params: map[string]string{"store": "My"}}},
		"restore_failed: the store cannot be opened": {
			winproto.RestoreResponse{OK: true, Phase: "restore_failed", FailedStep: "restore", Error: "store_error"},
			providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: "restore_failed", FailedStep: "restore",
				Error: "store_error", Reason: "windows.store_error", Params: map[string]string{"store": "My"}}},
		"restore_failed: backup missing after the gate": {
			winproto.RestoreResponse{OK: true, Phase: "restore_failed", FailedStep: "restore", CauseStep: "journal", Error: "backup_missing"},
			providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Phase: "restore_failed", FailedStep: "restore", CauseStep: "journal",
				Error: "backup_missing", Reason: "windows.backup_missing", Params: map[string]string{"store": "My"}}},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWEnv(t)
			b, err := json.Marshal(tc.a)
			require.NoError(t, err)
			w.script(winproto.SubIISRestore, func([]byte) linuxsshtest.Response { return linuxsshtest.Response{Stdout: append(b, '\n')} })
			r := w.rollbackReq(uuid.New())
			r.Location.Details = map[string]any{"store": "My"}
			out, err := w.session(t).RollbackDeployment(context.Background(), r, nil)
			require.NoError(t, providers.CheckRollbackReturn(out, err))
			require.NoError(t, err)
			assert.Equal(t, tc.want, out)
		})
	}
}

// A write command that cannot be built is refused before anything is dialled.
func TestRunWriteRefusesAnInvalidCommand(t *testing.T) {
	w := newWEnv(t)
	s := w.session(t)
	c := runWrite[winproto.RestoreResponse](context.Background(), s, "iis-cleanup", nil, restoreRefusals)
	require.NotNil(t, c.refusal)
	assert.Equal(t, "internal.unexpected", c.refusal.Code)
	assert.Nil(t, c.uncertain)
	assert.Equal(t, 1, w.srv.Connections(), "nothing dialled")
	pe := asProviderError(assert.AnError)
	assert.Equal(t, "internal.unexpected", pe.Code)
	assert.ErrorIs(t, pe, assert.AnError)
}
