package linuxsshtest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx/nginxconf"
	"alice/internal/testutil/pki"
)

const (
	emuOp  = "0190f5a0-0000-7000-8000-0000000000e1"
	emuOp2 = "0190f5a0-0000-7000-8000-0000000000e2"
	emuOp3 = "0190f5a0-0000-7000-8000-0000000000e3"

	crt = "/etc/nginx/ssl/www.crt"
	key = "/etc/nginx/ssl/www.key"
)

var testNow = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func hexSum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// line builds a helper command line the way the constructors do: flags literal, values quoted.
func line(sudo bool, sub string, args ...string) string {
	var b strings.Builder
	if sudo {
		b.WriteString("sudo -n ")
	}
	b.WriteString(helperproto.HelperPath + " " + sub)
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			b.WriteString(" " + a)
		} else {
			b.WriteString(" '" + a + "'")
		}
	}
	return b.String()
}

func input(cert, key []byte) []byte {
	b, _ := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(cert), KeyPEM: string(key)})
	return b
}

func deployLineFor(op, certPath, keyPath, expect string, in []byte) string {
	return line(true, helperproto.SubNginxDeploy, "--op", op, "--cert", certPath, "--key", keyPath, "--expect-cert-sha256", expect,
		"--content-sha256", hexSum(in))
}

type world struct {
	tb       *testing.T
	e        *Emulator
	old, nw  pki.Leaf
	other    pki.Leaf
	sameKey  pki.Leaf // another certificate for the old key (a file that changed but still loads)
	ca       *pki.CA
	oldSHA   string
	deployIn []byte
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ca := pki.NewCA("Emu", pki.ECDSA256, testNow)
	w := &world{tb: t, e: NewEmulator(), ca: ca,
		old:   ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow),
		nw:    ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow),
		other: ca.Issue(pki.Opts{CommonName: "other.example.test"}, testNow),
	}
	w.sameKey = ca.Issue(pki.Opts{CommonName: "www.example.test", Key: w.old.Key}, testNow)
	w.e.EnableNginx("1.22.1")
	w.e.AddSite(NginxSite{Names: []string{"www.example.test"}, Port: 443, CertPath: crt, KeyPath: key}, w.old.FullchainPEM, w.old.KeyPEM)
	w.oldSHA = hexSum(w.old.FullchainPEM)
	w.deployIn = input(w.nw.FullchainPEM, w.nw.KeyPEM)
	return w
}

func (w *world) run(cmd string, stdin []byte) Response { return w.e.handle(cmd, stdin) }

func (w *world) deploy(op string) Response {
	return w.run(deployLineFor(op, crt, key, w.oldSHA, w.deployIn), w.deployIn)
}

func (w *world) status(op string) helperproto.NginxStatusResponse {
	r := w.run(line(true, helperproto.SubNginxStatus, "--op", op), nil)
	var s helperproto.NginxStatusResponse
	require.Equal(w.t(), 0, r.Exit, string(r.Stdout))
	require.NoError(w.t(), json.Unmarshal(r.Stdout, &s))
	return s
}

func (w *world) t() *testing.T { return w.tb }

func decode[T any](t *testing.T, r Response) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal(r.Stdout, &v), string(r.Stdout))
	return v
}

func codeOf(t *testing.T, r Response) string {
	t.Helper()
	return decode[helperproto.ErrorResponse](t, r).Code
}

func (w *world) restore(op string) Response {
	return w.run(line(true, helperproto.SubNginxRestore, "--op", op), nil)
}

func (w *world) assertPair(t *testing.T, leaf pki.Leaf) {
	t.Helper()
	assert.Equal(t, string(leaf.FullchainPEM), string(w.e.NginxFile(crt)))
	assert.Equal(t, string(leaf.KeyPEM), string(w.e.NginxFile(key)))
}

// padded is a certificate file over the size limit that still loads (text outside PEM blocks is ignored).
func padded(pem []byte) []byte {
	return append(append([]byte{}, pem...), []byte(strings.Repeat("\n", helperproto.MaxCertFileSize))...)
}

func TestEmulatedNginxDeployAndRollback(t *testing.T) {
	w := newWorld(t)
	assert.Equal(t, pki.Fingerprint(w.old.Cert), w.e.Served(443, "www.example.test"))

	dump := w.run(line(true, helperproto.SubNginxDump), nil)
	require.Equal(t, 0, dump.Exit)
	d := decode[helperproto.NginxDumpResponse](t, dump)
	require.True(t, d.ConfigValid, "%+v", d)
	require.Len(t, d.Files, 2)
	assert.Equal(t, string(w.old.FullchainPEM), d.Files[0].PEM)
	assert.Empty(t, d.Files[1].PEM, "key files are never read")
	assert.Empty(t, d.Files[1].SHA256)
	assert.Equal(t, "1.22.1", d.Version)
	assert.Equal(t, "/etc/nginx/nginx.conf", d.ConfPath)
	require.Len(t, d.Servers, 1)
	assert.Equal(t, 1, d.Servers[0].Line)
	assert.Equal(t, []string{"www.example.test"}, d.Servers[0].Names)
	assert.Equal(t, []helperproto.NginxListen{{Port: 443}}, d.Servers[0].Listens)
	assert.Equal(t, []helperproto.NginxPair{{Cert: crt, Key: key}}, d.Servers[0].Pairs)

	r := w.deploy(emuOp)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	resp := decode[helperproto.NginxDeployResponse](t, r)
	assert.Equal(t, helperproto.PhaseCommitted, resp.Phase)
	assert.Equal(t, []helperproto.NginxStep{stepOK("backup"), stepOK("write_key"), stepOK("write_cert"), stepOK("config_test"), stepOK("reload")}, resp.Steps)
	assert.Equal(t, pki.Fingerprint(w.nw.Cert), w.e.Served(443, "www.example.test"))
	assert.Equal(t, 1, w.e.Reloads())
	assert.Equal(t, 1, w.e.DeployCount())

	// The same operation again answers from the journal.
	r = w.deploy(emuOp)
	require.Equal(t, 0, r.Exit)
	assert.Equal(t, helperproto.PhaseCommitted, decode[helperproto.NginxDeployResponse](t, r).Phase)
	assert.Equal(t, 1, w.e.Reloads())

	r = w.restore(emuOp)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	rr := decode[helperproto.NginxRestoreResponse](t, r)
	assert.Equal(t, helperproto.PhaseRestored, rr.Phase)
	assert.Equal(t, []helperproto.NginxStep{stepOK("restore"), stepOK("rollback_config_test"), stepOK("rollback_reload")}, rr.Steps)
	assert.Equal(t, pki.Fingerprint(w.old.Cert), w.e.Served(443, "www.example.test"))
	w.assertPair(t, w.old)
}

// A deployment that breaks another site sharing the key file: nginx -t fails with key_mismatch and
// the old pair is back (the content check of nginx-deploy makes a wrong key unreachable otherwise).
func TestEmulatedNginxConfigTestChecksEveryPair(t *testing.T) {
	w := newWorld(t)
	w.e.AddSite(NginxSite{Names: []string{"shop.example.test"}, Port: 8443, CertPath: "/etc/nginx/ssl/shop.crt", KeyPath: key},
		w.old.FullchainPEM, w.old.KeyPEM)
	r := w.deploy(emuOp)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	resp := decode[helperproto.NginxDeployResponse](t, r)
	assert.Equal(t, helperproto.PhaseRestored, resp.Phase)
	assert.Equal(t, helperproto.StepConfigTest, resp.FailedStep)
	assert.Equal(t, helperproto.StepConfigTest, resp.CauseStep)
	assert.Equal(t, helperproto.ConfigErrKeyMismatch, resp.Error)
	assert.Contains(t, resp.Steps, stepFailed("config_test", "key_mismatch"))
	w.assertPair(t, w.old)
	assert.Equal(t, 1, w.e.Reloads(), "only the rollback reloaded")
}

// changedFiles are the refusal cases that leave a file other than the old pair on disk.
var changedFiles = []string{"file changed", "cert missing", "cert garbled", "key does not match", "cert missing after nginx -T", "cert too large", "cert changed before the key is replaced",
	"cert hard linked", "special file system"}

func TestEmulatedNginxRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(w *world)
		exit  int
		code  string
	}{
		{"profile missing", func(w *world) { w.e.SetNginxProfile(false) }, 1, ""},
		{"config invalid", func(w *world) { w.e.SetConfigInvalid(helperproto.ConfigErrSyntax) }, helperproto.ExitPrecondition, helperproto.CodeConfigInvalid},
		{"nginx missing", func(w *world) { w.e.nx.installed = false }, helperproto.ExitPrecondition, helperproto.CodeNginxNotFound},
		{"nginx killed", func(w *world) { w.e.SetNginxKilled(true) }, helperproto.ExitFailed, helperproto.CodeIOError},
		{"pair not in the configuration", func(w *world) { w.e.nx.servers = nil }, helperproto.ExitPrecondition, helperproto.CodeConfigChanged},
		{"file changed", func(w *world) { w.e.SetNginxFile(crt, w.sameKey.FullchainPEM) }, helperproto.ExitPrecondition, helperproto.CodeHashMismatch},
		// Real nginx -T loads the pair files: a missing or garbled one is a configuration error.
		{"cert missing", func(w *world) { w.e.RemoveNginxFile(crt) }, helperproto.ExitPrecondition, helperproto.CodeConfigInvalid},
		{"cert garbled", func(w *world) { w.e.SetNginxFile(crt, []byte("x")) }, helperproto.ExitPrecondition, helperproto.CodeConfigInvalid},
		{"key does not match", func(w *world) { w.e.SetNginxFile(key, w.other.KeyPEM) }, helperproto.ExitPrecondition, helperproto.CodeConfigInvalid},
		// The race the helper guards against: the files changed after nginx -T (a forged dump).
		{"cert missing after nginx -T", func(w *world) { w.e.SetNginxDump(w.e.NginxDumpText()); w.e.RemoveNginxFile(crt) }, helperproto.ExitPrecondition, helperproto.CodeNotFound},
		{"cert hard linked", func(w *world) { w.e.SetFileProblem(crt, helperproto.FileHardLinked) }, helperproto.ExitRefused, helperproto.CodeUnsafeFile},
		{"key not regular", func(w *world) { w.e.SetFileProblem(key, helperproto.FileNotRegular) }, helperproto.ExitRefused, helperproto.CodeNotRegularFile},
		{"walk not root controlled", func(w *world) { w.e.SetFileProblem(key, helperproto.FileNotRootControlled) }, helperproto.ExitRefused, helperproto.CodePathNotAllowed},
		{"special file system", func(w *world) { w.e.SetFileProblem(crt, helperproto.FileSpecialFS) }, helperproto.ExitRefused, helperproto.CodePathNotAllowed},
		{"cert too large", func(w *world) { w.e.SetNginxFile(crt, padded(w.old.FullchainPEM)) }, helperproto.ExitRefused, helperproto.CodeTooLarge},
		{"no space", func(w *world) { w.e.SetFreeBytes(1) }, helperproto.ExitPrecondition, helperproto.CodeNoSpace},
		{"too many operations", func(w *world) { w.e.SetMaxNginxOps(1); w.e.nx.ops[emuOp3] = &opDir{j: &emuJournal{op: emuOp3}} }, helperproto.ExitPrecondition, helperproto.CodeNoSpace},
		{"busy", func(w *world) { w.e.HoldLock(true) }, helperproto.ExitFailed, helperproto.CodeBusy},
		{"cannot write", func(w *world) { w.e.FailWriteIn("/etc/nginx/ssl") }, helperproto.ExitFailed, helperproto.CodeIOError},
		{"journal cannot be written", func(w *world) { w.e.FailJournalWrite(helperproto.PhasePrepared) }, helperproto.ExitFailed, helperproto.CodeIOError},
		{"journal writing cannot be written", func(w *world) { w.e.FailJournalWrite(helperproto.PhaseWriting) }, helperproto.ExitFailed, helperproto.CodeIOError},
		{"cert changed before the key is replaced", func(w *world) { w.e.InterfereAt(helperproto.StepBackup, crt, []byte("x")) }, helperproto.ExitPrecondition, helperproto.CodeHashMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.setup(w)
			r := w.deploy(emuOp)
			assert.Equal(t, tc.exit, r.Exit, string(r.Stdout)+string(r.Stderr))
			if tc.code != "" {
				assert.Equal(t, tc.code, codeOf(t, r))
				assert.Equal(t, "", w.e.NginxPhase(emuOp), "a refusal leaves no operation behind")
			}
			assert.Equal(t, 0, w.e.Reloads())
			if !slices.Contains(changedFiles, tc.name) {
				w.assertPair(t, w.old)
			}
		})
	}
}

func TestEmulatedNginxArgumentValidationIsTheHelpers(t *testing.T) {
	w := newWorld(t)
	good := deployLineFor(emuOp, crt, key, w.oldSHA, w.deployIn)
	// The sudoers lines refuse what does not match their shape: the helper is never reached.
	for name, cmd := range map[string]string{
		"no arguments":     line(true, helperproto.SubNginxDeploy),
		"restore two ops":  line(true, helperproto.SubNginxRestore, "--op", emuOp, "--op", emuOp),
		"dump with a flag": line(true, helperproto.SubNginxDump, "--x"),
		"short op id":      line(true, helperproto.SubNginxStatus, "--op", "abc"),
		"relative cert":    deployLineFor(emuOp, "etc/x.crt", key, w.oldSHA, w.deployIn),
		"absent expect":    deployLineFor(emuOp, crt, key, helperproto.AbsentSHA256, w.deployIn),
		"short hash":       line(true, helperproto.SubNginxDeploy, "--op", emuOp, "--cert", crt, "--key", key, "--expect-cert-sha256", "ab", "--content-sha256", hexSum(w.deployIn)),
	} {
		r := w.run(cmd, w.deployIn)
		assert.Equal(t, 1, r.Exit, name)
		assert.Contains(t, string(r.Stderr), "sudo:", name)
	}
	assert.Zero(t, w.e.DeployCount())
	// Without sudo the helper itself refuses (NOT_ROOT), before its arguments.
	for _, sub := range []string{helperproto.SubNginxDump, helperproto.SubNginxTest, helperproto.SubNginxDeploy, helperproto.SubNginxRestore, helperproto.SubNginxStatus} {
		r := w.run(line(false, sub), nil)
		assert.Equal(t, helperproto.ExitRefused, r.Exit, sub)
		assert.Equal(t, helperproto.CodeNotRoot, codeOf(t, r), sub)
	}
	// Past sudo, the helper's validators answer INVALID_ARGUMENT, in the helper's order.
	upper := "0190F5A0-0000-7000-8000-0000000000E1"
	for name, tc := range map[string]struct {
		cmd  string
		code string
	}{
		"op not lower case":  {deployLineFor(upper, crt, key, w.oldSHA, w.deployIn), helperproto.CodeInvalidArgument},
		"dotdot path":        {deployLineFor(emuOp, "/etc/../shadow", key, w.oldSHA, w.deployIn), helperproto.CodeInvalidArgument},
		"same cert and key":  {deployLineFor(emuOp, crt, crt, w.oldSHA, w.deployIn), helperproto.CodeInvalidArgument},
		"status op not hex":  {line(true, helperproto.SubNginxStatus, "--op", strings.Repeat("z", 36)), helperproto.CodeInvalidArgument},
		"restore op not hex": {line(true, helperproto.SubNginxRestore, "--op", strings.Repeat("z", 36)), helperproto.CodeInvalidArgument},
	} {
		r := w.run(tc.cmd, w.deployIn)
		assert.Equal(t, helperproto.ExitRefused, r.Exit, name)
		assert.Equal(t, tc.code, codeOf(t, r), name)
	}
	// Content checks: incomplete stdin, not JSON, a key that is not the leaf's.
	r := w.run(good, w.deployIn[:len(w.deployIn)-10])
	assert.Equal(t, helperproto.ExitPrecondition, r.Exit)
	assert.Equal(t, helperproto.CodeContentMismatch, codeOf(t, r))
	for name, in := range map[string][]byte{
		"not json":      []byte("cert"),
		"wrong key":     input(w.nw.FullchainPEM, w.other.KeyPEM),
		"extra member":  []byte(`{"cert_pem":"a","key_pem":"b","x":"c"}`),
		"duplicate key": []byte(`{"cert_pem":"a","cert_pem":"b"}`),
		"too large":     make([]byte, helperproto.MaxDeployInput+1),
	} {
		wantExit, wantCode := helperproto.ExitRefused, helperproto.CodeBadContent
		if name == "too large" {
			wantCode = helperproto.CodeTooLarge
		}
		r := w.run(deployLineFor(emuOp, crt, key, w.oldSHA, in), in)
		assert.Equal(t, wantExit, r.Exit, name)
		assert.Equal(t, wantCode, codeOf(t, r), name)
	}
	assert.Zero(t, w.e.DeployCount(), "no refusal above reached the transaction")
	assert.Len(t, w.e.DeployStdins(), 9, "every call that got past sudo and the argument checks is recorded")
}

func TestEmulatedUnchangedDeployAnswersWithoutWriting(t *testing.T) {
	w := newWorld(t)
	w.e.SetNginxFile(crt, w.nw.FullchainPEM)
	w.e.SetNginxFile(key, w.nw.KeyPEM)
	r := w.run(deployLineFor(emuOp, crt, key, hexSum(w.nw.FullchainPEM), w.deployIn), w.deployIn)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	resp := decode[helperproto.NginxDeployResponse](t, r)
	assert.Equal(t, helperproto.PhaseUnchanged, resp.Phase)
	assert.Empty(t, resp.Steps)
	assert.Equal(t, 0, w.e.Reloads())
	assert.Equal(t, helperproto.PhaseUnchanged, w.status(emuOp).Phase)
	// Nothing to restore.
	rr := decode[helperproto.NginxRestoreResponse](t, w.restore(emuOp))
	assert.Equal(t, helperproto.PhaseUnchanged, rr.Phase)
}

func TestEmulatedHangupAndKill(t *testing.T) {
	w := newWorld(t)
	w.e.HangupAfter(helperproto.StepWriteCert)
	r := w.deploy(emuOp)
	assert.True(t, r.Hangup)
	assert.Equal(t, helperproto.PhaseCommitted, w.status(emuOp).Phase, "the helper finished on its own")
	assert.Equal(t, pki.Fingerprint(w.nw.Cert), w.e.Served(443, "www.example.test"))

	w = newWorld(t)
	w.e.KillAt(helperproto.StepWriteKey)
	r = w.deploy(emuOp)
	assert.Empty(t, r.Stdout, "a killed helper prints nothing")
	assert.Equal(t, "KILL", r.Signal, "and ends by a signal")
	assert.False(t, r.Hangup)
	st := w.status(emuOp)
	assert.Equal(t, helperproto.PhaseWriting, st.Phase)
	assert.False(t, st.Active)
	assert.Equal(t, hexSum(w.old.FullchainPEM), st.CurrentCertSHA256)
	assert.Equal(t, hexSum(w.nw.FullchainPEM), st.NewCertSHA256)
	assert.Equal(t, w.nw.KeyPEM, w.e.NginxFile(key), "the key was replaced, the certificate not: a mixed pair")
	assert.Equal(t, w.old.FullchainPEM, w.e.NginxFile(crt))
	r = w.restore(emuOp)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxRestoreResponse](t, r).Phase)
	w.assertPair(t, w.old)
	assert.Equal(t, helperproto.PhaseRestored, w.status(emuOp).Phase)

	// The kill is once: the same deployment sent again runs (the journal says restored: its answer).
	r = w.deploy(emuOp)
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxDeployResponse](t, r).Phase)
}

// The helper is killed at every point of a deployment: whatever it left, status answers and
// nginx-restore brings the pair back to the old files, complete.
func TestEmulatedKillAtEveryPointRecovers(t *testing.T) {
	keyFile, certFile := stagedName(emuOp, kindKey), stagedName(emuOp, kindCert)
	points := []string{
		"journal prepared staged", "journal prepared renamed", "backup cert", "backup key", "backup", "pair record staged", "pair record renamed",
		"journal writing staged", "journal writing renamed",
		"stage " + keyFile, "staged " + keyFile, "renamed " + keyFile, "write_key",
		"stage " + certFile, "staged " + certFile, "renamed " + certFile, "write_cert",
		"config_test", "reload", "journal committed staged", "journal committed renamed",
	}
	for _, p := range points {
		t.Run(p, func(t *testing.T) {
			w := newWorld(t)
			w.e.KillAt(p)
			r := w.deploy(emuOp)
			require.Equal(t, "KILL", r.Signal, "the point is reached")
			st := w.status(emuOp)
			assert.False(t, st.Active)
			switch st.Phase {
			case helperproto.PhaseNone, helperproto.PhasePrepared:
				w.assertPair(t, w.old)
			case helperproto.PhaseCommitted:
				w.assertPair(t, w.nw)
			}
			r = w.restore(emuOp)
			if st.Phase == helperproto.PhaseNone {
				assert.Equal(t, helperproto.CodeUnknownOp, codeOf(t, r))
			} else {
				require.Equal(t, 0, r.Exit, string(r.Stdout))
				assert.Contains(t, []string{helperproto.PhasePrepared, helperproto.PhaseRestored}, decode[helperproto.NginxRestoreResponse](t, r).Phase)
			}
			w.assertPair(t, w.old)
			assert.Equal(t, pki.Fingerprint(w.old.Cert), w.e.Served(443, "www.example.test"))
		})
	}
}

// A kill inside a rollback: another nginx-restore finishes it.
func TestEmulatedKillInsideARollback(t *testing.T) {
	for _, p := range []string{"journal restoring renamed", "renamed " + stagedName(emuOp, kindCert), "restore", "rollback_config_test", "rollback_reload"} {
		t.Run(p, func(t *testing.T) {
			w := newWorld(t)
			require.Equal(t, 0, w.deploy(emuOp).Exit)
			w.e.KillAt(p)
			assert.Equal(t, "KILL", w.restore(emuOp).Signal)
			r := w.restore(emuOp)
			require.Equal(t, 0, r.Exit, string(r.Stdout))
			assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxRestoreResponse](t, r).Phase)
			w.assertPair(t, w.old)
		})
	}
}

func TestEmulatedFailedStepsAreRolledBack(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setup    func(w *world)
		phase    string
		failed   string
		cause    string
		errClass string
		lastStep helperproto.NginxStep
		pair     string // old, new, mixed or foreign: the files on disk after the answer
		reloads  int
	}{
		{"config test", func(w *world) { w.e.FailConfigTest(1) }, helperproto.PhaseRestored, "config_test", "config_test", "syntax",
			stepOK("rollback_reload"), "old", 1},
		{"nginx killed during the test", func(w *world) { w.e.KillNginxAt(helperproto.StepWriteCert) }, helperproto.PhaseRestoreFailed, "rollback_config_test", "config_test", "",
			stepFailed("rollback_config_test", ""), "old", 0},
		{"reload", func(w *world) { w.e.FailReload(1) }, helperproto.PhaseRestored, "reload", "reload", "", stepOK("rollback_reload"), "old", 2},
		{"journal", func(w *world) { w.e.FailJournalWrite(helperproto.PhaseCommitted) }, helperproto.PhaseRestored, "journal", "journal", "", stepOK("rollback_reload"), "old", 2},
		{"rollback test", func(w *world) { w.e.FailConfigTest(2) }, helperproto.PhaseRestoreFailed, "rollback_config_test", "config_test", "syntax",
			stepFailed("rollback_config_test", "syntax"), "old", 0},
		{"rollback reload", func(w *world) { w.e.FailReload(2) }, helperproto.PhaseRestoreFailed, "rollback_reload", "reload", "", stepFailed("rollback_reload", ""), "old", 2},
		{"restore of the key", func(w *world) { w.e.FailConfigTest(1); w.e.FailRestoreFile(key) }, helperproto.PhaseRestoreFailed, "restore", "config_test", "syntax",
			stepFailed("restore", ""), "mixed", 0},
		{"restore of both", func(w *world) { w.e.FailConfigTest(1); w.e.FailRestoreFile(crt) }, helperproto.PhaseRestoreFailed, "restore", "config_test", "syntax",
			stepFailed("restore", ""), "new", 0},
		{"cert changed during the deployment", func(w *world) { w.e.InterfereAt(helperproto.StepWriteKey, crt, []byte("someone else's")) }, helperproto.PhaseRestoreFailed,
			"write_cert", "write_cert", "file_changed", stepOK("restore"), "foreign", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.setup(w)
			r := w.deploy(emuOp)
			require.Equal(t, 0, r.Exit, string(r.Stdout))
			resp := decode[helperproto.NginxDeployResponse](t, r)
			assert.Equal(t, tc.phase, resp.Phase)
			assert.Equal(t, tc.failed, resp.FailedStep)
			assert.Equal(t, tc.cause, resp.CauseStep)
			assert.Equal(t, tc.errClass, resp.Error)
			assert.Equal(t, tc.lastStep, resp.Steps[len(resp.Steps)-1])
			assert.Equal(t, tc.reloads, w.e.Reloads())
			switch tc.pair {
			case "old":
				w.assertPair(t, w.old)
			case "new":
				w.assertPair(t, w.nw)
			case "mixed":
				assert.Equal(t, w.old.FullchainPEM, w.e.NginxFile(crt))
				assert.Equal(t, w.nw.KeyPEM, w.e.NginxFile(key))
			case "foreign":
				assert.Equal(t, "someone else's", string(w.e.NginxFile(crt)))
				assert.Equal(t, w.old.KeyPEM, w.e.NginxFile(key), "this transaction's own key is put back")
			}
			assert.Equal(t, pki.Fingerprint(w.old.Cert), w.e.Served(443, "www.example.test"), "no failed deployment changed what Nginx serves")
			// The status says what the answer said.
			st := w.status(emuOp)
			assert.Equal(t, resp.Phase, st.Phase)
			assert.Equal(t, resp.FailedStep, st.FailedStep)
			assert.Equal(t, resp.CauseStep, st.CauseStep)
			assert.Equal(t, resp.Error, st.Error)
		})
	}
}

// Writing the certificate fails while the key's directory is writable: the key already replaced is
// rolled back (restored, failed_step write_cert); the rollback has nothing to write in the
// certificate's directory.
func TestEmulatedWriteFailureOfTheCertificateOnly(t *testing.T) {
	w := newWorld(t)
	w.e.AddSite(NginxSite{Names: []string{"a.example.test"}, Port: 9443, CertPath: "/etc/nginx/cert/a.crt", KeyPath: "/etc/nginx/key/a.key"},
		w.old.FullchainPEM, w.old.KeyPEM)
	w.e.FailWriteIn("/etc/nginx/cert")
	r := w.run(deployLineFor(emuOp, "/etc/nginx/cert/a.crt", "/etc/nginx/key/a.key", w.oldSHA, w.deployIn), w.deployIn)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	resp := decode[helperproto.NginxDeployResponse](t, r)
	assert.Equal(t, helperproto.PhaseRestored, resp.Phase, "%+v", resp)
	assert.Equal(t, helperproto.StepWriteCert, resp.FailedStep)
	assert.Equal(t, stepFailed("write_cert", ""), resp.Steps[2])
	assert.Equal(t, w.old.KeyPEM, w.e.NginxFile("/etc/nginx/key/a.key"))
}

func TestEmulatedRestoreRefusals(t *testing.T) {
	w := newWorld(t)
	assert.Equal(t, helperproto.CodeUnknownOp, codeOf(t, w.restore(emuOp)))
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	w.e.HoldLock(true)
	assert.Equal(t, helperproto.CodeBusy, codeOf(t, w.restore(emuOp)))
	assert.True(t, w.status(emuOp).Active)
	w.e.HoldLock(false)
	// Someone else changed the certificate after the deployment: nothing is restored.
	w.e.SetNginxFile(crt, []byte("someone else's"))
	r := w.restore(emuOp)
	assert.Equal(t, helperproto.ExitPrecondition, r.Exit)
	assert.Equal(t, helperproto.CodeHashMismatch, codeOf(t, r))
	assert.Equal(t, w.nw.KeyPEM, w.e.NginxFile(key))
	assert.Equal(t, helperproto.PhaseRestoreFailed, w.status(emuOp).Phase)
	assert.Equal(t, helperproto.RestoreErrFileChanged, w.status(emuOp).Error)
	// The same refusal again changes nothing.
	r = w.restore(emuOp)
	assert.Equal(t, helperproto.CodeHashMismatch, codeOf(t, r))
}

// Only the operation that last replaced a pair's files can be restored; operations that changed
// nothing are passed over; after the latest is cleaned up no older one is restorable.
func TestEmulatedSupersededRule(t *testing.T) {
	cleanup := func(w *world, op string) Response { return w.run(line(true, helperproto.SubCleanup, "--op", op), nil) }
	w := newWorld(t)
	require.Equal(t, 0, w.deploy(emuOp).Exit) // A: old -> nw
	third := w.ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	inB := input(third.FullchainPEM, third.KeyPEM)
	r := w.run(deployLineFor(emuOp2, crt, key, hexSum(w.nw.FullchainPEM), inB), inB) // B: nw -> third
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, helperproto.PhaseCommitted, decode[helperproto.NginxDeployResponse](t, r).Phase)

	// A is superseded by B.
	r = w.restore(emuOp)
	assert.Equal(t, helperproto.ExitPrecondition, r.Exit)
	assert.Equal(t, helperproto.CodeSuperseded, codeOf(t, r))
	// So is a re-sent interrupted A.
	// A no-op C (unchanged) is passed over: B stays the latest.
	r = w.run(deployLineFor(emuOp3, crt, key, hexSum(third.FullchainPEM), inB), inB)
	assert.Equal(t, helperproto.PhaseUnchanged, decode[helperproto.NginxDeployResponse](t, r).Phase)
	assert.Equal(t, helperproto.CodeSuperseded, codeOf(t, w.restore(emuOp)), "A is still superseded")
	// Removing the no-op C hands the record back: B is restorable, A is not.
	assert.Equal(t, 1, decode[helperproto.CleanupResponse](t, cleanup(w, emuOp3)).Removed)
	// B cleaned up: no older operation of the pair can be restored.
	assert.Equal(t, 1, decode[helperproto.CleanupResponse](t, cleanup(w, emuOp2)).Removed)
	r = w.restore(emuOp)
	assert.Equal(t, helperproto.CodeSuperseded, codeOf(t, r), "the latest operation is gone: the older one is not restorable")
	w.assertPair(t, third)

	// B restorable while it is the latest (a fresh world).
	w = newWorld(t)
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	r = w.run(deployLineFor(emuOp2, crt, key, hexSum(w.nw.FullchainPEM), inB), inB)
	require.Equal(t, 0, r.Exit)
	r = w.restore(emuOp2)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, w.nw.KeyPEM, w.e.NginxFile(key))
}

func TestEmulatedSupersededResentDeployment(t *testing.T) {
	w := newWorld(t)
	w.e.KillAt(helperproto.StepWriteKey)
	require.Equal(t, "KILL", w.deploy(emuOp).Signal)
	// A later operation replaces the pair (the first rolled itself back: the pair is old again).
	require.Equal(t, 0, w.restore(emuOp).Exit)
	third := w.ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	inB := input(third.FullchainPEM, third.KeyPEM)
	require.Equal(t, 0, w.run(deployLineFor(emuOp2, crt, key, w.oldSHA, inB), inB).Exit)
	// The restored first operation answers from its journal; an interrupted one would be superseded.
	w.e.nx.ops[emuOp].j.phase = helperproto.PhaseWriting
	r := w.deploy(emuOp)
	assert.Equal(t, helperproto.CodeSuperseded, codeOf(t, r))
}

func TestEmulatedCleanup(t *testing.T) {
	w := newWorld(t)
	cleanup := func(op string) Response { return w.run(line(true, helperproto.SubCleanup, "--op", op), nil) }
	w.e.KillAt(helperproto.StepWriteKey)
	require.Equal(t, "KILL", w.deploy(emuOp).Signal)
	// An interrupted operation is kept: its backups are what nginx-restore needs.
	r := cleanup(emuOp)
	assert.Equal(t, helperproto.ExitFailed, r.Exit)
	assert.Equal(t, helperproto.CodeBusy, codeOf(t, r))
	require.Equal(t, 0, w.restore(emuOp).Exit)
	w.e.HoldLock(true)
	assert.Equal(t, helperproto.CodeBusy, codeOf(t, cleanup(emuOp)))
	w.e.HoldLock(false)
	assert.Equal(t, 1, decode[helperproto.CleanupResponse](t, cleanup(emuOp)).Removed)
	assert.Equal(t, helperproto.PhaseNone, w.status(emuOp).Phase)
	assert.Equal(t, 0, decode[helperproto.CleanupResponse](t, cleanup(emuOp)).Removed)
}

func TestEmulatedProbe(t *testing.T) {
	w := newWorld(t)
	probe := func(addr, port, sni, kt string) Response {
		return w.run(line(false, helperproto.SubTLSProbe, "--addr", addr, "--port", port, "--sni", sni, "--key-type", kt), nil)
	}
	r := probe("127.0.0.1", "443", "www.example.test", "any")
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	p := decode[helperproto.TLSProbeResponse](t, r)
	assert.Equal(t, pki.Fingerprint(w.old.Cert), p.LeafSHA256)
	assert.Equal(t, 2, p.ChainLength, "leaf and intermediate")
	assert.Equal(t, w.old.Cert.NotAfter.UTC().Format(time.RFC3339), p.NotAfter)
	// With a name that no server has, and without one, the default server answers (here the only one).
	assert.Equal(t, 0, probe("127.0.0.1", "443", "nobody.example.test", "any").Exit)
	assert.Equal(t, 0, probe("127.0.0.1", "443", "_", "any").Exit)
	// A key type the served leaf does not have fails the handshake.
	assert.Equal(t, 0, probe("127.0.0.1", "443", "_", "ecdsa").Exit)
	r = probe("127.0.0.1", "443", "_", "rsa")
	assert.Equal(t, helperproto.ExitFailed, r.Exit)
	assert.Equal(t, helperproto.CodeProbeFailed, codeOf(t, r))
	// Nothing listens on another port.
	assert.Equal(t, helperproto.CodeProbeFailed, codeOf(t, probe("127.0.0.1", "8443", "_", "any")))
	// Argument errors are the helper's.
	assert.Equal(t, helperproto.CodeInvalidArgument, codeOf(t, probe("localhost", "443", "_", "any")))
	assert.Equal(t, helperproto.CodeInvalidArgument, codeOf(t, probe("127.0.0.1", "0443", "_", "any")))
	assert.Equal(t, helperproto.CodeInvalidArgument, codeOf(t, probe("127.0.0.1", "443", "WWW", "any")))
	assert.Equal(t, helperproto.CodeInvalidArgument, codeOf(t, probe("127.0.0.1", "443", "_", "dsa")))
	assert.Equal(t, helperproto.CodeUsage, codeOf(t, w.run(line(false, helperproto.SubTLSProbe, "--addr", "127.0.0.1"), nil)))
	// sudo does not list tls-probe: sudo refuses it.
	r = w.run(line(true, helperproto.SubTLSProbe, "--addr", "127.0.0.1", "--port", "443", "--sni", "_", "--key-type", "any"), nil)
	assert.Equal(t, 1, r.Exit)
	assert.Contains(t, string(r.Stderr), "sudo:")

	// After a deploy and its reload the served leaf changes; a failed reload keeps the old one.
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	assert.Equal(t, pki.Fingerprint(w.nw.Cert), decode[helperproto.TLSProbeResponse](t, probe("127.0.0.1", "443", "_", "any")).LeafSHA256)
	w.e.LocalProbeFails(true)
	assert.Equal(t, helperproto.CodeProbeFailed, codeOf(t, probe("127.0.0.1", "443", "_", "any")))
}

func TestEmulatedServedFollowsReloadsAndOtherListeners(t *testing.T) {
	w := newWorld(t)
	oldFP, newFP := pki.Fingerprint(w.old.Cert), pki.Fingerprint(w.nw.Cert)

	// NoopReload: the reload "succeeds" and Nginx keeps serving the old files (F-05).
	w.e.NoopReload(true)
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	assert.Equal(t, oldFP, w.e.Served(443, "www.example.test"))
	assert.Equal(t, w.nw.FullchainPEM, w.e.NginxFile(crt))
	w.e.NoopReload(false)

	// Something else answers on the port (F-06).
	w.e.ServeOther(443, "deadbeef")
	assert.Equal(t, "deadbeef", w.e.Served(443, "www.example.test"))
	w.e.ServeOther(443, "")

	// From the next successful reload until the one after it.
	w = newWorld(t)
	oldFP = pki.Fingerprint(w.old.Cert)
	w.e.ServeOtherAfterReload(443, "cafe")
	assert.Equal(t, oldFP, w.e.Served(443, ""))
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	assert.Equal(t, "cafe", w.e.Served(443, ""))
	require.Equal(t, 0, w.restore(emuOp).Exit)
	assert.Equal(t, oldFP, w.e.Served(443, ""), "the rollback's reload ends it")
	_ = newFP
}

func TestEmulatedServerSelection(t *testing.T) {
	w := newWorld(t)
	other := w.ca.Issue(pki.Opts{CommonName: "wild.example.test"}, testNow)
	dflt := w.ca.Issue(pki.Opts{CommonName: "default.example.test"}, testNow)
	w.e.AddSite(NginxSite{Names: []string{"*.wild.test"}, Port: 443, CertPath: "/etc/nginx/ssl/wild.crt", KeyPath: "/etc/nginx/ssl/wild.key"}, other.FullchainPEM, other.KeyPEM)
	w.e.AddSite(NginxSite{Names: []string{"d.example.test"}, Port: 443, Default: true, CertPath: "/etc/nginx/ssl/d.crt", KeyPath: "/etc/nginx/ssl/d.key"}, dflt.FullchainPEM, dflt.KeyPEM)
	w.e.AddSite(NginxSite{Names: []string{"v6.example.test"}, Port: 443, Addr: "::1", CertPath: "/etc/nginx/ssl/v6.crt", KeyPath: "/etc/nginx/ssl/v6.key"}, other.FullchainPEM, other.KeyPEM)
	assert.Equal(t, pki.Fingerprint(w.old.Cert), w.e.Served(443, "www.example.test"), "an exact name")
	assert.Equal(t, pki.Fingerprint(other.Cert), w.e.Served(443, "a.wild.test"), "a wildcard")
	assert.Equal(t, pki.Fingerprint(dflt.Cert), w.e.Served(443, "unknown.example.test"), "the default server")
	assert.Equal(t, pki.Fingerprint(dflt.Cert), w.e.Served(443, ""), "no SNI: the default server")
	assert.Empty(t, w.e.Served(444, ""))
	// A site bound to an address answers only there.
	probe := func(addr string) Response {
		return w.run(line(false, helperproto.SubTLSProbe, "--addr", addr, "--port", "443", "--sni", "v6.example.test", "--key-type", "any"), nil)
	}
	assert.Equal(t, pki.Fingerprint(other.Cert), decode[helperproto.TLSProbeResponse](t, probe("::1")).LeafSHA256)
	assert.NotEqual(t, pki.Fingerprint(other.Cert), decode[helperproto.TLSProbeResponse](t, probe("127.0.0.1")).LeafSHA256)
}

func TestEmulatedNoSudoersProfileIsIndependentOfNginx(t *testing.T) {
	e := NewEmulator() // no Nginx installed, profile installed by default
	r := e.handle(line(true, helperproto.SubNginxDump), nil)
	assert.Equal(t, helperproto.ExitPrecondition, r.Exit)
	assert.Equal(t, helperproto.CodeNginxNotFound, decode[helperproto.ErrorResponse](t, r).Code)
	r = e.handle(line(true, helperproto.SubNginxTest), nil)
	assert.Equal(t, helperproto.CodeNginxNotFound, decode[helperproto.ErrorResponse](t, r).Code)
	e.EnableNginx("1.22.1")
	e.SetNginxProfile(false)
	for _, sub := range []string{helperproto.SubNginxDump, helperproto.SubNginxTest} {
		r = e.handle(line(true, sub), nil)
		assert.Equal(t, 1, r.Exit, sub)
	}
	// cleanup, version and the Phase 3 subcommands are unaffected.
	assert.Equal(t, 0, e.handle(line(true, helperproto.SubCleanup, "--op", emuOp), nil).Exit)
}

func TestEmulatedNginxTest(t *testing.T) {
	w := newWorld(t)
	run := func() helperproto.NginxTestResponse {
		r := w.run(line(true, helperproto.SubNginxTest), nil)
		require.Equal(t, 0, r.Exit, string(r.Stdout))
		return decode[helperproto.NginxTestResponse](t, r)
	}
	assert.Equal(t, helperproto.NginxTestResponse{OK: true, Valid: true}, run())
	w.e.SetConfigInvalid(helperproto.ConfigErrSyntax)
	assert.Equal(t, helperproto.NginxTestResponse{OK: true, Valid: false, Error: "syntax"}, run())
	w.e.SetConfigInvalid("")
	// A key that does not match: found by the test of the current files.
	w.e.SetNginxFile(key, w.other.KeyPEM)
	assert.Equal(t, helperproto.NginxTestResponse{OK: true, Valid: false, Error: "key_mismatch"}, run())
	w.e.SetNginxFile(key, []byte("not a key"))
	assert.Equal(t, "key_load", run().Error)
	w.e.SetNginxFile(crt, []byte("not a certificate"))
	assert.Equal(t, "cert_load", run().Error)
	w.e.RemoveNginxFile(crt)
	assert.Equal(t, "file_missing", run().Error)
	// FailConfigTest is for the tests inside a deploy only.
	w = newWorld(t)
	w.e.FailConfigTest(1)
	assert.True(t, run().Valid)
	w.e.SetNginxKilled(true)
	r := w.run(line(true, helperproto.SubNginxTest), nil)
	assert.Equal(t, helperproto.ExitFailed, r.Exit)
	assert.Equal(t, helperproto.CodeIOError, codeOf(t, r))
	assert.Equal(t, helperproto.ExitFailed, w.run(line(true, helperproto.SubNginxDump), nil).Exit)
}

// The emulated state never prints key material: not %+v, %#v nor a slog-style dump of the emulator,
// its recorded deploy inputs, journals or backups.
func TestEmulatorStateNeverPrintsAKey(t *testing.T) {
	w := newWorld(t)
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	w.e.KillAt(helperproto.StepWriteKey)
	_ = w.run(deployLineFor(emuOp2, crt, key, hexSum(w.nw.FullchainPEM), input(w.other.FullchainPEM, w.other.KeyPEM)), nil)
	needles := []string{}
	for _, k := range [][]byte{w.old.KeyPEM, w.nw.KeyPEM, w.other.KeyPEM} {
		body := strings.Split(string(k), "\n")[1]
		prefix := []byte(body[:12])
		needles = append(needles, body, hex.EncodeToString([]byte(body)), fmt.Sprintf("%d", prefix)) // a byte slice printed as numbers
	}
	for _, v := range []any{w.e, w.e.nx, w.e.nx.ops, w.e.nx.stdins, w.e.nx.content, w.e.nx.ops[emuOp], w.e.nx.ops[emuOp].j} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(format, v)
			for _, n := range needles {
				assert.NotContains(t, out, n, "%s of %T", format, v)
			}
		}
	}
	assert.NotEmpty(t, w.e.DeployStdins(), "the accessor itself returns the bytes")
}

func TestEmulatedNginxDumpFromAConfiguration(t *testing.T) {
	w := newWorld(t)
	w.e.AddUnsupported([]string{"var.example.test"}, 443, "/etc/nginx/ssl/$host.crt", nginxconf.ReasonVariable)
	d := decode[helperproto.NginxDumpResponse](t, w.run(line(true, helperproto.SubNginxDump), nil))
	require.True(t, d.ConfigValid, "%+v", d)
	require.Len(t, d.Servers, 2)
	assert.Equal(t, 11, d.Servers[1].Line)
	assert.Equal(t, helperproto.NginxPair{Cert: "", Key: "", Unsupported: "variable", Raw: "/etc/nginx/ssl/$host.crt"}, d.Servers[1].Pairs[0])
	assert.Len(t, d.Files, 2, "an unsupported pair's files are not described")

	// Every unsupported reason the real parser produces, through its real text.
	for _, tc := range []struct{ reason, raw, wantRaw string }{
		{nginxconf.ReasonVariable, "/etc/nginx/ssl/$host.crt", "/etc/nginx/ssl/$host.crt"},
		{nginxconf.ReasonDataValue, "data:$ssl_cert", "data:$ssl_cert"},
		{nginxconf.ReasonEngineKey, "/etc/nginx/ssl/e.crt", "/etc/nginx/ssl/e.crt"},
		{nginxconf.ReasonKeyMissing, "/etc/nginx/ssl/m.crt", "/etc/nginx/ssl/m.crt"},
		{nginxconf.ReasonPasswordFile, "/etc/nginx/ssl/p.crt", "/etc/nginx/ssl/p.crt"},
		{nginxconf.ReasonPathNotAllowed, "ssl/", "ssl/"},
		{nginxconf.ReasonCombinedFile, "/etc/nginx/ssl/c.pem", "/etc/nginx/ssl/c.pem"},
		{nginxconf.ReasonStream, "/etc/nginx/ssl/s.crt", "/etc/nginx/ssl/s.crt"},
		{nginxconf.ReasonConfigFileWritable, "/etc/nginx/ssl/w.crt", "/etc/nginx/ssl/w.crt"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			e := NewEmulator()
			e.EnableNginx("1.22.1")
			e.AddUnsupported([]string{"u.example.test"}, 443, tc.raw, tc.reason)
			d := decode[helperproto.NginxDumpResponse](t, e.handle(line(true, helperproto.SubNginxDump), nil))
			require.True(t, d.ConfigValid, "%+v", d)
			require.Len(t, d.Servers, 1)
			require.Len(t, d.Servers[0].Pairs, 1)
			assert.Equal(t, tc.reason, d.Servers[0].Pairs[0].Unsupported)
			assert.Equal(t, tc.wantRaw, d.Servers[0].Pairs[0].Raw)
			assert.Empty(t, d.Files)
			assert.Equal(t, tc.reason == nginxconf.ReasonStream, d.Servers[0].Stream)
			if tc.reason == nginxconf.ReasonStream {
				assert.Equal(t, []string{helperproto.WarnStreamTLS}, d.Warnings, "D12: a stream entry warns stream_tls")
			}
			if tc.reason == nginxconf.ReasonConfigFileWritable {
				assert.Equal(t, []string{helperproto.WarnConfigFileWritable}, d.Warnings)
				assert.Equal(t, []string{"/etc/nginx/conf.d/writable.conf"}, d.Writable)
			}
		})
	}

	// The reason of a writable file marks only the pairs that file holds.
	e := NewEmulator()
	e.EnableNginx("1.22.1")
	e.AddSite(NginxSite{Names: []string{"a"}, Port: 443, CertPath: crt, KeyPath: key}, w.old.FullchainPEM, w.old.KeyPEM)
	e.SetNginxFileMode("/etc/nginx/conf.d/emu.conf", "root", "root", 0o664)
	d = decode[helperproto.NginxDumpResponse](t, e.handle(line(true, helperproto.SubNginxDump), nil))
	assert.Equal(t, nginxconf.ReasonConfigFileWritable, d.Servers[0].Pairs[0].Unsupported)
	assert.Equal(t, []string{"/etc/nginx/conf.d/emu.conf"}, d.Writable)
	e.SetNginxFileMode("/etc/nginx/conf.d/emu.conf", "alice", "root", 0o644)
	d = decode[helperproto.NginxDumpResponse](t, e.handle(line(true, helperproto.SubNginxDump), nil))
	assert.Equal(t, nginxconf.ReasonConfigFileWritable, d.Servers[0].Pairs[0].Unsupported, "owned by a user other than root")
}

func TestEmulatedNginxDumpFilesAndWarnings(t *testing.T) {
	w := newWorld(t)
	dump := func() helperproto.NginxDumpResponse {
		r := w.run(line(true, helperproto.SubNginxDump), nil)
		require.Equal(t, 0, r.Exit, string(r.Stdout))
		return decode[helperproto.NginxDumpResponse](t, r)
	}
	file := func(d helperproto.NginxDumpResponse, kind string) helperproto.NginxFile {
		for _, f := range d.Files {
			if f.Kind == kind {
				return f
			}
		}
		t.Fatalf("no %s file in %+v", kind, d.Files)
		return helperproto.NginxFile{}
	}
	d := dump()
	c := file(d, "cert")
	assert.Equal(t, helperproto.NginxFile{Path: crt, Kind: "cert", Exists: true, Resolved: crt, Mode: "0644", Owner: "root", Group: "root",
		Size: int64(len(w.old.FullchainPEM)), SHA256: hexSum(w.old.FullchainPEM), PEM: string(w.old.FullchainPEM), FreeBytes: 1 << 30}, c)
	k := file(d, "key")
	assert.Equal(t, helperproto.NginxFile{Path: key, Kind: "key", Exists: true, Resolved: key, Mode: "0600", Owner: "root", Group: "root",
		Size: int64(len(w.old.KeyPEM)), FreeBytes: 1 << 30}, k)
	assert.Equal(t, []string{}, d.Warnings)
	assert.Equal(t, []string{}, d.Writable)

	// Problems. What real nginx -T would refuse (a pair file that is missing or not a certificate)
	// shows only in a dump forged from the files as they were.
	forge := func() { w.e.SetNginxDump(w.e.NginxDumpText()) }
	for _, tc := range []struct {
		name    string
		setup   func()
		kind    string
		problem string
		exists  bool
	}{
		{"missing cert", func() { forge(); w.e.RemoveNginxFile(crt) }, "cert", helperproto.FileMissing, false},
		{"missing key", func() { forge(); w.e.RemoveNginxFile(key) }, "key", helperproto.FileMissing, false},
		{"special file system", func() { w.e.SetFileProblem(crt, helperproto.FileSpecialFS) }, "cert", helperproto.FileSpecialFS, true},
		{"not root controlled", func() { w.e.SetFileProblem(key, helperproto.FileNotRootControlled) }, "key", helperproto.FileNotRootControlled, true},
		{"not regular cert", func() { w.e.SetFileProblem(crt, helperproto.FileNotRegular) }, "cert", helperproto.FileNotRegular, true},
		{"hard linked key", func() { w.e.SetFileProblem(key, helperproto.FileHardLinked) }, "key", helperproto.FileHardLinked, true},
		{"too large cert", func() { w.e.SetNginxFile(crt, padded(w.old.FullchainPEM)) }, "cert", helperproto.FileTooLarge, true},
		{"not a certificate", func() { forge(); w.e.SetNginxFile(crt, []byte("hello")) }, "cert", helperproto.FileNotACertificate, true},
	} {
		w = newWorld(t)
		tc.setup()
		f := file(dump(), tc.kind)
		assert.Equal(t, tc.problem, f.Problem, tc.name)
		assert.Equal(t, tc.exists, f.Exists, tc.name)
	}

	// Warnings.
	w = newWorld(t)
	w.e.SetNginxFileMode(key, "root", "ssl-cert", 0o640)
	d = dump()
	assert.Equal(t, []string{helperproto.WarnKeyGroupOpen}, d.Warnings)
	assert.Equal(t, "0640", file(d, "key").Mode)
	assert.Equal(t, "ssl-cert", file(d, "key").Group)
	w = newWorld(t)
	w.e.SetNginxFileMode(key, "root", "root", 0o644)
	assert.Equal(t, []string{helperproto.WarnKeyGroupOpen}, dump().Warnings)
	w = newWorld(t)
	w.e.SetNginxDump(w.e.NginxDumpText())
	w.e.SetNginxFile(crt, append(append([]byte{}, w.old.FullchainPEM...), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")...))
	d = dump()
	assert.Equal(t, []string{helperproto.WarnCertificateBlockDropped}, d.Warnings)
	assert.Equal(t, string(w.old.FullchainPEM), file(d, "cert").PEM)
	w = newWorld(t)
	w.e.SetNginxConfig("/etc/nginx/nginx.conf", "events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\nmail { server { listen 995 ssl; ssl_certificate /x/a.crt; ssl_certificate_key /x/a.key; } }\n")
	assert.Equal(t, []string{helperproto.WarnMailTLS}, dump().Warnings)

	// Too many files: the helper lists at most MaxNginxFiles, certificates first.
	w = newWorld(t)
	for i := range helperproto.MaxNginxFiles {
		w.e.AddSite(NginxSite{Port: 10000 + i, CertPath: fmt.Sprintf("/etc/nginx/many/%d.crt", i), KeyPath: fmt.Sprintf("/etc/nginx/many/%d.key", i)},
			w.old.CertPEM, w.old.KeyPEM)
	}
	d = dump()
	assert.Contains(t, d.Warnings, helperproto.WarnTooManyFiles)
	assert.Len(t, d.Files, helperproto.MaxNginxFiles)

	// An answer over the budget is never truncated.
	w = newWorld(t)
	w.e.SetNginxDumpBudget(100)
	r := w.run(line(true, helperproto.SubNginxDump), nil)
	assert.Equal(t, helperproto.ExitFailed, r.Exit)
	assert.Equal(t, helperproto.CodeOutputTooLarge, codeOf(t, r))
}

func TestEmulatedNginxDumpRefusalsSayWhyAndWhere(t *testing.T) {
	const confPath = "/etc/nginx/nginx.conf"
	main := "http { include /etc/nginx/conf.d/*.conf; }\n"
	for _, tc := range []struct {
		name         string
		setup        func(e *Emulator)
		class        string
		reason, file string
	}{
		{"syntax of nginx -T", func(e *Emulator) { e.SetConfigInvalid(helperproto.ConfigErrSyntax) }, "syntax", "", ""},
		{"key mismatch of nginx -T", func(e *Emulator) { e.SetConfigInvalid(helperproto.ConfigErrKeyMismatch) }, "key_mismatch", "", ""},
		{"unbalanced braces", func(e *Emulator) { e.SetNginxConfig(confPath, "http {\n") }, "syntax", "", ""},
		{"no conf path", func(e *Emulator) { e.SetNginxConfPath("") }, "unsupported", helperproto.ConfigReasonNoConfPath, ""},
		{"relative conf path", func(e *Emulator) { e.SetNginxConfPath("nginx.conf") }, "unsupported", helperproto.ConfigReasonNoConfPath, ""},
		{"nul byte", func(e *Emulator) { e.SetNginxDump("# configuration file " + confPath + ":\nhttp {}\x00\n") }, "unsupported", helperproto.ConfigReasonNULByte, ""},
		{"include loop", func(e *Emulator) {
			e.SetNginxConfig(confPath, "include /etc/nginx/a.conf;\n")
			e.SetNginxConfig("/etc/nginx/a.conf", "include /etc/nginx/nginx.conf;\n")
		}, "unsupported", helperproto.ConfigReasonIncludeLoop, ""},
		{"too complex", func(e *Emulator) {
			e.SetNginxConfig(confPath, "http {"+strings.Repeat("a;\n", 1<<20+1)+"}\n")
		}, "unsupported", helperproto.ConfigReasonTooComplex, ""},
		{"name not allowed", func(e *Emulator) {
			e.SetNginxDump(e.nx.dumpOutput() + "# configuration file /etc/nginx/conf.d/a b.conf:\n\n")
		},
			"unsupported", helperproto.ConfigReasonNameNotAllowed, ""},
		{"duplicate file", func(e *Emulator) {
			e.SetNginxDump("# configuration file " + confPath + ":\n" + main + "\n# configuration file " + confPath + ":\n" + main + "\n")
		}, "untrusted", helperproto.ConfigReasonDuplicateFile, ""},
		{"unexpected text", func(e *Emulator) { e.SetNginxDump("http { server { }}\n" + e.nx.dumpOutput()) }, "untrusted", helperproto.ConfigReasonUnexpectedText, ""},
		{"wrong first file", func(e *Emulator) { e.SetNginxDump("# configuration file /etc/nginx/other.conf:\n" + main + "\n") }, "untrusted", helperproto.ConfigReasonWrongFirstFile, "/etc/nginx/other.conf"},
		{"empty dump", func(e *Emulator) { e.SetNginxDump("") }, "untrusted", helperproto.ConfigReasonWrongFirstFile, ""},
		{"changed", func(e *Emulator) {
			e.SetNginxDump(e.nx.dumpOutput())
			e.SetNginxFile("/etc/nginx/conf.d/emu.conf", append(e.NginxFile("/etc/nginx/conf.d/emu.conf"), '#', '\n'))
		}, "untrusted", helperproto.ConfigReasonChanged, "/etc/nginx/conf.d/emu.conf"},
		{"no line feed after the file", func(e *Emulator) { e.SetNginxDump(strings.TrimSuffix(e.nx.dumpOutput(), "\n")) },
			"untrusted", helperproto.ConfigReasonChanged, "/etc/nginx/conf.d/emu.conf"},
		{"missing config file", func(e *Emulator) {
			e.SetNginxDump(e.nx.dumpOutput())
			e.RemoveNginxFile("/etc/nginx/conf.d/emu.conf")
		}, "untrusted", helperproto.ConfigReasonMissing, "/etc/nginx/conf.d/emu.conf"},
		{"special file system", func(e *Emulator) { e.SetFileProblem("/etc/nginx/conf.d/emu.conf", helperproto.FileSpecialFS) }, "untrusted", helperproto.ConfigReasonSpecialFS, "/etc/nginx/conf.d/emu.conf"},
		{"not root controlled", func(e *Emulator) { e.SetFileProblem("/etc/nginx/conf.d/emu.conf", helperproto.FileNotRootControlled) }, "untrusted", helperproto.ConfigReasonNotRootControlled, "/etc/nginx/conf.d/emu.conf"},
		{"not regular", func(e *Emulator) { e.SetFileProblem("/etc/nginx/conf.d/emu.conf", helperproto.FileNotRegular) }, "untrusted", helperproto.ConfigReasonNotRegular, "/etc/nginx/conf.d/emu.conf"},
		{"removed config file", func(e *Emulator) { e.RemoveNginxFile("/etc/nginx/conf.d/emu.conf") }, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.setup(w.e)
			r := w.run(line(true, helperproto.SubNginxDump), nil)
			require.Equal(t, 0, r.Exit, string(r.Stdout))
			d := decode[helperproto.NginxDumpResponse](t, r)
			if tc.class == "" {
				assert.True(t, d.ConfigValid, "a removed file is no file of the dump any more: %+v", d)
				assert.Empty(t, d.Servers)
				return
			}
			assert.False(t, d.ConfigValid)
			assert.Equal(t, tc.class, d.ConfigError)
			assert.Equal(t, tc.reason, d.ConfigErrorReason)
			assert.Equal(t, tc.file, d.ConfigErrorFile)
			assert.Empty(t, d.Servers)
			assert.Empty(t, d.Files)
			assert.Equal(t, "1.22.1", d.Version, "nginx -V still answered")
		})
	}
}

func TestEmulatedNginxDumpTooLargeAndKilled(t *testing.T) {
	w := newWorld(t)
	w.e.SetNginxConfig("/etc/nginx/nginx.conf", "# "+strings.Repeat("x", helperproto.MaxNginxConfig)+"\nhttp { include /etc/nginx/conf.d/*.conf; }\n")
	d := decode[helperproto.NginxDumpResponse](t, w.run(line(true, helperproto.SubNginxDump), nil))
	assert.Equal(t, "unsupported", d.ConfigError)
	assert.Equal(t, helperproto.ConfigReasonTooLarge, d.ConfigErrorReason)

	w = newWorld(t)
	w.e.SetNginxKilled(true)
	r := w.run(line(true, helperproto.SubNginxDump), nil)
	assert.Equal(t, helperproto.ExitFailed, r.Exit)
	assert.Equal(t, helperproto.CodeIOError, codeOf(t, r))
}

// A re-sent deployment whose first run was interrupted answers from its rolled-back journal: phase
// restored with NO failed_step (the interruption has no step that failed). The framework's
// outcome invariants (providers.DeployOutcome rolled_back) require one: the Nginx provider must not
// pass this answer on as rolled_back as it is (Task 11 finding, see the Task 9 report).
func TestEmulatedResentInterruptedDeployHasNoFailedStep(t *testing.T) {
	w := newWorld(t)
	w.e.KillAt(helperproto.StepWriteKey)
	require.Equal(t, "KILL", w.deploy(emuOp).Signal)
	r := w.deploy(emuOp)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	resp := decode[helperproto.NginxDeployResponse](t, r)
	assert.Equal(t, helperproto.PhaseRestored, resp.Phase)
	assert.Empty(t, resp.FailedStep)
	assert.Empty(t, resp.CauseStep)
	w.assertPair(t, w.old)
	assert.Equal(t, pki.Fingerprint(w.old.Cert), w.e.Served(443, "www.example.test"))
}

// Real nginx -T loads the pair files, so a host left with a mixed pair by a killed deployment
// answers nginx-dump with an invalid configuration and refuses a NEW deployment (CONFIG_INVALID);
// nginx-restore of the interrupted operation does not need nginx -T and repairs the pair.
func TestEmulatedMixedPairIsAConfigurationError(t *testing.T) {
	w := newWorld(t)
	w.e.KillAt(helperproto.StepWriteKey)
	require.Equal(t, "KILL", w.deploy(emuOp).Signal)
	d := decode[helperproto.NginxDumpResponse](t, w.run(line(true, helperproto.SubNginxDump), nil))
	assert.False(t, d.ConfigValid)
	assert.Equal(t, helperproto.ConfigErrKeyMismatch, d.ConfigError)
	assert.Equal(t, "1.22.1", d.Version)
	assert.Empty(t, d.Servers)
	inB := input(w.other.FullchainPEM, w.other.KeyPEM)
	r := w.run(deployLineFor(emuOp2, crt, key, w.oldSHA, inB), inB)
	assert.Equal(t, helperproto.CodeConfigInvalid, codeOf(t, r))
	assert.Equal(t, "", w.e.NginxPhase(emuOp2))
	assert.Equal(t, helperproto.PhaseWriting, w.status(emuOp).Phase)
	r = w.restore(emuOp)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxRestoreResponse](t, r).Phase)
	w.assertPair(t, w.old)
	d = decode[helperproto.NginxDumpResponse](t, w.run(line(true, helperproto.SubNginxDump), nil))
	assert.True(t, d.ConfigValid)
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxDeployResponse](t, w.deploy(emuOp)).Phase, "a re-send answers from the journal")
}

// The kill switch of the nginx binary does not stop the reload (systemctl); a failing reload is
// FailReload.
func TestEmulatedNginxKilledDoesNotFailTheReload(t *testing.T) {
	w := newWorld(t)
	w.e.KillNginxAt(helperproto.StepConfigTest) // after the test passed, before the reload
	r := w.deploy(emuOp)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, helperproto.PhaseCommitted, decode[helperproto.NginxDeployResponse](t, r).Phase)
	assert.Equal(t, 1, w.e.Reloads())
	assert.Equal(t, pki.Fingerprint(w.nw.Cert), w.e.Served(443, "www.example.test"))
	assert.Equal(t, helperproto.CodeIOError, codeOf(t, w.run(line(true, helperproto.SubNginxTest), nil)), "but nginx -t is killed")
}

func TestEmulatedFaultKnobs(t *testing.T) {
	// FailJournalWrite is for the phases the helper answers an error for.
	e := NewEmulator()
	assert.Panics(t, func() { e.FailJournalWrite(helperproto.PhaseUnchanged) })
	assert.Panics(t, func() { e.FailJournalWrite(helperproto.PhaseRestored) })
	assert.NotPanics(t, func() { e.FailJournalWrite(helperproto.PhaseRestoring) }, "nginx-restore refuses when it cannot write restoring (m6)")

	// Armed transaction faults are consumed by the next transaction command, fired or not.
	w := newWorld(t)
	w.e.KillAt(helperproto.StepWriteKey)
	w.e.HangupAfter(helperproto.StepReload)
	w.e.InterfereAt(helperproto.StepBackup, crt, []byte("x"))
	w.e.FailJournalWrite(helperproto.PhaseCommitted)
	w.e.HoldLock(true)
	assert.Equal(t, helperproto.CodeBusy, codeOf(t, w.deploy(emuOp)), "a refusal before the transaction")
	w.e.HoldLock(false)
	r := w.deploy(emuOp)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, helperproto.PhaseCommitted, decode[helperproto.NginxDeployResponse](t, r).Phase, "nothing fired in the later call")
	assert.False(t, r.Hangup)
	w.assertPair(t, w.nw)

	// A kill reached inside the cleanup of a no-op operation does not crash the server: it is the
	// killed answer, with the operation and the record untouched.
	w = newWorld(t)
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	inB := input(w.other.FullchainPEM, w.other.KeyPEM)
	w.e.KillAt("pair record renamed") // B took the record and changed nothing
	require.Equal(t, "KILL", w.run(deployLineFor(emuOp2, crt, key, hexSum(w.nw.FullchainPEM), inB), inB).Signal)
	cleanup := func() Response { return w.run(line(true, helperproto.SubCleanup, "--op", emuOp2), nil) }
	w.e.KillAt("pair record staged") // handing the record back to A
	r = cleanup()
	assert.Equal(t, "KILL", r.Signal)
	assert.Equal(t, helperproto.PhasePrepared, w.e.NginxPhase(emuOp2))
	assert.Equal(t, 1, decode[helperproto.CleanupResponse](t, cleanup()).Removed, "the kill was consumed")
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxRestoreResponse](t, w.restore(emuOp)).Phase, "A is the latest again")
}

// A killed helper that ends by status 137 without a signal: nothing on stdout.
func TestEmulatedKillWithExit137(t *testing.T) {
	w := newWorld(t)
	w.e.KillAtWithExit137(helperproto.StepWriteCert)
	r := w.deploy(emuOp)
	assert.Equal(t, 137, r.Exit)
	assert.Empty(t, r.Stdout)
	assert.Empty(t, r.Signal)
	assert.Equal(t, helperproto.PhaseWriting, w.status(emuOp).Phase)
	w.e.KillAt(helperproto.StepRestore)
	assert.Equal(t, "KILL", w.restore(emuOp).Signal, "the style is not sticky")
}

func TestEmulatedToWireCleansNames(t *testing.T) {
	assert.Equal(t, "ab", clean("a\x00b\n", 10))
	assert.Equal(t, "ab", clean("a\xffb", 10))
	assert.Equal(t, "aé", clean("aéé", 3))
	assert.Equal(t, "abc", cleanRunes("abcdef", 3))
}

// KillAt after KillAtWithExit137 kills by a signal again: the style of the last call counts.
func TestEmulatedKillAtResetsTheExitStyle(t *testing.T) {
	w := newWorld(t)
	w.e.KillAtWithExit137(helperproto.StepWriteCert)
	w.e.KillAt(helperproto.StepWriteCert)
	r := w.deploy(emuOp)
	assert.Equal(t, "KILL", r.Signal)
	assert.Equal(t, 0, r.Exit)
}

// Faults armed for a subcommand wait for it: a provider's deployment runs without them and its
// inline nginx-restore takes them.
func TestEmulatedFaultsArmedForASubcommand(t *testing.T) {
	assert.Panics(t, func() { NewEmulator().ArmFaultsFor(helperproto.SubNginxStatus) })

	w := newWorld(t)
	w.e.KillAt(helperproto.StepRestore)
	w.e.ArmFaultsFor(helperproto.SubNginxRestore)
	r := w.deploy(emuOp)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, helperproto.PhaseCommitted, decode[helperproto.NginxDeployResponse](t, r).Phase, "the deployment ran without it")
	assert.Equal(t, "KILL", w.restore(emuOp).Signal, "the restore took the kill")
	assert.Equal(t, helperproto.PhaseRestoring, w.status(emuOp).Phase)
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxRestoreResponse](t, w.restore(emuOp)).Phase, "consumed")
	w.assertPair(t, w.old)

	w = newWorld(t)
	w.e.FailReload(1)
	w.e.ArmFaultsFor(helperproto.SubNginxRestore)
	require.Equal(t, helperproto.PhaseCommitted, decode[helperproto.NginxDeployResponse](t, w.deploy(emuOp)).Phase, "its reload passed")
	rr := decode[helperproto.NginxRestoreResponse](t, w.restore(emuOp))
	assert.Equal(t, helperproto.PhaseRestoreFailed, rr.Phase, "the reload failure was kept for the restore")
	assert.Equal(t, helperproto.StepRollbackReload, rr.FailedStep)
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxRestoreResponse](t, w.restore(emuOp)).Phase, "consumed")

	// FailConfigTest and FailRestoreFile wait too; "" goes back to the next command.
	w = newWorld(t)
	w.e.FailConfigTest(1)
	w.e.ArmFaultsFor(helperproto.SubNginxRestore)
	w.e.ArmFaultsFor("")
	r = w.deploy(emuOp)
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxDeployResponse](t, r).Phase)
	w = newWorld(t)
	w.e.FailRestoreFile(key)
	w.e.ArmFaultsFor(helperproto.SubNginxRestore)
	require.Equal(t, helperproto.PhaseCommitted, decode[helperproto.NginxDeployResponse](t, w.deploy(emuOp)).Phase)
	rr = decode[helperproto.NginxRestoreResponse](t, w.restore(emuOp))
	assert.Equal(t, helperproto.PhaseRestoreFailed, rr.Phase)
	assert.Equal(t, helperproto.StepRestore, rr.FailedStep)

	// Armed for the cleanup: a restore before it runs without the fault.
	w = newWorld(t)
	require.Equal(t, 0, w.deploy(emuOp).Exit)
	w.e.KillAt(helperproto.StepRestore)
	w.e.ArmFaultsFor(helperproto.SubCleanup)
	assert.Equal(t, helperproto.PhaseRestored, decode[helperproto.NginxRestoreResponse](t, w.restore(emuOp)).Phase)
}

func TestEmulatedProbeServed(t *testing.T) {
	w := newWorld(t)
	leaf, chain, ok := w.e.ProbeServed("", 443, "www.example.test", helperproto.ProbeAny)
	require.True(t, ok)
	assert.Equal(t, hexSum(w.old.Cert.Raw), leaf)
	assert.Equal(t, 2, chain, "leaf and intermediate")
	_, _, ok = w.e.ProbeServed("", 443, "www.example.test", helperproto.ProbeRSA)
	assert.False(t, ok, "an ECDSA-only site has nothing for an RSA probe")
	_, _, ok = w.e.ProbeServed("", 8443, "", helperproto.ProbeAny)
	assert.False(t, ok, "nothing listens there")

	// A listen on a specific address answers only there; another block answers elsewhere.
	other := w.ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	w.e.AddSite(NginxSite{Names: []string{"www.example.test"}, Port: 8443, Addr: "10.0.0.5", CertPath: "/etc/nginx/ssl/a.crt", KeyPath: "/etc/nginx/ssl/a.key"},
		other.FullchainPEM, other.KeyPEM)
	leaf, _, ok = w.e.ProbeServed("10.0.0.5", 8443, "www.example.test", helperproto.ProbeAny)
	require.True(t, ok)
	assert.Equal(t, hexSum(other.Cert.Raw), leaf)
	_, _, ok = w.e.ProbeServed("192.0.2.10", 8443, "www.example.test", helperproto.ProbeAny)
	assert.False(t, ok, "not at another address")
}
