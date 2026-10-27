//go:build windows

package main

// The fidelity of the CCS subcommands (W5 Task 5, R68): ccs-dump, ccs-deploy (a commit, unchanged and
// every refusal of winhelper's TestCCSDeployRefusesBeforeAnyWrite this machine can stage), iis-status,
// iis-fence and iis-restore of a CCS journal run with winhelper's own code against the real host (IIS's
// CCS at the fixture's folder, ccs_windows_test.go's newCCSReal) and against the emulator configured
// alike, with the same standard input and operation ids. The exit statuses and the answers must be
// equal field by field, message dropped, and the folder must hold the same names on both afterwards.
//
// What is normalised, because it is the machine's and not the scenario's: a dumped file's modified_at
// (the file system's clock against the model's) and its file_sha256 once each host's value is checked
// against the bytes that host holds (BuildPFX salts every write, so the two hosts' new files differ
// byte for byte while holding the same certificates). A symbolic link and a directory with a .pfx
// name are modelled with SetCCSReparse (the model has neither; both are "not a regular file" to
// ReadCCS and left out of ListCCS).

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// both runs a call on the real host and on the model and requires the same exit status and answer.
func (f *ccsReal) both(stdin []byte, args ...string) (int, map[string]any) {
	f.t.Helper()
	ro, real := execOn(f.t, f.w, stdin, args)
	mo, model := execOn(f.t, f.model.Host(), stdin, args)
	require.NotNil(f.t, real, "the real helper answers %v", args)
	if args[0] == winproto.SubCCSDump {
		f.normalizeDump(real, func(name string) ([]byte, bool) {
			b, err := os.ReadFile(f.path(name)) //nolint:gosec // the fixture's folder
			return b, err == nil
		})
		f.normalizeDump(model, f.model.CCSFile)
	}
	require.Equal(f.t, ro.Exit, mo.Exit, "exit status of %v (real %v, model %v)", args, real, model)
	require.Equal(f.t, real, model, "answer of %v", args)
	return ro.Exit, real
}

// normalizeDump checks each dumped file's file_sha256 against the bytes the host holds, then drops it
// and modified_at.
func (f *ccsReal) normalizeDump(m map[string]any, read func(string) ([]byte, bool)) {
	f.t.Helper()
	for _, file := range asList(m["files"]) {
		name := asString(file["name"])
		if sum := asString(file["file_sha256"]); sum != "" {
			data, ok := read(name)
			require.True(f.t, ok, "%s is in the folder", name)
			s := sha256.Sum256(data)
			assert.Equal(f.t, hex.EncodeToString(s[:]), sum, "file_sha256 of %s is the bytes' hash", name)
		}
		delete(file, "file_sha256")
		delete(file, "modified_at")
	}
}

// sameNames requires the folder to hold the same file names on both hosts (the real folder's regular
// files; the model's names).
func (f *ccsReal) sameNames() {
	f.t.Helper()
	entries, err := os.ReadDir(f.folder)
	require.NoError(f.t, err)
	real := []string{}
	for _, e := range entries {
		if e.Type().IsRegular() {
			real = append(real, e.Name())
		}
	}
	slices.Sort(real)
	assert.Equal(f.t, real, f.model.CCSNames(), "the folder's files")
}

func TestFidelityCCS(t *testing.T) {
	f := newCCSReal(t, portCCSFidelity, "f.alice-w5.test")
	now := time.Now()
	ca := pki.NewCA("alice-w5-fidelity", pki.ECDSA256, now)
	issue := func(cn string) pki.Leaf { return ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, now) }
	old, newer, other := issue("f.alice-w5.test"), issue("f.alice-w5.test"), winhelper.NewPFXPassword()
	oldSum, newSum := sum256hex(old.Cert.Raw), sum256hex(newer.Cert.Raw)
	t.Cleanup(func() { removeCertificate(t, "CA", thumbprint(ca.Intermediate), false) }) // import_chain adds it

	f.put("f.alice-w5.test.pfx", ccsPFX(t, old, f.password, ca.Intermediate))
	f.put("w.alice-w5.test.pfx", ccsPFX(t, issue("w.alice-w5.test"), other))
	f.put("junk.alice-w5.test.pfx", []byte("junk"))
	f.put("big.alice-w5.test.pfx", make([]byte, winproto.MaxCCSFile+1))
	f.put("bad name.pfx", []byte("x"))
	f.put("readme.txt", []byte("x"))
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "s.pfx"), ccsPFX(t, issue("s.alice-w5.test"), f.password), 0o600))
	link := f.path("s.alice-w5.test.pfx")
	t.Cleanup(func() { _ = os.Remove(link) }) // the link only, before the folder
	mklink(t, link, filepath.Join(outside, "s.pfx"))
	f.model.SetCCSReparse(link, true)
	require.NoError(t, os.Mkdir(f.path("sub.alice-w5.test.pfx"), 0o700))
	f.model.SetCCSReparse(f.path("sub.alice-w5.test.pfx"), true) // not a regular file: refused alike

	pw := []byte(`{"password":"` + string(f.password) + `"}`)
	dump := func() map[string]any {
		t.Helper()
		_, got := f.both(pw, winproto.SubCCSDump)
		return got
	}
	got := dump()
	assert.Equal(t, true, got["local"], "%v", got)
	assert.EqualValues(t, 1, got["ignored"], "bad name.pfx")
	assert.Len(t, asList(got["files"]), 4, "f, w, junk and big; not the link, the directory or readme.txt")
	_, got = f.both([]byte(`{"password":"`+string(other)+`"}`), winproto.SubCCSDump)
	assert.Equal(t, true, got["ok"], "another valid password: every file a mismatch, %v", got)
	for _, c := range []struct {
		stdin string
		args  []string
		code  string
	}{
		{`{}`, nil, winproto.CodeBadContent},
		{`{"password":"short"}`, nil, winproto.CodeInvalidArgument},
		{string(pw), []string{"x"}, winproto.CodeUsage},
	} {
		exit, got := f.both([]byte(c.stdin), append([]string{winproto.SubCCSDump}, c.args...)...)
		assert.Equal(t, 2, exit)
		assert.Equal(t, c.code, got["code"], "%s %v", c.stdin, c.args)
	}

	deploy := func(op, host string, leaf pki.Leaf, expect string) (int, map[string]any) {
		t.Helper()
		return f.both(f.ccsInput(host, leaf, expect), winproto.SubCCSDeploy, winproto.ArgOp, op)
	}
	_, got = deploy(op1, "f.alice-w5.test", newer, oldSum)
	assertPhase(t, got, winproto.PhaseCommitted)
	assert.Equal(t, newSum, got["new_sha256"])
	assert.Equal(t, oldSum, got["previous_sha256"])
	f.sameNames()
	dump()
	_, got = deploy(op2, "f.alice-w5.test", newer, newSum)
	assertPhase(t, got, winproto.PhaseUnchanged)

	// Every refusal the machine can stage, each answered before any write.
	setReg := func(enabled bool, path string) func() {
		return func() {
			setCCSRegistry(t, enabled, path)
			f.model.SetCCS(enabled, path)
		}
	}
	restore := setReg(true, f.folder)
	another := issue("f.alice-w5.test")
	for _, c := range []struct {
		name   string
		host   string
		expect string
		edit   func(*winproto.CCSDeployInput)
		raw    string
		args   []string
		setup  func()
		exit   int
		code   string
	}{
		{name: "CCS disabled", setup: setReg(false, f.folder), exit: 3, code: winproto.CodeCCSDisabled},
		{name: "a UNC registry path", setup: setReg(true, `\\alice-w5-fs.invalid\certs`), exit: 3, code: winproto.CodeCCSPathUnsupported},
		{name: "another folder", edit: func(in *winproto.CCSDeployInput) { in.Path = `C:\alice-w5-other` }, exit: 3, code: winproto.CodeCCSPathChanged},
		{name: "an absent file", host: "none.alice-w5.test", exit: 3, code: winproto.CodeCCSFileNotFound},
		{name: "another password", edit: func(in *winproto.CCSDeployInput) { in.Password = string(other) }, exit: 3,
			code: winproto.CodeCCSPasswordMismatch},
		{name: "a file of another password", host: "w.alice-w5.test", exit: 3, code: winproto.CodeCCSPasswordMismatch},
		{name: "another leaf", expect: sum256hex([]byte("x")), exit: 3, code: winproto.CodeHashMismatch},
		{name: "not a PFX", host: "junk.alice-w5.test", exit: 3, code: winproto.CodeHashMismatch},
		{name: "a file past the bound", host: "big.alice-w5.test", exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a symbolic link", host: "s.alice-w5.test", exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a directory", host: "sub.alice-w5.test", exit: 2, code: winproto.CodeInvalidArgument},
		{name: `a host a\b`, host: `a\b`, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a host ..", host: "..", exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a host with a colon", host: "f.alice-w5.test:x", exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a host with a percent sign", host: "f%2e.alice-w5.test", exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a host with a NUL", host: "f\x00.alice-w5.test", exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a relative input path", edit: func(in *winproto.CCSDeployInput) { in.Path = `CCS` }, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a short password", edit: func(in *winproto.CCSDeployInput) { in.Password = string(f.password[:11]) }, exit: 2,
			code: winproto.CodeInvalidArgument},
		{name: "the absent marker", expect: "absent", exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a forbidden list that is not hashes", edit: func(in *winproto.CCSDeployInput) { in.ForbiddenLeaf = []string{"x"} }, exit: 2,
			code: winproto.CodeInvalidArgument},
		{name: "not a chain", edit: func(in *winproto.CCSDeployInput) { in.ChainPEM = "x" }, exit: 2, code: winproto.CodeBadContent},
		{name: "an unknown member", raw: `{"path":"x","extra":1}`, exit: 2, code: winproto.CodeBadContent},
		{name: "a member twice", raw: `{"path":"x","path":"x"}`, exit: 2, code: winproto.CodeBadContent},
		{name: "a member missing", raw: `{"path":"C:\\CCS"}`, exit: 2, code: winproto.CodeBadContent},
		{name: "not an object", raw: `[]`, exit: 2, code: winproto.CodeBadContent},
		{name: "trailing data", raw: `{} {}`, exit: 2, code: winproto.CodeBadContent},
		{name: "a known operation", args: []string{winproto.ArgOp, op1}, exit: 3, code: winproto.CodeOperationExists},
		{name: "a fenced operation", args: []string{winproto.ArgOp, op6}, setup: func() {
			_, got := f.both(nil, winproto.SubIISFence, winproto.ArgOp, op6)
			assertPhase(t, got, winproto.PhaseFenced)
		}, exit: 3, code: winproto.CodeFenced},
		{name: "no operation", args: []string{}, exit: 2, code: winproto.CodeUsage},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.setup != nil {
				c.setup()
				t.Cleanup(restore)
			}
			host, expect := c.host, c.expect
			if host == "" {
				host = "f.alice-w5.test"
			}
			if expect == "" {
				expect = newSum
			}
			in := []byte(c.raw)
			if c.raw == "" {
				edits := []func(*winproto.CCSDeployInput){}
				if c.edit != nil {
					edits = append(edits, c.edit)
				}
				in = f.ccsInput(host, another, expect, edits...)
			}
			args := []string{winproto.ArgOp, op3}
			if c.args != nil {
				args = c.args
			}
			exit, got := f.both(in, append([]string{winproto.SubCCSDeploy}, args...)...)
			assert.Equal(t, c.exit, exit, "%v", got)
			assert.Equal(t, c.code, got["code"], "%v", got)
			if c.setup != nil {
				dump() // the registry's state as both hosts read it
				// Back to the fixture's folder before the names are compared: the model lists the
				// folder the registry names now (run 1: the UNC row compared the model's empty one).
				restore()
			}
			f.sameNames()
		})
	}

	// The journal of op1: its status, its restore to the backup, and the status after.
	_, got = f.both(nil, winproto.SubIISStatus, winproto.ArgOp, op1)
	assertPhase(t, got, winproto.PhaseCommitted)
	assert.Equal(t, newSum, got["current_cert_sha256"])
	_, got = f.both(restoreInput(t), winproto.SubIISRestore, winproto.ArgOp, op1)
	assertPhase(t, got, winproto.PhaseRestored)
	_, got = f.both(nil, winproto.SubIISStatus, winproto.ArgOp, op1)
	assertPhase(t, got, winproto.PhaseRestored)
	assert.Equal(t, oldSum, got["current_cert_sha256"])
	f.sameNames()
	dump()
}
