package winhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

const ccsFolder = `C:\CCS`

func ccsInput(pw []byte) []byte { return []byte(`{"password":"` + string(pw) + `"}`) }

func ccsDump(t *testing.T, h *fakeWriteHost, in []byte, args ...string) (Outcome, winproto.CCSDumpResponse, []byte) {
	t.Helper()
	o, out := execute(t, context.Background(), h, bytes.NewReader(in), append([]string{winproto.SubCCSDump}, args...)...)
	var r winproto.CCSDumpResponse
	if o.Exit == 0 {
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatal(err)
		}
	}
	return o, r, out
}

func lowerCCSBudget(t *testing.T, d time.Duration) {
	t.Helper()
	old := ccsDumpBudget
	ccsDumpBudget = d
	t.Cleanup(func() { ccsDumpBudget = old })
}

// tick advances the fake's clock by d.
func (f *fakeWriteHost) tick(d time.Duration) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.now.IsZero() {
		f.now = testNow
	}
	f.now = f.now.Add(d)
}

func TestCCSDump(t *testing.T) {
	ca := pki.NewCA("CCS Dump", pki.ECDSA256, testNow)
	l := ca.Issue(pki.Opts{CommonName: "a.example.test", SANs: []string{"a.example.test"}}, testNow)
	pw, otherPW := NewPFXPassword(), NewPFXPassword()
	alice, err := BuildPFX(l.Cert.Raw, pkcs8Of(t, l), pw, ca.Intermediate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := BuildPFX(l.Cert.Raw, pkcs8Of(t, l), otherPW)
	if err != nil {
		t.Fatal(err)
	}
	junk := []byte("not a pfx")
	many := map[string][]byte{}
	for i := range winproto.MaxCCSFiles + 1 {
		many["h"+strconv.Itoa(i)+".example.test.pfx"] = junk
	}
	stamp := testNow.Format(time.RFC3339)

	for _, c := range []struct {
		name  string
		setup func(t *testing.T, h *fakeWriteHost)
		check func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse)
	}{
		{"disabled", func(*testing.T, *fakeWriteHost) {}, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if r.Enabled || r.Local || r.Files == nil || len(r.Files) != 0 || h.ccsLists != 0 {
				t.Fatalf("%+v lists=%d", r, h.ccsLists)
			}
		}},
		{"UNC path", func(_ *testing.T, h *fakeWriteHost) { h.setCCS(`\\fs\certs`, nil) }, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if !r.Enabled || r.Local || r.Path != `\\fs\certs` || len(r.Files) != 0 || h.ccsLists != 0 {
				t.Fatalf("%+v lists=%d", r, h.ccsLists)
			}
		}},
		{"folder is a reparse point", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, nil)
			h.ccsListErr = ErrCCSFolderUnsupported
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if !r.Enabled || r.Local || r.Path != ccsFolder || len(r.Files) != 0 {
				t.Fatalf("%+v", r)
			}
		}},
		{"three files", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": alice, "B.Example.Test.pfx": foreign, "x.pfx.bak": alice})
		}, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if !r.Enabled || !r.Local || r.Path != ccsFolder || len(r.Files) != 2 || r.Ignored != 0 || r.Truncated {
				t.Fatalf("%+v", r)
			}
			a, b := r.Files[1], r.Files[0] // sorted by name: "B.Example..." < "a.example..."
			if a.Name != "a.example.test.pfx" || a.Host != "a.example.test" || a.Problem != "" || a.LeafDER != b64(l.Cert.Raw) ||
				len(a.Chain) != 1 || a.Chain[0] != b64(ca.Intermediate.Raw) || a.FileSHA256 != hexSHA256(alice) ||
				a.Size != int64(len(alice)) || a.ModifiedAt != stamp {
				t.Fatalf("alice's file: %+v", a)
			}
			if b.Host != "b.example.test" || b.Problem != winproto.CCSProblemPasswordMismatch || b.LeafDER != "" ||
				b.Chain == nil || len(b.Chain) != 0 || b.FileSHA256 != hexSHA256(foreign) {
				t.Fatalf("the other password's file: %+v", b)
			}
			if strings.Join(h.ccsReads, ",") != "B.Example.Test.pfx,a.example.test.pfx" {
				t.Fatalf("reads %v", h.ccsReads)
			}
		}},
		{"a name without a valid host", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"not a host.pfx": junk, "_.example.test.pfx": junk})
		}, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if r.Ignored != 1 || len(r.Files) != 1 || r.Files[0].Host != "*.example.test" || r.Files[0].Problem != winproto.CCSProblemNotPFX ||
				r.Truncated || len(h.ccsReads) != 1 {
				t.Fatalf("%+v reads=%v", r, h.ccsReads)
			}
		}},
		{"501 files", func(_ *testing.T, h *fakeWriteHost) { h.setCCS(ccsFolder, many) }, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != winproto.MaxCCSFiles || !r.Truncated {
				t.Fatalf("%d %v", len(r.Files), r.Truncated)
			}
		}},
		{"a 257 KiB file", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"big.example.test.pfx": make([]byte, 257<<10)})
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 1 || r.Files[0].Problem != winproto.CCSProblemTooLarge || r.Files[0].Size != 257<<10 ||
				r.Files[0].FileSHA256 != "" || r.Files[0].LeafDER != "" || r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
		{"the budget ends after 2 files", func(t *testing.T, h *fakeWriteHost) {
			lowerCCSBudget(t, 2*time.Second)
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": junk, "b.example.test.pfx": junk, "c.example.test.pfx": junk})
			h.ccsReadFn = func(string) error { h.tick(time.Second); return nil }
		}, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 2 || !r.Truncated || len(h.ccsReads) != 2 {
				t.Fatalf("%d %v %v", len(r.Files), r.Truncated, h.ccsReads)
			}
		}},
		{"an unreadable file is dropped", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": junk, "b.example.test.pfx": junk})
			h.ccsReadFn = func(name string) error {
				if name == "a.example.test.pfx" {
					return errors.New("access denied")
				}
				return nil
			}
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 1 || r.Files[0].Name != "b.example.test.pfx" || !r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
		{"a file that vanished is skipped", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": junk})
			h.ccsReadFn = func(name string) error {
				h.wmu.Lock()
				defer h.wmu.Unlock()
				delete(h.ccsFiles, name)
				return nil
			}
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 0 || r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
		{"a chain past the bounds is dropped", func(t *testing.T, h *fakeWriteHost) {
			long, err := BuildPFX(l.Cert.Raw, pkcs8Of(t, l), pw, slices.Repeat([][]byte{ca.Intermediate.Raw}, winproto.MaxChainCerts+1)...)
			if err != nil {
				t.Fatal(err)
			}
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": long})
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 0 || !r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
		{"a file the host cannot open is dropped", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": junk})
			h.ccsOpenErr = func([]byte) error { return errors.New("crypt32") }
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 0 || !r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newWriteHost()
			c.setup(t, h)
			o, r, out := ccsDump(t, h, ccsInput(pw))
			if o.Exit != 0 || !r.OK {
				t.Fatalf("%+v %s", o, out)
			}
			if bytes.Contains(out, pw) {
				t.Fatal("the password is in the answer")
			}
			c.check(t, h, r)
		})
	}
}

func TestCCSDumpRefusals(t *testing.T) {
	pw := NewPFXPassword()
	for _, c := range []struct {
		name  string
		in    []byte
		args  []string
		setup func(h *fakeWriteHost)
		exit  int
		code  string
	}{
		{"not elevated", ccsInput(pw), nil, func(h *fakeWriteHost) { h.elevated = false }, winproto.ExitRefused, winproto.CodeNotElevated},
		{"an argument", ccsInput(pw), []string{"x"}, nil, winproto.ExitRefused, winproto.CodeUsage},
		{"11 characters", ccsInput(pw[:11]), nil, nil, winproto.ExitRefused, winproto.CodeInvalidArgument},
		{"a space", ccsInput(append([]byte("with space "), pw...)), nil, nil, winproto.ExitRefused, winproto.CodeInvalidArgument},
		{"an unknown member", []byte(`{"password":"` + string(pw) + `","path":"C:\\x"}`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"a duplicate member", []byte(`{"password":"` + string(pw) + `","password":"` + string(pw) + `"}`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"no member", []byte(`{}`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"not an object", []byte(`["x"]`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"not a string", []byte(`{"password":12}`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"trailing data", append(ccsInput(pw), []byte(" {}")...), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"4 KiB + 1", append(ccsInput(pw), bytes.Repeat([]byte(" "), winproto.MaxCCSDumpInput+1-len(ccsInput(pw)))...), nil, nil,
			winproto.ExitRefused, winproto.CodeTooLarge},
		{"an unreadable registry", ccsInput(pw), nil, func(h *fakeWriteHost) { h.ccsConfigErr = errors.New("registry") }, winproto.ExitFailed, winproto.CodeIOError},
		{"an unreadable folder", ccsInput(pw), nil, func(h *fakeWriteHost) {
			h.setCCS(ccsFolder, nil)
			h.ccsListErr = errors.New("access denied")
		}, winproto.ExitFailed, winproto.CodeIOError},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newWriteHost()
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": []byte("x")})
			if c.setup != nil {
				c.setup(h)
			}
			o, _, out := ccsDump(t, h, c.in, c.args...)
			wantError(t, o.Exit, out, c.exit, c.code)
			if len(h.ccsReads) != 0 || bytes.Contains(out, pw[:11]) {
				t.Fatalf("reads %v, answer %s", h.ccsReads, out)
			}
		})
	}
	// The JSON escapes of a valid password decode (the strict parser is a JSON parser).
	h := newWriteHost()
	if o, r, out := ccsDump(t, h, []byte(` { "password" : "\u0041`+string(pw[1:])+`" } `)); o.Exit != 0 || r.Enabled {
		t.Fatalf("%+v %s", o, out)
	}
}

func TestCCSDumpClearsThePassword(t *testing.T) {
	ca := pki.NewCA("CCS Clear", pki.ECDSA256, testNow)
	l := ca.Issue(leafOpts, testNow)
	pw := NewPFXPassword()
	pfx, err := BuildPFX(l.Cert.Raw, pkcs8Of(t, l), pw)
	if err != nil {
		t.Fatal(err)
	}
	h := newWriteHost()
	h.setCCS(ccsFolder, map[string][]byte{"www.example.test.pfx": pfx, "b.example.test.pfx": pfx})
	o, r, out := ccsDump(t, h, ccsInput(pw))
	if o.Exit != 0 || len(r.Files) != 2 || r.Files[0].Problem != "" || r.Files[1].Problem != "" {
		t.Fatalf("%+v %s", o, out)
	}
	if len(h.ccsPasswords) != 2 {
		t.Fatalf("%d", len(h.ccsPasswords))
	}
	for _, p := range h.ccsPasswords {
		if len(p) != len(pw) || !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatalf("the password buffer was not cleared: %d bytes", len(p))
		}
	}
}

// TestCCSDumpHostProblemsAndIgnored: a problem the host answers outside winproto.CCSProblem* is an
// error for that file (dropped, Truncated), and Ignored counts every host-less name, after the cut too.
func TestCCSDumpHostProblemsAndIgnored(t *testing.T) {
	pw := NewPFXPassword()
	h := newWriteHost()
	h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": []byte("x")})
	h.ccsProblem = "the host's own words"
	if o, r, out := ccsDump(t, h, ccsInput(pw)); o.Exit != 0 || len(r.Files) != 0 || !r.Truncated || bytes.Contains(out, []byte("own words")) {
		t.Fatalf("%+v %s", o, out)
	}
	h.ccsProblem = winproto.CCSProblemNoKey
	if _, r, out := ccsDump(t, h, ccsInput(pw)); len(r.Files) != 1 || r.Files[0].Problem != winproto.CCSProblemNoKey || r.Truncated {
		t.Fatalf("%s", out)
	}

	// A file ReadCCS refuses as a reparse point or not a regular file is not listed, and the list is
	// whole (W5 ruling W5-7).
	h = newWriteHost()
	h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": []byte("x"), "b.example.test.pfx": []byte("x")})
	h.ccsReadFn = func(name string) error {
		if name == "a.example.test.pfx" {
			return fmt.Errorf("wrapped: %w", ErrCCSFileUnsupported)
		}
		return nil
	}
	if _, r, out := ccsDump(t, h, ccsInput(pw)); len(r.Files) != 1 || r.Files[0].Name != "b.example.test.pfx" || r.Truncated {
		t.Fatalf("%s", out)
	}

	files := map[string][]byte{"zz bad.pfx": nil, "zz worse.pfx": nil, "_bad.pfx": nil}
	for i := range winproto.MaxCCSFiles + 1 {
		files["h"+strconv.Itoa(i)+".example.test.pfx"] = []byte("x")
	}
	h = newWriteHost()
	h.setCCS(ccsFolder, files)
	if _, r, out := ccsDump(t, h, ccsInput(pw)); len(r.Files) != winproto.MaxCCSFiles || !r.Truncated || r.Ignored != 3 {
		t.Fatalf("files %d truncated %v ignored %d: %.200s", len(r.Files), r.Truncated, r.Ignored, out)
	}
}

const (
	ccsHost = "www.example.test"
	ccsName = "www.example.test.pfx"
	ccsKey  = "ccs/" + ccsName
)

// ccsFixture is the W2 fixture (its CA, previous and new leaves) with a CCS folder C:\CCS holding
// www.example.test.pfx: the previous leaf and the CA's intermediate under the password pw.
type ccsFixture struct {
	*fixture
	pw     []byte
	oldPFX []byte
}

func newCCSFixture(t *testing.T) *ccsFixture {
	t.Helper()
	f := &ccsFixture{fixture: newFixture(t), pw: NewPFXPassword()}
	f.oldPFX = f.pfx(f.old, f.ca.Intermediate.Raw)
	f.h.setCCS(ccsFolder, map[string][]byte{ccsName: f.oldPFX})
	return f
}

func (f *ccsFixture) pfx(l pki.Leaf, intermediates ...[]byte) []byte {
	f.t.Helper()
	b, err := BuildPFX(l.Cert.Raw, pkcs8Of(f.t, l), f.pw, intermediates...)
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *ccsFixture) in(edit ...func(*winproto.CCSDeployInput)) []byte {
	in := winproto.CCSDeployInput{Path: ccsFolder, Host: ccsHost, ExpectSHA256: f.oldSHA256, ChainPEM: string(f.nw.FullchainPEM),
		KeyPEM: string(f.nw.KeyPEM), Password: string(f.pw), ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}}
	for _, e := range edit {
		e(&in)
	}
	raw, err := json.Marshal(in)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// deployOn runs ccs-deploy on h (f.h or a wrapper of it).
func (f *ccsFixture) deployOn(h WriteHost, op string, in []byte) (Outcome, winproto.DeployResponse, []byte) {
	f.t.Helper()
	o, out := execute(f.t, context.Background(), h, bytes.NewReader(in), winproto.SubCCSDeploy, winproto.ArgOp, op)
	var r winproto.DeployResponse
	if o.Exit == 0 {
		if err := json.Unmarshal(out, &r); err != nil {
			f.t.Fatal(err)
		}
	}
	return o, r, out
}

func (f *ccsFixture) ccsDeploy(op string, in []byte) (Outcome, winproto.DeployResponse, []byte) {
	f.t.Helper()
	return f.deployOn(f.h, op, in)
}

func (f *ccsFixture) ccsCommitted(op string, in []byte) {
	f.t.Helper()
	if o, r, out := f.ccsDeploy(op, in); o.Exit != 0 || r.Phase != winproto.PhaseCommitted {
		f.t.Fatalf("ccs-deploy %s: %+v %s", op, o, out)
	}
}

// file is a file of the fake CCS folder.
func (f *ccsFixture) file(name string) ([]byte, bool) {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	c, ok := f.h.ccsFiles[name]
	return c.data, ok
}

func (f *ccsFixture) setFile(name string, data []byte) {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	f.h.ccsFiles[name] = fakeCCSFile{data: data, mod: testNow}
}

// names are the fake CCS folder's file names, sorted.
func (f *ccsFixture) names() []string {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	out := []string{}
	for n := range f.h.ccsFiles {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

func ccsBackup(op string) string { return ccsName + ".alice-" + op[len(op)-8:] + ".bak" }
func ccsTemp(op string) string   { return ".alice-" + op + ".tmp" }

// holds reports that the fake's file opens with pw to leaf and exactly the intermediates.
func (f *ccsFixture) holds(name string, leaf []byte, intermediates ...[]byte) bool {
	data, ok := f.file(name)
	if !ok {
		return false
	}
	l, chain, err := pki.OpenPFX(data, f.pw)
	return err == nil && bytes.Equal(l, leaf) && slices.EqualFunc(chain, intermediates, bytes.Equal)
}

func TestCCSDeployCommits(t *testing.T) {
	f := newCCSFixture(t)
	f.reset()
	o, r, out := f.ccsDeploy(op1, f.in())
	if o.Exit != 0 || r.Phase != winproto.PhaseCommitted || r.NewSHA256 != f.newSHA256 || r.NewSHA1 != f.newSHA1 ||
		r.PreviousSHA256 != f.oldSHA256 || r.PreviousSHA1 != f.oldSHA1 || r.Store != "" || r.AliceImported || r.FailedStep != "" ||
		!reflect.DeepEqual(r.Steps, []winproto.Step{ok(winproto.StepImportChain), ok(winproto.StepWriteFile)}) {
		t.Fatalf("%+v %s", o, out)
	}
	if !f.holds(ccsName, f.nw.Cert.Raw, f.ca.Intermediate.Raw) {
		t.Fatal("the file does not hold the new leaf and its intermediate")
	}
	if bak, _ := f.file(ccsBackup(op1)); !bytes.Equal(bak, f.oldPFX) {
		t.Fatal("the backup does not hold the old bytes")
	}
	if names := f.names(); !slices.Equal(names, []string{ccsName, ccsBackup(op1)}) {
		t.Fatalf("folder %v", names)
	}
	data, _ := f.file(ccsName)
	j := f.journal(op1)
	want := ccsJournal{Path: ccsFolder, File: ccsName, Host: ccsHost, Backup: ccsBackup(op1), Temp: ccsTemp(op1),
		PreviousFileSHA256: hexSHA256(f.oldPFX), NewFileSHA256: hexSHA256(data), PreviousSPKISHA256: f.oldSPKI}
	if j.Phase != winproto.PhaseCommitted || j.Kind != winproto.JournalKindCCS || j.CCS == nil || *j.CCS != want ||
		j.Binding != ccsKey || j.Store != "" || len(j.Intermediates) != 1 {
		t.Fatalf("%+v %+v", j, j.CCS)
	}
	if got := f.phases(op1); !slices.Equal(got, []string{winproto.PhasePrepared, winproto.PhaseWriting, winproto.PhaseCommitted}) {
		t.Fatalf("phases %v", got)
	}
	if rec, err := readBindingRecord(f.h, ccsKey); err != nil || rec != op1 {
		t.Fatalf("file record %q %v", rec, err)
	}
	wantText := "ccs file " + ccsName + " sha256 " + f.oldSHA256 + " -> " + f.newSHA256 + " op " + op1
	if len(f.h.events) != 1 || f.h.events[0].id != 1004 || f.h.events[0].text != wantText {
		t.Fatalf("%+v", f.h.events)
	}
	var machine []string
	for _, w := range f.h.writes() {
		if !strings.HasPrefix(w, "state ") {
			machine = append(machine, w)
		}
	}
	if !slices.Equal(machine, []string{"intermediate " + f.interSHA1, "ccs-write " + ccsTemp(op1), "ccs-replace " + ccsName, "ccs-refresh",
		"event 1004"}) || r.CCSRefreshFailed || bytes.Contains(out, []byte("ccs_refresh_failed")) {
		t.Fatalf("%v", machine)
	}
	// The answer and the event carry no secret.
	for _, b := range [][]byte{out, []byte(wantText)} {
		if bytes.Contains(b, f.pw) || bytes.Contains(b, []byte("PRIVATE KEY")) || bytes.Contains(b, []byte("BEGIN")) {
			t.Fatal("a secret is in the answer or the event")
		}
	}
	// A re-sent operation is refused; another case and a trailing backslash name the same folder.
	o, _, out = f.ccsDeploy(op1, f.in())
	wantError(t, o.Exit, out, winproto.ExitPrecondition, winproto.CodeOperationExists)
	o, r, out = f.ccsDeploy(op2, f.in(func(in *winproto.CCSDeployInput) { in.Path, in.ExpectSHA256 = `c:\ccs\`, f.newSHA256 }))
	if o.Exit != 0 || r.Phase != winproto.PhaseUnchanged {
		t.Fatalf("%+v %s", o, out)
	}
}

func TestCCSDeployUnchanged(t *testing.T) {
	f := newCCSFixture(t)
	f.setFile(ccsName, f.pfx(f.nw, f.ca.Intermediate.Raw))
	f.reset()
	o, r, out := f.ccsDeploy(op1, f.in(func(in *winproto.CCSDeployInput) { in.ExpectSHA256 = f.newSHA256 }))
	if o.Exit != 0 || r.Phase != winproto.PhaseUnchanged || r.NewSHA256 != f.newSHA256 || len(r.Steps) != 0 || len(f.h.writes()) != 0 {
		t.Fatalf("%+v %s %v", o, out, f.h.writes())
	}
	// The same leaf with another chain (the file has no intermediate) is written.
	f.setFile(ccsName, f.pfx(f.nw))
	f.ccsCommitted(op2, f.in(func(in *winproto.CCSDeployInput) { in.ExpectSHA256 = f.newSHA256 }))
	if !f.holds(ccsName, f.nw.Cert.Raw, f.ca.Intermediate.Raw) {
		t.Fatal("not written")
	}
}

// TestCCSDeployRefusesBeforeAnyWrite is Review Focus 1: every refusal leaves the write log empty.
func TestCCSDeployRefusesBeforeAnyWrite(t *testing.T) {
	other := NewPFXPassword()
	for _, c := range []struct {
		name  string
		setup func(f *ccsFixture)
		edit  func(*winproto.CCSDeployInput)
		raw   string // the input instead of f.in()
		args  []string
		exit  int
		code  string
	}{
		{name: "CCS disabled", setup: func(f *ccsFixture) { f.h.ccsEnabled = false }, exit: 3, code: winproto.CodeCCSDisabled},
		{name: "another folder", edit: func(in *winproto.CCSDeployInput) { in.Path = `C:\Other` }, exit: 3, code: winproto.CodeCCSPathChanged},
		{name: "a UNC registry path", setup: func(f *ccsFixture) { f.h.ccsPath = `\\fs\certs` }, exit: 3, code: winproto.CodeCCSPathUnsupported},
		{name: "a relative registry path", setup: func(f *ccsFixture) { f.h.ccsPath = `CCS` }, exit: 3, code: winproto.CodeCCSPathUnsupported},
		{name: "the folder is a reparse point", setup: func(f *ccsFixture) { f.h.ccsListErr = ErrCCSFolderUnsupported }, exit: 3,
			code: winproto.CodeCCSPathUnsupported},
		{name: "the folder cannot be listed", setup: func(f *ccsFixture) { f.h.ccsListErr = errors.New("denied") }, exit: winproto.ExitFailed,
			code: winproto.CodeIOError},
		{name: "the registry cannot be read", setup: func(f *ccsFixture) { f.h.ccsConfigErr = errors.New("registry") }, exit: winproto.ExitFailed,
			code: winproto.CodeIOError},
		{name: "an absent file", setup: func(f *ccsFixture) { delete(f.h.ccsFiles, ccsName) }, exit: 3, code: winproto.CodeCCSFileNotFound},
		{name: "an unreadable file", setup: func(f *ccsFixture) { f.h.ccsReadFn = func(string) error { return errors.New("denied") } },
			exit: winproto.ExitFailed, code: winproto.CodeIOError},
		{name: "the file is a reparse point", setup: func(f *ccsFixture) { f.h.ccsReadFn = func(string) error { return ErrCCSFileUnsupported } },
			exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a file past the bound", setup: func(f *ccsFixture) { f.setFile(ccsName, make([]byte, winproto.MaxCCSFile+1)) },
			exit: 2, code: winproto.CodeInvalidArgument},
		{name: "the host cannot open the file", setup: func(f *ccsFixture) { f.h.ccsOpenErr = func([]byte) error { return errors.New("crypt32") } },
			exit: winproto.ExitFailed, code: winproto.CodeIOError},
		{name: "another password", edit: func(in *winproto.CCSDeployInput) { in.Password = string(other) }, exit: 3,
			code: winproto.CodeCCSPasswordMismatch},
		{name: "another leaf", edit: func(in *winproto.CCSDeployInput) { in.ExpectSHA256 = s256a }, exit: 3, code: winproto.CodeHashMismatch},
		{name: "not a PFX", setup: func(f *ccsFixture) { f.setFile(ccsName, []byte("junk")) }, exit: 3, code: winproto.CodeHashMismatch},
		{name: "a host problem outside the list", setup: func(f *ccsFixture) { f.h.ccsProblem = "odd" }, exit: winproto.ExitFailed, code: winproto.CodeIOError},
		{name: `a host a\b`, edit: func(in *winproto.CCSDeployInput) { in.Host = `a\b` }, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a host ..", edit: func(in *winproto.CCSDeployInput) { in.Host = ".." }, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a host with a colon", edit: func(in *winproto.CCSDeployInput) { in.Host = "www.example.test:x" }, exit: 2,
			code: winproto.CodeInvalidArgument},
		{name: "a host with a percent sign", edit: func(in *winproto.CCSDeployInput) { in.Host = "www%2e.example.test" }, exit: 2,
			code: winproto.CodeInvalidArgument},
		{name: "a host with a NUL", edit: func(in *winproto.CCSDeployInput) { in.Host = "www\x00.example.test" }, exit: 2,
			code: winproto.CodeInvalidArgument},
		{name: "a relative input path", edit: func(in *winproto.CCSDeployInput) { in.Path = `CCS` }, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "a short password", edit: func(in *winproto.CCSDeployInput) { in.Password = string(other[:11]) }, exit: 2,
			code: winproto.CodeInvalidArgument},
		{name: "the absent marker", edit: func(in *winproto.CCSDeployInput) { in.ExpectSHA256 = "absent" }, exit: 2,
			code: winproto.CodeInvalidArgument},
		{name: "a forbidden list that is not hashes", edit: func(in *winproto.CCSDeployInput) { in.ForbiddenLeaf = []string{"x"} }, exit: 2,
			code: winproto.CodeInvalidArgument},
		{name: "not a chain", edit: func(in *winproto.CCSDeployInput) { in.ChainPEM = "x" }, exit: 2, code: winproto.CodeBadContent},
		{name: "an unknown member", raw: `{"path":"x","extra":1}`, exit: 2, code: winproto.CodeBadContent},
		{name: "a member twice", raw: `{"path":"x","path":"x"}`, exit: 2, code: winproto.CodeBadContent},
		{name: "a member missing", raw: `{"path":"C:\\CCS"}`, exit: 2, code: winproto.CodeBadContent},
		{name: "not an object", raw: `[]`, exit: 2, code: winproto.CodeBadContent},
		{name: "a list that is not strings", raw: `{"forbidden_leaf_sha256":[1]}`, exit: 2, code: winproto.CodeBadContent},
		{name: "a string that is not one", raw: `{"host":1}`, exit: 2, code: winproto.CodeBadContent},
		{name: "trailing data", raw: `{} {}`, exit: 2, code: winproto.CodeBadContent},
		{name: "a known operation", setup: func(f *ccsFixture) { mustWrite(f.t, f.h, sampleJournal(op1)) }, exit: 3,
			code: winproto.CodeOperationExists},
		{name: "a fenced operation", setup: func(f *ccsFixture) { mustWrite(f.t, f.h, journal{Op: op1, Phase: winproto.PhaseFenced}) },
			exit: 3, code: winproto.CodeFenced},
		{name: "an unreadable journal", setup: func(f *ccsFixture) { f.h.state[journalName(op1)] = []byte("{") }, exit: winproto.ExitFailed,
			code: winproto.CodeIOError},
		{name: "an interrupted operation on the file", setup: func(f *ccsFixture) {
			j := sampleJournal(op2)
			j.Phase = winproto.PhaseWriting
			mustWrite(f.t, f.h, j)
			if err := writeBindingRecord(f.h, ccsKey, op2); err != nil {
				f.t.Fatal(err)
			}
		}, exit: 3, code: winproto.CodeRecoveryPending},
		{name: "an unreadable file record", setup: func(f *ccsFixture) { f.h.state[bindingRecordName(ccsKey)] = []byte("{") }, exit: winproto.ExitFailed,
			code: winproto.CodeIOError},
		{name: "not elevated", setup: func(f *ccsFixture) { f.h.elevated = false }, exit: 2, code: winproto.CodeNotElevated},
		{name: "lock held", setup: func(f *ccsFixture) { f.h.lockHeld = true }, exit: winproto.ExitFailed, code: winproto.CodeBusy},
		{name: "no operation", args: []string{}, exit: 2, code: winproto.CodeUsage},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newCCSFixture(t)
			if c.setup != nil {
				c.setup(f)
			}
			in := f.in()
			if c.edit != nil {
				in = f.in(c.edit)
			}
			if c.raw != "" {
				in = []byte(c.raw)
			}
			args := []string{winproto.ArgOp, op1}
			if c.args != nil {
				args = c.args
			}
			f.reset()
			o, out := execute(t, context.Background(), f.h, bytes.NewReader(in), append([]string{winproto.SubCCSDeploy}, args...)...)
			wantError(t, o.Exit, out, c.exit, c.code)
			if w := f.h.writes(); len(w) != 0 {
				t.Fatalf("writes %v", w)
			}
			if bytes.Contains(out, f.pw) || bytes.Contains(out, other) {
				t.Fatal("a password is in the answer")
			}
		})
	}
}

// TestCCSPlainName: a derived name with ":" (an NTFS alternate data stream) or a path separator is
// never joined to the folder.
func TestCCSPlainName(t *testing.T) {
	for name, want := range map[string]bool{"a.example.test.pfx": true, "a:b.pfx": false, `a\b.pfx`: false, "a/b.pfx": false, "": false} {
		if plainName(name) != want {
			t.Errorf("%q", name)
		}
	}
}

// partialReplace is ReplaceFileW's ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: the file went to the backup
// name, the replacement did not move.
type partialReplace struct{ *fakeWriteHost }

func (p partialReplace) ReplaceCCS(_ context.Context, _, name, _, backupName string) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.ccsFiles[backupName] = p.ccsFiles[name]
	delete(p.ccsFiles, name)
	p.log = append(p.log, "ccs-replace-partial "+name)
	return errors.New("unable to move the replacement")
}

// failMove is a host whose MoveFileEx of the backup fails.
type failMove struct{ *fakeWriteHost }

func (failMove) RestoreCCS(context.Context, string, string, string) error {
	return errors.New("denied")
}

// TestCCSRefresh is ruling W5-10: the ccs records are refreshed after the replace, after a
// self-restore and after an iis-restore (also one that finds the file put back already); a failed
// refresh is answered, never a rollback by itself.
func TestCCSRefresh(t *testing.T) {
	after := func(t *testing.T, log []string, what string) {
		t.Helper()
		i := slices.Index(log, what)
		if i < 0 || !slices.Contains(log[i:], "ccs-refresh") {
			t.Fatalf("no refresh after %s: %v", what, log)
		}
	}
	f := newCCSFixture(t)
	f.h.ccsRefreshErr = errors.New("http.sys")
	o, r, out := f.ccsDeploy(op1, f.in())
	if o.Exit != 0 || r.Phase != winproto.PhaseCommitted || !r.CCSRefreshFailed || !f.journal(op1).CCS.RefreshFailed {
		t.Fatalf("%+v %s", o, out)
	}
	after(t, f.h.writes(), "ccs-replace "+ccsName)

	f.h.ccsRefreshErr = nil
	restore := func() winproto.RestoreResponse {
		t.Helper()
		o, out := execute(t, context.Background(), f.h, bytes.NewReader(restoreInput([]string{}, []string{})), winproto.SubIISRestore,
			winproto.ArgOp, op1)
		var rr winproto.RestoreResponse
		if err := json.Unmarshal(out, &rr); err != nil || o.Exit != 0 || rr.Phase != winproto.PhaseRestored {
			t.Fatalf("%+v %s", o, out)
		}
		return rr
	}
	if rr := restore(); rr.CCSRefreshFailed || f.journal(op1).CCS.RefreshFailed {
		t.Fatalf("%+v", rr)
	}
	after(t, f.h.writes(), "ccs-restore "+ccsName)

	// A restore killed after the file was put back, before its refresh: the next one finds the file
	// restored already and refreshes all the same; its failure is answered.
	g := newCCSFixture(t)
	g.ccsCommitted(op1, g.in())
	g.h.pointErr = func(name string) error {
		if name == "restore.bound" {
			return errors.New("killed")
		}
		return nil
	}
	var killed bytes.Buffer
	if o := Execute(context.Background(), g.h, []string{winproto.SubIISRestore, winproto.ArgOp, op1},
		bytes.NewReader(restoreInput([]string{}, []string{})), &killed); !o.Killed {
		t.Fatalf("%+v", o)
	}
	g.h.pointErr = nil
	g.reset()
	g.h.ccsRefreshErr = errors.New("http.sys")
	f = g
	if rr := restore(); !rr.CCSRefreshFailed {
		t.Fatalf("%+v", rr)
	}
	if w := g.h.writes(); slices.Contains(w, "ccs-restore "+ccsName) || !slices.Contains(w, "ccs-refresh") {
		t.Fatalf("%v", w)
	}

	// A self-restore (the read-back fails) refreshes after it put the backup back.
	f = newCCSFixture(t)
	once := false
	f.h.ccsReadData = func(name string, data []byte) []byte {
		if name == ccsName && slices.Contains(f.h.log, "ccs-replace "+ccsName) && !once {
			once = true
			return []byte("other bytes")
		}
		return data
	}
	if _, r, out := f.ccsDeploy(op1, f.in()); r.Phase != winproto.PhaseRestored || r.CCSRefreshFailed {
		t.Fatalf("%s", out)
	}
	after(t, f.h.writes(), "ccs-restore "+ccsName)
}

// TestCCSDeployReadBackRestores is Review Focus 3 within the helper.
func TestCCSDeployReadBackRestores(t *testing.T) {
	restoredBy := func(t *testing.T, f *ccsFixture, r winproto.DeployResponse, step, class string) {
		t.Helper()
		if r.Phase != winproto.PhaseRestored || r.FailedStep != step || r.CauseStep != step || r.Error != class {
			t.Fatalf("%+v", r)
		}
		if data, _ := f.file(ccsName); !bytes.Equal(data, f.oldPFX) {
			t.Fatal("the file is not the old one")
		}
		if names := f.names(); !slices.Equal(names, []string{ccsName}) {
			t.Fatalf("folder %v", names)
		}
		if j := f.journal(op1); j.Phase != winproto.PhaseRestored {
			t.Fatal(j.Phase)
		}
	}
	t.Run("the file reads back other bytes", func(t *testing.T) {
		f := newCCSFixture(t)
		once := false
		f.h.ccsReadData = func(name string, data []byte) []byte {
			if name == ccsName && slices.Contains(f.h.log, "ccs-replace "+ccsName) && !once {
				once = true
				return []byte("other bytes")
			}
			return data
		}
		_, r, _ := f.ccsDeploy(op1, f.in())
		restoredBy(t, f, r, winproto.StepWriteFile, winproto.ErrReadBack)
		want := []winproto.Step{ok(winproto.StepImportChain), bad(winproto.StepWriteFile, winproto.ErrReadBack), ok(winproto.StepRestore)}
		if !reflect.DeepEqual(r.Steps, want) || !slices.Contains(f.h.writes(), "ccs-restore "+ccsName) || f.h.events[len(f.h.events)-1].id != 1002 {
			t.Fatalf("%+v %v", r.Steps, f.h.writes())
		}
	})
	t.Run("the file reads back neither the previous nor the new bytes, lastingly", func(t *testing.T) {
		f := newCCSFixture(t)
		f.h.ccsReadData = func(name string, data []byte) []byte {
			if name == ccsName && slices.Contains(f.h.log, "ccs-replace "+ccsName) {
				return []byte("other bytes")
			}
			return data
		}
		_, r, _ := f.ccsDeploy(op1, f.in())
		if r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrFileChanged || r.CauseStep != winproto.StepWriteFile ||
			slices.Contains(f.h.writes(), "ccs-restore "+ccsName) {
			t.Fatalf("%+v %v", r, f.h.writes())
		}
	})
	t.Run("the file opens to nothing", func(t *testing.T) {
		f := newCCSFixture(t)
		f.h.ccsReadData = func(name string, data []byte) []byte {
			if name == ccsName && slices.Contains(f.h.log, "ccs-replace "+ccsName) {
				f.h.ccsProblem = winproto.CCSProblemNotPFX // under the fake's lock, before the read back opens it
			}
			return data
		}
		_, r, _ := f.ccsDeploy(op1, f.in())
		restoredBy(t, f, r, winproto.StepWriteFile, winproto.ErrReadBack)
	})
	t.Run("the read back fails", func(t *testing.T) {
		f := newCCSFixture(t)
		n := 0
		f.h.ccsReadFn = func(string) error {
			if n++; n == 2 {
				return errors.New("denied")
			}
			return nil
		}
		_, r, _ := f.ccsDeploy(op1, f.in())
		restoredBy(t, f, r, winproto.StepWriteFile, winproto.ErrReadBack)
	})
	t.Run("a replace that fails before swapping", func(t *testing.T) {
		f := newCCSFixture(t)
		f.h.ccsReplaceErr = errors.New("sharing violation")
		f.reset()
		_, r, _ := f.ccsDeploy(op1, f.in())
		restoredBy(t, f, r, winproto.StepWriteFile, winproto.ErrIO)
		w := f.h.writes()
		if !slices.Contains(w, "ccs-unlink "+ccsTemp(op1)) || slices.Contains(w, "ccs-restore "+ccsName) || len(f.h.events) != 0 {
			t.Fatalf("%v", w)
		}
	})
	t.Run("a replace that moved the file to the backup only", func(t *testing.T) {
		f := newCCSFixture(t)
		_, r, _ := f.deployOn(partialReplace{f.h}, op1, f.in())
		restoredBy(t, f, r, winproto.StepWriteFile, winproto.ErrIO)
		if !slices.Contains(f.h.writes(), "ccs-restore "+ccsName) {
			t.Fatalf("%v", f.h.writes())
		}
	})
	t.Run("a replace that failed and cannot be read", func(t *testing.T) {
		f := newCCSFixture(t)
		f.h.ccsReplaceErr = errors.New("sharing violation")
		n := 0
		f.h.ccsReadFn = func(string) error {
			if n++; n >= 2 {
				return errors.New("denied")
			}
			return nil
		}
		_, r, _ := f.ccsDeploy(op1, f.in())
		if r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrIO || r.CauseStep != winproto.StepWriteFile {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("the temporary file cannot be written", func(t *testing.T) {
		f := newCCSFixture(t)
		f.h.ccsWriteErr = errors.New("disk full")
		_, r, _ := f.ccsDeploy(op1, f.in())
		restoredBy(t, f, r, winproto.StepWriteFile, winproto.ErrIO)
	})
	t.Run("an intermediate cannot be added", func(t *testing.T) {
		f := newCCSFixture(t)
		f.h.addIntermediateErr = errors.New("store")
		_, r, _ := f.ccsDeploy(op1, f.in())
		restoredBy(t, f, r, winproto.StepImportChain, winproto.ErrStore)
	})
	t.Run("the committed journal cannot be written", func(t *testing.T) {
		f := newCCSFixture(t)
		failPhase(f.fixture, winproto.PhaseCommitted)
		_, r, _ := f.ccsDeploy(op1, f.in())
		restoredBy(t, f, r, winproto.StepJournal, winproto.ErrIO)
	})
	t.Run("the prepared journal cannot be written", func(t *testing.T) {
		f := newCCSFixture(t)
		failPhase(f.fixture, winproto.PhasePrepared)
		o, _, out := f.ccsDeploy(op1, f.in())
		wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeOutcomeUnknown)
		if names := f.names(); !slices.Equal(names, []string{ccsName}) {
			t.Fatalf("folder %v", names)
		}
	})
}

// TestCCSKillAtEveryPoint is Review Focus 4 within the helper: after a kill at any point, iis-status
// names the phase and what the file holds, and the recovery the phase allows (iis-fence for none or
// prepared, iis-restore otherwise) leaves exactly the old file.
func TestCCSKillAtEveryPoint(t *testing.T) {
	type want struct {
		phase   string // "" for no journal
		current string // "old" or "new"
	}
	points := map[string]want{
		"ccs.locked": {"", "old"}, "ccs.prepared": {winproto.PhasePrepared, "old"}, "ccs.import_chain": {winproto.PhasePrepared, "old"},
		"ccs.writing": {winproto.PhaseWriting, "old"}, "ccs.temp_written": {winproto.PhaseWriting, "old"},
		"ccs.replaced": {winproto.PhaseWriting, "new"}, "ccs.read_back": {winproto.PhaseWriting, "new"},
		"ccs.committed":     {winproto.PhaseCommitted, "new"},
		"restore.restoring": {winproto.PhaseRestoring, "new"}, "restore.bound": {winproto.PhaseRestoring, "old"},
		"restore.restored": {winproto.PhaseRestored, "old"},
	}
	f := newCCSFixture(t)
	f.ccsCommitted(op1, f.in())
	if !slices.Equal(f.h.points, []string{"ccs.locked", "ccs.prepared", "ccs.import_chain", "ccs.writing", "ccs.temp_written",
		"ccs.replaced", "ccs.read_back", "ccs.committed"}) {
		t.Fatalf("points %v", f.h.points)
	}
	for p, w := range points {
		t.Run(p, func(t *testing.T) {
			f := newCCSFixture(t)
			args := []string{winproto.SubCCSDeploy, winproto.ArgOp, op1}
			in := f.in()
			if strings.HasPrefix(p, "restore.") {
				f.ccsCommitted(op1, f.in())
				args[0], in = winproto.SubIISRestore, restoreInput([]string{}, []string{})
			}
			f.h.pointErr = func(name string) error {
				if name == p {
					return errors.New("kill")
				}
				return nil
			}
			var out bytes.Buffer
			if o := Execute(context.Background(), f.h, args, bytes.NewReader(in), &out); !o.Killed || out.Len() != 0 {
				t.Fatalf("%+v %s", o, out.Bytes())
			}
			f.h.pointErr = nil
			cur := map[string]string{"old": f.oldSHA256, "new": f.newSHA256}
			_, st, raw := f.statusCall(winproto.SubIISStatus, op1)
			if (w.phase == "" && st.Phase != winproto.PhaseNone) || (w.phase != "" && (st.Phase != w.phase || st.CurrentCertSHA256 != cur[w.current])) {
				t.Fatalf("status %s", raw)
			}
			f.reset()
			fenced := false
			switch st.Phase {
			case winproto.PhaseNone, winproto.PhasePrepared:
				if _, r, out := f.statusCall(winproto.SubIISFence, op1); r.Phase != winproto.PhaseFenced {
					t.Fatalf("fence: %s", out)
				}
				o, _, out := f.ccsDeploy(op1, f.in())
				wantError(t, o.Exit, out, 3, winproto.CodeFenced)
				fenced = true
			default:
				if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored {
					t.Fatalf("restore: %s", out)
				}
				if w.current == "old" && slices.ContainsFunc(f.h.writes(), func(s string) bool { return strings.HasPrefix(s, "ccs-restore") }) {
					t.Fatalf("a restore wrote a file it had not changed: %v", f.h.writes())
				}
				if names := f.names(); !slices.Equal(names, []string{ccsName}) {
					t.Fatalf("folder %v", names)
				}
			}
			if data, _ := f.file(ccsName); !bytes.Equal(data, f.oldPFX) {
				t.Fatal("the file is not the old one")
			}
			if _, st, _ := f.statusCall(winproto.SubIISStatus, op1); !fenced && st.CurrentCertSHA256 != f.oldSHA256 {
				t.Fatalf("status names %s", st.CurrentCertSHA256)
			}
			if fenced {
				if rec, _ := readBindingRecord(f.h, ccsKey); rec != "" {
					t.Fatalf("the file record still names %s", rec)
				}
			}
		})
	}
}

func TestCCSRestoreRules(t *testing.T) {
	committed := func(t *testing.T) *ccsFixture {
		f := newCCSFixture(t)
		f.ccsCommitted(op1, f.in())
		f.reset()
		return f
	}
	current := func(f *ccsFixture) []byte { d, _ := f.file(ccsName); return d }
	restoreOn := func(f *ccsFixture, h WriteHost) winproto.RestoreResponse {
		o, out := execute(f.t, context.Background(), h, bytes.NewReader(restoreInput([]string{}, []string{})), winproto.SubIISRestore,
			winproto.ArgOp, op1)
		var r winproto.RestoreResponse
		if o.Exit != 0 || json.Unmarshal(out, &r) != nil {
			f.t.Fatalf("%+v %s", o, out)
		}
		return r
	}
	t.Run("a forbidden previous leaf or SPKI", func(t *testing.T) {
		for _, bySPKI := range []bool{false, true} {
			f := committed(t)
			before := current(f)
			spki, leaf := []string{}, []string{f.oldSHA256}
			if bySPKI {
				spki, leaf = []string{f.oldSPKI}, []string{}
			}
			if _, r, out := f.restore(op1, spki, leaf); r.Phase != winproto.PhaseRestoreForbidden || !bytes.Equal(current(f), before) {
				t.Fatalf("%s", out)
			}
			// It stays forbidden for a call with shorter lists.
			if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestoreForbidden || !bytes.Equal(current(f), before) {
				t.Fatalf("%s", out)
			}
		}
	})
	t.Run("a third party replaced or removed the file", func(t *testing.T) {
		for _, gone := range []bool{false, true} {
			f := committed(t)
			if gone {
				delete(f.h.ccsFiles, ccsName)
			} else {
				f.setFile(ccsName, f.pfx(f.ca.Issue(leafOpts, testNow)))
			}
			o, _, out := f.restore(op1, []string{}, []string{})
			wantError(t, o.Exit, out, 3, winproto.CodeSuperseded)
			if len(f.h.writes()) != 0 {
				t.Fatalf("%v", f.h.writes())
			}
		}
	})
	t.Run("a later deployment of the file", func(t *testing.T) {
		f := committed(t)
		third := f.ca.Issue(leafOpts, testNow)
		f.ccsCommitted(op2, f.in(func(in *winproto.CCSDeployInput) {
			in.ExpectSHA256, in.ChainPEM, in.KeyPEM = f.newSHA256, string(third.FullchainPEM), string(third.KeyPEM)
		}))
		o, _, out := f.restore(op1, []string{}, []string{})
		wantError(t, o.Exit, out, 3, winproto.CodeSuperseded)
	})
	t.Run("the backup deleted or changed", func(t *testing.T) {
		for _, gone := range []bool{false, true} {
			f := committed(t)
			if gone {
				delete(f.h.ccsFiles, ccsBackup(op1))
			} else {
				f.setFile(ccsBackup(op1), []byte("changed"))
			}
			o, _, out := f.restore(op1, []string{}, []string{})
			wantError(t, o.Exit, out, 3, winproto.CodeBackupMissing)
			if len(f.h.writes()) != 0 {
				t.Fatalf("%v", f.h.writes())
			}
		}
	})
	t.Run("a second restore writes nothing", func(t *testing.T) {
		f := committed(t)
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored {
			t.Fatalf("%s", out)
		}
		if !bytes.Equal(current(f), f.oldPFX) || slices.Contains(f.names(), ccsBackup(op1)) || f.h.events[len(f.h.events)-1].id != 1002 {
			t.Fatal("not restored from the backup")
		}
		f.reset()
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored || len(f.h.writes()) != 0 {
			t.Fatalf("%s %v", out, f.h.writes())
		}
	})
	t.Run("someone put the old file back", func(t *testing.T) {
		f := committed(t)
		f.setFile(ccsName, f.oldPFX)
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored ||
			slices.ContainsFunc(f.h.writes(), func(s string) bool { return strings.HasPrefix(s, "ccs-restore") }) {
			t.Fatalf("%s %v", out, f.h.writes())
		}
	})
	t.Run("the move fails", func(t *testing.T) {
		f := committed(t)
		if r := restoreOn(f, failMove{f.h}); r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrIO {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("the move reads back other bytes", func(t *testing.T) {
		f := committed(t)
		n := 0
		f.h.ccsReadData = func(name string, data []byte) []byte {
			if name == ccsName {
				if n++; n == 2 {
					return []byte("other")
				}
			}
			return data
		}
		if r := restoreOn(f, f.h); r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrReadBack {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("the file cannot be read", func(t *testing.T) {
		f := committed(t)
		f.h.ccsReadFn = func(string) error { return errors.New("denied") }
		o, _, out := f.restore(op1, []string{}, []string{})
		wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeIOError)
		if _, st, _ := f.statusCall(winproto.SubIISStatus, op1); st.CurrentCertSHA256 != "" || st.Phase != winproto.PhaseCommitted {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("a fence of a committed operation changes nothing", func(t *testing.T) {
		f := committed(t)
		if _, r, out := f.statusCall(winproto.SubIISFence, op1); r.Phase != winproto.PhaseCommitted || r.CurrentCertSHA256 != f.newSHA256 ||
			len(f.h.writes()) != 0 {
			t.Fatalf("%s", out)
		}
	})
}

// TestCCSJournalHoldsNoPassword is Review Focus 2: no state file holds the password, the key or a PFX,
// and every buffer that held them is zero after the call, on the commit path and on a failure path.
func TestCCSJournalHoldsNoPassword(t *testing.T) {
	for _, fail := range []bool{false, true} {
		f := newCCSFixture(t)
		var all []*secrets
		secretsHook = func(s *secrets) { all = append(all, s) }
		t.Cleanup(func() { secretsHook = nil })
		if fail {
			f.h.ccsReplaceErr = errors.New("x")
		}
		f.ccsDeploy(op1, f.in())
		secretsHook = nil
		written, _ := f.file(ccsName)
		for _, w := range f.h.stateLog {
			for _, s := range [][]byte{f.pw, f.nw.KeyPEM, pkcs8Of(t, f.nw), written, f.oldPFX} {
				if bytes.Contains(w.data, s) {
					t.Fatalf("%s holds a secret", w.name)
				}
			}
			if bytes.Contains(w.data, []byte("PRIVATE")) {
				t.Fatalf("%s holds a key", w.name)
			}
		}
		for _, e := range f.h.events {
			if strings.Contains(e.text, string(f.pw)) {
				t.Fatal("an event holds the password")
			}
		}
		if len(all) != 1 {
			t.Fatalf("%d secrets", len(all))
		}
		for _, b := range all[0].bufs {
			if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
				t.Fatal("a secret buffer was not cleared")
			}
		}
		if len(f.h.ccsPasswords) == 0 {
			t.Fatal("OpenPFX was not called")
		}
		for _, p := range f.h.ccsPasswords {
			if !bytes.Equal(p, make([]byte, len(p))) {
				t.Fatal("a password given to OpenPFX was not cleared")
			}
		}
	}
}

// TestCCSInterruptedThenChangedByAThirdParty: an interrupted operation whose file someone else wrote
// ends restore_failed file_changed with the file left as it is, so the next ccs-deploy is not held up.
func TestCCSInterruptedThenChangedByAThirdParty(t *testing.T) {
	for _, p := range []string{"ccs.temp_written", "ccs.replaced"} {
		t.Run(p, func(t *testing.T) {
			f := newCCSFixture(t)
			f.h.pointErr = func(name string) error {
				if name == p {
					return errors.New("kill")
				}
				return nil
			}
			f.killedDeploy(op1, f.in())
			f.h.pointErr = nil
			third := f.ca.Issue(leafOpts, testNow)
			theirs := f.pfx(third)
			f.setFile(ccsName, theirs)
			f.reset()
			if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrFileChanged {
				t.Fatalf("%s", out)
			}
			if data, _ := f.file(ccsName); !bytes.Equal(data, theirs) {
				t.Fatal("the third party's file was overwritten")
			}
			f.ccsCommitted(op2, f.in(func(in *winproto.CCSDeployInput) { in.ExpectSHA256 = hexSHA256(third.Cert.Raw) }))
		})
	}
}

// killedDeploy runs a ccs-deploy that a point kills: no answer.
func (f *ccsFixture) killedDeploy(op string, in []byte) {
	f.t.Helper()
	var out bytes.Buffer
	if o := Execute(context.Background(), f.h, []string{winproto.SubCCSDeploy, winproto.ArgOp, op}, bytes.NewReader(in), &out); !o.Killed {
		f.t.Fatalf("not killed: %+v %s", o, out.Bytes())
	}
}

func (f *ccsFixture) plan() (Outcome, []byte) {
	f.t.Helper()
	return execute(f.t, context.Background(), f.h, bytes.NewReader(planInput()), winproto.SubIISCleanup, winproto.ArgPlan)
}

// TestCCSAfterThePathChanged (W5 Ruling 17): a committed operation is still rolled back, and its backup
// still pruned, in the folder its journal names after the registry names another; a journal folder
// that became a reparse point is refused with nothing written.
func TestCCSAfterThePathChanged(t *testing.T) {
	t.Run("restore", func(t *testing.T) {
		f := newCCSFixture(t)
		f.ccsCommitted(op1, f.in())
		f.h.moveCCS(`C:\New`)
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored {
			t.Fatalf("%s", out)
		}
		if data, _ := f.file(ccsName); !bytes.Equal(data, f.oldPFX) {
			t.Fatal("not restored")
		}
	})
	t.Run("prune", func(t *testing.T) {
		f := newCCSFixture(t)
		f.ccsCommitted(op1, f.in())
		f.h.moveCCS(`C:\New`)
		if o, out := f.plan(); o.Exit != 0 {
			t.Fatalf("%s", out)
		}
		if _, ok := f.file(ccsBackup(op1)); ok {
			t.Fatal("the backup stays")
		}
	})
	t.Run("the journal's folder became a reparse point", func(t *testing.T) {
		f := newCCSFixture(t)
		f.ccsCommitted(op1, f.in())
		f.h.ccsListErr = ErrCCSFolderUnsupported
		f.reset()
		o, _, out := f.restore(op1, []string{}, []string{})
		wantError(t, o.Exit, out, winproto.ExitPrecondition, winproto.CodeCCSPathUnsupported)
		if len(f.h.writes()) != 0 {
			t.Fatalf("%v", f.h.writes())
		}
		if o, out := f.plan(); o.Exit != 0 {
			t.Fatalf("%s", out)
		}
		if _, ok := f.file(ccsBackup(op1)); !ok || slices.ContainsFunc(f.h.writes(), func(s string) bool { return strings.HasPrefix(s, "ccs-unlink") }) {
			t.Fatalf("%v", f.h.writes())
		}
		if _, ok := f.h.state[journalName(op1)]; !ok {
			t.Fatal("the journal was removed")
		}
	})
}
