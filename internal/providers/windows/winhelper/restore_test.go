package winhelper

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// TestRestoreForbiddenOnEveryPath is Review Focus 3: the self-restore, iis-restore with the lists on
// stdin, and a re-sent iis-restore of a restore_forbidden or restore_failed journal.
func TestRestoreForbiddenOnEveryPath(t *testing.T) {
	t.Run("self-restore", func(t *testing.T) {
		f := newFixture(t)
		n := 0
		f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding {
			if n++; n == 1 {
				b.Flags = 0
			}
			return b
		}
		_, r, out := f.deploy(op1, f.input(func(in *winproto.DeployInput) { in.ForbiddenSPKI = []string{f.oldSPKI} }))
		if r.Phase != winproto.PhaseRestoreForbidden || f.current().CertSHA1 != f.newSHA1 {
			t.Fatalf("%s", out)
		}
		// A re-sent restore of it checks again.
		_, rr, out := f.restore(op1, []string{}, []string{})
		if rr.Phase != winproto.PhaseRestoreForbidden || f.current().CertSHA1 != f.newSHA1 || len(f.h.updates) != 1 {
			t.Fatalf("%s", out)
		}
	})
	t.Run("iis-restore lists, then re-sent", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		for range 2 {
			o, r, out := f.restore(op1, []string{}, []string{f.oldSHA256})
			if o.Exit != 0 || r.Phase != winproto.PhaseRestoreForbidden || r.Error != winproto.ErrForbidden || r.FailedStep != winproto.StepRestore {
				t.Fatalf("%+v %s", o, out)
			}
			if f.current().CertSHA1 != f.newSHA1 || len(f.h.updates) != 1 {
				t.Fatal("restored although forbidden")
			}
		}
		if j := f.journal(op1); j.Phase != winproto.PhaseRestoreForbidden {
			t.Fatal(j.Phase)
		}
	})
	t.Run("forbidden by stdin, re-sent with empty lists: still forbidden (the guard only grows)", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		if _, r, out := f.restore(op1, []string{f.oldSPKI}, []string{}); r.Phase != winproto.PhaseRestoreForbidden {
			t.Fatalf("%s", out)
		}
		if j := f.journal(op1); len(j.ForbiddenSPKI) != 1 || j.ForbiddenSPKI[0] != f.oldSPKI || j.ForbiddenFinal {
			t.Fatalf("%+v", j)
		}
		f.reset()
		o, r, out := f.restore(op1, []string{}, []string{})
		if o.Exit != 0 || r.Phase != winproto.PhaseRestoreForbidden || len(f.h.updates) != 0 || len(f.h.writes()) != 0 {
			t.Fatalf("%+v %s %v", o, out, f.h.writes())
		}
		if f.current().CertSHA1 != f.newSHA1 {
			t.Fatal("restored")
		}
	})
	t.Run("forbidden by more hashes than a list holds: final", func(t *testing.T) {
		f := newFixture(t)
		journalLeaf := make([]string, winproto.MaxForbidden)
		stdinLeaf := []string{f.oldSHA256}
		for i := range journalLeaf {
			journalLeaf[i] = strings.Repeat("0", 56) + hexN(i)
		}
		f.deploy(op1, f.input(func(in *winproto.DeployInput) { in.ForbiddenLeaf = journalLeaf }))
		if _, r, out := f.restore(op1, []string{}, stdinLeaf); r.Phase != winproto.PhaseRestoreForbidden {
			t.Fatalf("%s", out)
		}
		j := f.journal(op1)
		if !j.ForbiddenFinal || len(j.ForbiddenLeaf) != winproto.MaxForbidden {
			t.Fatalf("final %v, %d hashes", j.ForbiddenFinal, len(j.ForbiddenLeaf))
		}
		f.reset()
		if _, r, _ := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestoreForbidden || len(f.h.writes()) != 0 {
			t.Fatal("not final", r)
		}
	})
	t.Run("journal lists", func(t *testing.T) {
		f := newFixture(t)
		f.deploy(op1, f.input(func(in *winproto.DeployInput) { in.ForbiddenLeaf = []string{f.oldSHA256} }))
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestoreForbidden {
			t.Fatalf("%s", out)
		}
	})
	t.Run("re-sent restore of restore_failed", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		f.h.updateErr = func(winproto.SSLBinding) error { return errors.New("httpapi") }
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestoreFailed {
			t.Fatalf("%s", out)
		}
		f.h.updateErr = nil
		if _, r, out := f.restore(op1, []string{f.oldSPKI}, []string{}); r.Phase != winproto.PhaseRestoreForbidden {
			t.Fatalf("%s", out)
		}
		if f.current().CertSHA1 != f.newSHA1 {
			t.Fatal("restored")
		}
	})
}

// TestRestoreRules is Ruling 12.
func TestRestoreRules(t *testing.T) {
	t.Run("from committed", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		f.reset()
		o, r, out := f.restore(op1, []string{}, []string{})
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != "" || r.Error != "" ||
			!reflect.DeepEqual(r.Steps, []winproto.Step{ok(winproto.StepRestore)}) {
			t.Fatalf("%+v %s", o, out)
		}
		if !reflect.DeepEqual(f.current(), f.rec) || len(f.h.updates) != 1 || !reflect.DeepEqual(f.h.updates[0], f.rec) {
			t.Fatal("not the previous record byte for byte")
		}
		if len(f.h.events) != 1 || f.h.events[0].id != 1002 {
			t.Fatal(f.h.events)
		}
		if p := f.phases(op1); !reflect.DeepEqual(p, []string{winproto.PhaseRestoring, winproto.PhaseRestored}) {
			t.Fatal(p)
		}
		// Again: restored, nothing written.
		f.reset()
		if _, r, _ := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored || len(f.h.writes()) != 0 {
			t.Fatal(r, f.h.writes())
		}
	})
	t.Run("the record is the previous already", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		f.h.setRecord(f.rec)
		f.reset()
		o, r, out := f.restore(op1, []string{}, []string{f.oldSHA256}) // nothing is put back: no guard applies
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || len(f.h.updates) != 0 {
			t.Fatalf("%+v %s", o, out)
		}
	})
	t.Run("previous hash, other settings changed by someone after the commit", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		other := cloneBinding(f.rec)
		other.Flags = 7
		f.h.setRecord(other)
		f.reset()
		if _, r, _ := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored || len(f.h.updates) != 0 {
			t.Fatal(r)
		}
	})
	t.Run("a third certificate", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		f.h.setRecord(withHash(f.rec, h3))
		o, r, out := f.restore(op1, []string{}, []string{})
		if o.Exit != 0 || r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrFileChanged || r.FailedStep != winproto.StepRestore {
			t.Fatalf("%+v %s", o, out)
		}
		f.reset()
		if _, r, _ := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestoreFailed || len(f.h.writes()) != 0 {
			t.Fatal("rewritten", r)
		}
	})
	t.Run("the record is gone", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		delete(f.h.records, canon443)
		if _, r, _ := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrFileChanged {
			t.Fatal(r)
		}
	})
	for _, c := range []struct {
		name  string
		setup func(f *fixture)
		exit  int
		code  string
	}{
		{"previous deleted", func(f *fixture) { delete(f.h.certs, [2]string{"MY", f.oldSHA1}) }, 3, winproto.CodeBackupMissing},
		{"previous without a key", func(f *fixture) { f.h.addCert("MY", f.old.Cert.Raw, false) }, 3, winproto.CodeBackupMissing},
		{"previous replaced by other DER", func(f *fixture) {
			c := f.h.certs[[2]string{"MY", f.oldSHA1}]
			c.DER = b64([]byte("other"))
			f.h.certs[[2]string{"MY", f.oldSHA1}] = c
		}, 3, winproto.CodeBackupMissing},
		{"store error", func(f *fixture) { f.h.certErr = ErrStore }, 4, winproto.CodeStoreError},
		{"certificate unreadable", func(f *fixture) { f.h.certErr = errors.New("crypt32") }, 4, winproto.CodeIOError},
		{"binding unreadable", func(f *fixture) { f.h.bindingErr = errors.New("httpapi") }, 4, winproto.CodeIOError},
		{"busy", func(f *fixture) { f.h.lockHeld = true }, 4, winproto.CodeBusy},
		{"journal directory", func(f *fixture) { f.h.dataDirErr = ErrJournal }, 4, winproto.CodeJournalFailed},
		{"journal unreadable", func(f *fixture) { f.h.state[journalName(op1)] = []byte("{") }, 4, winproto.CodeIOError},
		{"record unreadable", func(f *fixture) { f.h.state[bindingRecordName(canon443)] = []byte("{") }, 4, winproto.CodeIOError},
		{"restoring unwritten", func(f *fixture) { failPhase(f, winproto.PhaseRestoring) }, 4, winproto.CodeOutcomeUnknown},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.committed(op1)
			c.setup(f)
			f.reset()
			o, _, out := f.restore(op1, []string{}, []string{})
			wantError(t, o.Exit, out, c.exit, c.code)
			if c.code != winproto.CodeOutcomeUnknown && len(f.h.writes()) != 0 {
				t.Fatal(f.h.writes())
			}
			if f.current().CertSHA1 != f.newSHA1 {
				t.Fatal("restored")
			}
		})
	}
	t.Run("superseded", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		third := f.ca.Issue(leafOpts, testNow)
		o, r, out := f.deploy(op2, f.input(func(in *winproto.DeployInput) {
			in.ExpectSHA256, in.ChainPEM, in.KeyPEM = f.newSHA256, string(third.FullchainPEM), string(third.KeyPEM)
		}))
		if o.Exit != 0 || r.Phase != winproto.PhaseCommitted {
			t.Fatalf("%+v %s", o, out)
		}
		f.reset()
		o, _, out = f.restore(op1, []string{}, []string{})
		wantError(t, o.Exit, out, 3, winproto.CodeSuperseded)
		if len(f.h.writes()) != 0 {
			t.Fatal(f.h.writes())
		}
	})
	t.Run("unknown op", func(t *testing.T) {
		f := newFixture(t)
		o, _, out := f.restore(op3, []string{}, []string{})
		wantError(t, o.Exit, out, 3, winproto.CodeUnknownOp)
	})
	t.Run("nothing to restore", func(t *testing.T) {
		for _, phase := range []string{winproto.PhasePrepared, winproto.PhaseUnchanged} {
			f := newFixture(t)
			j := sampleJournal(op1)
			j.Phase = phase
			mustWrite(t, f.h, j)
			f.reset()
			o, r, out := f.restore(op1, []string{}, []string{})
			if o.Exit != 0 || r.Phase != phase || len(r.Steps) != 0 || len(f.h.writes()) != 0 {
				t.Fatalf("%+v %s", o, out)
			}
		}
		f := newFixture(t)
		f.statusCall(winproto.SubIISFence, op3)
		if _, r, _ := f.restore(op3, []string{}, []string{}); r.Phase != winproto.PhaseFenced {
			t.Fatal(r)
		}
	})
	t.Run("from writing after a kill at bound", func(t *testing.T) {
		f := newFixture(t)
		f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding { b.Extended = nil; return b }
		f.h.pointErr = func(n string) error {
			if n == "deploy.bound" {
				return errors.New("kill")
			}
			return nil
		}
		f.killedDeploy(op1, f.input())
		f.h.pointErr, f.h.afterUpdate = nil, nil
		// The record names the previous hash? No: the new one, with the Ex parameters lost.
		o, r, out := f.restore(op1, []string{}, []string{})
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || !reflect.DeepEqual(f.current(), f.rec) {
			t.Fatalf("%+v %s", o, out)
		}
	})
	t.Run("from writing, the previous hash with settings lost", func(t *testing.T) {
		f := newFixture(t)
		j := sampleJournal(op1)
		j.Phase, j.Previous, j.PreviousSHA1, j.PreviousSHA256, j.Store = winproto.PhaseWriting, f.rec, f.oldSHA1, f.oldSHA256, "MY"
		j.NewSHA1, j.NewSHA256 = f.newSHA1, f.newSHA256
		mustWrite(t, f.h, j)
		_ = writeBindingRecord(f.h, canon443, op1)
		lost := cloneBinding(f.rec)
		lost.Extended = nil
		f.h.setRecord(lost)
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored || !reflect.DeepEqual(f.current(), f.rec) {
			t.Fatalf("%s", out)
		}
	})
}

// TestRestoreKeepsTheCauseClass: a failed restore's class does not replace the deployment's cause;
// a later successful restore answers the cause's class.
func TestRestoreKeepsTheCauseClass(t *testing.T) {
	f := newFixture(t)
	n := 0
	f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding {
		if n++; n == 1 {
			b.Flags = 0 // the bind reads back wrong
		}
		return b
	}
	f.h.updateErr = func(winproto.SSLBinding) error {
		if n == 1 {
			return ErrKeyUnusable // the self-restore's update (the second) hits 1312
		}
		return nil
	}
	_, r, out := f.deploy(op1, f.input())
	if r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrKeyUnusable || r.CauseStep != winproto.StepBind {
		t.Fatalf("%s", out)
	}
	f.h.updateErr = nil
	o, rr, out := f.restore(op1, []string{}, []string{})
	if o.Exit != 0 || rr.Phase != winproto.PhaseRestored || rr.FailedStep != winproto.StepBind || rr.Error != winproto.ErrReadBack {
		t.Fatalf("%+v %s", o, out)
	}
	if !reflect.DeepEqual(f.current(), f.rec) {
		t.Fatal("not restored")
	}
}

func TestRestoreInputRefusals(t *testing.T) {
	f := newFixture(t)
	f.committed(op1)
	for _, c := range []struct {
		in   string
		code string
	}{
		{"", winproto.CodeBadContent},
		{"{", winproto.CodeBadContent},
		{`{"forbidden_spki_sha256":[]}`, winproto.CodeBadContent},
		{`{"forbidden_spki_sha256":[],"forbidden_leaf_sha256":[],"x":1}`, winproto.CodeBadContent},
		{`{"forbidden_spki_sha256":[],"forbidden_leaf_sha256":[]} {}`, winproto.CodeBadContent},
		{`{"forbidden_spki_sha256":["zz"],"forbidden_leaf_sha256":[]}`, winproto.CodeInvalidArgument},
	} {
		f.reset()
		o, _, out := f.restoreRaw(op1, []byte(c.in))
		wantError(t, o.Exit, out, 2, c.code)
		if len(f.h.writes()) != 0 {
			t.Fatal(f.h.writes())
		}
	}
	o, _, out := f.restoreRaw(op1, append(restoreInput([]string{}, []string{}), make([]byte, winproto.MaxRestoreInput)...))
	wantError(t, o.Exit, out, 2, winproto.CodeTooLarge)
	for _, args := range [][]string{{winproto.SubIISRestore}, {winproto.SubIISRestore, winproto.ArgOp, "x"}} {
		o, out := execute(t, t.Context(), f.h, nil, args...)
		wantError(t, o.Exit, out, 2, map[bool]string{true: winproto.CodeUsage, false: winproto.CodeInvalidArgument}[len(args) == 1])
	}
}

func TestRestoreWithRSA(t *testing.T) {
	ca := pki.NewCA("RSA Test", pki.RSA2048, testNow)
	f := newFixture(t)
	nw := ca.Issue(pki.Opts{CommonName: "rsa.example.test", KeyType: pki.RSA2048}, testNow)
	f.nw = nw
	f.newSHA1, f.newSHA256 = sha1Hex(nw.Cert.Raw), hexSHA256(nw.Cert.Raw)
	r := f.committed(op1)
	if r.NewSHA1 != f.newSHA1 || r.BuiltChainLength != 2 {
		t.Fatal(r)
	}
	if _, rr, out := f.restore(op1, []string{}, []string{}); rr.Phase != winproto.PhaseRestored {
		t.Fatalf("%s", out)
	}
}
