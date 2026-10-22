package winhelper

import (
	"errors"
	"testing"

	"alice/internal/providers/windows/winproto"
)

func TestStatusAndFence(t *testing.T) {
	t.Run("status of an unknown op", func(t *testing.T) {
		f := newFixture(t)
		o, r, out := f.statusCall(winproto.SubIISStatus, op3)
		if o.Exit != 0 || r.Phase != winproto.PhaseNone || r.Active || r.NewCertSHA256 != "" {
			t.Fatalf("%+v %s", o, out)
		}
		f.h.lockHeld = true // another helper process holds the lock: status needs none
		if _, r, _ := f.statusCall(winproto.SubIISStatus, op3); !r.Active {
			t.Fatal("not active")
		}
		if f.h.locks != 0 || len(f.h.writes()) != 0 {
			t.Fatal("status took the lock or wrote")
		}
	})
	t.Run("fence of an unknown op, then a deploy of it", func(t *testing.T) {
		f := newFixture(t)
		o, r, out := f.statusCall(winproto.SubIISFence, op3)
		if o.Exit != 0 || r.Phase != winproto.PhaseFenced || r.Active || f.h.locks != 1 {
			t.Fatalf("%+v %s", o, out)
		}
		o, _, out = f.deploy(op3, f.input())
		wantError(t, o.Exit, out, 3, winproto.CodeFenced)
		if _, r, _ := f.statusCall(winproto.SubIISStatus, op3); r.Phase != winproto.PhaseFenced || r.CurrentCertSHA256 != "" {
			t.Fatal(r)
		}
		f.reset()
		if _, r, _ := f.statusCall(winproto.SubIISFence, op3); r.Phase != winproto.PhaseFenced || len(f.h.writes()) != 0 {
			t.Fatal("a second fence wrote")
		}
	})
	t.Run("fence of committed", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		f.reset()
		o, r, out := f.statusCall(winproto.SubIISFence, op1)
		if o.Exit != 0 || r.Phase != winproto.PhaseCommitted || r.NewCertSHA256 != f.newSHA256 || r.CurrentCertSHA256 != f.newSHA256 ||
			len(f.h.writes()) != 0 {
			t.Fatalf("%+v %s", o, out)
		}
		if _, r, _ := f.statusCall(winproto.SubIISStatus, op1); r.Phase != winproto.PhaseCommitted || r.CurrentCertSHA256 != f.newSHA256 {
			t.Fatal(r)
		}
		// The store lacks what the record names now: "".
		delete(f.h.certs, [2]string{"MY", f.newSHA1})
		if _, r, _ := f.statusCall(winproto.SubIISStatus, op1); r.CurrentCertSHA256 != "" {
			t.Fatal(r)
		}
		f.h.bindingErr = errors.New("httpapi")
		if _, r, _ := f.statusCall(winproto.SubIISStatus, op1); r.CurrentCertSHA256 != "" || r.Phase != winproto.PhaseCommitted {
			t.Fatal(r)
		}
	})
	t.Run("fence of prepared hands the record back", func(t *testing.T) {
		f := newFixture(t)
		f.h.pointErr = func(n string) error {
			if n == "deploy.prepared" {
				return errors.New("kill")
			}
			return nil
		}
		f.killedDeploy(op1, f.input())
		f.h.pointErr = nil
		if rec, _ := readBindingRecord(f.h, canon443); rec != op1 {
			t.Fatal(rec)
		}
		if _, r, _ := f.statusCall(winproto.SubIISStatus, op1); r.Phase != winproto.PhasePrepared || r.CurrentCertSHA256 != f.oldSHA256 {
			t.Fatal(r)
		}
		o, r, out := f.statusCall(winproto.SubIISFence, op1)
		if o.Exit != 0 || r.Phase != winproto.PhaseFenced {
			t.Fatalf("%+v %s", o, out)
		}
		if rec, _ := readBindingRecord(f.h, canon443); rec != "" {
			t.Fatal(rec)
		}
		if j := f.journal(op1); j.Phase != winproto.PhaseFenced {
			t.Fatal(j)
		}
		o, _, out = f.deploy(op1, f.input())
		wantError(t, o.Exit, out, 3, winproto.CodeFenced)
	})
	for _, c := range []struct {
		name  string
		sub   string
		setup func(f *fixture)
		exit  int
		code  string
	}{
		{"status usage", winproto.SubIISStatus, nil, 2, winproto.CodeUsage},
		{"fence usage", winproto.SubIISFence, nil, 2, winproto.CodeUsage},
		{"status journal unreadable", winproto.SubIISStatus, func(f *fixture) { f.h.state[journalName(op1)] = []byte("{") }, 4, winproto.CodeIOError},
		{"fence journal unreadable", winproto.SubIISFence, func(f *fixture) { f.h.state[journalName(op1)] = []byte("{") }, 4, winproto.CodeIOError},
		{"fence busy", winproto.SubIISFence, func(f *fixture) { f.h.lockHeld = true }, 4, winproto.CodeBusy},
		{"fence journal directory", winproto.SubIISFence, func(f *fixture) { f.h.dataDirErr = ErrJournal }, 4, winproto.CodeJournalFailed},
		{"fence tombstone unwritten", winproto.SubIISFence, func(f *fixture) {
			f.h.writeStateErr = func(string) error { return errors.New("disk") }
		}, 4, winproto.CodeOutcomeUnknown},
		{"fence hand-back unwritten", winproto.SubIISFence, func(f *fixture) {
			j := sampleJournal(op1)
			mustWrite(t, f.h, j)
			_ = writeBindingRecord(f.h, canon443, op1)
			f.h.writeStateErr = func(string) error { return errors.New("disk") }
		}, 4, winproto.CodeOutcomeUnknown},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			if c.setup != nil {
				c.setup(f)
			}
			args := []string{c.sub, winproto.ArgOp, op1}
			if c.code == winproto.CodeUsage {
				args = args[:1]
			}
			o, out := execute(t, t.Context(), f.h, nil, args...)
			wantError(t, o.Exit, out, c.exit, c.code)
		})
	}
	t.Run("killed after the fence's tombstone is not possible: no point", func(t *testing.T) {
		f := newFixture(t)
		f.h.pointErr = func(string) error { return errors.New("kill") }
		if _, r, _ := f.statusCall(winproto.SubIISFence, op3); r.Phase != winproto.PhaseFenced {
			t.Fatal(r)
		}
	})
}
