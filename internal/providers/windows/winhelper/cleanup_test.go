package winhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

const day = 24 * time.Hour

// cleanupFixture is a host whose certificates the tests put into stores with Alice's friendly name
// (and an import inventory entry) or another one.
type cleanupFixture struct {
	t  *testing.T
	h  *fakeWriteHost
	ca *pki.CA
	n  int
}

// cref is a certificate a test put into a store, with the operation whose friendly name it carries.
type cref struct{ op, store, sha1, sha256 string }

func (c cref) ref() winproto.CleanupRef { return winproto.CleanupRef{SHA1: c.sha1, SHA256: c.sha256} }

func (c cref) item(reason string) winproto.CleanupItem {
	return winproto.CleanupItem{Store: c.store, SHA1: c.sha1, SHA256: c.sha256, Reason: reason}
}

func cleanupOp(i int) string { return fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i) }

func newCleanup(t *testing.T) *cleanupFixture {
	t.Helper()
	h := newWriteHost()
	h.now, h.modTimes = testNow, map[string]time.Time{}
	return &cleanupFixture{t: t, h: h, ca: pki.NewCA("Cleanup Test", pki.ECDSA256, testNow)}
}

// put adds a new certificate to store; friendly "alice" is Alice's name for the certificate's operation.
func (f *cleanupFixture) put(store, friendly string, edit ...func(*pki.Opts)) cref {
	f.t.Helper()
	f.n++
	op := cleanupOp(f.n)
	o := pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}
	for _, e := range edit {
		e(&o)
	}
	leaf := f.ca.Issue(o, testNow)
	sha := f.h.addCert(store, leaf.Cert.Raw, true)
	if friendly == "alice" {
		friendly = aliceName(op)
	}
	f.h.mu.Lock()
	c := f.h.certs[[2]string{store, sha}]
	c.FriendlyName = friendly
	f.h.certs[[2]string{store, sha}] = c
	f.h.mu.Unlock()
	return cref{op: op, store: store, sha1: sha, sha256: hexSHA256(leaf.Cert.Raw)}
}

// imported is a certificate Alice imported: its friendly name and its inventory entry.
func (f *cleanupFixture) imported(store string, edit ...func(*pki.Opts)) cref {
	f.t.Helper()
	c := f.put(store, "alice", edit...)
	f.record(c)
	return c
}

func (f *cleanupFixture) record(c cref) {
	f.t.Helper()
	if err := recordImport(f.h, importEntry{Op: c.op, Store: c.store, SHA1: c.sha1, SHA256: c.sha256}); err != nil {
		f.t.Fatal(err)
	}
}

// reset forgets the set-up's writes.
func (f *cleanupFixture) reset() {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	f.h.log, f.h.stateLog, f.h.events, f.h.points = nil, nil, nil, nil
}

func (f *cleanupFixture) advance(d time.Duration) {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	f.h.now = f.h.now.Add(d)
}

func (f *cleanupFixture) clock() time.Time { return f.h.Now() }

func planInput(watch ...cref) []byte {
	refs := []winproto.CleanupRef{}
	for _, c := range watch {
		refs = append(refs, c.ref())
	}
	raw, _ := json.Marshal(winproto.CleanupPlanInput{Watch: refs})
	return raw
}

func applyInput(items ...winproto.CleanupItem) []byte {
	raw, _ := json.Marshal(winproto.CleanupApplyInput{Remove: items})
	return raw
}

func (f *cleanupFixture) call(flag string, in []byte) (Outcome, []byte) {
	f.t.Helper()
	return execute(f.t, context.Background(), f.h, bytes.NewReader(in), winproto.SubIISCleanup, flag)
}

func (f *cleanupFixture) plan(watch ...cref) winproto.CleanupPlanResponse {
	f.t.Helper()
	o, out := f.call(winproto.ArgPlan, planInput(watch...))
	if o.Exit != 0 {
		f.t.Fatalf("plan: %+v %s", o, out)
	}
	var r winproto.CleanupPlanResponse
	if err := json.Unmarshal(out, &r); err != nil {
		f.t.Fatal(err)
	}
	if !r.OK || r.Candidates == nil || r.Watched == nil || r.Warnings == nil {
		f.t.Fatalf("plan answer: %s", out)
	}
	return r
}

func (f *cleanupFixture) apply(items ...winproto.CleanupItem) winproto.CleanupApplyResponse {
	f.t.Helper()
	o, out := f.call(winproto.ArgApply, applyInput(items...))
	if o.Exit != 0 {
		f.t.Fatalf("apply: %+v %s", o, out)
	}
	var r winproto.CleanupApplyResponse
	if err := json.Unmarshal(out, &r); err != nil {
		f.t.Fatal(err)
	}
	if !r.OK || len(r.Results) != len(items) {
		f.t.Fatalf("apply answer: %s", out)
	}
	return r
}

// entries are the inventory's entries for c.
func (f *cleanupFixture) entries(c cref) []importEntry {
	f.t.Helper()
	imp, err := readImports(f.h)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []importEntry
	for _, e := range imp.Imports {
		if e.SHA1 == c.sha1 {
			out = append(out, e)
		}
	}
	return out
}

func (f *cleanupFixture) present(c cref) bool {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	_, ok := f.h.certs[[2]string{c.store, c.sha1}]
	return ok
}

func candidateOf(r winproto.CleanupPlanResponse, c cref) (winproto.CleanupCandidate, bool) {
	for _, x := range r.Candidates {
		if x.SHA1 == c.sha1 {
			return x, true
		}
	}
	return winproto.CleanupCandidate{}, false
}

func watchedOf(r winproto.CleanupPlanResponse, c cref) []winproto.CleanupWatched {
	var out []winproto.CleanupWatched
	for _, w := range r.Watched {
		if w.SHA256 == c.sha256 {
			out = append(out, w)
		}
	}
	return out
}

func removals(log []string) []string {
	var out []string
	for _, l := range log {
		if strings.HasPrefix(l, "remove") {
			out = append(out, l)
		}
	}
	return out
}

// liveJournal is a journal of op in phase naming c as previous (asPrevious) or new.
func liveJournal(op, phase string, c cref, asPrevious bool) journal {
	j := sampleJournal(op)
	j.Phase = phase
	if asPrevious {
		j.Previous.CertSHA1, j.PreviousSHA1, j.PreviousSHA256 = c.sha1, c.sha1, c.sha256
	} else {
		j.NewSHA1, j.NewSHA256 = c.sha1, c.sha256
	}
	return j
}

const winrmApp = "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}"

// TestCleanupKeepsEveryUsedCertificate is Review Focus 1: a certificate something uses, or that is not
// Alice's, is never a candidate, is kept with its reason when watched and when an apply names it,
// however long it has been there; an unused one of Alice's next to it is removed.
func TestCleanupKeepsEveryUsedCertificate(t *testing.T) {
	later := testNow.Add(8 * day) // the second plan's time: the journals are fresh then
	for _, tc := range []struct {
		name   string
		setup  func(f *cleanupFixture) cref
		reason string
	}{
		{"bound by an IIS record", func(f *cleanupFixture) cref {
			c := f.imported("My")
			f.h.setRecord(ipb(443, "My", c.sha1))
			return c
		}, winproto.KeptBound},
		{"bound by a foreign application's record in another store", func(f *cleanupFixture) cref {
			c := f.imported("My")
			b := ipb(5986, "WebHosting", c.sha1)
			b.AppID = winrmApp
			f.h.setRecord(b)
			return c
		}, winproto.KeptBound},
		{"bound by a record with a NULL store", func(f *cleanupFixture) cref {
			c := f.imported("My")
			f.h.setRecord(ipb(8443, "", c.sha1))
			return c
		}, winproto.KeptBound},
		{"the RDP listener's certificate", func(f *cleanupFixture) cref {
			c := f.imported("My")
			f.h.protected.RDP = []string{c.sha1}
			return c
		}, winproto.KeptRDP},
		{"a WinRM listener's certificate", func(f *cleanupFixture) cref {
			c := f.imported("My")
			f.h.protected.WinRM = []string{h1, c.sha1}
			return c
		}, winproto.KeptWinRM},
		{"previous of a writing journal", func(f *cleanupFixture) cref {
			c := f.imported("My")
			mustWrite(t, f.h, liveJournal(op1, winproto.PhaseWriting, c, true))
			f.h.modTimes[journalName(op1)] = later
			return c
		}, winproto.KeptJournal},
		{"new of a prepared journal", func(f *cleanupFixture) cref {
			c := f.imported("My")
			mustWrite(t, f.h, liveJournal(op1, winproto.PhasePrepared, c, false))
			f.h.modTimes[journalName(op1)] = later
			return c
		}, winproto.KeptJournal},
		{"new of a restoring journal", func(f *cleanupFixture) cref {
			c := f.imported("My")
			mustWrite(t, f.h, liveJournal(op1, winproto.PhaseRestoring, c, false))
			f.h.modTimes[journalName(op1)] = later
			return c
		}, winproto.KeptJournal},
		{"previous of a restore_failed journal", func(f *cleanupFixture) cref {
			c := f.imported("My")
			mustWrite(t, f.h, liveJournal(op1, winproto.PhaseRestoreFailed, c, true))
			f.h.modTimes[journalName(op1)] = later
			return c
		}, winproto.KeptJournal},
		{"any certificate while a journal is undecodable", func(f *cleanupFixture) cref {
			c := f.imported("My")
			f.h.state[journalName(op1)] = []byte("{")
			f.h.modTimes[journalName(op1)] = later
			return c
		}, winproto.KeptJournalUnreadable},
		{"any certificate while a journal cannot be read", func(f *cleanupFixture) cref {
			c := f.imported("My")
			f.h.state[journalName(op1)] = []byte("{")
			f.h.modTimes[journalName(op1)] = later
			f.h.readStateErr = nil
			hook := journalName(op1)
			f.h.readStateFn = func(name string) error {
				if name == hook {
					return errors.New("disk")
				}
				return nil
			}
			return c
		}, winproto.KeptJournalUnreadable},
		{"a third party's copy", func(f *cleanupFixture) cref {
			c := f.put("My", "Contoso www")
			f.record(c) // Alice once imported it; someone removed it and added their own copy
			return c
		}, winproto.KeptNotAlice},
		{"a W2 journal's certificate without the existed record", func(f *cleanupFixture) cref {
			c := f.put("My", "alice")
			j := liveJournal(c.op, winproto.PhaseCommitted, c, false)
			j.Store = "My"
			mustWrite(t, f.h, j)
			f.h.modTimes[journalName(c.op)] = later
			return c
		}, winproto.KeptNotAlice},
		{"a journal that met an existing copy", func(f *cleanupFixture) cref {
			c := f.put("My", "alice")
			j := liveJournal(c.op, winproto.PhaseCommitted, c, false)
			j.Store, j.Existed, j.AliceImported = "My", boolPtr(true), false
			mustWrite(t, f.h, j)
			f.h.modTimes[journalName(c.op)] = later
			return c
		}, winproto.KeptNotAlice},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCleanup(t)
			c := tc.setup(f)
			control := f.imported("My") // unused and Alice's
			unreadable := tc.reason == winproto.KeptJournalUnreadable
			f.reset()
			for _, r := range []winproto.CleanupPlanResponse{f.plan(c), func() winproto.CleanupPlanResponse {
				f.advance(8 * day)
				return f.plan(c, control)
			}()} {
				if _, found := candidateOf(r, c); found {
					t.Fatalf("a candidate: %+v", r)
				}
				if w := watchedOf(r, c); len(w) != 1 || w[0].State != winproto.WatchKept || w[0].Reason != tc.reason || w[0].Store != "My" {
					t.Fatalf("watched %+v", r.Watched)
				}
				if unreadable != slices.Contains(r.Warnings, winproto.WarnJournalUnreadable) {
					t.Fatalf("warnings %v", r.Warnings)
				}
				if _, found := candidateOf(r, control); found == unreadable {
					t.Fatalf("control: %+v", r)
				}
			}
			r := f.plan(c, control)
			if cc, _ := candidateOf(r, control); !unreadable && cc.Eligible != winproto.CleanupAged {
				t.Fatalf("control not aged: %+v", r)
			}
			res := f.apply(c.item(winproto.CleanupAged), c.item(winproto.CleanupIncident), c.item(winproto.CleanupExpired),
				control.item(winproto.CleanupAged))
			for _, x := range res.Results[:3] {
				if x.Result != winproto.CleanupKept || x.Reason != tc.reason || x.SHA256 != c.sha256 {
					t.Fatalf("%+v", res)
				}
			}
			if !f.present(c) {
				t.Fatal("the used certificate was removed")
			}
			want := winproto.CleanupResult{SHA256: control.sha256, Result: winproto.CleanupRemoved}
			if unreadable {
				want = winproto.CleanupResult{SHA256: control.sha256, Result: winproto.CleanupKept, Reason: winproto.KeptJournalUnreadable}
			}
			if res.Results[3] != want {
				t.Fatalf("control %+v", res.Results[3])
			}
			for _, l := range removals(f.h.writes()) {
				if strings.HasSuffix(l, c.sha1) {
					t.Fatalf("removed %s", l)
				}
			}
		})
	}
}

// TestUnboundSinceRules is Review Focus 3: the helper's clock decides the age; a certificate used again
// starts over, a stamp in the future is reset, an expired certificate needs no age.
func TestUnboundSinceRules(t *testing.T) {
	t.Run("the first plan stamps now, seven days later it is aged", func(t *testing.T) {
		f := newCleanup(t)
		c := f.imported("My")
		r := f.plan()
		cc, found := candidateOf(r, c)
		if !found || cc.UnboundSince != stamp(testNow) || cc.Eligible != "" || cc.Store != "My" || cc.SHA256 != c.sha256 ||
			cc.FriendlyName != aliceName(c.op) || cc.NotAfter == "" {
			t.Fatalf("%+v", r)
		}
		if e := f.entries(c); len(e) != 1 || e[0].UnboundSince != stamp(testNow) {
			t.Fatalf("%+v", e)
		}
		f.advance(7*day - time.Second)
		if cc, _ := candidateOf(f.plan(), c); cc.Eligible != "" || cc.UnboundSince != stamp(testNow) {
			t.Fatalf("%+v", cc)
		}
		if res := f.apply(c.item(winproto.CleanupAged)); res.Results[0].Reason != winproto.KeptTooYoung {
			t.Fatalf("%+v", res)
		}
		f.advance(time.Second)
		if cc, _ := candidateOf(f.plan(), c); cc.Eligible != winproto.CleanupAged {
			t.Fatalf("%+v", cc)
		}
	})
	t.Run("bound again in between: the stamp is cleared and the wait starts over", func(t *testing.T) {
		f := newCleanup(t)
		c := f.imported("My")
		f.plan()
		f.advance(5 * day)
		f.h.setRecord(ipb(443, "My", c.sha1))
		if _, found := candidateOf(f.plan(), c); found {
			t.Fatal("a bound certificate is a candidate")
		}
		if e := f.entries(c); len(e) != 1 || e[0].UnboundSince != "" {
			t.Fatalf("%+v", e)
		}
		f.h.wmu.Lock()
		delete(f.h.records, canon443)
		f.h.wmu.Unlock()
		f.advance(day)
		restart := f.clock()
		if cc, _ := candidateOf(f.plan(), c); cc.UnboundSince != stamp(restart) || cc.Eligible != "" {
			t.Fatalf("%+v", cc)
		}
		f.advance(6 * day)
		if cc, _ := candidateOf(f.plan(), c); cc.Eligible != "" {
			t.Fatalf("%+v", cc)
		}
		f.advance(day)
		if cc, _ := candidateOf(f.plan(), c); cc.Eligible != winproto.CleanupAged || cc.UnboundSince != stamp(restart) {
			t.Fatalf("%+v", cc)
		}
	})
	t.Run("a stamp in the future is reset to now", func(t *testing.T) {
		f := newCleanup(t)
		c := f.imported("My")
		if err := writeImports(f.h, importsFile{Imports: []importEntry{{Op: c.op, Store: c.store, SHA1: c.sha1, SHA256: c.sha256,
			UnboundSince: stamp(testNow.Add(30 * day))}}}); err != nil {
			t.Fatal(err)
		}
		if res := f.apply(c.item(winproto.CleanupAged)); res.Results[0].Reason != winproto.KeptTooYoung {
			t.Fatalf("%+v", res)
		}
		if cc, _ := candidateOf(f.plan(), c); cc.UnboundSince != stamp(testNow) || cc.Eligible != "" {
			t.Fatalf("%+v", cc)
		}
		if e := f.entries(c); e[0].UnboundSince != stamp(testNow) {
			t.Fatalf("%+v", e)
		}
	})
	t.Run("an entry without a stamp is too young for an apply", func(t *testing.T) {
		f := newCleanup(t)
		c := f.imported("My")
		if res := f.apply(c.item(winproto.CleanupAged)); res.Results[0].Reason != winproto.KeptTooYoung || !f.present(c) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("expired: eligible on the first plan", func(t *testing.T) {
		f := newCleanup(t)
		c := f.imported("My", func(o *pki.Opts) {
			o.NotBefore, o.NotAfter = testNow.Add(-100*day), testNow.Add(-time.Hour)
		})
		young := f.imported("My")
		r := f.plan()
		if cc, _ := candidateOf(r, c); cc.Eligible != winproto.CleanupExpired || cc.NotAfter != stamp(testNow.Add(-time.Hour)) {
			t.Fatalf("%+v", r)
		}
		res := f.apply(young.item(winproto.CleanupExpired), c.item(winproto.CleanupExpired))
		if res.Results[0].Reason != winproto.KeptTooYoung || res.Results[1].Result != winproto.CleanupRemoved {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("incident needs no age", func(t *testing.T) {
		f := newCleanup(t)
		c := f.imported("My")
		if res := f.apply(c.item(winproto.CleanupIncident)); res.Results[0].Result != winproto.CleanupRemoved || f.present(c) {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("a stamp whose wait has passed is kept", func(t *testing.T) {
		f := newCleanup(t)
		c := f.imported("My")
		old := stamp(testNow.Add(-20 * day))
		if err := writeImports(f.h, importsFile{Imports: []importEntry{{Op: c.op, Store: c.store, SHA1: c.sha1, SHA256: c.sha256,
			UnboundSince: old}}}); err != nil {
			t.Fatal(err)
		}
		f.reset()
		if cc, _ := candidateOf(f.plan(), c); cc.UnboundSince != old || cc.Eligible != winproto.CleanupAged {
			t.Fatalf("%+v", cc)
		}
		if len(f.h.writes()) != 0 {
			t.Fatalf("an unchanged inventory was written: %v", f.h.writes())
		}
	})
}

// TestApplyJudgesAgainUnderTheLock is Review Focus 1: an apply acts on the machine as it is, never on
// the plan.
func TestApplyJudgesAgainUnderTheLock(t *testing.T) {
	f := newCleanup(t)
	a, b, c, d := f.imported("My"), f.imported("My"), f.imported("My"), f.imported("My")
	f.plan()
	f.advance(8 * day)
	r := f.plan()
	for _, x := range []cref{a, b, c, d} {
		if cc, _ := candidateOf(r, x); cc.Eligible != winproto.CleanupAged {
			t.Fatalf("%+v", r)
		}
	}
	f.reset()
	f.h.setRecord(ipb(443, "My", a.sha1)) // re-pointed to a after the plan
	f.h.protected.RDP = []string{d.sha1}
	f.h.mu.Lock()
	delete(f.h.certs, [2]string{b.store, b.sha1}) // removed by someone meanwhile
	f.h.mu.Unlock()
	wrong := c.item(winproto.CleanupAged)
	wrong.SHA256 = s256a // another certificate with that thumbprint
	res := f.apply(a.item(winproto.CleanupAged), b.item(winproto.CleanupAged), wrong, d.item(winproto.CleanupIncident))
	want := []winproto.CleanupResult{
		{SHA256: a.sha256, Result: winproto.CleanupKept, Reason: winproto.KeptBound},
		{SHA256: b.sha256, Result: winproto.CleanupAbsent},
		{SHA256: s256a, Result: winproto.CleanupKept, Reason: winproto.KeptNotAlice},
		{SHA256: d.sha256, Result: winproto.CleanupKept, Reason: winproto.KeptRDP},
	}
	if !slices.Equal(res.Results, want) {
		t.Fatalf("%+v", res.Results)
	}
	if len(f.h.writes()) != 0 || !f.present(a) || !f.present(c) || !f.present(d) {
		t.Fatalf("changed: %v", f.h.writes())
	}
	// c is removed; a re-sent apply of it is absent and changes nothing.
	if res := f.apply(c.item(winproto.CleanupAged)); res.Results[0].Result != winproto.CleanupRemoved {
		t.Fatalf("%+v", res)
	}
	f.reset()
	if res := f.apply(c.item(winproto.CleanupAged), c.item(winproto.CleanupIncident)); res.Results[0].Result != winproto.CleanupAbsent ||
		res.Results[1].Result != winproto.CleanupAbsent {
		t.Fatalf("%+v", res)
	}
	if len(f.h.writes()) != 0 {
		t.Fatalf("changed: %v", f.h.writes())
	}
	// A watched certificate: removable when Alice's and unused, absent when no store holds it.
	r = f.plan(d, c, b)
	if w := watchedOf(r, d); len(w) != 1 || w[0].State != winproto.WatchKept || w[0].Reason != winproto.KeptRDP {
		t.Fatalf("%+v", r.Watched)
	}
	for _, x := range []cref{c, b} {
		if w := watchedOf(r, x); len(w) != 1 || w[0].State != winproto.WatchAbsent || w[0].Reason != "" || w[0].SHA1 != x.sha1 {
			t.Fatalf("%+v", r.Watched)
		}
	}
	f.h.protected.RDP = nil
	if w := watchedOf(f.plan(d), d); len(w) != 1 || w[0].State != winproto.WatchRemovable || w[0].Store != "My" {
		t.Fatalf("%+v", w)
	}
}

// TestCleanupWatchLooksInBothStores: a watched certificate is looked up in My and WebHosting, by SHA-1,
// and its DER SHA-256 must match.
func TestCleanupWatchLooksInBothStores(t *testing.T) {
	f := newCleanup(t)
	web := f.imported("WebHosting")
	foreign := f.put("My", "Contoso www")
	r := f.plan(web, foreign, cref{sha1: web.sha1, sha256: s256b})
	if w := watchedOf(r, web); len(w) != 1 || w[0].Store != "WebHosting" || w[0].State != winproto.WatchRemovable {
		t.Fatalf("%+v", r.Watched)
	}
	if w := watchedOf(r, foreign); len(w) != 1 || w[0].State != winproto.WatchKept || w[0].Reason != winproto.KeptNotAlice {
		t.Fatalf("%+v", r.Watched)
	}
	if w := watchedOf(r, cref{sha256: s256b}); len(w) != 1 || w[0].State != winproto.WatchAbsent {
		t.Fatalf("%+v", r.Watched)
	}
	// In both stores: one verdict for each.
	both := f.put("My", "alice")
	f.h.mu.Lock()
	cp := f.h.certs[[2]string{"My", both.sha1}]
	cp.Store = "WebHosting"
	f.h.certs[[2]string{"WebHosting", both.sha1}] = cp
	f.h.mu.Unlock()
	f.record(cref{op: both.op, store: "WebHosting", sha1: both.sha1, sha256: both.sha256})
	w := watchedOf(f.plan(both), both)
	if len(w) != 2 || w[0].Store != "My" || w[0].Reason != winproto.KeptNotAlice || w[1].Store != "WebHosting" ||
		w[1].State != winproto.WatchRemovable {
		t.Fatalf("%+v", w)
	}
	// A copy whose DER does not decode is not Alice's.
	bad := f.imported("My")
	f.h.mu.Lock()
	cp = f.h.certs[[2]string{"My", bad.sha1}]
	cp.DER = "%%%"
	f.h.certs[[2]string{"My", bad.sha1}] = cp
	f.h.mu.Unlock()
	r = f.plan(bad)
	if _, found := candidateOf(r, bad); found || len(watchedOf(r, bad)) != 1 || watchedOf(r, bad)[0].State != winproto.WatchAbsent {
		t.Fatalf("%+v", r)
	}
	if res := f.apply(bad.item(winproto.CleanupIncident)); res.Results[0].Reason != winproto.KeptNotAlice {
		t.Fatalf("%+v", res)
	}
}

// TestApplyRemovesAndRecords: key first, then the certificate, its inventory entry, the binding records'
// chains naming it, event 1003; intermediates stay.
func TestApplyRemovesAndRecords(t *testing.T) {
	f := newCleanup(t)
	a, b, keep := f.imported("My"), f.imported("My"), f.imported("My")
	inter := f.ca.Intermediate.Raw
	f.h.ca[sha1Hex(inter)] = inter
	canon444, _ := winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 444, AppID: app1}.Canonical()
	for _, r := range []bindingRecord{
		{Binding: canon443, Op: op1, Chain: []string{a.sha256, hexSHA256(inter)}},
		{Binding: canon444, Op: op2, Chain: []string{keep.sha256, hexSHA256(inter)}},
	} {
		if err := writeBindingState(f.h, r); err != nil {
			t.Fatal(err)
		}
	}
	f.h.state[bindingsDir+"README"] = []byte("x")
	f.h.state[bindingsDir+strings.Repeat("e", 64)+".json"] = []byte("{")
	f.plan()
	f.advance(8 * day)
	f.plan()
	f.reset()
	res := f.apply(a.item(winproto.CleanupAged), b.item(winproto.CleanupIncident))
	if res.Results[0] != (winproto.CleanupResult{SHA256: a.sha256, Result: winproto.CleanupRemoved}) ||
		res.Results[1] != (winproto.CleanupResult{SHA256: b.sha256, Result: winproto.CleanupRemoved}) {
		t.Fatalf("%+v", res)
	}
	got := removals(f.h.writes())
	want := []string{"remove-key My " + a.sha1, "remove My " + a.sha1, "remove-key My " + b.sha1, "remove My " + b.sha1}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	if f.present(a) || f.present(b) || !f.present(keep) || len(f.entries(a)) != 0 || len(f.entries(b)) != 0 || len(f.entries(keep)) != 1 {
		t.Fatal("removal not recorded")
	}
	if r, err := readBindingState(f.h, canon443); err != nil || r.Op != op1 || r.Chain != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := readBindingState(f.h, canon444); err != nil || r.Op != op2 || len(r.Chain) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if len(f.h.ca) != 1 {
		t.Fatal("an intermediate was touched")
	}
	if len(f.h.events) != 2 {
		t.Fatalf("%+v", f.h.events)
	}
	for i, c := range []struct {
		c      cref
		reason string
	}{{a, "aged"}, {b, "incident"}} {
		e := f.h.events[i]
		text := "removed store My sha1 " + c.c.sha1 + " sha256 " + c.c.sha256 + " reason " + c.reason
		if e.id != 1003 || e.text != text || strings.Contains(e.text, "BEGIN") {
			t.Fatalf("%+v", e)
		}
	}
	// The order of the writes: certificate, the chain, inventory, the event (Ruling 10 as amended).
	log := f.h.writes()
	idx := func(s string) int { return slices.Index(log, s) }
	order := []int{idx("remove My " + a.sha1), idx("state " + bindingRecordName(canon443)), idx("state " + importsName), idx("event 1003")}
	if order[0] < 0 || !slices.IsSorted(order) {
		t.Fatalf("%v", log)
	}
}

// TestRemovalOrderSurvivesAKill is Review Focus 2.
func TestRemovalOrderSurvivesAKill(t *testing.T) {
	setup := func(t *testing.T) (*cleanupFixture, cref) {
		f := newCleanup(t)
		c := f.imported("My")
		f.plan()
		f.advance(8 * day)
		f.plan()
		return f, c
	}
	t.Run("a kill after the removal", func(t *testing.T) {
		f, c := setup(t)
		f.h.pointErr = func(name string) error {
			if name == "cleanup.removed" {
				return errors.New("kill")
			}
			return nil
		}
		var out bytes.Buffer
		if o := Execute(context.Background(), f.h, []string{winproto.SubIISCleanup, winproto.ArgApply},
			bytes.NewReader(applyInput(c.item(winproto.CleanupAged))), &out); !o.Killed || out.Len() != 0 {
			t.Fatalf("%+v %s", o, out.Bytes())
		}
		f.h.pointErr = nil
		if f.present(c) || len(f.entries(c)) != 1 {
			t.Fatal("not removed, or the entry went with it")
		}
		r := f.plan(c)
		if _, found := candidateOf(r, c); found || len(f.entries(c)) != 0 || watchedOf(r, c)[0].State != winproto.WatchAbsent {
			t.Fatalf("%+v %+v", r, f.entries(c))
		}
	})
	t.Run("a kill after the key only", func(t *testing.T) {
		f, c := setup(t)
		f.h.removeAfterKeyErr = errors.New("killed")
		o, out := f.call(winproto.ArgApply, applyInput(c.item(winproto.CleanupAged)))
		wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeOutcomeUnknown)
		f.h.removeAfterKeyErr = nil
		f.h.mu.Lock()
		kept := f.h.certs[[2]string{c.store, c.sha1}]
		f.h.mu.Unlock()
		if !f.present(c) || kept.HasKey || len(f.entries(c)) != 1 {
			t.Fatal("the key was not removed first")
		}
		cc, found := candidateOf(f.plan(), c)
		if !found || cc.Eligible != winproto.CleanupAged {
			t.Fatalf("the keyless certificate is not offered again: %+v", cc)
		}
		f.reset()
		if res := f.apply(c.item(winproto.CleanupAged)); res.Results[0].Result != winproto.CleanupRemoved {
			t.Fatalf("%+v", res)
		}
		if got := removals(f.h.writes()); !slices.Equal(got, []string{"remove My " + c.sha1}) || f.present(c) || len(f.entries(c)) != 0 {
			t.Fatalf("%v", got)
		}
	})
}

// TestCleanupAfterAKillBetweenImportAndInventory: W2's deferred kill window (Ruling 5(b)). A deployment
// killed after ImportPFX, before the inventory names the certificate, leaves only its 0.3.0 journal: the
// certificate is Alice's, kept while that journal is live, adopted into the inventory, and once the
// operation is fenced it ages like any other.
func TestCleanupAfterAKillBetweenImportAndInventory(t *testing.T) {
	f := newFixture(t)
	f.h.now, f.h.modTimes = testNow, map[string]time.Time{journalName(op1): testNow}
	f.h.writeStateErr = func(name string) error {
		if name == importsName {
			return errors.New("disk")
		}
		return nil
	}
	f.h.pointErr = func(name string) error {
		if name == "deploy.import_certificate" {
			return errors.New("kill")
		}
		return nil
	}
	f.killedDeploy(op1, f.input())
	f.h.writeStateErr, f.h.pointErr = nil, nil
	if j := f.journal(op1); j.Phase != winproto.PhasePrepared || j.Existed == nil || *j.Existed || !j.AliceImported {
		t.Fatalf("%+v", j)
	}
	if _, found, _ := f.h.ReadState(importsName); found {
		t.Fatal("the inventory names it")
	}
	c := &cleanupFixture{t: t, h: f.h}
	nw := cref{op: op1, store: "MY", sha1: f.newSHA1, sha256: f.newSHA256}
	r := c.plan()
	if _, found := candidateOf(r, nw); found {
		t.Fatalf("a certificate of a prepared journal is a candidate: %+v", r)
	}
	if e := c.entries(nw); len(e) != 1 || e[0].Op != op1 || e[0].UnboundSince != "" || e[0].SHA256 != f.newSHA256 {
		t.Fatalf("not adopted: %+v", e)
	}
	if res := c.apply(nw.item(winproto.CleanupIncident)); res.Results[0].Reason != winproto.KeptJournal {
		t.Fatalf("%+v", res)
	}
	if _, st, out := f.statusCall(winproto.SubIISFence, op1); st.Phase != winproto.PhaseFenced {
		t.Fatalf("%s", out)
	}
	cc, found := candidateOf(c.plan(), nw)
	if !found || cc.UnboundSince != stamp(testNow) || cc.Eligible != "" {
		t.Fatalf("%+v", cc)
	}
	c.advance(7 * day)
	if cc, _ := candidateOf(c.plan(), nw); cc.Eligible != winproto.CleanupAged {
		t.Fatalf("%+v", cc)
	}
	if res := c.apply(nw.item(winproto.CleanupAged)); res.Results[0].Result != winproto.CleanupRemoved {
		t.Fatalf("%+v", res)
	}
	if _, ok := f.h.record(canon443); !ok || f.current().CertSHA1 != f.oldSHA1 {
		t.Fatal("the binding changed")
	}
}

// TestPrune is Ruling 11.
func TestPrune(t *testing.T) {
	f := newCleanup(t)
	at := func(name string, age time.Duration) { f.h.modTimes[name] = testNow.Add(-age) }
	n := 100
	put := func(phase string, age time.Duration) string {
		n++
		op := cleanupOp(n)
		j := sampleJournal(op)
		j.Phase = phase
		if phase == winproto.PhaseFenced {
			j = journal{Op: op, Phase: phase}
		}
		mustWrite(t, f.h, j)
		at(journalName(op), age)
		return op
	}
	var gone, stay []string
	for _, phase := range []string{winproto.PhaseCommitted, winproto.PhaseUnchanged, winproto.PhaseRestored,
		winproto.PhaseRestoreForbidden, winproto.PhasePrepared, winproto.PhaseFenced} {
		stay = append(stay, put(phase, 6*day))
		gone = append(gone, put(phase, 8*day))
	}
	stay = append(stay, put(winproto.PhaseRestoreFailed, 8*day))
	gone = append(gone, put(winproto.PhaseRestoreFailed, 31*day))
	for _, age := range []time.Duration{8 * day, 31 * day} {
		n++
		op := cleanupOp(n)
		f.h.state[journalName(op)] = []byte("{")
		at(journalName(op), age)
		if age == 8*day {
			stay = append(stay, op)
		} else {
			gone = append(gone, op)
		}
	}
	stay = append(stay, put(winproto.PhaseWriting, 60*day), put(winproto.PhaseRestoring, 60*day))
	// The latest operation of a binding record, and the operation a prepared latest one falls back to.
	latest := put(winproto.PhaseCommitted, 60*day)
	if err := writeBindingRecord(f.h, canon443, latest); err != nil {
		t.Fatal(err)
	}
	canon444, _ := winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 444, AppID: app1}.Canonical()
	base := put(winproto.PhaseCommitted, 60*day)
	n++
	top := cleanupOp(n)
	j := sampleJournal(top)
	j.Binding, j.Locator.Port, j.Previous.Port, j.PrevRecord = canon444, 444, 444, base
	mustWrite(t, f.h, j)
	at(journalName(top), 60*day)
	if err := writeBindingRecord(f.h, canon444, top); err != nil {
		t.Fatal(err)
	}
	stay = append(stay, latest, base, top)
	f.h.state[journalDir+"README"] = []byte("x") // not a journal: never read, never removed
	at(journalDir+"README", 90*day)
	f.reset()
	r := f.plan()
	if r.Pruned != len(gone) || len(r.Warnings) != 1 {
		t.Fatalf("pruned %d, want %d (%v)", r.Pruned, len(gone), r.Warnings)
	}
	for _, op := range gone {
		if _, ok := f.h.state[journalName(op)]; ok {
			t.Fatalf("%s stays", op)
		}
		if !slices.Contains(f.h.writes(), "unlink "+journalName(op)) {
			t.Fatalf("%s was not unlinked", op)
		}
	}
	for _, op := range stay {
		if _, ok := f.h.state[journalName(op)]; !ok {
			t.Fatalf("%s is gone", op)
		}
	}
	if _, ok := f.h.state[journalDir+"README"]; !ok {
		t.Fatal("a foreign file was removed")
	}

	t.Run("a binding record that cannot be read stops pruning, with a warning", func(t *testing.T) {
		f := newCleanup(t)
		mustWrite(t, f.h, sampleJournal(op1))
		f.h.modTimes[journalName(op1)] = testNow.Add(-60 * day)
		f.h.state[bindingsDir+strings.Repeat("d", 64)+".json"] = []byte("{")
		if r := f.plan(); r.Pruned != 0 || !slices.Equal(r.Warnings, []string{winproto.WarnBindingRecordUnreadable}) {
			t.Fatalf("%+v", r)
		}
		f.h.state[bindingsDir+strings.Repeat("d", 64)+".json"] = []byte(`{"binding":"` + canon443 + `","op":""}`) // named for another binding
		if r := f.plan(); r.Pruned != 0 || !slices.Equal(r.Warnings, []string{winproto.WarnBindingRecordUnreadable}) {
			t.Fatalf("%+v", r)
		}
		delete(f.h.state, bindingsDir+strings.Repeat("d", 64)+".json")
		f.h.listStateErr = nil
		failBindings := true
		f.h.listStateFn = func(dir string) error {
			if dir == bindingsDir && failBindings {
				return errors.New("disk")
			}
			return nil
		}
		if r := f.plan(); r.Pruned != 0 || !slices.Equal(r.Warnings, []string{winproto.WarnBindingRecordUnreadable}) {
			t.Fatalf("%+v", r)
		}
		f.h.readStateFn = func(name string) error {
			if strings.HasPrefix(name, bindingsDir) {
				return errors.New("disk")
			}
			return nil
		}
		failBindings = false
		if err := writeBindingRecord(f.h, canon443, ""); err != nil {
			t.Fatal(err)
		}
		if r := f.plan(); r.Pruned != 0 || !slices.Equal(r.Warnings, []string{winproto.WarnBindingRecordUnreadable}) {
			t.Fatalf("%+v", r)
		}
		f.h.readStateFn = nil
		if r := f.plan(); r.Pruned != 1 || len(r.Warnings) != 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("at most MaxPrunePerRun a run, the oldest first", func(t *testing.T) {
		f := newCleanup(t)
		for i := range winproto.MaxPrunePerRun + 1 {
			op := cleanupOp(10000 + i)
			mustWrite(t, f.h, journal{Op: op, Phase: winproto.PhaseFenced})
			f.h.modTimes[journalName(op)] = testNow.Add(-8*day - time.Duration(i)*time.Second)
		}
		if r := f.plan(); r.Pruned != winproto.MaxPrunePerRun {
			t.Fatalf("%d", r.Pruned)
		}
		if _, ok := f.h.state[journalName(cleanupOp(10000))]; !ok || len(f.h.state) != 1 {
			t.Fatalf("%d left", len(f.h.state))
		}
		if r := f.plan(); r.Pruned != 1 {
			t.Fatalf("%d", r.Pruned)
		}
	})
}

// TestCleanupRefusals: every refusal comes before any change.
func TestCleanupRefusals(t *testing.T) {
	item := func(c cref) string {
		b, _ := json.Marshal(c.item(winproto.CleanupAged))
		return string(b)
	}
	for _, tc := range []struct {
		name  string
		args  []string
		input func(c cref) string
		edit  func(f *cleanupFixture)
		exit  int
		code  string
	}{
		{"not elevated", []string{winproto.ArgPlan}, nil, func(f *cleanupFixture) { f.h.elevated = false }, 2, winproto.CodeNotElevated},
		{"both flags", []string{winproto.ArgPlan, winproto.ArgApply}, nil, nil, 2, winproto.CodeUsage},
		{"neither flag", nil, nil, nil, 2, winproto.CodeUsage},
		{"another argument", []string{"--op"}, nil, nil, 2, winproto.CodeUsage},
		{"oversized stdin", []string{winproto.ArgApply}, func(cref) string { return strings.Repeat(" ", winproto.MaxCleanupInput+1) }, nil, 2, winproto.CodeTooLarge},
		{"reason forced", []string{winproto.ArgApply}, func(c cref) string {
			return `{"remove":[{"store":"My","sha1":"` + c.sha1 + `","sha256":"` + c.sha256 + `","reason":"forced"}]}`
		}, nil, 2, winproto.CodeInvalidArgument},
		{"an item's store", []string{winproto.ArgApply}, func(c cref) string {
			return `{"remove":[{"store":"My\\..","sha1":"` + c.sha1 + `","sha256":"` + c.sha256 + `","reason":"aged"}]}`
		}, nil, 2, winproto.CodeInvalidArgument},
		{"no item", []string{winproto.ArgApply}, func(cref) string { return `{"remove":[]}` }, nil, 2, winproto.CodeInvalidArgument},
		{"too many items", []string{winproto.ArgApply}, func(c cref) string {
			return `{"remove":[` + strings.Repeat(item(c)+",", winproto.MaxCleanupItems) + item(c) + `]}`
		}, nil, 2, winproto.CodeInvalidArgument},
		{"apply: syntax", []string{winproto.ArgApply}, func(cref) string { return `{"remove":[` }, nil, 2, winproto.CodeBadContent},
		{"apply: no list", []string{winproto.ArgApply}, func(cref) string { return `{}` }, nil, 2, winproto.CodeBadContent},
		{"apply: a null list", []string{winproto.ArgApply}, func(cref) string { return `{"remove":null}` }, nil, 2, winproto.CodeBadContent},
		{"apply: unknown member", []string{winproto.ArgApply}, func(c cref) string { return `{"remove":[` + item(c) + `],"force":true}` }, nil, 2, winproto.CodeBadContent},
		{"apply: unknown member of an item", []string{winproto.ArgApply}, func(c cref) string {
			return `{"remove":[{"store":"My","sha1":"` + c.sha1 + `","sha256":"` + c.sha256 + `","reason":"aged","x":1}]}`
		}, nil, 2, winproto.CodeBadContent},
		{"apply: duplicate member", []string{winproto.ArgApply}, func(c cref) string { return `{"remove":[` + item(c) + `],"remove":[]}` }, nil, 2, winproto.CodeBadContent},
		{"apply: duplicate member of an item", []string{winproto.ArgApply}, func(c cref) string {
			return `{"remove":[{"store":"My","sha1":"` + c.sha1 + `","sha256":"` + c.sha256 + `","reason":"aged","reason":"incident"}]}`
		}, nil, 2, winproto.CodeBadContent},
		{"apply: a member in another case", []string{winproto.ArgApply}, func(c cref) string { return `{"Remove":[` + item(c) + `]}` }, nil, 2, winproto.CodeBadContent},
		{"apply: trailing data", []string{winproto.ArgApply}, func(c cref) string { return `{"remove":[` + item(c) + `]} {}` }, nil, 2, winproto.CodeBadContent},
		{"apply: not an object", []string{winproto.ArgApply}, func(cref) string { return `[]` }, nil, 2, winproto.CodeBadContent},
		{"apply: empty", []string{winproto.ArgApply}, func(cref) string { return `` }, nil, 2, winproto.CodeBadContent},
		{"plan: no watch", []string{winproto.ArgPlan}, func(cref) string { return `{}` }, nil, 2, winproto.CodeBadContent},
		{"plan: a watch member twice", []string{winproto.ArgPlan}, func(cref) string { return `{"watch":[],"watch":[]}` }, nil, 2, winproto.CodeBadContent},
		{"plan: a ref member twice", []string{winproto.ArgPlan}, func(c cref) string {
			return `{"watch":[{"sha1":"` + c.sha1 + `","sha1":"` + c.sha1 + `","sha256":"` + c.sha256 + `"}]}`
		}, nil, 2, winproto.CodeBadContent},
		{"plan: a bad ref", []string{winproto.ArgPlan}, func(c cref) string { return `{"watch":[{"sha1":"` + c.sha1 + `","sha256":"x"}]}` }, nil, 2, winproto.CodeInvalidArgument},
		{"plan: an upper-case ref", []string{winproto.ArgPlan}, func(c cref) string {
			return `{"watch":[{"sha1":"ABCDEF0123ABCDEF0123ABCDEF0123ABCDEF0123","sha256":"` + c.sha256 + `"}]}`
		}, nil, 2, winproto.CodeInvalidArgument},
		{"plan: too many refs", []string{winproto.ArgPlan}, func(c cref) string {
			r, _ := json.Marshal(c.ref())
			return `{"watch":[` + strings.Repeat(string(r)+",", winproto.MaxForbidden) + string(r) + `]}`
		}, nil, 2, winproto.CodeInvalidArgument},
		{"lock held", []string{winproto.ArgApply}, nil, func(f *cleanupFixture) { f.h.lockHeld = true }, 4, winproto.CodeBusy},
		{"lock fails", []string{winproto.ArgPlan}, nil, func(f *cleanupFixture) { f.h.lockErr = errors.New("x") }, 4, winproto.CodeIOError},
		{"unsafe data directory", []string{winproto.ArgPlan}, nil, func(f *cleanupFixture) { f.h.dataDirErr = ErrJournal }, 4, winproto.CodeJournalFailed},
		{"unreadable registry", []string{winproto.ArgPlan}, nil, func(f *cleanupFixture) { f.h.protectedErr = errors.New("registry") }, 4, winproto.CodeIOError},
		{"unreadable registry (apply)", []string{winproto.ArgApply}, nil, func(f *cleanupFixture) { f.h.protectedErr = errors.New("registry") }, 4, winproto.CodeIOError},
		{"unreadable bindings", []string{winproto.ArgApply}, nil, func(f *cleanupFixture) { f.h.bindingsErr = errors.New("http.sys") }, 4, winproto.CodeIOError},
		{"an undecodable binding", []string{winproto.ArgPlan}, nil, func(f *cleanupFixture) {
			f.h.records["undecodable"] = winproto.SSLBinding{}
		}, 4, winproto.CodeIOError},
		{"an undecodable binding (apply)", []string{winproto.ArgApply}, nil, func(f *cleanupFixture) {
			f.h.records["undecodable"] = winproto.SSLBinding{}
		}, 4, winproto.CodeIOError},
		{"a truncated binding table", []string{winproto.ArgPlan}, nil, func(f *cleanupFixture) { f.h.records = fullTable() }, 4, winproto.CodeIOError},
		{"a truncated binding table (apply)", []string{winproto.ArgApply}, nil, func(f *cleanupFixture) { f.h.records = fullTable() }, 4, winproto.CodeIOError},
		{"journals cannot be listed", []string{winproto.ArgPlan}, nil, func(f *cleanupFixture) { f.h.listStateErr = errors.New("disk") }, 4, winproto.CodeIOError},
		{"inventory cannot be read", []string{winproto.ArgPlan}, nil, func(f *cleanupFixture) { f.h.state[importsName] = []byte("{") }, 4, winproto.CodeIOError},
		{"inventory cannot be read (apply)", []string{winproto.ArgApply}, nil, func(f *cleanupFixture) { f.h.state[importsName] = []byte("{") }, 4, winproto.CodeIOError},
		{"a store cannot be opened", []string{winproto.ArgPlan}, nil, func(f *cleanupFixture) { f.h.certErr = ErrStore }, 4, winproto.CodeStoreError},
		{"a certificate cannot be read", []string{winproto.ArgApply}, nil, func(f *cleanupFixture) { f.h.certErr = errors.New("x") }, 4, winproto.CodeIOError},
		{"a watched certificate cannot be read", []string{winproto.ArgPlan}, func(c cref) string { return string(planInput(c)) }, func(f *cleanupFixture) {
			f.h.certErrs = map[[2]string]error{}
			for k := range f.h.certs {
				f.h.certErrs[[2]string{"WebHosting", k[1]}] = errors.New("x")
			}
		}, 4, winproto.CodeIOError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCleanup(t)
			c := f.imported("My")
			f.plan()
			f.advance(8 * day)
			if tc.edit != nil {
				tc.edit(f)
			}
			f.reset()
			in := ""
			switch {
			case tc.input != nil:
				in = tc.input(c)
			case slices.Contains(tc.args, winproto.ArgApply):
				in = string(applyInput(c.item(winproto.CleanupAged)))
			default:
				in = string(planInput())
			}
			o, out := execute(t, context.Background(), f.h, strings.NewReader(in), append([]string{winproto.SubIISCleanup}, tc.args...)...)
			wantError(t, o.Exit, out, tc.exit, tc.code)
			if w := f.h.writes(); len(w) != 0 || len(f.h.stateLog) != 0 || !f.present(c) {
				t.Fatalf("changed: %v", w)
			}
			if bytes.Contains(out, []byte(c.sha1)) || bytes.Contains(out, []byte("My")) {
				t.Fatalf("the message echoes input: %s", out)
			}
		})
	}
}

// fullTable is MaxBindings+1 ipport records, the most the helper reads of one table: the listing may
// be cut, so iis-cleanup must refuse it.
func fullTable() map[string]winproto.SSLBinding {
	out := map[string]winproto.SSLBinding{}
	for i := range winproto.MaxBindings + 1 {
		out[fmt.Sprintf("0.0.0.0:%d", 1+i)] = winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 1 + i,
			AppID: "{00000000-0000-0000-0000-000000000000}", CertSHA1: strings.Repeat("0", 40)}
	}
	return out
}

// TestCleanupGate is Ruling 12: once the first change is made, every failure is OUTCOME_UNKNOWN.
func TestCleanupGate(t *testing.T) {
	setup := func(t *testing.T) (*cleanupFixture, cref, cref) {
		f := newCleanup(t)
		a, b := f.imported("My"), f.imported("My")
		f.plan()
		f.advance(8 * day)
		f.plan()
		f.reset()
		return f, a, b
	}
	t.Run("a budget that ends after the first removal", func(t *testing.T) {
		lowerBudget(t, 50*time.Millisecond, 2*time.Second)
		f, a, b := setup(t)
		done := make(chan struct{})
		f.h.pointErr = func(name string) error {
			if name == "cleanup.removed" {
				time.Sleep(200 * time.Millisecond)
			}
			return nil
		}
		f.h.wmu.Lock()
		base := f.h.releases
		f.h.wmu.Unlock()
		var out bytes.Buffer
		go func() {
			defer close(done)
			o := Execute(context.Background(), f.h, []string{winproto.SubIISCleanup, winproto.ArgApply},
				bytes.NewReader(applyInput(a.item(winproto.CleanupAged), b.item(winproto.CleanupAged))), &out)
			if !o.Abandoned || o.Exit != winproto.ExitFailed || o.Code != winproto.CodeOutcomeUnknown {
				t.Errorf("%+v %s", o, out.Bytes())
			}
		}()
		<-done
		wantError(t, winproto.ExitFailed, out.Bytes(), winproto.ExitFailed, winproto.CodeOutcomeUnknown)
		// The handler finishes a's step under the grace (the removal is recorded) and starts no other:
		// b is still there when it released the lock.
		deadline := time.Now().Add(5 * time.Second)
		for {
			f.h.wmu.Lock()
			released := f.h.releases
			f.h.wmu.Unlock()
			if released == base+1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the handler did not finish")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if f.present(a) || len(f.entries(a)) != 0 || !f.present(b) || len(f.entries(b)) != 1 ||
			len(removals(f.h.writes())) != 2 {
			t.Fatalf("%v", f.h.writes())
		}
	})
	t.Run("a budget that ends before the first change", func(t *testing.T) {
		lowerBudget(t, 50*time.Millisecond, time.Second)
		f, a, _ := setup(t)
		f.h.bindingBlockFn = func() { time.Sleep(150 * time.Millisecond) }
		o, out := f.call(winproto.ArgApply, applyInput(a.item(winproto.CleanupAged)))
		wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeIOError)
		time.Sleep(200 * time.Millisecond)
		if len(f.h.writes()) != 0 || !f.present(a) {
			t.Fatalf("changed after the budget: %v", f.h.writes())
		}
	})
	for _, tc := range []struct {
		name string
		edit func(f *cleanupFixture)
	}{
		{"the first removal fails", func(f *cleanupFixture) { f.h.removeCertErr = errors.New("x") }},
		{"the inventory cannot be written", func(f *cleanupFixture) {
			f.h.writeStateErr = func(name string) error {
				if name == importsName {
					return errors.New("disk")
				}
				return nil
			}
		}},
		{"the binding records cannot be listed", func(f *cleanupFixture) {
			f.h.listStateFn = func(dir string) error {
				if dir == bindingsDir {
					return errors.New("disk")
				}
				return nil
			}
		}},
		{"a chain cannot be cleared", func(f *cleanupFixture) {
			imp, _ := readImports(f.h)
			if err := writeBindingState(f.h, bindingRecord{Binding: canon443, Chain: []string{imp.Imports[0].SHA256}}); err != nil {
				f.t.Fatal(err)
			}
			f.h.writeStateErr = func(name string) error {
				if strings.HasPrefix(name, bindingsDir) {
					return errors.New("disk")
				}
				return nil
			}
		}},
		{"the second item cannot be read", func(f *cleanupFixture) {
			imp, _ := readImports(f.h)
			f.h.certErrs = map[[2]string]error{{"My", imp.Imports[1].SHA1}: errors.New("x")}
		}},
	} {
		t.Run("apply: "+tc.name, func(t *testing.T) {
			f, a, b := setup(t)
			tc.edit(f)
			o, out := f.call(winproto.ArgApply, applyInput(a.item(winproto.CleanupAged), b.item(winproto.CleanupAged)))
			wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeOutcomeUnknown)
		})
	}
	for _, tc := range []struct {
		name string
		edit func(f *cleanupFixture)
	}{
		{"the inventory cannot be written", func(f *cleanupFixture) {
			f.imported("My") // a new certificate: its stamp is a change
			f.h.writeStateErr = func(name string) error {
				if name == importsName {
					return errors.New("disk")
				}
				return nil
			}
		}},
		{"a journal cannot be removed", func(f *cleanupFixture) {
			mustWrite(f.t, f.h, journal{Op: op1, Phase: winproto.PhaseFenced})
			f.h.modTimes[journalName(op1)] = testNow
			f.h.removeStateErr = func(string) error { return errors.New("disk") }
		}},
	} {
		t.Run("plan: "+tc.name, func(t *testing.T) {
			f, _, _ := setup(t)
			tc.edit(f)
			o, out := f.call(winproto.ArgPlan, planInput())
			wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeOutcomeUnknown)
		})
	}
}

// TestReadJournalsForCleanup: what the cleanup reads of journal/ (Ruling 7), bounded.
func TestReadJournalsForCleanup(t *testing.T) {
	h := newWriteHost()
	old := maxJournalFiles
	maxJournalFiles = 3
	t.Cleanup(func() { maxJournalFiles = old })
	for _, op := range []string{op1, op2, op3, cleanupOp(4)} {
		mustWrite(t, h, journal{Op: op, Phase: winproto.PhaseFenced})
	}
	h.state[journalDir+op1+".json.tmp"] = []byte("{")
	files, err := readJournals(h)
	if err != nil || len(files) != 4 {
		t.Fatalf("%v %+v", err, files)
	}
	for i, f := range files {
		if (i < 3) != f.OK || (i == 3) != f.Unread {
			t.Fatalf("%d %+v", i, f)
		}
	}
}

// TestCleanupPlanBounds: an entry naming another DER is not Alice's; at most MaxCleanupCandidates
// candidates, the oldest stamp first.
func TestCleanupPlanBounds(t *testing.T) {
	t.Run("an entry whose SHA-256 is another certificate's", func(t *testing.T) {
		f := newCleanup(t)
		c := f.put("My", "alice")
		if err := writeImports(f.h, importsFile{Imports: []importEntry{{Op: c.op, Store: c.store, SHA1: c.sha1, SHA256: s256a}}}); err != nil {
			t.Fatal(err)
		}
		f.reset()
		r := f.plan(c)
		if _, found := candidateOf(r, c); found || watchedOf(r, c)[0].Reason != winproto.KeptNotAlice || len(f.h.writes()) != 0 {
			t.Fatalf("%+v %v", r, f.h.writes())
		}
		if res := f.apply(c.item(winproto.CleanupIncident)); res.Results[0].Reason != winproto.KeptNotAlice {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		f := newCleanup(t)
		first := f.imported("My")
		f.plan()
		f.advance(day)
		for range winproto.MaxCleanupCandidates {
			f.imported("WebHosting")
		}
		r := f.plan()
		if !r.Truncated || len(r.Candidates) != winproto.MaxCleanupCandidates || r.Candidates[0].SHA1 != first.sha1 ||
			r.Candidates[0].UnboundSince != stamp(testNow) || r.Candidates[1].UnboundSince != stamp(testNow.Add(day)) {
			t.Fatalf("%v %d %+v", r.Truncated, len(r.Candidates), r.Candidates[0])
		}
	})
}

// goneMeanwhile is a host whose store no longer holds a certificate when RemoveCertificate runs.
type goneMeanwhile struct{ *fakeWriteHost }

func (g goneMeanwhile) RemoveCertificate(context.Context, string, string) (bool, error) {
	return false, nil
}

// TestApplyCertificateGoneAtRemoval: removed by someone between the judgement and the removal: absent,
// its entry dropped, no event.
func TestApplyCertificateGoneAtRemoval(t *testing.T) {
	f := newCleanup(t)
	c := f.imported("My")
	f.reset()
	var out bytes.Buffer
	o := Execute(context.Background(), goneMeanwhile{f.h}, []string{winproto.SubIISCleanup, winproto.ArgApply},
		bytes.NewReader(applyInput(c.item(winproto.CleanupIncident))), &out)
	var r winproto.CleanupApplyResponse
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || o.Exit != 0 || len(r.Results) != 1 ||
		r.Results[0] != (winproto.CleanupResult{SHA256: c.sha256, Result: winproto.CleanupAbsent}) {
		t.Fatalf("%+v %s", o, out.Bytes())
	}
	if len(f.entries(c)) != 0 || len(f.h.events) != 0 {
		t.Fatalf("%+v %+v", f.entries(c), f.h.events)
	}
}

// TestRemovalBookkeepingSurvivesAFailure: a failure between clearing the chains and dropping the
// inventory entry (Ruling 10 as amended) leaves the entry; the next plan settles it, and no binding
// record's chain names the removed leaf.
func TestRemovalBookkeepingSurvivesAFailure(t *testing.T) {
	setup := func(t *testing.T) (*cleanupFixture, cref) {
		f := newCleanup(t)
		c := f.imported("My")
		if err := writeBindingState(f.h, bindingRecord{Binding: canon443, Op: op1, Chain: []string{c.sha256}}); err != nil {
			t.Fatal(err)
		}
		f.reset()
		return f, c
	}
	noChain := func(t *testing.T, f *cleanupFixture) {
		t.Helper()
		if r, err := readBindingState(f.h, canon443); err != nil || r.Op != op1 || r.Chain != nil {
			t.Fatalf("%+v %v", r, err)
		}
	}
	t.Run("the inventory write fails after the chains", func(t *testing.T) {
		f, c := setup(t)
		f.h.writeStateErr = func(name string) error {
			if name == importsName {
				return errors.New("disk")
			}
			return nil
		}
		o, out := f.call(winproto.ArgApply, applyInput(c.item(winproto.CleanupIncident)))
		wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeOutcomeUnknown)
		f.h.writeStateErr = nil
		if f.present(c) || len(f.entries(c)) != 1 || len(f.h.events) != 0 {
			t.Fatal("the entry went, or an event was written")
		}
		noChain(t, f)
		r := f.plan(c)
		if _, found := candidateOf(r, c); found || len(f.entries(c)) != 0 || watchedOf(r, c)[0].State != winproto.WatchAbsent {
			t.Fatalf("%+v", r)
		}
		noChain(t, f)
		if res := f.apply(c.item(winproto.CleanupIncident)); res.Results[0].Result != winproto.CleanupAbsent {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("a kill before the chains: the next plan clears them", func(t *testing.T) {
		f, c := setup(t)
		f.h.pointErr = func(name string) error {
			if name == "cleanup.removed" {
				return errors.New("kill")
			}
			return nil
		}
		var out bytes.Buffer
		if o := Execute(context.Background(), f.h, []string{winproto.SubIISCleanup, winproto.ArgApply},
			bytes.NewReader(applyInput(c.item(winproto.CleanupIncident))), &out); !o.Killed {
			t.Fatalf("%+v", o)
		}
		f.h.pointErr = nil
		if r, _ := readBindingState(f.h, canon443); len(r.Chain) != 1 || len(f.entries(c)) != 1 {
			t.Fatal("changed before the point")
		}
		f.plan()
		noChain(t, f)
		if len(f.entries(c)) != 0 {
			t.Fatal("the entry stays")
		}
	})
	t.Run("the plan's chain clearing fails: OUTCOME_UNKNOWN, the entry stays", func(t *testing.T) {
		f, c := setup(t)
		f.h.mu.Lock()
		delete(f.h.certs, [2]string{c.store, c.sha1})
		f.h.mu.Unlock()
		f.h.writeStateErr = func(name string) error {
			if strings.HasPrefix(name, bindingsDir) {
				return errors.New("disk")
			}
			return nil
		}
		o, out := f.call(winproto.ArgPlan, planInput())
		wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeOutcomeUnknown)
		if len(f.entries(c)) != 1 {
			t.Fatal("the entry went before the chains")
		}
	})
}

// TestPruneCCSBackups (W5 Ruling 16): pruning a CCS journal removes its temporary file, then its backup
// when the backup holds the previous file's bytes, then the journal.
func TestPruneCCSBackups(t *testing.T) {
	f := newCleanup(t)
	f.h.setCCS(ccsFolder, nil)
	old := []byte("the previous file's bytes")
	put := func(op, phase string, age time.Duration, bak []byte) journal {
		j := sampleCCSJournal(op)
		j.Phase, j.CCS.PreviousFileSHA256 = phase, hexSHA256(old)
		if phase == winproto.PhaseRestored {
			j.Steps = append(j.Steps, winproto.Step{Name: winproto.StepRestore, Status: winproto.StepOK})
		}
		mustWrite(t, f.h, j)
		f.h.modTimes[journalName(op)] = testNow.Add(-age)
		f.h.ccsFiles[j.CCS.Temp] = fakeCCSFile{data: []byte("temporary")}
		if bak != nil {
			f.h.ccsFiles[j.CCS.Backup] = fakeCCSFile{data: bak}
		}
		return j
	}
	committed := put(op1, winproto.PhaseCommitted, 8*day, old)
	changed := put(op2, winproto.PhaseCommitted, 8*day, []byte("changed"))
	writing := put(op3, winproto.PhaseWriting, 60*day, old)
	restored := put(cleanupOp(4), winproto.PhaseRestored, 8*day, nil)
	unreadable := put(cleanupOp(5), winproto.PhaseCommitted, 8*day, old)
	young := put(cleanupOp(6), winproto.PhaseCommitted, 6*day, old)
	f.h.ccsReadFn = func(name string) error {
		if name == unreadable.CCS.Backup {
			return errors.New("denied")
		}
		return nil
	}
	f.reset()
	if r := f.plan(); r.Pruned != 3 {
		t.Fatalf("pruned %d", r.Pruned)
	}
	w := f.h.writes()
	i, k, l := slices.Index(w, "ccs-unlink "+committed.CCS.Temp), slices.Index(w, "ccs-unlink "+committed.CCS.Backup),
		slices.Index(w, "unlink "+journalName(op1))
	if i < 0 || k < i || l < k {
		t.Fatalf("order %v", w)
	}
	has := func(name string) bool { _, ok := f.h.ccsFiles[name]; return ok }
	if !has(changed.CCS.Backup) || has(changed.CCS.Temp) || !slices.Contains(w, "unlink "+journalName(op2)) {
		t.Fatal("a changed backup was removed, or its journal kept")
	}
	if !has(writing.CCS.Backup) || !has(writing.CCS.Temp) || slices.Contains(w, "unlink "+journalName(op3)) {
		t.Fatal("a writing journal's files were touched")
	}
	if !slices.Contains(w, "unlink "+journalName(restored.Op)) || slices.Contains(w, "ccs-unlink "+restored.CCS.Backup) {
		t.Fatalf("restored: %v", w)
	}
	if !has(unreadable.CCS.Backup) || !has(unreadable.CCS.Temp) || slices.Contains(w, "unlink "+journalName(unreadable.Op)) {
		t.Fatal("a journal whose backup could not be read was pruned")
	}
	if !has(young.CCS.Backup) || slices.Contains(w, "unlink "+journalName(young.Op)) {
		t.Fatal("a young journal was pruned")
	}

	t.Run("the latest operation of a file keeps its journal, not its backup", func(t *testing.T) {
		f := newCleanup(t)
		newBytes := []byte("the new file's bytes")
		f.h.setCCS(ccsFolder, map[string][]byte{ccsName: newBytes})
		put := func(op, phase, file string, age time.Duration) journal {
			j := sampleCCSJournal(op)
			j.Phase, j.CCS.PreviousFileSHA256, j.CCS.NewFileSHA256 = phase, hexSHA256(old), hexSHA256(newBytes)
			j.Binding, j.CCS.File, j.CCS.Host = ccsRecordKey(file+".pfx"), file+".pfx", file
			j.CCS.Backup = ccsBackupName(j.CCS.File, op)
			if phase == winproto.PhaseRestoreFailed {
				j.Steps = append(j.Steps, winproto.Step{Name: winproto.StepRestore, Status: winproto.StepFailed, Error: winproto.ErrIO})
				j.FailedStep, j.Error = winproto.StepRestore, winproto.ErrIO
			}
			mustWrite(t, f.h, j)
			if err := writeBindingRecord(f.h, j.Binding, op); err != nil {
				t.Fatal(err)
			}
			f.h.modTimes[journalName(op)] = testNow.Add(-age)
			f.h.ccsFiles[j.CCS.Temp] = fakeCCSFile{data: []byte("temporary")}
			f.h.ccsFiles[j.CCS.Backup] = fakeCCSFile{data: old}
			return j
		}
		latest := put(op1, winproto.PhaseCommitted, ccsHost, 8*day)
		// Another file's latest operation, restore_failed 8 days old: its 30 days apply.
		failedJ := put(op2, winproto.PhaseRestoreFailed, "b.example.test", 8*day)
		f.reset()
		if r := f.plan(); r.Pruned != 0 {
			t.Fatalf("pruned %d", r.Pruned)
		}
		has := func(name string) bool { _, ok := f.h.ccsFiles[name]; return ok }
		if has(latest.CCS.Backup) || has(latest.CCS.Temp) {
			t.Fatal("the latest operation's backup or temporary file stays")
		}
		if _, ok := f.h.state[journalName(op1)]; !ok {
			t.Fatal("the latest operation's journal was removed")
		}
		if !has(failedJ.CCS.Backup) || !has(failedJ.CCS.Temp) {
			t.Fatal("a restore_failed journal's files were removed before 30 days")
		}
		// A second plan finds nothing more to remove.
		f.reset()
		f.plan()
		for _, w := range f.h.writes() {
			if strings.HasPrefix(w, "ccs-unlink") || strings.HasPrefix(w, "unlink") {
				t.Fatalf("second plan: %v", f.h.writes())
			}
		}
		// The operation can no longer be rolled back: BACKUP_MISSING, nothing written.
		f.reset()
		o, out := execute(t, context.Background(), f.h, bytes.NewReader(restoreInput([]string{}, []string{})), winproto.SubIISRestore,
			winproto.ArgOp, op1)
		wantError(t, o.Exit, out, winproto.ExitPrecondition, winproto.CodeBackupMissing)
		if len(f.h.writes()) != 0 {
			t.Fatalf("%v", f.h.writes())
		}
	})

	t.Run("a removal that fails", func(t *testing.T) {
		f := newCleanup(t)
		f.h.setCCS(ccsFolder, nil)
		j := sampleCCSJournal(op1)
		mustWrite(t, f.h, j)
		f.h.modTimes[journalName(op1)] = testNow.Add(-8 * day)
		f.h.ccsFiles[j.CCS.Temp] = fakeCCSFile{data: []byte("temporary")}
		o, out := execute(t, context.Background(), failRemoveCCS{f.h}, bytes.NewReader(planInput()), winproto.SubIISCleanup, winproto.ArgPlan)
		wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeOutcomeUnknown)
		if _, ok := f.h.state[journalName(op1)]; !ok {
			t.Fatal("the journal was removed")
		}
	})
}

// failRemoveCCS is a host whose removals in the CCS folder fail.
type failRemoveCCS struct{ *fakeWriteHost }

func (failRemoveCCS) RemoveCCS(context.Context, string, string) error { return errors.New("denied") }
