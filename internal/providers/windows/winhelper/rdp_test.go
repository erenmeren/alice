package winhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

// rdpFixture is the W2 fixture (its CA, the previous certificate in My, the new one to deploy) with the
// RDP-Tcp listener on (TLS, NLA, port 3389) naming the previous certificate, and one self-signed
// certificate in Remote Desktop. With absent, the value is absent: the listener serves the self-signed
// certificate, which is then what an rdp-deploy expects.
type rdpFixture struct {
	*fixture
	self                           pki.Leaf
	selfSHA1, selfSHA256, selfSPKI string
}

func newRDPFixture(t *testing.T, absent bool) *rdpFixture {
	t.Helper()
	f := &rdpFixture{fixture: newFixture(t), self: pki.SelfSigned("WIN-RDP", pki.ECDSA256, testNow)}
	f.selfSHA1 = f.h.addCert(winproto.RDPStoreSelfSigned, f.self.Cert.Raw, true)
	f.selfSHA256 = hexSHA256(f.self.Cert.Raw)
	f.selfSPKI = spkiSHA256(f.self.Cert.PublicKey, f.self.Cert.RawSubjectPublicKeyInfo)
	f.h.rdp = &RDPListener{Enabled: true, NLA: true, Port: 3389, SecurityLayer: 2, CertSHA1: f.oldSHA1}
	if absent {
		f.h.rdp.CertSHA1, f.expect = "", f.selfSHA256
	}
	return f
}

// clearLogs forgets the set-up's writes, the ACL log included.
func (f *rdpFixture) clearLogs() {
	f.reset()
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	f.h.acl = nil
}

func (f *rdpFixture) in(edit ...func(*winproto.RDPDeployInput)) []byte {
	expect := f.oldSHA256
	if f.expect != "" {
		expect = f.expect
	}
	in := winproto.RDPDeployInput{ExpectSHA256: expect, ChainPEM: string(f.nw.FullchainPEM), KeyPEM: string(f.nw.KeyPEM),
		ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}}
	for _, e := range edit {
		e(&in)
	}
	raw, err := json.Marshal(in)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *rdpFixture) rdpDeploy(op string, in []byte) (Outcome, winproto.DeployResponse, []byte) {
	f.t.Helper()
	o, out := execute(f.t, context.Background(), f.h, bytes.NewReader(in), winproto.SubRDPDeploy, winproto.ArgOp, op)
	var r winproto.DeployResponse
	if o.Exit == 0 {
		if err := json.Unmarshal(out, &r); err != nil {
			f.t.Fatal(err)
		}
	}
	return o, r, out
}

func (f *rdpFixture) rdpCommitted(op string, in []byte) winproto.DeployResponse {
	f.t.Helper()
	o, r, out := f.rdpDeploy(op, in)
	if o.Exit != 0 || r.Phase != winproto.PhaseCommitted {
		f.t.Fatalf("rdp-deploy %s: %+v %s", op, o, out)
	}
	return r
}

// value is the listener's SSLCertificateSHA1Hash ("" absent).
func (f *rdpFixture) value() string {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	return f.h.rdp.CertSHA1
}

func (f *rdpFixture) setValue(sha1 string) {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	f.h.rdp.CertSHA1 = sha1
}

// readable reports NETWORK SERVICE's read access to the key of a certificate in My.
func (f *rdpFixture) readable(sha1 string) bool {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	return nsCanRead(f.h.nsACEs[[2]string{"MY", sha1}])
}

func (f *rdpFixture) aclLog() []string {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	return slices.Clone(f.h.acl)
}

// machineWrites are the writes that are not state files of the helper.
func (f *rdpFixture) machineWrites() []string {
	var out []string
	for _, w := range f.h.writes() {
		if !strings.HasPrefix(w, "state ") {
			out = append(out, w)
		}
	}
	return out
}

func rdpDump(t *testing.T, h Host, args ...string) (Outcome, winproto.RDPDumpResponse, []byte) {
	t.Helper()
	o, out := execute(t, context.Background(), h, nil, append([]string{winproto.SubRDPDump}, args...)...)
	var r winproto.RDPDumpResponse
	if o.Exit == 0 {
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatal(err)
		}
	}
	return o, r, out
}

func intPtr(v int) *int { return &v }

func TestRDPDump(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(f *rdpFixture)
		check func(t *testing.T, f *rdpFixture, r winproto.RDPDumpResponse)
	}{
		{"RDP-Tcp absent", func(f *rdpFixture) { f.h.rdp = nil }, func(t *testing.T, f *rdpFixture, r winproto.RDPDumpResponse) {
			if !r.OK || r.Present || r.Certificate != nil || f.h.storeLists != 0 || len(f.h.certReads) != 0 {
				t.Fatalf("%+v lists=%d reads=%v", r, f.h.storeLists, f.h.certReads)
			}
		}},
		{"the value names a certificate in My", func(*rdpFixture) {}, func(t *testing.T, f *rdpFixture, r winproto.RDPDumpResponse) {
			if !r.Present || !r.Enabled || !r.NLA || !r.ValueSet || r.Port != 3389 || r.SecurityLayer != 2 || r.SelfSignedCount != 0 ||
				r.Certificate == nil || r.Certificate.SHA1 != f.oldSHA1 || r.Certificate.Store != "MY" || r.Certificate.DER != b64(f.old.Cert.Raw) ||
				f.h.storeLists != 0 {
				t.Fatalf("%+v %+v", r, r.Certificate)
			}
		}},
		{"the value names a certificate not in My", func(f *rdpFixture) { f.h.rdp.CertSHA1 = strings.Repeat("e", 40) },
			func(t *testing.T, _ *rdpFixture, r winproto.RDPDumpResponse) {
				if !r.ValueSet || r.Certificate != nil || r.SelfSignedCount != 0 {
					t.Fatalf("%+v", r)
				}
			}},
		{"the value absent, Remote Desktop empty", func(f *rdpFixture) {
			f.h.rdp.CertSHA1 = ""
			delete(f.h.certs, [2]string{winproto.RDPStoreSelfSigned, f.selfSHA1})
		}, func(t *testing.T, _ *rdpFixture, r winproto.RDPDumpResponse) {
			if r.ValueSet || r.Certificate != nil || r.SelfSignedCount != 0 {
				t.Fatalf("%+v", r)
			}
		}},
		{"the value absent, two in Remote Desktop", func(f *rdpFixture) {
			f.h.rdp.CertSHA1 = ""
			f.h.addCert(winproto.RDPStoreSelfSigned, pki.SelfSigned("OTHER", pki.ECDSA256, testNow).Cert.Raw, true)
		}, func(t *testing.T, _ *rdpFixture, r winproto.RDPDumpResponse) {
			if r.ValueSet || r.Certificate != nil || r.SelfSignedCount != 2 {
				t.Fatalf("%+v", r)
			}
		}},
		{"the policy overrides the listener", func(f *rdpFixture) {
			f.h.rdpPolicyLayer, f.h.rdpPolicyEnabled, f.h.rdpPolicyNLA = intPtr(0), boolPtr(false), boolPtr(false)
			f.h.rdp.CertTemplate = "RemoteDesktopComputer"
		}, func(t *testing.T, _ *rdpFixture, r winproto.RDPDumpResponse) {
			if r.SecurityLayer != 0 || r.Enabled || r.NLA || r.CertTemplate != "RemoteDesktopComputer" || !r.Present {
				t.Fatalf("%+v", r)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newRDPFixture(t, false)
			c.setup(f)
			o, r, out := rdpDump(t, f.h)
			if o.Exit != 0 {
				t.Fatalf("%+v %s", o, out)
			}
			c.check(t, f, r)
			if len(f.h.writes()) != 0 {
				t.Fatalf("rdp-dump wrote %v", f.h.writes())
			}
		})
	}
}

// TestRDPDumpSelfSigned is Review Focus 3: the value absent, the single certificate of Remote Desktop
// is the current one.
func TestRDPDumpSelfSigned(t *testing.T) {
	f := newRDPFixture(t, true)
	o, r, out := rdpDump(t, f.h)
	if o.Exit != 0 || r.ValueSet || r.SelfSignedCount != 1 || r.Certificate == nil || r.Certificate.SHA1 != f.selfSHA1 ||
		r.Certificate.Store != winproto.RDPStoreSelfSigned || r.Certificate.DER != b64(f.self.Cert.Raw) || r.Certificate.AliceImported {
		t.Fatalf("%+v %s", o, out)
	}
}

func TestRDPDumpRefusals(t *testing.T) {
	f := newRDPFixture(t, false)
	o, _, out := rdpDump(t, f.h, "x")
	wantError(t, o.Exit, out, winproto.ExitRefused, winproto.CodeUsage)
	f.h.elevated = false
	o, _, out = rdpDump(t, f.h)
	wantError(t, o.Exit, out, winproto.ExitRefused, winproto.CodeNotElevated)
	f.h.elevated, f.h.rdpErr = true, errors.New("registry")
	o, _, out = rdpDump(t, f.h)
	wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeIOError)
	f.h.rdpErr, f.h.certErr = nil, ErrStore
	o, _, out = rdpDump(t, f.h)
	wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeStoreError)
	f.h.certErr = nil
	f.setValue("")
	f.h.storeListErr = errors.New("disk")
	o, _, out = rdpDump(t, f.h)
	wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeIOError)
	// A certificate the helper cannot send fails the dump (Alice then marks nothing missing).
	f.h.storeListErr = nil
	c := f.h.certs[[2]string{winproto.RDPStoreSelfSigned, f.selfSHA1}]
	c.DER = "not base64"
	f.h.certs[[2]string{winproto.RDPStoreSelfSigned, f.selfSHA1}] = c
	o, _, out = rdpDump(t, f.h)
	wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeIOError)
}

func TestRDPDeployCommits(t *testing.T) {
	for _, absent := range []bool{false, true} {
		f := newRDPFixture(t, absent)
		f.clearLogs()
		r := f.rdpCommitted(op1, f.in())
		want := []winproto.Step{ok(winproto.StepImportChain), ok(winproto.StepImportCertificate), ok(winproto.StepGrantKeyRead),
			ok(winproto.StepSetListener)}
		prev, prevSHA1, prevStore := f.oldSHA256, f.oldSHA1, "MY"
		if absent {
			prev, prevSHA1, prevStore = f.selfSHA256, f.selfSHA1, winproto.RDPStoreSelfSigned
		}
		if !slices.Equal(r.Steps, want) || r.Store != "MY" || !r.AliceImported || r.NewSHA1 != f.newSHA1 || r.NewSHA256 != f.newSHA256 ||
			r.PreviousSHA1 != prevSHA1 || r.PreviousSHA256 != prev || r.BuiltChainLength != 2 || r.RDPKeyACLLeft {
			t.Fatalf("absent=%v: %+v", absent, r)
		}
		if f.value() != f.newSHA1 || !f.readable(f.newSHA1) || !slices.Equal(f.aclLog(), []string{"grant MY " + f.newSHA1}) {
			t.Fatalf("listener %s readable %v acl %v", f.value(), f.readable(f.newSHA1), f.aclLog())
		}
		j := f.journal(op1)
		if j.Phase != winproto.PhaseCommitted || j.Kind != winproto.JournalKindRDP || j.Binding != winproto.RDPCanonical || j.Store != "MY" ||
			j.RDP == nil || j.RDP.PreviousAbsent != absent || j.RDP.PreviousStore != prevStore || j.RDP.KeyReadHad == nil || *j.RDP.KeyReadHad ||
			j.RDP.ACLLeft || (absent && j.RDP.PreviousSPKISHA256 != f.selfSPKI) || (!absent && j.RDP.PreviousSPKISHA256 != f.oldSPKI) {
			t.Fatalf("journal %+v %+v", j, j.RDP)
		}
		if got := f.phases(op1); !slices.Equal(got, []string{winproto.PhasePrepared, winproto.PhaseWriting, winproto.PhaseCommitted}) {
			t.Fatalf("phases %v", got)
		}
		if rec, err := readBindingState(f.h, winproto.RDPCanonical); err != nil || rec.Op != op1 || len(rec.Chain) != 2 {
			t.Fatalf("record %+v %v", rec, err)
		}
		ev := f.h.events[len(f.h.events)-1]
		if ev.id != 1005 || ev.text != "operation "+op1+" rdp RDP-Tcp old "+prev+" new "+f.newSHA256+" key_read_granted true" {
			t.Fatalf("event %+v", ev)
		}
		for _, e := range f.h.events {
			if strings.Contains(e.text, "PRIVATE") || strings.Contains(e.text, "BEGIN") {
				t.Fatalf("event %+v", e)
			}
		}
		// Every write of the machine is the import, the one ACE and the one value.
		if got := f.machineWrites(); !slices.Equal(got, []string{"intermediate " + f.interSHA1, "import MY " + f.newSHA1,
			"acl grant MY " + f.newSHA1, "rdp-set " + f.newSHA1, "event 1005"}) {
			t.Fatalf("writes %v", got)
		}
	}
}

// TestRDPDeployUnchanged is Ruling 14.
func TestRDPDeployUnchanged(t *testing.T) {
	f := newRDPFixture(t, false)
	f.rdpCommitted(op1, f.in())
	f.expect = f.newSHA256
	f.clearLogs()
	o, r, out := f.rdpDeploy(op2, f.in())
	if o.Exit != 0 || r.Phase != winproto.PhaseUnchanged || r.AliceImported || len(f.machineWrites()) != 0 || len(f.aclLog()) != 0 {
		t.Fatalf("%s %v", out, f.machineWrites())
	}
	if rec, _ := readBindingState(f.h, winproto.RDPCanonical); rec.Op != op2 || len(rec.Chain) != 2 {
		t.Fatalf("record %+v", rec)
	}
	// The key not readable: the grant, then a write of the same value.
	f.h.nsACEs[[2]string{"MY", f.newSHA1}] = nil
	f.clearLogs()
	o, r, out = f.rdpDeploy(op3, f.in())
	if o.Exit != 0 || r.Phase != winproto.PhaseCommitted ||
		!slices.Equal(f.machineWrites(), []string{"acl grant MY " + f.newSHA1, "rdp-set " + f.newSHA1, "event 1005"}) {
		t.Fatalf("%s %v", out, f.machineWrites())
	}
	if ev := f.h.events[len(f.h.events)-1]; !strings.HasSuffix(ev.text, " key_read_granted true") {
		t.Fatal(ev.text)
	}
	// Readable and named, but another chain served: the value is written again, no grant.
	f.h.nsACEs[[2]string{"MY", f.newSHA1}] = []fakeACE{{mask: fakeGrantMask}}
	if err := writeBindingState(f.h, bindingRecord{Binding: winproto.RDPCanonical, Op: op3}); err != nil {
		t.Fatal(err)
	}
	f.clearLogs()
	const op4 = "44444444-4444-4444-8444-444444444444"
	o, r, out = f.rdpDeploy(op4, f.in())
	if o.Exit != 0 || r.Phase != winproto.PhaseCommitted || !slices.Equal(f.machineWrites(), []string{"rdp-set " + f.newSHA1, "event 1005"}) {
		t.Fatalf("%s %v", out, f.machineWrites())
	}
	if ev := f.h.events[len(f.h.events)-1]; !strings.HasSuffix(ev.text, " key_read_granted false") {
		t.Fatal(ev.text)
	}
}

func TestRDPDeployRefusesBeforeAnyWrite(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(f *rdpFixture)
		exit  int
		code  string
	}{
		{"RDP-Tcp absent", func(f *rdpFixture) { f.h.rdp = nil }, winproto.ExitPrecondition, winproto.CodeBindingNotFound},
		{"RDP off", func(f *rdpFixture) { f.h.rdp.Enabled = false }, winproto.ExitPrecondition, winproto.CodeRDPDisabled},
		{"RDP off by policy", func(f *rdpFixture) { f.h.rdpPolicyEnabled = boolPtr(false) }, winproto.ExitPrecondition, winproto.CodeRDPDisabled},
		{"security layer 0", func(f *rdpFixture) { f.h.rdp.SecurityLayer = 0 }, winproto.ExitPrecondition, winproto.CodeRDPTLSOff},
		{"another current leaf", func(f *rdpFixture) { f.expect = s256a }, winproto.ExitPrecondition, winproto.CodeHashMismatch},
		{"the value names a certificate not in My", func(f *rdpFixture) { f.h.rdp.CertSHA1 = strings.Repeat("e", 40) },
			winproto.ExitPrecondition, winproto.CodeHashMismatch},
		{"two self-signed certificates", func(f *rdpFixture) {
			f.h.rdp.CertSHA1, f.expect = "", f.selfSHA256
			f.h.addCert(winproto.RDPStoreSelfSigned, pki.SelfSigned("OTHER", pki.ECDSA256, testNow).Cert.Raw, true)
		}, winproto.ExitPrecondition, winproto.CodeHashMismatch},
		{"no self-signed certificate", func(f *rdpFixture) {
			f.h.rdp.CertSHA1, f.expect = "", f.selfSHA256
			delete(f.h.certs, [2]string{winproto.RDPStoreSelfSigned, f.selfSHA1})
		}, winproto.ExitPrecondition, winproto.CodeHashMismatch},
		{"the new certificate in My without a key", func(f *rdpFixture) { f.h.addCert("MY", f.nw.Cert.Raw, false) },
			winproto.ExitPrecondition, winproto.CodeKeyUnusable},
		{"a known operation", func(f *rdpFixture) { f.rdpCommitted(op1, f.in()); f.setValue(f.oldSHA1) },
			winproto.ExitPrecondition, winproto.CodeOperationExists},
		{"a fenced operation", func(f *rdpFixture) { mustWrite(f.t, f.h, journal{Op: op1, Phase: winproto.PhaseFenced}) },
			winproto.ExitPrecondition, winproto.CodeFenced},
		{"an interrupted latest operation", func(f *rdpFixture) {
			f.h.pointErr = func(name string) error {
				if name == "rdp.writing" {
					return errors.New("kill")
				}
				return nil
			}
			var out bytes.Buffer
			if o := Execute(context.Background(), f.h, []string{winproto.SubRDPDeploy, winproto.ArgOp, op2}, bytes.NewReader(f.in()), &out); !o.Killed {
				f.t.Fatalf("%+v %s", o, out.Bytes())
			}
			f.h.pointErr = nil
		}, winproto.ExitPrecondition, winproto.CodeRecoveryPending},
		{"not elevated", func(f *rdpFixture) { f.h.elevated = false }, winproto.ExitRefused, winproto.CodeNotElevated},
		{"the lock is held", func(f *rdpFixture) { f.h.lockHeld = true }, winproto.ExitFailed, winproto.CodeBusy},
		{"the listener cannot be read", func(f *rdpFixture) { f.h.rdpErr = errors.New("registry") }, winproto.ExitFailed, winproto.CodeIOError},
		{"a store cannot be opened", func(f *rdpFixture) { f.h.certErr = ErrStore }, winproto.ExitFailed, winproto.CodeStoreError},
		{"the new certificate cannot be read", func(f *rdpFixture) { f.h.certErrs = map[[2]string]error{{"MY", f.newSHA1}: errors.New("x")} },
			winproto.ExitFailed, winproto.CodeIOError},
		{"the journal cannot be read", func(f *rdpFixture) { f.h.readStateFn = func(string) error { return errors.New("disk") } },
			winproto.ExitFailed, winproto.CodeIOError},
		{"the binding record cannot be read", func(f *rdpFixture) {
			f.h.state[bindingRecordName(winproto.RDPCanonical)] = []byte("{")
		}, winproto.ExitFailed, winproto.CodeIOError},
		{"a usage error", nil, winproto.ExitRefused, winproto.CodeUsage},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newRDPFixture(t, false)
			args := []string{winproto.SubRDPDeploy, winproto.ArgOp, op1}
			if c.setup == nil {
				args = args[:1]
			} else {
				c.setup(f)
			}
			before := ""
			if f.h.rdp != nil {
				before = f.value()
			}
			f.clearLogs()
			o, out := execute(t, context.Background(), f.h, bytes.NewReader(f.in()), args...)
			wantError(t, o.Exit, out, c.exit, c.code)
			if len(f.h.writes()) != 0 || len(f.aclLog()) != 0 || (f.h.rdp != nil && f.value() != before) {
				t.Fatalf("writes %v acl %v", f.h.writes(), f.aclLog())
			}
		})
	}
}

// TestRDPDeployInputHasNoLocator is Review Focus 1: the input names no listener, store, SID or registry
// path, and it is decoded as strictly as W2's.
func TestRDPDeployInputHasNoLocator(t *testing.T) {
	f := newRDPFixture(t, false)
	good := f.in()
	with := func(member string) []byte { return append(bytes.Clone(good[:len(good)-1]), []byte(","+member+"}")...) }
	for name, c := range map[string]struct {
		in   []byte
		code string
	}{
		"a locator":                  {with(`"locator":{"type":"ipport","ip":"0.0.0.0","port":443,"app_id":"` + app1 + `"}`), winproto.CodeBadContent},
		"a store":                    {with(`"store":"Root"`), winproto.CodeBadContent},
		"a SID":                      {with(`"sid":"S-1-1-0"`), winproto.CodeBadContent},
		"a listener":                 {with(`"listener":"RDP-Tcp"`), winproto.CodeBadContent},
		"a member twice":             {with(`"expect_sha256":"` + s256a + `"`), winproto.CodeBadContent},
		"a member missing":           {[]byte(`{"expect_sha256":"` + s256a + `","chain_pem":"x","key_pem":"y","forbidden_spki_sha256":[]}`), winproto.CodeBadContent},
		"data after the object":      {append(bytes.Clone(good), 'x'), winproto.CodeBadContent},
		"not an object":              {[]byte(`[]`), winproto.CodeBadContent},
		"a member that is no string": {[]byte(strings.Replace(string(good), `"expect_sha256":"`, `"expect_sha256":1,"x":"`, 1)), winproto.CodeBadContent},
		"an expected hash":           {f.in(func(in *winproto.RDPDeployInput) { in.ExpectSHA256 = "ABC" }), winproto.CodeInvalidArgument},
		"a forbidden list":           {f.in(func(in *winproto.RDPDeployInput) { in.ForbiddenLeaf = []string{"x"} }), winproto.CodeInvalidArgument},
		"no certificate":             {f.in(func(in *winproto.RDPDeployInput) { in.ChainPEM = "" }), winproto.CodeBadContent},
		"another key":                {f.in(func(in *winproto.RDPDeployInput) { in.KeyPEM = string(f.old.KeyPEM) }), winproto.CodeBadContent},
	} {
		t.Run(name, func(t *testing.T) {
			f.clearLogs()
			o, out := execute(t, context.Background(), f.h, bytes.NewReader(c.in), winproto.SubRDPDeploy, winproto.ArgOp, op1)
			wantError(t, o.Exit, out, winproto.ExitRefused, c.code)
			if len(f.h.writes()) != 0 {
				t.Fatalf("%v", f.h.writes())
			}
		})
	}
	o, out := execute(t, context.Background(), f.h, bytes.NewReader(make([]byte, winproto.MaxDeployInput+1)), winproto.SubRDPDeploy, winproto.ArgOp, op1)
	wantError(t, o.Exit, out, winproto.ExitRefused, winproto.CodeTooLarge)
	// White space around the object is accepted.
	if o, r, out := f.rdpDeploy(op1, append(append([]byte(" \n"), good...), '\n')); o.Exit != 0 || r.Phase != winproto.PhaseCommitted {
		t.Fatalf("%s", out)
	}
}

// TestRDPGrantOnlyTheListenersKey is Review Focus 1: one grant, on the key of the certificate the
// listener gets, in My.
func TestRDPGrantOnlyTheListenersKey(t *testing.T) {
	t.Run("an import", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.nsACEs = map[[2]string][]fakeACE{}
		f.rdpCommitted(op1, f.in())
		if !slices.Equal(f.aclLog(), []string{"grant MY " + f.newSHA1}) || len(f.h.nsACEs) != 1 {
			t.Fatalf("%v %v", f.aclLog(), f.h.nsACEs)
		}
	})
	t.Run("an existing copy", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.addCert("MY", f.nw.Cert.Raw, true)
		r := f.rdpCommitted(op1, f.in())
		if r.AliceImported || !slices.Equal(f.aclLog(), []string{"grant MY " + f.newSHA1}) {
			t.Fatalf("%+v %v", r, f.aclLog())
		}
	})
	t.Run("an import that met a copy someone added", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.pointErr = func(name string) error {
			if name == "rdp.import_chain" {
				f.h.addCert("MY", f.nw.Cert.Raw, true)
			}
			return nil
		}
		r := f.rdpCommitted(op1, f.in())
		if r.AliceImported || !slices.Equal(f.aclLog(), []string{"grant MY " + f.newSHA1}) || f.value() != f.newSHA1 {
			t.Fatalf("%+v %v", r, f.aclLog())
		}
		if j := f.journal(op1); j.AliceImported || j.Existed == nil || *j.Existed {
			t.Fatalf("%+v", j)
		}
	})
	t.Run("an import that failed grants nothing", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.importErr = ErrStore
		o, r, out := f.rdpDeploy(op1, f.in())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepImportCertificate || len(f.aclLog()) != 0 ||
			f.value() != f.oldSHA1 {
			t.Fatalf("%s %v", out, f.aclLog())
		}
		if j := f.journal(op1); j.RDP.KeyReadHad != nil {
			t.Fatalf("%+v", j.RDP)
		}
	})
	t.Run("a failed import_chain grants nothing", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.addIntermediateErr = errors.New("ca")
		o, r, out := f.rdpDeploy(op1, f.in())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepImportChain || len(f.aclLog()) != 0 {
			t.Fatalf("%s %v", out, f.aclLog())
		}
	})
}

func TestRDPGrantFails(t *testing.T) {
	for _, readFails := range []bool{false, true} {
		f := newRDPFixture(t, false)
		if readFails {
			f.h.keyReadErr = errors.New("ncrypt")
		} else {
			f.h.keyACLErr = func(grant bool) error {
				if grant {
					return errors.New("ncrypt")
				}
				return nil
			}
		}
		f.clearLogs()
		o, r, out := f.rdpDeploy(op1, f.in())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepGrantKeyRead || r.CauseStep != winproto.StepGrantKeyRead ||
			r.Error != winproto.ErrKeyACL || r.RDPKeyACLLeft {
			t.Fatalf("%s", out)
		}
		if f.value() != f.oldSHA1 || f.readable(f.newSHA1) || slices.ContainsFunc(f.h.writes(), func(s string) bool { return strings.HasPrefix(s, "rdp-") }) {
			t.Fatalf("the listener or the key changed: %v", f.h.writes())
		}
		// A grant that failed is taken back all the same (whatever part of it was done).
		if want := []string(nil); !readFails {
			want = []string{"revoke MY " + f.newSHA1}
			if !slices.Equal(f.aclLog(), want) {
				t.Fatalf("acl %v", f.aclLog())
			}
		}
		if j := f.journal(op1); j.Phase != winproto.PhaseRestored || (readFails != (j.RDP.KeyReadHad == nil)) {
			t.Fatalf("%+v %+v", j, j.RDP)
		}
		// Not an interrupted operation: the next deployment runs.
		f.h.keyReadErr, f.h.keyACLErr = nil, nil
		f.rdpCommitted(op2, f.in())
	}
	t.Run("the take-back fails too", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.keyACLErr = func(bool) error { return errors.New("ncrypt") }
		if o, r, out := f.rdpDeploy(op1, f.in()); o.Exit != 0 || r.Phase != winproto.PhaseRestored || !r.RDPKeyACLLeft {
			t.Fatalf("%s", out)
		}
	})
}

// TestRDPDeployReadBackRestores: a failed set_listener is restored under the guard, the ACE revoked.
func TestRDPDeployReadBackRestores(t *testing.T) {
	t.Run("the value reads back other bytes", func(t *testing.T) {
		f := newRDPFixture(t, false)
		// Read 1 is the listener's check, 2 the read-back after the write.
		f.h.rdpReadFn = func(n int, l RDPListener) RDPListener {
			if n == 2 {
				l.CertSHA1 = strings.Repeat("e", 40)
			}
			return l
		}
		o, r, out := f.rdpDeploy(op1, f.in())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepSetListener || r.Error != winproto.ErrReadBack ||
			!slices.Equal(r.Steps[len(r.Steps)-2:], []winproto.Step{bad(winproto.StepSetListener, winproto.ErrReadBack), ok(winproto.StepRestore)}) {
			t.Fatalf("%s", out)
		}
		if f.value() != f.oldSHA1 || f.readable(f.newSHA1) || !slices.Equal(f.aclLog(), []string{"grant MY " + f.newSHA1, "revoke MY " + f.newSHA1}) {
			t.Fatalf("listener %s acl %v", f.value(), f.aclLog())
		}
		if f.h.events[len(f.h.events)-1].id != 1002 {
			t.Fatal("no restore event")
		}
	})
	t.Run("the write fails", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.rdpSetErr = errors.New("registry")
		o, r, out := f.rdpDeploy(op1, f.in())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepSetListener || r.Error != winproto.ErrIO ||
			f.value() != f.oldSHA1 || f.readable(f.newSHA1) {
			t.Fatalf("%s", out)
		}
	})
	t.Run("the committed journal cannot be written", func(t *testing.T) {
		f := newRDPFixture(t, true)
		f.h.phaseErr = []string{winproto.PhaseCommitted}
		o, r, out := f.rdpDeploy(op1, f.in())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepJournal || f.value() != "" || f.readable(f.newSHA1) ||
			!slices.Contains(f.h.writes(), "rdp-delete") {
			t.Fatalf("%s %v", out, f.h.writes())
		}
	})
	t.Run("the restore's write fails", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.rdpReadFn = func(n int, l RDPListener) RDPListener {
			if n == 2 {
				l.CertSHA1 = strings.Repeat("e", 40)
			}
			return l
		}
		f.h.pointErr = func(name string) error {
			if name == "rdp.set" {
				f.h.rdpSetErr = errors.New("registry") // the deployment's write went through, the restore's fails
			}
			return nil
		}
		o, r, out := f.rdpDeploy(op1, f.in())
		// The listener may name the new certificate: its key stays readable.
		if o.Exit != 0 || r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrIO || f.value() != f.newSHA1 || !f.readable(f.newSHA1) {
			t.Fatalf("%s", out)
		}
	})
}

// TestRDPKillAtEveryPoint is Review Focus 1 and 2: wherever the helper dies, iis-status names the phase
// and the listener's certificate, and iis-restore leaves the listener on the previous certificate and
// the key without an ACE this operation added.
func TestRDPKillAtEveryPoint(t *testing.T) {
	type want struct {
		phase   string // "" for no journal
		current string // "old" or "new"
	}
	points := map[string]want{
		"rdp.locked": {"", "old"}, "rdp.prepared": {winproto.PhasePrepared, "old"}, "rdp.import_chain": {winproto.PhasePrepared, "old"},
		"rdp.import_certificate": {winproto.PhasePrepared, "old"},
		"rdp.granted":            {winproto.PhaseWriting, "old"}, "rdp.grant_key_read": {winproto.PhaseWriting, "old"},
		"rdp.writing": {winproto.PhaseWriting, "old"}, "rdp.set": {winproto.PhaseWriting, "new"}, "rdp.read_back": {winproto.PhaseWriting, "new"},
		"rdp.committed":     {winproto.PhaseCommitted, "new"},
		"restore.restoring": {winproto.PhaseRestoring, "new"}, "restore.bound": {winproto.PhaseRestoring, "old"},
		"restore.restored": {winproto.PhaseRestored, "old"},
	}
	f := newRDPFixture(t, false)
	f.rdpCommitted(op1, f.in())
	if !slices.Equal(f.h.points, []string{"rdp.locked", "rdp.prepared", "rdp.import_chain", "rdp.import_certificate", "rdp.granted",
		"rdp.grant_key_read", "rdp.writing", "rdp.set", "rdp.read_back", "rdp.committed"}) {
		t.Fatalf("points %v", f.h.points)
	}
	for _, absent := range []bool{false, true} {
		for p, w := range points {
			t.Run(p, func(t *testing.T) {
				f := newRDPFixture(t, absent)
				prevValue, prevLeaf := f.oldSHA1, f.oldSHA256
				if absent {
					prevValue, prevLeaf = "", f.selfSHA256
				}
				args := []string{winproto.SubRDPDeploy, winproto.ArgOp, op1}
				in := f.in()
				if strings.HasPrefix(p, "restore.") {
					f.rdpCommitted(op1, f.in())
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
				cur := map[string]string{"old": prevLeaf, "new": f.newSHA256}
				_, st, raw := f.statusCall(winproto.SubIISStatus, op1)
				if (w.phase == "" && st.Phase != winproto.PhaseNone) || (w.phase != "" && (st.Phase != w.phase || st.CurrentCertSHA256 != cur[w.current])) {
					t.Fatalf("status %s", raw)
				}
				o, r, raw := f.restore(op1, []string{}, []string{})
				switch w.phase {
				case "":
					wantError(t, o.Exit, raw, winproto.ExitPrecondition, winproto.CodeUnknownOp)
				case winproto.PhasePrepared:
					if r.Phase != winproto.PhasePrepared {
						t.Fatalf("restore: %s", raw)
					}
				default:
					if r.Phase != winproto.PhaseRestored {
						t.Fatalf("restore: %s", raw)
					}
				}
				if f.value() != prevValue || f.readable(f.newSHA1) {
					t.Fatalf("listener %q (want %q), readable %v, acl %v", f.value(), prevValue, f.readable(f.newSHA1), f.aclLog())
				}
				if _, st, _ := f.statusCall(winproto.SubIISStatus, op1); w.phase != "" && st.CurrentCertSHA256 != prevLeaf {
					t.Fatalf("status names %s", st.CurrentCertSHA256)
				}
				// The next deployment is not held up.
				f.rdpCommitted(op2, f.in())
			})
		}
	}
}

func TestRDPRestoreRules(t *testing.T) {
	committed := func(t *testing.T, absent bool) *rdpFixture {
		f := newRDPFixture(t, absent)
		f.rdpCommitted(op1, f.in())
		f.clearLogs()
		return f
	}
	t.Run("a forbidden previous leaf or SPKI", func(t *testing.T) {
		for _, bySPKI := range []bool{false, true} {
			for _, absent := range []bool{false, true} {
				f := committed(t, absent)
				leafHash, spki := f.oldSHA256, f.oldSPKI
				if absent {
					leafHash, spki = f.selfSHA256, f.selfSPKI
				}
				lists := [2][]string{{}, {leafHash}}
				if bySPKI {
					lists = [2][]string{{spki}, {}}
				}
				if _, r, out := f.restore(op1, lists[0], lists[1]); r.Phase != winproto.PhaseRestoreForbidden || r.Error != winproto.ErrForbidden ||
					f.value() != f.newSHA1 || len(f.machineWrites()) != 0 || !f.readable(f.newSHA1) {
					t.Fatalf("%s %v", out, f.machineWrites())
				}
				if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestoreForbidden || f.value() != f.newSHA1 {
					t.Fatalf("%s", out)
				}
			}
		}
	})
	t.Run("a third party re-pointed the listener", func(t *testing.T) {
		for _, v := range []string{strings.Repeat("e", 40), ""} {
			f := committed(t, false)
			f.setValue(v)
			o, _, out := f.restore(op1, []string{}, []string{})
			wantError(t, o.Exit, out, winproto.ExitPrecondition, winproto.CodeSuperseded)
			if len(f.h.writes()) != 0 || f.value() != v {
				t.Fatalf("%v", f.h.writes())
			}
		}
	})
	t.Run("an interrupted operation re-pointed by a third party", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.pointErr = func(name string) error {
			if name == "rdp.read_back" {
				return errors.New("kill")
			}
			return nil
		}
		var out bytes.Buffer
		Execute(context.Background(), f.h, []string{winproto.SubRDPDeploy, winproto.ArgOp, op1}, bytes.NewReader(f.in()), &out)
		f.h.pointErr = nil
		f.setValue(strings.Repeat("e", 40))
		_, r, raw := f.restore(op1, []string{}, []string{})
		if r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrFileChanged || f.value() != strings.Repeat("e", 40) || f.readable(f.newSHA1) {
			t.Fatalf("%s", raw)
		}
	})
	t.Run("a later deployment", func(t *testing.T) {
		f := committed(t, false)
		third := f.ca.Issue(leafOpts, testNow)
		f.rdpCommitted(op2, f.in(func(in *winproto.RDPDeployInput) {
			in.ExpectSHA256, in.ChainPEM, in.KeyPEM = f.newSHA256, string(third.FullchainPEM), string(third.KeyPEM)
		}))
		o, _, out := f.restore(op1, []string{}, []string{})
		wantError(t, o.Exit, out, winproto.ExitPrecondition, winproto.CodeSuperseded)
	})
	t.Run("the previous certificate gone from My", func(t *testing.T) {
		for _, keyless := range []bool{false, true} {
			f := committed(t, false)
			if keyless {
				f.h.addCert("MY", f.old.Cert.Raw, false)
			} else {
				delete(f.h.certs, [2]string{"MY", f.oldSHA1})
			}
			o, _, out := f.restore(op1, []string{}, []string{})
			wantError(t, o.Exit, out, winproto.ExitPrecondition, winproto.CodeBackupMissing)
			if len(f.h.writes()) != 0 || f.value() != f.newSHA1 || !f.readable(f.newSHA1) {
				t.Fatalf("%v", f.h.writes())
			}
		}
	})
	t.Run("the previous value absent and the self-signed certificate gone", func(t *testing.T) {
		f := committed(t, true)
		delete(f.h.certs, [2]string{winproto.RDPStoreSelfSigned, f.selfSHA1})
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored || f.value() != "" ||
			!slices.Equal(f.machineWrites(), []string{"rdp-delete", "acl revoke MY " + f.newSHA1, "event 1002"}) {
			t.Fatalf("%s %v", out, f.machineWrites())
		}
	})
	t.Run("a second restore writes nothing", func(t *testing.T) {
		f := committed(t, false)
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored || f.value() != f.oldSHA1 ||
			!slices.Equal(f.machineWrites(), []string{"rdp-set " + f.oldSHA1, "acl revoke MY " + f.newSHA1, "event 1002"}) {
			t.Fatalf("%s %v", out, f.machineWrites())
		}
		f.clearLogs()
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored || len(f.h.writes()) != 0 {
			t.Fatalf("%s %v", out, f.h.writes())
		}
	})
	t.Run("someone put the previous certificate back", func(t *testing.T) {
		f := committed(t, false)
		f.setValue(f.oldSHA1)
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored ||
			!slices.Equal(f.machineWrites(), []string{"acl revoke MY " + f.newSHA1}) {
			t.Fatalf("%s %v", out, f.machineWrites())
		}
	})
	t.Run("the value reads back other bytes", func(t *testing.T) {
		f := committed(t, false)
		f.h.rdpReadFn = func(_ int, l RDPListener) RDPListener {
			if l.CertSHA1 == f.oldSHA1 {
				l.CertSHA1 = strings.Repeat("e", 40)
			}
			return l
		}
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrReadBack ||
			!f.readable(f.newSHA1) {
			t.Fatalf("%s", out)
		}
	})
	t.Run("the listener cannot be read", func(t *testing.T) {
		f := committed(t, false)
		f.h.rdpErr = errors.New("registry")
		o, _, out := f.restore(op1, []string{}, []string{})
		wantError(t, o.Exit, out, winproto.ExitFailed, winproto.CodeIOError)
		if _, st, _ := f.statusCall(winproto.SubIISStatus, op1); st.CurrentCertSHA256 != "" || st.Phase != winproto.PhaseCommitted {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("RDP-Tcp removed", func(t *testing.T) {
		f := committed(t, false)
		f.h.rdp = nil
		o, _, out := f.restore(op1, []string{}, []string{})
		wantError(t, o.Exit, out, winproto.ExitPrecondition, winproto.CodeSuperseded)
	})
	t.Run("a fence of a committed operation changes nothing", func(t *testing.T) {
		f := committed(t, false)
		if _, r, out := f.statusCall(winproto.SubIISFence, op1); r.Phase != winproto.PhaseCommitted || r.CurrentCertSHA256 != f.newSHA256 ||
			len(f.h.writes()) != 0 {
			t.Fatalf("%s", out)
		}
	})
	t.Run("a fence of a prepared operation", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.pointErr = func(name string) error {
			if name == "rdp.import_certificate" {
				return errors.New("kill")
			}
			return nil
		}
		var out bytes.Buffer
		Execute(context.Background(), f.h, []string{winproto.SubRDPDeploy, winproto.ArgOp, op1}, bytes.NewReader(f.in()), &out)
		f.h.pointErr = nil
		if _, r, raw := f.statusCall(winproto.SubIISFence, op1); r.Phase != winproto.PhaseFenced || len(f.aclLog()) != 0 {
			t.Fatalf("%s", raw)
		}
		o, _, raw := f.rdpDeploy(op1, f.in())
		wantError(t, o.Exit, raw, winproto.ExitPrecondition, winproto.CodeFenced)
		if rec, _ := readBindingRecord(f.h, winproto.RDPCanonical); rec != "" {
			t.Fatalf("the record still names %s", rec)
		}
	})
}

// TestRDPRestoreRevokesOnlyItsGrant is Review Focus 2.
func TestRDPRestoreRevokesOnlyItsGrant(t *testing.T) {
	t.Run("NETWORK SERVICE could read the key already", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.h.addCert("MY", f.nw.Cert.Raw, true)
		f.h.nsACEs = map[[2]string][]fakeACE{{"MY", f.newSHA1}: {{mask: fakeGrantMask}}}
		f.rdpCommitted(op1, f.in())
		if j := f.journal(op1); j.RDP.KeyReadHad == nil || !*j.RDP.KeyReadHad {
			t.Fatalf("%+v", j.RDP)
		}
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored || len(f.aclLog()) != 0 || !f.readable(f.newSHA1) {
			t.Fatalf("%s %v", out, f.aclLog())
		}
	})
	t.Run("the grant was this operation's", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.rdpCommitted(op1, f.in())
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored || r.RDPKeyACLLeft || f.readable(f.newSHA1) ||
			!slices.Equal(f.aclLog(), []string{"grant MY " + f.newSHA1, "revoke MY " + f.newSHA1}) {
			t.Fatalf("%s %v", out, f.aclLog())
		}
	})
	t.Run("the revoke fails", func(t *testing.T) {
		f := newRDPFixture(t, false)
		f.rdpCommitted(op1, f.in())
		f.h.keyACLErr = func(grant bool) error {
			if !grant {
				return errors.New("ncrypt")
			}
			return nil
		}
		_, r, out := f.restore(op1, []string{}, []string{})
		if r.Phase != winproto.PhaseRestored || !r.RDPKeyACLLeft || r.Steps[len(r.Steps)-1] != ok(winproto.StepRestore) || f.value() != f.oldSHA1 {
			t.Fatalf("%s", out)
		}
		if j := f.journal(op1); !j.RDP.ACLLeft {
			t.Fatalf("%+v", j.RDP)
		}
		if !strings.Contains(string(out), `"rdp_key_acl_left":true`) {
			t.Fatalf("%s", out)
		}
	})
}

// TestRDPNoKeyMaterialOutsideStdin: every buffer that held the key is zero after the call, on the
// commit path and the failure paths, and no state file, event or answer holds it.
func TestRDPNoKeyMaterialOutsideStdin(t *testing.T) {
	var kept []*secrets
	old := secretsHook
	secretsHook = func(s *secrets) { kept = append(kept, s) }
	t.Cleanup(func() { secretsHook = old })
	for name, setup := range map[string]func(f *rdpFixture){
		"committed":             func(*rdpFixture) {},
		"the grant fails":       func(f *rdpFixture) { f.h.keyACLErr = func(bool) error { return errors.New("ncrypt") } },
		"refused after parsing": func(f *rdpFixture) { f.h.rdp.SecurityLayer = 0 },
		"the import fails":      func(f *rdpFixture) { f.h.importErr = ErrStore },
	} {
		t.Run(name, func(t *testing.T) {
			kept = nil
			f := newRDPFixture(t, false)
			setup(f)
			var out bytes.Buffer
			Execute(context.Background(), f.h, []string{winproto.SubRDPDeploy, winproto.ArgOp, op1}, bytes.NewReader(f.in()), &out)
			if len(kept) != 1 || len(kept[0].bufs) == 0 {
				t.Fatalf("secrets %d", len(kept))
			}
			for i, b := range kept[0].bufs {
				if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
					t.Fatalf("buffer %d not cleared", i)
				}
			}
			body := strings.Split(string(f.nw.KeyPEM), "\n")[1]
			texts := []string{out.String()}
			for _, w := range f.h.stateLog {
				texts = append(texts, string(w.data))
			}
			for _, e := range f.h.events {
				texts = append(texts, e.text)
			}
			for _, s := range texts {
				if strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, body) {
					t.Fatalf("key material in %.80q", s)
				}
			}
		})
	}
}

// TestRDPRevokeKeepsOtherACEs (review I1): NETWORK SERVICE ACEs the key held before the operation, a
// deny one and an allow one of another mask, survive the grant's revoke, on a restore and on the
// take-back of a failed grant.
func TestRDPRevokeKeepsOtherACEs(t *testing.T) {
	theirs := []fakeACE{{deny: true, mask: fakeGrantMask}, {mask: 0x1}}
	setup := func(t *testing.T) *rdpFixture {
		f := newRDPFixture(t, false)
		f.h.addCert("MY", f.nw.Cert.Raw, true)
		f.h.nsACEs = map[[2]string][]fakeACE{{"MY", f.newSHA1}: slices.Clone(theirs)}
		return f
	}
	t.Run("a restore", func(t *testing.T) {
		f := setup(t)
		f.rdpCommitted(op1, f.in())
		if !f.readable(f.newSHA1) {
			t.Fatal("not granted")
		}
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored {
			t.Fatalf("%s", out)
		}
		if got := f.h.nsACEs[[2]string{"MY", f.newSHA1}]; !slices.Equal(got, theirs) {
			t.Fatalf("ACEs %v, want %v", got, theirs)
		}
	})
	t.Run("a failed grant taken back", func(t *testing.T) {
		f := setup(t)
		f.h.keyACLErr = func(grant bool) error {
			if grant {
				return errors.New("ncrypt")
			}
			return nil
		}
		if o, r, out := f.rdpDeploy(op1, f.in()); o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepGrantKeyRead {
			t.Fatalf("%s", out)
		}
		if got := f.h.nsACEs[[2]string{"MY", f.newSHA1}]; !slices.Equal(got, theirs) || !slices.Equal(f.aclLog(), []string{"revoke MY " + f.newSHA1}) {
			t.Fatalf("ACEs %v, want %v; acl %v", got, theirs, f.aclLog())
		}
	})
	t.Run("a self-restore after the grant", func(t *testing.T) {
		f := setup(t)
		f.h.pointErr = func(name string) error {
			if name == "rdp.granted" {
				f.h.rdpSetErr = errors.New("registry") // set_listener fails after the grant: self-restore revokes
			}
			return nil
		}
		if o, r, out := f.rdpDeploy(op1, f.in()); o.Exit != 0 || r.Phase != winproto.PhaseRestored {
			t.Fatalf("%s", out)
		}
		if got := f.h.nsACEs[[2]string{"MY", f.newSHA1}]; !slices.Equal(got, theirs) {
			t.Fatalf("ACEs %v, want %v", got, theirs)
		}
	})
}

// TestRDPKeyMethodsRefuseOtherStores (review minor 3): the host's key methods act on My only.
func TestRDPKeyMethodsRefuseOtherStores(t *testing.T) {
	f := newRDPFixture(t, false)
	if _, err := f.h.RDPKeyRead(context.Background(), winproto.RDPStoreSelfSigned, f.selfSHA1); err == nil {
		t.Fatal("RDPKeyRead read Remote Desktop")
	}
	if err := f.h.SetRDPKeyRead(context.Background(), winproto.RDPStoreSelfSigned, f.selfSHA1, true); err == nil || len(f.aclLog()) != 0 {
		t.Fatalf("SetRDPKeyRead wrote Remote Desktop: %v %v", err, f.aclLog())
	}
	if _, err := f.h.RDPKeyRead(context.Background(), "MY", f.oldSHA1); err != nil {
		t.Fatal(err)
	}
}

// TestRDPKillOverAnExistingCopy (review minor 2, Ruling 27 item 4): a key Alice did not import, killed
// after the grant, loses that grant at the restore.
func TestRDPKillOverAnExistingCopy(t *testing.T) {
	for _, p := range []string{"rdp.granted", "rdp.grant_key_read"} {
		t.Run(p, func(t *testing.T) {
			f := newRDPFixture(t, false)
			f.h.addCert("MY", f.nw.Cert.Raw, true)
			f.h.pointErr = func(name string) error {
				if name == p {
					return errors.New("kill")
				}
				return nil
			}
			var out bytes.Buffer
			if o := Execute(context.Background(), f.h, []string{winproto.SubRDPDeploy, winproto.ArgOp, op1}, bytes.NewReader(f.in()), &out); !o.Killed {
				t.Fatalf("%+v %s", o, out.Bytes())
			}
			f.h.pointErr = nil
			if j := f.journal(op1); j.AliceImported || j.Phase != winproto.PhaseWriting || j.RDP.KeyReadHad == nil || *j.RDP.KeyReadHad ||
				!f.readable(f.newSHA1) {
				t.Fatalf("%+v %+v", j, j.RDP)
			}
			if _, r, raw := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored {
				t.Fatalf("%s", raw)
			}
			if f.readable(f.newSHA1) || f.value() != f.oldSHA1 ||
				!slices.Equal(f.aclLog(), []string{"grant MY " + f.newSHA1, "revoke MY " + f.newSHA1}) {
				t.Fatalf("readable %v value %s acl %v", f.readable(f.newSHA1), f.value(), f.aclLog())
			}
		})
	}
}
