package winhelper

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // a certificate store's thumbprint is SHA-1
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

func sha1Hex(der []byte) string {
	s := sha1.Sum(der) //nolint:gosec // a thumbprint
	return hex.EncodeToString(s[:])
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// fixture is a host with one IIS record (0.0.0.0:443, a NULL store, every setting set) naming the
// previous certificate, and a new certificate of the same CA to deploy.
type fixture struct {
	t                                      *testing.T
	h                                      *fakeWriteHost
	ca                                     *pki.CA
	old, nw                                pki.Leaf
	oldSHA1, oldSHA256, newSHA1, newSHA256 string
	interSHA1                              string
	rec                                    winproto.SSLBinding
	oldSPKI                                string
	expect                                 string // the expected hash input() sends ("": the previous)
}

var leafOpts = pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ca := pki.NewCA("Deploy Test", pki.ECDSA256, testNow)
	f := &fixture{t: t, h: newWriteHost(), ca: ca, old: ca.Issue(leafOpts, testNow), nw: ca.Issue(leafOpts, testNow)}
	f.oldSHA1 = f.h.addCert("MY", f.old.Cert.Raw, true)
	f.oldSHA256 = hexSHA256(f.old.Cert.Raw)
	f.newSHA1, f.newSHA256 = sha1Hex(f.nw.Cert.Raw), hexSHA256(f.nw.Cert.Raw)
	f.interSHA1 = sha1Hex(ca.Intermediate.Raw)
	f.oldSPKI = spkiSHA256(f.old.Cert.PublicKey, f.old.Cert.RawSubjectPublicKeyInfo)
	f.rec = ipb(443, "", f.oldSHA1)
	f.rec.Flags, f.rec.CertCheckMode, f.rec.RevocationFreshnessTime, f.rec.URLRetrievalTimeout = 0x42, 1, 600, 7000
	f.rec.CTLIdentifier, f.rec.CTLStore = "ctl", "Root"
	f.rec.Extended = []winproto.ExtendedParam{{Type: 1, Data: b64([]byte{1, 2, 3, 4})}, {Type: 5, Data: b64([]byte{9, 8, 7})}}
	f.h.setRecord(f.rec)
	return f
}

// reset forgets the set-up's writes (the logs then hold only what the call under test did).
func (f *fixture) reset() {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	f.h.log, f.h.stateLog, f.h.updates, f.h.events, f.h.points = nil, nil, nil, nil, nil
}

func (f *fixture) input(edit ...func(*winproto.DeployInput)) []byte {
	expect := f.oldSHA256
	if f.expect != "" {
		expect = f.expect
	}
	in := winproto.DeployInput{Locator: loc443(), ExpectSHA256: expect, ChainPEM: string(f.nw.FullchainPEM),
		KeyPEM: string(f.nw.KeyPEM), ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}}
	for _, e := range edit {
		e(&in)
	}
	raw, err := json.Marshal(in)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// killedDeploy runs an iis-deploy that a point kills: no answer.
func (f *fixture) killedDeploy(op string, in []byte) {
	f.t.Helper()
	var out bytes.Buffer
	if o := Execute(context.Background(), f.h, []string{winproto.SubIISDeploy, winproto.ArgOp, op}, bytes.NewReader(in), &out); !o.Killed {
		f.t.Fatalf("not killed: %+v %s", o, out.Bytes())
	}
}

func (f *fixture) deploy(op string, in []byte) (Outcome, winproto.DeployResponse, []byte) {
	f.t.Helper()
	o, out := execute(f.t, context.Background(), f.h, bytes.NewReader(in), winproto.SubIISDeploy, winproto.ArgOp, op)
	var r winproto.DeployResponse
	if o.Exit == 0 {
		if err := json.Unmarshal(out, &r); err != nil {
			f.t.Fatal(err)
		}
	}
	return o, r, out
}

func restoreInput(spki, leaf []string) []byte {
	raw, _ := json.Marshal(winproto.RestoreInput{ForbiddenSPKI: spki, ForbiddenLeaf: leaf})
	return raw
}

func (f *fixture) restoreRaw(op string, in []byte) (Outcome, winproto.RestoreResponse, []byte) {
	f.t.Helper()
	o, out := execute(f.t, context.Background(), f.h, bytes.NewReader(in), winproto.SubIISRestore, winproto.ArgOp, op)
	var r winproto.RestoreResponse
	if o.Exit == 0 {
		if err := json.Unmarshal(out, &r); err != nil {
			f.t.Fatal(err)
		}
	}
	return o, r, out
}

func (f *fixture) restore(op string, spki, leaf []string) (Outcome, winproto.RestoreResponse, []byte) {
	f.t.Helper()
	return f.restoreRaw(op, restoreInput(spki, leaf))
}

func (f *fixture) statusCall(sub, op string) (Outcome, winproto.StatusResponse, []byte) {
	f.t.Helper()
	o, out := execute(f.t, context.Background(), f.h, nil, sub, winproto.ArgOp, op)
	var r winproto.StatusResponse
	if o.Exit == 0 {
		if err := json.Unmarshal(out, &r); err != nil {
			f.t.Fatal(err)
		}
	}
	return o, r, out
}

// phases is the sequence of journal phases op's WriteState calls wrote, repeats folded.
func (f *fixture) phases(op string) []string {
	f.h.wmu.Lock()
	defer f.h.wmu.Unlock()
	var out []string
	for _, w := range f.h.stateLog {
		if w.name != journalName(op) {
			continue
		}
		var j journal
		if err := json.Unmarshal(w.data, &j); err != nil {
			f.t.Fatal(err)
		}
		if len(out) == 0 || out[len(out)-1] != j.Phase {
			out = append(out, j.Phase)
		}
	}
	return out
}

func (f *fixture) journal(op string) journal {
	f.t.Helper()
	j, found, err := readJournal(f.h, op)
	if err != nil || !found {
		f.t.Fatalf("journal of %s: %v %v", op, found, err)
	}
	return j
}

func (f *fixture) current() winproto.SSLBinding {
	f.t.Helper()
	b, ok := f.h.record(canon443)
	if !ok {
		f.t.Fatal("the record is gone")
	}
	return b
}

func (f *fixture) committed(op string) winproto.DeployResponse {
	f.t.Helper()
	o, r, out := f.deploy(op, f.input())
	if o.Exit != 0 || r.Phase != winproto.PhaseCommitted {
		f.t.Fatalf("deploy %s: %+v %s", op, o, out)
	}
	return r
}

func withHash(b winproto.SSLBinding, sha string) winproto.SSLBinding {
	b = cloneBinding(b)
	b.CertSHA1 = sha
	return b
}

func ok(name string) winproto.Step { return winproto.Step{Name: name, Status: winproto.StepOK} }

func bad(name, class string) winproto.Step {
	return winproto.Step{Name: name, Status: winproto.StepFailed, Error: class}
}

func TestDeployCommitsAndJournals(t *testing.T) {
	f := newFixture(t)
	r := f.committed(op1)
	if want := []winproto.Step{ok(winproto.StepImportChain), ok(winproto.StepImportCertificate), ok(winproto.StepBind)}; !reflect.DeepEqual(r.Steps, want) {
		t.Fatalf("steps %+v", r.Steps)
	}
	if !r.OK || r.NewSHA1 != f.newSHA1 || r.NewSHA256 != f.newSHA256 || r.PreviousSHA1 != f.oldSHA1 || r.PreviousSHA256 != f.oldSHA256 ||
		r.Store != "MY" || !r.AliceImported || r.BuiltChainLength != 2 || r.FailedStep != "" || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	if p := f.phases(op1); !reflect.DeepEqual(p, []string{winproto.PhasePrepared, winproto.PhaseWriting, winproto.PhaseCommitted}) {
		t.Fatalf("phases %v", p)
	}
	if got := f.current(); !reflect.DeepEqual(got, withHash(f.rec, f.newSHA1)) || got.Store != "" {
		t.Fatalf("record %+v", got)
	}
	j := f.journal(op1)
	if !j.AliceImported || len(j.Intermediates) != 1 || j.Intermediates[0].SHA1 != f.interSHA1 || !reflect.DeepEqual(j.Previous, f.rec) {
		t.Fatalf("journal %+v", j)
	}
	if _, ok := f.h.ca[f.interSHA1]; !ok {
		t.Fatal("the intermediate is not in CA")
	}
	if len(f.h.events) != 1 || f.h.events[0].id != 1001 || !strings.Contains(f.h.events[0].text, op1) ||
		!strings.Contains(f.h.events[0].text, f.newSHA256) || !strings.Contains(f.h.events[0].text, f.oldSHA256) ||
		!strings.Contains(f.h.events[0].text, canon443) || strings.Contains(f.h.events[0].text, "PRIVATE") {
		t.Fatalf("events %+v", f.h.events)
	}
	imports, err := readImports(f.h)
	if err != nil || len(imports.Imports) != 1 || imports.Imports[0] != (importEntry{Op: op1, Store: "MY", SHA1: f.newSHA1, SHA256: f.newSHA256}) {
		t.Fatalf("%v %+v", err, imports)
	}
	if rec, err := readBindingRecord(f.h, canon443); err != nil || rec != op1 {
		t.Fatal(rec, err)
	}
	if f.h.locks != 1 || f.h.releases != 1 {
		t.Fatalf("locks %d releases %d", f.h.locks, f.h.releases)
	}
	if fn := f.h.friendlyNames; len(fn) != 1 || fn[0] != "Alice www.example.test "+f.nw.Cert.NotAfter.UTC().Format("2006-01-02")+" 11111111" {
		t.Fatalf("friendly names %q", fn)
	}
	// The PFX was imported into the store the record names.
	if c, found := f.h.certs[[2]string{"MY", f.newSHA1}]; !found || !c.HasKey {
		t.Fatal("the new certificate is not in MY")
	}
}

func TestDeployFriendlyNameFallsBack(t *testing.T) {
	ca := pki.NewCA("Name Test", pki.ECDSA256, testNow)
	for _, c := range []struct {
		opts pki.Opts
		want string
	}{
		{pki.Opts{CommonName: "cn.example.test"}, "cn.example.test"},
		{pki.Opts{SANs: []string{"10.0.0.5"}}, "10.0.0.5"},
		{pki.Opts{}, "certificate"},
	} {
		l := ca.Issue(c.opts, testNow)
		if got := friendlyName(l.Cert, op1); got != "Alice "+c.want+" "+l.Cert.NotAfter.UTC().Format("2006-01-02")+" 11111111" {
			t.Errorf("%q", got)
		}
	}
	l := ca.Issue(pki.Opts{CommonName: strings.Repeat("a", 400)}, testNow)
	if got := friendlyName(l.Cert, op1); len(got) > winproto.MaxText {
		t.Errorf("%d", len(got))
	}
}

func TestDeployRefusalsChangeNothing(t *testing.T) {
	ed := pki.SelfSigned("ed.example.test", pki.Ed25519, testNow)
	for _, c := range []struct {
		name    string
		args    []string
		setup   func(f *fixture)
		in      func(f *fixture) []byte
		exit    int
		code    string
		pending string
	}{
		{name: "usage", args: []string{winproto.ArgOp}, exit: 2, code: winproto.CodeUsage},
		{name: "usage flag", args: []string{"--id", op1}, exit: 2, code: winproto.CodeUsage},
		{name: "bad op", args: []string{winproto.ArgOp, "NOT-AN-OP"}, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "mismatched key", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.KeyPEM = string(f.old.KeyPEM) })
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "not JSON", in: func(*fixture) []byte { return []byte("{") }, exit: 2, code: winproto.CodeBadContent},
		{name: "empty", in: func(*fixture) []byte { return nil }, exit: 2, code: winproto.CodeBadContent},
		{name: "unknown member", in: func(f *fixture) []byte {
			return append(bytes.TrimSuffix(f.input(), []byte("}")), []byte(`,"store":"My"}`)...)
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "trailing data", in: func(f *fixture) []byte { return append(f.input(), []byte(" {}")...) }, exit: 2, code: winproto.CodeBadContent},
		{name: "no key", in: func(f *fixture) []byte {
			return []byte(`{"locator":{"type":"ipport","ip":"0.0.0.0","port":443,"app_id":"` + app1 + `"},"expect_sha256":"` +
				f.oldSHA256 + `","chain_pem":"x","forbidden_spki_sha256":[],"forbidden_leaf_sha256":[]}`)
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "chain not PEM", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.ChainPEM = "text " + in.ChainPEM })
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "chain empty", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.ChainPEM = "" })
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "chain with a key block", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.ChainPEM += string(f.nw.KeyPEM) })
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "too many intermediates", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) {
				in.ChainPEM = string(f.nw.CertPEM) + strings.Repeat(string(f.ca.IntermediatePEM), winproto.MaxChainCerts+1)
			})
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "two keys", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.KeyPEM += in.KeyPEM })
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "key with text", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.KeyPEM = "x" + in.KeyPEM })
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "key with headers", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) {
				in.KeyPEM = strings.Replace(in.KeyPEM, "-----\n", "-----\nProc-Type: 4,ENCRYPTED\n\n", 1)
			})
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "Ed25519 key", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.ChainPEM, in.KeyPEM = string(ed.CertPEM), string(ed.KeyPEM) })
		}, exit: 2, code: winproto.CodeBadContent},
		{name: "IDN host", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) {
				in.Locator = winproto.Locator{Type: winproto.BindingHostnamePort, Host: "bücher.example", Port: 443, AppID: app1}
			})
		}, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "ccs", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) {
				in.Locator = winproto.Locator{Type: winproto.BindingCCS, Port: 443, AppID: app1}
			})
		}, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "bad expect", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.ExpectSHA256 = f.oldSHA256[:63] + "A" })
		}, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "bad list", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.ForbiddenLeaf = []string{"zz"} })
		}, exit: 2, code: winproto.CodeInvalidArgument},
		{name: "journal directory", setup: func(f *fixture) { f.h.dataDirErr = ErrJournal }, exit: 4, code: winproto.CodeJournalFailed},
		{name: "busy", setup: func(f *fixture) { f.h.lockHeld = true }, exit: 4, code: winproto.CodeBusy},
		{name: "lock fails", setup: func(f *fixture) { f.h.lockErr = errors.New("lock") }, exit: 4, code: winproto.CodeIOError},
		{name: "operation exists", setup: func(f *fixture) {
			j := sampleJournal(op1)
			j.Phase = winproto.PhaseCommitted
			mustWrite(t, f.h, j)
		}, exit: 3, code: winproto.CodeOperationExists},
		{name: "fenced", setup: func(f *fixture) {
			mustWrite(t, f.h, journal{Op: op1, Phase: winproto.PhaseFenced})
		}, exit: 3, code: winproto.CodeFenced},
		{name: "journal unreadable", setup: func(f *fixture) { f.h.state[journalName(op1)] = []byte("{") }, exit: 4, code: winproto.CodeIOError},
		{name: "state unreadable", setup: func(f *fixture) { f.h.readStateErr = errors.New("disk") }, exit: 4, code: winproto.CodeIOError},
		{name: "recovery pending", setup: func(f *fixture) {
			j := sampleJournal(op2)
			j.Phase = winproto.PhaseWriting
			mustWrite(t, f.h, j)
			_ = writeBindingRecord(f.h, canon443, op2)
		}, exit: 3, code: winproto.CodeRecoveryPending, pending: op2},
		{name: "recovery pending, unreadable", setup: func(f *fixture) {
			f.h.state[journalName(op2)] = []byte("{")
			_ = writeBindingRecord(f.h, canon443, op2)
		}, exit: 3, code: winproto.CodeRecoveryPending, pending: op2},
		{name: "binding record unreadable", setup: func(f *fixture) {
			f.h.state[bindingRecordName(canon443)] = []byte("{")
		}, exit: 4, code: winproto.CodeIOError},
		{name: "binding not found", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.Locator.Port = 8443 })
		}, exit: 3, code: winproto.CodeBindingNotFound},
		{name: "binding unreadable", setup: func(f *fixture) { f.h.bindingErr = errors.New("httpapi") }, exit: 4, code: winproto.CodeIOError},
		{name: "record cannot be written back", setup: func(f *fixture) {
			r := cloneBinding(f.rec)
			r.Extended = append(r.Extended, r.Extended[0])
			f.h.setRecord(r)
		}, exit: 4, code: winproto.CodeIOError},
		{name: "hash mismatch", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.ExpectSHA256 = s256a })
		}, exit: 3, code: winproto.CodeHashMismatch},
		{name: "hash its store lacks", setup: func(f *fixture) { delete(f.h.certs, [2]string{"MY", f.oldSHA1}) }, exit: 3, code: winproto.CodeHashMismatch},
		{name: "record names no hash", setup: func(f *fixture) { f.h.setRecord(withHash(f.rec, "")) }, exit: 3, code: winproto.CodeHashMismatch},
		{name: "store DER unreadable", setup: func(f *fixture) {
			c := f.h.certs[[2]string{"MY", f.oldSHA1}]
			c.DER = "%%"
			f.h.certs[[2]string{"MY", f.oldSHA1}] = c
		}, exit: 3, code: winproto.CodeHashMismatch},
		{name: "store error", setup: func(f *fixture) { f.h.certErr = ErrStore }, exit: 4, code: winproto.CodeStoreError},
		{name: "certificate unreadable", setup: func(f *fixture) { f.h.certErr = errors.New("crypt32") }, exit: 4, code: winproto.CodeIOError},
		{name: "new certificate unreadable", setup: func(f *fixture) {
			f.h.certErrs = map[[2]string]error{{"MY", f.newSHA1}: ErrStore}
		}, exit: 4, code: winproto.CodeStoreError},
		{name: "copy without a key", setup: func(f *fixture) { f.h.addCert("MY", f.nw.Cert.Raw, false) }, exit: 3, code: winproto.CodeKeyUnusable},
		{name: "killed at locked", setup: func(f *fixture) {
			f.h.pointErr = func(string) error { return errors.New("kill") }
		}, exit: ExitKilled},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			if c.setup != nil {
				c.setup(f)
			}
			f.reset()
			in := f.input()
			if c.in != nil {
				in = c.in(f)
			}
			args := c.args
			if args == nil {
				args = []string{winproto.ArgOp, op1}
			}
			var out bytes.Buffer
			o := Execute(context.Background(), f.h, append([]string{winproto.SubIISDeploy}, args...), bytes.NewReader(in), &out)
			if c.exit == ExitKilled {
				if !o.Killed || out.Len() != 0 {
					t.Fatalf("%+v %s", o, out.Bytes())
				}
			} else {
				wantError(t, o.Exit, out.Bytes(), c.exit, c.code)
				var e winproto.ErrorResponse
				_ = json.Unmarshal(out.Bytes(), &e)
				if e.PendingOp != c.pending || strings.Contains(e.Message, "PRIVATE") {
					t.Fatalf("%+v", e)
				}
			}
			if w := f.h.writes(); len(w) != 0 || len(f.h.pfxs) != 0 || len(f.h.events) != 0 {
				t.Fatalf("writes %v", w)
			}
			if f.h.held {
				t.Fatal("the lock is still held")
			}
		})
	}
}

func TestDeployInputParser(t *testing.T) {
	f := newFixture(t)
	good := string(f.input())
	sec := newSecrets()
	defer sec.clear()
	if _, err := parseDeployInput([]byte(good), sec); err != nil {
		t.Fatal(err)
	}
	// Escapes and white space are JSON's; a locator member order is free.
	esc := strings.ReplaceAll(good, `\n`, `\u000a`)
	esc = strings.Replace(esc, `{"locator":{"type":"ipport","ip":"0.0.0.0","port":443,"app_id"`, ` { "locator" : { "app_id" `, 1)
	esc = strings.Replace(esc, `"`+app1+`"}`, `"`+app1+`", "port": 443 , "ip":"0.0.0.0","type":"ipport" }`, 1)
	if _, err := parseDeployInput([]byte(esc+"\n"), sec); err != nil {
		t.Fatalf("%v\n%s", err, esc)
	}
	for _, bad := range []string{
		`[]`, `{}`, `{"locator":1}`, `{"locator":{"type":"ipport","type":"ipport"}}`, `{"locator":{"port":"443"}}`,
		`{"locator":{"port":123456}}`, `{"locator":{"port":-1}}`, `{"locator":{"x":1}}`, `{"locator":{"type":"a"`,
		`{"locator":{"type":"ipport"} "x"}`,
		strings.Replace(good, `"expect_sha256"`, `"locator":{},"expect_sha256"`, 1),
		strings.Replace(good, `"chain_pem":"`, `"chain_pem":"\x01`, 1),
		strings.Replace(good, `"chain_pem":"`, `"chain_pem":"\q`, 1),
		strings.Replace(good, `"chain_pem":"`, `"chain_pem":"\ud800`, 1),
		strings.Replace(good, `"chain_pem":"`, `"chain_pem":"\u12`, 1),
		strings.Replace(good, `"chain_pem":"`, `"chain_pem":"\u12zz`, 1),
		strings.Replace(good, `"forbidden_leaf_sha256":[]`, `"forbidden_leaf_sha256":[1]`, 1),
		strings.Replace(good, `"forbidden_leaf_sha256":[]`, `"forbidden_leaf_sha256":["a" "b"]`, 1),
		strings.Replace(good, `"forbidden_leaf_sha256":[]`, `"forbidden_leaf_sha256":[],"forbidden_leaf_sha256":[]`, 1),
		strings.Replace(good, `"forbidden_spki_sha256":[]`, `"forbidden_spki_sha256":[],"forbidden_spki_sha256":[]`, 1),
		strings.Replace(good, `"key_pem":"`, `"key_pem":"x","key_pem":"`, 1),
		strings.Replace(good, `"chain_pem":"`, `"chain_pem":"x","chain_pem":"`, 1),
		strings.Replace(good, `"expect_sha256":"`, `"expect_sha256":"x","expect_sha256":"`, 1),
		good[:len(good)-30],
		`{"locator":{"type":"` + strings.Repeat("a", 300) + `"}}`,
		strings.Replace(good, `"key_pem":"`, `"key_pem":"\`, 1)[:strings.Index(good, `"key_pem":"`)+12],
	} {
		if _, err := parseDeployInput([]byte(bad), sec); err == nil {
			t.Errorf("accepted %.120q", bad)
		}
	}
	// Too many forbidden hashes.
	many := make([]string, winproto.MaxForbidden+1)
	for i := range many {
		many[i] = hexN(i)
	}
	raw := f.input(func(in *winproto.DeployInput) { in.ForbiddenSPKI = many })
	if _, err := parseDeployInput(raw, sec); err == nil {
		t.Error("accepted too many hashes")
	}
}

func TestDeployKeyForms(t *testing.T) {
	ca := pki.NewCA("Key Test", pki.ECDSA256, testNow)
	rsaLeaf := ca.Issue(pki.Opts{CommonName: "rsa.example.test", KeyType: pki.RSA2048}, testNow)
	ecLeaf := ca.Issue(pki.Opts{CommonName: "ec.example.test", KeyType: pki.ECDSA256}, testNow)
	for _, c := range []struct {
		name string
		leaf pki.Leaf
		key  []byte
		ok   bool
	}{
		{"PKCS #8 RSA", rsaLeaf, rsaLeaf.KeyPEM, true},
		{"PKCS #1", rsaLeaf, pki.KeyPEMPKCS1(rsaLeaf.Key.(*rsa.PrivateKey)), true},
		{"SEC 1", ecLeaf, pki.KeyPEMSEC1(ecLeaf.Key.(*ecdsa.PrivateKey)), true},
		{"CRLF", ecLeaf, bytes.ReplaceAll(ecLeaf.KeyPEM, []byte("\n"), []byte("\r\n")), true},
		{"encrypted", ecLeaf, pki.EncryptedKeyPEM(ecLeaf), false},
		{"other type", ecLeaf, bytes.ReplaceAll(ecLeaf.KeyPEM, []byte("PRIVATE KEY"), []byte("PUBLIC KEY")), false},
		{"bad base64", ecLeaf, bytes.Replace(ecLeaf.KeyPEM, []byte("\n"), []byte("\n!"), 1), false},
		{"no end", ecLeaf, ecLeaf.KeyPEM[:len(ecLeaf.KeyPEM)-10], false},
		{"no begin line end", ecLeaf, []byte("-----BEGIN PRIVATE KEY"), false},
		{"text after", ecLeaf, append(append([]byte{}, ecLeaf.KeyPEM...), 'x'), false},
		{"garbage DER", ecLeaf, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), false},
		{"PKCS #1 garbage", ecLeaf, []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sec := newSecrets()
			defer sec.clear()
			_, err := checkContent(c.leaf.FullchainPEM, c.key, sec)
			if (err == nil) != c.ok {
				t.Fatalf("%v", err)
			}
		})
	}
	// A certificate over MaxCertDER is refused.
	sec := newSecrets()
	defer sec.clear()
	big := pemCert(make([]byte, winproto.MaxCertDER+1))
	if _, err := checkContent(big, ecLeaf.KeyPEM, sec); err == nil {
		t.Fatal("accepted a huge certificate")
	}
	if _, err := checkContent(pemCert([]byte{1, 2, 3}), ecLeaf.KeyPEM, sec); err == nil {
		t.Fatal("accepted a garbage certificate")
	}
	if _, err := checkContent(append(append([]byte{}, ecLeaf.CertPEM...), pemCert([]byte{1})...), ecLeaf.KeyPEM, sec); err == nil {
		t.Fatal("accepted a garbage intermediate")
	}
	hdr := bytes.Replace(ecLeaf.CertPEM, []byte("-----\n"), []byte("-----\nA: b\n\n"), 1)
	if _, err := checkContent(hdr, ecLeaf.KeyPEM, sec); err == nil {
		t.Fatal("accepted a certificate with headers")
	}
}

func pemCert(der []byte) []byte {
	return []byte("-----BEGIN CERTIFICATE-----\n" + b64(der) + "\n-----END CERTIFICATE-----\n")
}

// chain is the new certificate's chain as the binding record keeps it (leaf, intermediate).
func (f *fixture) chain() []string {
	return []string{f.newSHA256, hexSHA256(f.ca.Intermediate.Raw)}
}

// TestDeployUnchanged (Ruling 10, fix round 3): unchanged only when the record names the new
// certificate, no intermediate was added and Alice's last committed bind left this chain served.
func TestDeployUnchanged(t *testing.T) {
	setup := func(t *testing.T, interInCA bool) *fixture {
		f := newFixture(t)
		f.h.addCert("MY", f.nw.Cert.Raw, true)
		f.h.setRecord(withHash(f.rec, f.newSHA1))
		if interInCA {
			f.h.ca[f.interSHA1] = f.ca.Intermediate.Raw
		}
		f.expect = f.newSHA256
		f.reset()
		return f
	}
	served := func(t *testing.T, f *fixture) []string {
		t.Helper()
		r, err := readBindingState(f.h, canon443)
		if err != nil {
			t.Fatal(err)
		}
		return r.Chain
	}
	t.Run("a binding Alice never wrote: one same-hash write, then unchanged", func(t *testing.T) {
		f := setup(t, true)
		o, r, out := f.deploy(op1, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseCommitted || len(f.h.updates) != 1 || f.h.updates[0].CertSHA1 != f.newSHA1 {
			t.Fatalf("%+v %s", o, out)
		}
		if !reflect.DeepEqual(served(t, f), f.chain()) {
			t.Fatal(served(t, f))
		}
		f.reset()
		o, r, out = f.deploy(op2, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseUnchanged || r.AliceImported || len(f.h.updates) != 0 || len(f.h.pfxs) != 0 {
			t.Fatalf("%+v %s updates %d", o, out, len(f.h.updates))
		}
		if p := f.phases(op2); !reflect.DeepEqual(p, []string{winproto.PhasePrepared, winproto.PhaseUnchanged}) {
			t.Fatal(p)
		}
		if len(f.h.events) != 0 {
			t.Fatal(f.h.events)
		}
		if rec, _ := readBindingState(f.h, canon443); rec.Op != op2 || !reflect.DeepEqual(rec.Chain, f.chain()) {
			t.Fatalf("%+v", rec)
		}
		// An unchanged deployment puts back the chain it read: a third deploy is unchanged too.
		f.reset()
		if _, r, out := f.deploy(op3, f.input()); r.Phase != winproto.PhaseUnchanged {
			t.Fatalf("%s", out)
		}
	})
	t.Run("an intermediate added: a same-hash write", func(t *testing.T) {
		f := setup(t, false)
		_ = writeBindingState(f.h, bindingRecord{Binding: canon443, Chain: f.chain()})
		o, r, out := f.deploy(op1, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseCommitted || r.AliceImported || len(f.h.updates) != 1 ||
			f.h.updates[0].CertSHA1 != f.newSHA1 {
			t.Fatalf("%+v %s", o, out)
		}
	})
	t.Run("another chain served: a same-hash write", func(t *testing.T) {
		f := setup(t, true)
		_ = writeBindingState(f.h, bindingRecord{Binding: canon443, Chain: []string{f.newSHA256}})
		if _, r, out := f.deploy(op1, f.input()); r.Phase != winproto.PhaseCommitted || len(f.h.updates) != 1 {
			t.Fatalf("%s", out)
		}
	})
	t.Run("after an interrupted deploy that added an intermediate, the redeploy writes", func(t *testing.T) {
		// Task 9 on real Windows: built 2, served 1 forever if the redeploy answered unchanged.
		f := setup(t, false)
		_ = writeBindingState(f.h, bindingRecord{Binding: canon443, Chain: f.chain()})
		f.h.pointErr = func(n string) error {
			if n == "deploy.writing" {
				return errors.New("kill")
			}
			return nil
		}
		f.killedDeploy(op1, f.input())
		f.h.pointErr = nil
		if c := served(t, f); c != nil {
			t.Fatalf("the chain was not cleared before the bind: %v", c)
		}
		if _, ok := f.h.ca[f.interSHA1]; !ok {
			t.Fatal("the intermediate was not imported")
		}
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored {
			t.Fatalf("%s", out)
		}
		f.reset()
		o, r, out := f.deploy(op2, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseCommitted || len(f.h.updates) != 1 || f.h.updates[0].CertSHA1 != f.newSHA1 {
			t.Fatalf("%+v %s", o, out)
		}
		if !reflect.DeepEqual(served(t, f), f.chain()) {
			t.Fatal(served(t, f))
		}
	})
	// Fix round 4: the chain goes with the prepared write, so a kill at any point of a deployment,
	// even before its bind, leaves the next deployment a same-hash write.
	for _, point := range []string{"deploy.prepared", "deploy.import_chain", "deploy.import_certificate"} {
		t.Run("killed at "+point+", fenced: the next deploy writes", func(t *testing.T) {
			f := setup(t, true)
			_ = writeBindingState(f.h, bindingRecord{Binding: canon443, Op: op3, Chain: f.chain()})
			mustWrite(t, f.h, func() journal {
				j := sampleJournal(op3)
				j.Phase = winproto.PhaseCommitted
				return j
			}())
			f.h.pointErr = func(n string) error {
				if n == point {
					return errors.New("kill")
				}
				return nil
			}
			f.killedDeploy(op1, f.input())
			f.h.pointErr = nil
			if rec, _ := readBindingState(f.h, canon443); rec.Op != op1 || rec.Chain != nil {
				t.Fatalf("taken with its chain: %+v", rec)
			}
			if _, r, out := f.statusCall(winproto.SubIISFence, op1); r.Phase != winproto.PhaseFenced {
				t.Fatalf("%s", out)
			}
			if rec, _ := readBindingState(f.h, canon443); rec.Op != op3 || rec.Chain != nil {
				t.Fatalf("handed back: %+v", rec)
			}
			f.reset()
			if _, r, out := f.deploy(op2, f.input()); r.Phase != winproto.PhaseCommitted || len(f.h.updates) != 1 {
				t.Fatalf("%s", out)
			}
		})
	}
	t.Run("a restore clears the chain", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		if r, _ := readBindingState(f.h, canon443); !reflect.DeepEqual(r.Chain, f.chain()) {
			t.Fatal(r)
		}
		if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored {
			t.Fatalf("%s", out)
		}
		if r, _ := readBindingState(f.h, canon443); r.Op != op1 || r.Chain != nil {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("the chain cannot be cleared before a restore write: OUTCOME_UNKNOWN, nothing restored", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		f.h.writeStateErr = func(n string) error {
			if n == bindingRecordName(canon443) {
				return errors.New("disk")
			}
			return nil
		}
		o, _, out := f.restore(op1, []string{}, []string{})
		wantError(t, o.Exit, out, 4, winproto.CodeOutcomeUnknown)
		if len(f.h.updates) != 1 || f.journal(op1).Phase != winproto.PhaseCommitted {
			t.Fatal("restored or journalled")
		}
	})
	t.Run("the binding record cannot be read before a restore write: OUTCOME_UNKNOWN", func(t *testing.T) {
		f := newFixture(t)
		f.committed(op1)
		n := 0
		f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding {
			if n++; n == 1 {
				f.h.state[bindingRecordName(canon443)] = []byte("{") // read back fails, then the record is unreadable
				b.Flags = 0
			}
			return b
		}
		// A second deployment whose bind reads back wrong: its self-restore cannot clear the chain.
		third := f.ca.Issue(leafOpts, testNow)
		o, _, out := f.deploy(op2, f.input(func(in *winproto.DeployInput) {
			in.ExpectSHA256, in.ChainPEM, in.KeyPEM = f.newSHA256, string(third.FullchainPEM), string(third.KeyPEM)
		}))
		wantError(t, o.Exit, out, 4, winproto.CodeOutcomeUnknown)
	})
}

func TestBindingRecordChain(t *testing.T) {
	h := newWriteHost()
	chain := []string{s256a, s256b}
	if err := writeBindingState(h, bindingRecord{Binding: canon443, Op: op1, Chain: chain}); err != nil {
		t.Fatal(err)
	}
	if r, err := readBindingState(h, canon443); err != nil || r.Op != op1 || !reflect.DeepEqual(r.Chain, chain) {
		t.Fatal(r, err)
	}
	for _, bad := range [][]string{{"x"}, {"A" + s256a[1:]}, make([]string, winproto.MaxChainCerts+2)} {
		for i := range bad {
			if bad[i] == "" {
				bad[i] = s256a
			}
		}
		if err := writeBindingState(h, bindingRecord{Binding: canon443, Chain: bad}); !errors.Is(err, errBadJournal) {
			t.Errorf("wrote %v", bad)
		}
		raw, _ := json.Marshal(bindingRecord{Binding: canon443, Chain: bad})
		h.state[bindingRecordName(canon443)] = raw
		if _, err := readBindingState(h, canon443); !errors.Is(err, errBadJournal) {
			t.Errorf("read %v", bad)
		}
	}
	// Writing an op alone clears the chain.
	_ = writeBindingRecord(h, canon443, op2)
	if r, _ := readBindingState(h, canon443); r.Chain != nil {
		t.Fatal(r.Chain)
	}
}

// TestBindPreservesTheWholeRecord is Review Focus 2.
func TestBindPreservesTheWholeRecord(t *testing.T) {
	for _, store := range []string{"", "MY"} {
		t.Run("store "+store, func(t *testing.T) {
			f := newFixture(t)
			rec := cloneBinding(f.rec)
			rec.Store = store
			f.h.setRecord(rec)
			f.committed(op1)
			if len(f.h.updates) != 1 || !reflect.DeepEqual(f.h.updates[0], withHash(rec, f.newSHA1)) {
				t.Fatalf("%+v", f.h.updates)
			}
			if f.h.updates[0].Store != store {
				t.Fatal("the store changed")
			}
		})
	}
}

func TestBindKeyUnusable(t *testing.T) {
	f := newFixture(t)
	f.h.updateErr = func(winproto.SSLBinding) error { return ErrKeyUnusable }
	o, r, out := f.deploy(op1, f.input())
	if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepBind || r.CauseStep != winproto.StepBind ||
		r.Error != winproto.ErrKeyUnusable {
		t.Fatalf("%+v %s", o, out)
	}
	if !reflect.DeepEqual(f.current(), f.rec) || len(f.h.updates) != 0 || f.journal(op1).Phase != winproto.PhaseRestored {
		t.Fatal("changed")
	}
	if r.Steps[len(r.Steps)-1] != bad(winproto.StepBind, winproto.ErrKeyUnusable) {
		t.Fatal(r.Steps)
	}
}

func TestBindRecordVanishes(t *testing.T) {
	f := newFixture(t)
	f.h.updateErr = func(winproto.SSLBinding) error { return ErrBindingNotFound }
	o, r, out := f.deploy(op1, f.input())
	if o.Exit != 0 || r.Phase != winproto.PhaseRestoreFailed || r.FailedStep != winproto.StepBind || r.Error != winproto.ErrFileChanged {
		t.Fatalf("%+v %s", o, out)
	}
}

// TestBindErrorAfterAPartialWrite: an update error other than ErrKeyUnusable and ErrBindingNotFound
// may come after the record changed (the real host's Ex updates follow the base update).
func TestBindErrorAfterAPartialWrite(t *testing.T) {
	partial := func(f *fixture) {
		n := 0
		f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding {
			n++
			if n == 1 {
				b.Extended = nil // the base went in, the Ex parameters did not
			}
			return b
		}
		f.h.updateFailAfter = func(winproto.SSLBinding) error {
			if n == 1 {
				return errors.New("ex update")
			}
			return nil
		}
	}
	t.Run("restored", func(t *testing.T) {
		f := newFixture(t)
		partial(f)
		o, r, out := f.deploy(op1, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepBind || r.CauseStep != winproto.StepBind || r.Error != winproto.ErrIO {
			t.Fatalf("%+v %s", o, out)
		}
		if !reflect.DeepEqual(f.current(), f.rec) || len(f.h.updates) != 2 || !reflect.DeepEqual(f.h.updates[1], f.rec) {
			t.Fatalf("%+v", f.h.updates)
		}
		if p := f.phases(op1); !reflect.DeepEqual(p, []string{winproto.PhasePrepared, winproto.PhaseWriting, winproto.PhaseRestoring, winproto.PhaseRestored}) {
			t.Fatal(p)
		}
		if len(f.h.events) != 1 || f.h.events[0].id != 1002 {
			t.Fatal(f.h.events)
		}
	})
	t.Run("forbidden", func(t *testing.T) {
		f := newFixture(t)
		partial(f)
		o, r, out := f.deploy(op1, f.input(func(in *winproto.DeployInput) { in.ForbiddenSPKI = []string{f.oldSPKI} }))
		if o.Exit != 0 || r.Phase != winproto.PhaseRestoreForbidden || r.Error != winproto.ErrForbidden {
			t.Fatalf("%+v %s", o, out)
		}
		if len(f.h.updates) != 1 {
			t.Fatal("restored although forbidden")
		}
	})
	t.Run("nothing written", func(t *testing.T) {
		f := newFixture(t)
		f.h.updateErr = func(winproto.SSLBinding) error { return errors.New("httpapi") }
		o, r, out := f.deploy(op1, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || len(f.h.updates) != 0 || !reflect.DeepEqual(f.current(), f.rec) {
			t.Fatalf("%+v %s", o, out)
		}
	})
	t.Run("record unreadable afterwards", func(t *testing.T) {
		f := newFixture(t)
		partial(f)
		reads := 0
		f.h.bindingErrFn = func() error {
			if reads++; reads > 1 {
				return errors.New("httpapi")
			}
			return nil
		}
		o, r, out := f.deploy(op1, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestoreFailed || r.FailedStep != winproto.StepRestore {
			t.Fatalf("%+v %s", o, out)
		}
	})
}

func TestReadBackMismatchSelfRestores(t *testing.T) {
	corrupt := func(f *fixture) {
		n := 0
		f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding {
			if n++; n == 1 {
				b.Extended = b.Extended[:1]
			}
			return b
		}
	}
	t.Run("restored", func(t *testing.T) {
		f := newFixture(t)
		corrupt(f)
		o, r, out := f.deploy(op1, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepBind || r.CauseStep != winproto.StepBind ||
			r.Error != winproto.ErrReadBack {
			t.Fatalf("%+v %s", o, out)
		}
		if !reflect.DeepEqual(f.current(), f.rec) || len(f.h.updates) != 2 {
			t.Fatal("not restored")
		}
		want := []winproto.Step{ok(winproto.StepImportChain), ok(winproto.StepImportCertificate), bad(winproto.StepBind, winproto.ErrReadBack), ok(winproto.StepRestore)}
		if !reflect.DeepEqual(r.Steps, want) {
			t.Fatal(r.Steps)
		}
	})
	t.Run("forbidden", func(t *testing.T) {
		f := newFixture(t)
		corrupt(f)
		o, r, out := f.deploy(op1, f.input(func(in *winproto.DeployInput) { in.ForbiddenLeaf = []string{f.oldSHA256} }))
		if o.Exit != 0 || r.Phase != winproto.PhaseRestoreForbidden || r.FailedStep != winproto.StepRestore || r.CauseStep != winproto.StepBind {
			t.Fatalf("%+v %s", o, out)
		}
		if f.current().CertSHA1 != f.newSHA1 || len(f.h.updates) != 1 {
			t.Fatal("restored although forbidden")
		}
	})
	t.Run("the record is gone", func(t *testing.T) {
		f := newFixture(t)
		f.h.updateFailAfter = func(winproto.SSLBinding) error {
			delete(f.h.records, canon443) // the record went away right after the update (lock held)
			return nil
		}
		o, r, out := f.deploy(op1, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrFileChanged {
			t.Fatalf("%+v %s", o, out)
		}
	})
	t.Run("the restore's read-back differs too", func(t *testing.T) {
		f := newFixture(t)
		f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding { b.Flags = 0; return b }
		o, r, out := f.deploy(op1, f.input())
		if o.Exit != 0 || r.Phase != winproto.PhaseRestoreFailed || r.Error != winproto.ErrReadBack || r.FailedStep != winproto.StepRestore {
			t.Fatalf("%+v %s", o, out)
		}
	})
}

func TestDeployFailuresAfterTheGate(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(f *fixture)
		phase string
		step  string
		class string
		code  string // OUTCOME_UNKNOWN instead of an answer
	}{
		{name: "intermediate import fails", setup: func(f *fixture) { f.h.addIntermediateErr = errors.New("ca") },
			phase: winproto.PhaseRestored, step: winproto.StepImportChain, class: winproto.ErrStore},
		{name: "PFX import fails", setup: func(f *fixture) { f.h.importErr = ErrStore },
			phase: winproto.PhaseRestored, step: winproto.StepImportCertificate, class: winproto.ErrStore},
		{name: "PFX import key unusable", setup: func(f *fixture) { f.h.importErr = ErrKeyUnusable },
			phase: winproto.PhaseRestored, step: winproto.StepImportCertificate, class: winproto.ErrKeyUnusable},
		{name: "prepared unwritten", setup: func(f *fixture) {
			f.h.writeStateErr = func(string) error { return errors.New("disk") }
		}, code: winproto.CodeOutcomeUnknown},
		{name: "binding record unwritten", setup: func(f *fixture) {
			f.h.writeStateErr = func(n string) error {
				if strings.HasPrefix(n, bindingsDir) {
					return errors.New("disk")
				}
				return nil
			}
		}, code: winproto.CodeOutcomeUnknown},
		{name: "writing unwritten", setup: func(f *fixture) { failPhase(f, winproto.PhaseWriting) }, code: winproto.CodeOutcomeUnknown},
		{name: "import_chain journal unwritten", setup: func(f *fixture) { failNthJournal(f, 2) }, code: winproto.CodeOutcomeUnknown},
		{name: "import_certificate journal unwritten", setup: func(f *fixture) { failNthJournal(f, 3) }, code: winproto.CodeOutcomeUnknown},
		{name: "failure journal unwritten", setup: func(f *fixture) {
			f.h.importErr = ErrStore
			failPhase(f, winproto.PhaseRestored)
		}, code: winproto.CodeOutcomeUnknown},
		{name: "committed unwritten: rolled back", setup: func(f *fixture) { failPhase(f, winproto.PhaseCommitted) },
			phase: winproto.PhaseRestored, step: winproto.StepJournal, class: winproto.ErrIO},
		{name: "restoring unwritten", setup: func(f *fixture) {
			failPhase(f, winproto.PhaseCommitted)
			failPhase(f, winproto.PhaseRestoring)
		}, code: winproto.CodeOutcomeUnknown},
		{name: "unchanged unwritten", setup: func(f *fixture) {
			f.h.addCert("MY", f.nw.Cert.Raw, true)
			f.h.setRecord(withHash(f.rec, f.newSHA1))
			f.h.ca[f.interSHA1] = f.ca.Intermediate.Raw
			_ = writeBindingState(f.h, bindingRecord{Binding: canon443, Chain: f.chain()})
			failPhase(f, winproto.PhaseUnchanged)
			f.expect = f.newSHA256
		}, code: winproto.CodeOutcomeUnknown},
		{name: "backup gone before the self-restore", setup: func(f *fixture) {
			f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding {
				delete(f.h.certs, [2]string{"MY", f.oldSHA1})
				b.Flags = 0
				return b
			}
		}, phase: winproto.PhaseRestoreFailed, step: winproto.StepRestore, class: winproto.ErrBackupMissing},
		{name: "store unreadable before the self-restore", setup: func(f *fixture) {
			f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding {
				f.h.certErr = ErrStore
				b.Flags = 0
				return b
			}
		}, phase: winproto.PhaseRestoreFailed, step: winproto.StepRestore, class: winproto.ErrStore},
		{name: "the restore update fails", setup: func(f *fixture) {
			n := 0
			f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding { b.Flags = 0; return b }
			f.h.updateErr = func(winproto.SSLBinding) error {
				if n++; n == 2 {
					return ErrKeyUnusable
				}
				return nil
			}
		}, phase: winproto.PhaseRestoreFailed, step: winproto.StepRestore, class: winproto.ErrKeyUnusable},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			c.setup(f)
			o, r, out := f.deploy(op1, f.input())
			if c.code != "" {
				wantError(t, o.Exit, out, 4, c.code)
				return
			}
			if o.Exit != 0 || r.Phase != c.phase || r.FailedStep != c.step || r.Error != c.class {
				t.Fatalf("%+v %s", o, out)
			}
			if c.phase == winproto.PhaseRestored && !reflect.DeepEqual(f.current(), f.rec) {
				t.Fatal("the record is not the previous one")
			}
		})
	}
	t.Run("the import answers another SHA-1", func(t *testing.T) {
		f := newFixture(t)
		other := f.ca.Issue(leafOpts, testNow)
		h := &otherImport{fakeWriteHost: f.h, der: other.Cert.Raw}
		o, out := execute(t, context.Background(), h, bytes.NewReader(f.input()), winproto.SubIISDeploy, winproto.ArgOp, op1)
		var r winproto.DeployResponse
		_ = json.Unmarshal(out, &r)
		if o.Exit != 0 || r.Phase != winproto.PhaseRestored || r.FailedStep != winproto.StepImportCertificate || r.Error != winproto.ErrStore {
			t.Fatalf("%+v %s", o, out)
		}
		// What the host answered is in the import inventory, so W3's cleanup finds it.
		imports, err := readImports(f.h)
		want := importEntry{Op: op1, Store: "MY", SHA1: sha1Hex(other.Cert.Raw), SHA256: hexSHA256(other.Cert.Raw)}
		if err != nil || len(imports.Imports) != 1 || imports.Imports[0] != want {
			t.Fatalf("%v %+v", err, imports)
		}
	})
}

// otherImport is a host whose ImportPFX imports another certificate than the PFX's.
type otherImport struct {
	*fakeWriteHost
	der []byte
}

func (o *otherImport) ImportPFX(_ context.Context, store string, _, _ []byte, _ string) (string, error) {
	return o.addCert(store, o.der, true), nil
}

// failPhase makes the WriteState of a journal in that phase fail.
func failPhase(f *fixture, phase string) { f.h.phaseErr = append(f.h.phaseErr, phase) }

// failNthJournal makes the n-th journal write fail.
func failNthJournal(f *fixture, n int) {
	i := 0
	f.h.writeStateErr = func(name string) error {
		if strings.HasPrefix(name, journalDir) {
			if i++; i == n {
				return errors.New("disk")
			}
		}
		return nil
	}
}

// TestNoKeyMaterialOutsideStdin is Review Focus 5.
func TestNoKeyMaterialOutsideStdin(t *testing.T) {
	var kept []*secrets
	old := secretsHook
	secretsHook = func(s *secrets) { kept = append(kept, s) }
	t.Cleanup(func() { secretsHook = old })

	for _, c := range []struct {
		name  string
		setup func(f *fixture)
		in    func(f *fixture) []byte
	}{
		{name: "committed"},
		{name: "import fails", setup: func(f *fixture) { f.h.importErr = ErrStore }},
		{name: "refused after parsing", setup: func(f *fixture) { f.h.lockHeld = true }},
		{name: "mismatched key", in: func(f *fixture) []byte {
			return f.input(func(in *winproto.DeployInput) { in.ChainPEM = string(f.old.FullchainPEM) })
		}},
		{name: "broken JSON after the key", in: func(f *fixture) []byte { return append(f.input(), 'x') }},
	} {
		t.Run(c.name, func(t *testing.T) {
			kept = nil
			f := newFixture(t)
			if c.setup != nil {
				c.setup(f)
			}
			in := f.input()
			if c.in != nil {
				in = c.in(f)
			}
			var out bytes.Buffer
			Execute(context.Background(), f.h, []string{winproto.SubIISDeploy, winproto.ArgOp, op1}, bytes.NewReader(in), &out)
			if len(kept) != 1 || len(kept[0].bufs) == 0 {
				t.Fatalf("secrets %d", len(kept))
			}
			for i, b := range kept[0].bufs {
				if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
					t.Fatalf("buffer %d not cleared", i)
				}
			}
			for i := range f.h.pfxs {
				if !bytes.Equal(f.h.pfxs[i], make([]byte, len(f.h.pfxs[i]))) || !bytes.Equal(f.h.passwords[i], make([]byte, len(f.h.passwords[i]))) {
					t.Fatal("the PFX or its password was not cleared")
				}
			}
			keyDER := pkcs8Of(t, f.nw)
			pkcs8, _ := x509.MarshalPKCS8PrivateKey(f.nw.Key)
			body := strings.Split(string(f.nw.KeyPEM), "\n")[1]
			texts := []string{out.String()}
			for _, w := range f.h.stateLog {
				texts = append(texts, string(w.data))
			}
			for _, e := range f.h.events {
				texts = append(texts, e.text)
			}
			texts = append(texts, f.h.friendlyNames...)
			for _, s := range texts {
				for _, secret := range []string{"PRIVATE KEY", body, b64(keyDER), b64(pkcs8), string(keyDER)} {
					if strings.Contains(s, secret) {
						t.Fatalf("key material in %.80q", s)
					}
				}
				for _, pw := range f.h.passwordCopies {
					if strings.Contains(s, pw) {
						t.Fatal("the password leaked")
					}
				}
			}
		})
	}
}

// TestKillPointsAreNamed: every point is reached once in a successful deploy and in a restore; a
// kill at each answers nothing and leaves the journal at the phase written last.
func TestKillPointsAreNamed(t *testing.T) {
	deployPoints := []string{"deploy.locked", "deploy.prepared", "deploy.import_chain", "deploy.import_certificate",
		"deploy.writing", "deploy.bound", "deploy.read_back", "deploy.committed"}
	restorePoints := []string{"restore.restoring", "restore.bound", "restore.restored"}
	f := newFixture(t)
	f.committed(op1)
	if !reflect.DeepEqual(f.h.points, deployPoints) {
		t.Fatalf("deploy points %v", f.h.points)
	}
	f.reset()
	if o, r, out := f.restore(op1, []string{}, []string{}); o.Exit != 0 || r.Phase != winproto.PhaseRestored {
		t.Fatalf("%+v %s", o, out)
	}
	if !reflect.DeepEqual(f.h.points, restorePoints) {
		t.Fatalf("restore points %v", f.h.points)
	}

	lastPhase := map[string]string{"deploy.locked": "", "deploy.prepared": winproto.PhasePrepared,
		"deploy.import_chain": winproto.PhasePrepared, "deploy.import_certificate": winproto.PhasePrepared,
		"deploy.writing": winproto.PhaseWriting, "deploy.bound": winproto.PhaseWriting, "deploy.read_back": winproto.PhaseWriting,
		"deploy.committed": winproto.PhaseCommitted, "restore.restoring": winproto.PhaseRestoring,
		"restore.bound": winproto.PhaseRestoring, "restore.restored": winproto.PhaseRestored}
	for _, p := range append(slices.Clone(deployPoints), restorePoints...) {
		t.Run(p, func(t *testing.T) {
			f := newFixture(t)
			kill := func(name string) error {
				if name == p {
					return errors.New("kill")
				}
				return nil
			}
			args := []string{winproto.SubIISDeploy, winproto.ArgOp, op1}
			in := f.input()
			if strings.HasPrefix(p, "restore.") {
				f.committed(op1)
				args[0], in = winproto.SubIISRestore, restoreInput([]string{}, []string{})
			}
			f.h.pointErr = kill
			var out bytes.Buffer
			o := Execute(context.Background(), f.h, args, bytes.NewReader(in), &out)
			if !o.Killed || o.Exit != ExitKilled || out.Len() != 0 {
				t.Fatalf("%+v %q", o, out.String())
			}
			j, found, err := readJournal(f.h, op1)
			if err != nil || found != (lastPhase[p] != "") || j.Phase != lastPhase[p] {
				t.Fatalf("%v %v %q", err, found, j.Phase)
			}
		})
	}
}

func TestJSONScanStrings(t *testing.T) {
	for in, want := range map[string]string{
		`"a\"b\\c\/d\be\ff\ng\rh\ti"`: "a\"b\\c/d\be\ff\ng\rh\ti",
		"\"\\u00fc\"":                 "\u00fc",
	} {
		p := jsonScan{b: []byte(in)}
		got, ok := p.str(make([]byte, 0, 64), 64)
		if !ok || string(got) != want {
			t.Errorf("%s: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{`x`, `"abc`, `"\`, `"abcdef"`, `"\u00fc\u00fc\u00fc"`} {
		p := jsonScan{b: []byte(in)}
		if _, ok := p.str(make([]byte, 0, 5), 5); ok {
			t.Errorf("accepted %s", in)
		}
	}
	if !sameRecord(winproto.SSLBinding{Extended: []winproto.ExtendedParam{}}, winproto.SSLBinding{}) {
		t.Error("an empty and an absent Extended list differ")
	}
}

// TestRecoveryAfterAKillAtEveryPoint (Review Focus 4 within the helper): after a kill at any point,
// the recovery the phase allows (iis-fence for none or prepared, iis-restore otherwise) leaves the
// record exactly the previous or exactly the new one, and a fenced operation never runs.
func TestRecoveryAfterAKillAtEveryPoint(t *testing.T) {
	points := []string{"deploy.locked", "deploy.prepared", "deploy.import_chain", "deploy.import_certificate",
		"deploy.writing", "deploy.bound", "deploy.read_back", "deploy.committed",
		"restore.restoring", "restore.bound", "restore.restored"}
	for _, p := range points {
		variants := []bool{false}
		if p == "deploy.bound" {
			variants = append(variants, true)
		}
		for _, lossy := range variants {
			name := p
			if lossy {
				name += ", the bind loses the Ex parameters"
			}
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				if lossy {
					// A kill after a partial base write: the record names the new hash without its Ex parameters.
					n := 0
					f.h.afterUpdate = func(b winproto.SSLBinding) winproto.SSLBinding {
						if n++; n == 1 {
							b.Extended = nil
						}
						return b
					}
				}
				kill := func(name string) error {
					if name == p {
						return errors.New("kill")
					}
					return nil
				}
				if strings.HasPrefix(p, "restore.") {
					f.committed(op1)
					f.h.pointErr = kill
					var out bytes.Buffer
					if o := Execute(context.Background(), f.h, []string{winproto.SubIISRestore, winproto.ArgOp, op1},
						bytes.NewReader(restoreInput([]string{}, []string{})), &out); !o.Killed {
						t.Fatalf("%+v", o)
					}
				} else {
					f.h.pointErr = kill
					f.killedDeploy(op1, f.input())
				}
				if lossy && f.journal(op1).Phase != winproto.PhaseWriting {
					t.Fatal("the lossy bind did not stop at writing")
				}
				f.h.pointErr, f.h.afterUpdate = nil, nil
				_, st, _ := f.statusCall(winproto.SubIISStatus, op1)
				fenced := false
				switch st.Phase {
				case winproto.PhaseNone, winproto.PhasePrepared:
					if _, r, out := f.statusCall(winproto.SubIISFence, op1); r.Phase != winproto.PhaseFenced {
						t.Fatalf("fence: %s", out)
					}
					o, _, out := f.deploy(op1, f.input())
					wantError(t, o.Exit, out, 3, winproto.CodeFenced)
					fenced = true
				case winproto.PhaseWriting, winproto.PhaseCommitted, winproto.PhaseRestoring:
					if _, r, out := f.restore(op1, []string{}, []string{}); r.Phase != winproto.PhaseRestored {
						t.Fatalf("restore: %s", out)
					}
				case winproto.PhaseRestored:
				default:
					t.Fatalf("phase %s", st.Phase)
				}
				cur := f.current()
				if !reflect.DeepEqual(cur, f.rec) && !reflect.DeepEqual(cur, withHash(f.rec, f.newSHA1)) {
					t.Fatalf("record %+v", cur)
				}
				if _, st, _ := f.statusCall(winproto.SubIISStatus, op1); !fenced && st.CurrentCertSHA256 != hexSHA256(certDERFor(f, cur.CertSHA1)) {
					t.Fatal("status does not name what the record serves")
				}
			})
		}
	}
}

func certDERFor(f *fixture, sha string) []byte {
	if sha == f.newSHA1 {
		return f.nw.Cert.Raw
	}
	return f.old.Cert.Raw
}
