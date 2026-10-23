package wintest

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

var _ winhelper.WriteHost = host{}

// opID is the n-th operation id of a test (a lower-case UUID).
func opID(n int) string { return fmt.Sprintf("%08x-0000-4000-8000-%012x", n, n) }

var exParams = []winproto.ExtendedParam{
	{Type: 1, Data: base64.StdEncoding.EncodeToString([]byte("http2 window and limits"))},
	{Type: 4, Data: base64.StdEncoding.EncodeToString([]byte{0x01, 0x00, 0x00, 0x00})},
}

// wfix is a model with one IIS SNI binding whose record carries every setting there is.
type wfix struct {
	m       *Model
	ca      *pki.CA
	old     pki.Leaf
	oldSHA1 string
	loc     winproto.Locator
	record  winproto.SSLBinding
}

func newWriteFixture(t *testing.T) *wfix {
	t.Helper()
	f := &wfix{m: NewModel(), ca: pki.NewCA("Write", pki.ECDSA256, now)}
	f.m.AddIntermediate(f.ca.IntermediatePEM)
	f.old = f.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	f.oldSHA1 = f.m.AddCertificate("My", f.old.CertPEM, f.old.KeyPEM, CertOptions{FriendlyName: "old"})
	f.record = winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: "www.example.test", Port: 443, AppID: winproto.AppIDIIS,
		CertSHA1: f.oldSHA1, Store: "My", Flags: 0x42, CertCheckMode: 1, RevocationFreshnessTime: 600, URLRetrievalTimeout: 7000,
		CTLIdentifier: "alice-ctl", CTLStore: "CA", Extended: slices.Clone(exParams)}
	f.m.AddBinding(f.record)
	f.loc = winproto.Locator{Type: winproto.BindingHostnamePort, Host: "www.example.test", Port: 443, AppID: winproto.AppIDIIS}
	return f
}

func (f *wfix) serve(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if err := f.m.Serve(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); f.m.serving.Wait() })
}

func (f *wfix) issue(cn string) pki.Leaf {
	return f.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, now)
}

func deployInput(t *testing.T, loc winproto.Locator, expect string, l pki.Leaf, forbidLeaf ...string) []byte {
	t.Helper()
	b, err := json.Marshal(winproto.DeployInput{Locator: loc, ExpectSHA256: expect, ChainPEM: string(l.FullchainPEM),
		KeyPEM: string(l.KeyPEM), ForbiddenSPKI: []string{}, ForbiddenLeaf: append([]string{}, forbidLeaf...)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// run sends one command line with stdin to the model's handler and decodes the answer into v (when
// there is one).
func run(t *testing.T, m *Model, line string, stdin []byte, v any) linuxsshtest.Response {
	t.Helper()
	r := m.Handler()(line, stdin)
	if len(r.Stdout) > 0 && v != nil {
		if err := json.Unmarshal(r.Stdout, v); err != nil {
			t.Fatalf("%q answered %q: %v", line, r.Stdout, err)
		}
	}
	return r
}

func (f *wfix) deploy(t *testing.T, op string, l pki.Leaf) (linuxsshtest.Response, winproto.DeployResponse) {
	t.Helper()
	var d winproto.DeployResponse
	r := run(t, f.m, "iis-deploy --op "+op, deployInput(t, f.loc, sum256(f.old.Cert.Raw), l), &d)
	return r, d
}

func restoreInput(leaf ...string) []byte {
	b, _ := json.Marshal(winproto.RestoreInput{ForbiddenSPKI: []string{}, ForbiddenLeaf: append([]string{}, leaf...)})
	return b
}

func status(t *testing.T, m *Model, op string) winproto.StatusResponse {
	t.Helper()
	var s winproto.StatusResponse
	if r := run(t, m, "iis-status --op "+op, nil, &s); r.Exit != 0 {
		t.Fatalf("status: %d %s", r.Exit, r.Stdout)
	}
	return s
}

func (f *wfix) current(t *testing.T) winproto.SSLBinding {
	t.Helper()
	b, ok := f.m.Binding(f.loc)
	if !ok {
		t.Fatal("the binding is gone")
	}
	return b
}

func TestModelHostIsAWriteHost(t *testing.T) {
	var h winhelper.Host = NewModel().Host()
	if _, ok := h.(winhelper.WriteHost); !ok {
		t.Fatal("Model.Host is not a WriteHost")
	}
}

func TestModelDeployServesTheNewCertificate(t *testing.T) {
	f := newWriteFixture(t)
	f.serve(t)
	nl := f.issue("www.example.test")
	r, d := f.deploy(t, opID(1), nl)
	if r.Exit != 0 || d.Phase != winproto.PhaseCommitted || !d.AliceImported || d.BuiltChainLength != 2 || d.Store != "My" ||
		d.NewSHA256 != sum256(nl.Cert.Raw) || d.PreviousSHA1 != f.oldSHA1 {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	cs, err := tlsDial(t, f.m.Endpoint(443), "www.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if sum256(cs.PeerCertificates[0].Raw) != sum256(nl.Cert.Raw) || len(cs.PeerCertificates) != 2 {
		t.Fatalf("served %d certificates, leaf %s", len(cs.PeerCertificates), cs.PeerCertificates[0].Subject)
	}
	// The imported key is the software KSP's, not exportable, and the certificate carries Alice's name.
	c, ok, _ := f.m.Host().Certificate(context.Background(), "My", d.NewSHA1)
	if !ok || !c.HasKey || c.KeyExportable || c.KeyProvider != defaultKeyProvider || !strings.HasPrefix(c.FriendlyName, "Alice www.example.test ") {
		t.Fatalf("%+v", c)
	}
	// Every other setting of the record survived (Review Focus 2).
	want := f.record
	want.CertSHA1 = d.NewSHA1
	if got := f.current(t); !reflectEqual(got, want) {
		t.Fatalf("record %+v\nwant %+v", got, want)
	}
	if j, ok := f.m.Journal(opID(1)); !ok || !strings.Contains(string(j), `"committed"`) || strings.Contains(string(j), "PRIVATE KEY") {
		t.Fatalf("journal %s", j)
	}
	if _, ok := f.m.Journal(opID(2)); ok {
		t.Fatal("a journal of an operation that never ran")
	}
}

func reflectEqual(a, b winproto.SSLBinding) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestModelUpdateReplacesTheWholeRecord(t *testing.T) {
	f := newWriteFixture(t)
	h := f.m.Host()
	ctx := context.Background()
	// An update that names only the key fields and the certificate resets everything else: the model
	// is http.sys, the helper must send the whole record (W0 F2).
	bare := winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: "www.example.test", Port: 443, AppID: winproto.AppIDIIS,
		CertSHA1: f.oldSHA1, Store: "My"}
	if err := h.UpdateBinding(ctx, bare); err != nil {
		t.Fatal(err)
	}
	got, found, err := h.Binding(ctx, f.loc)
	if err != nil || !found || !reflectEqual(got, bare) || got.Flags != 0 || len(got.Extended) != 0 || got.CTLIdentifier != "" {
		t.Fatalf("%+v %v %v", got, found, err)
	}
	// The whole record back: everything returns.
	if err := h.UpdateBinding(ctx, f.record); err != nil {
		t.Fatal(err)
	}
	if got := f.current(t); !reflectEqual(got, f.record) {
		t.Fatalf("%+v", got)
	}
	// A record http.sys does not hold is not created.
	other := f.record
	other.Port = 444
	if err := h.UpdateBinding(ctx, other); !errors.Is(err, winhelper.ErrBindingNotFound) {
		t.Fatalf("%v", err)
	}
	// A hash whose certificate has no usable key is 1312 and changes nothing.
	nokey := f.issue("nokey.example.test")
	nk := f.m.AddCertificate("My", nokey.CertPEM, nil, CertOptions{})
	unusable := f.issue("unusable.example.test")
	un := f.m.AddCertificate("My", unusable.CertPEM, unusable.KeyPEM, CertOptions{KeyUsableBySystem: yes(false)})
	for _, sha := range []string{nk, un, strings.Repeat("ab", 20)} {
		b := f.record
		b.CertSHA1 = sha
		if err := h.UpdateBinding(ctx, b); !errors.Is(err, winhelper.ErrKeyUnusable) {
			t.Fatalf("%s: %v", sha, err)
		}
	}
	// A hash that is no hash never reaches http.sys (the real helper's encodeBase refuses it): a plain
	// error, neither 1312 nor not found, nothing changed.
	for _, sha := range []string{"", "not hex", strings.Repeat("ab", maxHashBytes+1)} {
		b := f.record
		b.CertSHA1 = sha
		err := h.UpdateBinding(ctx, b)
		if err == nil || errors.Is(err, winhelper.ErrKeyUnusable) || errors.Is(err, winhelper.ErrBindingNotFound) {
			t.Fatalf("%q: %v", sha, err)
		}
	}
	if got := f.current(t); !reflectEqual(got, f.record) {
		t.Fatalf("%+v", got)
	}
	// The dump reads no extended parameters (the real helper's dump does not); the live read does.
	all, _ := h.SSLBindings(ctx)
	if len(all) != 1 || len(all[0].Extended) != 0 || all[0].Flags != 0x42 {
		t.Fatalf("%+v", all)
	}
	// A locator of another kind or spelling finds the record by http.sys's key.
	ip := winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "::ffff:10.0.0.5", Port: 443, AppID: winproto.AppIDIIS, CertSHA1: f.oldSHA1, Store: "My"}
	f.m.AddBinding(ip)
	if _, found, _ := h.Binding(ctx, winproto.Locator{Type: winproto.BindingIPPort, IP: "10.0.0.5", Port: 443, AppID: winproto.AppIDIIS}); !found {
		t.Fatal("the mapped address is the same key")
	}
	if _, found, _ := h.Binding(ctx, winproto.Locator{Type: winproto.BindingIPPort, IP: "10.0.0.6", Port: 443}); found {
		t.Fatal("another address")
	}
	if _, found, _ := h.Binding(ctx, winproto.Locator{Type: winproto.BindingHostnamePort, Host: "WWW.example.test", Port: 443}); !found {
		t.Fatal("host names are compared without case")
	}
}

func TestModelChainCache(t *testing.T) {
	f := newWriteFixture(t)
	f.serve(t)
	// A leaf of another CA whose intermediate is not in CA yet.
	other := pki.NewCA("Other", pki.ECDSA256, now)
	nl := other.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	nl.FullchainPEM = nl.CertPEM // Alice sends no intermediate: CA lacks it
	r, d := f.deploy(t, opID(1), nl)
	if r.Exit != 0 || d.Phase != winproto.PhaseCommitted || d.BuiltChainLength != 1 {
		t.Fatalf("%s", r.Stdout)
	}
	served := func() int {
		t.Helper()
		cs, err := tlsDial(t, f.m.Endpoint(443), "www.example.test")
		if err != nil {
			t.Fatal(err)
		}
		return len(cs.PeerCertificates)
	}
	if n := served(); n != 1 {
		t.Fatalf("%d", n)
	}
	// The intermediate arrives after the bind: schannel keeps the chain it built at the write.
	f.m.AddIntermediate(other.IntermediatePEM)
	if n := served(); n != 1 {
		t.Fatalf("served %d before a same-hash write", n)
	}
	if _, n, _ := f.m.Served("127.0.0.1", 443, "www.example.test"); n != 1 {
		t.Fatalf("Served %d", n)
	}
	// A same-hash write (what the helper does when only intermediates changed) rebuilds it.
	h := f.m.Host()
	if err := h.UpdateBinding(context.Background(), f.current(t)); err != nil {
		t.Fatal(err)
	}
	if n := served(); n != 2 {
		t.Fatalf("served %d after the write", n)
	}
	// A reboot drops the cache: the chain is built anew from the records.
	f.m.AddIntermediate(other.RootPEM) // a root is never part of the served chain
	f.m.Reboot()
	if n := served(); n != 2 {
		t.Fatalf("served %d after a reboot", n)
	}
}

func TestModelChainDiffers(t *testing.T) {
	f := newWriteFixture(t)
	f.serve(t)
	cross := pki.NewCA("Cross", pki.ECDSA256, now)
	f.m.ChainDiffers(cross.IntermediatePEM)
	nl := f.issue("www.example.test")
	r, d := f.deploy(t, opID(1), nl)
	if r.Exit != 0 || d.Phase != winproto.PhaseCommitted || d.BuiltChainLength != 3 {
		t.Fatalf("%s", r.Stdout)
	}
	cs, err := tlsDial(t, f.m.Endpoint(443), "www.example.test")
	if err != nil || len(cs.PeerCertificates) != 3 {
		t.Fatalf("%v", err)
	}
	// DER is accepted as well; nil takes it out again.
	block, _ := pem.Decode(cross.IntermediatePEM)
	f.m.ChainDiffers(block.Bytes)
	f.m.ChainDiffers(nil)
	if _, n, _ := f.m.Served("127.0.0.1", 443, "www.example.test"); n != 3 {
		t.Fatalf("the cache keeps the chain of the write: %d", n)
	}
	f.m.Reboot()
	if _, n, _ := f.m.Served("127.0.0.1", 443, "www.example.test"); n != 2 {
		t.Fatalf("%d", n)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("garbage is a test bug")
		}
	}()
	f.m.ChainDiffers([]byte("garbage"))
}

// deployPoints and restorePoints are Task 3's crash points in the order a run reaches them.
var (
	deployPoints = []string{"deploy.locked", "deploy.prepared", "deploy.import_chain", "deploy.import_certificate",
		"deploy.writing", "deploy.bound", "deploy.read_back", "deploy.committed"}
	restorePoints = []string{"restore.restoring", "restore.bound", "restore.restored"}
)

func TestModelKillAtEveryPoint(t *testing.T) {
	// The point list is complete: a deploy and a restore pass exactly these.
	f := newWriteFixture(t)
	f.deploy(t, opID(1), f.issue("www.example.test"))
	run(t, f.m, "iis-restore --op "+opID(1), restoreInput(), nil)
	if got := f.m.Points(); !slices.Equal(got, append(slices.Clone(deployPoints), restorePoints...)) {
		t.Fatalf("points %v", got)
	}

	wantPhase := map[string]string{
		"deploy.locked": winproto.PhaseNone, "deploy.prepared": winproto.PhasePrepared, "deploy.import_chain": winproto.PhasePrepared,
		"deploy.import_certificate": winproto.PhasePrepared, "deploy.writing": winproto.PhaseWriting, "deploy.bound": winproto.PhaseWriting,
		"deploy.read_back": winproto.PhaseWriting, "deploy.committed": winproto.PhaseCommitted,
		"restore.restoring": winproto.PhaseRestoring, "restore.bound": winproto.PhaseRestoring, "restore.restored": winproto.PhaseRestored,
	}
	for _, p := range append(slices.Clone(deployPoints), restorePoints...) {
		t.Run(p, func(t *testing.T) {
			f := newWriteFixture(t)
			f.serve(t)
			op := opID(7)
			nl := f.issue("www.example.test")
			if strings.HasPrefix(p, "restore.") {
				if _, d := f.deploy(t, op, nl); d.Phase != winproto.PhaseCommitted {
					t.Fatalf("%+v", d)
				}
			}
			f.m.KillAt(p)
			var r linuxsshtest.Response
			if strings.HasPrefix(p, "deploy.") {
				r, _ = f.deploy(t, op, nl)
			} else {
				r = run(t, f.m, "iis-restore --op "+op, restoreInput(), nil)
			}
			// A killed helper answers nothing.
			if len(r.Stdout) != 0 || r.Exit != KilledExit {
				t.Fatalf("killed at %s: %d %q", p, r.Exit, r.Stdout)
			}
			// The dead process's lock is gone before any reboot (the OS releases LockFileEx locks).
			if s := status(t, f.m, op); s.Active {
				t.Fatalf("the lock outlived the killed helper at %s: %+v", p, s)
			}
			f.m.Reboot()
			s := status(t, f.m, op)
			if s.Phase != wantPhase[p] || s.Active {
				t.Fatalf("status after a kill at %s: %+v", p, s)
			}
			// Alice's recovery: a fence when nothing (or only prepared) was written, else a restore.
			switch s.Phase {
			case winproto.PhaseNone, winproto.PhasePrepared:
				var fs winproto.StatusResponse
				if r := run(t, f.m, "iis-fence --op "+op, nil, &fs); r.Exit != 0 || fs.Phase != winproto.PhaseFenced {
					t.Fatalf("fence: %d %s", r.Exit, r.Stdout)
				}
				var e winproto.ErrorResponse
				if r := run(t, f.m, "iis-deploy --op "+op, deployInput(t, f.loc, sum256(f.old.Cert.Raw), nl), &e); r.Exit != winproto.ExitPrecondition || e.Code != winproto.CodeFenced {
					t.Fatalf("a re-sent deploy after the fence: %d %s", r.Exit, r.Stdout)
				}
			default:
				var rs winproto.RestoreResponse
				if r := run(t, f.m, "iis-restore --op "+op, restoreInput(), &rs); r.Exit != 0 || rs.Phase != winproto.PhaseRestored {
					t.Fatalf("restore: %d %s", r.Exit, r.Stdout)
				}
			}
			// The binding names exactly the previous certificate, whole, and that is what is served.
			if got := f.current(t); !reflectEqual(got, f.record) {
				t.Fatalf("record after recovery %+v", got)
			}
			if leaf, _, ok := f.m.Served("127.0.0.1", 443, "www.example.test"); !ok || leaf != sum256(f.old.Cert.Raw) {
				t.Fatalf("served %s", leaf)
			}
			cs, err := tlsDial(t, f.m.Endpoint(443), "www.example.test")
			if err != nil || sum256(cs.PeerCertificates[0].Raw) != sum256(f.old.Cert.Raw) {
				t.Fatalf("handshake %v", err)
			}
		})
	}
}

func TestModelFaults(t *testing.T) {
	t.Run("lock held", func(t *testing.T) {
		f := newWriteFixture(t)
		f.m.SetLockWait(30 * time.Millisecond)
		release := f.m.HoldLock()
		if s := status(t, f.m, opID(1)); !s.Active || s.Phase != winproto.PhaseNone {
			t.Fatalf("%+v", s)
		}
		start := time.Now()
		var e winproto.ErrorResponse
		if r := run(t, f.m, "iis-deploy --op "+opID(1), deployInput(t, f.loc, sum256(f.old.Cert.Raw), f.issue("www.example.test")), &e); r.Exit != winproto.ExitFailed || e.Code != winproto.CodeBusy {
			t.Fatalf("%d %s", r.Exit, r.Stdout)
		}
		if time.Since(start) < 30*time.Millisecond {
			t.Fatal("BUSY before the lock wait")
		}
		release()
		release() // idempotent
		if s := status(t, f.m, opID(1)); s.Active {
			t.Fatal("released")
		}
		// A reboot drops a lock someone held; its late release changes nothing.
		late := f.m.HoldLock()
		f.m.Reboot()
		again := f.m.HoldLock()
		late()
		if s := status(t, f.m, opID(1)); !s.Active {
			t.Fatal("the release of a lock from before the reboot freed the one taken after it")
		}
		again()
		// A lock taken while the holder lets go within the wait succeeds.
		r3 := f.m.HoldLock()
		f.m.SetLockWait(2 * time.Second)
		go func() { time.Sleep(20 * time.Millisecond); r3() }()
		if r, d := f.deploy(t, opID(2), f.issue("www.example.test")); r.Exit != 0 || d.Phase != winproto.PhaseCommitted {
			t.Fatalf("%s", r.Stdout)
		}
		// A context that ends while waiting is BUSY.
		f.m.HoldLock()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := f.m.Host().Lock(ctx); !errors.Is(err, winhelper.ErrBusy) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("key unusable at bind", func(t *testing.T) {
		f := newWriteFixture(t)
		f.m.FailUpdate(winhelper.ErrKeyUnusable)
		_, d := f.deploy(t, opID(1), f.issue("www.example.test"))
		if d.Phase != winproto.PhaseRestored || d.FailedStep != winproto.StepBind || d.Error != winproto.ErrKeyUnusable {
			t.Fatalf("%+v", d)
		}
		if got := f.current(t); !reflectEqual(got, f.record) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("other update failure", func(t *testing.T) {
		f := newWriteFixture(t)
		f.m.FailUpdate(winhelper.ErrStore)
		_, d := f.deploy(t, opID(1), f.issue("www.example.test"))
		if d.Phase != winproto.PhaseRestored || d.FailedStep != winproto.StepBind {
			t.Fatalf("%+v", d)
		}
		if got := f.current(t); !reflectEqual(got, f.record) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("read back loses an Ex parameter", func(t *testing.T) {
		f := newWriteFixture(t)
		f.m.CorruptReadBack(true)
		_, d := f.deploy(t, opID(1), f.issue("www.example.test"))
		if d.Phase != winproto.PhaseRestored || d.FailedStep != winproto.StepBind || d.Error != winproto.ErrReadBack {
			t.Fatalf("%+v", d)
		}
		if got := f.current(t); !reflectEqual(got, f.record) {
			t.Fatalf("%+v", got)
		}
		// Off again: a record without Ex parameters reads back with a flag changed.
		f.m.CorruptReadBack(true)
		f.m.CorruptReadBack(false)
		g := newWriteFixture(t)
		rec := g.record
		rec.Extended = nil
		if err := g.m.Host().UpdateBinding(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
		g.record = rec
		g.m.CorruptReadBack(true)
		if _, d := g.deploy(t, opID(1), g.issue("www.example.test")); d.Error != winproto.ErrReadBack || d.Phase != winproto.PhaseRestored {
			t.Fatalf("%+v", d)
		}
	})
	t.Run("import fails after prepared", func(t *testing.T) {
		f := newWriteFixture(t)
		f.m.FailImport(true)
		_, d := f.deploy(t, opID(1), f.issue("www.example.test"))
		if d.Phase != winproto.PhaseRestored || d.FailedStep != winproto.StepImportCertificate || d.Error != winproto.ErrStore {
			t.Fatalf("%+v", d)
		}
		if got := f.current(t); !reflectEqual(got, f.record) {
			t.Fatalf("%+v", got)
		}
		if j, _ := f.m.Journal(opID(1)); !strings.Contains(string(j), `"restored"`) {
			t.Fatalf("%s", j)
		}
		f.m.FailImport(false)
		if _, d := f.deploy(t, opID(2), f.issue("www.example.test")); d.Phase != winproto.PhaseCommitted {
			t.Fatalf("%+v", d)
		}
	})
	t.Run("stale TLS", func(t *testing.T) {
		f := newWriteFixture(t)
		f.serve(t)
		f.m.StaleTLS(true)
		nl := f.issue("www.example.test")
		if _, d := f.deploy(t, opID(1), nl); d.Phase != winproto.PhaseCommitted {
			t.Fatalf("%+v", d)
		}
		// A second write keeps serving what was served before the first.
		if err := f.m.Host().UpdateBinding(context.Background(), f.current(t)); err != nil {
			t.Fatal(err)
		}
		cs, err := tlsDial(t, f.m.Endpoint(443), "www.example.test")
		if err != nil || sum256(cs.PeerCertificates[0].Raw) != sum256(f.old.Cert.Raw) {
			t.Fatalf("%v", err)
		}
		if leaf, _, _ := f.m.Served("127.0.0.1", 443, "www.example.test"); leaf != sum256(f.old.Cert.Raw) {
			t.Fatal("Served sees the stale listener too")
		}
		f.m.StaleTLS(false)
		if leaf, _, _ := f.m.Served("127.0.0.1", 443, "www.example.test"); leaf != sum256(nl.Cert.Raw) {
			t.Fatal("off: the listener serves the record again")
		}
		// A record that served nothing before the write is not kept stale.
		g := newWriteFixture(t)
		g.m.RemoveCertificate("My", g.oldSHA1)
		g.m.StaleTLS(true)
		b := g.record
		b.CertSHA1 = g.m.AddCertificate("My", nl.CertPEM, nl.KeyPEM, CertOptions{})
		if err := g.m.Host().UpdateBinding(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		if leaf, _, _ := g.m.Served("127.0.0.1", 443, "www.example.test"); leaf != sum256(nl.Cert.Raw) {
			t.Fatal("nothing was served before")
		}
	})
}

func TestModelEventsAndImports(t *testing.T) {
	f := newWriteFixture(t)
	nl := f.issue("www.example.test")
	_, d := f.deploy(t, opID(1), nl)
	if d.Phase != winproto.PhaseCommitted {
		t.Fatalf("%+v", d)
	}
	if ev := f.m.Events(); len(ev) != 1 || ev[0].ID != 1001 || !strings.Contains(ev[0].Text, opID(1)) || strings.Contains(ev[0].Text, "PRIVATE") {
		t.Fatalf("%+v", ev)
	}
	if got := f.m.Imported(); !slices.Equal(got, []string{d.NewSHA1}) {
		t.Fatalf("%v", got)
	}
	var rs winproto.RestoreResponse
	if r := run(t, f.m, "iis-restore --op "+opID(1), restoreInput(), &rs); r.Exit != 0 || rs.Phase != winproto.PhaseRestored {
		t.Fatalf("%s", r.Stdout)
	}
	if ev := f.m.Events(); len(ev) != 2 || ev[1].ID != 1002 {
		t.Fatalf("%+v", ev)
	}
	// imports.json on the modelled disk names it (W3's cleanup reads it).
	if b, ok, _ := f.m.Host().ReadState("imports.json"); !ok || !strings.Contains(string(b), d.NewSHA1) {
		t.Fatalf("%s", b)
	}
	// A deploy of a certificate already in the store with its key imports nothing.
	g := newWriteFixture(t)
	g.m.AddCertificate("My", nl.CertPEM, nl.KeyPEM, CertOptions{})
	if _, d := g.deploy(t, opID(2), nl); d.Phase != winproto.PhaseCommitted || d.AliceImported {
		t.Fatalf("%+v", d)
	}
	if len(g.m.Imported()) != 0 {
		t.Fatal("nothing was imported")
	}
}

func TestModelImportPFX(t *testing.T) {
	m := NewModel()
	h := m.Host()
	ctx := context.Background()
	ca := pki.NewCA("PFX", pki.RSA2048, now)
	l := ca.Issue(pki.Opts{CommonName: "pfx.example.test", SANs: []string{"pfx.example.test"}, KeyType: pki.RSA2048}, now)
	key, err := x509.MarshalPKCS8PrivateKey(l.Key)
	if err != nil {
		t.Fatal(err)
	}
	password := winhelper.NewPFXPassword()
	pfx, err := winhelper.BuildPFX(l.Cert.Raw, key, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.ImportPFX(ctx, "WebHosting", pfx, []byte("wrong"), "x"); !errors.Is(err, winhelper.ErrStore) {
		t.Fatalf("a wrong password: %v", err)
	}
	// Another PKCS #12 writer's file (a CA certificate in it) is not what BuildPFX writes.
	other, err := pkcs12.Modern.Encode(l.Key, l.Cert, []*x509.Certificate{ca.Intermediate}, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.ImportPFX(ctx, "WebHosting", other, []byte("pw"), "x"); !errors.Is(err, winhelper.ErrStore) {
		t.Fatalf("a foreign PFX: %v", err)
	}
	sha, existed, err := h.ImportPFX(ctx, "WebHosting", pfx, password, "Alice pfx")
	if err != nil || sha != thumbprint(l.Cert.Raw) || existed {
		t.Fatalf("%s %v %v", sha, existed, err)
	}
	c, ok, _ := h.Certificate(ctx, "webhosting", sha)
	if !ok || !c.HasKey || c.KeyExportable || c.KeyProvider != defaultKeyProvider || c.FriendlyName != "Alice pfx" || c.KeyProblem != "" {
		t.Fatalf("%+v", c)
	}
	// A second import of the same certificate returns its thumbprint, answers existed and adds nothing.
	if again, existed, err := h.ImportPFX(ctx, "WebHosting", pfx, password, "y"); err != nil || again != sha || !existed {
		t.Fatalf("%s %v %v", again, existed, err)
	}
	if c, _, _ := h.Certificate(ctx, "WebHosting", sha); c.FriendlyName != "Alice pfx" {
		t.Fatalf("the existing copy was renamed: %q", c.FriendlyName)
	}
	if got := m.Imported(); !slices.Equal(got, []string{sha}) {
		t.Fatalf("%v", got)
	}
	// The intermediate store never replaces.
	block, _ := pem.Decode(ca.IntermediatePEM)
	if added, err := h.AddIntermediate(ctx, block.Bytes); err != nil || !added {
		t.Fatalf("%v %v", added, err)
	}
	if added, _ := h.AddIntermediate(ctx, block.Bytes); added {
		t.Fatal("added twice")
	}
	if _, err := h.AddIntermediate(ctx, []byte("garbage")); !errors.Is(err, winhelper.ErrStore) {
		t.Fatalf("%v", err)
	}
}

func TestModelState(t *testing.T) {
	m := NewModel()
	h := m.Host()
	if err := h.DataDirSafe(); err != nil {
		t.Fatal(err)
	}
	if _, found, err := h.ReadState("journal/x.json"); found || err != nil {
		t.Fatal("empty disk")
	}
	data := []byte(`{"a":1}`)
	if err := h.WriteState("journal/x.json", data); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X' // the disk keeps its own copy
	got, found, err := h.ReadState("journal/x.json")
	if err != nil || !found || string(got) != `{"a":1}` {
		t.Fatalf("%s %v %v", got, found, err)
	}
	got[0] = 'Y'
	if again, _, _ := h.ReadState("journal/x.json"); string(again) != `{"a":1}` {
		t.Fatal("a read hands out the disk's copy")
	}
	// A file over the bound reads MaxStateBytes+1 bytes (the caller refuses it).
	if err := h.WriteState("big.json", make([]byte, winhelper.MaxStateBytes+10)); err != nil {
		t.Fatal(err)
	}
	if b, _, _ := h.ReadState("big.json"); len(b) != winhelper.MaxStateBytes+1 {
		t.Fatalf("%d", len(b))
	}
	// The reboot keeps the disk.
	m.Reboot()
	if _, found, _ := h.ReadState("journal/x.json"); !found {
		t.Fatal("the reboot lost a state file")
	}
	m.SetDataDirUnsafe(true)
	if err := h.DataDirSafe(); !errors.Is(err, winhelper.ErrJournal) {
		t.Fatalf("%v", err)
	}
	var e winproto.ErrorResponse
	if r := run(t, m, "iis-fence --op "+opID(1), nil, &e); e.Code != winproto.CodeJournalFailed {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	for range maxPoints + 5 {
		if h.Point("anything") != nil {
			t.Fatal("no kill armed")
		}
	}
	if n := len(m.Points()); n != maxPoints {
		t.Fatalf("%d points kept", n)
	}
}

func TestDemoHostIsDeployable(t *testing.T) {
	m, err := Demo(now)
	if err != nil {
		t.Fatal(err)
	}
	ca := pki.NewCA("Alice", pki.ECDSA256, now)
	h := m.Host()
	for i, c := range []struct {
		loc  winproto.Locator
		cn   string
		sni  string
		port int
	}{
		{winproto.Locator{Type: winproto.BindingHostnamePort, Host: "www.win.example.test", Port: 443, AppID: winproto.AppIDIIS}, "www.win.example.test", "www.win.example.test", 443},
		{winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS}, "intranet.win.example.test", "", 8443},
	} {
		prev, ok := m.Binding(c.loc)
		if !ok {
			t.Fatalf("%+v", c.loc)
		}
		pc, _, _ := h.Certificate(context.Background(), prev.Store, prev.CertSHA1)
		der, _ := base64.StdEncoding.DecodeString(pc.DER)
		nl := ca.Issue(pki.Opts{CommonName: c.cn, SANs: []string{c.cn}}, now)
		var d winproto.DeployResponse
		r := run(t, m, "iis-deploy --op "+opID(i+1), deployInput(t, c.loc, sum256(der), nl), &d)
		if r.Exit != 0 || d.Phase != winproto.PhaseCommitted || d.Store != prev.Store || d.BuiltChainLength != 2 {
			t.Fatalf("%d %s", r.Exit, r.Stdout)
		}
		if leaf, n, ok := m.Served("0.0.0.0", c.port, c.sni); !ok || leaf != sum256(nl.Cert.Raw) || n != 2 {
			t.Fatalf("served %s %d %v", leaf, n, ok)
		}
	}
}
