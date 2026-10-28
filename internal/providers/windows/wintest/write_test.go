package wintest

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/linuxssh/linuxsshtest"
	"alice/internal/providers/tlsverify"
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

// The cleanup half (W3 Task 4): iis-cleanup against the model.

func (f *wfix) plan(t *testing.T, watch ...winproto.CleanupRef) winproto.CleanupPlanResponse {
	t.Helper()
	if watch == nil {
		watch = []winproto.CleanupRef{}
	}
	in, _ := json.Marshal(winproto.CleanupPlanInput{Watch: watch})
	var p winproto.CleanupPlanResponse
	if r := run(t, f.m, "iis-cleanup --plan", in, &p); r.Exit != 0 || !p.OK {
		t.Fatalf("plan: %d %s", r.Exit, r.Stdout)
	}
	return p
}

// apply answers the decoded response, or the decoded error (Code "" when it succeeded).
func (f *wfix) apply(t *testing.T, items ...winproto.CleanupItem) (winproto.CleanupApplyResponse, winproto.ErrorResponse) {
	t.Helper()
	in, _ := json.Marshal(winproto.CleanupApplyInput{Remove: items})
	r := f.m.Handler()("iis-cleanup --apply", in)
	var a winproto.CleanupApplyResponse
	var e winproto.ErrorResponse
	if r.Exit == 0 {
		if err := json.Unmarshal(r.Stdout, &a); err != nil {
			t.Fatalf("%s: %v", r.Stdout, err)
		}
	} else if len(r.Stdout) > 0 {
		_ = json.Unmarshal(r.Stdout, &e)
	}
	return a, e
}

func itemOf(c winproto.CleanupCandidate, reason string) winproto.CleanupItem {
	return winproto.CleanupItem{Store: c.Store, SHA1: c.SHA1, SHA256: c.SHA256, Reason: reason}
}

// redeployTo deploys each leaf in turn to the fixture's binding (the first over the old certificate),
// operations 1, 2, ...
func (f *wfix) redeployTo(t *testing.T, leaves ...pki.Leaf) {
	t.Helper()
	from := f.old
	for i, to := range leaves {
		var d winproto.DeployResponse
		if r := run(t, f.m, "iis-deploy --op "+opID(i+1), deployInput(t, f.loc, sum256(from.Cert.Raw), to), &d); r.Exit != 0 || d.Phase != winproto.PhaseCommitted {
			t.Fatalf("deploy %d: %d %s", i+1, r.Exit, r.Stdout)
		}
		from = to
	}
}

func (f *wfix) redeploy(t *testing.T) (a, b pki.Leaf) {
	t.Helper()
	a, b = f.issue("www.example.test"), f.issue("www.example.test")
	f.redeployTo(t, a, b)
	return a, b
}

func TestModelCleanupAfterARedeploy(t *testing.T) {
	f := newWriteFixture(t)
	a, b := f.redeploy(t)
	aSHA, bSHA := thumbprint(a.Cert.Raw), thumbprint(b.Cert.Raw)
	keys := f.m.KeyCount()

	p := f.plan(t)
	if len(p.Candidates) != 1 || p.Candidates[0].SHA1 != aSHA || p.Candidates[0].Eligible != "" {
		t.Fatalf("a fresh unbound import is a candidate, not eligible: %+v", p.Candidates)
	}
	f.m.Advance(7*24*time.Hour + time.Minute)
	p = f.plan(t)
	if len(p.Candidates) != 1 || p.Candidates[0].Eligible != winproto.CleanupAged {
		t.Fatalf("%+v", p.Candidates)
	}
	res, e := f.apply(t, itemOf(p.Candidates[0], winproto.CleanupAged))
	if e.Code != "" || len(res.Results) != 1 || res.Results[0].Result != winproto.CleanupRemoved {
		t.Fatalf("%+v %+v", res, e)
	}
	if f.m.HasCertificate("My", aSHA) || f.m.HasKey("My", aSHA) || f.m.KeyCount() != keys-1 {
		t.Fatal("A and its key are gone")
	}
	if !f.m.HasCertificate("My", bSHA) || !f.m.HasKey("My", bSHA) {
		t.Fatal("B stays")
	}
	if ev := f.m.Events(); len(ev) == 0 || ev[len(ev)-1].ID != 1003 {
		t.Fatalf("%+v", ev)
	}
}

func TestModelCleanupKeepsListeners(t *testing.T) {
	f := newWriteFixture(t)
	a, _ := f.redeploy(t)
	aSHA := thumbprint(a.Cert.Raw)
	f.m.Advance(7*24*time.Hour + time.Minute)
	f.plan(t) // stamps unbound_since
	f.m.Advance(7*24*time.Hour + time.Minute)
	keptBy := func(reason string) {
		t.Helper()
		p := f.plan(t, winproto.CleanupRef{SHA1: aSHA, SHA256: sum256(a.Cert.Raw)})
		if len(p.Watched) != 1 || p.Watched[0].State != winproto.WatchKept || p.Watched[0].Reason != reason {
			t.Fatalf("want %s: %+v", reason, p.Watched)
		}
		res, e := f.apply(t, winproto.CleanupItem{Store: "My", SHA1: aSHA, SHA256: sum256(a.Cert.Raw), Reason: winproto.CleanupAged})
		if e.Code != "" || res.Results[0].Result != winproto.CleanupKept || res.Results[0].Reason != reason {
			t.Fatalf("%+v %+v", res, e)
		}
		if !f.m.HasCertificate("My", aSHA) {
			t.Fatal("A was removed")
		}
	}
	f.m.SetRDP(RDPConfig{Present: true, Enabled: true, Port: 3389, SecurityLayer: 2})
	f.m.SetRDPThumbprint(aSHA)
	keptBy(winproto.KeptRDP)
	f.m.SetRDPThumbprint("")
	f.m.SetWinRMThumbprints(aSHA)
	keptBy(winproto.KeptWinRM)
	f.m.SetWinRMThumbprints()
	f.m.FailProtected(true)
	in, _ := json.Marshal(winproto.CleanupPlanInput{Watch: []winproto.CleanupRef{}})
	var e winproto.ErrorResponse
	if r := run(t, f.m, "iis-cleanup --plan", in, &e); r.Exit == 0 || e.Code != winproto.CodeIOError {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if _, e := f.apply(t, winproto.CleanupItem{Store: "My", SHA1: aSHA, SHA256: sum256(a.Cert.Raw), Reason: winproto.CleanupAged}); e.Code != winproto.CodeIOError {
		t.Fatalf("%+v", e)
	}
	f.m.FailProtected(false)
	f.plan(t) // the listeners no longer name A: the clock of its age starts again
	f.m.Advance(7*24*time.Hour + time.Minute)
	if p := f.plan(t); len(p.Candidates) != 1 || p.Candidates[0].Eligible != winproto.CleanupAged {
		t.Fatalf("%+v", p.Candidates)
	}
}

func TestModelKillBetweenKeyAndCertificate(t *testing.T) {
	f := newWriteFixture(t)
	a, b := f.redeploy(t)
	aSHA := thumbprint(a.Cert.Raw)
	f.plan(t) // stamps unbound_since
	f.m.Advance(7*24*time.Hour + time.Minute)
	p := f.plan(t)
	item := itemOf(p.Candidates[0], winproto.CleanupAged)
	keys := f.m.KeyCount()

	f.m.FailAfterKey(true)
	if _, e := f.apply(t, item); e.Code != winproto.CodeOutcomeUnknown {
		t.Fatalf("%+v", e)
	}
	if !f.m.HasCertificate("My", aSHA) || f.m.HasKey("My", aSHA) || f.m.KeyCount() != keys-1 {
		t.Fatal("the certificate stays keyless, no orphan key")
	}
	// The failure was once: the next plan offers A again, keyless, and the next apply removes it.
	p = f.plan(t)
	if len(p.Candidates) != 1 || p.Candidates[0].SHA1 != aSHA || p.Candidates[0].Eligible != winproto.CleanupAged {
		t.Fatalf("%+v", p.Candidates)
	}
	res, e := f.apply(t, itemOf(p.Candidates[0], winproto.CleanupAged))
	if e.Code != "" || res.Results[0].Result != winproto.CleanupRemoved {
		t.Fatalf("%+v %+v", res, e)
	}
	if f.m.HasCertificate("My", aSHA) || f.m.KeyCount() != keys-1 || !f.m.HasKey("My", thumbprint(b.Cert.Raw)) {
		t.Fatalf("%d keys", f.m.KeyCount())
	}
}

func TestModelPrunesStateFiles(t *testing.T) {
	f := newWriteFixture(t)
	f.redeployTo(t, f.issue("www.example.test"), f.issue("www.example.test"), f.issue("www.example.test"))
	op := func(n int) string { return "journal/" + opID(n) + ".json" }
	if before := f.m.StateFiles(); !slices.Contains(before, op(1)) || !slices.Contains(before, op(3)) {
		t.Fatalf("%v", before)
	}
	old := f.m.Host().(host).Now().Add(-8 * 24 * time.Hour)
	f.m.SetStateTime(op(1), old)
	f.m.SetStateTime(op(2), old)
	p := f.plan(t)
	if p.Pruned < 1 {
		t.Fatalf("%+v", p)
	}
	after := f.m.StateFiles()
	if slices.Contains(after, op(1)) || !slices.Contains(after, op(3)) {
		t.Fatalf("%v", after)
	}
}

func TestModelClockAndStateTimes(t *testing.T) {
	m := NewModel()
	h := m.Host().(host)
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	m.SetNow(t0)
	m.Advance(time.Hour)
	if !h.Now().Equal(t0.Add(time.Hour)) {
		t.Fatalf("%v", h.Now())
	}
	_ = h.WriteState("journal/b.json", []byte("{}"))
	_ = h.WriteState("journal/a.json", []byte("{}"))
	_ = h.WriteState("bindings/x.json", []byte("{}"))
	_ = h.WriteState("imports.json", []byte("{}"))
	fs, err := h.ListState("journal/")
	if err != nil || len(fs) != 2 || !fs[0].ModTime.Equal(t0.Add(time.Hour)) {
		t.Fatalf("%v %v", fs, err)
	}
	for _, f := range fs {
		if strings.Contains(f.Name, "/") {
			t.Fatalf("names are relative: %q", f.Name)
		}
	}
	if fs, _ := h.ListState("nothing/"); len(fs) != 0 {
		t.Fatal("a missing directory lists nothing")
	}
	m.SetStateTime("journal/a.json", t0)
	if fs, _ := h.ListState("journal/"); !slices.ContainsFunc(fs, func(f winhelper.StateFile) bool { return f.Name == "a.json" && f.ModTime.Equal(t0) }) {
		t.Fatalf("%v", fs)
	}
	if err := h.RemoveState("journal/a.json"); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveState("journal/a.json"); err != nil {
		t.Fatal("an absent file is nil")
	}
	if got := m.StateFiles(); !slices.Equal(got, []string{"bindings/x.json", "imports.json", "journal/b.json"}) {
		t.Fatalf("%v", got)
	}
	// The default clock is the system's, moved by Advance.
	m2 := NewModel()
	m2.Advance(time.Hour)
	if d := time.Until(m2.Host().(host).Now()); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("%v", d)
	}
}

func TestModelRemoveCertificateWholeAndOutside(t *testing.T) {
	f := newWriteFixture(t)
	h := f.m.Host().(host)
	ctx := context.Background()
	if ok, err := h.RemoveCertificate(ctx, "My", strings.Repeat("0", 40)); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if !f.m.HasCertificate("my", f.oldSHA1) || !f.m.HasKey("My", f.oldSHA1) || f.m.HasKey("My", "nope") {
		t.Fatal("lookups fold the store name")
	}
	n := f.m.KeyCount()
	f.m.RemoveCertificate("My", f.oldSHA1) // someone else removes it: the key goes too
	if f.m.HasCertificate("My", f.oldSHA1) || f.m.HasKey("My", f.oldSHA1) || f.m.KeyCount() != n-1 {
		t.Fatal("removed with its key")
	}
	p, err := h.ProtectedThumbprints(ctx)
	if err != nil || len(p.RDP) != 0 || len(p.WinRM) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	f.m.SetRDPThumbprint("ABCD")
	f.m.SetWinRMThumbprints("EF", "01")
	if p, _ := h.ProtectedThumbprints(ctx); len(p.RDP) != 0 {
		t.Fatalf("without the RDP-Tcp key the value protects nothing: %+v", p)
	}
	f.m.SetRDP(RDPConfig{Present: true, Enabled: true, Port: 3389, SecurityLayer: 2})
	if p, _ := h.ProtectedThumbprints(ctx); !slices.Equal(p.RDP, []string{"abcd"}) || !slices.Equal(p.WinRM, []string{"ef", "01"}) {
		t.Fatalf("%+v", p)
	}
	f.m.FailProtected(true)
	if _, err := h.ProtectedThumbprints(ctx); err == nil {
		t.Fatal("unreadable")
	}
}

func TestDemoHostDumpShowsAliceImported(t *testing.T) {
	m, err := Demo(now)
	if err != nil {
		t.Fatal(err)
	}
	dump := func() winproto.IISDumpResponse {
		var d winproto.IISDumpResponse
		if r := run(t, m, "iis-dump", nil, &d); r.Exit != 0 {
			t.Fatalf("%d %s", r.Exit, r.Stdout)
		}
		return d
	}
	for _, c := range dump().Certificates {
		if c.AliceImported {
			t.Fatalf("the demo's certificates are not Alice's: %+v", c)
		}
	}
	ca := pki.NewCA("Alice", pki.ECDSA256, now)
	loc := winproto.Locator{Type: winproto.BindingHostnamePort, Host: "www.win.example.test", Port: 443, AppID: winproto.AppIDIIS}
	prev, _ := m.Binding(loc)
	pc, _, _ := m.Host().Certificate(context.Background(), prev.Store, prev.CertSHA1)
	der, _ := base64.StdEncoding.DecodeString(pc.DER)
	nl := ca.Issue(pki.Opts{CommonName: "www.win.example.test", SANs: []string{"www.win.example.test"}}, now)
	if r := run(t, m, "iis-deploy --op "+opID(1), deployInput(t, loc, sum256(der), nl), nil); r.Exit != 0 {
		t.Fatalf("%s", r.Stdout)
	}
	nsha := thumbprint(nl.Cert.Raw)
	var seen int
	for _, c := range dump().Certificates {
		switch {
		case c.SHA1 == nsha && c.AliceImported:
			seen++
		case c.SHA1 != nsha && c.AliceImported:
			t.Fatalf("only the new one: %+v", c)
		}
	}
	if seen != 1 {
		t.Fatalf("%d", seen)
	}
}

// The CCS half (W5 Task 4): the folder IIS's Centralized Certificate Store reads, ccs-dump and ccs-deploy
// against it, and TLS served by SNI from its files.

// ccsFolder is the CCS folder of the CCS tests.
const ccsFolder = `C:\CCS`

// cfix is a model with CCS on at ccsFolder, a ccs http.sys record on 443 and one file for
// ccs.example.test that a third party made with the store's password (built at run time).
type cfix struct {
	m        *Model
	ca       *pki.CA
	inter    *x509.Certificate
	password string
	old      pki.Leaf
}

func newCCSFixture(t *testing.T) *cfix {
	t.Helper()
	f := &cfix{m: NewModel(), ca: pki.NewCA("CCS", pki.ECDSA256, now), password: "ccs-" + rand.Text()}
	f.inter = f.ca.Intermediate
	f.m.AddBinding(winproto.SSLBinding{Type: winproto.BindingCCS, IP: "0.0.0.0", Port: 443, AppID: winproto.AppIDIIS})
	f.m.SetCCS(true, ccsFolder)
	f.m.SetCCSPassword(f.password)
	f.old = f.issue("ccs.example.test")
	f.put("ccs.example.test.pfx", f.old)
	return f
}

func (f *cfix) issue(cn string) pki.Leaf {
	return f.ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, now)
}

func (f *cfix) put(name string, l pki.Leaf) {
	f.m.PutCCSFile(name, l.Cert, []*x509.Certificate{f.inter}, l.Key, f.password)
}

func (f *cfix) serve(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if err := f.m.Serve(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); f.m.serving.Wait() })
}

func (f *cfix) dump(t *testing.T) winproto.CCSDumpResponse {
	t.Helper()
	in, _ := json.Marshal(winproto.CCSDumpInput{Password: f.password})
	var d winproto.CCSDumpResponse
	if r := run(t, f.m, winproto.SubCCSDump, in, &d); r.Exit != 0 || !d.OK {
		t.Fatalf("ccs-dump: %d %s", r.Exit, r.Stdout)
	}
	return d
}

func (f *cfix) deploy(t *testing.T, op, host, expect string, l pki.Leaf) (linuxsshtest.Response, winproto.DeployResponse) {
	t.Helper()
	in, err := json.Marshal(winproto.CCSDeployInput{Path: ccsFolder, Host: host, ExpectSHA256: expect, ChainPEM: string(l.FullchainPEM),
		KeyPEM: string(l.KeyPEM), Password: f.password, ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	var d winproto.DeployResponse
	r := run(t, f.m, winproto.SubCCSDeploy+" --op "+op, in, &d)
	return r, d
}

// servedCCS is the leaf a fresh handshake with sni on the 443 listener presents ("" when it fails).
func (f *cfix) servedCCS(t *testing.T, sni string) string {
	t.Helper()
	cs, err := tlsDial(t, f.m.Endpoint(443), sni)
	if err != nil {
		return ""
	}
	return sum256(cs.PeerCertificates[0].Raw)
}

func TestModelCCSDeployAndServe(t *testing.T) {
	f := newCCSFixture(t)
	f.serve(t)
	d := f.dump(t)
	if !d.Enabled || !d.Local || d.Path != ccsFolder || len(d.Files) != 1 || d.Files[0].Host != "ccs.example.test" || d.Files[0].Problem != "" {
		t.Fatalf("%+v", d)
	}
	leaf, _ := base64.StdEncoding.DecodeString(d.Files[0].LeafDER)
	if sum256(leaf) != sum256(f.old.Cert.Raw) || len(d.Files[0].Chain) != 1 {
		t.Fatalf("the dump reads another leaf: %+v", d.Files[0])
	}
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(f.old.Cert.Raw) {
		t.Fatalf("before: %s", got)
	}

	nl := f.issue("ccs.example.test")
	r, dr := f.deploy(t, opID(1), "ccs.example.test", sum256(f.old.Cert.Raw), nl)
	if r.Exit != 0 || dr.Phase != winproto.PhaseCommitted || dr.NewSHA256 != sum256(nl.Cert.Raw) {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(nl.Cert.Raw) {
		t.Fatalf("a fresh handshake serves %s, not the new file", got)
	}
	bak := "ccs.example.test.pfx.alice-" + opID(1)[len(opID(1))-8:] + ".bak"
	if names := f.m.CCSNames(); !slices.Equal(names, []string{"ccs.example.test.pfx", bak}) {
		t.Fatalf("names %v", names)
	}
	if ev := f.m.Events(); len(ev) != 1 || ev[0].ID != 1004 || strings.Contains(ev[0].Text, f.password) {
		t.Fatalf("events %+v", ev)
	}

	var rs winproto.RestoreResponse
	if r := run(t, f.m, "iis-restore --op "+opID(1), restoreInput(), &rs); r.Exit != 0 || rs.Phase != winproto.PhaseRestored {
		t.Fatalf("restore: %d %s", r.Exit, r.Stdout)
	}
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(f.old.Cert.Raw) {
		t.Fatalf("after the restore: %s", got)
	}
	if names := f.m.CCSNames(); !slices.Equal(names, []string{"ccs.example.test.pfx"}) {
		t.Fatalf("the restore consumes the backup: %v", names)
	}
	if s := status(t, f.m, opID(1)); s.CurrentCertSHA256 != sum256(f.old.Cert.Raw) {
		t.Fatalf("status %+v", s)
	}
}

func TestModelCCSWildcard(t *testing.T) {
	f := newCCSFixture(t)
	wild, exact := f.issue("*.example.test"), f.issue("x.example.test")
	f.put("_.example.test.pfx", wild)
	f.serve(t)
	if got := f.servedCCS(t, "x.example.test"); got != sum256(wild.Cert.Raw) {
		t.Fatalf("the wildcard file serves %s", got)
	}
	// Ruling W5-13 (F17 measured): a wildcard file serves a suffix at any depth, never its own parent.
	if got := f.servedCCS(t, "a.b.example.test"); got != sum256(wild.Cert.Raw) {
		t.Fatalf("the wildcard file serves a host two labels down: %s", got)
	}
	if got := f.servedCCS(t, "example.test"); got != "" {
		t.Fatal("the wildcard file does not serve its own parent")
	}
	deeper := f.issue("*.b.example.test")
	f.put("_.b.example.test.pfx", deeper)
	if got := f.servedCCS(t, "a.b.example.test"); got != sum256(deeper.Cert.Raw) {
		t.Fatal("the nearest wildcard file comes first")
	}
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(f.old.Cert.Raw) {
		t.Fatal("the exact file comes before the wildcard")
	}
	// NTFS compares names without case: a file spelled in capitals is found for the host.
	f.put("X.Example.TEST.PFX", exact)
	if got := f.servedCCS(t, "x.example.test"); got != sum256(exact.Cert.Raw) {
		t.Fatalf("the exact file serves %s", got)
	}
	if _, ok := f.m.CCSFile("x.example.test.pfx"); !ok {
		t.Fatal("CCSFile finds a name without case")
	}
	// Without SNI, with CCS off, or with the store's password not opening the file, nothing is served.
	if got := f.servedCCS(t, ""); got != "" {
		t.Fatal("no SNI, no file")
	}
	f.m.PutCCSFile("y.example.test.pfx", exact.Cert, nil, exact.Key, "other-"+rand.Text())
	if got := f.servedCCS(t, "y.example.test"); got != "" {
		t.Fatal("a file the store's password does not open is not served (F16)")
	}
	f.m.SetCCS(false, ccsFolder)
	if got := f.servedCCS(t, "x.example.test"); got != "" {
		t.Fatal("CCS off serves nothing")
	}
}

func TestModelCCSFailReplace(t *testing.T) {
	f := newCCSFixture(t)
	before := mustCCS(t, f.m, "ccs.example.test.pfx")
	f.m.FailReplace(true)
	r, d := f.deploy(t, opID(1), "ccs.example.test", sum256(f.old.Cert.Raw), f.issue("ccs.example.test"))
	if r.Exit != 0 || d.Phase != winproto.PhaseRestored || d.FailedStep != winproto.StepWriteFile {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if names := f.m.CCSNames(); !slices.Equal(names, []string{"ccs.example.test.pfx"}) {
		t.Fatalf("names %v", names)
	}
	if after := mustCCS(t, f.m, "ccs.example.test.pfx"); !slices.Equal(after, before) {
		t.Fatal("the file changed")
	}
	// FailReplace fails the next replace only.
	if r, d := f.deploy(t, opID(2), "ccs.example.test", sum256(f.old.Cert.Raw), f.issue("ccs.example.test")); r.Exit != 0 || d.Phase != winproto.PhaseCommitted {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
}

func TestModelServeStaleCCS(t *testing.T) {
	f := newCCSFixture(t)
	f.serve(t)
	f.m.ServeStaleCCS(true)
	nl := f.issue("ccs.example.test")
	if r, d := f.deploy(t, opID(1), "ccs.example.test", sum256(f.old.Cert.Raw), nl); r.Exit != 0 || d.Phase != winproto.PhaseCommitted {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(f.old.Cert.Raw) {
		t.Fatal("a stale listener keeps the file as it was before the replace")
	}
	// The rollback puts that file back: it is served, stale or not.
	if r := run(t, f.m, "iis-restore --op "+opID(1), restoreInput(), nil); r.Exit != 0 {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(f.old.Cert.Raw) {
		t.Fatal("after the restore")
	}
	if r, _ := f.deploy(t, opID(2), "ccs.example.test", sum256(f.old.Cert.Raw), nl); r.Exit != 0 {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	f.m.Reboot()
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(nl.Cert.Raw) {
		t.Fatal("a reboot serves the file as it is")
	}
	third := f.issue("ccs.example.test")
	if r, _ := f.deploy(t, opID(3), "ccs.example.test", sum256(nl.Cert.Raw), third); r.Exit != 0 {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(nl.Cert.Raw) {
		t.Fatal("still stale after the reboot")
	}
	f.m.ServeStaleCCS(false)
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(third.Cert.Raw) {
		t.Fatal("with stale off the file is served again")
	}
	if leaf, n, ok := f.m.Served("0.0.0.0", 443, "ccs.example.test"); !ok || leaf != sum256(third.Cert.Raw) || n != 2 {
		t.Fatalf("Served %s %d %v", leaf, n, ok)
	}
}

func TestModelCCSFolderAndFiles(t *testing.T) {
	f := newCCSFixture(t)
	h := f.m.Host()
	ctx := context.Background()
	if en, p, err := h.CCSConfig(ctx); err != nil || !en || p != ccsFolder {
		t.Fatalf("%v %q %v", en, p, err)
	}
	_, v := call(t, f.m, "win-facts")
	if iis := v["iis"].(map[string]any); iis["ccs_enabled"] != true || iis["ccs_path"] != ccsFolder {
		t.Fatalf("win-facts %v", iis)
	}
	// A folder that does not exist lists nothing (a journal's folder after a path change); the trailing
	// backslash and the case of the folder do not matter.
	if l, err := h.ListCCS(ctx, `D:\gone`); err != nil || len(l) != 0 {
		t.Fatalf("%v %v", l, err)
	}
	if l, err := h.ListCCS(ctx, `c:\ccs\`); err != nil || len(l) != 1 || l[0].Name != "ccs.example.test.pfx" || l[0].Size == 0 {
		t.Fatalf("%+v %v", l, err)
	}
	if _, found, err := h.ReadCCS(ctx, `D:\gone`, "a.pfx", 10); found || err != nil {
		t.Fatal("a file of a folder that does not exist")
	}
	if data, found, err := h.ReadCCS(ctx, ccsFolder, "CCS.example.test.pfx", 10); !found || err != nil || len(data) != 11 {
		t.Fatalf("ReadCCS reads at most limit+1 bytes: %d %v %v", len(data), found, err)
	}
	if err := h.WriteCCSTemp(ctx, `D:\gone`, ".alice-x.tmp", []byte("x")); err == nil {
		t.Fatal("a temporary file in a folder that does not exist")
	}
	if err := h.WriteCCSTemp(ctx, ccsFolder, ".alice-x.tmp", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := h.WriteCCSTemp(ctx, ccsFolder, ".alice-x.tmp", []byte("x")); err == nil {
		t.Fatal("CREATE_NEW over an existing file")
	}
	if err := h.RemoveCCS(ctx, ccsFolder, "ccs.example.test.pfx"); err == nil {
		t.Fatal("RemoveCCS removes a .tmp or .bak only")
	}
	for _, folder := range []string{ccsFolder, `D:\gone`} {
		if err := h.RemoveCCS(ctx, folder, ".alice-x.tmp"); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.ReplaceCCS(ctx, ccsFolder, "ccs.example.test.pfx", ".alice-none.tmp", "b.bak"); err == nil {
		t.Fatal("a replace without its temporary file")
	}
	if err := h.RestoreCCS(ctx, ccsFolder, "none.bak", "ccs.example.test.pfx"); err == nil {
		t.Fatal("a restore without its backup")
	}
	if _, ok := f.m.CCSFile("none.pfx"); ok {
		t.Fatal("CCSFile of no file")
	}

	// A third party's bytes: not a PFX, and a PFX the password does not open.
	f.m.PutRawCCSFile("raw.example.test.pfx", []byte("not a pfx"))
	f.m.PutCCSFile("other.example.test.pfx", f.old.Cert, nil, f.old.Key, "other-"+rand.Text())
	f.m.PutRawCCSFile("readme.txt", []byte("x"))
	d := f.dump(t)
	problems := map[string]string{}
	for _, file := range d.Files {
		problems[file.Name] = file.Problem
	}
	if len(d.Files) != 3 || problems["raw.example.test.pfx"] != winproto.CCSProblemNotPFX ||
		problems["other.example.test.pfx"] != winproto.CCSProblemPasswordMismatch || problems["ccs.example.test.pfx"] != "" {
		t.Fatalf("%+v", d)
	}
	if !slices.Contains(f.m.CCSNames(), "readme.txt") {
		t.Fatal("CCSNames lists every name")
	}
	if leaf, chain, problem, err := h.OpenPFX(mustCCS(t, f.m, "ccs.example.test.pfx"), []byte(f.password)); err != nil || problem != "" ||
		sum256(leaf) != sum256(f.old.Cert.Raw) || len(chain) != 1 {
		t.Fatalf("OpenPFX %q %v", problem, err)
	}
}

func mustCCS(t *testing.T, m *Model, name string) []byte {
	t.Helper()
	b, ok := m.CCSFile(name)
	if !ok {
		t.Fatalf("no %s", name)
	}
	return b
}

func TestModelCCSPathChangeKeepsTheOldFolder(t *testing.T) {
	f := newCCSFixture(t)
	if r, d := f.deploy(t, opID(1), "ccs.example.test", sum256(f.old.Cert.Raw), f.issue("ccs.example.test")); r.Exit != 0 || d.Phase != winproto.PhaseCommitted {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	f.m.SetCCS(true, `D:\Certs`)
	if names := f.m.CCSNames(); len(names) != 0 {
		t.Fatalf("the new folder is empty: %v", names)
	}
	if r, _ := f.deploy(t, opID(2), "ccs.example.test", sum256(f.old.Cert.Raw), f.issue("ccs.example.test")); r.Exit != 3 {
		t.Fatalf("a deployment to the old folder: %d %s", r.Exit, r.Stdout)
	}
	// The rollback restores into the folder its journal names (W5 Ruling 17).
	var rs winproto.RestoreResponse
	if r := run(t, f.m, "iis-restore --op "+opID(1), restoreInput(), &rs); r.Exit != 0 || rs.Phase != winproto.PhaseRestored {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	f.m.SetCCS(true, ccsFolder)
	if got, _, err := pki.OpenPFX(mustCCS(t, f.m, "ccs.example.test.pfx"), []byte(f.password)); err != nil || sum256(got) != sum256(f.old.Cert.Raw) {
		t.Fatalf("the old folder's file holds the old leaf again: %v", err)
	}
}

func TestDemoHostHasCCS(t *testing.T) {
	m, err := Demo(now)
	if err != nil {
		t.Fatal(err)
	}
	pw := m.CCSPassword()
	if !winproto.ValidCCSPassword([]byte(pw)) {
		t.Fatalf("the demo's password is not one Alice manages (%d bytes)", len(pw))
	}
	in, _ := json.Marshal(winproto.CCSDumpInput{Password: pw})
	var d winproto.CCSDumpResponse
	if r := run(t, m, winproto.SubCCSDump, in, &d); r.Exit != 0 || !d.Enabled || !d.Local || d.Path != `C:\CCS` || len(d.Files) != 2 ||
		d.Files[0].Name != "_.unlinked.test.pfx" || d.Files[1].Name != "ccs.example.test.pfx" || d.Files[0].Problem != "" || d.Files[1].Problem != "" {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	var id winproto.IISDumpResponse
	if r := run(t, m, winproto.SubIISDump, nil, &id); r.Exit != 0 {
		t.Fatal(r.Exit)
	}
	linked := false
	for _, s := range id.Sites {
		for _, b := range s.Bindings {
			linked = linked || (b.Information == "*:443:ccs.example.test" && b.SSLFlags == 3)
		}
	}
	if !linked {
		t.Fatalf("no CCS site binding: %+v", id.Sites)
	}
	leaf, _ := base64.StdEncoding.DecodeString(d.Files[1].LeafDER)
	if got, n, ok := m.Served("0.0.0.0", 443, "ccs.example.test"); !ok || got != sum256(leaf) || n != 2 {
		t.Fatalf("served %s %d %v", got, n, ok)
	}
}

// A folder or a file that is a reparse point (W5 Ruling 3, Review Focus 1): the dump reports the folder
// not local, a deployment is refused before any write, and a marked file is neither listed nor read.
func TestModelCCSReparsePoints(t *testing.T) {
	f := newCCSFixture(t)
	before := mustCCS(t, f.m, "ccs.example.test.pfx")
	f.m.SetCCSReparse(`c:\ccs\`, true)
	if d := f.dump(t); d.Local || len(d.Files) != 0 || d.Path != ccsFolder {
		t.Fatalf("a reparse-point folder: %+v", d)
	}
	r, _ := f.deploy(t, opID(1), "ccs.example.test", sum256(f.old.Cert.Raw), f.issue("ccs.example.test"))
	var e winproto.ErrorResponse
	if err := json.Unmarshal(r.Stdout, &e); err != nil || r.Exit != 3 || e.Code != winproto.CodeCCSPathUnsupported {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if _, ok := f.m.Journal(opID(1)); ok || !slices.Equal(f.m.CCSNames(), []string{"ccs.example.test.pfx"}) ||
		!slices.Equal(mustCCS(t, f.m, "ccs.example.test.pfx"), before) {
		t.Fatal("something was written")
	}

	f.m.SetCCSReparse(ccsFolder, false)
	f.m.SetCCSReparse(ccsFolder+`\CCS.example.test.pfx`, true)
	if d := f.dump(t); !d.Local || len(d.Files) != 0 {
		t.Fatalf("a reparse-point file is not listed: %+v", d)
	}
	if _, _, err := f.m.Host().ReadCCS(context.Background(), ccsFolder, "ccs.example.test.pfx", 10); !errors.Is(err, winhelper.ErrCCSFileUnsupported) {
		t.Fatalf("ReadCCS of a reparse-point file: %v", err)
	}
	r, _ = f.deploy(t, opID(2), "ccs.example.test", sum256(f.old.Cert.Raw), f.issue("ccs.example.test"))
	if err := json.Unmarshal(r.Stdout, &e); err != nil || r.Exit != 2 || e.Code != winproto.CodeInvalidArgument {
		t.Fatalf("a deployment over a reparse-point file: %d %s", r.Exit, r.Stdout)
	}
	if _, ok := f.m.Journal(opID(2)); ok || !slices.Equal(mustCCS(t, f.m, "ccs.example.test.pfx"), before) {
		t.Fatal("something was written")
	}
	f.m.SetCCSReparse(ccsFolder+`\ccs.example.test.pfx`, false)
	if d := f.dump(t); len(d.Files) != 1 {
		t.Fatalf("unmarked: %+v", d)
	}
}

// IIS caches a served certificate by host, not by folder: a stale listener keeps it across a path
// change to a folder holding the same file name.
func TestModelServeStaleCCSAcrossAPathChange(t *testing.T) {
	f := newCCSFixture(t)
	f.serve(t)
	f.m.ServeStaleCCS(true)
	if r, _ := f.deploy(t, opID(1), "ccs.example.test", sum256(f.old.Cert.Raw), f.issue("ccs.example.test")); r.Exit != 0 {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	f.m.SetCCS(true, `D:\Certs`)
	f.put("ccs.example.test.pfx", f.issue("ccs.example.test"))
	if got := f.servedCCS(t, "ccs.example.test"); got != sum256(f.old.Cert.Raw) {
		t.Fatal("the stale certificate follows the host")
	}
}

// F15 as measured (ruling W5-10): IIS serves a file the helper replaced only after the ccs records are
// refreshed; ServeStaleCCS keeps the old bytes across a refresh; a third party's write is served.
func TestModelCCSServedAfterRefresh(t *testing.T) {
	f := newCCSFixture(t)
	ctx := context.Background()
	h := f.m.Host()
	served := func() string {
		t.Helper()
		leaf, _, ok := f.m.Served("127.0.0.1", 443, "ccs.example.test")
		if !ok {
			t.Fatal("nothing served")
		}
		return leaf
	}
	replace := func(l pki.Leaf, op8 string) {
		t.Helper()
		pkcs8, err := x509.MarshalPKCS8PrivateKey(l.Key)
		if err != nil {
			t.Fatal(err)
		}
		pfx, err := winhelper.BuildPFX(l.Cert.Raw, pkcs8, []byte(f.password))
		if err != nil {
			t.Fatal(err)
		}
		tmp, bak := ".alice-"+opID(1)+".tmp", "ccs.example.test.pfx.alice-"+op8+".bak"
		if err := h.WriteCCSTemp(ctx, ccsFolder, tmp, pfx); err != nil {
			t.Fatal(err)
		}
		if err := h.ReplaceCCS(ctx, ccsFolder, "ccs.example.test.pfx", tmp, bak); err != nil {
			t.Fatal(err)
		}
	}
	if served() != sum256(f.old.Cert.Raw) {
		t.Fatal("positive control")
	}
	a := f.issue("ccs.example.test")
	replace(a, "0000000a")
	if served() != sum256(f.old.Cert.Raw) {
		t.Fatal("a replaced file is served before the refresh")
	}
	if n, err := h.RefreshCCSRecords(ctx); n != 1 || err != nil {
		t.Fatalf("%d %v", n, err)
	}
	if served() != sum256(a.Cert.Raw) {
		t.Fatal("the refresh did not serve the new file")
	}

	f.m.FailCCSRefresh(true)
	b := f.issue("ccs.example.test")
	replace(b, "0000000b")
	if _, err := h.RefreshCCSRecords(ctx); err == nil || served() != sum256(a.Cert.Raw) {
		t.Fatalf("a failed refresh: %v", err)
	}
	f.m.FailCCSRefresh(false)

	f.m.ServeStaleCCS(true)
	if _, err := h.RefreshCCSRecords(ctx); err != nil || served() != sum256(a.Cert.Raw) {
		t.Fatal("ServeStaleCCS keeps the old bytes across a refresh")
	}
	f.m.ServeStaleCCS(false)
	if served() != sum256(b.Cert.Raw) {
		t.Fatal("ServeStaleCCS(false) serves the file")
	}

	c := f.issue("ccs.example.test")
	replace(c, "0000000c")
	f.put("CCS.example.test.pfx", f.old) // a third party's write is served at once
	if served() != sum256(f.old.Cert.Raw) {
		t.Fatal("a third party's write is not served")
	}
	// ReplaceFileW leaves the name as the helper spells it (F17 as measured).
	f.put("CCS.Example.Test.PFX", f.old)
	replace(c, "0000000d")
	if names := f.m.CCSNames(); !slices.Contains(names, "ccs.example.test.pfx") {
		t.Fatalf("%v", names)
	}
}

// W5-12 (F16, run 2): Windows answers a corrupt PFX as it answers another password
// (PFXImportCertStore 86, ERROR_INVALID_PASSWORD), so OpenPFX reports a password mismatch for it, as
// the emulator does: its MAC no longer verifies. Every byte is tried: none is a host error, and most
// (those of the authenticated content) read as a mismatch.
func TestModelCCSCorruptPFXIsAPasswordMismatch(t *testing.T) {
	f := newCCSFixture(t)
	pfx, ok := f.m.CCSFile("ccs.example.test.pfx")
	if !ok {
		t.Fatal("no file")
	}
	h := f.m.Host()
	mismatch := 0
	for i := range pfx {
		corrupt := slices.Clone(pfx)
		corrupt[i] ^= 0xff
		_, _, problem, err := h.OpenPFX(corrupt, []byte(f.password))
		// A byte outside what the MAC covers and the reader checks (a version, a tag's class) may still open.
		if err != nil || problem != "" && problem != winproto.CCSProblemPasswordMismatch && problem != winproto.CCSProblemNotPFX {
			t.Fatalf("byte %d: %q %v", i, problem, err)
		}
		if problem == winproto.CCSProblemPasswordMismatch {
			mismatch++
		}
	}
	corrupt := slices.Clone(pfx)
	corrupt[len(corrupt)/2] ^= 0xff // F16's corrupt file
	if _, _, problem, _ := h.OpenPFX(corrupt, []byte(f.password)); problem != winproto.CCSProblemPasswordMismatch {
		t.Fatalf("the middle byte: %q", problem)
	}
	if mismatch < len(pfx)/2 {
		t.Fatalf("only %d of %d corruptions read as a mismatch", mismatch, len(pfx))
	}
}

// rfix is a model with the RDP-Tcp listener (enabled, security layer 2, NLA on, the value absent) and its
// self-signed certificate in Remote Desktop, served on a random port (W6 Ruling 23).
type rfix struct {
	m    *Model
	ca   *pki.CA
	self pki.Leaf
}

func newRDPFixture(t *testing.T) *rfix {
	t.Helper()
	f := &rfix{m: NewModel(), ca: pki.NewCA("RDP", pki.ECDSA256, now), self: pki.SelfSigned("win-rdp01", pki.ECDSA256, now)}
	f.m.AddIntermediate(f.ca.IntermediatePEM)
	f.m.AddCertificate(winproto.RDPStoreSelfSigned, f.self.CertPEM, f.self.KeyPEM, CertOptions{})
	f.m.SetRDP(RDPConfig{Present: true, Enabled: true, NLA: true, Port: 3389, SecurityLayer: 2})
	ctx, cancel := context.WithCancel(context.Background())
	if err := f.m.Serve(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); f.m.serving.Wait() })
	return f
}

// probe is Alice's RDP probe of the listener: the served leaf's SHA-256, or the error.
func (f *rfix) probe(t *testing.T) (string, error) {
	t.Helper()
	h, p, err := net.SplitHostPort(f.m.Endpoint(3389))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	got, err := tlsverify.TLSProber{RDP: true}.Probe(context.Background(), h, port, "", helperproto.ProbeAny)
	return got.LeafSHA256, err
}

func (f *rfix) served(t *testing.T) string {
	t.Helper()
	got, err := f.probe(t)
	if err != nil {
		t.Fatalf("the RDP probe fails: %v", err)
	}
	return got
}

func (f *rfix) dump(t *testing.T) winproto.RDPDumpResponse {
	t.Helper()
	var d winproto.RDPDumpResponse
	if r := run(t, f.m, winproto.SubRDPDump, nil, &d); r.Exit != 0 || !d.OK {
		t.Fatalf("rdp-dump: %d %s", r.Exit, r.Stdout)
	}
	return d
}

func rdpDeployInput(t *testing.T, expect string, l pki.Leaf) []byte {
	t.Helper()
	in, err := json.Marshal(winproto.RDPDeployInput{ExpectSHA256: expect, ChainPEM: string(l.FullchainPEM), KeyPEM: string(l.KeyPEM),
		ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func (f *rfix) deploy(t *testing.T, op, expect string, l pki.Leaf) (linuxsshtest.Response, winproto.DeployResponse) {
	t.Helper()
	var d winproto.DeployResponse
	r := run(t, f.m, winproto.SubRDPDeploy+" --op "+op, rdpDeployInput(t, expect, l), &d)
	return r, d
}

func (f *rfix) issue() pki.Leaf {
	return f.ca.Issue(pki.Opts{CommonName: "rdp.example.test", SANs: []string{"rdp.example.test"}}, now)
}

func TestModelRDPDeployAndServe(t *testing.T) {
	f := newRDPFixture(t)
	selfSHA := sum256(f.self.Cert.Raw)
	d := f.dump(t)
	if !d.Present || !d.Enabled || !d.NLA || d.ValueSet || d.Port != 3389 || d.SecurityLayer != 2 || d.SelfSignedCount != 1 ||
		d.Certificate == nil || d.Certificate.SHA256 != selfSHA || d.Certificate.Store != winproto.RDPStoreSelfSigned {
		t.Fatalf("%+v", d)
	}
	if got := f.served(t); got != selfSHA {
		t.Fatalf("before: %s", got)
	}

	b := f.issue()
	bSHA1 := thumbprint(b.Cert.Raw)
	r, dr := f.deploy(t, opID(1), selfSHA, b)
	if r.Exit != 0 || dr.Phase != winproto.PhaseCommitted || dr.NewSHA256 != sum256(b.Cert.Raw) || dr.BuiltChainLength != 2 {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if f.m.RDPThumbprint() != bSHA1 || !f.m.KeyReadableByNetworkService("My", bSHA1) {
		t.Fatalf("value %q, readable %v", f.m.RDPThumbprint(), f.m.KeyReadableByNetworkService("My", bSHA1))
	}
	if got := f.served(t); got != sum256(b.Cert.Raw) {
		t.Fatalf("a fresh handshake serves %s, not B", got)
	}
	// The helper's own probe reaches the listener too (tls-probe --rdp).
	if r, v := call(t, f.m, "tls-probe --addr 127.0.0.1 --port 3389 --sni _ --key-type any --rdp"); r.Exit != 0 ||
		v["leaf_sha256"] != sum256(b.Cert.Raw) || v["chain_length"] != float64(2) {
		t.Fatalf("%d %v", r.Exit, v)
	}
	if d := f.dump(t); !d.ValueSet || d.Certificate == nil || d.Certificate.SHA1 != bSHA1 || d.SelfSignedCount != 0 {
		t.Fatalf("%+v", d)
	}
	if ev := f.m.Events(); len(ev) != 1 || ev[0].ID != 1005 {
		t.Fatalf("events %+v", ev)
	}
	if s := status(t, f.m, opID(1)); s.CurrentCertSHA256 != sum256(b.Cert.Raw) {
		t.Fatalf("status %+v", s)
	}
	// The same certificate again: the listener names it and NETWORK SERVICE reads its key: unchanged.
	if r, dr := f.deploy(t, opID(2), sum256(b.Cert.Raw), b); r.Exit != 0 || dr.Phase != winproto.PhaseUnchanged {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}

	var rs winproto.RestoreResponse
	if r := run(t, f.m, "iis-restore --op "+opID(1), restoreInput(), &rs); r.Exit != 0 || rs.Phase != winproto.PhaseRestored {
		t.Fatalf("restore: %d %s", r.Exit, r.Stdout)
	}
	if f.m.RDPThumbprint() != "" || f.m.KeyReadableByNetworkService("My", bSHA1) {
		t.Fatalf("the value %q is not absent again, or the grant stays", f.m.RDPThumbprint())
	}
	if got := f.served(t); got != selfSHA {
		t.Fatalf("after the restore: %s", got)
	}
}

func TestModelRDPNeedsKeyRead(t *testing.T) {
	f := newRDPFixture(t)
	c := f.issue()
	sha := f.m.AddCertificate("My", c.CertPEM, c.KeyPEM, CertOptions{})
	f.m.SetRDPThumbprint(strings.Map(func(r rune) rune { // upper-case hex
		if r >= 'a' && r <= 'f' {
			return r - 'a' + 'A'
		}
		return r
	}, sha))
	if f.m.RDPThumbprint() != sha {
		t.Fatalf("value %q", f.m.RDPThumbprint())
	}
	if _, err := f.probe(t); !errors.Is(err, tlsverify.ErrProbeFailed) {
		t.Fatalf("a key NETWORK SERVICE cannot read fails the handshake (F21): %v", err)
	}
	h, ctx := f.m.Host(), context.Background()
	if ok, err := h.RDPKeyRead(ctx, "MY", sha); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if err := h.SetRDPKeyRead(ctx, "MY", sha, true); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.RDPKeyRead(ctx, "My", sha); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if got := f.served(t); got != sum256(c.Cert.Raw) {
		t.Fatalf("after the grant: %s", got)
	}
	// The key methods refuse every store but My, and a certificate the store does not hold.
	selfSHA1 := thumbprint(f.self.Cert.Raw)
	if _, err := h.RDPKeyRead(ctx, winproto.RDPStoreSelfSigned, selfSHA1); err == nil {
		t.Fatal("Remote Desktop is refused")
	}
	if err := h.SetRDPKeyRead(ctx, "WebHosting", sha, true); err == nil {
		t.Fatal("WebHosting is refused")
	}
	if _, err := h.RDPKeyRead(ctx, "MY", strings.Repeat("0", 40)); err == nil {
		t.Fatal("an absent certificate is refused")
	}
	if !f.m.KeyReadableByNetworkService(winproto.RDPStoreSelfSigned, selfSHA1) {
		t.Fatal("TermService's own certificate is readable by NETWORK SERVICE")
	}
	// Removed with its certificate, the flag goes too.
	f.m.RemoveCertificate("My", sha)
	if f.m.KeyReadableByNetworkService("My", sha) {
		t.Fatal("the flag outlives the key")
	}
	// The value is 20 bytes or nothing; the RDP-Tcp key must exist.
	if err := h.SetRDPCertificate(ctx, "abcd"); err == nil {
		t.Fatal("a value that is not 20 bytes")
	}
	f.m.SetRDP(RDPConfig{})
	if err := h.SetRDPCertificate(ctx, sha); err == nil {
		t.Fatal("no RDP-Tcp key")
	}
	if l, err := h.RDPListener(ctx); err != nil || l.Present || l.CertSHA1 != "" {
		t.Fatalf("%+v %v", l, err)
	}
	if p, _ := h.ProtectedThumbprints(ctx); len(p.RDP) != 0 {
		t.Fatalf("without the listener no value protects: %+v", p)
	}
}

// rdpConfirm sends a Connection Request with requestedProtocols to addr and returns what the listener
// answers in its first 19 bytes (fewer when it closes first).
func rdpConfirm(t *testing.T, addr string, requested byte) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	req := slices.Clone(helperproto.RDPConnectionRequest)
	req[len(req)-4] = requested
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 19)
	n, _ := io.ReadFull(c, b)
	return b[:n]
}

func TestModelRDPSecurityLayer(t *testing.T) {
	f := newRDPFixture(t)
	addr := f.m.Endpoint(3389)
	// NLA on: HYBRID when asked for, HYBRID_REQUIRED_BY_SERVER otherwise (F22 as modelled).
	if got := rdpConfirm(t, addr, 3); !slices.Equal(got, helperproto.RDPConfirm(helperproto.RDPProtocolHybrid)) {
		t.Fatalf("% x", got)
	}
	if got := rdpConfirm(t, addr, 1); !slices.Equal(got, helperproto.RDPFailure(5)) {
		t.Fatalf("% x", got)
	}
	// NLA off: HYBRID still whenever asked for (F22 measured HYBRID with NLA on and off), SSL when asked
	// for SSL alone, SSL_REQUIRED_BY_SERVER otherwise.
	f.m.SetRDP(RDPConfig{Present: true, Enabled: true, Port: 3389, SecurityLayer: 2})
	if got := rdpConfirm(t, addr, 3); !slices.Equal(got, helperproto.RDPConfirm(helperproto.RDPProtocolHybrid)) {
		t.Fatalf("NLA off, SSL|HYBRID asked: % x", got)
	}
	if got := rdpConfirm(t, addr, 1); !slices.Equal(got, helperproto.RDPConfirm(helperproto.RDPProtocolSSL)) {
		t.Fatalf("NLA off, SSL asked: % x", got)
	}
	if got := rdpConfirm(t, addr, 0); !slices.Equal(got, helperproto.RDPFailure(1)) {
		t.Fatalf("% x", got)
	}
	if got := f.served(t); got != sum256(f.self.Cert.Raw) {
		t.Fatalf("NLA off: %s", got)
	}

	f.m.SetRDP(RDPConfig{Present: true, Enabled: true, NLA: true, Port: 3389, SecurityLayer: 0})
	if _, err := f.probe(t); !errors.Is(err, tlsverify.ErrProbeFailed) || !errors.Is(err, helperproto.ErrRDPNoTLS) {
		t.Fatalf("layer 0: %v", err)
	}
	if got := rdpConfirm(t, addr, 3); !slices.Equal(got, helperproto.RDPFailure(2)) {
		t.Fatalf("% x", got)
	}
	if d := f.dump(t); d.SecurityLayer != 0 {
		t.Fatalf("%+v", d)
	}
	var e winproto.ErrorResponse
	if r := run(t, f.m, winproto.SubRDPDeploy+" --op "+opID(1), rdpDeployInput(t, sum256(f.self.Cert.Raw), f.issue()), &e); r.Exit == 0 ||
		e.Code != winproto.CodeRDPTLSOff {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}

	// RDP turned off: nothing answers the negotiation.
	f.m.SetRDP(RDPConfig{Present: true, Port: 3389, SecurityLayer: 2})
	if got := rdpConfirm(t, addr, 3); len(got) != 0 {
		t.Fatalf("% x", got)
	}
	if _, err := f.probe(t); !errors.Is(err, helperproto.ErrRDPNegotiation) {
		t.Fatalf("disabled: %v", err)
	}
	// Bytes that are no Connection Request are not answered.
	f.m.SetRDP(RDPConfig{Present: true, Enabled: true, Port: 3389, SecurityLayer: 2})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0, 0, 0, 0, 0})
	// Closed, not timed out (W6-7): EOF, or a reset when the listener closed with bytes still unread.
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("a TLS ClientHello without the negotiation is closed unanswered; got %v", err)
	}
}

func TestModelRDPFailKeyACL(t *testing.T) {
	f := newRDPFixture(t)
	b := f.issue()
	f.m.FailKeyACL(true)
	r, dr := f.deploy(t, opID(1), sum256(f.self.Cert.Raw), b)
	if r.Exit != 0 || dr.Phase != winproto.PhaseRestored || dr.FailedStep != winproto.StepGrantKeyRead || dr.RDPKeyACLLeft {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if f.m.RDPThumbprint() != "" || f.m.KeyReadableByNetworkService("My", thumbprint(b.Cert.Raw)) {
		t.Fatal("something is left changed")
	}
	if got := f.served(t); got != sum256(f.self.Cert.Raw) {
		t.Fatalf("%s", got)
	}
	// Once: the next deployment grants.
	if r, dr := f.deploy(t, opID(2), sum256(f.self.Cert.Raw), b); r.Exit != 0 || dr.Phase != winproto.PhaseCommitted {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
}

// ServeStaleRDP is StaleTLS's RDP half: from the next write of the value on, the listener keeps serving
// what it served before, until ServeStaleRDP(false) or a reboot.
func TestModelServeStaleRDP(t *testing.T) {
	f := newRDPFixture(t)
	selfSHA := sum256(f.self.Cert.Raw)
	b := f.issue()
	f.m.ServeStaleRDP(true)
	if r, dr := f.deploy(t, opID(1), selfSHA, b); r.Exit != 0 || dr.Phase != winproto.PhaseCommitted {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if got := f.served(t); got != selfSHA {
		t.Fatalf("a stale listener keeps the self-signed certificate: %s", got)
	}
	f.m.ServeStaleRDP(false)
	if got := f.served(t); got != sum256(b.Cert.Raw) {
		t.Fatalf("with stale off: %s", got)
	}
	f.m.ServeStaleRDP(true)
	f.m.SetRDPThumbprint("")
	if got := f.served(t); got != sum256(b.Cert.Raw) {
		t.Fatalf("stale across an outside write: %s", got)
	}
	f.m.Reboot()
	if got := f.served(t); got != selfSHA {
		t.Fatalf("a reboot ends the stale listener: %s", got)
	}
}

// W6-6: a stale listener pinned while it had no usable certificate keeps that failure through later
// writes of the value; it never serves the certificate a later write named.
func TestModelRDPStalePinKeepsAFailure(t *testing.T) {
	f := newRDPFixture(t)
	f.m.RemoveCertificate(winproto.RDPStoreSelfSigned, thumbprint(f.self.Cert.Raw))
	if got, err := f.probe(t); err == nil {
		t.Fatalf("Remote Desktop empty: the handshake fails, served %s", got)
	}
	f.m.ServeStaleRDP(true)
	ctx := context.Background()
	var last string
	for i := range 2 {
		l := f.issue()
		last = sum256(l.Cert.Raw)
		sha := f.m.AddCertificate("My", l.CertPEM, l.KeyPEM, CertOptions{})
		if err := f.m.Host().SetRDPKeyRead(ctx, "My", sha, true); err != nil {
			t.Fatal(err)
		}
		f.m.SetRDPThumbprint(sha)
		if got, err := f.probe(t); err == nil {
			t.Fatalf("write %d: a stale listener keeps its failure, served %s", i+1, got)
		}
	}
	f.m.ServeStaleRDP(false)
	if got := f.served(t); got != last {
		t.Fatalf("with stale off the value's certificate is served: %s", got)
	}
}

// W6-8: adding a certificate that My holds already keeps the NETWORK SERVICE grant of its key; a first
// add into My grants nothing, into Remote Desktop everything (TermService made it).
func TestModelReAddKeepsTheNetworkServiceGrant(t *testing.T) {
	m := NewModel()
	l := pki.SelfSigned("re-add", pki.ECDSA256, now)
	sha := m.AddCertificate("My", l.CertPEM, l.KeyPEM, CertOptions{})
	if m.KeyReadableByNetworkService("My", sha) {
		t.Fatal("a first add into My grants NETWORK SERVICE nothing")
	}
	if err := m.Host().SetRDPKeyRead(context.Background(), "My", sha, true); err != nil {
		t.Fatal(err)
	}
	m.AddCertificate("My", l.CertPEM, l.KeyPEM, CertOptions{})
	if !m.KeyReadableByNetworkService("My", sha) {
		t.Fatal("re-adding the certificate dropped the NETWORK SERVICE grant")
	}
	self := pki.SelfSigned("win-rdp01", pki.ECDSA256, now)
	if !m.KeyReadableByNetworkService(winproto.RDPStoreSelfSigned, m.AddCertificate(winproto.RDPStoreSelfSigned, self.CertPEM, self.KeyPEM, CertOptions{})) {
		t.Fatal("Remote Desktop's own certificate is readable")
	}
}

func TestDemoHostHasRDP(t *testing.T) {
	m, err := Demo(now)
	if err != nil {
		t.Fatal(err)
	}
	var d winproto.RDPDumpResponse
	if r := run(t, m, winproto.SubRDPDump, nil, &d); r.Exit != 0 || !d.Present || !d.Enabled || !d.NLA || d.ValueSet || d.Port != 3389 ||
		d.SecurityLayer != 2 || d.SelfSignedCount != 1 || d.Certificate == nil || d.Certificate.Store != winproto.RDPStoreSelfSigned {
		t.Fatalf("%d %s", r.Exit, r.Stdout)
	}
	if !m.KeyReadableByNetworkService(winproto.RDPStoreSelfSigned, d.Certificate.SHA1) {
		t.Fatal("NETWORK SERVICE reads the self-signed certificate's key")
	}
	// The real helper names four stores in win-facts; Remote Desktop is not one of them.
	if _, v := call(t, m, "win-facts"); fmt.Sprint(v["stores"]) != "[My WebHosting CA Root]" {
		t.Fatalf("stores %v", v["stores"])
	}
}
