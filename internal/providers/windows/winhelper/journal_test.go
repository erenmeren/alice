package winhelper

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"alice/internal/providers/windows/winproto"
)

const (
	op1 = "11111111-1111-4111-8111-111111111111"
	op2 = "22222222-2222-4222-8222-222222222222"
	op3 = "33333333-3333-4333-8333-333333333333"
)

var (
	s256a = strings.Repeat("a", 64)
	s256b = strings.Repeat("b", 64)
	s256c = strings.Repeat("c", 64)
)

const canon443 = "http.sys/ipport/0.0.0.0:443"

func loc443() winproto.Locator {
	return winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 443, AppID: app1}
}

func sampleJournal(op string) journal {
	prev := ipb(443, "", h1)
	prev.Flags, prev.CertCheckMode, prev.RevocationFreshnessTime, prev.URLRetrievalTimeout = 0x42, 1, 600, 7000
	prev.CTLIdentifier, prev.CTLStore = "ctl", "Root"
	prev.Extended = []winproto.ExtendedParam{{Type: 1, Data: base64.StdEncoding.EncodeToString([]byte{1, 2, 3})}}
	return journal{Op: op, Phase: winproto.PhasePrepared, Binding: canon443, Locator: loc443(), Previous: prev,
		PreviousSHA1: h1, PreviousSHA256: s256a, NewSHA1: h2, NewSHA256: s256b, Store: "MY",
		Intermediates: []certRef{{SHA1: h3, SHA256: s256c}}, AliceImported: true,
		Steps:         []winproto.Step{{Name: winproto.StepImportChain, Status: winproto.StepOK}},
		ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{s256c}}
}

func TestJournalRoundTripAndValidation(t *testing.T) {
	h := newWriteHost()
	j := sampleJournal(op1)
	if err := writeJournal(h, j); err != nil {
		t.Fatal(err)
	}
	if h.stateLog[0].name != "journal/"+op1+".json" {
		t.Fatal(h.stateLog[0].name)
	}
	got, found, err := readJournal(h, op1)
	if err != nil || !found || !reflect.DeepEqual(got, j) {
		t.Fatalf("%v %v\n%+v\n%+v", err, found, got, j)
	}
	if _, found, err := readJournal(h, op2); found || err != nil {
		t.Fatal(found, err)
	}
	// nil steps are written as an empty list
	j2 := sampleJournal(op2)
	j2.Steps = nil
	if err := writeJournal(h, j2); err != nil || !strings.Contains(string(h.state["journal/"+op2+".json"]), `"steps":[]`) {
		t.Fatal(err)
	}

	bad := map[string]func(*journal){
		"another op":      func(j *journal) { j.Op = op2 },
		"bad op":          func(j *journal) { j.Op = "x" },
		"unknown phase":   func(j *journal) { j.Phase = "done" },
		"none phase":      func(j *journal) { j.Phase = winproto.PhaseNone },
		"too many steps":  func(j *journal) { j.Steps = make([]winproto.Step, maxSteps+1) },
		"bad step":        func(j *journal) { j.Steps = []winproto.Step{{Name: "x", Status: winproto.StepOK}} },
		"bad step status": func(j *journal) { j.Steps = []winproto.Step{{Name: winproto.StepBind, Status: "maybe"}} },
		"bad step error": func(j *journal) {
			j.Steps = []winproto.Step{{Name: winproto.StepBind, Status: winproto.StepFailed, Error: "oops"}}
		},
		"bad prev sha1":      func(j *journal) { j.PreviousSHA1 = "AB" },
		"prev sha1 differs":  func(j *journal) { j.PreviousSHA1 = h3 },
		"bad prev sha256":    func(j *journal) { j.PreviousSHA256 = strings.Repeat("A", 64) },
		"absent sha256":      func(j *journal) { j.NewSHA256 = strings.Repeat("0", 63) + "x" },
		"bad new sha1":       func(j *journal) { j.NewSHA1 = "" },
		"bad store":          func(j *journal) { j.Store = `My\..\x` },
		"bad prev store":     func(j *journal) { j.Previous.Store = "a/b" },
		"bad binding":        func(j *journal) { j.Binding = "http.sys/ipport/0.0.0.0:444" },
		"bad locator":        func(j *journal) { j.Locator.Type = winproto.BindingCCS },
		"prev other port":    func(j *journal) { j.Previous.Port = 444 },
		"prev other ip":      func(j *journal) { j.Previous.IP = "10.0.0.5" },
		"prev bad ip":        func(j *journal) { j.Previous.IP = "x" },
		"prev other type":    func(j *journal) { j.Previous.Type = winproto.BindingHostnamePort },
		"prev long text":     func(j *journal) { j.Previous.CTLStore = strings.Repeat("x", winproto.MaxText+1) },
		"prev bad extended":  func(j *journal) { j.Previous.Extended = []winproto.ExtendedParam{{Type: 1, Data: "!"}} },
		"bad intermediate":   func(j *journal) { j.Intermediates = []certRef{{SHA1: h1, SHA256: "x"}} },
		"many intermediates": func(j *journal) { j.Intermediates = make([]certRef, winproto.MaxChainCerts+1) },
		"bad failed step":    func(j *journal) { j.FailedStep = "x" },
		"bad cause step":     func(j *journal) { j.CauseStep = "x" },
		"bad error":          func(j *journal) { j.Error = "OS said no" },
		"bad prev record":    func(j *journal) { j.PrevRecord = "x" },
		"own prev record":    func(j *journal) { j.PrevRecord = op1 },
		"bad forbidden":      func(j *journal) { j.ForbiddenSPKI = []string{"x"} },
		"bad forbidden leaf": func(j *journal) { j.ForbiddenLeaf = []string{s256a, s256a} },
	}
	for name, mutate := range bad {
		j := sampleJournal(op1)
		mutate(&j)
		if j.valid(op1) {
			t.Errorf("%s: valid", name)
		}
		if name == "another op" {
			continue // a valid journal of op2: written as op2's
		}
		h := newWriteHost()
		if err := writeJournal(h, j); !errors.Is(err, errBadJournal) || len(h.stateLog) != 0 {
			t.Errorf("%s: written (%v)", name, err)
		}
	}
	// every phase but none and fenced is a journal phase; a step of each name and error class is valid
	for _, p := range []string{winproto.PhasePrepared, winproto.PhaseWriting, winproto.PhaseCommitted, winproto.PhaseUnchanged,
		winproto.PhaseRestoring, winproto.PhaseRestored, winproto.PhaseRestoreFailed, winproto.PhaseRestoreForbidden} {
		j := sampleJournal(op1)
		j.Phase = p
		j.FailedStep, j.CauseStep, j.Error = winproto.StepBind, winproto.StepBind, winproto.ErrReadBack
		j.Steps = []winproto.Step{{Name: winproto.StepImportCertificate, Status: winproto.StepFailed, Error: winproto.ErrKeyUnusable},
			{Name: winproto.StepJournal, Status: winproto.StepOK}, {Name: winproto.StepRestore, Status: winproto.StepFailed, Error: winproto.ErrForbidden}}
		if !j.valid(op1) {
			t.Errorf("%s: invalid", p)
		}
	}
	// a hostnameport journal, a NULL previous store, no intermediates and nil lists are valid
	j = sampleJournal(op1)
	j.Locator = winproto.Locator{Type: winproto.BindingHostnamePort, Host: "www.example.com", Port: 443, AppID: app1}
	j.Binding = "http.sys/hostnameport/www.example.com:443"
	j.Previous.Type, j.Previous.IP, j.Previous.Host = winproto.BindingHostnamePort, "", "www.example.com"
	j.Intermediates, j.ForbiddenLeaf, j.ForbiddenSPKI, j.PrevRecord = nil, nil, nil, op2
	if !j.valid(op1) {
		t.Fatal("hostnameport journal invalid")
	}
	// the record as http.sys spells it (upper-case host, app id without braces) names the same binding
	j.Previous.Host, j.Previous.AppID = "WWW.Example.com", "4DC3E181-E14B-4A21-B022-59FC669B0914"
	if !j.valid(op1) {
		t.Fatal("record spelling refused")
	}
	j.Previous.Host = "api.example.com"
	if j.valid(op1) {
		t.Fatal("a previous record of another host accepted")
	}
	// an IPv4-mapped IPv6 spelling of the record's IP names the same ipport binding
	j = sampleJournal(op1)
	j.Previous.IP = "::ffff:0.0.0.0"
	if !j.valid(op1) {
		t.Fatal("mapped IP refused")
	}

	// fenced tombstones: the operation, the phase and a handed-back record only
	tomb := journal{Op: op1, Phase: winproto.PhaseFenced}
	if !tomb.valid(op1) || tomb.valid(op2) {
		t.Fatal("tombstone")
	}
	tomb.PrevRecord = op2
	if !tomb.valid(op1) {
		t.Fatal("tombstone with a record")
	}
	for name, mutate := range map[string]func(*journal){
		"binding": func(j *journal) { j.Binding = canon443 },
		"sha":     func(j *journal) { j.NewSHA256 = s256a },
		"steps":   func(j *journal) { j.Steps = []winproto.Step{{Name: winproto.StepBind, Status: winproto.StepOK}} },
		"empty":   func(j *journal) { j.Steps = []winproto.Step{} },
		"store":   func(j *journal) { j.Store = "MY" },
		"record":  func(j *journal) { j.PrevRecord = "x" },
		"import":  func(j *journal) { j.AliceImported = true },
	} {
		tb := journal{Op: op1, Phase: winproto.PhaseFenced}
		mutate(&tb)
		if tb.valid(op1) {
			t.Errorf("tombstone with %s: valid", name)
		}
	}
	if err := writeJournal(h, journal{Op: op3, Phase: winproto.PhaseFenced}); err != nil {
		t.Fatal(err)
	}
	if got, found, err := readJournal(h, op3); err != nil || !found || got.Phase != winproto.PhaseFenced || got.Steps != nil {
		t.Fatalf("%+v %v %v", got, found, err)
	}
}

func TestReadJournalRefusesBadFiles(t *testing.T) {
	good, _ := json.Marshal(sampleJournal(op1))
	for name, data := range map[string]string{
		"not json":      "{",
		"unknown field": strings.Replace(string(good), `{"op"`, `{"key_pem":"x","op"`, 1),
		"two values":    string(good) + " {}",
		"another op":    strings.Replace(string(good), op1, op2, 1),
		"too large":     string(good) + strings.Repeat(" ", MaxStateBytes),
	} {
		h := newWriteHost()
		h.state["journal/"+op1+".json"] = []byte(data)
		if _, found, err := readJournal(h, op1); !errors.Is(err, errBadJournal) || found {
			t.Errorf("%s: %v %v", name, found, err)
		}
	}
	h := newWriteHost()
	h.readStateErr = errors.New("disk")
	if _, _, err := readJournal(h, op1); err == nil || errors.Is(err, errBadJournal) {
		t.Fatal(err)
	}
	if _, _, err := readJournal(h, "../x"); !errors.Is(err, errBadJournal) {
		t.Fatal("an invalid op id must not be read")
	}
	h = newWriteHost()
	h.writeStateErr = func(string) error { return errors.New("disk full") }
	if err := writeJournal(h, sampleJournal(op1)); err == nil {
		t.Fatal("write error lost")
	}
}

// The journal never holds key material: no field is bytes, and no JSON name speaks of keys, PEM, DER,
// PFX or passwords (a reflect walk over the whole type, nested structs included).
func TestJournalHoldsNoKeyMaterial(t *testing.T) {
	var walk func(t *testing.T, path string, typ reflect.Type)
	walk = func(t *testing.T, path string, typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Slice, reflect.Array:
			if typ.Elem().Kind() == reflect.Uint8 {
				t.Errorf("%s holds bytes", path)
			}
			walk(t, path+"[]", typ.Elem())
		case reflect.Struct:
			for i := range typ.NumField() {
				f := typ.Field(i)
				name := asciiLower(f.Name + " " + f.Tag.Get("json"))
				for _, bad := range []string{"pem", "der", "pfx", "password", "private", "pkcs", "secret"} {
					if strings.Contains(name, bad) {
						t.Errorf("%s.%s: %q", path, f.Name, bad)
					}
				}
				walk(t, path+"."+f.Name, f.Type)
			}
		case reflect.Pointer: // journal.Existed (*bool): what it points to is checked
			walk(t, path+"*", typ.Elem())
		case reflect.Map, reflect.Interface:
			t.Errorf("%s: %s cannot be checked", path, typ.Kind())
		}
	}
	walk(t, "journal", reflect.TypeFor[journal]())
	walk(t, "bindingRecord", reflect.TypeFor[bindingRecord]())
	walk(t, "importEntry", reflect.TypeFor[importsFile]())
}

func TestTrimSteps(t *testing.T) {
	var steps []winproto.Step
	for i := range 100 {
		steps = append(steps, winproto.Step{Name: winproto.StepRestore, Status: winproto.StepOK, Error: string(rune('a' + i%26))})
	}
	if got := trimSteps(steps[:maxSteps-8]); len(got) != maxSteps-8 {
		t.Fatal(len(got))
	}
	got := trimSteps(steps)
	if len(got) != maxSteps-8 || !reflect.DeepEqual(got[:keptHead], steps[:keptHead]) || got[len(got)-1] != steps[99] ||
		got[keptHead] != steps[100-(maxSteps-8-keptHead)] {
		t.Fatalf("%d", len(got))
	}
}

func TestBindingRecordAndSuperseded(t *testing.T) {
	h := newWriteHost()
	sum := sha256.Sum256([]byte(canon443))
	name := "bindings/" + hex.EncodeToString(sum[:]) + ".json"
	if bindingRecordName(canon443) != name {
		t.Fatal(bindingRecordName(canon443))
	}
	if op, err := readBindingRecord(h, canon443); op != "" || err != nil {
		t.Fatal(op, err)
	}

	// op1 deploys (committed), then op2 deploys: op1 is superseded, op2 is not.
	j1 := sampleJournal(op1)
	j1.Phase = winproto.PhaseCommitted
	mustWrite(t, h, j1)
	if err := writeBindingRecord(h, canon443, op1); err != nil {
		t.Fatal(err)
	}
	if s, err := superseded(h, j1); s || err != nil {
		t.Fatal("op1 alone superseded", err)
	}
	j2 := sampleJournal(op2)
	j2.Phase, j2.PrevRecord = winproto.PhaseCommitted, op1
	mustWrite(t, h, j2)
	if err := writeBindingRecord(h, canon443, op2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(h.state[name]), `"binding":"http.sys/ipport/0.0.0.0:443"`) {
		t.Fatal(string(h.state[name]))
	}
	if s, err := superseded(h, j1); !s || err != nil {
		t.Fatal("op1 not superseded", err)
	}
	if s, _ := superseded(h, j2); s {
		t.Fatal("op2 superseded")
	}

	// op3 changed nothing (prepared, then unchanged or fenced): the record falls through to op2.
	for _, phase := range []string{winproto.PhasePrepared, winproto.PhaseUnchanged} {
		j3 := sampleJournal(op3)
		j3.Phase, j3.PrevRecord = phase, op2
		mustWrite(t, h, j3)
		if err := writeBindingRecord(h, canon443, op3); err != nil {
			t.Fatal(err)
		}
		if op, ok, err := latestOp(h, j1); op != op2 || !ok || err != nil {
			t.Fatalf("%s: %s %v %v", phase, op, ok, err)
		}
		if s, _ := superseded(h, j2); s {
			t.Fatalf("%s: op2 superseded by a no-op", phase)
		}
	}
	mustWrite(t, h, journal{Op: op3, Phase: winproto.PhaseFenced, PrevRecord: op2})
	if s, _ := superseded(h, j2); s {
		t.Fatal("op2 superseded by a fence")
	}

	// handing back: only an operation that changed nothing hands the record back.
	j3 := sampleJournal(op3)
	j3.PrevRecord = op2
	for _, phase := range []string{winproto.PhaseWriting, winproto.PhaseCommitted, winproto.PhaseRestoring, winproto.PhaseRestored} {
		_ = writeBindingRecord(h, canon443, op3)
		jc := j3
		jc.Phase = phase
		if err := handBack(h, jc); err != nil {
			t.Fatal(err)
		}
		if op, _ := readBindingRecord(h, canon443); op != op3 {
			t.Fatalf("%s handed the record back", phase)
		}
	}
	// the record names op3 (prepared, a no-op) and goes back to op2; a record naming another op stays.
	if err := handBack(h, j3); err != nil {
		t.Fatal(err)
	}
	if op, _ := readBindingRecord(h, canon443); op != op2 {
		t.Fatal(op)
	}
	if err := handBack(h, j3); err != nil {
		t.Fatal(err)
	}
	if op, _ := readBindingRecord(h, canon443); op != op2 {
		t.Fatal(op)
	}
	if err := handBack(h, journal{Op: op3, Phase: winproto.PhaseFenced}); err != nil {
		t.Fatal("a tombstone without a binding has nothing to hand back")
	}

	// a record naming an operation without a journal, or a loop, cannot be decided: superseded.
	if err := writeBindingRecord(h, canon443, "44444444-4444-4444-8444-444444444444"); err != nil {
		t.Fatal(err)
	}
	if s, err := superseded(h, j2); !s || err != nil {
		t.Fatal("unknown latest op not superseded")
	}
	ja := sampleJournal(op1)
	ja.Phase, ja.PrevRecord = winproto.PhasePrepared, op2
	jb := sampleJournal(op2)
	jb.Phase, jb.PrevRecord = winproto.PhasePrepared, op1
	mustWrite(t, h, ja)
	mustWrite(t, h, jb)
	_ = writeBindingRecord(h, canon443, op1)
	if s, _ := superseded(h, sampleJournal(op3)); !s {
		t.Fatal("a loop not superseded")
	}

	// a record that is not valid, or names another binding, is an error
	for _, data := range []string{"{", `{"binding":"http.sys/ipport/0.0.0.0:444","op":"` + op1 + `"}`, `{"binding":"` + canon443 + `","op":"x"}`} {
		h.state[name] = []byte(data)
		if _, err := readBindingRecord(h, canon443); !errors.Is(err, errBadJournal) {
			t.Errorf("%s: %v", data, err)
		}
		if _, err := superseded(h, j2); err == nil {
			t.Errorf("%s: superseded without error", data)
		}
	}
	if err := writeBindingRecord(h, canon443, "x"); !errors.Is(err, errBadJournal) {
		t.Fatal(err)
	}
	// op "" clears the record
	if err := writeBindingRecord(h, canon443, ""); err != nil {
		t.Fatal(err)
	}
	if op, err := readBindingRecord(h, canon443); op != "" || err != nil {
		t.Fatal(op, err)
	}
	h.readStateErr = errors.New("disk")
	if _, err := readBindingRecord(h, canon443); err == nil {
		t.Fatal("read error lost")
	}
	if err := handBack(h, j3); err == nil {
		t.Fatal("read error lost")
	}
}

func mustWrite(t *testing.T, h WriteHost, j journal) {
	t.Helper()
	if err := writeJournal(h, j); err != nil {
		t.Fatal(err)
	}
}

func TestRecordImport(t *testing.T) {
	h := newWriteHost()
	e := importEntry{Op: op1, Store: "My", SHA1: h1, SHA256: s256a}
	if err := recordImport(h, e); err != nil {
		t.Fatal(err)
	}
	if err := recordImport(h, e); err != nil { // twice is once
		t.Fatal(err)
	}
	f, err := readImports(h)
	if err != nil || len(f.Imports) != 1 || f.Imports[0] != e {
		t.Fatalf("%+v %v", f, err)
	}
	// bounded: the oldest entries go first
	for i := range maxImports - 1 {
		f.Imports = append(f.Imports, importEntry{Op: op2, Store: "WebHosting", SHA1: strings.Repeat("0", 32) + hexN(i), SHA256: s256b})
	}
	full, _ := json.Marshal(f)
	h.state[importsName] = full
	last := importEntry{Op: op3, Store: "My", SHA1: h3, SHA256: s256c}
	if err := recordImport(h, last); err != nil {
		t.Fatal(err)
	}
	f, _ = readImports(h)
	if len(f.Imports) != maxImports || f.Imports[0].SHA1 == h1 || f.Imports[maxImports-1] != last {
		t.Fatalf("%d", len(f.Imports))
	}
	if err := recordImport(h, importEntry{Op: "x", Store: "My", SHA1: h1, SHA256: s256a}); !errors.Is(err, errBadJournal) {
		t.Fatal(err)
	}
	h.state[importsName] = []byte("{")
	if _, err := readImports(h); !errors.Is(err, errBadJournal) {
		t.Fatal(err)
	}
	h.state[importsName] = []byte(`{"imports":[{"op":"x","store":"My","sha1":"` + h1 + `","sha256":"` + s256a + `"}]}`)
	if _, err := readImports(h); !errors.Is(err, errBadJournal) {
		t.Fatal(err)
	}
	if err := recordImport(h, e); err == nil {
		t.Fatal("a bad inventory was overwritten")
	}
	h.readStateErr = errors.New("disk")
	if _, err := readImports(h); err == nil || errors.Is(err, errBadJournal) {
		t.Fatal(err)
	}
}

func hexN(i int) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 8)
	for k := 7; k >= 0; k-- {
		out[k] = digits[i&15]
		i >>= 4
	}
	return string(out)
}

func TestRecoveryPendingNamesTheOperation(t *testing.T) {
	var out strings.Builder
	code := reply(&out, nil, recoveryPending(op2))
	var e winproto.ErrorResponse
	if err := json.Unmarshal([]byte(out.String()), &e); err != nil || code != 3 || e.Code != winproto.CodeRecoveryPending || e.PendingOp != op2 {
		t.Fatalf("%d %s %v", code, out.String(), err)
	}
	out.Reset()
	_ = reply(&out, nil, refused(winproto.CodeUsage, "x"))
	if strings.Contains(out.String(), "pending_op") {
		t.Fatal(out.String())
	}
}

func boolPtr(b bool) *bool { return &b }

// listsGone is a host whose journal listing names a file that is gone by the time it is read.
type listsGone struct{ *fakeWriteHost }

func (l listsGone) ListState(dir string) ([]StateFile, error) {
	files, err := l.fakeWriteHost.ListState(dir)
	return append(files, StateFile{Name: op3 + ".json"}), err
}

// TestReadJournals: every file of journal/, the good ones decoded, the others named (W3 Ruling 7).
func TestReadJournals(t *testing.T) {
	h := newWriteHost()
	mustWrite(t, h, sampleJournal(op2))
	mustWrite(t, h, journal{Op: op1, Phase: winproto.PhaseFenced})
	h.state[journalDir+"README"] = []byte("x")
	h.state[journalDir+"not-an-op.json"] = []byte("{}")
	h.state[journalName(op3)] = []byte("{")
	h.state[bindingRecordName(canon443)] = []byte("{}") // another directory
	h.modTimes = map[string]time.Time{journalName(op2): testNow}
	files, err := readJournals(h)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range files {
		got = append(got, fmt.Sprintf("%s %v %s", f.File.Name, f.OK, f.J.Op))
	}
	want := []string{op1 + ".json true " + op1, op2 + ".json true " + op2, op3 + ".json false ", "README false ", "not-an-op.json false "}
	if !reflect.DeepEqual(got, want) || !files[1].File.ModTime.Equal(testNow) {
		t.Fatalf("%q", got)
	}
	// A file listed and then removed is left out.
	delete(h.state, journalName(op3))
	if files, err := readJournals(listsGone{h}); err != nil || len(files) != 4 {
		t.Fatalf("%v %+v", err, files)
	}
	h.readStateErr = errors.New("disk")
	if _, err := readJournals(h); err == nil || errors.Is(err, errBadJournal) {
		t.Fatal(err)
	}
	h.listStateErr = errors.New("disk")
	if _, err := readJournals(h); err == nil {
		t.Fatal("listed")
	}
}

// TestJournalExistedRecord: a 0.3.0 journal keeps whether the store held the certificate (Ruling 5); a
// W2 journal has no such record and still reads.
func TestJournalExistedRecord(t *testing.T) {
	h := newWriteHost()
	for _, existed := range []bool{true, false} {
		j := sampleJournal(op1)
		j.Existed, j.AliceImported = boolPtr(existed), !existed
		mustWrite(t, h, j)
		if !strings.Contains(string(h.state[journalName(op1)]), fmt.Sprintf(`"existed":%v`, existed)) {
			t.Fatal(string(h.state[journalName(op1)]))
		}
		got, found, err := readJournal(h, op1)
		if err != nil || !found || got.Existed == nil || *got.Existed != existed || !reflect.DeepEqual(got, j) {
			t.Fatalf("%v %v %+v", err, found, got)
		}
	}
	// A W2 journal (no "existed" member) decodes with Existed nil.
	w2 := sampleJournal(op2)
	raw, _ := json.Marshal(w2)
	if strings.Contains(string(raw), "existed") {
		t.Fatal(string(raw))
	}
	h.state[journalName(op2)] = raw
	got, found, err := readJournal(h, op2)
	if err != nil || !found || got.Existed != nil {
		t.Fatalf("%v %v %+v", err, found, got.Existed)
	}
	// "existed" true and alice_imported true contradict each other: refused.
	bad := sampleJournal(op3)
	bad.Existed = boolPtr(true)
	if err := writeJournal(h, bad); !errors.Is(err, errBadJournal) {
		t.Fatal(err)
	}
}

// TestImportEntryUnboundSince: the import inventory's age stamp (Ruling 8).
func TestImportEntryUnboundSince(t *testing.T) {
	h := newWriteHost()
	e := importEntry{Op: op1, Store: "My", SHA1: h1, SHA256: s256a, UnboundSince: "2026-10-20T08:00:00Z"}
	if err := writeImports(h, importsFile{Imports: []importEntry{e}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(h.state[importsName]), `"unbound_since":"2026-10-20T08:00:00Z"`) {
		t.Fatal(string(h.state[importsName]))
	}
	f, err := readImports(h)
	if err != nil || len(f.Imports) != 1 || f.Imports[0] != e {
		t.Fatalf("%v %+v", err, f)
	}
	// Recording the same certificate again keeps the entry and its stamp.
	if err := recordImport(h, importEntry{Op: op1, Store: "My", SHA1: h1, SHA256: s256a}); err != nil {
		t.Fatal(err)
	}
	if f, err := readImports(h); err != nil || len(f.Imports) != 1 || f.Imports[0] != e {
		t.Fatalf("%v %+v", err, f)
	}
	for _, stamp := range []string{"yesterday", "2026-10-20T08:00:00+02:00", "2026-10-20", "2026-13-01T00:00:00Z", "2026-10-20T08:00:00.5Z"} {
		h.state[importsName] = []byte(`{"imports":[{"op":"` + op1 + `","store":"My","sha1":"` + h1 + `","sha256":"` + s256a +
			`","unbound_since":"` + stamp + `"}]}`)
		if _, err := readImports(h); !errors.Is(err, errBadJournal) {
			t.Fatalf("%s: %v", stamp, err)
		}
		bad := importEntry{Op: op1, Store: "My", SHA1: h1, SHA256: s256a, UnboundSince: stamp}
		if err := writeImports(h, importsFile{Imports: []importEntry{bad}}); !errors.Is(err, errBadJournal) {
			t.Fatal(err)
		}
	}
	if err := writeImports(h, importsFile{Imports: make([]importEntry, maxImports+1)}); !errors.Is(err, errBadJournal) {
		t.Fatal(err)
	}
	// No list at all reads and writes as an empty one.
	if err := writeImports(h, importsFile{}); err != nil || string(h.state[importsName]) != `{"imports":[]}` {
		t.Fatal(err, string(h.state[importsName]))
	}
	h.state[importsName] = []byte(`{"imports":null}`)
	if f, err := readImports(h); err != nil || f.Imports == nil || len(f.Imports) != 0 {
		t.Fatalf("%v %+v", err, f)
	}
	// A W2 imports.json (no unbound_since) reads.
	h.state[importsName] = []byte(`{"imports":[{"op":"` + op1 + `","store":"My","sha1":"` + h1 + `","sha256":"` + s256a + `"}]}`)
	if f, err := readImports(h); err != nil || len(f.Imports) != 1 || f.Imports[0].UnboundSince != "" {
		t.Fatalf("%v %+v", err, f)
	}
}
