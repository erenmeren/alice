package winhelper

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // a certificate store's thumbprint is SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/providers/windows/winproto"
)

// fakeHost is a Host with settable readings and error injection; calls counts every reading.
type fakeHost struct {
	elevated    bool
	elevatedErr error
	os          OSFacts
	osErr       error
	iis         winproto.IISFacts
	iisErr      error
	stores      []string
	storesErr   error
	bindings    []winproto.SSLBinding
	block       bool // OSFacts blocks until ctx ends and then returns ctx.Err()
	dialErr     error
	calls       atomic.Int32

	// iis-dump readings
	certs        map[[2]string]winproto.StoreCertificate // by (store, sha1); absent means not found
	certErr      error
	certErrs     map[[2]string]error // per certificate, before certErr
	certReads    map[[2]string]int
	expired      map[string]int
	appcmd       []byte
	appcmdErr    error
	appcmdCalls  atomic.Int32
	bindingsErr  error
	bindingBlock bool // SSLBindings blocks until ctx ends
	mu           sync.Mutex
}

func (f *fakeHost) Elevated() (bool, error) { f.calls.Add(1); return f.elevated, f.elevatedErr }

func (f *fakeHost) OSFacts(ctx context.Context) (OSFacts, error) {
	f.calls.Add(1)
	if f.block {
		<-ctx.Done()
		return OSFacts{}, ctx.Err()
	}
	return f.os, f.osErr
}

func (f *fakeHost) IISFacts(context.Context) (winproto.IISFacts, error) {
	f.calls.Add(1)
	return f.iis, f.iisErr
}

func (f *fakeHost) Stores(context.Context) ([]string, error) {
	f.calls.Add(1)
	return f.stores, f.storesErr
}

func (f *fakeHost) SSLBindings(ctx context.Context) ([]winproto.SSLBinding, error) {
	f.calls.Add(1)
	if f.bindingBlock {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.bindings, f.bindingsErr
}

func (f *fakeHost) Certificate(_ context.Context, store, sha1 string) (winproto.StoreCertificate, bool, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.certReads == nil {
		f.certReads = map[[2]string]int{}
	}
	k := [2]string{store, sha1}
	f.certReads[k]++
	if err := f.certErrs[k]; err != nil {
		return winproto.StoreCertificate{}, false, err
	}
	if f.certErr != nil {
		return winproto.StoreCertificate{}, false, f.certErr
	}
	c, ok := f.certs[k]
	return c, ok, nil
}

func (f *fakeHost) ExpiredInStore(_ context.Context, store string) (int, error) {
	f.calls.Add(1)
	return f.expired[store], nil
}

func (f *fakeHost) AppcmdSites(context.Context) ([]byte, error) {
	f.calls.Add(1)
	f.appcmdCalls.Add(1)
	return f.appcmd, f.appcmdErr
}

func (f *fakeHost) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.calls.Add(1)
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// stateWrite is one WriteState call as the fake saw it.
type stateWrite struct {
	name string
	data []byte
}

// fakeEvent is one Event call.
type fakeEvent struct {
	id   uint32
	text string
}

// fakeWriteHost is a WriteHost over fakeHost's readings. It models http.sys's record table with the
// whole-record replace of W0 F2 (UpdateBinding stores exactly the record it is given; afterUpdate models
// what http.sys keeps of it), the certificate stores (fakeHost.certs, ImportPFX decodes the PFX and adds
// the leaf with a key), LocalMachine\CA, the state files and the lock. Every write to the machine is in
// log, in order ("state <name>", "update <canonical>", "intermediate <sha1>", "import <store> <sha1>",
// "event <id>"); every WriteState is in stateLog; every Point name in points. Faults are injected with
// the *Err fields and hooks. Readings (ReadState, Binding, Certificate, LockHeld) are not in log.
type fakeWriteHost struct {
	*fakeHost

	wmu      sync.Mutex
	state    map[string][]byte              // the state files by name
	stateLog []stateWrite                   // every WriteState, in order
	log      []string                       // every write to the machine, in order
	records  map[string]winproto.SSLBinding // http.sys's table by canonical text
	updates  []winproto.SSLBinding          // every UpdateBinding argument, in order
	ca       map[string][]byte              // LocalMachine\CA by SHA-1
	events   []fakeEvent
	points   []string

	// What ImportPFX was given (the slices themselves, so a test can check the caller cleared them).
	pfxs, passwords [][]byte
	friendlyNames   []string

	lockHeld     bool  // another process holds helper.lock: Lock answers ErrBusy, LockHeld true
	lockErr      error // Lock fails with it
	locks        int   // Lock calls that took the lock
	releases     int   // release calls (idempotent: counted once per Lock)
	held         bool  // this process holds the lock now
	dataDirErr   error
	readStateErr error
	// writeStateErr, when set, decides each WriteState (nil writes).
	writeStateErr func(name string) error
	// phaseErr fails the WriteState of a journal in one of these phases.
	phaseErr []string
	// passwordCopies are the PFX passwords ImportPFX saw, copied as text when it was called.
	passwordCopies []string
	bindingErr     error
	updateErr      func(b winproto.SSLBinding) error
	// afterUpdate, when set, is what http.sys keeps of an update (read-back faults).
	afterUpdate func(b winproto.SSLBinding) winproto.SSLBinding
	// updateBlock, when set, makes UpdateBinding wait until it is closed (the context does not end the
	// wait: a host call that ignores its context).
	updateBlock chan struct{}
	// updateFailAfter, when set, decides each UpdateBinding after the record was replaced (a partial
	// write that then fails: the real host's base update succeeded and an Ex update did not).
	updateFailAfter func(b winproto.SSLBinding) error
	// bindingErrFn, when set, decides each Binding read before bindingErr (read-back faults).
	bindingErrFn       func() error
	importErr          error
	addIntermediateErr error
	// pointErr, when set, decides each Point (a non-nil answer is a kill there).
	pointErr func(name string) error

	// W3: the helper's clock (testNow when zero), the state files' times by name, the listeners'
	// thumbprints and the faults of the cleanup methods.
	now            time.Time
	modTimes       map[string]time.Time
	listStateErr   error
	removeStateErr func(name string) error
	removeCertErr  error
	// removeAfterKeyErr, when set, makes RemoveCertificate remove the key and then fail with it before
	// the certificate (a kill between the two, W3 Ruling 10): the certificate stays, keyless.
	removeAfterKeyErr error
	// readStateFn, listStateFn decide each ReadState and ListState (nil reads); bindingBlockFn runs
	// before each SSLBindings (a slow http.sys).
	readStateFn    func(name string) error
	listStateFn    func(dir string) error
	bindingBlockFn func()
	protected      Protected
	protectedErr   error
}

func newWriteHost() *fakeWriteHost {
	return &fakeWriteHost{fakeHost: &fakeHost{elevated: true, certs: map[[2]string]winproto.StoreCertificate{}},
		state: map[string][]byte{}, records: map[string]winproto.SSLBinding{}, ca: map[string][]byte{}}
}

// recordKey is the canonical text of a record (its raw fields when it has none, e.g. ccs).
func recordKey(b winproto.SSLBinding) string {
	app, _ := winproto.CanonicalAppID(b.AppID)
	if c, ok := (winproto.Locator{Type: b.Type, IP: b.IP, Host: b.Host, Port: b.Port, AppID: app}).Canonical(); ok {
		return c
	}
	return b.Type + "/" + b.IP + "/" + b.Host + "/" + strconv.Itoa(b.Port)
}

func cloneBinding(b winproto.SSLBinding) winproto.SSLBinding {
	b.Extended = slices.Clone(b.Extended)
	return b
}

// setRecord puts a record into http.sys's table (test set-up, not logged).
func (f *fakeWriteHost) setRecord(b winproto.SSLBinding) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	f.records[recordKey(b)] = cloneBinding(b)
}

// record reads a record of the table.
func (f *fakeWriteHost) record(canonical string) (winproto.SSLBinding, bool) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	b, ok := f.records[canonical]
	return cloneBinding(b), ok
}

// addCert puts a certificate into a store (test set-up, not logged).
func (f *fakeWriteHost) addCert(store string, der []byte, hasKey bool) (sha1Hex string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s1 := sha1.Sum(der) //nolint:gosec // a thumbprint
	s2 := sha256.Sum256(der)
	sha1Hex = hex.EncodeToString(s1[:])
	c := winproto.StoreCertificate{Store: store, SHA1: sha1Hex, SHA256: hex.EncodeToString(s2[:]),
		DER: base64.StdEncoding.EncodeToString(der), Chain: []string{}, NotAfter: "2030-01-01T00:00:00Z", HasKey: hasKey}
	if !hasKey {
		c.KeyProblem = "key_missing"
	}
	f.certs[[2]string{store, sha1Hex}] = c
	return sha1Hex
}

// writes is the write log so far.
func (f *fakeWriteHost) writes() []string {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	return slices.Clone(f.log)
}

func (f *fakeWriteHost) logf(s string) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	f.log = append(f.log, s)
}

func (f *fakeWriteHost) SSLBindings(context.Context) ([]winproto.SSLBinding, error) {
	f.calls.Add(1)
	if f.bindingBlockFn != nil {
		f.bindingBlockFn()
	}
	if f.bindingsErr != nil {
		return nil, f.bindingsErr
	}
	f.wmu.Lock()
	defer f.wmu.Unlock()
	keys := make([]string, 0, len(f.records))
	for k := range f.records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]winproto.SSLBinding, 0, len(keys))
	for _, k := range keys {
		out = append(out, cloneBinding(f.records[k]))
	}
	return out, nil
}

func (f *fakeWriteHost) Lock(ctx context.Context) (func(), error) {
	f.calls.Add(1)
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.lockErr != nil {
		return nil, f.lockErr
	}
	if f.lockHeld || f.held {
		return nil, ErrBusy
	}
	if ctx.Err() != nil {
		return nil, ErrBusy
	}
	f.locks++
	f.held = true
	var once sync.Once
	return func() {
		once.Do(func() {
			f.wmu.Lock()
			defer f.wmu.Unlock()
			f.releases++
			f.held = false
		})
	}, nil
}

func (f *fakeWriteHost) LockHeld() bool {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	return f.lockHeld
}

func (f *fakeWriteHost) ReadState(name string) ([]byte, bool, error) {
	f.calls.Add(1)
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.readStateErr != nil {
		return nil, false, f.readStateErr
	}
	if f.readStateFn != nil {
		if err := f.readStateFn(name); err != nil {
			return nil, false, err
		}
	}
	b, ok := f.state[name]
	return slices.Clone(b), ok, nil
}

func (f *fakeWriteHost) WriteState(name string, data []byte) error {
	f.calls.Add(1)
	if f.writeStateErr != nil {
		if err := f.writeStateErr(name); err != nil {
			return err
		}
	}
	if len(f.phaseErr) > 0 && strings.HasPrefix(name, journalDir) {
		var j journal
		if json.Unmarshal(data, &j) == nil && slices.Contains(f.phaseErr, j.Phase) {
			return errors.New("disk")
		}
	}
	f.wmu.Lock()
	defer f.wmu.Unlock()
	f.state[name] = slices.Clone(data)
	f.stateLog = append(f.stateLog, stateWrite{name: name, data: slices.Clone(data)})
	f.log = append(f.log, "state "+name)
	return nil
}

func (f *fakeWriteHost) DataDirSafe() error {
	f.calls.Add(1)
	return f.dataDirErr
}

func (f *fakeWriteHost) Binding(_ context.Context, l winproto.Locator) (winproto.SSLBinding, bool, error) {
	f.calls.Add(1)
	if f.bindingErrFn != nil {
		if err := f.bindingErrFn(); err != nil {
			return winproto.SSLBinding{}, false, err
		}
	}
	if f.bindingErr != nil {
		return winproto.SSLBinding{}, false, f.bindingErr
	}
	c, ok := l.Canonical()
	if !ok {
		return winproto.SSLBinding{}, false, nil
	}
	b, found := f.record(c)
	return b, found, nil
}

func (f *fakeWriteHost) UpdateBinding(_ context.Context, b winproto.SSLBinding) error {
	f.calls.Add(1)
	if f.updateBlock != nil {
		<-f.updateBlock
	}
	if f.updateErr != nil {
		if err := f.updateErr(b); err != nil {
			return err
		}
	}
	key := recordKey(b)
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if _, ok := f.records[key]; !ok {
		return ErrBindingNotFound
	}
	f.updates = append(f.updates, cloneBinding(b))
	kept := cloneBinding(b)
	if f.afterUpdate != nil {
		kept = f.afterUpdate(kept)
	}
	f.records[key] = kept // the whole record is replaced (W0 F2)
	f.log = append(f.log, "update "+key)
	if f.updateFailAfter != nil {
		return f.updateFailAfter(b)
	}
	return nil
}

func (f *fakeWriteHost) AddIntermediate(_ context.Context, der []byte) (bool, error) {
	f.calls.Add(1)
	if f.addIntermediateErr != nil {
		return false, f.addIntermediateErr
	}
	s := sha1.Sum(der) //nolint:gosec // a thumbprint
	k := hex.EncodeToString(s[:])
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if _, ok := f.ca[k]; ok {
		return false, nil // CERT_STORE_ADD_NEW: never replaced
	}
	f.ca[k] = slices.Clone(der)
	f.log = append(f.log, "intermediate "+k)
	return true, nil
}

func (f *fakeWriteHost) ImportPFX(_ context.Context, store string, pfx, password []byte, friendlyName string) (string, bool, error) {
	f.calls.Add(1)
	f.wmu.Lock()
	f.pfxs = append(f.pfxs, pfx)
	f.passwords = append(f.passwords, password)
	f.passwordCopies = append(f.passwordCopies, string(password))
	f.friendlyNames = append(f.friendlyNames, friendlyName)
	f.wmu.Unlock()
	if f.importErr != nil {
		return "", false, f.importErr
	}
	_, leaf, _, err := pkcs12.DecodeChain(pfx, string(password))
	if err != nil {
		return "", false, ErrStore
	}
	f.mu.Lock()
	_, existed := f.certs[[2]string{store, sum1(leaf.Raw)}]
	f.mu.Unlock()
	if existed {
		// CERT_STORE_ADD_NEW: the copy there is left as it is.
		return sum1(leaf.Raw), true, nil
	}
	sha := f.addCert(store, leaf.Raw, true)
	chain := f.builtChain(leaf)
	f.mu.Lock()
	c := f.certs[[2]string{store, sha}]
	c.FriendlyName, c.Chain = friendlyName, chain
	f.certs[[2]string{store, sha}] = c
	f.mu.Unlock()
	f.logf("import " + store + " " + sha)
	return sha, false, nil
}

func (f *fakeWriteHost) Now() time.Time {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.now.IsZero() {
		return testNow
	}
	return f.now
}

// ListState lists the state files under dir; every file's time is modTimes[name] (the zero time when
// unset).
func (f *fakeWriteHost) ListState(dir string) ([]StateFile, error) {
	f.calls.Add(1)
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.listStateErr != nil {
		return nil, f.listStateErr
	}
	if f.listStateFn != nil {
		if err := f.listStateFn(dir); err != nil {
			return nil, err
		}
	}
	out := []StateFile{}
	for name := range f.state {
		if rest, ok := strings.CutPrefix(name, dir); ok && !strings.Contains(rest, "/") {
			out = append(out, StateFile{Name: rest, ModTime: f.modTimes[name]})
		}
	}
	return out, nil
}

func (f *fakeWriteHost) RemoveState(name string) error {
	f.calls.Add(1)
	if f.removeStateErr != nil {
		if err := f.removeStateErr(name); err != nil {
			return err
		}
	}
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if _, ok := f.state[name]; ok {
		delete(f.state, name)
		f.log = append(f.log, "unlink "+name)
	}
	return nil
}

// RemoveCertificate removes a certificate and its key (key first, as the log shows).
func (f *fakeWriteHost) RemoveCertificate(_ context.Context, store, sha1 string) (bool, error) {
	f.calls.Add(1)
	if f.removeCertErr != nil {
		return false, f.removeCertErr
	}
	f.mu.Lock()
	k := [2]string{store, sha1}
	c, ok := f.certs[k]
	if ok && f.removeAfterKeyErr != nil {
		c.HasKey, c.KeyProblem = false, "key_missing"
		f.certs[k] = c
		f.mu.Unlock()
		f.logf("remove-key " + store + " " + sha1)
		return false, f.removeAfterKeyErr
	}
	if ok {
		delete(f.certs, k)
	}
	f.mu.Unlock()
	if !ok {
		return false, nil
	}
	if c.HasKey {
		f.logf("remove-key " + store + " " + sha1)
	}
	f.logf("remove " + store + " " + sha1)
	return true, nil
}

func (f *fakeWriteHost) ProtectedThumbprints(context.Context) (Protected, error) {
	f.calls.Add(1)
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.protectedErr != nil {
		return Protected{}, f.protectedErr
	}
	return Protected{RDP: slices.Clone(f.protected.RDP), WinRM: slices.Clone(f.protected.WinRM)}, nil
}

// builtChain is CertGetCertificateChain's answer for leaf over LocalMachine\CA as it is now: the
// issuers found there, base64, root (self-signed) excluded.
func (f *fakeWriteHost) builtChain(leaf *x509.Certificate) []string {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	chain := []string{}
	cur := leaf
	for range winproto.MaxChainCerts {
		var next *x509.Certificate
		for _, der := range f.ca {
			c, err := x509.ParseCertificate(der)
			if err == nil && bytes.Equal(c.RawSubject, cur.RawIssuer) && !bytes.Equal(c.RawSubject, c.RawIssuer) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		chain = append(chain, base64.StdEncoding.EncodeToString(next.Raw))
		cur = next
	}
	return chain
}

func (f *fakeWriteHost) Event(id uint32, text string) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	f.events = append(f.events, fakeEvent{id: id, text: text})
	f.log = append(f.log, "event "+strconv.FormatUint(uint64(id), 10))
}

func (f *fakeWriteHost) Point(name string) error {
	f.wmu.Lock()
	f.points = append(f.points, name)
	hook := f.pointErr
	f.wmu.Unlock()
	if hook != nil {
		return hook(name)
	}
	return nil
}

var _ WriteHost = (*fakeWriteHost)(nil)
