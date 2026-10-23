package wintest

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

// The write half of the model (W2, R61): the helper's data directory and lock, http.sys's
// whole-record update, schannel's chain cache, the stores' imports, the Application log and the crash
// points between the journal phases, with the faults the provider's and the engine's tests need.

// KilledExit is the exit status the SSH client sees for a helper killed at a crash point (KillAt): it
// printed nothing.
const KilledExit = 255

// Event is one Application log entry the helper wrote (source "Alice Helper").
type Event struct {
	ID   uint32
	Text string
}

var errModelKilled = errors.New("wintest: the helper was killed at this point")

// errNoHash is UpdateBinding's answer to a record whose hash is no hash (the real helper's errBadValue).
var errNoHash = errors.New("wintest: the record names no certificate hash")

// maxHashBytes is the longest hash the real helper sends to http.sys (cmd/alice-winhelper's
// maxHashBytes, the HTTP_SERVICE_CONFIG_SSL_PARAM hash it encodes).
const maxHashBytes = 64

// keyOf is http.sys's key of a record: (IP, port) for ipport (the address unmapped), (host, port)
// without case for hostnameport, the port for ccs.
func keyOf(b winproto.SSLBinding) string {
	return recordKey(b.Type, b.IP, b.Host, b.Port)
}

func recordKey(typ, ip, hostName string, port int) string {
	p := strconv.Itoa(port)
	switch typ {
	case winproto.BindingIPPort:
		if a, err := netip.ParseAddr(ip); err == nil {
			ip = a.Unmap().String()
		}
		return typ + "/" + ip + "/" + p
	case winproto.BindingHostnamePort:
		return typ + "/" + fold(hostName) + "/" + p
	}
	return typ + "/" + p
}

func cloneRecord(b winproto.SSLBinding) winproto.SSLBinding {
	b.Extended = slices.Clone(b.Extended)
	return b
}

func (m *Model) indexLocked(key string) int {
	return slices.IndexFunc(m.bindings, func(b winproto.SSLBinding) bool { return keyOf(b) == key })
}

// KillAt makes the helper die at the named crash point of the next call that reaches it (once): it
// answers nothing (KilledExit) and leaves the model as it had written it. The points are winhelper's
// ("deploy.prepared", "restore.bound", ...).
func (m *Model) KillAt(point string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.killAt = point
}

// maxPoints bounds what Points remembers (the latest ones are kept).
const maxPoints = 1024

// Points lists the crash points the helper passed so far (the latest maxPoints), in order.
func (m *Model) Points() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.points)
}

// Reboot is a restart of the machine: the helper lock is released (also any HoldLock) and schannel's
// cache and the listeners' stale certificates are gone, so every record is served as built anew from
// the records at its next handshake. Records, stores, the data directory and the log are kept.
func (m *Model) Reboot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockOwned, m.lockOutside = false, 0
	m.lockGen++
	m.served = map[string]*servedEntry{}
	m.corruptNext = false
}

// HoldLock is another helper process holding helper.lock until release (idempotent): a status shows
// Active, a deploy waits the lock wait and answers BUSY.
func (m *Model) HoldLock() (release func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockOutside++
	gen := m.lockGen
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.lockGen == gen {
				m.lockOutside--
			}
		})
	}
}

// SetLockWait sets how long the helper waits for the lock before BUSY (winproto.LockWait; tests
// lower it).
func (m *Model) SetLockWait(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockWait = d
}

// FailUpdate makes the next UpdateBinding fail with err (winhelper.ErrKeyUnusable, ErrStore, ...),
// changing nothing.
func (m *Model) FailUpdate(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failUpdate = err
}

// CorruptReadBack(true) makes the first read after the next update lose the record's last Ex parameter
// (a record without one reads back with a flag changed); the record itself is as written.
func (m *Model) CorruptReadBack(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.corruptArmed = on
}

// FailImport makes every ImportPFX fail (ErrStore) while on.
func (m *Model) FailImport(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failImport = on
}

// StaleTLS(true) is a website that does not take a change (Ruling 23): from the next write of a
// record on, its listener keeps serving what it served before. StaleTLS(false) lets the listeners
// serve the records again.
func (m *Model) StaleTLS(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stale = on
	if !on {
		for _, s := range m.served {
			s.pinned = nil
		}
	}
}

// ChainDiffers puts a cross-signed certificate (PEM or DER; nil takes it out) at the end of every chain
// Windows builds from then on, so the built and served chain is one longer than the one Alice sent
// (win.chain_differs). Records written before keep their cached chain until their next write or a
// reboot. It panics on bytes that are no certificate (a test helper).
func (m *Model) ChainDiffers(extraIntermediate []byte) {
	var c *x509.Certificate
	if extraIntermediate != nil {
		der := extraIntermediate
		if block, _ := pem.Decode(extraIntermediate); block != nil {
			der = block.Bytes
		}
		var err error
		if c, err = x509.ParseCertificate(der); err != nil {
			panic("wintest: " + err.Error())
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chainExtra = c
}

// SetDataDirUnsafe makes the data directory one the helper cannot trust (DataDirSafe: ErrJournal).
func (m *Model) SetDataDirUnsafe(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dataDirBad = on
}

// Binding reads the record a locator names, as http.sys holds it (base and Extended).
func (m *Model) Binding(l winproto.Locator) (winproto.SSLBinding, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.indexLocked(recordKey(l.Type, l.IP, l.Host, l.Port))
	if i < 0 {
		return winproto.SSLBinding{}, false
	}
	return cloneRecord(m.bindings[i]), true
}

// Journal is the journal file of an operation on the modelled disk.
func (m *Model) Journal(op string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.state["journal/"+op+".json"]
	return slices.Clone(b), ok
}

// Events lists the Application log entries so far.
func (m *Model) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.events)
}

// Imported lists the SHA-1s of the certificates ImportPFX added, in order.
func (m *Model) Imported() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.imported)
}

// Lock takes helper.lock, waiting at most the lock wait (ErrBusy after, or when ctx ends).
func (h host) Lock(ctx context.Context) (func(), error) {
	h.m.mu.Lock()
	expired := time.NewTimer(h.m.lockWait)
	h.m.mu.Unlock()
	defer expired.Stop()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for {
		h.m.mu.Lock()
		if !h.m.lockOwned && h.m.lockOutside == 0 {
			h.m.lockOwned = true
			gen := h.m.lockGen
			h.m.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					h.m.mu.Lock()
					defer h.m.mu.Unlock()
					if h.m.lockGen == gen {
						h.m.lockOwned = false
					}
				})
			}, nil
		}
		h.m.mu.Unlock()
		if ctx.Err() != nil {
			return nil, winhelper.ErrBusy
		}
		select {
		case <-ctx.Done():
			return nil, winhelper.ErrBusy
		case <-expired.C:
			return nil, winhelper.ErrBusy
		case <-poll.C:
		}
	}
}

// LockHeld reports whether a helper process holds the lock now.
func (h host) LockHeld() bool {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	return h.m.lockOwned || h.m.lockOutside > 0
}

// ReadState reads a state file, at most MaxStateBytes+1 bytes of it (the caller refuses more).
func (h host) ReadState(name string) ([]byte, bool, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	b, ok := h.m.state[name]
	if !ok {
		return nil, false, nil
	}
	return slices.Clone(b[:min(len(b), winhelper.MaxStateBytes+1)]), true, nil
}

// WriteState replaces a state file at once (the real helper's temporary file and write-through
// rename: a kill never leaves half a file).
func (h host) WriteState(name string, data []byte) error {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	h.m.state[name] = slices.Clone(data)
	return nil
}

func (h host) DataDirSafe() error {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if h.m.dataDirBad {
		return winhelper.ErrJournal
	}
	return nil
}

// Binding is the live read of a record, base and Extended (CorruptReadBack's first read after an
// update loses an Ex parameter).
func (h host) Binding(_ context.Context, l winproto.Locator) (winproto.SSLBinding, bool, error) {
	b, ok := h.m.Binding(l)
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if ok && h.m.corruptNext {
		h.m.corruptNext = false
		if n := len(b.Extended); n > 0 {
			b.Extended = b.Extended[:n-1]
		} else {
			b.Flags ^= 1
		}
	}
	return b, ok, nil
}

// UpdateBinding is the real helper's UpdateBinding (HttpUpdateServiceConfiguration of the base record,
// then the Ex writes): the record of the same key is replaced by exactly what it is given, only when the
// certificate it names is in its store with a usable key (else 1312: ErrKeyUnusable, nothing changed).
// A hash that is no hash (empty, not hex) never reaches http.sys: a plain error, as the real helper's
// encodeBase gives. schannel's chain for the record is built at this write and served until the next
// one (W0 F5); a stale listener keeps what it served.
//
// The base fields reset as on Windows (W0 F2: a field left out is reset). The extended parameters are
// stricter than Windows on purpose: real http.sys keeps them across a base update (F9, confirmed on
// 2022 and 2025), while the model resets those the record it is given leaves out, so a helper that
// forgot to send them back fails here (Review Focus 2). Not modelled: a CTL name the machine does not
// hold, which http.sys refuses with 1312 (W0 F2); the model takes any CTLIdentifier.
func (h host) UpdateBinding(_ context.Context, b winproto.SSLBinding) error {
	m := h.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failUpdate; err != nil {
		m.failUpdate = nil
		return err
	}
	if raw, err := hex.DecodeString(b.CertSHA1); err != nil || len(raw) == 0 || len(raw) > maxHashBytes {
		return errNoHash
	}
	k := keyOf(b)
	i := m.indexLocked(k)
	if i < 0 {
		return winhelper.ErrBindingNotFound
	}
	e, err := m.usableLocked(&b)
	if err != nil {
		return winhelper.ErrKeyUnusable
	}
	var pin *tls.Certificate
	if m.stale {
		if old, err := m.presentedLocked(&m.bindings[i]); err == nil {
			pin = old
		}
	}
	m.bindings[i] = cloneRecord(b)
	m.served[k] = &servedEntry{chain: m.chainLocked(e.leaf), pinned: pin}
	if m.corruptArmed {
		m.corruptArmed, m.corruptNext = false, true
	}
	return nil
}

// AddIntermediate adds a public certificate to LocalMachine\CA, never replacing one there.
func (h host) AddIntermediate(_ context.Context, der []byte) (bool, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return false, winhelper.ErrStore
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if slices.ContainsFunc(h.m.inter, func(x *x509.Certificate) bool { return x.Equal(c) }) {
		return false, nil
	}
	h.m.inter = append(h.m.inter, c)
	return true, nil
}

// ImportPFX imports what winhelper.BuildPFX writes (one leaf with its RSA or ECDSA key, no other
// certificate; decoded with go-pkcs12) into a machine store: the key non-exportable, in the software
// KSP, usable by SYSTEM. A certificate the store holds already is left as it is and answered existed
// (CERT_STORE_ADD_NEW). Anything else is ErrStore.
func (h host) ImportPFX(_ context.Context, storeName string, pfx, password []byte, friendlyName string) (string, bool, error) {
	h.m.mu.Lock()
	fail := h.m.failImport
	h.m.mu.Unlock()
	if fail {
		return "", false, winhelper.ErrStore
	}
	key, leaf, cas, err := pkcs12.DecodeChain(pfx, string(password))
	if err != nil || len(cas) != 0 {
		return "", false, winhelper.ErrStore
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if !k.PublicKey.Equal(leaf.PublicKey) {
			return "", false, winhelper.ErrStore
		}
	case *ecdsa.PrivateKey:
		if !k.PublicKey.Equal(leaf.PublicKey) {
			return "", false, winhelper.ErrStore
		}
	default:
		return "", false, winhelper.ErrStore
	}
	sha := thumbprint(leaf.Raw)
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if h.m.certLocked(storeName, sha) != nil {
		return sha, true, nil
	}
	usable := true
	s := h.m.storeLocked(storeName)
	s.certs = append(s.certs, &certEntry{leaf: leaf, sha1: sha, key: key, friendly: friendlyName, provider: defaultKeyProvider, usable: &usable})
	h.m.imported = append(h.m.imported, sha)
	return sha, false, nil
}

// errNotModelled is the answer of the W3 cleanup methods until the emulator models them (W3 Task 4).
var errNotModelled = errors.New("wintest: not modelled yet")

// Now is the helper's clock (W3 Task 4 gives the model its own).
func (h host) Now() time.Time {
	return time.Now() //nolint:forbidigo // the emulated helper's clock until W3 Task 4 gives the model one
}

// ListState is not modelled yet (W3 Task 4).
func (h host) ListState(string) ([]winhelper.StateFile, error) { return nil, errNotModelled }

// RemoveState is not modelled yet (W3 Task 4).
func (h host) RemoveState(string) error { return errNotModelled }

// RemoveCertificate is not modelled yet (W3 Task 4).
func (h host) RemoveCertificate(context.Context, string, string) (bool, error) {
	return false, errNotModelled
}

// ProtectedThumbprints is not modelled yet (W3 Task 4).
func (h host) ProtectedThumbprints(context.Context) (winhelper.Protected, error) {
	return winhelper.Protected{}, errNotModelled
}

// Event records an Application log entry.
func (h host) Event(id uint32, text string) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	h.m.events = append(h.m.events, Event{ID: id, Text: text})
}

// Point is a crash point: KillAt's point kills the call there, once.
func (h host) Point(name string) error {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if len(h.m.points) >= maxPoints { // the e2e fake runs for long
		h.m.points = slices.Delete(h.m.points, 0, len(h.m.points)-maxPoints+1)
	}
	h.m.points = append(h.m.points, name)
	if h.m.killAt != "" && h.m.killAt == name {
		h.m.killAt = ""
		return errModelKilled
	}
	return nil
}
