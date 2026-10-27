package wintest

import (
	"context"
	"crypto"
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
	"strings"
	"sync"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
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
// the records at its next handshake (a CCS file as it is now). Records, stores, the CCS folders, the
// data directory and the log are kept.
func (m *Model) Reboot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockOwned, m.lockOutside = false, 0
	m.lockGen++
	m.served = map[string]*servedEntry{}
	clear(m.ccsPinned)
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
	h.m.stateTimes[name] = h.m.nowLocked()
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
	h.m.keys[keyID(storeName, sha)] = true
	s := h.m.storeLocked(storeName)
	s.certs = append(s.certs, &certEntry{leaf: leaf, sha1: sha, key: key, friendly: friendlyName, provider: defaultKeyProvider, usable: &usable})
	h.m.imported = append(h.m.imported, sha)
	return sha, false, nil
}

// errCannotRead is a registry value that cannot be read (FailProtected).
var errCannotRead = errors.New("wintest: the registry cannot be read")

// errAfterKey is FailAfterKey's failure between the key and the certificate.
var errAfterKey = errors.New("wintest: the removal failed after the key was deleted")

// nowLocked is the helper's clock: SetNow's time (moved by Advance) or the system's.
func (m *Model) nowLocked() time.Time {
	if !m.clockFixed.IsZero() {
		return m.clockFixed
	}
	return time.Now().Add(m.clockSkew) //nolint:forbidigo // the emulated helper's clock is the system's until SetNow
}

// SetNow fixes the helper's clock at t (the default is the system clock); the zero time restores it.
func (m *Model) SetNow(t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clockFixed, m.clockSkew = t, 0
}

// Advance moves the helper's clock forward by d.
func (m *Model) Advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.clockFixed.IsZero() {
		m.clockSkew += d
		return
	}
	m.clockFixed = m.clockFixed.Add(d)
}

// SetRDPThumbprint sets the certificate the RDP listener names ("" none).
func (m *Model) SetRDPThumbprint(sha1 string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rdp = fold(sha1)
}

// SetWinRMThumbprints sets the certificates the WinRM HTTPS listeners name.
func (m *Model) SetWinRMThumbprints(sha1s ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.winrm = nil
	for _, s := range sha1s {
		m.winrm = append(m.winrm, fold(s))
	}
}

// FailProtected makes the listeners' thumbprints unreadable (ProtectedThumbprints fails) while on.
func (m *Model) FailProtected(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failProtect = on
}

// HasCertificate reports whether the store holds the certificate.
func (m *Model) HasCertificate(storeName, sha1 string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certLocked(storeName, sha1) != nil
}

// HasKey reports whether the certificate's key still exists in the machine key store.
func (m *Model) HasKey(storeName, sha1 string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[keyID(storeName, sha1)]
}

// KeyCount is the number of keys in the machine key store, those of no certificate (orphans) included.
func (m *Model) KeyCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keys)
}

// StateFiles lists the names under the data directory, sorted.
func (m *Model) StateFiles() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.state))
	for n := range m.state {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// SetStateTime sets the modification time of a state file (one that does not exist is ignored).
func (m *Model) SetStateTime(name string, t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.state[name]; ok {
		m.stateTimes[name] = t
	}
}

// FailAfterKey makes the next RemoveCertificate of the helper delete the key, then fail before the
// certificate (a kill between the two); the certificate stays, keyless.
func (m *Model) FailAfterKey(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failAfterKey = on
}

// Now is the helper's clock.
func (h host) Now() time.Time {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	return h.m.nowLocked()
}

// ListState lists the files directly under dir ("journal/", "bindings/"), by their names within it and
// their modification times, sorted by name. A directory without files lists nothing.
func (h host) ListState(dir string) ([]winhelper.StateFile, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	var out []winhelper.StateFile
	for n := range h.m.state {
		if rest, ok := strings.CutPrefix(n, dir); ok && rest != "" && !strings.Contains(rest, "/") {
			out = append(out, winhelper.StateFile{Name: rest, ModTime: h.m.stateTimes[n]})
		}
	}
	slices.SortFunc(out, func(a, b winhelper.StateFile) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// RemoveState removes a state file; one that is absent is nil.
func (h host) RemoveState(name string) error {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	delete(h.m.state, name)
	delete(h.m.stateTimes, name)
	return nil
}

// RemoveCertificate removes the key, then the certificate (the real helper's order, F11). FailAfterKey
// fails between the two, once: the certificate is left without its key.
func (h host) RemoveCertificate(_ context.Context, storeName, sha1 string) (bool, error) {
	m := h.m
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.certLocked(storeName, sha1)
	if e == nil {
		return false, nil
	}
	delete(m.keys, keyID(storeName, sha1))
	e.key = nil
	if m.failAfterKey {
		m.failAfterKey = false
		return false, errAfterKey
	}
	s := m.storeLocked(storeName)
	s.certs = slices.DeleteFunc(s.certs, func(c *certEntry) bool { return c == e })
	return true, nil
}

// ProtectedThumbprints are the certificates the RDP and WinRM listeners name (lower-case SHA-1).
func (h host) ProtectedThumbprints(context.Context) (winhelper.Protected, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if h.m.failProtect {
		return winhelper.Protected{}, errCannotRead
	}
	var p winhelper.Protected
	if h.m.rdp != "" {
		p.RDP = []string{h.m.rdp}
	}
	p.WinRM = slices.Clone(h.m.winrm)
	return p, nil
}

// Event records an Application log entry.
func (h host) Event(id uint32, text string) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	h.m.events = append(h.m.events, Event{ID: id, Text: text})
}

// The CCS half of the model (W5, R68): IIS's Centralized Certificate Store. The registry's Enabled and
// CertStoreLocation are the IIS facts' CCSEnabled and CCSPath; each folder holds its files by name,
// compared without case as NTFS does (W5 ruling: a file spelled WWW.Example.COM.PFX is found for host
// www.example.com, F17). A folder named before a path change keeps its files, so a journal's folder can
// still be restored and pruned (W5 Ruling 17); a folder that does not exist lists nothing. Not modelled:
// a folder that is a reparse point (ErrCCSFolderUnsupported) and a file that is one.

// ccsFile is one file of a modelled folder: its name as written, its bytes and its time.
type ccsFile struct {
	name string
	data []byte
	mod  time.Time
}

var (
	errNoCCSFolder = errors.New("wintest: the CCS folder does not exist")
	errCCSExists   = errors.New("wintest: the file exists")
	errCCSNoFile   = errors.New("wintest: the file does not exist")
	errCCSReplace  = errors.New("wintest: ReplaceFileW failed")
	errCCSRemove   = errors.New("wintest: not a temporary file or a backup")
)

// folderKey is a folder as Windows compares it: ASCII case folded, one trailing backslash trimmed.
func folderKey(folder string) string { return fold(strings.TrimSuffix(folder, `\`)) }

// pinKey names a file of a folder in ccsPinned.
func pinKey(folder, name string) string { return folderKey(folder) + `\` + fold(name) }

// SetCCS turns the Centralized Certificate Store on or off with its folder (what
// Enable-WebCentralCertProvider writes to the registry; win-facts and every CCS call read it). The
// folder exists from then on; a folder named before keeps its files.
func (m *Model) SetCCS(enabled bool, path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.iis.CCSEnabled, m.iis.CCSPath = enabled, path
	if path != "" {
		m.ccsDirLocked(path)
	}
}

func (m *Model) ccsDirLocked(folder string) map[string]*ccsFile {
	k := folderKey(folder)
	d, ok := m.ccsDirs[k]
	if !ok {
		d = map[string]*ccsFile{}
		m.ccsDirs[k] = d
	}
	return d
}

// SetCCSPassword sets IIS's private-key password of the store: TLS serves a file only when it opens it
// (F16 as modelled). Alice never reads it (W5 Ruling 12); the tests and ctl ccs-password do.
func (m *Model) SetCCSPassword(password string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ccsPassword = password
}

// CCSPassword is IIS's private-key password of the store (SetCCSPassword).
func (m *Model) CCSPassword() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ccsPassword
}

// PutCCSFile puts a file into the CCS folder as a third party made it: the leaf, its key and chain in
// winhelper.BuildPFX's format under password (one that is not the store's makes a file IIS cannot open).
// It replaces the file of that name, any case. It panics on a key or a password BuildPFX refuses, or
// without a CCS folder (a test helper).
func (m *Model) PutCCSFile(name string, leaf *x509.Certificate, chain []*x509.Certificate, key crypto.Signer, password string) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic("wintest: " + err.Error())
	}
	ders := make([][]byte, 0, len(chain))
	for _, c := range chain {
		ders = append(ders, c.Raw)
	}
	pfx, err := winhelper.BuildPFX(leaf.Raw, pkcs8, []byte(password), ders...)
	if err != nil {
		panic("wintest: " + err.Error())
	}
	m.PutRawCCSFile(name, pfx)
}

// PutRawCCSFile puts bytes into the CCS folder under name (any name: a .pfx that is no PFX, a file IIS
// ignores), replacing the file of that name, any case. It panics without a CCS folder.
func (m *Model) PutRawCCSFile(name string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.iis.CCSPath == "" {
		panic("wintest: SetCCS names no folder")
	}
	m.ccsDirLocked(m.iis.CCSPath)[fold(name)] = &ccsFile{name: name, data: slices.Clone(data), mod: m.nowLocked()}
}

// CCSFile reads a file of the CCS folder the registry names now (any case).
func (m *Model) CCSFile(name string) (data []byte, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.ccsDirs[folderKey(m.iis.CCSPath)][fold(name)]
	if f == nil {
		return nil, false
	}
	return slices.Clone(f.data), true
}

// CCSNames lists every name in the CCS folder the registry names now, .bak and .tmp included, sorted.
func (m *Model) CCSNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := []string{}
	for _, f := range m.ccsDirs[folderKey(m.iis.CCSPath)] {
		names = append(names, f.name)
	}
	slices.Sort(names)
	return names
}

// FailReplace(true) makes the next ReplaceCCS fail before it swaps anything (once).
func (m *Model) FailReplace(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failReplace = on
}

// ServeStaleCCS(true) is IIS that does not pick a replaced file up (F15 route (b) modelled): from the
// next replace or restore of a file on, TLS keeps serving the file as it was before it. ServeStaleCCS(false)
// serves the files again.
func (m *Model) ServeStaleCCS(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ccsStale = on
	if !on {
		clear(m.ccsPinned)
	}
}

// pinLocked keeps what TLS serves for folder\name before a change, when stale (the first change's
// bytes stay until ServeStaleCCS(false), as StaleTLS keeps a record's).
func (m *Model) pinLocked(folder, name string, served []byte) {
	if k := pinKey(folder, name); m.ccsStale {
		if _, ok := m.ccsPinned[k]; !ok {
			m.ccsPinned[k] = slices.Clone(served)
		}
	}
}

func (h host) CCSConfig(context.Context) (bool, string, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	return h.m.iis.CCSEnabled, h.m.iis.CCSPath, nil
}

// ListCCS lists the *.pfx files of folder (any case of the extension). A folder that does not exist
// lists nothing (W5 ruling: so that a journal whose folder was removed after a path change can still be
// pruned).
func (h host) ListCCS(_ context.Context, folder string) ([]winhelper.CCSEntry, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	out := []winhelper.CCSEntry{}
	for k, f := range h.m.ccsDirs[folderKey(folder)] {
		if strings.HasSuffix(k, ".pfx") {
			out = append(out, winhelper.CCSEntry{Name: f.name, Size: int64(len(f.data)), ModTime: f.mod})
		}
	}
	return out, nil
}

// ReadCCS reads at most limit+1 bytes of folder\name (any case); a file or a folder that does not exist
// is not found.
func (h host) ReadCCS(_ context.Context, folder, name string, limit int) ([]byte, bool, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	f := h.m.ccsDirs[folderKey(folder)][fold(name)]
	if f == nil {
		return nil, false, nil
	}
	return slices.Clone(f.data[:min(len(f.data), limit+1)]), true, nil
}

// OpenPFX reads what BuildPFX writes with the test-only reader (pki.OpenPFX); every failure is a
// problem of the file, never of the host.
func (host) OpenPFX(data, password []byte) ([]byte, [][]byte, string, error) {
	leaf, chain, err := pki.OpenPFX(data, password)
	switch {
	case errors.Is(err, pki.ErrPFXPassword):
		return nil, nil, winproto.CCSProblemPasswordMismatch, nil
	case errors.Is(err, pki.ErrPFXNoKey):
		return nil, nil, winproto.CCSProblemNoKey, nil
	case err != nil:
		return nil, nil, winproto.CCSProblemNotPFX, nil
	}
	return leaf, chain, "", nil
}

// WriteCCSTemp creates folder\tmpName (CREATE_NEW: an existing file is an error).
func (h host) WriteCCSTemp(_ context.Context, folder, tmpName string, data []byte) error {
	m := h.m
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.ccsDirs[folderKey(folder)]
	switch {
	case d == nil:
		return errNoCCSFolder
	case d[fold(tmpName)] != nil:
		return errCCSExists
	}
	d[fold(tmpName)] = &ccsFile{name: tmpName, data: slices.Clone(data), mod: m.nowLocked()}
	return nil
}

// ReplaceCCS is ReplaceFileW: name's bytes go to backupName (replacing one there), tmpName's to name
// (which keeps its spelling), tmpName is gone. FailReplace fails it before anything moved.
func (h host) ReplaceCCS(_ context.Context, folder, name, tmpName, backupName string) error {
	m := h.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReplace {
		m.failReplace = false
		return errCCSReplace
	}
	d := m.ccsDirs[folderKey(folder)]
	old, tmp := d[fold(name)], d[fold(tmpName)]
	if old == nil || tmp == nil {
		return errCCSNoFile
	}
	m.pinLocked(folder, name, old.data)
	d[fold(backupName)] = &ccsFile{name: backupName, data: old.data, mod: old.mod}
	d[fold(name)] = &ccsFile{name: old.name, data: tmp.data, mod: m.nowLocked()}
	delete(d, fold(tmpName))
	return nil
}

// RestoreCCS is MoveFileEx(backupName, name, MOVEFILE_REPLACE_EXISTING).
func (h host) RestoreCCS(_ context.Context, folder, backupName, name string) error {
	m := h.m
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.ccsDirs[folderKey(folder)]
	bak := d[fold(backupName)]
	if bak == nil {
		return errCCSNoFile
	}
	spelled := name
	if cur := d[fold(name)]; cur != nil {
		m.pinLocked(folder, name, cur.data)
		spelled = cur.name
	}
	d[fold(name)] = &ccsFile{name: spelled, data: bak.data, mod: bak.mod}
	delete(d, fold(backupName))
	return nil
}

// RemoveCCS removes folder\name, a .tmp or .bak name only; one that is absent, or whose folder does not
// exist, is nil.
func (h host) RemoveCCS(_ context.Context, folder, name string) error {
	if n := fold(name); !strings.HasSuffix(n, ".tmp") && !strings.HasSuffix(n, ".bak") {
		return errCCSRemove
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	delete(h.m.ccsDirs[folderKey(folder)], fold(name))
	return nil
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
