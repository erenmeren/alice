// Package wintest is the emulated Windows host of the tests of the Windows provider and of the e2e
// fake (design 2026-10-21 §13, R60, R61): a modelled machine (elevation, operating system, IIS, the
// certificate stores, the http.sys binding table, the IIS sites, the CCS folders, the helper's data
// directory and lock, the Application log) that implements winhelper.WriteHost, so the helper's own code
// (winhelper.ExecuteForced) answers and changes it behind the linuxsshtest SSH server, plus real TLS
// listeners that serve what http.sys and schannel would. It is never linked into the alice binary.
package wintest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1" //nolint:gosec // G505: Windows names certificates by their SHA-1 thumbprint
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

// defaultKeyProvider is where a PFX import puts a key (design §14 F4).
const defaultKeyProvider = "Microsoft Software Key Storage Provider"

// CertOptions are the properties of a certificate added to a store.
type CertOptions struct {
	FriendlyName string
	// KeyProvider names the key storage provider; "" is the Microsoft Software Key Storage Provider.
	KeyProvider string
	Exportable  bool
	// KeyUsableBySystem is whether SYSTEM can use the key; nil with a key means yes.
	KeyUsableBySystem *bool
}

type certEntry struct {
	leaf     *x509.Certificate
	sha1     string
	key      crypto.PrivateKey // nil: the store holds the certificate without its key
	friendly string
	provider string
	export   bool
	usable   *bool
}

type store struct {
	name  string // the spelling of the first use
	certs []*certEntry
}

// Model is the emulated machine. All methods are safe for concurrent use.
type Model struct {
	mu       sync.Mutex
	os       winhelper.OSFacts
	elevated bool
	iis      winproto.IISFacts
	stores   map[string]*store // by folded name
	inter    []*x509.Certificate
	bindings []winproto.SSLBinding
	sites    []winproto.Site
	expired  map[string]int

	failAppcmd    bool
	helperMissing bool
	noForced      bool
	protocol      int
	delays        map[string]time.Duration

	root      []byte // CARootPEM
	endpoints map[int]string
	intents   map[string]string // client address -> the address the helper meant to reach
	serving   sync.WaitGroup

	// The write half (write.go).
	served       map[string]*servedEntry // schannel's cache per record, by http.sys key (tls.go)
	state        map[string][]byte       // the helper's data directory: "journal/<op>.json", ...
	dataDirBad   bool
	lockOwned    bool // a helper call holds helper.lock
	lockOutside  int  // HoldLock holders (other helper processes)
	lockGen      int  // bumped by Reboot: a release from before it changes nothing
	lockWait     time.Duration
	killAt       string
	points       []string
	failUpdate   error
	corruptArmed bool // CorruptReadBack: the next update arms corruptNext
	corruptNext  bool // the next Binding read loses an Ex parameter
	failImport   bool
	stale        bool
	chainExtra   *x509.Certificate
	events       []Event
	imported     []string

	// The cleanup half (W3 Task 4).
	clockFixed   time.Time            // SetNow's time; zero: the system clock
	clockSkew    time.Duration        // Advance, on the system clock
	stateTimes   map[string]time.Time // the modification time of each state file
	keys         map[string]bool      // the machine key store: "<store>/<sha1>"
	rdp          string               // SSLCertificateSHA1Hash of RDP-Tcp, lower case ("" absent)
	winrm        []string
	failProtect  bool
	failAfterKey bool

	// The CCS half (W5 Task 4, write.go). IIS's Enabled and CertStoreLocation are iis.CCSEnabled and
	// iis.CCSPath.
	ccsDirs     map[string]map[string]*ccsFile // the folders by folderKey, their files by folded name
	ccsPassword string                         // IIS's private-key password (SetCCSPassword)
	failReplace bool
	ccsStale    bool
	ccsPinned   map[string][]byte // what IIS keeps serving for a file name until a refresh (F15), by folded file name
	failRefresh bool              // FailCCSRefresh
	ccsReparse  map[string]bool   // SetCCSReparse: the folders and files that are reparse points, by folderKey

	// The RDP half (W6 Task 3, write.go and tls.go; Ruling 23). The value is rdp above.
	rdpCfg     RDPConfig
	nsRead     map[string]bool  // the keys NETWORK SERVICE can read, by keyID
	failKeyACL bool             // FailKeyACL
	rdpStale   bool             // ServeStaleRDP
	rdpPinned  *tls.Certificate // what a stale listener keeps serving (nil with rdpPinSet: its failure)
	rdpPinSet  bool             // the stale listener took its pin at the first write of the value
}

// NewModel returns an elevated Windows Server 2022 Datacenter with IIS 10.0 installed, the stores My,
// WebHosting, CA and Root, and no bindings, certificates or sites.
func NewModel() *Model {
	m := &Model{
		os: winhelper.OSFacts{Build: "10.0.20348.2700", Product: "Windows Server 2022 Datacenter", InstallationType: "Server",
			OpenSSHVersion: "OpenSSH_for_Windows_8.1p1"},
		elevated:   true,
		iis:        winproto.IISFacts{Installed: true, Version: "10.0"},
		stores:     map[string]*store{},
		expired:    map[string]int{},
		protocol:   winproto.Protocol,
		delays:     map[string]time.Duration{},
		endpoints:  map[int]string{},
		intents:    map[string]string{},
		served:     map[string]*servedEntry{},
		state:      map[string][]byte{},
		ccsDirs:    map[string]map[string]*ccsFile{},
		ccsPinned:  map[string][]byte{},
		ccsReparse: map[string]bool{},
		stateTimes: map[string]time.Time{},
		keys:       map[string]bool{},
		nsRead:     map[string]bool{},
		lockWait:   winproto.LockWait,
	}
	for _, s := range []string{"My", "WebHosting", "CA", "Root"} {
		m.storeLocked(s)
	}
	return m
}

// fold is ASCII case folding: Windows compares store names and host names without case.
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// storeLocked returns the store of a name, creating it. A missing (NULL) store name is MY (W0 F2).
func (m *Model) storeLocked(name string) *store {
	if name == "" {
		name = "MY"
	}
	s, ok := m.stores[fold(name)]
	if !ok {
		s = &store{name: name}
		m.stores[fold(name)] = s
	}
	return s
}

// SetOS replaces the operating system facts.
func (m *Model) SetOS(f winhelper.OSFacts) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.os = f
}

// SetElevated sets whether the helper's token is elevated.
func (m *Model) SetElevated(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.elevated = v
}

// SetIIS replaces the IIS facts. Installed false is a machine without IIS: the facts say so and
// AppcmdSites refuses with winhelper.ErrIISNotInstalled.
func (m *Model) SetIIS(f winproto.IISFacts) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.iis = f
}

// AddCertificate puts the first certificate of chainPEM into the machine store (created when new), with
// the key of keyPEM (nil: the store holds the certificate without a key), and returns its SHA-1
// thumbprint in lower case hex. Further certificates in chainPEM are ignored: the chain the model
// presents is built from AddIntermediate's certificates, as Windows builds it. It panics on PEM that does
// not parse or a key that does not match (a test helper).
func (m *Model) AddCertificate(store string, chainPEM, keyPEM []byte, o CertOptions) (sha1 string) {
	block, _ := pem.Decode(chainPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		panic("wintest: no certificate in the PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("wintest: " + err.Error())
	}
	e := &certEntry{leaf: leaf, sha1: thumbprint(leaf.Raw), friendly: o.FriendlyName, export: o.Exportable}
	if keyPEM != nil {
		pair, err := tls.X509KeyPair(pem.EncodeToMemory(block), keyPEM)
		if err != nil {
			panic("wintest: " + err.Error())
		}
		e.key = pair.PrivateKey
		e.provider = o.KeyProvider
		if e.provider == "" {
			e.provider = defaultKeyProvider
		}
		e.usable = o.KeyUsableBySystem
		if e.usable == nil {
			t := true
			e.usable = &t
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.storeLocked(store)
	if keyPEM != nil {
		k := keyID(store, e.sha1)
		m.keys[k] = true
		// TermService makes the certificates of Remote Desktop itself, with a key it can read. A key the
		// store holds already keeps its grant (W6-8).
		if _, held := m.nsRead[k]; !held {
			m.nsRead[k] = fold(store) == fold(winproto.RDPStoreSelfSigned)
		}
	}
	s.certs = slices.DeleteFunc(s.certs, func(c *certEntry) bool { return c.sha1 == e.sha1 })
	s.certs = append(s.certs, e)
	return e.sha1
}

func thumbprint(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec // G401: a thumbprint is an identifier, not a security hash
	return hex.EncodeToString(sum[:])
}

// AddIntermediate puts a certificate into LocalMachine\CA: the chain the model builds for a leaf is the
// certificates found there, up to (and excluding) a self-signed root.
func (m *Model) AddIntermediate(certPEM []byte) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		panic("wintest: no certificate in the PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("wintest: " + err.Error())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inter = append(m.inter, c)
}

// RemoveCertificate deletes a certificate and its key from a store, as someone outside Alice would
// (the binding naming it stays).
func (m *Model) RemoveCertificate(storeName, sha1 string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.storeLocked(storeName)
	s.certs = slices.DeleteFunc(s.certs, func(c *certEntry) bool { return c.sha1 == sha1 })
	delete(m.keys, keyID(storeName, sha1))
	delete(m.nsRead, keyID(storeName, sha1))
}

// keyID names a key of the machine key store by its certificate.
func keyID(storeName, sha1 string) string { return fold(storeName) + "/" + sha1 }

// AddBinding appends a record to the http.sys table. A port a Serve call has not listened on yet gets
// its listener with the next Serve.
func (m *Model) AddBinding(b winproto.SSLBinding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bindings = append(m.bindings, cloneRecord(b))
	delete(m.served, keyOf(b))
}

// AddSite appends an IIS site.
func (m *Model) AddSite(s winproto.Site) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sites = append(m.sites, s)
}

// SetExpired sets how many expired certificates the named store holds (what the dump counts).
func (m *Model) SetExpired(storeName string, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expired[fold(storeName)] = n
}

// FailAppcmd makes appcmd fail (the dump then answers IO_ERROR, Ruling 12).
func (m *Model) FailAppcmd(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failAppcmd = v
}

// SetHelperMissing makes every line fail as on a host without the helper: exit 1, text on stderr only
// (cmd.exe's "is not recognized").
func (m *Model) SetHelperMissing(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.helperMissing = v
}

// SetNoForcedCommand models sshd without its ForceCommand: the login shell runs the line, which
// answers the same as a missing helper (Review Focus 5).
func (m *Model) SetNoForcedCommand(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.noForced = v
}

// SetProtocol makes "version" answer protocol p.
func (m *Model) SetProtocol(p int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.protocol = p
}

// Delay makes the named subcommand answer after d (a slow host).
func (m *Model) Delay(sub string, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delays[sub] = d
}

// CARootPEM is the root of the test CA Demo generated (nil on any other model).
func (m *Model) CARootPEM() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.root...)
}

// Host returns the model as the machine the helper's code runs on.
func (m *Model) Host() winhelper.WriteHost { return host{m} }

// host is the winhelper.Host view of a Model.
type host struct{ m *Model }

func (h host) Elevated() (bool, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	return h.m.elevated, nil
}

func (h host) OSFacts(context.Context) (winhelper.OSFacts, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	return h.m.os, nil
}

func (h host) IISFacts(context.Context) (winproto.IISFacts, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if !h.m.iis.Installed {
		return winproto.IISFacts{}, winhelper.ErrIISNotInstalled
	}
	return h.m.iis, nil
}

// helperStores are the stores the real helper names in win-facts, in its order (cmd/alice-winhelper's
// factStores).
var helperStores = []string{"My", "WebHosting", "CA", "Root"}

// Stores answers as the real helper does: My, WebHosting, CA and Root in that order, those the model
// holds, under the spelling of their first use. The real helper names no other store; a store a test
// created beyond these four follows them, sorted, so that it stays visible to the test. Remote Desktop,
// which every real host has (W6), is never named.
func (h host) Stores(context.Context) ([]string, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	names := make([]string, 0, len(h.m.stores))
	for _, n := range helperStores {
		if s, ok := h.m.stores[fold(n)]; ok {
			names = append(names, s.name)
		}
	}
	var others []string
	for k, s := range h.m.stores {
		if k != fold(winproto.RDPStoreSelfSigned) && !slices.ContainsFunc(helperStores, func(n string) bool { return fold(n) == k }) {
			others = append(others, s.name)
		}
	}
	slices.Sort(others)
	return append(names, others...), nil
}

// SSLBindings is the dump's read of the table: like the real helper's, it reads no extended
// parameters (only Binding, the deploy and restore path's live read, does).
func (h host) SSLBindings(context.Context) ([]winproto.SSLBinding, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	out := slices.Clone(h.m.bindings)
	for i := range out {
		out[i].Extended = nil
	}
	return out, nil
}

func (h host) Certificate(_ context.Context, storeName, sha1 string) (winproto.StoreCertificate, bool, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	e := h.m.certLocked(storeName, sha1)
	if e == nil {
		return winproto.StoreCertificate{}, false, nil
	}
	return h.m.storeCertLocked(storeName, e), true, nil
}

// storeCertLocked is a certificate of a store as the helper reads it.
func (m *Model) storeCertLocked(storeName string, e *certEntry) winproto.StoreCertificate {
	sum := sha256.Sum256(e.leaf.Raw)
	c := winproto.StoreCertificate{Store: storeName, SHA1: e.sha1, SHA256: hex.EncodeToString(sum[:]),
		DER: base64.StdEncoding.EncodeToString(e.leaf.Raw), Chain: []string{}, FriendlyName: e.friendly,
		NotAfter: e.leaf.NotAfter.UTC().Format(time.RFC3339), HasKey: e.key != nil, KeyProvider: e.provider,
		KeyExportable: e.export, KeyUsableBySystem: e.usable}
	for _, x := range m.chainLocked(e.leaf) {
		c.Chain = append(c.Chain, base64.StdEncoding.EncodeToString(x.Raw))
	}
	switch {
	case e.key == nil:
		c.KeyProblem = "key_missing"
	case e.usable != nil && !*e.usable:
		c.KeyProblem = "key_inaccessible"
	}
	return c
}

func (h host) ExpiredInStore(_ context.Context, storeName string) (int, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	return h.m.expired[fold(storeName)], nil
}

var errAppcmd = errors.New("wintest: appcmd failed")

func (h host) AppcmdSites(context.Context) ([]byte, error) {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if !h.m.iis.Installed {
		return nil, winhelper.ErrIISNotInstalled
	}
	if h.m.failAppcmd {
		return nil, errAppcmd
	}
	return renderAppcmd(h.m.sites), nil
}

// Dial reaches the listener of the binding port in addr (the model serves on its own addresses), and
// remembers which address the caller meant, so the TLS selection sees it (an ipport entry for 10.0.0.5).
func (h host) Dial(ctx context.Context, _, addr string) (net.Conn, error) {
	ip, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	h.m.mu.Lock()
	ep := h.m.endpoints[port]
	h.m.mu.Unlock()
	if ep == "" {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	}
	if a, err := net.ResolveTCPAddr("tcp", ep); err == nil && a.IP.IsUnspecified() {
		a.IP = net.IPv4(127, 0, 0, 1)
		ep = a.String()
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", ep)
	if err != nil {
		return nil, err
	}
	key := c.LocalAddr().String()
	h.m.mu.Lock()
	h.m.intents[key] = ip
	h.m.mu.Unlock()
	return &intentConn{Conn: c, m: h.m, key: key}, nil
}

type intentConn struct {
	net.Conn
	m    *Model
	key  string
	once sync.Once
}

func (c *intentConn) Close() error {
	c.once.Do(func() {
		c.m.mu.Lock()
		delete(c.m.intents, c.key)
		c.m.mu.Unlock()
	})
	return c.Conn.Close()
}

// certLocked finds a certificate by store (any case; "" is MY) and thumbprint.
func (m *Model) certLocked(storeName, sha1 string) *certEntry {
	s, ok := m.stores[fold(orMy(storeName))]
	if !ok {
		return nil
	}
	for _, c := range s.certs {
		if c.sha1 == sha1 {
			return c
		}
	}
	return nil
}

func orMy(s string) string {
	if s == "" {
		return "MY"
	}
	return s
}

// chainLocked is the chain Windows builds after the leaf: issuers found in LocalMachine\CA, a
// self-signed root excluded, then the cross-signed certificate of ChainDiffers when there is one.
func (m *Model) chainLocked(leaf *x509.Certificate) []*x509.Certificate {
	out := m.issuersLocked(leaf)
	if m.chainExtra != nil && len(out) < winproto.MaxChainCerts {
		out = append(out, m.chainExtra)
	}
	return out
}

// issuersLocked is the chain built from LocalMachine\CA alone.
func (m *Model) issuersLocked(leaf *x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	cur := leaf
	for len(out) < winproto.MaxChainCerts && !selfSigned(cur) {
		var next *x509.Certificate
		for _, c := range m.inter {
			if bytes.Equal(c.RawSubject, cur.RawIssuer) && !bytes.Equal(c.Raw, cur.Raw) && cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil || selfSigned(next) {
			break
		}
		out = append(out, next)
		cur = next
	}
	return out
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
}

// renderAppcmd writes the sites the way "appcmd list site /config /xml" does (design §14 F6).
func renderAppcmd(sites []winproto.Site) []byte {
	var b bytes.Buffer
	esc := func(s string) string {
		var e bytes.Buffer
		_ = xml.EscapeText(&e, []byte(s))
		return e.String()
	}
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<appcmd>\n")
	for _, s := range sites {
		state := s.State
		if state == "" {
			state = "Started"
		}
		var list []string
		for _, sb := range s.Bindings {
			list = append(list, sb.Protocol+"/"+sb.Information)
		}
		b.WriteString("    <SITE SITE.NAME=\"" + esc(s.Name) + "\" SITE.ID=\"" + strconv.FormatInt(s.ID, 10) + "\" bindings=\"" +
			esc(strings.Join(list, ",")) + "\" state=\"" + esc(state) + "\">\n")
		b.WriteString("        <site name=\"" + esc(s.Name) + "\" id=\"" + strconv.FormatInt(s.ID, 10) + "\">\n            <bindings>\n")
		for _, sb := range s.Bindings {
			b.WriteString("                <binding protocol=\"" + esc(sb.Protocol) + "\" bindingInformation=\"" + esc(sb.Information) +
				"\" sslFlags=\"" + strconv.Itoa(sb.SSLFlags) + "\" />\n")
		}
		b.WriteString("            </bindings>\n        </site>\n    </SITE>\n")
	}
	b.WriteString("</appcmd>\n")
	return b.Bytes()
}
