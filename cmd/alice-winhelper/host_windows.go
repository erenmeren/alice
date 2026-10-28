//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

// host is the real Windows machine behind winhelper.WriteHost. Every reading is a fixed registry value,
// file, API call or program (design 2026-10-21 §7); every change is an http.sys update, a certificate
// store add, a state file under dataDir, the helper lock or an Application event (W2), or a file of the
// CCS folder (W5, ccs_windows.go). Errors carry no OS text into the answer: winhelper replaces them with
// fixed messages.
type host struct {
	now     func() time.Time
	dataDir string // winproto.DataDir; tests use a private one
}

func newHost(dataDir string) host {
	return host{now: time.Now, dataDir: dataDir} //nolint:forbidigo // the helper is a separate binary; its clock is injected through host.now
}

var errBadValue = errors.New("alice-winhelper: a value has an unexpected type or size")

// dialTimeout bounds tls-probe's connection (winhelper bounds the handshake).
const dialTimeout = 5 * time.Second

// maxFactFile bounds the configuration files the facts read (redirection.config, the task XML).
const maxFactFile = 1 << 20

func (host) Elevated() (bool, error) { return tokenElevated() }

// Registry locations of the facts.
const (
	keyCurrentVersion = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	keyInetStp        = `SOFTWARE\Microsoft\InetStp`
	keyCentralCert    = `SOFTWARE\Microsoft\IIS\CentralCertProvider`
)

// openKey opens an HKLM key for reading in the 64-bit view.
func openKey(path string) (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
}

// OSFacts reads the version from the registry (Build is major.minor.build.UBR, as winver shows it) and
// the OpenSSH version from sshd.exe's version resource ("" when sshd is not where the Windows
// capability installs it).
func (host) OSFacts(context.Context) (winhelper.OSFacts, error) {
	k, err := openKey(keyCurrentVersion)
	if err != nil {
		return winhelper.OSFacts{}, err
	}
	defer func() { _ = k.Close() }()
	major, _, err := k.GetIntegerValue("CurrentMajorVersionNumber")
	if err != nil {
		return winhelper.OSFacts{}, err
	}
	minor, _, err := k.GetIntegerValue("CurrentMinorVersionNumber")
	if err != nil {
		return winhelper.OSFacts{}, err
	}
	build, _, err := k.GetStringValue("CurrentBuildNumber")
	if err != nil {
		return winhelper.OSFacts{}, err
	}
	ubr, _, err := k.GetIntegerValue("UBR")
	if err != nil {
		return winhelper.OSFacts{}, err
	}
	product, _, err := k.GetStringValue("ProductName")
	if err != nil {
		return winhelper.OSFacts{}, err
	}
	installation, _, err := k.GetStringValue("InstallationType")
	if err != nil {
		return winhelper.OSFacts{}, err
	}
	ssh, err := openSSHVersion()
	if err != nil {
		return winhelper.OSFacts{}, err
	}
	return winhelper.OSFacts{Build: fmt.Sprintf("%d.%d.%s.%d", major, minor, build, ubr), Product: product,
		InstallationType: installation, OpenSSHVersion: ssh}, nil
}

// openSSHVersion is the ProductVersion string of %windir%\System32\OpenSSH\sshd.exe ("" when the file
// is absent), else its fixed product version a.b.c.d.
func openSSHVersion() (string, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	path := filepath.Join(sys, "OpenSSH", "sshd.exe")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return "", err
	}
	if size == 0 || size > maxFactFile {
		return "", errBadValue
	}
	block := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&block[0])); err != nil {
		return "", err
	}
	if s := versionString(block, "ProductVersion"); s != "" {
		return s, nil
	}
	// unsafe: VerQueryValue returns a pointer into block (kept alive by this function) and the size it
	// points to; both are checked before the pointer is read.
	var fixed *windows.VS_FIXEDFILEINFO
	var n uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&block[0]), `\`, unsafe.Pointer(&fixed), &n); err != nil ||
		fixed == nil || n < uint32(unsafe.Sizeof(*fixed)) {
		return "", nil // a resource without version facts: nothing to report
	}
	return fmt.Sprintf("%d.%d.%d.%d", fixed.ProductVersionMS>>16, fixed.ProductVersionMS&0xffff,
		fixed.ProductVersionLS>>16, fixed.ProductVersionLS&0xffff), nil
}

// versionString reads one StringFileInfo value of the first translation of a version resource; "" when
// there is none.
func versionString(block []byte, name string) string {
	// unsafe: as in openSSHVersion, VerQueryValue points into block and reports the length it covers.
	var lang *[2]uint16
	var n uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&block[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&lang), &n); err != nil ||
		lang == nil || n < 4 {
		return ""
	}
	var p *uint16
	sub := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, lang[0], lang[1], name)
	if err := windows.VerQueryValue(unsafe.Pointer(&block[0]), sub, unsafe.Pointer(&p), &n); err != nil || p == nil || n == 0 {
		return ""
	}
	if n > winproto.MaxText {
		n = winproto.MaxText
	}
	// n counts UTF-16 characters, the terminating NUL included.
	s := unsafe.Slice(p, n)
	if i := indexZero(s); i >= 0 {
		s = s[:i]
	}
	return string(utf16.Decode(s))
}

func indexZero(s []uint16) int {
	for i, c := range s {
		if c == 0 {
			return i
		}
	}
	return -1
}

// IISFacts reads InetStp (missing: IIS is not installed), the shared configuration switch of
// redirection.config, the Central Certificate Store provider and the AutoCertRebind task.
func (host) IISFacts(context.Context) (winproto.IISFacts, error) {
	k, err := openKey(keyInetStp)
	if errors.Is(err, registry.ErrNotExist) {
		return winproto.IISFacts{}, winhelper.ErrIISNotInstalled
	}
	if err != nil {
		return winproto.IISFacts{}, err
	}
	defer func() { _ = k.Close() }()
	major, _, err := k.GetIntegerValue("MajorVersion")
	if errors.Is(err, registry.ErrNotExist) {
		return winproto.IISFacts{}, winhelper.ErrIISNotInstalled // the key of an uninstalled IIS
	}
	if err != nil {
		return winproto.IISFacts{}, err
	}
	minor, _, err := k.GetIntegerValue("MinorVersion")
	if err != nil {
		return winproto.IISFacts{}, err
	}
	f := winproto.IISFacts{Installed: true, Version: fmt.Sprintf("%d.%d", major, minor)}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return winproto.IISFacts{}, err
	}
	if f.SharedConfig, err = sharedConfig(filepath.Join(sys, "inetsrv", "config", "redirection.config")); err != nil {
		return winproto.IISFacts{}, err
	}
	if f.CCSEnabled, f.CCSPath, err = centralCertStore(); err != nil {
		return winproto.IISFacts{}, err
	}
	task := filepath.Join(sys, "Tasks", "Microsoft", "Windows", "CertificateServicesClient", "AutoCertRebind")
	if f.AutoCertRebind, err = taskEnabled(task); err != nil {
		return winproto.IISFacts{}, err
	}
	return f, nil
}

// centralCertStore reads the CCS provider's Enabled and CertStoreLocation; a missing key or value is
// "not enabled".
func centralCertStore() (bool, string, error) {
	k, err := openKey(keyCentralCert)
	if errors.Is(err, registry.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	defer func() { _ = k.Close() }()
	enabled, _, err := k.GetIntegerValue("Enabled")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return false, "", err
	}
	path, _, err := k.GetStringValue("CertStoreLocation")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return false, "", err
	}
	return enabled != 0, path, nil
}

// openFact opens a fact file (tests replace it to simulate a token that may not read the file).
var openFact = func(path string) (io.ReadCloser, error) {
	return os.Open(path) //nolint:gosec // G304: a fixed path under the system directory
}

// readFact reads a configuration file of at most maxFactFile bytes as UTF-8 (a UTF-16 file with its
// byte order mark is converted); found is false when it does not exist, and also when the token may
// not read it: inetsrv\config and System32\Tasks admit only Administrators and SYSTEM, so a
// non-elevated helper cannot open them, and win-facts must still answer (elevated:false, Ruling 3).
// Such a fact is unknown and reported as false; iis-dump runs elevated and reads it.
func readFact(path string) (data []byte, found bool, err error) {
	f, err := openFact(path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxFactFile+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > maxFactFile {
		return nil, false, errBadValue
	}
	return toUTF8(b), true, nil
}

// toUTF8 converts UTF-16 with a byte order mark (Task Scheduler writes its XML so) and drops a UTF-8
// byte order mark; other input is returned as it is.
func toUTF8(b []byte) []byte {
	switch {
	case len(b) >= 2 && (b[0] == 0xff && b[1] == 0xfe || b[0] == 0xfe && b[1] == 0xff):
		big := b[0] == 0xfe
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			if big {
				u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
			} else {
				u = append(u, uint16(b[i+1])<<8|uint16(b[i]))
			}
		}
		return []byte(string(utf16.Decode(u)))
	case bytes.HasPrefix(b, []byte("\xef\xbb\xbf")):
		return b[3:]
	}
	return b
}

// decodeXML reads converted (UTF-8) XML whatever encoding its declaration names.
func decodeXML(data []byte, v any) error {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil } // already UTF-8 (toUTF8)
	return d.Decode(v)
}

// sharedConfig reports whether redirection.config's configurationRedirection is enabled (IIS shared
// configuration); a missing file is "not shared".
func sharedConfig(path string) (bool, error) {
	data, found, err := readFact(path)
	if err != nil || !found {
		return false, err
	}
	var doc struct {
		Redirection struct {
			Enabled string `xml:"enabled,attr"`
		} `xml:"configurationRedirection"`
	}
	if err := decodeXML(data, &doc); err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(doc.Redirection.Enabled), "true"), nil
}

// taskEnabled reads Settings/Enabled of a Task Scheduler task file; a missing file is "not enabled",
// a missing element is the schema's default (true).
func taskEnabled(path string) (bool, error) {
	data, found, err := readFact(path)
	if err != nil || !found {
		return false, err
	}
	var doc struct {
		Settings struct {
			Enabled *string `xml:"Enabled"`
		} `xml:"Settings"`
	}
	if err := decodeXML(data, &doc); err != nil {
		return false, err
	}
	if doc.Settings.Enabled == nil {
		return true, nil
	}
	return strings.EqualFold(strings.TrimSpace(*doc.Settings.Enabled), "true"), nil
}

// factStores are the machine stores win-facts names when they exist.
var factStores = []string{"My", "WebHosting", "CA", "Root"}

// Stores lists the factStores that open read-only in the local machine context.
func (host) Stores(context.Context) ([]string, error) {
	out := []string{}
	for _, name := range factStores {
		h, found, err := openExistingStore(name)
		if err != nil {
			return nil, err
		}
		if !found {
			continue // a store that does not exist is not listed
		}
		if err := windows.CertCloseStore(h, 0); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, nil
}

// openStore opens a local machine system store read-only, never creating it.
func openStore(name string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	// unsafe: the store name is the provider's pvPara, a NUL-terminated UTF-16 string kept alive until
	// the call returns.
	h, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG,
		uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(p)
	return h, err
}

// SSLBindings reads http.sys's SSL tables through httpapi.dll (httpapi_windows.go).
func (host) SSLBindings(context.Context) ([]winproto.SSLBinding, error) { return sslBindings() }

// Certificate reads one machine store certificate with its chain and key facts (stores_windows.go).
func (h host) Certificate(_ context.Context, store, sha1 string) (winproto.StoreCertificate, bool, error) {
	return certificate(store, sha1, h.now())
}

// ExpiredInStore counts a machine store's expired certificates.
func (h host) ExpiredInStore(_ context.Context, store string) (int, error) {
	return expiredInStore(store, h.now())
}

// AppcmdSites runs appcmd for the IIS sites (appcmd_windows.go).
func (host) AppcmdSites(ctx context.Context) ([]byte, error) { return appcmdSites(ctx) }

// Dial is tls-probe's connection to an endpoint of the server itself.
func (host) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, network, addr)
}

// errRDPNotImplemented is what the RDP methods answer until the real RDP half lands (W6 Task 4).
var errRDPNotImplemented = errors.New("alice-winhelper: the RDP listener is not implemented")

// RDPListener is not implemented yet (W6 Task 4).
func (host) RDPListener(context.Context) (winhelper.RDPListener, error) {
	return winhelper.RDPListener{}, errRDPNotImplemented
}

// SetRDPCertificate is not implemented yet (W6 Task 4).
func (host) SetRDPCertificate(context.Context, string) error { return errRDPNotImplemented }

// StoreCertificates is not implemented yet (W6 Task 4).
func (host) StoreCertificates(context.Context, string, int) ([]winproto.StoreCertificate, error) {
	return nil, errRDPNotImplemented
}

// RDPKeyRead is not implemented yet (W6 Task 4).
func (host) RDPKeyRead(context.Context, string, string) (bool, error) {
	return false, errRDPNotImplemented
}

// SetRDPKeyRead is not implemented yet (W6 Task 4).
func (host) SetRDPKeyRead(context.Context, string, string, bool) error { return errRDPNotImplemented }
