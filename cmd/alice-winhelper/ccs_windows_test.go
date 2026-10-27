//go:build windows

package main

// The real CCS half (W5 Task 5, R68): the pure helpers of ccs_windows.go on every Windows build, and,
// with ALICE_WIN_REAL=1 on the runners, the facts F15-F18 and the reparse refusals. Each test logs its
// verdicts as lines starting "F15: ", "F16: ", "F17: " or "F18: ", so the controller reads them from the
// job log.
//
// Fixtures (W5 Global Constraints, Ruling 26): ports 45480-45489 (an sslFlags=3 https binding of an
// alice-w5- site; 45499 is the sites' plain http binding), a CCS folder C:\alice-w5-ccs-<random>, the
// local account alice-w5-ccs as CCS's access account with a run-time password, the private-key
// password made at run time. Every cleanup is registered before its fixture is made and runs in
// reverse order: the http.sys ccs record, the site, the CCS configuration (disabled, the registry key
// restored as found), the account, the folder. The Web-CertProvider feature stays installed (removing
// it needs a restart). zz_runner_clean_windows_test.go checks that nothing is left.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

const (
	portCCSReplace  = 45480
	portCCSNames    = 45481
	portCCSPassword = 45482
	portCCSChain    = 45483
	portCCSReparse  = 45484
	portCCSFidelity = 45485
	portCCSSiteHTTP = 45499

	ccsAccount = "alice-w5-ccs"
	ccsRegKey  = `HKLM\` + keyCentralCert

	// ccsPickupLimit and ccsPoll are F15's measurement: fresh handshakes every 100 ms for up to 120 s.
	ccsPickupLimit = 120 * time.Second
	ccsPoll        = 100 * time.Millisecond
)

// ---- the pure helpers (every Windows build) --------------------------------------------------------

func TestCCSFilePathsAndNames(t *testing.T) {
	for _, c := range []struct {
		folder, name, want string
	}{
		{`C:\CCS`, "a.pfx", `C:\CCS\a.pfx`},
		{`C:\CCS\`, "a.pfx", `C:\CCS\a.pfx`},
		{`C:\`, "a.pfx", `C:\a.pfx`},
	} {
		got, err := ccsFilePath(c.folder, c.name)
		require.NoError(t, err, "%s %s", c.folder, c.name)
		assert.Equal(t, c.want, got)
	}
	for _, c := range [][2]string{{`C:\CCS`, `..`}, {`C:\CCS`, `.`}, {`C:\CCS`, `a\b.pfx`}, {`C:\CCS`, `a/b.pfx`},
		{`C:\CCS`, `a.pfx:s`}, {`C:\CCS`, ``}, {`\\fs\c`, `a.pfx`}, {`CCS`, `a.pfx`}, {`C:\a\..\b`, `a.pfx`}} {
		_, err := ccsFilePath(c[0], c[1])
		assert.ErrorIs(t, err, errBadValue, "%q %q", c[0], c[1])
	}
	for n, want := range map[string]bool{"a.pfx": true, "A.PFX": true, "a.Pfx": true, ".pfx": true, "a.pfxold": false,
		"a.pf": false, "pfx": false, "a.pfx.alice-01234567.bak": false, "a0pfx": false} {
		assert.Equal(t, want, pfxName(n), n)
	}
	op := "a1111111-1111-4111-8111-111111111111"
	assert.True(t, ccsTempRE.MatchString(".alice-"+op+".tmp"))
	assert.True(t, ccsBackupRE.MatchString("www.example.test.pfx.alice-11111111.bak"))
	for _, n := range []string{"www.example.test.pfx", ".alice-x.tmp", "a.tmp", `a\b.pfx.alice-11111111.bak`,
		"a.pfx.alice-1111111.bak", "a.pfx.alice-11111111.bak.pfx", ".alice-" + strings.ToUpper(op) + ".tmp"} { //nolint:forbidigo // a test input
		assert.False(t, ccsTempRE.MatchString(n) || ccsBackupRE.MatchString(n), n)
	}
}

func TestPFXChainOrder(t *testing.T) {
	now := time.Now()
	ca := pki.NewCA("alice-w5-order", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "o.alice-w5.test", SANs: []string{"o.alice-w5.test"}}, now)
	other := pki.SelfSigned("other.alice-w5.test", pki.ECDSA256, now)
	got := pfxChainOrder(leaf.Cert.Raw, [][]byte{ca.Root.Raw, other.Cert.Raw, ca.Intermediate.Raw})
	assert.Equal(t, [][]byte{ca.Intermediate.Raw, ca.Root.Raw, other.Cert.Raw}, got, "the chain first, the rest in store order")
	assert.Equal(t, [][]byte{ca.Intermediate.Raw}, pfxChainOrder(other.Cert.Raw, [][]byte{ca.Intermediate.Raw}), "a self-signed leaf")
	assert.Empty(t, pfxChainOrder(leaf.Cert.Raw, nil))
}

// ---- the fixture ---------------------------------------------------------------------------------------

// ccsReal is a CCS fixture on the real machine (and on the twin's model, for TestFidelityCCS): IIS's
// CCS enabled at a fresh folder with the alice-w5-ccs account and a private-key password, an alice-w5-
// site whose https bindings on port carry sslFlags=3, and the write host on a private data directory.
type ccsReal struct {
	*twin
	folder   string
	password []byte // IIS's private-key password of the store
	port     int
	w        host
	start    time.Time // when CCS was enabled
}

// randomHex is n random bytes in hex.
func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// requireCertProvider installs the Web-CertProvider feature once (it stays: removing it needs a
// restart). A runner without the feature or the cmdlets fails here with PowerShell's message, never
// skips.
func requireCertProvider(t *testing.T) {
	t.Helper()
	out, err := runPowershell(nil, `Import-Module ServerManager
$f = Get-WindowsFeature -Name Web-CertProvider
if (-not $f) { throw 'this image does not know the Web-CertProvider feature' }
if (-not $f.Installed) {
    $r = Install-WindowsFeature -Name Web-CertProvider
    if (-not $r.Success) { throw "Install-WindowsFeature Web-CertProvider failed (exit code $($r.ExitCode))" }
    'installed'
} else { 'present' }
Import-Module WebAdministration
if (-not (Get-Command Enable-WebCentralCertProvider -ErrorAction SilentlyContinue)) { throw 'WebAdministration has no Enable-WebCentralCertProvider' }`)
	require.NoError(t, err, "the CCS feature (Install-WindowsFeature Web-CertProvider, WebAdministration): %s", out)
	t.Logf("Web-CertProvider: %s", strings.TrimSpace(string(out)))
}

// regKeyExists reports whether the CentralCertProvider key exists.
func regKeyExists(t *testing.T) bool {
	t.Helper()
	k, err := openKey(keyCentralCert)
	if err == nil {
		_ = k.Close()
		return true
	}
	require.ErrorIs(t, err, registry.ErrNotExist)
	return false
}

// removeFolder removes a fixture folder, retrying while IIS still holds it (its change notification).
func removeFolder(t *testing.T, dir string) {
	t.Helper()
	var err error
	for range 20 {
		if err = os.RemoveAll(dir); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("cleanup of %s: %v", dir, err)
}

// newCCSReal makes the fixture: hosts are the host headers of the site's https bindings on port.
func newCCSReal(t *testing.T, port int, hosts ...string) *ccsReal {
	t.Helper()
	require.True(t, port >= 45480 && port <= 45489, "W5 CCS fixture ports are 45480-45489")
	tw := newTwin(t)
	tw.siteID, tw.httpPort = int64(port), portCCSSiteHTTP
	f := &ccsReal{twin: tw, port: port, password: winhelper.NewPFXPassword(), w: newHost(newTestDataDir(t))}
	requireCertProvider(t)

	f.folder = `C:\alice-w5-ccs-` + randomHex(t, 8)
	dir := f.folder
	tw.later(func() { removeFolder(t, dir) })
	require.NoError(t, os.Mkdir(f.folder, 0o700))

	accountPW := randomHex(t, 16) + "Aa1!" // the local password policy wants upper, lower, digit and symbol
	tw.later(func() {
		if _, err := runPowershell(map[string]string{"ALICE_W5_ACCOUNT": ccsAccount}, `$u = Get-LocalUser -Name $env:ALICE_W5_ACCOUNT -ErrorAction SilentlyContinue
if ($u) {
    Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $u.SID.Value } | Remove-CimInstance
    Remove-LocalUser -Name $env:ALICE_W5_ACCOUNT
}`); err != nil {
			t.Logf("cleanup of the account %s: %v", ccsAccount, err)
		}
	})
	powershellEnv(t, map[string]string{"ALICE_W5_ACCOUNT": ccsAccount, "ALICE_W5_PW": accountPW},
		`$pw = ConvertTo-SecureString -String $env:ALICE_W5_PW -AsPlainText -Force
New-LocalUser -Name $env:ALICE_W5_ACCOUNT -Password $pw -PasswordNeverExpires -AccountNeverExpires -Description 'alice-w5 CCS fixture' | Out-Null
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $env:ALICE_W5_ACCOUNT`) // BUILTIN\Users, as net user /add makes it
	out, err := exec.Command("icacls", f.folder, "/grant", ccsAccount+":(OI)(CI)R").CombinedOutput()
	require.NoError(t, err, "icacls: %s", out)

	// The registry key as found (after the feature's install, which stays), restored at the end.
	existed := regKeyExists(t)
	saved := ""
	if existed {
		tmp, err := os.CreateTemp("", "alice-w5-ccs-*.reg") // not t.TempDir: that one is gone before the twin's cleanups
		require.NoError(t, err)
		saved = tmp.Name()
		require.NoError(t, tmp.Close())
		out, err := exec.Command("reg", "export", ccsRegKey, saved, "/y").CombinedOutput()
		require.NoError(t, err, "reg export: %s", out)
	}
	tw.later(func() { restoreCCSRegistry(t, existed, saved) })
	powershellEnv(t, map[string]string{"ALICE_W5_FOLDER": f.folder, "ALICE_W5_ACCOUNT": ccsAccount, "ALICE_W5_PW": accountPW,
		"ALICE_W5_PK": string(f.password)}, `Import-Module WebAdministration
Enable-WebCentralCertProvider -CertStoreLocation $env:ALICE_W5_FOLDER -UserName "$env:COMPUTERNAME\$env:ALICE_W5_ACCOUNT" -Password $env:ALICE_W5_PW -PrivateKeyPassword $env:ALICE_W5_PK`)
	f.start = time.Now()
	enabled, path, err := f.w.CCSConfig(context.Background())
	require.NoError(t, err)
	require.True(t, enabled, "the helper reads CCS enabled")
	require.Equal(t, f.folder, path, "the helper reads the folder Enable-WebCentralCertProvider wrote")
	tw.model.SetCCS(true, f.folder)
	tw.model.SetCCSPassword(string(f.password))

	bindings := []winproto.SiteBinding{}
	for _, h := range hosts {
		bindings = append(bindings, winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:%s", port, h), SSLFlags: 3})
	}
	tw.addSite(fmt.Sprintf("alice-w5-%d", port), bindings...)
	f.ensureCCSRecord()
	return f
}

// restoreCCSRegistry disables CCS and puts the key back as it was found (deleted when there was none).
func restoreCCSRegistry(t *testing.T, existed bool, saved string) {
	t.Helper()
	if _, err := runPowershell(nil, `Import-Module WebAdministration; Disable-WebCentralCertProvider`); err != nil {
		t.Logf("Disable-WebCentralCertProvider: %v (the key is restored below)", err)
	}
	if out, err := exec.Command("reg", "delete", ccsRegKey, "/f").CombinedOutput(); err != nil && regKeyExists(t) {
		t.Logf("reg delete %s: %v %s", ccsRegKey, err, out)
	}
	if existed {
		if out, err := exec.Command("reg", "import", saved).CombinedOutput(); err != nil {
			t.Logf("reg import %s: %v %s", saved, err, out)
		}
		_ = os.Remove(saved)
	}
}

// ccsRecord reads the http.sys ccs record of port.
func ccsRecord(t *testing.T, port int) (winproto.SSLBinding, bool) {
	t.Helper()
	list, err := sslBindings()
	require.NoError(t, err)
	return findBinding(list, winproto.BindingCCS, port)
}

// ensureCCSRecord logs whether IIS made the http.sys ccs:<port> record for the sslFlags=3 binding
// appcmd added (F15's side question), and makes it with netsh when it did not.
func (f *ccsReal) ensureCCSRecord() {
	t := f.t
	t.Helper()
	found := false
	for deadline := time.Now().Add(10 * time.Second); !found && time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		_, found = ccsRecord(t, f.port)
	}
	t.Logf("F15: appcmd's sslFlags=3 binding created the http.sys ccs:%d record: %v", f.port, found)
	key := "ccs=" + strconv.Itoa(f.port)
	f.later(func() {
		if _, ok := ccsRecord(t, f.port); !ok {
			return // the site's removal took it
		}
		if out, err := exec.Command("netsh", "http", "delete", "sslcert", key).CombinedOutput(); err != nil {
			t.Logf("cleanup of %s: %v %s", key, err, out)
		}
	})
	if !found {
		netsh(t, "add", "sslcert", key, "appid="+winproto.AppIDIIS)
		_, found = ccsRecord(t, f.port)
		require.True(t, found, "netsh made the ccs:%d record", f.port)
	}
	f.ports[f.port] = true
}

// path is a file of the fixture's folder.
func (f *ccsReal) path(name string) string { return filepath.Join(f.folder, name) }

// pfx is a leaf with its key and intermediates in BuildPFX's format under pw.
func ccsPFX(t *testing.T, leaf pki.Leaf, pw []byte, intermediates ...*x509.Certificate) []byte {
	t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
	require.NoError(t, err)
	ders := [][]byte{}
	for _, c := range intermediates {
		ders = append(ders, c.Raw)
	}
	b, err := winhelper.BuildPFX(leaf.Cert.Raw, pkcs8, pw, ders...)
	require.NoError(t, err)
	return b
}

// put writes a file into the folder as a third party does, on the machine and on the model.
func (f *ccsReal) put(name string, data []byte) {
	f.t.Helper()
	require.NoError(f.t, os.WriteFile(f.path(name), data, 0o600))
	f.model.PutRawCCSFile(name, data)
}

// ccsInput is a CCSDeployInput for the fixture's folder and password, edited.
func (f *ccsReal) ccsInput(host string, leaf pki.Leaf, expect string, edit ...func(*winproto.CCSDeployInput)) []byte {
	f.t.Helper()
	in := winproto.CCSDeployInput{Path: f.folder, Host: host, ExpectSHA256: expect, ChainPEM: string(leaf.FullchainPEM),
		KeyPEM: string(leaf.KeyPEM), Password: string(f.password), ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}}
	for _, e := range edit {
		e(&in)
	}
	b, err := json.Marshal(in)
	require.NoError(f.t, err)
	return b
}

// deployReal runs ccs-deploy on the real host only and requires the phase.
func (f *ccsReal) deployReal(op, host string, leaf pki.Leaf, expect, phase string) map[string]any {
	f.t.Helper()
	_, got := execOn(f.t, f.w, f.ccsInput(host, leaf, expect), []string{winproto.SubCCSDeploy, winproto.ArgOp, op})
	require.Equal(f.t, phase, got["phase"], "ccs-deploy %s: %v", host, got)
	return got
}

// backupName is winhelper's ccsBackupName.
func backupName(file, op string) string { return file + ".alice-" + op[len(op)-8:] + ".bak" }

// ccsAddr is the fixture's endpoint on this machine.
func (f *ccsReal) addr() string { return "127.0.0.1:" + strconv.Itoa(f.port) }

// pickup polls fresh handshakes (no session cache) every ccsPoll for up to limit until sni is served
// the leaf want: how long it took, whether it was, and the last answer.
func pickup(addr, sni, want string, limit time.Duration) (time.Duration, bool, []string, error) {
	start := time.Now()
	var last []string
	var err error
	for time.Since(start) < limit {
		if last, err = served(addr, sni); err == nil && len(last) > 0 && last[0] == want {
			return time.Since(start), true, last, nil
		}
		time.Sleep(ccsPoll)
	}
	return time.Since(start), false, last, err
}

// requireServed waits until sni is served want (a positive control) and returns the chain served.
func (f *ccsReal) requireServed(sni string, want *x509.Certificate) []string {
	f.t.Helper()
	d, ok, last, err := pickup(f.addr(), sni, sum256hex(want.Raw), ccsPickupLimit)
	require.True(f.t, ok, "%s on %d is served %s within %v (last %v, %v)", sni, f.port, want.Subject.CommonName, ccsPickupLimit, last, err)
	f.t.Logf("%s served %s after %v", sni, want.Subject.CommonName, d.Round(time.Millisecond))
	return last
}

// sddl is a file's owner, group and DACL in SDDL.
func sddl(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	return sd.String()
}

// updateCCSRecordSame sends the ccs record of port back to http.sys as it is
// (HttpUpdateServiceConfiguration of HTTP_SERVICE_CONFIG_SSL_CCS_SET with the base fields read): F15
// route (a)'s same-record update, measured here before the helper has it.
func updateCCSRecordSame(t *testing.T, port int) error {
	t.Helper()
	b, ok := ccsRecord(t, port)
	require.True(t, ok)
	ip, err := netip.ParseAddr(b.IP)
	require.NoError(t, err)
	appID, err := windows.GUIDFromString(b.AppID)
	require.NoError(t, err)
	hash, err := hex.DecodeString(b.CertSHA1)
	require.NoError(t, err)
	a := newArena(int(unsafe.Sizeof(sslCcsSet{})) + len(hash) + 8 + stringBytes(b.Store) + stringBytes(b.CTLIdentifier) +
		stringBytes(b.CTLStore))
	off := a.alloc(int(unsafe.Sizeof(sslCcsSet{})))
	// unsafe: the structure is laid over the arena's first bytes (aligned, no Go pointers inside).
	s := (*sslCcsSet)(unsafe.Pointer(&a.b[off]))
	s.LocalAddress = putSockaddr(ip.Unmap(), port)
	s.Param.SslHashLength = uint32(len(hash)) //nolint:gosec // G115: a short hash
	s.Param.SslHash = a.put(hash)
	s.Param.AppID = appID
	s.Param.SslCertStoreName = a.putString(b.Store)
	s.Param.DefaultCertCheckMode = b.CertCheckMode
	s.Param.DefaultRevocationFreshnessTime = b.RevocationFreshnessTime
	s.Param.DefaultRevocationURLRetrievalTimeout = b.URLRetrievalTimeout
	s.Param.DefaultSslCtlIdentifier = a.putString(b.CTLIdentifier)
	s.Param.DefaultSslCtlStoreName = a.putString(b.CTLStore)
	s.Param.DefaultFlags = b.Flags
	return withHTTP(func() error {
		r, _, _ := procHttpUpdateServiceConfiguration.Call(0, configSSLCcsCertInfo, a.addr(off), unsafe.Sizeof(*s), 0)
		runtime.KeepAlive(a)
		return ulongResult(r)
	})
}

// ---- F15 ---------------------------------------------------------------------------------------------

// TestRealCCSReplaceIsPickedUp measures F15: ccs-deploy's ReplaceFileW is served at a fresh handshake
// (the delay of a plain replace, twice, and of a replace followed by a same-record update of the ccs
// record), the backup holds the bytes replaced, the file keeps its ACL, and a .bak or .tmp file is
// never served.
func TestRealCCSReplaceIsPickedUp(t *testing.T) {
	const host, file = "r.alice-w5.test", "r.alice-w5.test.pfx"
	f := newCCSReal(t, portCCSReplace, host, "n.alice-w5.test")
	now := time.Now()
	old := pki.SelfSigned("alice-w5-r-old.test", pki.ECDSA256, now)
	f.put(file, ccsPFX(t, old, f.password))
	// An explicit ACE of its own on the file: ReplaceFileW must keep it.
	out, err := exec.Command("icacls", f.path(file), "/grant", ccsAccount+":(RX)").CombinedOutput()
	require.NoError(t, err, "icacls: %s", out)
	acl := sddl(t, f.path(file))
	require.Contains(t, acl, "(A;", "positive control: a DACL is read")
	f.requireServed(host, old.Cert)
	t.Logf("F15: the first file of a new CCS folder was served %v after Enable-WebCentralCertProvider", time.Since(f.start).Round(time.Millisecond))

	// Files named as the helper's backup and temporary files, for a host that has no .pfx of its own.
	hidden := pki.SelfSigned("alice-w5-n.test", pki.ECDSA256, now)
	hiddenPFX := ccsPFX(t, hidden, f.password)
	f.put("n.alice-w5.test.pfx.alice-00000000.bak", hiddenPFX)
	f.put(".alice-"+op7+".tmp", hiddenPFX)

	prevBytes, err := os.ReadFile(f.path(file))
	require.NoError(t, err)
	prev := old
	var delays []string
	for i, c := range []struct {
		op     string
		update bool
	}{{op1, false}, {op2, false}, {op3, true}} {
		leaf := pki.SelfSigned(fmt.Sprintf("alice-w5-r-%d.test", i+1), pki.ECDSA256, time.Now())
		f.deployReal(c.op, host, leaf, sum256hex(prev.Cert.Raw), winproto.PhaseCommitted)
		kind := "plain replace"
		if c.update {
			kind = "replace followed by a same-record ccs update"
			if err := updateCCSRecordSame(t, f.port); err != nil {
				t.Logf("F15: the same-record update of ccs:%d failed: %v", f.port, err)
			}
		}
		d, ok, last, err := pickup(f.addr(), host, sum256hex(leaf.Cert.Raw), ccsPickupLimit)
		if ok {
			t.Logf("F15: %s %d picked up after %v (fresh handshakes every %v)", kind, i+1, d.Round(time.Millisecond), ccsPoll)
			delays = append(delays, fmt.Sprintf("%s %v", kind, d.Round(time.Millisecond)))
		} else {
			t.Logf("F15: %s %d NOT picked up within %v (last %v, %v)", kind, i+1, ccsPickupLimit, last, err)
			delays = append(delays, kind+" never")
		}
		assert.True(t, ok, "F15: the new file is served without a restart")

		bak, err := os.ReadFile(f.path(backupName(file, c.op)))
		require.NoError(t, err, "the backup of %s", c.op)
		assert.Equal(t, prevBytes, bak, "the backup holds the bytes replaced")
		_, err = os.Stat(f.path(".alice-" + c.op + ".tmp"))
		assert.ErrorIs(t, err, os.ErrNotExist, "no temporary file left")
		after := sddl(t, f.path(file))
		t.Logf("F15: ACL kept by ReplaceFileW (%d): %v", i+1, after == acl)
		assert.Equal(t, acl, after, "the file's ACL")
		prev = leaf
		prevBytes, err = os.ReadFile(f.path(file))
		require.NoError(t, err)
	}
	t.Logf("F15: verdict: %s", strings.Join(delays, "; "))

	got, err := served(f.addr(), "n.alice-w5.test")
	servedHidden := err == nil && len(got) > 0 && got[0] == sum256hex(hidden.Cert.Raw)
	t.Logf("F15: a .bak or .tmp file is served for its host: %v (answer %v, %v)", servedHidden, got, err)
	assert.False(t, servedHidden, "IIS never serves a .bak or .tmp file")
}

// ---- F16 ---------------------------------------------------------------------------------------------

// keyFiles lists the files of the machine and user key directories (CNG and the legacy CSPs).
func keyFiles(t *testing.T) map[string]bool {
	t.Helper()
	dirs := slices.Clone(machineKeyDirs)
	if appData := os.Getenv("APPDATA"); appData != "" {
		dirs = append(dirs, filepath.Join(appData, "Microsoft", "Crypto", "Keys"), filepath.Join(appData, "Microsoft", "Crypto", "RSA"))
	}
	out := map[string]bool{}
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				out[p] = true
			}
			return nil // a directory this image lacks, or one the token may not list
		})
	}
	return out
}

// logKeyProperties records which key properties PKCS12_NO_PERSIST_KEY gives the leaf (hasKey's
// question, F16).
func logKeyProperties(t *testing.T, pfx, password []byte) {
	t.Helper()
	pw := make([]uint16, len(password)+1)
	for i, c := range password {
		pw[i] = uint16(c)
	}
	blob := windows.CryptDataBlob{Size: uint32(len(pfx)), Data: &pfx[0]} //nolint:gosec // G115: a small file
	st, err := windows.PFXImportCertStore(&blob, &pw[0], windows.PKCS12_NO_PERSIST_KEY)
	runtime.KeepAlive(pfx)
	require.NoError(t, err)
	defer func() { _ = windows.CertCloseStore(st, 0) }()
	var prev *windows.CertContext
	for {
		c, _ := windows.CertEnumCertificatesInStore(st, prev)
		if c == nil {
			return
		}
		prev = c
		props := map[uint32]bool{}
		for _, id := range []uint32{certKeyProvInfoPropID, certKeyContextPropID, certNCryptKeyHandlePropID, certKeyHandlePropID} {
			_, _, found, err := contextProperty(c, id)
			props[id] = found && err == nil
		}
		t.Logf("F16: a PKCS12_NO_PERSIST_KEY certificate's key properties (2 prov info, 5 key context, 78 ncrypt handle, "+
			"79 either handle): %v; CNG key reachable: %v", props, keyReachable(c))
	}
}

// TestRealCCSWrongPasswordIsNotServed measures F16 (Review Focus 3): IIS serves a file BuildPFX wrote
// with the CCS password and does not serve one written with another; OpenPFX reports the second as a
// password mismatch and reads the first without leaving a key file.
func TestRealCCSWrongPasswordIsNotServed(t *testing.T) {
	f := newCCSReal(t, portCCSPassword, "good.alice-w5.test", "bad.alice-w5.test")
	now := time.Now()
	good := pki.SelfSigned("alice-w5-good.test", pki.RSA2048, now)
	bad := pki.SelfSigned("alice-w5-bad.test", pki.ECDSA256, now)
	other := winhelper.NewPFXPassword()
	goodPFX, badPFX := ccsPFX(t, good, f.password), ccsPFX(t, bad, other)
	f.put("good.alice-w5.test.pfx", goodPFX)
	f.put("bad.alice-w5.test.pfx", badPFX)
	f.requireServed("good.alice-w5.test", good.Cert)
	t.Logf("F16: IIS serves a file BuildPFX wrote with the CCS password (PBES2/AES-256-CBC, HMAC-SHA256 MAC, RSA key): true")

	_, ok, last, err := pickup(f.addr(), "bad.alice-w5.test", sum256hex(bad.Cert.Raw), 15*time.Second)
	t.Logf("F16: a file with another password is served: %v; the client sees %v, %v", ok, last, err)
	assert.False(t, ok, "a file IIS cannot open is never served")
	events, err := runPowershell(map[string]string{"ALICE_W5_SINCE": f.start.UTC().Format(time.RFC3339)},
		`$since = [DateTime]::Parse($env:ALICE_W5_SINCE, $null, [Globalization.DateTimeStyles]::RoundtripKind)
foreach ($log in @('Application', 'System')) {
    Get-WinEvent -FilterHashtable @{LogName = $log; StartTime = $since; Level = 1, 2, 3} -MaxEvents 30 -ErrorAction SilentlyContinue |
        ForEach-Object { $m = "$($_.Message)" -replace '\s+', ' '; if ($m.Length -gt 240) { $m = $m.Substring(0, 240) }
            "$log $($_.ProviderName) $($_.Id) $m" }
}`)
	require.NoError(t, err)
	if lines := strings.TrimSpace(string(events)); lines == "" {
		t.Logf("F16: no Application or System warning or error since the fixture")
	} else {
		for _, l := range strings.Split(lines, "\n") {
			t.Logf("F16: event %s", strings.TrimSpace(l))
		}
	}

	// The measured error of the import under another password, and PFXVerifyPassword's answer.
	pw := make([]uint16, len(f.password)+1)
	for i, c := range f.password {
		pw[i] = uint16(c)
	}
	blob := windows.CryptDataBlob{Size: uint32(len(badPFX)), Data: &badPFX[0]} //nolint:gosec // G115: a small file
	verified, _, _ := procPFXVerifyPassword.Call(uintptr(unsafe.Pointer(&blob)), uintptr(unsafe.Pointer(&pw[0])), 0)
	st, err := windows.PFXImportCertStore(&blob, &pw[0], windows.PKCS12_NO_PERSIST_KEY)
	runtime.KeepAlive(badPFX)
	if err == nil {
		_ = windows.CertCloseStore(st, 0)
	}
	var en windows.Errno
	_ = errors.As(err, &en)
	t.Logf("F16: PFXVerifyPassword with another password: %v; PFXImportCertStore: %v (code %d, 0x%08x)", verified != 0, err, uint32(en), uint32(en))
	require.Error(t, err, "the import refuses another password")
	_, _, problem, err := f.w.OpenPFX(badPFX, f.password)
	require.NoError(t, err)
	assert.Equal(t, winproto.CCSProblemPasswordMismatch, problem)

	// The right password: the leaf and no key file (machine and user key directories, by name).
	before := keyFiles(t)
	leaf, chain, problem, err := f.w.OpenPFX(goodPFX, f.password)
	afterFiles := keyFiles(t)
	require.NoError(t, err)
	assert.Empty(t, problem)
	assert.Equal(t, good.Cert.Raw, leaf)
	assert.Empty(t, chain)
	var left []string
	for p := range afterFiles {
		if !before[p] {
			left = append(left, p)
		}
	}
	t.Logf("F16: OpenPFX (PFXImportCertStore PKCS12_NO_PERSIST_KEY) left key files: %d %v (%d before)", len(left), left, len(before))
	logKeyProperties(t, goodPFX, f.password)
	assert.Empty(t, left, "PKCS12_NO_PERSIST_KEY leaves no key file")
	t.Logf("F16: machine key files created while IIS served the CCS files: %v", machineKeysSince(t, f.start))
}

// ---- F17 ---------------------------------------------------------------------------------------------

// servedLeaf is the leaf a fresh handshake is served ("" with the error).
func servedLeaf(addr, sni string) (string, error) {
	got, err := served(addr, sni)
	if err != nil || len(got) == 0 {
		return "", err
	}
	return got[0], nil
}

// TestRealCCSNameRules measures F17: the file IIS reads for SNI host h (h.pfx, then the one-label
// wildcard _.<parent>.pfx, names compared without case), and whether an explicit hostnameport record
// for h:port or the CCS file wins on the same port.
func TestRealCCSNameRules(t *testing.T) {
	f := newCCSReal(t, portCCSNames, "x.alice-w5.test", "exact.alice-w5.test", "up.alice-w5.test", "y.alice-w5.test", "a.b.alice-w5.test")
	now := time.Now()
	leaf := func(cn string) pki.Leaf { return pki.SelfSigned(cn, pki.ECDSA256, now) }
	wild, exact, upper, d := leaf("alice-w5-wild.test"), leaf("alice-w5-exact.test"), leaf("alice-w5-upper.test"), leaf("alice-w5-d.test")
	f.put("_.alice-w5.test.pfx", ccsPFX(t, wild, f.password))
	f.put("exact.alice-w5.test.pfx", ccsPFX(t, exact, f.password))
	f.put("UP.Alice-W5.Test.PFX", ccsPFX(t, upper, f.password))
	f.put("y.alice-w5.test.pfx", ccsPFX(t, d, f.password))

	_, ok, last, err := pickup(f.addr(), "x.alice-w5.test", sum256hex(wild.Cert.Raw), ccsPickupLimit)
	t.Logf("F17: _.alice-w5.test.pfx serves x.alice-w5.test: %v (last %v, %v)", ok, last, err)
	assert.True(t, ok, "the wildcard file serves a host one label below")
	_, ok, last, err = pickup(f.addr(), "exact.alice-w5.test", sum256hex(exact.Cert.Raw), 30*time.Second)
	t.Logf("F17: the exact file wins over the wildcard: %v (last %v, %v)", ok, last, err)
	assert.True(t, ok, "exact.alice-w5.test.pfx serves exact.alice-w5.test")
	_, ok, last, err = pickup(f.addr(), "up.alice-w5.test", sum256hex(upper.Cert.Raw), 30*time.Second)
	t.Logf("F17: the upper-case file UP.Alice-W5.Test.PFX serves up.alice-w5.test: %v (last %v, %v)", ok, last, err)
	assert.True(t, ok, "IIS compares file names without case")
	two, err := servedLeaf(f.addr(), "a.b.alice-w5.test")
	t.Logf("F17: _.alice-w5.test.pfx serves a.b.alice-w5.test (two labels below): %v (%q, %v)", two == sum256hex(wild.Cert.Raw), two, err)
	assert.NotEqual(t, sum256hex(wild.Cert.Raw), two, "a wildcard file covers one label only")

	// The helper's own lookups: the folder lists the name as spelled, ReadCCS finds it by the lower-case
	// name, and the spelling a deployment's ReplaceFileW leaves is recorded (the emulator keeps it).
	entries, err := f.w.ListCCS(context.Background(), f.folder)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	slices.Sort(names)
	assert.Equal(t, []string{"UP.Alice-W5.Test.PFX", "_.alice-w5.test.pfx", "exact.alice-w5.test.pfx", "y.alice-w5.test.pfx"}, names)
	data, found, err := f.w.ReadCCS(context.Background(), f.folder, "up.alice-w5.test.pfx", winproto.MaxCCSFile)
	t.Logf("F17: ReadCCS finds UP.Alice-W5.Test.PFX by up.alice-w5.test.pfx (Windows compares names without case): %v", found && err == nil)
	require.NoError(t, err)
	require.True(t, found)
	require.NotEmpty(t, data)
	upper2 := leaf("alice-w5-upper-2.test")
	f.deployReal(op1, "up.alice-w5.test", upper2, sum256hex(upper.Cert.Raw), winproto.PhaseCommitted)
	dir, err := os.ReadDir(f.folder)
	require.NoError(t, err)
	for _, e := range dir {
		if strings.EqualFold(e.Name(), "up.alice-w5.test.pfx") {
			t.Logf("F17: after ReplaceFileW over UP.Alice-W5.Test.PFX the file is spelled %q", e.Name())
		}
	}
	_, ok, _, _ = pickup(f.addr(), "up.alice-w5.test", sum256hex(upper2.Cert.Raw), ccsPickupLimit)
	assert.True(t, ok, "the deployment to the upper-case file is served")

	// Precedence on one port: a hostnameport record for y.alice-w5.test:45481 naming C, the CCS file D.
	c := leaf("alice-w5-c.test")
	addSSLCert(t, fmt.Sprintf("hostnameport=y.alice-w5.test:%d", f.port), importLeafWithKey(t, c), winproto.AppIDIIS)
	winner := "neither"
	var got string
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(ccsPoll) {
		got, err = servedLeaf(f.addr(), "y.alice-w5.test")
		if got == sum256hex(c.Cert.Raw) {
			winner = "hostnameport"
			break
		}
		if got == sum256hex(d.Cert.Raw) {
			winner = "ccs" // keep polling: the record may take effect a moment later
		}
	}
	t.Logf("F17: the winner on y.alice-w5.test:%d between a hostnameport record and a CCS file: %s (last %q, %v)", f.port, winner, got, err)
	assert.NotEqual(t, "neither", winner, "one of them is served")
}

// ---- F18 ---------------------------------------------------------------------------------------------

// TestRealCCSServedChain measures F18: the chain served for a CCS file, with the intermediate in the
// PFX and not in LocalMachine\CA, then with it in CA.
func TestRealCCSServedChain(t *testing.T) {
	f := newCCSReal(t, portCCSChain, "f18a.alice-w5.test", "f18b.alice-w5.test", "f18c.alice-w5.test")
	now := time.Now()
	ca := pki.NewCA("alice-w5-f18", pki.ECDSA256, now)
	issue := func(cn string) pki.Leaf { return ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, now) }
	a, b, c := issue("f18a.alice-w5.test"), issue("f18b.alice-w5.test"), issue("f18c.alice-w5.test")
	inter := sum256hex(ca.Intermediate.Raw)
	report := func(what string, chain []string) {
		t.Logf("F18: %s: served chain length %d (leaf included), the intermediate sent: %v", what, len(chain),
			len(chain) > 1 && chain[1] == inter)
	}
	f.put("f18a.alice-w5.test.pfx", ccsPFX(t, a, f.password, ca.Intermediate))
	f.put("f18b.alice-w5.test.pfx", ccsPFX(t, b, f.password))
	report("the intermediate in the PFX, not in CA", f.requireServed("f18a.alice-w5.test", a.Cert))
	report("the intermediate in neither", f.requireServed("f18b.alice-w5.test", b.Cert))

	importCertificate(t, "CA", ca.Intermediate)
	again, err := served(f.addr(), "f18a.alice-w5.test")
	require.NoError(t, err)
	report("the intermediate in the PFX and in CA (the file served before the import)", again)
	againB, err := served(f.addr(), "f18b.alice-w5.test")
	require.NoError(t, err)
	report("the intermediate in CA only (the file served before the import)", againB)
	f.put("f18c.alice-w5.test.pfx", ccsPFX(t, c, f.password))
	report("the intermediate in CA only (a file first served after the import)", f.requireServed("f18c.alice-w5.test", c.Cert))
}

// ---- Review Focus 1 ------------------------------------------------------------------------------

// dirState is every name in a directory with its bytes (a directory or a link as its kind).
func dirState(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	out := map[string]string{}
	for _, e := range entries {
		switch {
		case e.Type()&os.ModeSymlink != 0:
			out[e.Name()] = "link"
		case e.IsDir():
			out[e.Name()] = "dir"
		default:
			b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // the test's own folder
			require.NoError(t, err)
			out[e.Name()] = sum256hex(b)
		}
	}
	return out
}

// mklink runs cmd's mklink (args: /J for a junction, none for a file symbolic link).
func mklink(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("cmd", append([]string{"/c", "mklink"}, args...)...).CombinedOutput()
	require.NoError(t, err, "mklink %v: %s", args, out)
}

// setCCSRegistry writes CCS's Enabled and CertStoreLocation directly (the fixture's cleanup restores
// the whole key).
func setCCSRegistry(t *testing.T, enabled bool, path string) {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyCentralCert, registry.SET_VALUE|registry.WOW64_64KEY)
	require.NoError(t, err)
	defer func() { _ = k.Close() }()
	v := uint32(0)
	if enabled {
		v = 1
	}
	require.NoError(t, k.SetDWordValue("Enabled", v))
	require.NoError(t, k.SetStringValue("CertStoreLocation", path))
}

// TestRealCCSRefusesReparsePoints (Review Focus 1): a CCS folder that is a junction and a CCS file
// that is a symbolic link (or a directory) are refused, and nothing is written outside the folder.
func TestRealCCSRefusesReparsePoints(t *testing.T) {
	f := newCCSReal(t, portCCSReparse, "j.alice-w5.test", "s.alice-w5.test")
	ctx := context.Background()
	now := time.Now()
	outside := t.TempDir()
	j, s := pki.SelfSigned("alice-w5-j.test", pki.ECDSA256, now), pki.SelfSigned("alice-w5-s.test", pki.ECDSA256, now)
	require.NoError(t, os.WriteFile(filepath.Join(outside, "j.alice-w5.test.pfx"), ccsPFX(t, j, f.password), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "s-target.pfx"), ccsPFX(t, s, f.password), 0o600))
	before := dirState(t, outside)
	noJournal := func() {
		t.Helper()
		files, err := f.w.ListState("journal/")
		require.NoError(t, err)
		assert.Empty(t, files, "no journal was written")
	}
	deploy := func(host string, leaf pki.Leaf, expect string, path string) (winhelper.Outcome, map[string]any) {
		return execOn(t, f.w, f.ccsInput(host, leaf, expect, func(in *winproto.CCSDeployInput) { in.Path = path }),
			[]string{winproto.SubCCSDeploy, winproto.ArgOp, op1})
	}
	dump := func() winproto.CCSDumpResponse {
		var out bytes.Buffer
		o := winhelper.Execute(ctx, f.w, []string{winproto.SubCCSDump}, bytes.NewReader([]byte(`{"password":"`+string(f.password)+`"}`)), &out)
		require.Zero(t, o.Exit, "%s", out.String())
		var d winproto.CCSDumpResponse
		require.NoError(t, json.Unmarshal(out.Bytes(), &d))
		return d
	}

	// The folder is a junction to a directory outside.
	junction := f.folder + "-j"
	t.Cleanup(func() { _ = os.Remove(junction) }) // the junction only, never what it points to
	mklink(t, "/J", junction, outside)
	setCCSRegistry(t, true, junction)
	_, err := f.w.ListCCS(ctx, junction)
	assert.ErrorIs(t, err, winhelper.ErrCCSFolderUnsupported)
	d := dump()
	assert.False(t, d.Local, "%+v", d)
	assert.Empty(t, d.Files)
	o, got := deploy("j.alice-w5.test", pki.SelfSigned("alice-w5-j2.test", pki.ECDSA256, now), sum256hex(j.Cert.Raw), junction)
	assert.Equal(t, 3, o.Exit, "%v", got)
	assert.Equal(t, winproto.CodeCCSPathUnsupported, got["code"])
	noJournal()
	setCCSRegistry(t, true, f.folder)

	// The file is a symbolic link to a file outside; a directory carries a .pfx name.
	link := f.path("s.alice-w5.test.pfx")
	t.Cleanup(func() { _ = os.Remove(link) }) // the link only, before the folder
	mklink(t, link, filepath.Join(outside, "s-target.pfx"))
	require.NoError(t, os.Mkdir(f.path("d.alice-w5.test.pfx"), 0o700))
	entries, err := f.w.ListCCS(ctx, f.folder)
	require.NoError(t, err)
	assert.Empty(t, entries, "neither a link nor a directory is listed")
	for _, name := range []string{"s.alice-w5.test.pfx", "d.alice-w5.test.pfx"} {
		_, _, err := f.w.ReadCCS(ctx, f.folder, name, winproto.MaxCCSFile)
		assert.ErrorIs(t, err, winhelper.ErrCCSFileUnsupported, name)
	}
	d = dump()
	assert.True(t, d.Local)
	assert.Empty(t, d.Files)
	assert.False(t, d.Truncated)
	o, got = deploy("s.alice-w5.test", pki.SelfSigned("alice-w5-s2.test", pki.ECDSA256, now), sum256hex(s.Cert.Raw), f.folder)
	assert.Equal(t, 2, o.Exit, "%v", got)
	assert.Equal(t, winproto.CodeInvalidArgument, got["code"])
	noJournal()
	// A link named like a backup is not removed (nor followed); an absent temporary file is nil.
	bakLink := f.path("s.alice-w5.test.pfx.alice-11111111.bak")
	t.Cleanup(func() { _ = os.Remove(bakLink) })
	mklink(t, bakLink, filepath.Join(outside, "s-target.pfx"))
	assert.ErrorIs(t, f.w.RemoveCCS(ctx, f.folder, "s.alice-w5.test.pfx.alice-11111111.bak"), winhelper.ErrCCSFileUnsupported)
	assert.ErrorIs(t, f.w.RemoveCCS(ctx, f.folder, "s.alice-w5.test.pfx"), errBadValue, "a .pfx is never removed")
	require.NoError(t, f.w.RemoveCCS(ctx, f.folder, ".alice-"+op2+".tmp"))
	assert.ErrorIs(t, f.w.RestoreCCS(ctx, f.folder, "s.alice-w5.test.pfx.alice-11111111.bak", "s.alice-w5.test.pfx"),
		winhelper.ErrCCSFileUnsupported, "a link is never moved into a file's place")

	assert.Equal(t, before, dirState(t, outside), "nothing outside the folder changed")
	assert.Equal(t, map[string]string{"s.alice-w5.test.pfx": "link", "d.alice-w5.test.pfx": "dir",
		"s.alice-w5.test.pfx.alice-11111111.bak": "link"}, dirState(t, f.folder), "nothing written in the folder")
}
