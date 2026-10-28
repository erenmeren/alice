//go:build windows

package main

// The real RDP half (W6 Task 4, R69): with ALICE_WIN_REAL=1 on the runners, the facts F19-F23 of the
// W6 plan. Each test logs its verdicts as lines starting "F19: " to "F23: ", so the controller reads
// them from the job log.
//
// Fixtures (W6 Global Constraints "Real-Windows runs", Ruling 26): the listener stays on the port the
// image has (PortNumber, SecurityLayer and the policy key are never written). A fixture records
// fDenyTSConnections, UserAuthentication and SSLCertificateSHA1Hash before it changes anything and
// restores them as found when the test ends; it turns RDP on with fDenyTSConnections = 0 and, when the
// image has TermService stopped, starts it and stops it again at the end (never restarting a running
// one: that disconnects every session). http.sys fixtures use 45500-45519, certificates are named
// alice-w6-*, and every cleanup is registered before its fixture is made. The firewall is not touched
// (127.0.0.1 is not filtered). zz_runner_clean_windows_test.go checks that nothing is left.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

const (
	portW6Shared   = 45500 // TestRealRDPSharedWithBinding's ipport record and https site binding
	portW6SiteHTTP = 45519 // the plain http binding of the W6 fixture site
	firstW6SiteID  = 45500

	// rdpPickupLimit and rdpPoll are F20's measurement: fresh handshakes every 100 ms for up to 120 s.
	rdpPickupLimit = 120 * time.Second
	rdpPoll        = 100 * time.Millisecond
	// rdpListenWait is how long F19 waits for the listener to answer after RDP is turned on.
	rdpListenWait = 30 * time.Second

	// f4DACL is F4's DACL of a key the helper imported (design §14), as a DACL-only SDDL.
	f4DACL = "D:P(A;OICI;0xd01f01ff;;;SY)(A;OICI;0xd01f01ff;;;BA)"
)

// ---- the registry values the fixtures change -----------------------------------------------------

// rdpValues are the values an RDP fixture may write, as found: nil when absent.
type rdpValues struct {
	Deny, NLA *uint32
	Hash      []byte
}

func (v rdpValues) String() string {
	s := func(p *uint32) string {
		if p == nil {
			return "absent"
		}
		return strconv.FormatUint(uint64(*p), 10)
	}
	h := "absent"
	if v.Hash != nil {
		h = hex.EncodeToString(v.Hash)
	}
	return fmt.Sprintf("fDenyTSConnections=%s UserAuthentication=%s SSLCertificateSHA1Hash=%s", s(v.Deny), s(v.NLA), h)
}

// rdpAsFound are the values before the first RDP fixture of this binary changed anything (the clean
// check compares with them).
var (
	rdpAsFoundOnce sync.Once
	rdpAsFound     rdpValues
	rdpAsFoundErr  error
	rdpAsFoundSet  bool
)

func rawDword(path, name string) (*uint32, error) {
	k, err := openKey(path)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = k.Close() }()
	v, typ, err := k.GetIntegerValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if typ != registry.DWORD {
		return nil, fmt.Errorf("%s\\%s has type %d", path, name, typ)
	}
	u := uint32(v) //nolint:gosec // G115: a DWORD
	return &u, nil
}

func rawBinary(path, name string) ([]byte, error) {
	k, err := openKey(path)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetBinaryValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	return v, err
}

// setRaw writes a DWORD (u) or a binary value (b), or deletes the value when both are nil.
func setRaw(path, name string, u *uint32, b []byte) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	switch {
	case u != nil:
		return k.SetDWordValue(name, *u)
	case b != nil:
		return k.SetBinaryValue(name, b)
	}
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func readRDPValues() (rdpValues, error) {
	var v rdpValues
	var err error
	if v.Deny, err = rawDword(keyTerminalServer, valueRDPDeny); err != nil {
		return v, err
	}
	if v.NLA, err = rawDword(keyRDPTcp, valueRDPNLA); err != nil {
		return v, err
	}
	v.Hash, err = rawBinary(keyRDPTcp, valueRDPHash)
	return v, err
}

// restoreRDPValues writes the values back as found (deleting those that were absent).
func restoreRDPValues(logf func(string, ...any), v rdpValues) {
	for _, w := range []struct {
		path, name string
		u          *uint32
		b          []byte
	}{{keyRDPTcp, valueRDPHash, nil, v.Hash}, {keyRDPTcp, valueRDPNLA, v.NLA, nil}, {keyTerminalServer, valueRDPDeny, v.Deny, nil}} {
		if err := setRaw(w.path, w.name, w.u, w.b); err != nil {
			logf("cleanup: restoring %s\\%s: %v", w.path, w.name, err)
		}
	}
}

func u32(v uint32) *uint32 { return &v }

// ---- the fixture ----------------------------------------------------------------------------------

// rdpFixture is the real listener turned on, with a helper host on a private data directory.
type rdpFixture struct {
	t     *testing.T
	h     host
	ctx   context.Context
	port  int
	found rdpValues
	start time.Time
}

// newRDPFixture records the values and TermService's state, registers their restore, starts
// TermService when it is stopped, turns RDP on and waits until the listener answers the negotiation.
func newRDPFixture(t *testing.T) *rdpFixture {
	t.Helper()
	requireReal(t)
	rdpAsFoundOnce.Do(func() { rdpAsFound, rdpAsFoundErr = readRDPValues(); rdpAsFoundSet = true })
	require.NoError(t, rdpAsFoundErr)
	found, err := readRDPValues()
	require.NoError(t, err)
	t.Logf("RDP values found: %s", found)
	t.Cleanup(func() { restoreRDPValues(t.Logf, found) })
	f := &rdpFixture{t: t, ctx: context.Background(), found: found, start: time.Now()}
	f.h = newHost(newTestDataDir(t))

	state := strings.TrimSpace(string(powershell(t, `$s = Get-Service -Name TermService; "$($s.Status) $($s.StartType)"`)))
	t.Logf("F19: TermService found %s", state)
	if strings.HasPrefix(state, "Stopped") {
		t.Cleanup(func() {
			if out, err := runPowershell(nil, `Stop-Service -Name TermService -Force`); err != nil {
				t.Logf("cleanup: stopping TermService: %v %s", err, out)
			}
		})
		powershell(t, `Start-Service -Name TermService`)
		t.Logf("F19: TermService was stopped: started for this test, stopped again at its end")
	}

	l, err := f.h.RDPListener(f.ctx)
	require.NoError(t, err)
	require.True(t, l.Present, "the image has the RDP-Tcp listener key")
	f.port = l.Port
	if found.Deny == nil || *found.Deny != 0 {
		require.NoError(t, setRaw(keyTerminalServer, valueRDPDeny, u32(0), nil), "turning RDP on")
	}
	start := time.Now()
	var sel uint32
	for time.Since(start) < rdpListenWait {
		if sel, err = negotiateOnly(f.addr()); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	require.NoError(t, err, "F19: the listener answers the negotiation on %s within %v of RDP turned on", f.addr(), rdpListenWait)
	t.Logf("F19: %s answers the negotiation %v after fDenyTSConnections=0 (selectedProtocol %d)", f.addr(),
		time.Since(start).Round(time.Millisecond), sel)
	return f
}

func (f *rdpFixture) addr() string { return "127.0.0.1:" + strconv.Itoa(f.port) }

// call runs one helper call on the fixture's host and requires an answer.
func (f *rdpFixture) call(stdin []byte, args ...string) map[string]any {
	f.t.Helper()
	_, got := execOn(f.t, f.h, stdin, args)
	require.NotNil(f.t, got, "the helper answers %v", args)
	return got
}

func (f *rdpFixture) dump() map[string]any {
	f.t.Helper()
	d := f.call(nil, winproto.SubRDPDump)
	require.Equal(f.t, true, d["ok"], "rdp-dump: %v", d)
	return d
}

// probe is the helper's own tls-probe --rdp of the listener.
func (f *rdpFixture) probe() map[string]any {
	f.t.Helper()
	return f.call(nil, winproto.SubTLSProbe, "--addr", "127.0.0.1", "--port", strconv.Itoa(f.port), "--sni", helperproto.NoSNI,
		"--key-type", helperproto.ProbeAny, winproto.ArgRDP)
}

// dumpCert is the dump's current certificate.
func dumpCert(t *testing.T, d map[string]any) map[string]any {
	t.Helper()
	c, ok := d["certificate"].(map[string]any)
	require.True(t, ok, "rdp-dump names a current certificate: %v", d)
	return c
}

// setValue writes SSLCertificateSHA1Hash through the helper's own host method ("" deletes it).
func (f *rdpFixture) setValue(sha1 string) {
	f.t.Helper()
	require.NoError(f.t, f.h.SetRDPCertificate(f.ctx, sha1))
}

// importInto imports a leaf with its key into a machine store through the helper's own ImportPFX (F4's DACL) and
// removes both when the test ends (registered first). It returns the thumbprint.
func (f *rdpFixture) importInto(store string, leaf pki.Leaf) string {
	f.t.Helper()
	thumb := thumbprint(leaf.Cert)
	f.t.Cleanup(func() { removeCertificate(f.t, store, thumb, true) })
	pkcs8, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
	require.NoError(f.t, err)
	password := winhelper.NewPFXPassword()
	pfx, err := winhelper.BuildPFX(leaf.Cert.Raw, pkcs8, password)
	require.NoError(f.t, err)
	sha, existed, err := f.h.ImportPFX(f.ctx, store, pfx, password, leaf.Cert.Subject.CommonName)
	require.NoError(f.t, err)
	require.Equal(f.t, thumb, sha)
	require.False(f.t, existed)
	return thumb
}

// keySDDL is the SDDL of the key of a store's certificate: DACL only (as the helper reads and writes
// it) and, for the log, with owner and group.
func keySDDL(t *testing.T, store, thumb string) (dacl, full string) {
	t.Helper()
	require.NoError(t, withStoreKey(store, thumb, func(key windows.Handle) error {
		sd, keep, err := keyDACL(key)
		if err != nil {
			return err
		}
		dacl = sd.String()
		runtime.KeepAlive(keep)
		buf, _, ok := ncryptProperty(key, ncryptSecurityDescrProp, daclSecurityInformation|
			windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION)
		if ok {
			// unsafe: buf holds the self-relative descriptor NCryptGetProperty wrote.
			full = (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buf[0])).String()
			runtime.KeepAlive(buf)
		}
		return nil
	}))
	return dacl, full
}

// addACE appends one ACE of this mode and mask for a well-known SID to a key's DACL (a fixture: the
// helper's own splice, with what Ruling 10 never writes).
func addACE(t *testing.T, store, thumb string, mode windows.ACCESS_MODE, mask uint32, who windows.WELL_KNOWN_SID_TYPE) {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(who)
	require.NoError(t, err)
	ace, err := explicitACE(mode, mask, sid)
	require.NoError(t, err)
	require.NoError(t, withStoreKey(store, thumb, func(key windows.Handle) error { return editKeyDACL(key, nil, ace) }))
}

// ---- probes ------------------------------------------------------------------------------------------

// recorder keeps the bytes read from a connection.
type recorder struct {
	net.Conn
	got bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.got.Write(p[:n])
	return n, err
}

// negotiateOnly dials the listener and runs the negotiation alone.
func negotiateOnly(addr string) (uint32, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return helperproto.RDPNegotiate(conn)
}

// rdpHandshake is one fresh connection: the negotiation (its raw answer kept), then a TLS handshake;
// chain is the DER SHA-256 of each certificate served, leaf first. Nothing follows the handshake.
func rdpHandshake(addr string) (chain []string, selected uint32, confirm []byte, err error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, 0, nil, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	rec := &recorder{Conn: c}
	selected, err = helperproto.RDPNegotiate(rec)
	confirm = rec.got.Bytes()
	if err != nil {
		return nil, selected, confirm, err
	}
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // G402: the test compares what is served
	if err := tc.Handshake(); err != nil {
		return nil, selected, confirm, err
	}
	for _, pc := range tc.ConnectionState().PeerCertificates {
		chain = append(chain, sum256hex(pc.Raw))
	}
	return chain, selected, confirm, nil
}

// rdpPickup polls fresh handshakes every rdpPoll for up to limit until the leaf want is served (and,
// with chainLen > 0, a chain of that length): how long it took, whether it was, the last chain and error.
func rdpPickup(addr, want string, chainLen int, limit time.Duration) (time.Duration, bool, []string, error) {
	start := time.Now()
	var last []string
	var err error
	for time.Since(start) < limit {
		if last, _, _, err = rdpHandshake(addr); err == nil && len(last) > 0 && last[0] == want && (chainLen == 0 || len(last) == chainLen) {
			return time.Since(start), true, last, nil
		}
		time.Sleep(rdpPoll)
	}
	return time.Since(start), false, last, err
}

// requirePickup is rdpPickup that must succeed; it logs the delay under fact.
func (f *rdpFixture) requirePickup(fact, what, want string) []string {
	f.t.Helper()
	d, ok, last, err := rdpPickup(f.addr(), want, 0, rdpPickupLimit)
	f.t.Logf("%s: %s: served %v after %d ms (chain length %d, last error %v)", fact, what, ok, d.Milliseconds(), len(last), err)
	require.True(f.t, ok, "%s: %s is served within %v (last %v, %v)", fact, what, rdpPickupLimit, last, err)
	return last
}

// logEvents logs System and Application events of these providers and ids since since.
func logEvents(t *testing.T, fact string, since time.Time, log string, ids ...int) {
	t.Helper()
	list := make([]string, len(ids))
	for i, id := range ids {
		list[i] = strconv.Itoa(id)
	}
	out, err := runPowershell(map[string]string{"ALICE_W6_SINCE": since.UTC().Format(time.RFC3339), "ALICE_W6_LOG": log,
		"ALICE_W6_IDS": strings.Join(list, ",")},
		`$since = [DateTime]::Parse($env:ALICE_W6_SINCE, $null, [Globalization.DateTimeStyles]::RoundtripKind)
$ids = @($env:ALICE_W6_IDS -split ',' | ForEach-Object { [int]$_ })
@(Get-WinEvent -FilterHashtable @{LogName = $env:ALICE_W6_LOG; StartTime = $since; Id = $ids} -MaxEvents 30 -ErrorAction SilentlyContinue) |
    ForEach-Object { $m = "$($_.Message)" -replace '\s+', ' '; if ($m.Length -gt 300) { $m = $m.Substring(0, 300) }
        "$($_.TimeCreated.ToString('o')) $($_.ProviderName) $($_.Id) $m" }`)
	if err != nil {
		t.Logf("%s: reading the %s log failed: %v", fact, log, err)
		return
	}
	lines := strings.TrimSpace(string(out))
	if lines == "" {
		t.Logf("%s: no %s event %v since %s", fact, log, ids, since.UTC().Format(time.RFC3339))
		return
	}
	for _, l := range strings.Split(lines, "\n") {
		t.Logf("%s: %s event %s", fact, log, strings.TrimSpace(l))
	}
}

// tsGeneralSetting is what WMI's Win32_TSGeneralSetting reports for RDP-Tcp (tests only).
func tsGeneralSetting(t *testing.T) string {
	t.Helper()
	out, err := runPowershell(nil, `$s = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'"
"SSLCertificateSHA1Hash=$($s.SSLCertificateSHA1Hash) SSLCertificateSHA1HashType=$($s.SSLCertificateSHA1HashType) SecurityLayer=$($s.SecurityLayer) UserAuthenticationRequired=$($s.UserAuthenticationRequired) CertificateName=$($s.CertificateName)"`)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	return strings.TrimSpace(string(out))
}

func rdpDeployInput(t *testing.T, chainPEM, keyPEM []byte, expect string) []byte {
	t.Helper()
	b, err := json.Marshal(winproto.RDPDeployInput{ExpectSHA256: expect, ChainPEM: string(chainPEM), KeyPEM: string(keyPEM),
		ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}})
	require.NoError(t, err)
	return b
}

// removeChainLater removes a chain's leaf (with its key) from My and its intermediates from CA when the
// test ends.
func removeChainLater(t *testing.T, leaf pki.Leaf, ca *pki.CA) {
	t.Helper()
	leafThumb, interThumb := thumbprint(leaf.Cert), thumbprint(ca.Intermediate)
	t.Cleanup(func() { removeCertificate(t, "CA", interThumb, false) })
	t.Cleanup(func() { removeCertificate(t, "My", leafThumb, true) })
}

// ---- F19 ---------------------------------------------------------------------------------------------

// logRDPImage logs the image's RDP settings as PowerShell reads them, before any fixture.
func logRDPImage(t *testing.T) {
	t.Helper()
	out, err := runPowershell(nil, `$ts = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$l = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$h = 'absent'; if ($l.PSObject.Properties['SSLCertificateSHA1Hash']) { $h = (($l.SSLCertificateSHA1Hash | ForEach-Object { $_.ToString('x2') }) -join '') }
"values fDenyTSConnections=$($ts.fDenyTSConnections) PortNumber=$($l.PortNumber) SecurityLayer=$($l.SecurityLayer) UserAuthentication=$($l.UserAuthentication) MinEncryptionLevel=$($l.MinEncryptionLevel) SSLCertificateSHA1Hash=$h"
$p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
if (Test-Path -LiteralPath $p) {
    $v = @((Get-ItemProperty -LiteralPath $p).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Name)=$($_.Value)" })
    "policy key present: $($v -join ' ')"
} else { 'policy key absent' }
$s = 'Cert:\LocalMachine\Remote Desktop'
if (Test-Path -LiteralPath $s) {
    $c = @(Get-ChildItem -LiteralPath $s)
    "Remote Desktop store: $($c.Count) certificate(s)"
    foreach ($x in $c) { "Remote Desktop $($x.Thumbprint) $($x.Subject) notafter $($x.NotAfter.ToString('o')) key $($x.HasPrivateKey)" }
} else { 'Remote Desktop store absent' }
foreach ($f in Get-NetFirewallProfile) { "firewall profile $($f.Name) enabled $($f.Enabled)" }
foreach ($r in @(Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue)) { "firewall rule $($r.DisplayName) enabled $($r.Enabled) action $($r.Action)" }
$svc = Get-CimInstance Win32_Service -Filter "Name='TermService'"
"TermService state $($svc.State) start $($svc.StartMode) account $($svc.StartName)"`)
	require.NoError(t, err)
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		t.Logf("F19: %s", strings.TrimSpace(l))
	}
}

// remoteDesktopThumbs lists LocalMachine\Remote Desktop by PowerShell (lower case).
func remoteDesktopThumbs(t *testing.T) []string {
	t.Helper()
	out := powershell(t, `$s = 'Cert:\LocalMachine\Remote Desktop'; if (Test-Path -LiteralPath $s) { Get-ChildItem -LiteralPath $s | ForEach-Object { $_.Thumbprint.ToLowerInvariant() } }`)
	return strings.Fields(string(out))
}

// TestRealRDPListenerOnRunner measures F19: RDP turned on by fDenyTSConnections alone answers on
// 127.0.0.1:<PortNumber>, and the leaf it serves while SSLCertificateSHA1Hash is absent is the single
// certificate of LocalMachine\Remote Desktop (rdp-dump's current certificate).
func TestRealRDPListenerOnRunner(t *testing.T) {
	requireReal(t)
	logRDPImage(t)
	f := newRDPFixture(t)
	l, err := f.h.RDPListener(f.ctx)
	require.NoError(t, err)
	t.Logf("F19: the helper reads %+v", l)
	assert.True(t, l.Enabled, "RDP is on")

	d := f.dump()
	t.Logf("F19: rdp-dump present %v enabled %v nla %v value_set %v port %v security_layer %v cert_template %q self_signed_count %v",
		d["present"], d["enabled"], d["nla"], d["value_set"], d["port"], d["security_layer"], d["cert_template"], d["self_signed_count"])
	thumbs := remoteDesktopThumbs(t)
	t.Logf("F19: Remote Desktop holds %d certificate(s) after the listener answered: %v", len(thumbs), thumbs)
	p := f.probe()
	t.Logf("F19: tls-probe --rdp: ok %v leaf %v chain_length %v not_after %v", p["ok"], p["leaf_sha256"], p["chain_length"], p["not_after"])
	require.Equal(t, true, p["ok"], "tls-probe --rdp answers: %v", p)
	chain, sel, confirm, err := rdpHandshake(f.addr())
	require.NoError(t, err)
	require.NotEmpty(t, chain)
	t.Logf("F19: a fresh handshake: selectedProtocol %d, confirm % x, chain %v", sel, confirm, chain)
	assert.Equal(t, p["leaf_sha256"], chain[0], "the helper's probe and the test's handshake see one leaf")

	if d["value_set"] == true {
		t.Logf("F19: SSLCertificateSHA1Hash is set on this image; the self-signed half is not measured")
		return
	}
	c := dumpCert(t, d)
	assert.Equal(t, winproto.RDPStoreSelfSigned, c["store"])
	assert.Equal(t, float64(1), d["self_signed_count"], "one certificate in Remote Desktop")
	assert.Equal(t, []string{asString(c["sha1"])}, thumbs, "the dump's certificate is the store's single one, as PowerShell lists it")
	same := c["sha256"] == p["leaf_sha256"]
	t.Logf("F19: the served leaf is the dump's (Remote Desktop's single certificate): %v", same)
	assert.True(t, same, "F19: while the value is absent the listener serves Remote Desktop's single certificate (Ruling 4)")
	if !t.Failed() {
		t.Logf("F19 verdict: confirmed: fDenyTSConnections=0 alone turns RDP on (no restart); %s answers; the self-signed leaf served is Remote Desktop's single certificate %s",
			f.addr(), c["sha1"])
	}
}

// ---- F20 ---------------------------------------------------------------------------------------------

// TestRealRDPDeployIsPickedUp measures F20: rdp-deploy's raw registry write is served at a fresh
// handshake (the delay logged), and iis-restore's delete serves the self-signed leaf again; the served
// chain against built_chain_length; what Win32_TSGeneralSetting reports; whether a same-value rewrite
// rebuilds the served chain (Ruling 14); and whether a certificate only in Remote Desktop is served
// when named.
func TestRealRDPDeployIsPickedUp(t *testing.T) {
	f := newRDPFixture(t)
	d := f.dump()
	self := dumpCert(t, d)
	selfSHA256 := asString(self["sha256"])
	t.Logf("F20: Win32_TSGeneralSetting before: %s", tsGeneralSetting(t))

	// (1) rdp-deploy, then its rollback.
	ca := fixtureCA("alice-w6-f20")
	leaf := issue(ca, "alice-w6-f20.test")
	removeChainLater(t, leaf, ca)
	got := f.call(rdpDeployInput(t, leaf.FullchainPEM, leaf.KeyPEM, selfSHA256), winproto.SubRDPDeploy, winproto.ArgOp, op1)
	assertPhase(t, got, winproto.PhaseCommitted)
	t.Logf("F20: rdp-deploy: phase %v steps %v alice_imported %v built_chain_length %v", got["phase"], got["steps"], got["alice_imported"],
		got["built_chain_length"])
	served := f.requirePickup("F20", "the deployed certificate after rdp-deploy", sum256hex(leaf.Cert.Raw))
	t.Logf("F20: served chain length %d, built_chain_length %v", len(served), got["built_chain_length"])
	t.Logf("F20: Win32_TSGeneralSetting after rdp-deploy: %s", tsGeneralSetting(t))
	after := f.dump()
	assert.Equal(t, true, after["value_set"])
	assert.Equal(t, sum256hex(leaf.Cert.Raw), dumpCert(t, after)["sha256"], "rdp-dump names the deployed certificate")

	restored := f.call(restoreInput(t), winproto.SubIISRestore, winproto.ArgOp, op1)
	t.Logf("F20: iis-restore: %v", restored)
	assertPhase(t, restored, winproto.PhaseRestored)
	v, err := rawBinary(keyRDPTcp, valueRDPHash)
	require.NoError(t, err)
	assert.Nil(t, v, "the rollback deletes the value")
	f.requirePickup("F20", "the self-signed certificate after iis-restore", selfSHA256)
	t.Logf("F20: Win32_TSGeneralSetting after iis-restore: %s", tsGeneralSetting(t))

	// (2) Ruling 14: does a same-value rewrite rebuild the served chain? A leaf whose intermediate is
	// not in CA is served alone; the intermediate is added; the chain served is read before and after a
	// same-value rewrite.
	ca2 := fixtureCA("alice-w6-f20b")
	leaf2 := issue(ca2, "alice-w6-f20b.test")
	inter2 := thumbprint(ca2.Intermediate)
	t.Cleanup(func() { removeCertificate(t, "CA", inter2, false) })
	thumb2 := f.importInto("My", leaf2)
	require.NoError(t, f.h.SetRDPKeyRead(f.ctx, "MY", thumb2, true))
	f.setValue(thumb2)
	first := f.requirePickup("F20", "a leaf without its intermediate in CA", sum256hex(leaf2.Cert.Raw))
	t.Logf("F20: chain served without the intermediate in CA: %d", len(first))
	added, err := f.h.AddIntermediate(f.ctx, ca2.Intermediate.Raw)
	require.NoError(t, err)
	require.True(t, added)
	time.Sleep(5 * time.Second)
	noRewrite, _, _, err := rdpHandshake(f.addr())
	require.NoError(t, err)
	t.Logf("F20: chain served 5 s after the intermediate was added, without a rewrite: %d", len(noRewrite))
	f.setValue(thumb2)
	dd, rebuilt, last, err := rdpPickup(f.addr(), sum256hex(leaf2.Cert.Raw), 2, 20*time.Second)
	t.Logf("F20: a same-value rewrite of SSLCertificateSHA1Hash rebuilds the served chain: %v (after %d ms; last chain %d, %v)",
		rebuilt, dd.Milliseconds(), len(last), err)
	f.setValue("")
	f.requirePickup("F20", "the self-signed certificate after the value was deleted", selfSHA256)

	// (3) A certificate only in Remote Desktop (not My), named by the value, with NETWORK SERVICE's
	// read access (the helper's own ACE splice: SetRDPKeyRead refuses that store).
	leaf3 := pki.SelfSigned("alice-w6-f20c.test", pki.ECDSA256, time.Now())
	thumb3 := f.importInto(winproto.RDPStoreSelfSigned, leaf3)
	ns, err := windows.CreateWellKnownSid(windows.WinNetworkServiceSid)
	require.NoError(t, err)
	ace, err := explicitACE(windows.GRANT_ACCESS, rdpGrantMask, ns)
	require.NoError(t, err)
	require.NoError(t, withStoreKey(winproto.RDPStoreSelfSigned, thumb3, func(k windows.Handle) error { return editKeyDACL(k, nil, ace) }))
	f.setValue(thumb3)
	d3, ok3, last3, err := rdpPickup(f.addr(), sum256hex(leaf3.Cert.Raw), 0, 20*time.Second)
	servedSelf := len(last3) > 0 && last3[0] == selfSHA256
	t.Logf("F20: a certificate only in Remote Desktop is served when named: %v (after %d ms; else the self-signed one served: %v; %v)",
		ok3, d3.Milliseconds(), servedSelf, err)
	t.Logf("F20: Win32_TSGeneralSetting naming a Remote Desktop certificate: %s", tsGeneralSetting(t))
	f.setValue("")
	f.requirePickup("F20", "the self-signed certificate again", selfSHA256)
	if !t.Failed() {
		t.Logf("F20 verdict: route (a) applies when the delays above are under 10 s; a raw write and a delete are served at fresh handshakes without a restart")
	}
}

// ---- F21 ---------------------------------------------------------------------------------------------

// TestRealRDPKeyReadForNetworkService measures F21 (Review Focus 1, 2): a certificate whose key has
// F4's DACL is not usable by the listener; Ruling 10's ACE makes it so; the revoke gives F4's DACL back
// byte for byte, keeps every other NETWORK SERVICE ACE, and the key stays not exportable.
func TestRealRDPKeyReadForNetworkService(t *testing.T) {
	f := newRDPFixture(t)
	selfSHA256 := asString(dumpCert(t, f.dump())["sha256"])
	leaf := pki.SelfSigned("alice-w6-f21.test", pki.ECDSA256, time.Now())
	want := sum256hex(leaf.Cert.Raw)
	thumb := f.importInto("My", leaf)
	imported, full := keySDDL(t, "My", thumb)
	t.Logf("F21: the key's SDDL as imported: %s (DACL %s; F4's DACL: %v)", full, imported, imported == f4DACL)
	readable, err := f.h.RDPKeyRead(f.ctx, "MY", thumb)
	require.NoError(t, err)
	assert.False(t, readable, "F4's DACL gives NETWORK SERVICE no read")

	// Named without the grant.
	since := time.Now().Add(-time.Minute)
	f.setValue(thumb)
	d, ok, last, herr := rdpPickup(f.addr(), want, 0, 20*time.Second)
	servedSelf := len(last) > 0 && last[0] == selfSHA256
	t.Logf("F21: without the grant the certificate is served: %v (after %d ms); the last handshake: chain %v (the self-signed one: %v), error %v",
		ok, d.Milliseconds(), last, servedSelf, herr)
	logEvents(t, "F21", since, "System", 36870, 36874, 36888)
	if ok {
		t.Logf("F21: STOP: the handshake succeeded without the grant; TermService account and the key's SDDL follow")
		t.Logf("F21: key SDDL as imported %s", full)
		out, _ := runPowershell(nil, `sc.exe qc TermService; (Get-CimInstance Win32_Service -Filter "Name='TermService'").StartName`)
		t.Logf("F21: TermService: %s", strings.Join(strings.Fields(string(out)), " "))
	}
	assert.False(t, ok, "F21: without NETWORK SERVICE's read the listener does not serve the certificate")

	// The grant.
	require.NoError(t, f.h.SetRDPKeyRead(f.ctx, "MY", thumb, true))
	granted, grantedFull := keySDDL(t, "My", thumb)
	t.Logf("F21: the key's SDDL after the grant: %s (DACL %s)", grantedFull, granted)
	assert.Equal(t, imported+"(A;;GR;;;NS)", granted, "Ruling 10's one ACE appended")
	readable, err = f.h.RDPKeyRead(f.ctx, "MY", thumb)
	require.NoError(t, err)
	assert.True(t, readable, "the helper's has-read test matches the grant")
	assert.True(t, exportRefused(t, "My", thumb), "F21: the granted key stays not exportable")
	d, ok, _, herr = rdpPickup(f.addr(), want, 0, 30*time.Second)
	t.Logf("F21: after the grant, without a rewrite, the certificate is served: %v (after %d ms, %v)", ok, d.Milliseconds(), herr)
	if !ok {
		f.setValue(thumb)
		f.requirePickup("F21", "the certificate after the grant and a same-value rewrite", want)
	}

	// The revoke.
	f.setValue("")
	require.NoError(t, f.h.SetRDPKeyRead(f.ctx, "MY", thumb, false))
	revoked, _ := keySDDL(t, "My", thumb)
	t.Logf("F21: the key's SDDL after the revoke: %s", revoked)
	assert.Equal(t, imported, revoked, "F21: the revoke gives the DACL as imported back byte for byte")
	readable, err = f.h.RDPKeyRead(f.ctx, "MY", thumb)
	require.NoError(t, err)
	assert.False(t, readable)
	assert.True(t, exportRefused(t, "My", thumb), "F21: the key stays not exportable")

	// Coordinator precision 3: NETWORK SERVICE ACEs of another kind or mask survive a grant and revoke.
	leaf2 := pki.SelfSigned("alice-w6-f21b.test", pki.ECDSA256, time.Now())
	thumb2 := f.importInto("My", leaf2)
	addACE(t, "My", thumb2, windows.DENY_ACCESS, windows.GENERIC_WRITE, windows.WinNetworkServiceSid)
	addACE(t, "My", thumb2, windows.GRANT_ACCESS, 0x1, windows.WinNetworkServiceSid)
	before, _ := keySDDL(t, "My", thumb2)
	t.Logf("F21: a key with NETWORK SERVICE ACEs of its own: %s", before)
	readable, err = f.h.RDPKeyRead(f.ctx, "MY", thumb2)
	require.NoError(t, err)
	assert.False(t, readable, "an allow ACE without the read bits is no read")
	require.NoError(t, f.h.SetRDPKeyRead(f.ctx, "MY", thumb2, true))
	mid, _ := keySDDL(t, "My", thumb2)
	t.Logf("F21: after the grant: %s", mid)
	require.NoError(t, f.h.SetRDPKeyRead(f.ctx, "MY", thumb2, false))
	end, _ := keySDDL(t, "My", thumb2)
	t.Logf("F21: after the revoke: %s", end)
	assert.Equal(t, before, end, "F21: the revoke removes only the grant's ACE; the deny ACE and the other mask stay")

	// The key methods refuse another store.
	_, err = f.h.RDPKeyRead(f.ctx, winproto.RDPStoreSelfSigned, asString(dumpCert(t, f.dump())["sha1"]))
	assert.ErrorIs(t, err, errRDPStore)
	assert.ErrorIs(t, f.h.SetRDPKeyRead(f.ctx, winproto.RDPStoreSelfSigned, thumb, true), errRDPStore)
	if !t.Failed() {
		t.Logf("F21 verdict: confirmed: F4's DACL is not served; (A;;GR;;;NS) is; the revoke gives F4's DACL back and keeps other ACEs; NCryptExportKey still refused")
	}
}

// ---- F22, F23 ------------------------------------------------------------------------------------------

// TestRealRDPNegotiation measures F22 (the confirm bytes with NLA on and off; SecurityLayer is never
// written, Global Constraints) and F23 (with NLA on the TLS handshake completes before CredSSP, and ten
// probes leave no failed logon, Security 4625).
func TestRealRDPNegotiation(t *testing.T) {
	f := newRDPFixture(t)
	if out, err := runPowershell(nil, `auditpol.exe /get /subcategory:"Logon"`); err == nil {
		t.Logf("F23: audit policy: %s", strings.Join(strings.Fields(string(out)), " "))
	} else {
		t.Logf("F23: auditpol failed: %v", err)
	}
	for _, nla := range []uint32{1, 0} {
		require.NoError(t, setRaw(keyRDPTcp, valueRDPNLA, u32(nla), nil))
		l, err := f.h.RDPListener(f.ctx)
		require.NoError(t, err)
		require.Equal(t, nla == 1, l.NLA)
		time.Sleep(time.Second)
		chain, sel, confirm, err := rdpHandshake(f.addr())
		t.Logf("F22: UserAuthentication=%d: confirm (%d bytes) % x, selectedProtocol %d, TLS handshake %v, chain length %d",
			nla, len(confirm), confirm, sel, err, len(chain))
		require.NoError(t, err, "F22/F23: the TLS handshake completes with UserAuthentication=%d", nla)
		assert.Len(t, confirm, 19, "F22: a 19-byte Connection Confirm")
		if len(confirm) == 19 {
			assert.Equal(t, byte(0x02), confirm[11], "F22: RDP_NEG_RSP")
		}
		assert.Contains(t, []uint32{1, 2}, sel, "F22: TLS or CredSSP selected")
		p := f.probe()
		assert.Equal(t, true, p["ok"], "tls-probe --rdp with UserAuthentication=%d: %v", nla, p)
	}
	t.Logf("F22: SecurityLayer 0 is not measured: the tests never write SecurityLayer (Global Constraints)")

	require.NoError(t, setRaw(keyRDPTcp, valueRDPNLA, u32(1), nil))
	time.Sleep(time.Second)
	since := time.Now()
	for i := range 10 {
		_, _, _, err := rdpHandshake(f.addr())
		require.NoError(t, err, "probe %d with NLA on", i+1)
	}
	time.Sleep(3 * time.Second)
	out, err := runPowershell(map[string]string{"ALICE_W6_SINCE": since.Add(-time.Second).UTC().Format(time.RFC3339)},
		`$since = [DateTime]::Parse($env:ALICE_W6_SINCE, $null, [Globalization.DateTimeStyles]::RoundtripKind)
@(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4625; StartTime = $since} -ErrorAction SilentlyContinue).Count`)
	require.NoError(t, err)
	n := strings.TrimSpace(string(out))
	t.Logf("F23: Security 4625 events after ten probes with NLA on: %s", n)
	assert.Equal(t, "0", n, "F23: a probe leaves no failed logon")
	logEvents(t, "F23", since, "Security", 4625, 4740)
	if !t.Failed() {
		t.Logf("F23 verdict: confirmed: with NLA on the TLS handshake completes before CredSSP; ten probes logged no 4625")
	}
}

// ---- one certificate on the listener and an http.sys binding --------------------------------------------

// TestRealRDPSharedWithBinding (Ruling 26, W3's manual-matrix item): one alice-w6- certificate is
// deployed to the listener (rdp-deploy) and to an ipport record (iis-deploy). iis-cleanup --plan keeps
// it with reason rdp while the listener names it; rolling the RDP operation back leaves the binding
// serving it, and the plan then keeps it as bound.
func TestRealRDPSharedWithBinding(t *testing.T) {
	f := newRDPFixture(t)
	tw := newWriteTwin(t)
	tw.siteID, tw.httpPort = firstW6SiteID, portW6SiteHTTP
	tw.w = f.h // one data directory for both operations
	selfSHA256 := asString(dumpCert(t, f.dump())["sha256"])

	prev, prevSHA256 := tw.previous("alice-w6-shared-prev.test")
	loc := ipLoc(portW6Shared)
	tw.addRecord(loc, thumbprint(prev.Cert), nil)
	tw.addSite("alice-w6-shared", winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:", portW6Shared)})
	waitServed(t, portW6Shared, prevSHA256)

	ca := fixtureCA("alice-w6-shared")
	leaf := issue(ca, "alice-w6-shared.test")
	removeChainLater(t, leaf, ca)
	want := sum256hex(leaf.Cert.Raw)
	got := f.call(rdpDeployInput(t, leaf.FullchainPEM, leaf.KeyPEM, selfSHA256), winproto.SubRDPDeploy, winproto.ArgOp, op1)
	assertPhase(t, got, winproto.PhaseCommitted)
	f.requirePickup("shared", "the certificate on the listener", want)
	plan := f.call(planInput(t, leaf.Cert), winproto.SubIISCleanup, winproto.ArgPlan)
	t.Logf("shared: plan while the listener names it: %v", plan["watched"])
	w := asList(plan["watched"])
	require.Len(t, w, 1)
	assert.Equal(t, winproto.KeptRDP, w[0]["reason"], "kept for the listener")

	got = f.call(deployInput(t, loc, leaf.FullchainPEM, leaf.KeyPEM, prevSHA256), winproto.SubIISDeploy, winproto.ArgOp, op2)
	assertPhase(t, got, winproto.PhaseCommitted)
	waitServed(t, portW6Shared, want)

	restored := f.call(restoreInput(t), winproto.SubIISRestore, winproto.ArgOp, op1)
	assertPhase(t, restored, winproto.PhaseRestored)
	t.Logf("shared: the RDP rollback: %v", restored)
	f.requirePickup("shared", "the self-signed certificate after the RDP rollback", selfSHA256)
	waitServed(t, portW6Shared, want)
	plan = f.call(planInput(t, leaf.Cert), winproto.SubIISCleanup, winproto.ArgPlan)
	t.Logf("shared: plan after the RDP rollback: %v", plan["watched"])
	w = asList(plan["watched"])
	require.Len(t, w, 1)
	assert.Equal(t, winproto.KeptBound, w[0]["reason"], "kept for the binding")
}
