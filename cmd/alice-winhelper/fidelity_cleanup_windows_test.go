//go:build windows

package main

// The cleanup half of the helper on a real machine (W3 Task 5, R62): F11 (the CNG key and the
// certificate removed, nothing else touched), F12 (the RDP and WinRM listeners' certificates read from
// the registry) and the fidelity of iis-cleanup --plan and --apply against the emulator.
//
// W3 Ruling 22: ports 45390-45398, names prefixed alice-w3-, a private data directory, every cleanup
// registered before its fixture is made, and the RDP and WinRM registry values only read, never
// written; zz_runner_clean_windows_test.go checks at the end that nothing was left.
//
// The age path of TestFidelityCleanup needs the test build's clock offset (now_alicetest_windows.go,
// -tags alicetest): the workflow runs this package with that tag, and the test fails without it.

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

const (
	portW3F11      = 45390
	portW3Replaced = 45391
	portW3Bound    = 45392
	portW3SiteHTTP = 45398 // the plain http binding of every W3 fixture site (no http.sys SSL record)
	firstW3SiteID  = 45390
)

// testClockEnv is the test build's clock offset (now_alicetest_windows.go's clockOffsetEnv).
const testClockEnv = "ALICE_WIN_TEST_CLOCK_OFFSET"

// ntBadKeyset is NTE_BAD_KEYSET, what NCryptOpenKey answers for a key that does not exist.
const ntBadKeyset = 0x80090016

var (
	procNCryptOpenStorageProvider = modncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = modncrypt.NewProc("NCryptOpenKey")
)

var sha1HexRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// newCleanupTwin is the write twin on W3's site id and plain http port.
func newCleanupTwin(t *testing.T) *wtwin {
	t.Helper()
	tw := newWriteTwin(t)
	tw.siteID, tw.httpPort = firstW3SiteID, portW3SiteHTTP
	return tw
}

func planInput(t *testing.T, watch ...*x509.Certificate) []byte {
	t.Helper()
	in := winproto.CleanupPlanInput{Watch: []winproto.CleanupRef{}}
	for _, c := range watch {
		in.Watch = append(in.Watch, winproto.CleanupRef{SHA1: thumbprint(c), SHA256: sum256hex(c.Raw)})
	}
	b, err := json.Marshal(in)
	require.NoError(t, err)
	return b
}

type removal struct {
	cert   *x509.Certificate
	reason string
}

func applyInput(t *testing.T, items ...removal) []byte {
	t.Helper()
	in := winproto.CleanupApplyInput{}
	for _, it := range items {
		in.Remove = append(in.Remove, winproto.CleanupItem{Store: "My", SHA1: thumbprint(it.cert), SHA256: sum256hex(it.cert.Raw),
			Reason: it.reason})
	}
	b, err := json.Marshal(in)
	require.NoError(t, err)
	return b
}

// realCall runs one call on the real helper alone and requires an answer.
func (tw *wtwin) realCall(stdin []byte, args ...string) map[string]any {
	tw.t.Helper()
	_, got := execOn(tw.t, tw.w, stdin, args)
	require.NotNil(tw.t, got, "the real helper answers %v", args)
	return got
}

// cleanupBoth runs iis-cleanup on both hosts and requires the same exit status and answer. The only
// difference allowed is unbound_since, the stamp each host's own clock wrote at the first plan
// (seconds; the two clocks are read moments apart): within two seconds, then compared as equal.
func (tw *wtwin) cleanupBoth(stdin []byte, mode string) map[string]any {
	tw.t.Helper()
	args := []string{winproto.SubIISCleanup, mode}
	ro, real := execOn(tw.t, tw.w, stdin, args)
	mo, model := execOn(tw.t, tw.model.Host(), stdin, args)
	require.NotNil(tw.t, real, "the real helper answers %v", args)
	require.NotNil(tw.t, model, "the model answers %v", args)
	require.Equal(tw.t, ro.Exit, mo.Exit, "exit status of %v (real %v, model %v)", args, real, model)
	sameStamps(tw.t, real, model)
	require.Equal(tw.t, real, model, "answer of %v", args)
	return real
}

// sameStamps walks two decoded JSON values alike and, for every unbound_since both hold, requires the
// two times within two seconds and then copies the real one into the model's.
func sameStamps(t *testing.T, real, model any) {
	t.Helper()
	switch r := real.(type) {
	case map[string]any:
		m, ok := model.(map[string]any)
		if !ok {
			return
		}
		for k, rv := range r {
			if k != "unbound_since" {
				sameStamps(t, rv, m[k])
				continue
			}
			rs, _ := rv.(string)
			ms, _ := m[k].(string)
			if rs == "" || ms == "" {
				continue
			}
			rt, err := time.Parse(time.RFC3339, rs)
			require.NoError(t, err, rs)
			mt, err := time.Parse(time.RFC3339, ms)
			require.NoError(t, err, ms)
			d := rt.Sub(mt)
			assert.True(t, d <= 2*time.Second && d >= -2*time.Second, "unbound_since real %s model %s", rs, ms)
			m[k] = rs
		}
	case []any:
		m, ok := model.([]any)
		if !ok || len(m) != len(r) {
			return
		}
		for i := range r {
			sameStamps(t, r[i], m[i])
		}
	}
}

// waitServed waits until a fresh TLS handshake to the real endpoint presents the leaf want.
func waitServed(t *testing.T, port int, want string) {
	t.Helper()
	var got []string
	var err error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if got, err = served("127.0.0.1:"+strconv.Itoa(port), ""); err == nil && len(got) > 0 && got[0] == want {
			return
		}
	}
	require.NoError(t, err, "the real endpoint %d answers", port)
	require.NotEmpty(t, got)
	require.Equal(t, want, got[0], "the real endpoint %d serves the leaf", port)
}

// keyContainer reads the key container and provider a store certificate's CERT_KEY_PROV_INFO_PROP_ID
// names.
func keyContainer(t *testing.T, store, thumb string) (container, provider string) {
	t.Helper()
	st, err := openStore(store)
	require.NoError(t, err)
	defer func() { _ = windows.CertCloseStore(st, 0) }()
	hash, err := hex.DecodeString(thumb)
	require.NoError(t, err)
	require.Len(t, hash, 20)
	blob := windows.CryptHashBlob{Size: uint32(len(hash)), Data: &hash[0]} //nolint:gosec // G115: 20
	c, err := windows.CertFindCertificateInStore(st, encodingAny, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	runtime.KeepAlive(hash)
	require.NoError(t, err, "%s in %s", thumb, store)
	defer func() { _ = windows.CertFreeCertificateContext(c) }()
	buf, n, found, err := contextProperty(c, certKeyProvInfoPropID)
	require.NoError(t, err)
	require.True(t, found, "the certificate names a key")
	require.GreaterOrEqual(t, uintptr(n), unsafe.Sizeof(cryptKeyProvInfo{}))
	info := (*cryptKeyProvInfo)(unsafe.Pointer(&buf[0]))
	rec := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), n)
	container, ok := stringAt(rec, info.ContainerName)
	require.True(t, ok)
	provider, ok = stringAt(rec, info.ProvName)
	require.True(t, ok)
	require.NotEmpty(t, container)
	return container, provider
}

// openMachineKey opens a machine key by provider and container name (NCryptOpenKey with
// NCRYPT_MACHINE_KEY_FLAG) and answers the status (0 when it opened; the handle is freed).
func openMachineKey(t *testing.T, provider, container string) uint32 {
	t.Helper()
	pp, err := windows.UTF16PtrFromString(provider)
	require.NoError(t, err)
	cp, err := windows.UTF16PtrFromString(container)
	require.NoError(t, err)
	var prov, key uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(pp)), 0)
	require.Zero(t, r, "NCryptOpenStorageProvider %q", provider)
	defer func() { _, _, _ = procNCryptFreeObject.Call(prov) }()
	const machineKey = 0x20 // NCRYPT_MACHINE_KEY_FLAG
	r, _, _ = procNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(cp)), 0, machineKey|ncryptSilentFlag)
	runtime.KeepAlive(pp)
	runtime.KeepAlive(cp)
	if r == 0 {
		_, _, _ = procNCryptFreeObject.Call(key)
	}
	return uint32(r) //nolint:gosec // G115: an NTSTATUS-style status
}

// jsonStrings reads a list of strings ConvertTo-Json wrote: an array, or Windows PowerShell's
// {"value": [...], "Count": n} wrapping of one; empty for anything else.
func jsonStrings(v any) []string {
	if m, ok := v.(map[string]any); ok {
		v = m["value"]
	}
	l, _ := v.([]any)
	out := []string{}
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// minus is a without b.
func minus(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

func results(t *testing.T, got map[string]any) []map[string]any {
	t.Helper()
	assert.Equal(t, true, got["ok"], "%v", got)
	return asList(got["results"])
}

// TestRealCleanupRemovesKeyAndCertificate measures F11 (Review Focus 2): the removal route
// CryptAcquireCertificatePrivateKey, NCryptDeleteKey, then CertDeleteCertificateFromStore of a
// duplicated context removes exactly the certificate and its key file, and the certificate that
// replaced it keeps binding and serving.
func TestRealCleanupRemovesKeyAndCertificate(t *testing.T) {
	tw := newCleanupTwin(t)
	start := time.Now()
	old, oldSum := tw.previous("alice-w3-f11-old.test")
	loc := ipLoc(portW3F11)
	tw.addRecord(loc, thumbprint(old.Cert), nil)
	tw.addSite("alice-w3-f11", winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:", portW3F11)})
	ca := fixtureCA("alice-w3-f11")
	a, b := issue(ca, "alice-w3-f11a.test"), issue(ca, "alice-w3-f11b.test")
	aThumb, aSum, bSum := thumbprint(a.Cert), sum256hex(a.Cert.Raw), sum256hex(b.Cert.Raw)

	tw.removeLater(a.FullchainPEM)
	got := tw.realCall(deployInput(t, loc, a.FullchainPEM, a.KeyPEM, oldSum), winproto.SubIISDeploy, winproto.ArgOp, op1)
	assertPhase(t, got, winproto.PhaseCommitted)
	assert.Equal(t, true, got["alice_imported"])
	tw.removeLater(b.FullchainPEM)
	got = tw.realCall(deployInput(t, loc, b.FullchainPEM, b.KeyPEM, aSum), winproto.SubIISDeploy, winproto.ArgOp, op2)
	assertPhase(t, got, winproto.PhaseCommitted)
	waitServed(t, portW3F11, bSum) // positive control: B serves before the removal

	container, provider := keyContainer(t, "My", aThumb)
	t.Logf("F11: A's key: provider %q container %q", provider, container)
	require.Zero(t, openMachineKey(t, provider, container), "positive control: A's key opens before the removal")
	before := machineKeysSince(t, start)
	t.Logf("F11: machine key files created by this test before the removal: %v", before)

	got = tw.realCall(applyInput(t, removal{a.Cert, winproto.CleanupIncident}), winproto.SubIISCleanup, winproto.ArgApply)
	res := results(t, got)
	require.Len(t, res, 1, "%v", got)
	assert.Equal(t, map[string]any{"sha256": aSum, "result": winproto.CleanupRemoved, "reason": ""}, res[0])

	_, found, err := tw.w.Certificate(context.Background(), "My", aThumb)
	require.NoError(t, err)
	assert.False(t, found, "F11: A is gone from My")
	left := powershellEnv(t, map[string]string{"ALICE_W3_THUMB": upperASCII(aThumb)},
		`if (Test-Path -LiteralPath "Cert:\LocalMachine\My\$env:ALICE_W3_THUMB") { 'present' } else { 'absent' }`)
	assert.Equal(t, "absent", strings.TrimSpace(string(left)), "F11: the Cert: drive no longer lists A")
	status := openMachineKey(t, provider, container)
	t.Logf("F11: NCryptOpenKey of A's container after the removal: 0x%08x", status)
	assert.EqualValues(t, ntBadKeyset, status, "F11: A's key no longer opens (NTE_BAD_KEYSET)")
	after := machineKeysSince(t, start)
	gone, added := minus(before, after), minus(after, before)
	t.Logf("F11: key files removed by the cleanup: %v; created by it: %v", gone, added)
	assert.Len(t, gone, 1, "F11: exactly one key file (A's) is removed")
	assert.Empty(t, added, "the cleanup creates no key")
	if len(gone) == 1 && status == ntBadKeyset && !found {
		t.Logf("F11 verdict: confirmed: CryptAcquireCertificatePrivateKey(ONLY_NCRYPT|SILENT) then NCryptDeleteKey removed the key file " +
			"and CertDeleteCertificateFromStore of a duplicated context removed the certificate; no other key was touched")
	}

	// B and the previous certificate keep their keys; B still binds and serves.
	for _, c := range []*x509.Certificate{b.Cert, old.Cert} {
		sc, found, err := tw.w.Certificate(context.Background(), "My", thumbprint(c))
		require.NoError(t, err)
		require.True(t, found, c.Subject.CommonName)
		assert.True(t, sc.HasKey, "%s keeps its key", c.Subject.CommonName)
		assert.Empty(t, sc.KeyProblem, "%s keeps its key", c.Subject.CommonName)
	}
	assert.Equal(t, thumbprint(b.Cert), tw.readReal(loc).CertSHA1, "the record still names B")
	waitServed(t, portW3F11, bSum)

	got = tw.realCall(applyInput(t, removal{a.Cert, winproto.CleanupIncident}), winproto.SubIISCleanup, winproto.ArgApply)
	res = results(t, got)
	require.Len(t, res, 1, "%v", got)
	assert.Equal(t, winproto.CleanupAbsent, res[0]["result"], "a second apply finds nothing to remove")
}

// TestRealProtectedThumbprints measures F12: the RDP listener's SSLCertificateSHA1Hash and the WinRM
// HTTPS listeners' certThumbprint values, read by the helper, match an independent PowerShell reading
// of the same registry values, and the WinRM value names the certificate of the image's http.sys record
// 0.0.0.0:5986 (W0 F8). Nothing is written.
func TestRealProtectedThumbprints(t *testing.T) {
	requireReal(t)
	p, err := newHost(winproto.DataDir).ProtectedThumbprints(context.Background())
	require.NoError(t, err, "F12: the listeners' registry values are read")
	t.Logf("F12: the helper reads RDP %v, WinRM %v", p.RDP, p.WinRM)
	assert.LessOrEqual(t, len(p.RDP), 1, "one RDP listener value")
	for _, s := range append(append([]string{}, p.RDP...), p.WinRM...) {
		assert.Regexp(t, sha1HexRE, s, "a lower-case SHA-1")
	}

	out := powershell(t, `$r = ''
$k = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
if ($k -and $k.PSObject.Properties['SSLCertificateSHA1Hash']) { $r = (($k.SSLCertificateSHA1Hash | ForEach-Object { $_.ToString('x2') }) -join '') }
$w = @(); $names = @()
$base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener'
if (Test-Path -LiteralPath $base) {
    foreach ($l in Get-ChildItem -LiteralPath $base) {
        $names += [string]$l.PSChildName
        if ($l.PSChildName -like '*+HTTPS') {
            $v = (Get-ItemProperty -LiteralPath $l.PSPath -ErrorAction SilentlyContinue).certThumbprint
            if ($v) { $w += ([string]$v).Replace(' ', '').ToLowerInvariant() }
        }
    }
}
@{ rdp = $r; winrm = @($w); listeners = @($names) } | ConvertTo-Json -Compress`)
	var raw struct {
		RDP       string `json:"rdp"`
		WinRM     any    `json:"winrm"`
		Listeners any    `json:"listeners"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(string(out))), &raw), string(out))
	ind := struct {
		RDP              string
		WinRM, Listeners []string
	}{raw.RDP, jsonStrings(raw.WinRM), jsonStrings(raw.Listeners)}
	t.Logf("F12: PowerShell reads RDP %q, WinRM %v, listener keys %v", ind.RDP, ind.WinRM, ind.Listeners)
	if wsman, err := runPowershell(nil, `winrm enumerate winrm/config/listener`); err == nil {
		t.Logf("F12: winrm enumerate winrm/config/listener:\n%s", wsman)
	} else {
		t.Logf("F12: winrm enumerate failed: %v", err)
	}
	wantRDP := []string{}
	if ind.RDP != "" {
		wantRDP = []string{ind.RDP}
	}
	assert.Equal(t, wantRDP, append([]string{}, p.RDP...), "F12: RDP as PowerShell reads it")
	gotWinRM, wantWinRM := append([]string{}, p.WinRM...), append([]string{}, ind.WinRM...)
	sort.Strings(gotWinRM)
	sort.Strings(wantWinRM)
	assert.Equal(t, wantWinRM, gotWinRM, "F12: WinRM as PowerShell reads it")

	list, err := sslBindings()
	require.NoError(t, err)
	record := ""
	for _, b := range list {
		if b.Type == winproto.BindingIPPort && b.IP == "0.0.0.0" && b.Port == 5986 {
			record = foldASCII(b.CertSHA1)
		}
	}
	t.Logf("F12: the http.sys record 0.0.0.0:5986 names %q", record)
	require.NotEmpty(t, record, "W0 F8: the image has the WinRM listener's http.sys record 0.0.0.0:5986")
	assert.Contains(t, p.WinRM, record, "F12: the WinRM listener's registry value is the hash of its http.sys record")
	if slices.Contains(p.WinRM, record) {
		t.Logf("F12 verdict: confirmed: WSMAN\\Listener\\*+HTTPS certThumbprint equals the http.sys record 0.0.0.0:5986; RDP-Tcp SSLCertificateSHA1Hash %s",
			map[bool]string{true: "absent (RDP uses its self-signed certificate)", false: "present: " + ind.RDP}[ind.RDP == ""])
	}
}

// TestFidelityCleanup (Review Focus 1): iis-cleanup --plan and --apply on both hosts. A is deployed
// and then replaced by B (45391), C is imported by the test without Alice's name (foreign), D is
// deployed and bound by a second record (45392). The first plan finds nothing eligible; with the
// helper's clock 192 hours ahead (the test build's offset on the real host, Advance on the model) A is
// aged; the apply removes A and keeps C (not_alice) and D (bound). The answers, the import inventory
// and the binding records are equal field by field (messages dropped; unbound_since within two seconds).
func TestFidelityCleanup(t *testing.T) {
	tw := newCleanupTwin(t)
	require.True(t, testClockOffset, "this test needs the test build's clock offset: go test -tags alicetest")
	old, oldSum := tw.previous("alice-w3-clean-old.test")
	replaced, bound := ipLoc(portW3Replaced), ipLoc(portW3Bound)
	tw.addRecord(replaced, thumbprint(old.Cert), nil)
	tw.addRecord(bound, thumbprint(old.Cert), nil)
	ca := fixtureCA("alice-w3-clean")
	a, b, d := issue(ca, "alice-w3-clean-a.test"), issue(ca, "alice-w3-clean-b.test"), issue(ca, "alice-w3-clean-d.test")
	aSum := sum256hex(a.Cert.Raw)
	assertPhase(t, tw.deploy(op1, replaced, a, a.FullchainPEM, oldSum), winproto.PhaseCommitted)
	assertPhase(t, tw.deploy(op2, replaced, b, b.FullchainPEM, aSum), winproto.PhaseCommitted)
	assertPhase(t, tw.deploy(op3, bound, d, d.FullchainPEM, oldSum), winproto.PhaseCommitted)
	c := pki.SelfSigned("alice-w3-clean-c.test", pki.ECDSA256, time.Now())
	tw.addCertificate("My", c)

	watched := func(got map[string]any) map[string]string {
		out := map[string]string{}
		for _, w := range asList(got["watched"]) {
			out[asString(w["sha1"])] = asString(w["state"]) + " " + asString(w["reason"])
		}
		return out
	}
	wantWatched := map[string]string{thumbprint(a.Cert): winproto.WatchRemovable + " ",
		thumbprint(c.Cert): winproto.WatchKept + " " + winproto.KeptNotAlice, thumbprint(d.Cert): winproto.WatchKept + " " + winproto.KeptBound}

	// Now: A is unbound but too young; nothing is eligible.
	got := tw.cleanupBoth(planInput(t, a.Cert, c.Cert, d.Cert), winproto.ArgPlan)
	assert.Equal(t, true, got["ok"], "%v", got)
	cands := asList(got["candidates"])
	require.Len(t, cands, 1, "only A is an unbound certificate Alice imported: %v", got)
	assert.Equal(t, thumbprint(a.Cert), cands[0]["sha1"])
	assert.Equal(t, "", cands[0]["eligible"], "nothing is eligible yet")
	assert.NotEmpty(t, cands[0]["unbound_since"])
	assert.Equal(t, wantWatched, watched(got))
	assert.EqualValues(t, 0, got["pruned"])

	// 192 hours later by the helper's clock: A is aged, and op1's committed journal is pruned.
	t.Setenv(testClockEnv, "192h")
	tw.model.Advance(192 * time.Hour)
	got = tw.cleanupBoth(planInput(t, a.Cert, c.Cert, d.Cert), winproto.ArgPlan)
	cands = asList(got["candidates"])
	require.Len(t, cands, 1, "%v", got)
	assert.Equal(t, winproto.CleanupAged, cands[0]["eligible"], "the offset took effect: A is aged")
	assert.Equal(t, wantWatched, watched(got))
	assert.EqualValues(t, 1, got["pruned"], "op1's journal (committed, no record needs it) is older than JournalKeep")

	got = tw.cleanupBoth(applyInput(t, removal{a.Cert, winproto.CleanupAged}, removal{c.Cert, winproto.CleanupAged},
		removal{d.Cert, winproto.CleanupAged}), winproto.ArgApply)
	res := results(t, got)
	require.Len(t, res, 3, "%v", got)
	assert.Equal(t, winproto.CleanupRemoved, res[0]["result"], "A")
	assert.Equal(t, []any{winproto.CleanupKept, winproto.KeptNotAlice}, []any{res[1]["result"], res[1]["reason"]}, "C")
	assert.Equal(t, []any{winproto.CleanupKept, winproto.KeptBound}, []any{res[2]["result"], res[2]["reason"]}, "D")

	// What the hosts hold afterwards.
	mh := tw.model.Host()
	for _, x := range []struct {
		cert *x509.Certificate
		want bool
	}{{a.Cert, false}, {b.Cert, true}, {c.Cert, true}, {d.Cert, true}} {
		_, rFound, err := tw.w.Certificate(context.Background(), "My", thumbprint(x.cert))
		require.NoError(t, err)
		assert.Equal(t, x.want, rFound, "%s in the real My", x.cert.Subject.CommonName)
		assert.Equal(t, x.want, tw.model.HasCertificate("My", thumbprint(x.cert)), "%s in the model's My", x.cert.Subject.CommonName)
	}
	assert.False(t, tw.model.HasKey("My", thumbprint(a.Cert)), "the model deleted A's key")
	realImports, modelImports := stateFile(t, tw.w, "imports.json"), stateFile(t, mh, "imports.json")
	sameStamps(t, realImports, modelImports)
	assert.Equal(t, realImports, modelImports, "the import inventory")
	assert.NotContains(t, fmt.Sprint(realImports), thumbprint(a.Cert), "A's inventory entry is gone")
	for _, l := range []winproto.Locator{replaced, bound} {
		canonical, ok := l.Canonical()
		require.True(t, ok)
		name := "bindings/" + sum256hex([]byte(canonical)) + ".json"
		assert.Equal(t, stateFile(t, tw.w, name), stateFile(t, mh, name), "binding record %s", name)
	}
	assert.Nil(t, stateFile(t, tw.w, "journal/"+op1+".json"), "the real helper pruned op1's journal")
	assert.Nil(t, stateFile(t, mh, "journal/"+op1+".json"), "the model pruned op1's journal")
	ev := tw.model.Events()
	require.NotEmpty(t, ev)
	assert.EqualValues(t, 1003, ev[len(ev)-1].ID, "the model logged the removal")
}
