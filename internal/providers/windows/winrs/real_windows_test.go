//go:build windows

package winrs_test

// The real-Windows facts F24-F31 of R71 (plan "Before you start: facts to measure on a runner"), measured with
// the winrs client against the image's HTTPS listener (F8) on windows-2022 and windows-2025. Each test logs what
// it measures as "FACT F2x: ..."; the parts W7 relies on are asserted, the variants the plan only logs are not.
// fixture_windows_test.go holds the fixture.

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/winrs"
	"alice/internal/testutil/pki"
)

// outcome is a call's result for a log line: the error (winrs errors hold no server text and no credential) or
// the exit code and the start of stdout.
func outcome(res winrs.Result, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	out := bytes.TrimSpace(res.Stdout)
	if len(out) > 300 {
		out = out[:300]
	}
	return fmt.Sprintf("exit %d, %s", res.ExitCode, out)
}

// checkDials asserts F24 (d) as measured in runner run 2: at most 2 dials per call (Windows closes the first
// connection after the anonymous 401, so the sign-in may take a second one); more is a bug.
func checkDials(t *testing.T, what string, n int32) {
	t.Helper()
	fact(t, "F24", "%s used %d dial(s) (at most 2: F24 (d), maxDialsPerCall = 2)", what, n)
	assert.LessOrEqual(t, n, int32(2), "%s: more than 2 dials per call is a bug (F24 (d))", what)
}

func TestRealWinRMNTLMAuth(t *testing.T) {
	f := winrmFixture(t)
	// Runner runs 3 and 4: every program exited 1 with no stdout; the matrix runs first, before any setting changes
	// (logged only).
	diagnoseCommands(t, f)
	t0 := time.Now()

	// The exchange on the wire first (F24 (c), (d)): the client below refuses a second dial, so this is what
	// says why if it fails.
	r := newRaw(t, imageAddr, f.spki, account, f.pw)
	shell, a := r.create(t, callTimeout+winrs.ShellIdleSlack)
	fact(t, "F24", "the first request of a call (Create, with the credentials) took %d request(s) on the wire: %v", len(a.reqs), a.reqs)
	assert.LessOrEqual(t, len(a.reqs), 3, "the first request costs at most anonymous, type 1 and type 3")
	body, err := winrs.CommandRequest(r.header(), shell, f.stdinhash, []string{"0"})
	require.NoError(t, err)
	a = r.post(body, false)
	fact(t, "F24", "the following request (Command, no credentials) took %d request(s): %v, status %d, err %v", len(a.reqs), a.reqs, a.status, a.err)
	if a.status == http.StatusUnauthorized {
		fact(t, "F24", "LOUD: the connection did not stay authenticated (F24 (c))")
	}
	body, err = winrs.DeleteRequest(r.header(), shell)
	require.NoError(t, err)
	a = r.post(body, false)
	fact(t, "F24", "the following request (Delete, no credentials) took %d request(s): %v, status %d, err %v", len(a.reqs), a.reqs, a.status, a.err)
	checkDials(t, "the hand-driven call", r.dials.Load())

	// version and win-facts as alice-w7, with LocalAccountTokenFilterPolicy as the image ships it (F3).
	c := f.client(t, account)
	f.dials.Store(0)
	res, err := run(c, f.helperCall(winproto.SubVersion))
	fact(t, "F24", "version as %s: %s", account, outcome(res, err))
	checkDials(t, "the client's call", f.dials.Load())
	require.NoError(t, err)
	v := decode[winproto.VersionResponse](t, res.Stdout)
	assert.True(t, v.OK)
	assert.Equal(t, winproto.Version, v.Helper)
	assert.Zero(t, res.ExitCode)
	assert.Equal(t, f.spki, res.PeerSPKI, "the result names the presented identity")
	res, err = run(c, f.helperCall(winproto.SubWinFacts))
	require.NoError(t, err)
	wf := decode[winproto.WinFactsResponse](t, res.Stdout)
	latfp := f.asFound["LocalAccountTokenFilterPolicy"]
	fact(t, "F24", "win-facts as %s with LocalAccountTokenFilterPolicy %s (as found): elevated %t", account, latfp, wf.Elevated)
	assert.True(t, wf.Elevated, "the token is elevated with LocalAccountTokenFilterPolicy %s", latfp)

	// The username forms (Ruling 6): HOSTNAME\alice-w7 must work; .\alice-w7 sent raw (domain ".") is logged.
	for _, user := range []string{f.host + `\` + account, `.\` + account} {
		res, err := run(f.client(t, user), f.helperCall(winproto.SubVersion))
		fact(t, "F24", "the username form %q sent as typed: %s", user, outcome(res, err))
		if !strings.HasPrefix(user, `.\`) {
			assert.NoError(t, err, user)
		}
	}

	// LocalAccountTokenFilterPolicy 0 (F24 (a)): logged.
	restore := setDWORD(t, latfpKey, "LocalAccountTokenFilterPolicy", 0)
	res, err = run(c, f.helperCall(winproto.SubWinFacts))
	if err == nil && res.ExitCode == 0 {
		fact(t, "F24", "LocalAccountTokenFilterPolicy 0: win-facts answers, elevated %t", decode[winproto.WinFactsResponse](t, res.Stdout).Elevated)
	} else {
		fact(t, "F24", "LocalAccountTokenFilterPolicy 0: win-facts: %s", outcome(res, err))
	}
	restore()

	for _, l := range waitLogons(t, t0, 4624) {
		fact(t, "F24", "Security event of %s during the test: %s", account, l)
	}
}

func TestRealWinRMRunsTheForcedEntry(t *testing.T) {
	f := winrmFixture(t)
	c := f.client(t, account)
	auditProcessCreation(t)
	t0 := time.Now()

	res, err := run(c, f.helperCall(winproto.SubVersion))
	fact(t, "F25", "SSH_ORIGINAL_COMMAND=version, the helper with the argument ssh: %s", outcome(res, err))
	require.NoError(t, err)
	v := decode[winproto.VersionResponse](t, res.Stdout)
	assert.True(t, v.OK && v.Helper == winproto.Version, "the forced-command entry answers version: %s", res.Stdout)

	// The process as Windows records it, caught while stdinhash sleeps 2 s.
	wait := startWatcher(t)
	res, err = run(c, f.hashCall([]byte("x"), "0", "2"))
	seen := wait()
	require.NoError(t, err)
	fact(t, "F25", "the running program from Win32_Process: %s", seen)
	require.NotEqual(t, "none", seen, "the watcher saw stdinhash.exe running")
	p := decode[struct{ CommandLine, Parent, ParentCommandLine, Owner string }](t, []byte(seen))
	assert.Equal(t, `"`+f.stdinhash+`" 0 2`, p.CommandLine, "the command line is the quoted program and its arguments only")
	assert.False(t, strings.EqualFold("cmd.exe", p.Parent), "no cmd.exe between WinRM and the program")
	assert.True(t, strings.EqualFold(f.host+`\`+account, p.Owner), "the program runs as %s, not %s", account, p.Owner)

	time.Sleep(2 * time.Second)
	fact(t, "F25", "Security 4688 with command lines since the test started: %s", ps(t, map[string]string{"SINCE": t0.UTC().Format(time.RFC3339Nano)}, "",
		sinceScript+`$out = @()
foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $since } -ErrorAction SilentlyContinue)) {
    $d = Get-Data $e
    if ($d['NewProcessName'] -like '*\stdinhash.exe' -or $d['NewProcessName'] -like '*\alice-helper.exe') {
        $out += [pscustomobject]@{ NewProcessName = $d['NewProcessName']; CommandLine = $d['CommandLine']; Parent = $d['ParentProcessName']; Target = $d['TargetUserName'] }
    }
}
ConvertTo-Json -Compress -InputObject @($out)`))
}

func TestRealWinRMStdin(t *testing.T) {
	f := winrmFixture(t)
	c := f.client(t, account)
	for _, n := range []int{1, winrs.MaxSendChunk, winrs.MaxSendChunk + 1, 256 << 10} {
		in := randomBytes(t, n)
		res, err := run(c, f.hashCall(in, "0"))
		require.NoError(t, err, "%d bytes", n)
		got := strings.TrimSpace(string(res.Stdout))
		fact(t, "F26", "%d bytes of stdin in Sends of at most %d: the program's SHA-256 equals Go's: %t", n, winrs.MaxSendChunk, got == hashHex(in))
		assert.Equal(t, hashHex(in), got, "%d bytes arrive byte for byte", n)
	}
	fact(t, "F26", "MaxEnvelopeSizekb %s", ps(t, nil, "", `(Get-Item -LiteralPath 'WSMan:\localhost\MaxEnvelopeSizekb').Value`))

	// A Send above the listener's limit, built by hand (the codec refuses a chunk above MaxSendChunk).
	r := newRaw(t, imageAddr, f.spki, account, f.pw)
	shell, _ := r.create(t, callTimeout+winrs.ShellIdleSlack)
	body, err := winrs.CommandRequest(r.header(), shell, f.stdinhash, []string{"0"})
	require.NoError(t, err)
	a := r.post(body, false)
	require.NoError(t, a.err)
	require.Equal(t, http.StatusOK, a.status, a.fault())
	cmdID, err := winrs.ParseCommandStarted(a.body)
	require.NoError(t, err)
	small, err := winrs.SendRequest(r.header(), shell, cmdID, []byte("x"), true)
	require.NoError(t, err)
	big := bytes.Replace(small, []byte(">eA==<"), []byte(">"+base64.StdEncoding.EncodeToString(randomBytes(t, 450<<10))+"<"), 1)
	require.Greater(t, len(big), 600<<10)
	a = r.post(big, false)
	fact(t, "F26", "a hand-built Send of %d bytes: status %d, %s, err %v", len(big), a.status, a.fault(), a.err)
	body, err = winrs.DeleteRequest(r.header(), shell)
	require.NoError(t, err)
	a = r.post(body, false)
	t.Logf("Delete after it: status %d, err %v", a.status, a.err)
}

var durationRE = regexp.MustCompile(`^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?$`)

// parseDuration reads the xs:duration forms WinRM answers (PT90.000S, PT1M30S).
func parseDuration(s string) (time.Duration, bool) {
	m := durationRE.FindStringSubmatch(s)
	if m == nil || s == "PT" {
		return 0, false
	}
	var d time.Duration
	for i, unit := range []time.Duration{time.Hour, time.Minute} {
		if m[i+1] != "" {
			n, _ := strconv.Atoi(m[i+1])
			d += time.Duration(n) * unit
		}
	}
	if m[3] != "" {
		sec, _ := strconv.ParseFloat(m[3], 64)
		d += time.Duration(sec * float64(time.Second))
	}
	return d, true
}

// shells enumerates alice-w7's WinRS shells (as alice-w7: the password on stdin) as id -> "IdleTimeOut MaxIdleTimeOut".
func (f *fx) shells() (map[string][]string, error) {
	out, err := psRun(map[string]string{"ACCOUNT": f.host + `\` + account}, f.pw, `$p = [Console]::In.ReadLine()
$cred = New-Object System.Management.Automation.PSCredential($env:ACCOUNT, (ConvertTo-SecureString -String $p -AsPlainText -Force))
Remove-Variable p
$o = New-WSManSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
foreach ($s in @(Get-WSManInstance -ResourceURI shell -Enumerate -ComputerName 127.0.0.1 -Port 5986 -UseSSL -Credential $cred -Authentication Negotiate -SessionOption $o)) {
    "$($s.ShellId) $($s.IdleTimeOut) $($s.MaxIdleTimeOut)"
}
'end'`)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, out)
	}
	m := map[string][]string{}
	for _, l := range strings.Split(out, "\n") {
		if fs := strings.Fields(l); len(fs) >= 1 && fs[0] != "end" {
			m[fs[0]] = fs[1:]
		}
	}
	return m, nil
}

// findShell looks a shell id up whatever its case.
func findShell(m map[string][]string, id string) ([]string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, id) {
			return v, true
		}
	}
	return nil, false
}

func TestRealWinRMCost(t *testing.T) {
	f := winrmFixture(t)
	c := f.client(t, account)
	var ds []time.Duration
	for range 20 {
		start := time.Now()
		_, err := run(c, f.helperCall(winproto.SubVersion))
		require.NoError(t, err)
		ds = append(ds, time.Since(start))
	}
	slices.Sort(ds)
	fact(t, "F27", "20 sequential version calls (the NTLM exchange included): p50 %s, max %s, min %s", ds[len(ds)/2], ds[len(ds)-1], ds[0])
	if ds[len(ds)/2] > 3*time.Second {
		fact(t, "F27", "LOUD: p50 is above 3 s: the budgets of iis-dump and the probes are re-checked")
	}
	fact(t, "F27", "the shell limits: %s", ps(t, nil, "", `foreach ($n in 'MaxShellsPerUser', 'IdleTimeout', 'MaxConcurrentUsers', 'MaxProcessesPerShell', 'MaxMemoryPerShellMB') {
    "$n=$((Get-Item -LiteralPath "WSMan:\localhost\Shell\$n" -ErrorAction SilentlyContinue).Value)"
}`))

	// A shell left undeleted, with the IdleTimeOut Alice sends for a 30 s call.
	idle := 30*time.Second + winrs.ShellIdleSlack
	r := newRaw(t, imageAddr, f.spki, account, f.pw)
	shell, _ := r.create(t, idle)
	created := time.Now()
	r.close()
	seen, err := f.shells()
	if err != nil {
		fact(t, "F27", "the shells could not be enumerated, so the clamp and the reaping are not measured: %v", err)
		return
	}
	info, ok := findShell(seen, shell)
	if !ok {
		fact(t, "F27", "the undeleted shell %s is not among the %d enumerated, so the clamp and the reaping are not measured", shell, len(seen))
		return
	}
	fact(t, "F27", "IdleTimeOut sent PT%dS, read back from the shell (IdleTimeOut MaxIdleTimeOut): %v", int(idle.Seconds()), info)
	clamp, ok := time.Duration(0), len(info) > 0
	if ok {
		clamp, ok = parseDuration(info[0])
	}
	switch {
	case !ok:
		fact(t, "F27", "the read-back IdleTimeOut %v is not a duration: the reaping is not measured", info)
		return
	case clamp > 5*time.Minute:
		fact(t, "F27", "the clamp %s is over 5 minutes: the reaping is not waited for", clamp)
		return
	}
	deadline := created.Add(clamp + 30*time.Second)
	for {
		seen, err = f.shells()
		require.NoError(t, err)
		_, present := findShell(seen, shell)
		if !present {
			fact(t, "F27", "the undeleted shell is gone %s after its creation (IdleTimeOut %s)", time.Since(created).Round(time.Second), clamp)
			return
		}
		if time.Now().After(deadline) {
			fact(t, "F27", "LOUD: the undeleted shell is still there %s after its creation (IdleTimeOut %s)", time.Since(created).Round(time.Second), clamp)
			assert.Fail(t, "an undeleted shell is reaped after its idle time and 30 s")
			return
		}
		time.Sleep(5 * time.Second)
	}
}

func TestRealWinRMListenerIdentity(t *testing.T) {
	f := winrmFixture(t)

	// The image's listener keeps its identity over a service restart.
	ps(t, nil, "", `Restart-Service -Name WinRM -Force`)
	after := waitLeaf(t, imageAddr, nil, time.Minute).RawSubjectPublicKeyInfo
	fact(t, "F28", "after Restart-Service WinRM, %s presents %s (before: %s)", imageAddr, fingerprint(after), fingerprint(f.spki))
	assert.Equal(t, f.spki, after, "the image listener's identity is unchanged by a restart")

	// The test listener 127.0.0.1:45520.
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	cert := listenerCert(t, key1, now.Add(-time.Hour), now.AddDate(0, 1, 0))
	testListener(t, importCert(t, cert, key1))
	spki1 := waitLeaf(t, renewAddr, cert, time.Minute).RawSubjectPublicKeyInfo
	c := f.client(t, account)
	c.TLS = pinned(spki1, &f.refused)
	call := f.helperCall(winproto.SubVersion)
	call.Addr = renewAddr
	res, err := run(c, call)
	fact(t, "F28", "the test listener %s (%s): %s", renewAddr, fingerprint(spki1), outcome(res, err))
	require.NoError(t, err)

	// Renewed with a new key: the pin refuses the handshake, before any HTTP request.
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert = listenerCert(t, key2, now.Add(-time.Hour), now.AddDate(0, 1, 0))
	how := setListenerCert(t, importCert(t, cert, key2))
	waitLeaf(t, renewAddr, cert, time.Minute)
	time.Sleep(time.Second)
	t0 := time.Now()
	f.refused.Store(0)
	_, err = run(c, call)
	fact(t, "F28", "renewed with a new key (%s, now %s): %v; handshakes the pin refused: %d", how, fingerprint(cert.RawSubjectPublicKeyInfo), err, f.refused.Load())
	require.Error(t, err)
	assert.ErrorIs(t, err, winrs.ErrNotSent)
	assert.Positive(t, f.refused.Load(), "the pin refused the handshake")
	time.Sleep(3 * time.Second)
	ls := logons(t, t0)
	fact(t, "F28", "Security 4624/4625 of %s since the refused call: %v", account, ls)
	assert.Empty(t, ls, "no NTLM message reached the listener")
	fact(t, "F28", "Microsoft-Windows-WinRM/Operational since the refused call: %s", winrmEvents(t, t0))

	// Renewed with the same key: accepted.
	cert = listenerCert(t, key1, now.Add(-time.Hour), now.AddDate(0, 2, 0))
	how = setListenerCert(t, importCert(t, cert, key1))
	waitLeaf(t, renewAddr, cert, time.Minute)
	res, err = run(c, call)
	fact(t, "F28", "renewed with the same key (%s): %s", how, outcome(res, err))
	assert.NoError(t, err)

	// An expired certificate with the pinned key: served and accepted (Alice checks the pin only).
	cert = listenerCert(t, key1, now.AddDate(0, 0, -30), now.Add(-24*time.Hour))
	how = setListenerCert(t, importCert(t, cert, key1))
	waitLeaf(t, renewAddr, cert, time.Minute)
	res, err = run(c, call)
	fact(t, "F28", "an expired certificate (not after %s, %s) with the pinned key: %s", cert.NotAfter.UTC().Format(time.RFC3339), how, outcome(res, err))
	assert.NoError(t, err)
}

func TestRealWinRMExitCodes(t *testing.T) {
	f := winrmFixture(t)
	c := f.client(t, account)
	for _, code := range []int{0, 2, 3, 4} {
		res, err := run(c, f.hashCall([]byte("x"), strconv.Itoa(code)))
		require.NoError(t, err, "exit %d", code)
		fact(t, "F29", "a program exiting %d: ExitCode %d", code, res.ExitCode)
		assert.Equal(t, code, res.ExitCode)
	}

	res, err := run(c, f.helperCall(winproto.SubIISStatus+" "+winproto.ArgOp+" bad"))
	fact(t, "F29", "the helper's iis-status with a bad --op: %s", outcome(res, err))
	require.NoError(t, err)
	assert.Equal(t, winproto.ExitRefused, res.ExitCode)
	e := decode[winproto.ErrorResponse](t, res.Stdout)
	assert.False(t, e.OK)

	missing := f.helperCall(winproto.SubVersion)
	missing.Program = f.dir + `\missing.exe`
	_, err = run(c, missing)
	var fe *winrs.FaultError
	require.ErrorAs(t, err, &fe, "a program that does not exist is a WS-Management fault")
	fact(t, "F29", "a program path that does not exist: %v (WS-Management fault code %d)", err, fe.Code)
	assert.Equal(t, uint32(2), fe.Code, "Ruling 13: ERROR_FILE_NOT_FOUND at Command")

	killAtPrepared(t, f)
}

// killAtPrepared runs an iis-deploy of a helper built with -tags alicetest over WinRS, killed at deploy.prepared
// (logged only). The kill hook reads ALICE_WIN_TEST_KILL_AT, a second environment variable winrs never sends, so
// the shell is created by hand; the helper needs its trusted data directory (winproto.DataDir) and a real
// http.sys record to replace.
func killAtPrepared(t *testing.T, f *fx) {
	t.Helper()
	helper := filepath.Join(f.dir, "alice-helper-alicetest.exe")
	b, err := exec.Command("go", "build", "-tags", "alicetest", "-o", helper, "alice/cmd/alice-winhelper").CombinedOutput()
	require.NoError(t, err, "go build -tags alicetest: %s", b)

	// The record the deployment replaces: 0.0.0.0:45522 (a spare fixture port) naming an alice-w7- certificate.
	now := time.Now()
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certA := listenerCert(t, keyA, now.Add(-time.Hour), now.AddDate(0, 1, 0))
	thumbA := importCert(t, certA, keyA)
	loc := winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 45522, AppID: winproto.AppIDIIS}
	canonical, ok := loc.Canonical()
	require.True(t, ok)
	netsh := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	t.Cleanup(func() {
		out, err := exec.Command(netsh, "http", "delete", "sslcert", "ipport=0.0.0.0:45522").CombinedOutput()
		t.Logf("netsh http delete sslcert ipport=0.0.0.0:45522: %v: %s", err, bytes.TrimSpace(out))
	})
	out, err := exec.Command(netsh, "http", "add", "sslcert", "ipport=0.0.0.0:45522", "certhash="+thumbA,
		"appid="+winproto.AppIDIIS, "certstorename=MY").CombinedOutput()
	require.NoError(t, err, "netsh http add sslcert: %s", out)

	// The new certificate, removed at the end wherever a deployment that was not killed put it.
	ca := pki.NewCA("alice-w7-kill-ca", pki.RSA2048, now)
	leaf := ca.Issue(pki.Opts{CommonName: "alice-w7-kill", SANs: []string{"alice-w7-kill"}, KeyType: pki.RSA2048}, now)
	removeCertLater(t, "My", thumbprint(leaf.Cert))
	removeCertLater(t, "CA", thumbprint(ca.Intermediate))
	in, err := json.Marshal(winproto.DeployInput{Locator: loc, ExpectSHA256: hashHex(certA.Raw), ChainPEM: string(leaf.FullchainPEM),
		KeyPEM: string(leaf.KeyPEM), ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}})
	require.NoError(t, err)
	require.LessOrEqual(t, len(in), winrs.MaxSendChunk)
	op := uuid.NewString()
	helperDataDir(t, op, canonical)

	r := newRaw(t, imageAddr, f.spki, account, f.pw)
	body, err := winrs.CreateShellRequest(r.header(), map[string]string{"SSH_ORIGINAL_COMMAND": winproto.SubIISDeploy + " " + winproto.ArgOp + " " + op},
		callTimeout+winrs.ShellIdleSlack)
	require.NoError(t, err)
	body = bytes.Replace(body, []byte("</rsp:Environment>"),
		[]byte(`<rsp:Variable Name="ALICE_WIN_TEST_KILL_AT">deploy.prepared</rsp:Variable></rsp:Environment>`), 1)
	shell, _ := r.createBody(t, body)
	cmdID := r.command(t, shell, helper, "ssh")
	send, err := winrs.SendRequest(r.header(), shell, cmdID, in, true)
	require.NoError(t, err)
	a := r.post(send, false)
	require.NoError(t, a.err)
	require.Equal(t, http.StatusOK, a.status, "Send: %s", a.fault())
	stdout, _, code, err := r.receive(shell, cmdID)
	require.NoError(t, err)
	r.delete(t, shell)
	if answer := bytes.TrimSpace(stdout); len(answer) > 0 { // a deploy answer holds no key material
		fact(t, "F29", "kill not reached: exit=%d, the helper answered %s", code, answer)
		return
	}
	fact(t, "F29", "killed exit=%d (a helper killed at deploy.prepared answers nothing; winhelper.ExitKilled is %d, wintest.KilledExit 255)",
		code, winhelper.ExitKilled)
}

// helperDataDir makes the helper's data directory (owner Administrators, as the helper requires) when it is
// absent and removes what it made at the end; when it exists (TestRealSetupScript made it), it removes the state
// files this operation writes.
func helperDataDir(t *testing.T, op, canonical string) {
	t.Helper()
	top := "" // the first directory this test makes
	for d := winproto.DataDir; ; {
		if _, err := os.Stat(d); err == nil {
			break
		}
		top = d
		p := filepath.Dir(d)
		if p == d {
			break
		}
		d = p
	}
	if top != "" {
		t.Cleanup(func() {
			if err := os.RemoveAll(top); err != nil {
				t.Errorf("removing %s: %v", top, err)
			}
		})
		require.NoError(t, os.MkdirAll(winproto.DataDir, 0o700))
		out, err := exec.Command("icacls", winproto.DataDir, "/setowner", "*"+adminsSID).CombinedOutput()
		require.NoError(t, err, "icacls /setowner: %s", out)
		t.Logf("made the helper's data directory %s (absent before; %s removed at the end)", winproto.DataDir, top)
		return
	}
	sum := sha256.Sum256([]byte(canonical))
	files := []string{filepath.Join(winproto.DataDir, "journal", op+".json"), filepath.Join(winproto.DataDir, "bindings", hex.EncodeToString(sum[:])+".json")}
	t.Cleanup(func() {
		for _, f := range files {
			if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("removing %s: %v", f, err)
			}
		}
	})
}

func TestRealWinRMAuthOffer(t *testing.T) {
	f := winrmFixture(t)
	for _, k := range slices.Sorted(maps.Keys(f.asFound)) {
		if strings.HasPrefix(k, "Service.") || k == "LmCompatibilityLevel" {
			fact(t, "F30", "%s as found: %s", k, f.asFound[k])
		}
	}
	fact(t, "F30", "the listeners: %s", ps(t, nil, "", `(@(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate | ForEach-Object { "$($_.Address)/$($_.Transport):$($_.Port) enabled=$($_.Enabled)" })) -join ', '`))
	create := func(r *rawConn) []byte {
		b, err := winrs.CreateShellRequest(r.header(), nil, time.Minute)
		require.NoError(t, err)
		return b
	}
	anonymous := func(what string) []string {
		r := newRaw(t, imageAddr, f.spki, account, f.pw)
		a := r.post(create(r), false)
		require.NoError(t, a.err)
		offers := a.header.Values("WWW-Authenticate")
		fact(t, "F30", "%s: an anonymous request answers %d with WWW-Authenticate %q", what, a.status, offers)
		return offers
	}
	anonymous("as the image ships")

	// (a) Negotiate off, Basic on: the listener offers Basic only; the client sends one request, no
	// Authorization, and is refused.
	restoreBasic := setWSMan(t, `Service\Auth\Basic`, "true")
	restoreNegotiate := setWSMan(t, `Service\Auth\Negotiate`, "false")
	offers := anonymous("Negotiate false, Basic true")
	assert.False(t, slices.ContainsFunc(offers, func(o string) bool {
		return strings.HasPrefix(o, "Negotiate") || strings.HasPrefix(o, "NTLM")
	}), "only Basic is offered: %q", offers)
	f.dials.Store(0)
	_, err := run(f.client(t, account), f.helperCall(winproto.SubVersion))
	fact(t, "F30", "(a) the client against a Basic-only offer: %v, %d dial(s)", err, f.dials.Load())
	assert.ErrorIs(t, err, winrs.ErrAuthRefused)
	assert.Equal(t, int32(1), f.dials.Load())
	r := newRaw(t, imageAddr, f.spki, account, f.pw)
	a := r.post(create(r), true)
	fact(t, "F30", "(a) the Negotiator against a Basic-only offer: %d request(s): %v", len(a.reqs), a.reqs)
	if assert.Len(t, a.reqs, 1, "exactly one request") {
		assert.Empty(t, a.reqs[0].auth, "no Authorization header")
	}
	restoreNegotiate()
	restoreBasic()
	offers = anonymous("restored as found")
	require.True(t, slices.ContainsFunc(offers, func(o string) bool { return strings.HasPrefix(o, "Negotiate") }),
		"(b) and (c) run with Negotiate offered again, as found: %q", offers)

	// (b) A wrong password: refused after at most three requests.
	bad := f.client(t, account)
	bad.Password = newPassword(t)
	_, err = run(bad, f.helperCall(winproto.SubVersion))
	fact(t, "F30", "(b) a wrong password: %v", err)
	assert.ErrorIs(t, err, winrs.ErrAuthRefused)
	r = newRaw(t, imageAddr, f.spki, account, newPassword(t))
	a = r.post(create(r), true)
	fact(t, "F30", "(b) a wrong password on the wire: %d request(s): %v", len(a.reqs), a.reqs)
	assert.LessOrEqual(t, len(a.reqs), 3)
	assert.Equal(t, http.StatusUnauthorized, a.status)

	// (c) LmCompatibilityLevel 5 (NTLMv2 only): works.
	restore := setDWORD(t, lsaKey, "LmCompatibilityLevel", 5)
	res, err := run(f.client(t, account), f.helperCall(winproto.SubVersion))
	fact(t, "F30", "(c) LmCompatibilityLevel 5: %s", outcome(res, err))
	assert.NoError(t, err)
	restore()

	// CbtHardeningLevel Strict: logged (go-ntlmssp sends no channel binding, Ruling 31).
	restore = setWSMan(t, `Service\Auth\CbtHardeningLevel`, "Strict")
	res, err = run(f.client(t, account), f.helperCall(winproto.SubVersion))
	fact(t, "F30", "CbtHardeningLevel Strict: %s", outcome(res, err))
	restore()

	// Alice never dials 5985.
	f.dials.Store(0)
	plain := f.helperCall(winproto.SubVersion)
	plain.Addr = "127.0.0.1:5985"
	_, err = run(f.client(t, account), plain)
	assert.ErrorIs(t, err, winrs.ErrBadConfig)
	assert.Zero(t, f.dials.Load(), "port 5985 is refused before any dial")
}

func TestRealWinRMAccountRights(t *testing.T) {
	f := winrmFixture(t)
	sid, _, _, err := windows.LookupSID("", account)
	require.NoError(t, err)
	deny := []string{"SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight"}
	for _, right := range deny {
		grantRight(t, sid, right)
	}
	flags, err := strconv.Atoi(ps(t, map[string]string{"ACCOUNT": account}, "", `[int](([ADSI]"WinNT://$env:COMPUTERNAME/$env:ACCOUNT,user").Get('UserFlags'))`))
	require.NoError(t, err)
	require.NotZero(t, flags&0x10000, "PasswordNeverExpires (DONT_EXPIRE_PASSWORD) is set")

	c := f.client(t, account)
	t0 := time.Now()
	res, err := run(c, f.helperCall(winproto.SubVersion))
	fact(t, "F31", "with %v and PasswordNeverExpires: %s", deny, outcome(res, err))
	require.NoError(t, err)
	for _, right := range deny {
		require.True(t, holds(t, sid, right), "%s was taken away during the call (a concurrent secedit): the result says nothing", right)
	}
	ls := waitLogons(t, t0, 4624)
	for _, l := range ls {
		fact(t, "F31", "Security event of the call: %s", l)
	}
	assert.True(t, slices.ContainsFunc(ls, func(l logon) bool {
		return l.ID == 4624 && l.LogonType == "3" && l.Package == "NTLM" && l.Lm == "NTLM V2"
	}), "a 4624 network logon (type 3), package NTLM, LmPackageName NTLM V2: %v", ls)

	// A wrong password: 4625.
	t1 := time.Now()
	bad := f.client(t, account)
	bad.Password = newPassword(t)
	_, err = run(bad, f.helperCall(winproto.SubVersion))
	assert.ErrorIs(t, err, winrs.ErrAuthRefused)
	for _, l := range waitLogons(t, t1, 4625) {
		fact(t, "F31", "Security event of a wrong password: %s", l)
	}

	// A password change on the server: the old one is refused, the new one works.
	f.pw = newPassword(t)
	setPassword(t, f.pw)
	_, err = run(c, f.helperCall(winproto.SubVersion)) // c holds the old password
	fact(t, "F31", "the old password after the change: %v", err)
	assert.ErrorIs(t, err, winrs.ErrAuthRefused)
	res, err = run(f.client(t, account), f.helperCall(winproto.SubVersion))
	fact(t, "F31", "the new password: %s", outcome(res, err))
	assert.NoError(t, err)

	// "Deny access to this computer from the network" holding S-1-5-114: logged.
	local, err := windows.StringToSid(localAdmSID)
	require.NoError(t, err)
	restore := grantRight(t, local, "SeDenyNetworkLogonRight")
	res, err = run(f.client(t, account), f.helperCall(winproto.SubVersion))
	fact(t, "F31", "with %s in SeDenyNetworkLogonRight: %s", localAdmSID, outcome(res, err))
	restore()

	// Out of Administrators: logged. The fixture deletes the account at the end, so it is not put back.
	require.NoError(t, administrators(t, false))
	res, err = run(f.client(t, account), f.helperCall(winproto.SubVersion))
	fact(t, "F31", "the account out of Administrators: %s", outcome(res, err))
}
