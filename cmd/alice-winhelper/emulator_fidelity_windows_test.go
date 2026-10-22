//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

// The fidelity test (design 2026-10-21 §13, R60 Task 11): the same scenario runs against the real
// helper on this Windows machine (newHost: http.sys, the machine stores, appcmd, the network) and
// against the emulated machine of internal/providers/windows/wintest, and every answer is compared:
// exit status, error code and the whole answer. Both run winhelper's own code, so what is compared is
// the hosts' readings. The helper is the specification: a difference means the emulator is wrong.
//
// Each fixture is made on both machines by one mirrored helper (addCertificate, addIntermediate,
// addBinding, addSite, removeCertificate, dropKey): PowerShell, netsh and appcmd change the real
// machine (tests only; the helper runs none of them), the Model's setters change the emulated one.
//
// What is normalised, because it is the machine's and not the fixtures':
//   - the real http.sys table holds the runner image's records (about 100 IIS Express entries on
//     0.0.0.0:44300-44399 and the WinRM listener on 0.0.0.0:5986, W0 F2), its sites ("Default Web
//     Site") and their certificates: a dump is filtered to the twin's own ports (45300-45399), its own
//     sites (alice-w1-*) and the certificates its bindings name;
//   - win-facts' os_build, os_product and openssh_version are copied from the real answer into the
//     model's (TestRealOSFactsMatchTheRegistryReadIndependently checks them against an independent
//     reading, and the workflow requires it to pass; OpenSSH may be installed meanwhile by
//     TestRealSetupScript, which runs in another package at the same time);
//   - the model's installation type, IIS facts and expired counts are set from independent PowerShell
//     readings of this machine (Get-ItemProperty, the XML of redirection.config, Get-ScheduledTask,
//     Get-ChildItem Cert:), so the helper's own reading is compared;
//   - store names of bindings compare without case (http.sys answers MY and My for one store, W0 F2),
//     and so do those of certificates, which carry the spelling of the first binding naming them
//     (winhelper.BuildDump); the store list of win-facts is compared as it is, in the helper's order;
//   - the model's records carry netsh's documented defaults for what the twin does not set (no flags,
//     check mode 0, freshness 0, URL timeout 0: netshDefaults), so the helper's reading of them is
//     compared too;
//   - message is dropped (fixed texts on both sides, but not part of the protocol).

// fixturePorts are the ports of the twin's http.sys records and IIS bindings (W0: the runner images
// use 44300-44399 for IIS Express, so the fixtures never do). The other real tests of this package use
// 45301-45304.
const (
	portSNI      = 45310
	portIP       = 45311
	portNoEntry  = 45312
	portHosting  = 45313
	portForeign  = 45314
	portRemoved  = 45315
	portKeyless  = 45316
	portProbe    = 45320
	portSiteHTTP = 45399 // the plain http binding every fixture site is created with
	firstSiteID  = 45301
)

const appIDWinRM = "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}"

type twin struct {
	t       *testing.T
	real    winhelper.Host
	model   *wintest.Model
	cleanup []func()

	ports  map[int]bool
	sites  map[string]bool
	siteID int64
	webDir string
}

// newTwin is the real machine and a fresh model with the same IIS facts and expired counts. Its
// fixtures are removed when the test ends, in reverse order.
func newTwin(t *testing.T) *twin {
	t.Helper()
	requireReal(t)
	tw := &twin{t: t, real: newHost(), model: wintest.NewModel(), ports: map[int]bool{}, sites: map[string]bool{},
		siteID: firstSiteID}
	t.Cleanup(func() {
		for i := len(tw.cleanup) - 1; i >= 0; i-- {
			tw.cleanup[i]()
		}
	})
	// The model has My, WebHosting, CA and Root; IIS creates WebHosting, and this makes sure of it.
	powershell(t, `$s = New-Object System.Security.Cryptography.X509Certificates.X509Store('WebHosting', 'LocalMachine'); `+
		`$s.Open('ReadWrite'); $s.Close()`)
	tw.model.SetIIS(independentIISFacts(t))
	// Only the installation type of the model's OS facts is compared (see the top of the file).
	tw.model.SetOS(winhelper.OSFacts{InstallationType: strings.TrimSpace(string(powershell(t,
		`(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType`)))})
	for store, n := range independentExpired(t) {
		tw.model.SetExpired(store, n)
	}
	return tw
}

// independentIISFacts reads IIS's facts with PowerShell, not with the helper's code.
func independentIISFacts(t *testing.T) winproto.IISFacts {
	t.Helper()
	out := powershell(t, `$k = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\InetStp'
$shared = $false
$r = Join-Path $env:windir 'System32\inetsrv\config\redirection.config'
if (Test-Path -LiteralPath $r) {
    [xml]$x = Get-Content -LiteralPath $r -Raw
    $n = $x.SelectSingleNode('/configuration/configurationRedirection')
    if ($n -and "$($n.GetAttribute('enabled'))" -eq 'true') { $shared = $true }
}
$ccs = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider' -ErrorAction SilentlyContinue
$ccsEnabled = $false; $ccsPath = ''
if ($ccs) {
    if ($ccs.PSObject.Properties['Enabled'] -and [int]$ccs.Enabled -ne 0) { $ccsEnabled = $true }
    if ($ccs.PSObject.Properties['CertStoreLocation']) { $ccsPath = [string]$ccs.CertStoreLocation }
}
$task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\CertificateServicesClient\' -TaskName AutoCertRebind -ErrorAction SilentlyContinue
$rebind = [bool]($task -and "$($task.State)" -ne 'Disabled')
@{ installed = $true; version = "$($k.MajorVersion).$($k.MinorVersion)"; shared_config = $shared; ccs_enabled = $ccsEnabled
   ccs_path = $ccsPath; autocertrebind = $rebind } | ConvertTo-Json -Compress`)
	var f winproto.IISFacts
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(out), &f), string(out))
	return f
}

// independentExpired counts the expired certificates of My and WebHosting with PowerShell.
func independentExpired(t *testing.T) map[string]int {
	t.Helper()
	out := powershell(t, `$now = Get-Date
$r = @{}
foreach ($s in @('My', 'WebHosting')) {
    $p = "Cert:\LocalMachine\$s"
    $n = 0
    if (Test-Path -LiteralPath $p) { $n = @(Get-ChildItem -LiteralPath $p | Where-Object { $_.NotAfter -lt $now }).Count }
    $r[$s] = $n
}
$r | ConvertTo-Json -Compress`)
	var m map[string]int
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(out), &m), string(out))
	return m
}

// ---- running a command on both -----------------------------------------------------------------

// runOn runs one call on a host and decodes its one JSON line.
func runOn(t *testing.T, h winhelper.Host, args []string) (int, map[string]any) {
	t.Helper()
	var out bytes.Buffer
	code := winhelper.Run(context.Background(), h, args, nil, &out)
	var m map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(out.Bytes()), &m), "%v: %s", args, out.String())
	return code, m
}

// same runs the call on both machines, normalises the answers and requires the same exit status and
// the same answer; it returns the real (normalised) answer.
func (tw *twin) same(args ...string) map[string]any {
	tw.t.Helper()
	realCode, real := runOn(tw.t, tw.real, args)
	modelCode, model := runOn(tw.t, tw.model.Host(), args)
	tw.normalize(args[0], real, model)
	require.Equal(tw.t, realCode, modelCode, "exit status of %v (real %v, model %v)", args, real, model)
	require.Equal(tw.t, real, model, "answer of %v", args)
	return real
}

func (tw *twin) normalize(sub string, real, model map[string]any) {
	for _, m := range []map[string]any{real, model} {
		delete(m, "message")
	}
	if real["ok"] != true || model["ok"] != true {
		return
	}
	switch sub {
	case winproto.SubWinFacts:
		for _, k := range []string{"os_build", "os_product", "openssh_version"} {
			model[k] = real[k]
		}
	case winproto.SubIISDump:
		for _, m := range []map[string]any{real, model} {
			tw.filterDump(m)
		}
	}
}

// filterDump keeps the twin's own records, sites and certificates, with store names folded.
func (tw *twin) filterDump(m map[string]any) {
	named := map[string]bool{}
	bindings := []map[string]any{}
	for _, b := range asList(m["bindings"]) {
		port, _ := b["port"].(float64)
		if !tw.ports[int(port)] {
			continue
		}
		b["store"] = foldASCII(asString(b["store"]))
		if s := asString(b["cert_sha1"]); s != "" {
			named[s] = true
		}
		bindings = append(bindings, b)
	}
	key := func(b map[string]any) string {
		return fmt.Sprintf("%s|%s|%s|%v", b["type"], b["ip"], b["host"], b["port"])
	}
	sort.Slice(bindings, func(i, j int) bool { return key(bindings[i]) < key(bindings[j]) })
	certs := []map[string]any{}
	for _, c := range asList(m["certificates"]) {
		if named[asString(c["sha1"])] {
			c["store"] = foldASCII(asString(c["store"])) // the spelling of the binding that names it
			certs = append(certs, c)
		}
	}
	sites := []map[string]any{}
	for _, s := range asList(m["sites"]) {
		if tw.sites[asString(s["name"])] {
			sites = append(sites, s)
		}
	}
	sort.Slice(sites, func(i, j int) bool { return asString(sites[i]["name"]) < asString(sites[j]["name"]) })
	m["bindings"], m["certificates"], m["sites"] = anyList(bindings), anyList(certs), anyList(sites)
}

func asList(v any) []map[string]any {
	out := []map[string]any{}
	l, _ := v.([]any)
	for _, x := range l {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func anyList(l []map[string]any) []any {
	out := make([]any, 0, len(l))
	for _, m := range l {
		out = append(out, m)
	}
	return out
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// foldASCII folds ASCII upper case letters (store names compare so on Windows).
func foldASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// upperASCII is a thumbprint as the Cert: drive spells it.
func upperASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, s)
}

// ---- mirrored changes to the two machines ------------------------------------------------------

func (tw *twin) later(f func()) { tw.cleanup = append(tw.cleanup, f) }

// addCertificate imports a leaf with its key into LocalMachine\<store> through a PFX
// (Import-PfxCertificate, non-exportable, as an administrator does; W0 F4: the software KSP) with its
// common name as friendly name, and adds it to the model's store alike. It returns the thumbprint.
func (tw *twin) addCertificate(store string, leaf pki.Leaf) string {
	tw.t.Helper()
	name := leaf.Cert.Subject.CommonName
	pw := make([]byte, 16)
	_, err := rand.Read(pw)
	require.NoError(tw.t, err)
	password := hex.EncodeToString(pw)
	pfx, err := pkcs12.Modern2023.Encode(leaf.Key, leaf.Cert, nil, password)
	require.NoError(tw.t, err)
	file := filepath.Join(tw.t.TempDir(), "leaf.pfx")
	require.NoError(tw.t, os.WriteFile(file, pfx, 0o600))
	thumb := thumbprint(leaf.Cert)
	tw.later(func() { removeCertificate(tw.t, store, upperASCII(thumb), true) })
	powershellEnv(tw.t, map[string]string{"ALICE_W1_FILE": file, "ALICE_W1_PASSWORD": password, "ALICE_W1_STORE": store,
		"ALICE_W1_NAME": name, "ALICE_W1_THUMB": upperASCII(thumb)},
		`$pw = ConvertTo-SecureString -String $env:ALICE_W1_PASSWORD -AsPlainText -Force; `+
			`Import-PfxCertificate -FilePath $env:ALICE_W1_FILE -CertStoreLocation "Cert:\LocalMachine\$env:ALICE_W1_STORE" -Password $pw | Out-Null; `+
			`$c = Get-Item -LiteralPath "Cert:\LocalMachine\$env:ALICE_W1_STORE\$env:ALICE_W1_THUMB"; $c.FriendlyName = $env:ALICE_W1_NAME`)
	got := tw.model.AddCertificate(store, leaf.CertPEM, leaf.KeyPEM, wintest.CertOptions{FriendlyName: name})
	require.Equal(tw.t, thumb, got)
	return thumb
}

// addIntermediate puts the CA's intermediate into LocalMachine\CA on both. W0 F5: schannel serves the
// chain it built when the record was written, so this comes before addBinding.
func (tw *twin) addIntermediate(ca *pki.CA) {
	tw.t.Helper()
	tw.importCER("CA", ca.Intermediate.Raw, thumbprint(ca.Intermediate))
	tw.model.AddIntermediate(ca.IntermediatePEM)
}

// importCER adds a certificate without a key to a machine store (Import-Certificate).
func (tw *twin) importCER(store string, der []byte, thumb string) {
	tw.t.Helper()
	file := filepath.Join(tw.t.TempDir(), "cert.cer")
	require.NoError(tw.t, os.WriteFile(file, der, 0o600))
	tw.later(func() { removeCertificate(tw.t, store, upperASCII(thumb), false) })
	powershellEnv(tw.t, map[string]string{"ALICE_W1_FILE": file, "ALICE_W1_STORE": store},
		`Import-Certificate -FilePath $env:ALICE_W1_FILE -CertStoreLocation "Cert:\LocalMachine\$env:ALICE_W1_STORE" | Out-Null`)
}

// removeCertificate deletes a certificate from a store on both (certutil -delstore on the machine);
// the binding naming it stays.
func (tw *twin) removeCertificate(store, sha1 string) {
	tw.t.Helper()
	out, err := exec.Command("certutil", "-delstore", store, sha1).CombinedOutput()
	require.NoError(tw.t, err, "certutil -delstore %s %s: %s", store, sha1, out)
	tw.model.RemoveCertificate(store, sha1)
}

// dropKey leaves the certificate in its store without its key: the certificate is deleted, then
// imported again alone (same thumbprint, no key provider information: the key is no longer the
// certificate's). W0 F2/F4: http.sys refuses to bind a certificate without a usable key, so the record
// is written first and the key goes afterwards. The orphaned CNG key stays on the runner.
func (tw *twin) dropKey(store string, leaf pki.Leaf) {
	tw.t.Helper()
	thumb := thumbprint(leaf.Cert)
	powershellEnv(tw.t, map[string]string{"ALICE_W1_STORE": store, "ALICE_W1_THUMB": upperASCII(thumb)},
		`Remove-Item -LiteralPath "Cert:\LocalMachine\$env:ALICE_W1_STORE\$env:ALICE_W1_THUMB"`)
	tw.importCER(store, leaf.Cert.Raw, thumb)
	tw.model.RemoveCertificate(store, thumb)
	tw.model.AddCertificate(store, leaf.CertPEM, nil, wintest.CertOptions{})
}

// sslKey is netsh's name of a record.
func sslKey(b winproto.SSLBinding) string {
	if b.Type == winproto.BindingHostnamePort {
		return "hostnameport=" + b.Host + ":" + strconv.Itoa(b.Port)
	}
	return "ipport=" + b.IP + ":" + strconv.Itoa(b.Port)
}

// netshDefaults gives a record the settings "netsh http add sslcert" writes when only certhash, appid
// and certstorename are named (netsh's documented defaults: verifyclientcertrevocation enable,
// verifyrevocationwithcachedclientcertonly disable, usagecheck enable, revocationfreshnesstime 0,
// urlretrievaltimeout 0, no CTL, dsmapperusage and clientcertnegotiation disable, the later
// disable* options not set): DefaultCertCheckMode 0, freshness 0, URL timeout 0, DefaultFlags 0.
func netshDefaults(b winproto.SSLBinding) winproto.SSLBinding {
	b.Flags, b.CertCheckMode, b.RevocationFreshnessTime, b.URLRetrievalTimeout = 0, 0, 0, 0
	b.CTLIdentifier, b.CTLStore = "", ""
	return b
}

// addBinding writes an http.sys record with netsh (checked with netsh show, not with the helper's
// reading) and the same record, with netsh's defaults, into the model.
func (tw *twin) addBinding(b winproto.SSLBinding) {
	tw.t.Helper()
	require.True(tw.t, b.Port >= 45300 && b.Port <= 45399, "fixture ports are 45300-45399")
	addSSLCertIn(tw.t, sslKey(b), b.CertSHA1, b.AppID, b.Store)
	out, err := exec.Command("netsh", "http", "show", "sslcert", sslKey(b)).CombinedOutput()
	require.NoError(tw.t, err, "netsh http show sslcert %s: %s", sslKey(b), out)
	require.Contains(tw.t, strings.ToLower(string(out)), b.CertSHA1, "netsh wrote %s", sslKey(b)) //nolint:forbidigo // hex digits
	tw.model.AddBinding(netshDefaults(b))
	tw.ports[b.Port] = true
}

// addSSLCertIn is netsh http add sslcert with the store named, deleted when the test ends.
func addSSLCertIn(t *testing.T, key, thumb, appID, store string) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := exec.Command("netsh", "http", "delete", "sslcert", key).CombinedOutput(); err != nil {
			t.Logf("cleanup of %s: %v %s", key, err, out)
		}
	})
	netsh(t, "add", "sslcert", key, "certhash="+thumb, "appid="+appID, "certstorename="+store)
}

func appcmdPath() string {
	return filepath.Join(os.Getenv("SystemRoot"), "system32", "inetsrv", "appcmd.exe")
}

// addSite creates a started IIS site with these https bindings on both. The real site is created with
// a plain http binding on portSiteHTTP (appcmd's add takes no sslFlags); the helper lists https
// bindings only, so the model's site has none.
func (tw *twin) addSite(name string, bindings ...winproto.SiteBinding) {
	tw.t.Helper()
	require.True(tw.t, strings.HasPrefix(name, "alice-w1-"))
	if tw.webDir == "" {
		tw.webDir = filepath.Join(os.Getenv("SystemDrive")+`\`, "inetpub", "alice-w1-fidelity")
		require.NoError(tw.t, os.MkdirAll(tw.webDir, 0o750))
		dir := tw.webDir
		tw.later(func() { _ = os.RemoveAll(dir) }) // after the sites (reverse order)
	}
	id := tw.siteID
	tw.siteID++
	tw.later(func() {
		if out, err := exec.Command(appcmdPath(), "delete", "site", name).CombinedOutput(); err != nil {
			tw.t.Logf("cleanup of site %s: %v %s", name, err, out)
		}
	})
	appcmd(tw.t, "add", "site", "/name:"+name, "/id:"+strconv.FormatInt(id, 10), "/physicalPath:"+tw.webDir,
		"/bindings:http/*:"+strconv.Itoa(portSiteHTTP)+":"+name+".invalid")
	for _, b := range bindings {
		appcmd(tw.t, "set", "site", "/site.name:"+name, fmt.Sprintf("/+bindings.[protocol='https',bindingInformation='%s',sslFlags='%d']",
			b.Information, b.SSLFlags))
	}
	_ = exec.Command(appcmdPath(), "start", "site", "/site.name:"+name).Run() // "already started" is not an error here
	state := ""
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		out, _ := exec.Command(appcmdPath(), "list", "site", name, "/text:state").Output()
		if state = strings.TrimSpace(string(out)); state == "Started" {
			break
		}
	}
	require.Equal(tw.t, "Started", state, "site %s", name)
	tw.model.AddSite(winproto.Site{Name: name, ID: id, State: "Started", Bindings: bindings})
	tw.sites[name] = true
}

// serve starts the model's TLS listeners for its records (the real machine's are http.sys).
func (tw *twin) serve() {
	tw.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(tw.t, tw.model.Serve(ctx, "127.0.0.1:0"))
	tw.later(cancel)
}

// ---- the scenarios -------------------------------------------------------------------------------

func TestFidelityVersionAndRefusals(t *testing.T) {
	tw := newTwin(t)
	for _, c := range []struct {
		args []string
		code string
	}{
		{[]string{winproto.SubVersion}, ""},
		{[]string{winproto.SubVersion, "x"}, winproto.CodeUsage},
		{[]string{"iis-deploy"}, winproto.CodeUnknownSubcommand},
		{[]string{winproto.SubTLSProbe, "--addr"}, winproto.CodeUsage},
	} {
		got := tw.same(c.args...)
		if c.code == "" {
			assert.Equal(t, true, got["ok"], "%v", c.args)
			assert.EqualValues(t, winproto.Protocol, got["protocol"])
			continue
		}
		assert.Equal(t, c.code, got["code"], "%v", c.args)
	}
}

func TestFidelityWinFacts(t *testing.T) {
	tw := newTwin(t)
	got := tw.same(winproto.SubWinFacts)
	assert.Equal(t, true, got["elevated"], "the runner's token is elevated")
	iis, _ := got["iis"].(map[string]any)
	assert.Equal(t, true, iis["installed"], "the workflow installs IIS")
	assert.Equal(t, []any{"My", "WebHosting", "CA", "Root"}, got["stores"], "the helper's order")
	assert.NotEmpty(t, got["installation_type"])
}

// fidelityCA issues the twin's leaves; its intermediate is in LocalMachine\CA (addIntermediate).
func fidelityCA(t *testing.T, tw *twin, name string) func(cn string) pki.Leaf {
	t.Helper()
	now := time.Now()
	ca := pki.NewCA(name, pki.ECDSA256, now)
	tw.addIntermediate(ca)
	return func(cn string) pki.Leaf { return ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, now) }
}

func TestFidelityDumpSNIAndIPBindings(t *testing.T) {
	tw := newTwin(t)
	issue := fidelityCA(t, tw, "alice-w1-fidelity")
	sni := tw.addCertificate("My", issue("alice-w1-sni.test"))
	ip := tw.addCertificate("My", issue("alice-w1-ip.test"))
	hosting := tw.addCertificate("WebHosting", issue("alice-w1-hosting.test"))
	foreign := tw.addCertificate("My", pki.SelfSigned("alice-w1-foreign.test", pki.ECDSA256, time.Now()))

	tw.addBinding(winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: "alice-w1-sni.test", Port: portSNI,
		AppID: winproto.AppIDIIS, CertSHA1: sni, Store: "My"})
	tw.addBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: portIP, AppID: winproto.AppIDIIS,
		CertSHA1: ip, Store: "My"})
	tw.addBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: portHosting, AppID: winproto.AppIDIIS,
		CertSHA1: hosting, Store: "WebHosting"})
	tw.addBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: portForeign, AppID: appIDWinRM,
		CertSHA1: foreign, Store: "My"})
	tw.addSite("alice-w1-a",
		winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:alice-w1-sni.test", portSNI), SSLFlags: 1},
		winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:", portIP)})
	tw.addSite("alice-w1-b",
		winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:", portNoEntry)}, // an IIS binding without an entry
		winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:", portHosting)})

	got := tw.same(winproto.SubIISDump)
	// Positive controls: the filtered dump holds every fixture, so the comparison compared something.
	require.Len(t, asList(got["bindings"]), 4)
	certs := asList(got["certificates"])
	require.Len(t, certs, 4)
	require.Len(t, asList(got["sites"]), 2)
	for _, c := range certs {
		assert.Equal(t, true, c["has_key"], "%v", c["sha1"])
		assert.Equal(t, true, c["key_usable_by_system"], "%v", c["sha1"])
		if c["sha1"] != foreign {
			assert.Len(t, c["chain"], 1, "the intermediate from LocalMachine\\CA, root excluded")
		}
	}
}

func TestFidelityDumpCertificateRemoved(t *testing.T) {
	tw := newTwin(t)
	issue := fidelityCA(t, tw, "alice-w1-removed")
	thumb := tw.addCertificate("My", issue("alice-w1-removed.test"))
	// W0 F2: http.sys binds only a certificate that is there, so the record comes first.
	tw.addBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: portRemoved, AppID: winproto.AppIDIIS,
		CertSHA1: thumb, Store: "My"})
	tw.addSite("alice-w1-c", winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:", portRemoved)})
	before := tw.same(winproto.SubIISDump)
	require.Len(t, asList(before["certificates"]), 1)

	tw.removeCertificate("My", thumb)
	after := tw.same(winproto.SubIISDump)
	bindings := asList(after["bindings"])
	require.Len(t, bindings, 1, "the record stays")
	assert.Equal(t, thumb, bindings[0]["cert_sha1"])
	assert.Empty(t, asList(after["certificates"]), "the certificate is gone (cert_missing, Alice-side)")
}

func TestFidelityDumpKeyMissing(t *testing.T) {
	tw := newTwin(t)
	issue := fidelityCA(t, tw, "alice-w1-keyless")
	leaf := issue("alice-w1-keyless.test")
	thumb := tw.addCertificate("My", leaf)
	tw.addBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: portKeyless, AppID: winproto.AppIDIIS,
		CertSHA1: thumb, Store: "My"})
	tw.dropKey("My", leaf)
	got := tw.same(winproto.SubIISDump)
	certs := asList(got["certificates"])
	require.Len(t, certs, 1)
	assert.Equal(t, false, certs[0]["has_key"])
	assert.Equal(t, "key_missing", certs[0]["key_problem"])
	assert.Nil(t, certs[0]["key_usable_by_system"])
}

func TestFidelityTLSProbe(t *testing.T) {
	tw := newTwin(t)
	issue := fidelityCA(t, tw, "alice-w1-probe") // before the record: W0 F5
	leaf := issue("alice-w1.test")
	thumb := tw.addCertificate("My", leaf)
	tw.addBinding(winproto.SSLBinding{Type: winproto.BindingHostnamePort, Host: "alice-w1.test", Port: portProbe,
		AppID: winproto.AppIDIIS, CertSHA1: thumb, Store: "My"})
	tw.addSite("alice-w1-probe", winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:alice-w1.test", portProbe), SSLFlags: 1})
	tw.serve()

	args := []string{winproto.SubTLSProbe, "--addr", "127.0.0.1", "--port", strconv.Itoa(portProbe), "--sni", "alice-w1.test", "--key-type", "any"}
	// http.sys listens once IIS has registered the site's URL; wait for the first handshake.
	var code int
	var last map[string]any
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if code, last = runOn(t, tw.real, args); code == winproto.ExitOK {
			break
		}
	}
	require.Equal(t, winproto.ExitOK, code, "the real endpoint answers: %v", last)

	got := tw.same(args...)
	sum := sha256.Sum256(leaf.Cert.Raw)
	assert.Equal(t, hex.EncodeToString(sum[:]), got["leaf_sha256"])
	assert.EqualValues(t, 2, got["chain_length"], "W0 F5: the leaf and the intermediate, never the root")
	chain, _ := got["chain"].([]any)
	require.Len(t, chain, 2)
	assert.NotEqual(t, chain[0], chain[1])
}
