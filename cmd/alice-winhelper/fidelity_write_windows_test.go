//go:build windows

package main

// The fidelity of the write subcommands (W2 Task 9, R61): iis-deploy, iis-restore, iis-status and
// iis-fence run with winhelper's own code against the real helper's host on this machine (http.sys, the
// machine stores, a private data directory) and against the emulator, with the same standard input and
// the same operation ids, and the hosts must agree on:
//   - the exit status and the answer (message dropped; the SHA-1s compare as they are, since both
//     hosts imported the same certificate; built_chain_length compares too);
//   - afterwards, the http.sys record (base and every extended parameter), the journal, the binding
//     record and the import inventory (field by field: they hold no timestamps), and the store entries
//     of the certificates the scenario names (sameState);
//   - the leaf and chain a fresh TLS handshake is served (servedBoth).
//
// The record of each fixture is made with netsh and then read with the helper's own Binding; that
// reading (base and Ex, the store's spelling, the extended parameters' defaults this image reports) is
// a machine fact the model is given, as win-facts' os_build is (the W1 twin compares netsh's base
// fields already, TestFidelityDump*). What is compared is how each host carries the helper's writes out.
//
// W2 Ruling 22: ports 45340-45389 (Task 6 holds 45330-45339), names prefixed alice-w2-, a private data
// directory, every cleanup registered before its fixture is made; zz_runner_clean_windows_test.go
// checks at the end that nothing was left.
//
// The kills of TestFidelityDeployRefusals and TestFidelityStatusAndFence are the test build's hook
// (point_alicetest_windows.go, -tags alicetest): the workflow runs this package with that tag, and
// those tests fail without it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/wintest"
	"alice/internal/testutil/pki"
)

const (
	portW2SNI      = 45340
	portW2IP       = 45341
	portW2KeepIP   = 45342
	portW2KeepSNI  = 45343
	portW2Refuse   = 45344
	portW2Absent   = 45345 // never a record
	portW2Chain    = 45346
	portW2Status   = 45347
	portW2Forbid   = 45348
	portW2Keyless  = 45349
	portW2SiteHTTP = 45389 // the plain http binding of every W2 fixture site (no http.sys SSL record)
	firstW2SiteID  = 45340
)

// testKillEnv is the test build's kill hook (point_alicetest_windows.go's killAtEnv).
const testKillEnv = "ALICE_WIN_TEST_KILL_AT"

// Operation ids of the scenarios (each test has its own data directories, so they repeat across tests).
const (
	op1 = "a1111111-1111-4111-8111-111111111111"
	op2 = "a2222222-2222-4222-8222-222222222222"
	op3 = "a3333333-3333-4333-8333-333333333333"
	op4 = "a4444444-4444-4444-8444-444444444444"
	op5 = "a5555555-5555-4555-8555-555555555555"
	op6 = "a6666666-6666-4666-8666-666666666666"
	op7 = "a7777777-7777-4777-8777-777777777777"
)

// wtwin is the twin of the write subcommands: the real write host on a private data directory.
type wtwin struct {
	*twin
	w    host
	kept []string // the netsh options the last addRecord's record was made with
}

func newWriteTwin(t *testing.T) *wtwin {
	t.Helper()
	tw := newTwin(t)
	tw.siteID, tw.httpPort = firstW2SiteID, portW2SiteHTTP
	w := newHost(newTestDataDir(t))
	tw.real = w
	return &wtwin{twin: tw, w: w}
}

func sum256hex(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// ipLoc and sniLoc are IIS locators on the twin's ports.
func ipLoc(port int) winproto.Locator {
	return winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: port, AppID: winproto.AppIDIIS}
}

func sniLoc(host string, port int) winproto.Locator {
	return winproto.Locator{Type: winproto.BindingHostnamePort, Host: host, Port: port, AppID: winproto.AppIDIIS}
}

func netshKeyOf(l winproto.Locator) string {
	if l.Type == winproto.BindingHostnamePort {
		return "hostnameport=" + l.Host + ":" + strconv.Itoa(l.Port)
	}
	return "ipport=" + l.IP + ":" + strconv.Itoa(l.Port)
}

// addRecord writes an http.sys record naming thumb in My with netsh and these options (when netsh
// refuses, the last option is dropped and it tries again, logged: an older netsh may not know the
// newest), deleted when the test ends (registered first). ex, when set, is written with the helper's
// own Ex write. The model is given the record as the helper reads it.
func (tw *wtwin) addRecord(l winproto.Locator, thumb string, ex *winproto.ExtendedParam, opts ...string) winproto.SSLBinding {
	tw.t.Helper()
	require.True(tw.t, l.Port >= 45340 && l.Port <= 45389, "W2 fixture ports are 45340-45389")
	key := netshKeyOf(l)
	tw.t.Cleanup(func() {
		if out, err := exec.Command("netsh", "http", "delete", "sslcert", key).CombinedOutput(); err != nil {
			tw.t.Logf("cleanup of %s: %v %s", key, err, out)
		}
	})
	args := append([]string{"http", "add", "sslcert", key, "certhash=" + thumb, "appid=" + l.AppID, "certstorename=MY"}, opts...)
	out, err := exec.Command("netsh", args...).CombinedOutput()
	for n := len(opts); n > 0 && err != nil; n-- {
		tw.t.Logf("netsh %v: %v %s; retrying without %s", args, err, out, args[len(args)-1])
		args = args[:len(args)-1]
		out, err = exec.Command("netsh", args...).CombinedOutput()
	}
	require.NoError(tw.t, err, "netsh: %s", out)
	tw.kept = append([]string{}, args[7:]...) // the options netsh took (after http add sslcert key certhash appid certstorename)
	if ex != nil {
		k, err := keyOf(l.Type, l.IP, l.Host, l.Port)
		require.NoError(tw.t, err)
		require.NoError(tw.t, withHTTP(func() error { return writeEx(k, *ex) }), "the fixture's Ex parameter")
	}
	b := tw.readReal(l)
	tw.model.AddBinding(b)
	tw.ports[l.Port] = true
	return b
}

// readReal is the real record by the helper's live read.
func (tw *wtwin) readReal(l winproto.Locator) winproto.SSLBinding {
	tw.t.Helper()
	b, found, err := tw.w.Binding(context.Background(), l)
	require.NoError(tw.t, err)
	require.True(tw.t, found, "the real record %v", l)
	return b
}

// ---- calls on both hosts ------------------------------------------------------------------------

// execOn runs one call on a host; the answer is nil when the call printed nothing (a kill).
func execOn(t *testing.T, h winhelper.Host, stdin []byte, args []string) (winhelper.Outcome, map[string]any) {
	t.Helper()
	var out bytes.Buffer
	o := winhelper.Execute(context.Background(), h, args, bytes.NewReader(stdin), &out)
	if out.Len() == 0 {
		return o, nil
	}
	var m map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(out.Bytes()), &m), "%v: %s", args, out.String())
	delete(m, "message")
	return o, m
}

// call runs the call on both hosts and requires the same exit status and answer; it returns the real
// answer.
func (tw *wtwin) call(stdin []byte, args ...string) map[string]any {
	tw.t.Helper()
	ro, real := execOn(tw.t, tw.w, stdin, args)
	mo, model := execOn(tw.t, tw.model.Host(), stdin, args)
	require.NotNil(tw.t, real, "the real helper answers %v", args)
	require.Equal(tw.t, ro.Exit, mo.Exit, "exit status of %v (real %v, model %v)", args, real, model)
	require.Equal(tw.t, real, model, "answer of %v", args)
	return real
}

// killAt runs the call on both hosts with the helper killed at a crash point: neither answers.
func (tw *wtwin) killAt(point string, stdin []byte, args ...string) {
	tw.t.Helper()
	require.True(tw.t, testKillHook, "this test needs the test build's kill hook: go test -tags alicetest")
	tw.t.Setenv(testKillEnv, point)
	ro, real := execOn(tw.t, tw.w, stdin, args)
	require.NoError(tw.t, os.Unsetenv(testKillEnv))
	tw.model.KillAt(point)
	mo, model := execOn(tw.t, tw.model.Host(), stdin, args)
	assert.True(tw.t, ro.Killed, "the real helper was killed at %s (answer %v)", point, real)
	assert.True(tw.t, mo.Killed, "the model was killed at %s (answer %v)", point, model)
	assert.Nil(tw.t, real)
	assert.Nil(tw.t, model)
	require.Equal(tw.t, ro.Exit, mo.Exit)
}

func deployInput(t *testing.T, l winproto.Locator, chainPEM, keyPEM []byte, expect string) []byte {
	t.Helper()
	b, err := json.Marshal(winproto.DeployInput{Locator: l, ExpectSHA256: expect, ChainPEM: string(chainPEM),
		KeyPEM: string(keyPEM), ForbiddenSPKI: []string{}, ForbiddenLeaf: []string{}})
	require.NoError(t, err)
	return b
}

func restoreInput(t *testing.T, forbiddenLeaf ...string) []byte {
	t.Helper()
	b, err := json.Marshal(winproto.RestoreInput{ForbiddenSPKI: []string{}, ForbiddenLeaf: append([]string{}, forbiddenLeaf...)})
	require.NoError(t, err)
	return b
}

// removeLater removes the chain's leaf (with its key) from My and its intermediates from CA when the
// test ends: registered before a call that may import them.
func (tw *wtwin) removeLater(chainPEM []byte) {
	tw.t.Helper()
	rest := chainPEM
	for i := 0; ; i++ {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return
		}
		c, err := x509.ParseCertificate(block.Bytes)
		require.NoError(tw.t, err)
		thumb := thumbprint(c)
		if i == 0 {
			tw.later(func() { removeCertificate(tw.t, "My", thumb, true) })
		} else {
			tw.later(func() { removeCertificate(tw.t, "CA", thumb, false) })
		}
	}
}

// deploy deploys chainPEM (leaf first) with the leaf's key to l, expecting the record to name the
// certificate whose DER SHA-256 is expect.
func (tw *wtwin) deploy(op string, l winproto.Locator, leaf pki.Leaf, chainPEM []byte, expect string) map[string]any {
	tw.t.Helper()
	tw.removeLater(chainPEM)
	return tw.call(deployInput(tw.t, l, chainPEM, leaf.KeyPEM, expect), winproto.SubIISDeploy, winproto.ArgOp, op)
}

// killDeploy is deploy with the helper killed at point.
func (tw *wtwin) killDeploy(point, op string, l winproto.Locator, leaf pki.Leaf, chainPEM []byte, expect string) {
	tw.t.Helper()
	tw.removeLater(chainPEM)
	tw.killAt(point, deployInput(tw.t, l, chainPEM, leaf.KeyPEM, expect), winproto.SubIISDeploy, winproto.ArgOp, op)
}

func (tw *wtwin) restore(op string, forbiddenLeaf ...string) map[string]any {
	tw.t.Helper()
	return tw.call(restoreInput(tw.t, forbiddenLeaf...), winproto.SubIISRestore, winproto.ArgOp, op)
}

func (tw *wtwin) status(op string) map[string]any {
	tw.t.Helper()
	return tw.call(nil, winproto.SubIISStatus, winproto.ArgOp, op)
}

func (tw *wtwin) fence(op string) map[string]any {
	tw.t.Helper()
	return tw.call(nil, winproto.SubIISFence, winproto.ArgOp, op)
}

// ---- what the hosts hold afterwards ---------------------------------------------------------------

// stateFile decodes a state file of a host (nil when there is none).
func stateFile(t *testing.T, h winhelper.WriteHost, name string) any {
	t.Helper()
	data, found, err := h.ReadState(name)
	require.NoError(t, err, name)
	if !found {
		return nil
	}
	var v any
	require.NoError(t, json.Unmarshal(data, &v), "%s: %s", name, data)
	return v
}

// sameState requires both hosts to hold the same record for l, the same journal of op, binding record
// and import inventory, and the same My entries for these certificates (store names folded, as
// Windows compares them). It returns the real record.
func (tw *wtwin) sameState(op string, l winproto.Locator, certs ...*x509.Certificate) winproto.SSLBinding {
	tw.t.Helper()
	real := tw.readReal(l)
	model, found := tw.model.Binding(l)
	require.True(tw.t, found)
	require.Equal(tw.t, real, model, "the record of %v", l)
	canonical, ok := l.Canonical()
	require.True(tw.t, ok)
	sum := sha256.Sum256([]byte(canonical))
	mh := tw.model.Host()
	for _, n := range []string{"bindings/" + hex.EncodeToString(sum[:]) + ".json", "imports.json", "journal/" + op + ".json"} {
		assert.Equal(tw.t, stateFile(tw.t, tw.w, n), stateFile(tw.t, mh, n), "state file %s", n)
	}
	for _, c := range certs {
		thumb := thumbprint(c)
		rc, rFound, err := tw.w.Certificate(context.Background(), "My", thumb)
		require.NoError(tw.t, err)
		mc, mFound, err := mh.Certificate(context.Background(), "My", thumb)
		require.NoError(tw.t, err)
		require.Equal(tw.t, rFound, mFound, "%s in My", c.Subject.CommonName)
		rc.Store, mc.Store = foldASCII(rc.Store), foldASCII(mc.Store)
		assert.Equal(tw.t, rc, mc, "the store entry of %s", c.Subject.CommonName)
	}
	return real
}

// journalOf is a host's journal of op, decoded (nil when there is none).
func journalOf(t *testing.T, h winhelper.WriteHost, op string) map[string]any {
	t.Helper()
	m, _ := stateFile(t, h, "journal/"+op+".json").(map[string]any)
	return m
}

// served is the DER SHA-256 of each certificate a fresh TLS handshake (no session cache) to addr with
// sni presents, leaf first.
func served(addr, sni string) ([]string, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec // G402: the test compares what is served
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("not a TLS connection")
	}
	var out []string
	for _, c := range tc.ConnectionState().PeerCertificates {
		out = append(out, sum256hex(c.Raw))
	}
	return out, nil
}

// servedBoth waits until the real endpoint (http.sys, once IIS has registered its site's URL) serves
// the leaf want, and requires the model's listener to present the same chain; it returns its length.
func (tw *wtwin) servedBoth(port int, sni, want string) int {
	tw.t.Helper()
	var real []string
	var err error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if real, err = served("127.0.0.1:"+strconv.Itoa(port), sni); err == nil && len(real) > 0 && real[0] == want {
			break
		}
	}
	require.NoError(tw.t, err, "the real endpoint %d (%q) answers", port, sni)
	require.NotEmpty(tw.t, real)
	require.Equal(tw.t, want, real[0], "the real endpoint %d (%q) serves the leaf", port, sni)
	model, err := served(tw.model.Endpoint(port), sni)
	require.NoError(tw.t, err, "the model's endpoint %d", port)
	require.Equal(tw.t, real, model, "the chain served on %d (%q)", port, sni)
	return len(real)
}

// previous is a self-signed certificate with its key in My on both: what a fixture record names first.
func (tw *wtwin) previous(cn string) (pki.Leaf, string) {
	tw.t.Helper()
	leaf := pki.SelfSigned(cn, pki.ECDSA256, time.Now())
	tw.addCertificate("My", leaf)
	return leaf, sum256hex(leaf.Cert.Raw)
}

// fixtureCA issues the deployed leaves; its intermediate is not in LocalMachine\CA (the deployments
// import it, import_chain; deploy registers its removal).
func fixtureCA(name string) *pki.CA { return pki.NewCA(name, pki.ECDSA256, time.Now()) }

func issue(ca *pki.CA, cn string) pki.Leaf {
	return ca.Issue(pki.Opts{CommonName: cn, SANs: []string{cn}}, time.Now())
}

func assertPhase(t *testing.T, got map[string]any, phase string) {
	t.Helper()
	assert.Equal(t, true, got["ok"], "%v", got)
	assert.Equal(t, phase, got["phase"], "%v", got)
}

// ---- the scenarios ----------------------------------------------------------------------------------

func TestFidelityDeploySNIAndIP(t *testing.T) {
	tw := newWriteTwin(t)
	old, oldSum := tw.previous("alice-w2-old.test")
	sni, ip := sniLoc("alice-w2-sni.test", portW2SNI), ipLoc(portW2IP)
	tw.addRecord(sni, thumbprint(old.Cert), nil)
	tw.addRecord(ip, thumbprint(old.Cert), nil)
	tw.addSite("alice-w2-a",
		winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:alice-w2-sni.test", portW2SNI), SSLFlags: 1},
		winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:", portW2IP)})
	tw.serve()
	assert.Equal(t, 1, tw.servedBoth(portW2SNI, "alice-w2-sni.test", oldSum), "positive control: the old certificate first")
	assert.Equal(t, 1, tw.servedBoth(portW2IP, "", oldSum), "positive control: the old certificate first")

	ca := fixtureCA("alice-w2-deploy")
	for _, c := range []struct {
		op   string
		loc  winproto.Locator
		leaf pki.Leaf
		sni  string
	}{
		{op1, sni, issue(ca, "alice-w2-sni.test"), "alice-w2-sni.test"},
		{op2, ip, issue(ca, "alice-w2-ip.test"), ""},
	} {
		got := tw.deploy(c.op, c.loc, c.leaf, c.leaf.FullchainPEM, oldSum)
		assertPhase(t, got, winproto.PhaseCommitted)
		newSum := sum256hex(c.leaf.Cert.Raw)
		assert.Equal(t, newSum, got["new_sha256"])
		assert.Equal(t, thumbprint(c.leaf.Cert), got["new_sha1"])
		assert.Equal(t, oldSum, got["previous_sha256"])
		assert.Equal(t, true, got["alice_imported"])
		assert.EqualValues(t, 2, got["built_chain_length"], "the leaf and the intermediate imported into CA")
		rec := tw.sameState(c.op, c.loc, c.leaf.Cert, old.Cert)
		assert.Equal(t, thumbprint(c.leaf.Cert), rec.CertSHA1)
		// schannel: the leaf and the intermediate imported before the bind (W0 F5), never the root.
		assert.Equal(t, 2, tw.servedBoth(c.loc.Port, c.sni, newSum), "%v", c.loc)
	}
	ev := tw.model.Events()
	require.Len(t, ev, 2, "the model logged both deployments")
	assert.EqualValues(t, 1001, ev[0].ID)
}

// netshShow is "netsh http show sslcert <key>", its lines trimmed (blank ones dropped).
func netshShow(t *testing.T, l winproto.Locator) []string {
	t.Helper()
	out, err := exec.Command("netsh", "http", "show", "sslcert", netshKeyOf(l)).CombinedOutput()
	require.NoError(t, err, "netsh http show sslcert: %s", out)
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	require.NotEmpty(t, lines)
	return lines
}

// linesWith and linesWithout split netsh's lines by whether they name a thumbprint (any case).
func linesWith(lines []string, thumb string) []string {
	var out []string
	for _, l := range lines {
		if strings.Contains(strings.ToLower(l), thumb) { //nolint:forbidigo // hex digits
			out = append(out, l)
		}
	}
	return out
}

func linesWithout(lines []string, thumb string) []string {
	var out []string
	for _, l := range lines {
		if !strings.Contains(strings.ToLower(l), thumb) { //nolint:forbidigo // hex digits
			out = append(out, l)
		}
	}
	return out
}

// keepOpts are netsh's settings beside the certificate (Review Focus 2): client-certificate
// negotiation, revocation values and the TLS 1.3 / legacy TLS flags. A CTL is left out: http.sys refuses
// a record naming a CTL the machine does not hold (W0 F2), and the test makes none.
var keepOpts = []string{"clientcertnegotiation=enable", "verifyclientcertrevocation=disable", "revocationfreshnesstime=3600",
	"urlretrievaltimeout=5000", "disabletls13=enable", "disablelegacytls=enable"}

func TestFidelityDeployKeepsEverySetting(t *testing.T) {
	tw := newWriteTwin(t)
	old, oldSum := tw.previous("alice-w2-keep-old.test")
	ca := fixtureCA("alice-w2-keep")
	window := windowParam(1 << 20)
	for i, loc := range []winproto.Locator{ipLoc(portW2KeepIP), sniLoc("alice-w2-keep.test", portW2KeepSNI)} {
		op := []string{op1, op2}[i]
		before := tw.addRecord(loc, thumbprint(old.Cert), &window, keepOpts...)
		t.Logf("record before (%s): %+v", loc.Type, before)
		// Positive controls: the settings are there to be kept.
		assert.NotZero(t, before.Flags&0x2, "NEGOTIATE_CLIENT_CERT")
		assert.NotZero(t, before.CertCheckMode&1, "no client certificate revocation check")
		assert.EqualValues(t, 3600, before.RevocationFreshnessTime)
		assert.EqualValues(t, 5000, before.URLRetrievalTimeout)
		assert.Contains(t, before.Extended, window, "the HTTP/2 window set by the fixture")
		for opt, bit := range map[string]uint32{"disabletls13=enable": 0x40, "disablelegacytls=enable": 0x400} {
			if slices.Contains(tw.kept, opt) {
				assert.NotZero(t, uint32(before.Flags)&bit, "%s: flag %#x", opt, bit)
			} else {
				t.Logf("this netsh refused %s: its flag is not covered on this image", opt)
			}
		}
		// netsh's own reading of the record, so the helper's reader is not the only judge.
		netshBefore := netshShow(t, loc)

		leaf := issue(ca, "alice-w2-keep.test")
		got := tw.deploy(op, loc, leaf, leaf.FullchainPEM, oldSum)
		assertPhase(t, got, winproto.PhaseCommitted)
		after := tw.sameState(op, loc, leaf.Cert)
		assert.Equal(t, thumbprint(leaf.Cert), after.CertSHA1)
		assert.Empty(t, diffExceptHash(before, after), "every setting but the hash kept: %+v", after)
		netshAfter := netshShow(t, loc)
		assert.Len(t, linesWith(netshAfter, thumbprint(leaf.Cert)), 1, "netsh shows the new hash: %v", netshAfter)
		assert.Equal(t, linesWithout(netshBefore, thumbprint(old.Cert)), linesWithout(netshAfter, thumbprint(leaf.Cert)),
			"netsh shows every setting but the hash as before")

		got = tw.restore(op)
		assertPhase(t, got, winproto.PhaseRestored)
		back := tw.sameState(op, loc, leaf.Cert, old.Cert)
		assert.Equal(t, before, back, "the whole record is back")
		assert.Equal(t, netshBefore, netshShow(t, loc), "netsh shows the record as it was")
	}
}

func TestFidelityDeployRefusals(t *testing.T) {
	tw := newWriteTwin(t)
	old, oldSum := tw.previous("alice-w2-refuse-old.test")
	loc := ipLoc(portW2Refuse)
	tw.addRecord(loc, thumbprint(old.Cert), nil)
	ca := fixtureCA("alice-w2-refuse")
	l1, l2, l3 := issue(ca, "alice-w2-refuse1.test"), issue(ca, "alice-w2-refuse2.test"), issue(ca, "alice-w2-refuse3.test")
	sum1 := sum256hex(l1.Cert.Raw)
	code := func(got map[string]any, want string) {
		t.Helper()
		assert.Equal(t, false, got["ok"], "%v", got)
		assert.Equal(t, want, got["code"], "%v", got)
	}

	code(tw.deploy(op1, loc, l1, l1.FullchainPEM, sum1), winproto.CodeHashMismatch)
	code(tw.deploy(op1, ipLoc(portW2Absent), l1, l1.FullchainPEM, oldSum), winproto.CodeBindingNotFound)
	code(tw.call([]byte(`{"locator":`), winproto.SubIISDeploy, winproto.ArgOp, op1), winproto.CodeBadContent)
	rec := tw.sameState(op1, loc, l1.Cert)
	assert.Equal(t, thumbprint(old.Cert), rec.CertSHA1, "nothing changed")
	assert.Nil(t, journalOf(t, tw.w, op1), "no journal after a refusal")

	assertPhase(t, tw.deploy(op1, loc, l1, l1.FullchainPEM, oldSum), winproto.PhaseCommitted)
	code(tw.deploy(op1, loc, l1, l1.FullchainPEM, oldSum), winproto.CodeOperationExists)

	assertPhase(t, tw.fence(op2), winproto.PhaseFenced)
	code(tw.deploy(op2, loc, l2, l2.FullchainPEM, sum1), winproto.CodeFenced)

	// A deployment killed at deploy.writing (the journal says writing; the record is still l1's).
	tw.killDeploy("deploy.writing", op3, loc, l2, l2.FullchainPEM, sum1)
	rec = tw.sameState(op3, loc, l2.Cert)
	assert.Equal(t, thumbprint(l1.Cert), rec.CertSHA1)
	assert.Equal(t, winproto.PhaseWriting, journalOf(t, tw.w, op3)["phase"])
	got := tw.deploy(op4, loc, l3, l3.FullchainPEM, sum1)
	code(got, winproto.CodeRecoveryPending)
	assert.Equal(t, op3, got["pending_op"])

	// Recovery: the interrupted operation is restored, and the binding is free again.
	assertPhase(t, tw.restore(op3), winproto.PhaseRestored)
	rec = tw.sameState(op3, loc, l1.Cert, l2.Cert)
	assert.Equal(t, thumbprint(l1.Cert), rec.CertSHA1)
	assertPhase(t, tw.deploy(op4, loc, l3, l3.FullchainPEM, sum1), winproto.PhaseCommitted)
	tw.sameState(op4, loc, l3.Cert)
}

func TestFidelityUnchangedAndSameHashWrite(t *testing.T) {
	tw := newWriteTwin(t)
	old, oldSum := tw.previous("alice-w2-chain-old.test")
	loc := ipLoc(portW2Chain)
	tw.addRecord(loc, thumbprint(old.Cert), nil)
	tw.addSite("alice-w2-chain", winproto.SiteBinding{Protocol: "https", Information: fmt.Sprintf("*:%d:", portW2Chain)})
	tw.serve()
	ca := fixtureCA("alice-w2-chain")
	leaf := issue(ca, "alice-w2-chain.test")
	newSum := sum256hex(leaf.Cert.Raw)

	// The leaf alone: its intermediate is nowhere, so the chain built and served is the leaf.
	got := tw.deploy(op1, loc, leaf, leaf.CertPEM, oldSum)
	assertPhase(t, got, winproto.PhaseCommitted)
	assert.EqualValues(t, 1, got["built_chain_length"])
	tw.sameState(op1, loc, leaf.Cert)
	assert.Equal(t, 1, tw.servedBoth(portW2Chain, "", newSum))

	// The same leaf with a new intermediate: imported, and a same-hash write makes schannel build the
	// chain again (W0 F5): served only after it.
	got = tw.deploy(op2, loc, leaf, leaf.FullchainPEM, newSum)
	assertPhase(t, got, winproto.PhaseCommitted)
	assert.EqualValues(t, 2, got["built_chain_length"])
	assert.Equal(t, false, got["alice_imported"], "the leaf is in My from op1")
	tw.sameState(op2, loc, leaf.Cert)
	assert.Len(t, journalOf(t, tw.w, op2)["intermediates_added"], 1)
	assert.Equal(t, 2, tw.servedBoth(portW2Chain, "", newSum))

	// The bound certificate again, nothing new: unchanged, nothing written.
	got = tw.deploy(op3, loc, leaf, leaf.FullchainPEM, newSum)
	assertPhase(t, got, winproto.PhaseUnchanged)
	assert.EqualValues(t, 2, got["built_chain_length"])
	tw.sameState(op3, loc, leaf.Cert)
	assert.Equal(t, 2, tw.servedBoth(portW2Chain, "", newSum))

	// W0 F5 between the import and the write: a leaf of another CA alone (served 1), then the same leaf
	// with its intermediate, the helper killed at deploy.writing: the intermediate is in CA, the record
	// was not written, and schannel still serves the chain it built at the last write.
	ca2 := fixtureCA("alice-w2-chain2")
	m1 := ca2.Issue(pki.Opts{CommonName: "alice-w2-chain.test", SANs: []string{"alice-w2-chain.test"}}, time.Now())
	m1Sum := sum256hex(m1.Cert.Raw)
	assertPhase(t, tw.deploy(op4, loc, m1, m1.CertPEM, newSum), winproto.PhaseCommitted)
	assert.Equal(t, 1, tw.servedBoth(portW2Chain, "", m1Sum))
	tw.killDeploy("deploy.writing", op5, loc, m1, m1.FullchainPEM, m1Sum)
	tw.sameState(op5, loc, m1.Cert)
	assert.Len(t, journalOf(t, tw.w, op5)["intermediates_added"], 1, "the intermediate was imported before the kill")
	assert.Equal(t, 1, tw.servedBoth(portW2Chain, "", m1Sum), "W0 F5: an imported intermediate is not served before a write")
	assertPhase(t, tw.restore(op5), winproto.PhaseRestored) // nothing was written: nothing to put back
	assert.Equal(t, 1, tw.servedBoth(portW2Chain, "", m1Sum))

	// The same certificate again: the intermediate is in CA already (op5 added it), but the binding
	// record's chain was cleared before op5's bind, so it no longer says Alice's last committed bind left
	// this chain served: a same-hash write (committed), and only after it is the intermediate served.
	got = tw.deploy(op6, loc, m1, m1.FullchainPEM, m1Sum)
	assertPhase(t, got, winproto.PhaseCommitted)
	assert.EqualValues(t, 2, got["built_chain_length"])
	assert.Equal(t, false, got["alice_imported"])
	assert.Empty(t, journalOf(t, tw.w, op6)["intermediates_added"], "op5 added it")
	tw.sameState(op6, loc, m1.Cert)
	assert.Equal(t, 2, tw.servedBoth(portW2Chain, "", m1Sum), "the same-hash write makes schannel build the chain again")

	// A write of another leaf of that CA serves it with the chain too.
	m2 := ca2.Issue(pki.Opts{CommonName: "alice-w2-chain.test", SANs: []string{"alice-w2-chain.test"}}, time.Now())
	got = tw.deploy(op7, loc, m2, m2.FullchainPEM, m1Sum)
	assertPhase(t, got, winproto.PhaseCommitted)
	assert.EqualValues(t, 2, got["built_chain_length"])
	tw.sameState(op7, loc, m2.Cert)
	assert.Equal(t, 2, tw.servedBoth(portW2Chain, "", sum256hex(m2.Cert.Raw)))
}

func TestFidelityStatusAndFence(t *testing.T) {
	tw := newWriteTwin(t)
	old, oldSum := tw.previous("alice-w2-status-old.test")
	loc := ipLoc(portW2Status)
	tw.addRecord(loc, thumbprint(old.Cert), nil)
	ca := fixtureCA("alice-w2-status")
	leaf := issue(ca, "alice-w2-status.test")
	newSum := sum256hex(leaf.Cert.Raw)
	status := func(op, phase, current string) {
		t.Helper()
		got := tw.status(op)
		assertPhase(t, got, phase)
		assert.Equal(t, false, got["active"])
		assert.Equal(t, current, got["current_cert_sha256"], "%s %s", op, phase)
		tw.sameState(op, loc, leaf.Cert, old.Cert)
	}

	status(op1, winproto.PhaseNone, "")
	assertPhase(t, tw.deploy(op1, loc, leaf, leaf.FullchainPEM, oldSum), winproto.PhaseCommitted)
	status(op1, winproto.PhaseCommitted, newSum)
	assertPhase(t, tw.restore(op1), winproto.PhaseRestored)
	status(op1, winproto.PhaseRestored, oldSum)
	assertPhase(t, tw.fence(op1), winproto.PhaseRestored) // a finished operation: its status, nothing changed
	status(op1, winproto.PhaseRestored, oldSum)

	// The bound certificate with its key, the store's copy used as it is: the binding record holds no
	// chain of this certificate from a committed bind of Alice's (op1 bound another one, and its restore
	// wrote the record back), so a same-hash write first; the same deployment again is then unchanged.
	got := tw.deploy(op2, loc, old, old.CertPEM, oldSum)
	assertPhase(t, got, winproto.PhaseCommitted)
	assert.Equal(t, false, got["alice_imported"])
	status(op2, winproto.PhaseCommitted, oldSum)
	got = tw.deploy(op7, loc, old, old.CertPEM, oldSum)
	assertPhase(t, got, winproto.PhaseUnchanged)
	assert.Equal(t, false, got["alice_imported"])
	status(op7, winproto.PhaseUnchanged, oldSum)

	// Killed at prepared: the fence hands the binding back and leaves a tombstone.
	tw.killDeploy("deploy.prepared", op3, loc, leaf, leaf.FullchainPEM, oldSum)
	status(op3, winproto.PhasePrepared, oldSum)
	assertPhase(t, tw.fence(op3), winproto.PhaseFenced)
	got = tw.status(op3)
	assertPhase(t, got, winproto.PhaseFenced)
	assert.Equal(t, "", got["current_cert_sha256"], "a tombstone names no binding")
	tw.sameState(op3, loc)
	got = tw.deploy(op3, loc, leaf, leaf.FullchainPEM, oldSum)
	assert.Equal(t, winproto.CodeFenced, got["code"])

	// Killed at writing: restored by iis-restore without a write.
	tw.killDeploy("deploy.writing", op4, loc, leaf, leaf.FullchainPEM, oldSum)
	status(op4, winproto.PhaseWriting, oldSum)
	assertPhase(t, tw.restore(op4), winproto.PhaseRestored)
	status(op4, winproto.PhaseRestored, oldSum)

	// A restore killed at restore.restoring, then sent again.
	assertPhase(t, tw.deploy(op5, loc, leaf, leaf.FullchainPEM, oldSum), winproto.PhaseCommitted)
	tw.killAt("restore.restoring", restoreInput(t), winproto.SubIISRestore, winproto.ArgOp, op5)
	status(op5, winproto.PhaseRestoring, newSum)
	assertPhase(t, tw.restore(op5), winproto.PhaseRestored)
	status(op5, winproto.PhaseRestored, oldSum)

	// A fence of an operation the helper never saw: its later deployment is FENCED.
	assertPhase(t, tw.fence(op6), winproto.PhaseFenced)
	got = tw.deploy(op6, loc, leaf, leaf.FullchainPEM, oldSum)
	assert.Equal(t, winproto.CodeFenced, got["code"])
	rec := tw.sameState(op6, loc, leaf.Cert, old.Cert)
	assert.Equal(t, thumbprint(old.Cert), rec.CertSHA1)
}

// TestRealRestoreForbidden: the helper itself refuses a restore the rollback guard forbids (design §13
// W2 item 3, Review Focus 3), on the real machine as on the model; the guard only grows, so a restore
// re-sent without lists stays forbidden, and an unforbidden restore of a later deployment restores.
func TestRealRestoreForbidden(t *testing.T) {
	tw := newWriteTwin(t)
	old, oldSum := tw.previous("alice-w2-forbid-old.test")
	loc := ipLoc(portW2Forbid)
	tw.addRecord(loc, thumbprint(old.Cert), nil)
	ca := fixtureCA("alice-w2-forbid")
	l1, l2 := issue(ca, "alice-w2-forbid1.test"), issue(ca, "alice-w2-forbid2.test")

	assertPhase(t, tw.deploy(op1, loc, l1, l1.FullchainPEM, oldSum), winproto.PhaseCommitted)
	got := tw.restore(op1, oldSum)
	assertPhase(t, got, winproto.PhaseRestoreForbidden)
	assert.Equal(t, winproto.ErrForbidden, got["error"])
	rec := tw.sameState(op1, loc, l1.Cert, old.Cert)
	assert.Equal(t, thumbprint(l1.Cert), rec.CertSHA1, "the binding still names the new certificate")

	assertPhase(t, tw.restore(op1), winproto.PhaseRestoreForbidden)
	rec = tw.sameState(op1, loc, l1.Cert, old.Cert)
	assert.Equal(t, thumbprint(l1.Cert), rec.CertSHA1, "the guard only grows: still the new certificate")

	assertPhase(t, tw.deploy(op2, loc, l2, l2.FullchainPEM, sum256hex(l1.Cert.Raw)), winproto.PhaseCommitted)
	assertPhase(t, tw.restore(op2), winproto.PhaseRestored)
	rec = tw.sameState(op2, loc, l1.Cert, l2.Cert)
	assert.Equal(t, thumbprint(l1.Cert), rec.CertSHA1, "a restore without lists restores")
}

func TestFidelityKeyUnusable(t *testing.T) {
	tw := newWriteTwin(t)
	old, oldSum := tw.previous("alice-w2-keyless-old.test")
	loc := ipLoc(portW2Keyless)
	tw.addRecord(loc, thumbprint(old.Cert), nil)
	leaf := issue(fixtureCA("alice-w2-keyless"), "alice-w2-keyless.test")
	// The certificate in My without its key (the test's own import), on both.
	tw.importCER("My", leaf.Cert.Raw, thumbprint(leaf.Cert))
	tw.model.AddCertificate("My", leaf.CertPEM, nil, wintest.CertOptions{})
	tw.removeLater(leaf.CertPEM) // with its key, should the helper ever attach one

	got := tw.call(deployInput(t, loc, leaf.CertPEM, leaf.KeyPEM, oldSum), winproto.SubIISDeploy, winproto.ArgOp, op1)
	assert.Equal(t, winproto.CodeKeyUnusable, got["code"], "%v", got)
	rec := tw.sameState(op1, loc, leaf.Cert, old.Cert)
	assert.Equal(t, thumbprint(old.Cert), rec.CertSHA1, "nothing changed")
	assert.Nil(t, journalOf(t, tw.w, op1))
}
