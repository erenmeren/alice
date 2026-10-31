package wintest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	ntlmssp "github.com/Azure/go-ntlmssp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/winrs"
	"alice/internal/testutil/pki"
)

// winrmEnv is the demo host with a WinRM account and a test WinRM listener.
type winrmEnv struct {
	m        *Model
	s        *WinRMServer
	password string
}

func newWinRMEnv(t *testing.T) *winrmEnv {
	t.Helper()
	m, err := Demo(time.Now())
	require.NoError(t, err)
	e := &winrmEnv{m: m, password: winrmPassword(t)}
	m.SetWinRMAccount("alice", e.password)
	e.s = NewWinRMServer(t, m)
	return e
}

// winrmPassword is a password made now (never a literal in a test).
func winrmPassword(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return "Pw-" + hex.EncodeToString(b)
}

// pinTo accepts exactly the listener's SPKI.
func pinTo(spki []byte) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, //nolint:gosec // G402: VerifyConnection pins the SPKI
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].RawSubjectPublicKeyInfo, spki) {
				return errors.New("not the pinned listener")
			}
			return nil
		}}
}

func (e *winrmEnv) client(user, password string) *winrs.Client {
	return &winrs.Client{TLS: pinTo(e.s.SPKI), User: user, Password: password}
}

func (e *winrmEnv) call(line string, stdin []byte) winrs.Call {
	return winrs.Call{Addr: e.s.Addr, Program: winproto.HelperPath, Args: []string{"ssh"},
		Env: map[string]string{"SSH_ORIGINAL_COMMAND": line}, Stdin: stdin, Timeout: 30 * time.Second, MaxOutput: 1 << 20}
}

func (e *winrmEnv) run(t *testing.T, line string, stdin []byte) (winrs.Result, error) {
	t.Helper()
	return e.client("alice", e.password).Run(context.Background(), e.call(line, stdin))
}

// raw is a client of one connection that signs in with go-ntlmssp and posts hand-made bodies.
func (e *winrmEnv) raw(t *testing.T, user, password string) func(body []byte) (int, []byte) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: pinTo(e.s.SPKI), MaxConnsPerHost: 1, Proxy: nil}
	t.Cleanup(tr.CloseIdleConnections)
	c := &http.Client{Transport: ntlmssp.Negotiator{RoundTripper: tr}}
	return func(body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+e.s.Addr+"/wsman", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", winrs.ContentType)
		if user != "" {
			req.SetBasicAuth(user, password)
		}
		resp, err := c.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, b
	}
}

func (e *winrmEnv) header() winrs.Header {
	return winrs.Header{To: "https://" + e.s.Addr + "/wsman", MessageID: "uuid:" + uuid.NewString()}
}

func (e *winrmEnv) createBody(t *testing.T) []byte {
	t.Helper()
	b, err := winrs.CreateShellRequest(e.header(), map[string]string{"SSH_ORIGINAL_COMMAND": "version"}, time.Minute)
	require.NoError(t, err)
	return b
}

func faultCode(t *testing.T, status int, body []byte) uint32 {
	t.Helper()
	require.Equal(t, http.StatusInternalServerError, status, string(body))
	f, ok := winrs.ParseFault(body)
	require.True(t, ok, string(body))
	return f.Code
}

func actions(log []WinRMRequest) []string {
	var out []string
	for _, r := range log {
		if r.Action != "" {
			out = append(out, r.Action)
		}
	}
	return out
}

func TestWinRMEmulatorRunsTheHelper(t *testing.T) {
	e := newWinRMEnv(t)
	for i, line := range []string{winproto.SubVersion, winproto.SubWinFacts} {
		res, err := e.run(t, line, nil)
		require.NoError(t, err, line)
		want := e.m.Handler()(line, nil)
		assert.Equal(t, want.Exit, res.ExitCode, line)
		assert.JSONEq(t, string(want.Stdout), string(res.Stdout), "%s answers as over the SSH emulator", line)
		assert.Equal(t, e.s.SPKI, res.PeerSPKI)
		assert.Equal(t, i+1, e.s.Connections(), "one connection per call")
	}
	log := e.m.WinRMLog()
	assert.Equal(t, []string{"Create", "Command", "Send", "Receive", "Delete", "Create", "Command", "Send", "Receive", "Delete"}, actions(log))
	conns := map[int]bool{}
	for _, r := range log {
		assert.NotEqual(t, "basic", r.Auth)
		conns[r.Conn] = true
		switch r.Action {
		case "Create":
			assert.Equal(t, []string{"SSH_ORIGINAL_COMMAND"}, r.EnvNames)
		case "Command":
			assert.Equal(t, winproto.HelperPath, r.Program)
			assert.Equal(t, []string{"ssh"}, r.Args)
		}
	}
	assert.Len(t, conns, 2)
	auths := map[string]int{}
	for _, r := range log {
		auths[r.Auth]++
	}
	assert.Equal(t, 2, auths["negotiate"], "one type 1 per call")
	assert.Equal(t, 2, auths["authenticate"], "one type 3 per call")
}

func TestWinRMEmulatorDeploysAndRollsBack(t *testing.T) {
	e := newWinRMEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, e.m.Serve(ctx, "127.0.0.1:0"))
	t.Cleanup(func() { cancel(); e.m.serving.Wait() })
	old, _, ok := e.m.Served("0.0.0.0", 8443, "")
	require.True(t, ok)
	loc := winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS}
	ca := pki.NewCA("WinRM", pki.ECDSA256, time.Now())
	nl := ca.Issue(pki.Opts{CommonName: "intranet.win.example.test", SANs: []string{"intranet.win.example.test"}}, time.Now())
	op := opID(1)

	res, err := e.run(t, winproto.SubIISDeploy+" --op "+op, deployInput(t, loc, old, nl))
	require.NoError(t, err)
	var d winproto.DeployResponse
	require.NoError(t, json.Unmarshal(res.Stdout, &d), string(res.Stdout))
	require.Equal(t, 0, res.ExitCode)
	require.Equal(t, winproto.PhaseCommitted, d.Phase)
	served, _, _ := e.m.Served("0.0.0.0", 8443, "")
	assert.Equal(t, sum256(nl.Cert.Raw), served, "the binding serves the new certificate")

	res, err = e.run(t, winproto.SubIISRestore+" --op "+op, restoreInput())
	require.NoError(t, err)
	require.Equal(t, 0, res.ExitCode, string(res.Stdout))
	served, _, _ = e.m.Served("0.0.0.0", 8443, "")
	assert.Equal(t, old, served, "restored")
}

func TestWinRMEmulatorRefusesBadLogons(t *testing.T) {
	e := newWinRMEnv(t)
	for name, c := range map[string]*winrs.Client{
		"wrong password": e.client("alice", winrmPassword(t)),
		"wrong user":     e.client("bob", e.password),
	} {
		_, err := c.Run(context.Background(), e.call(winproto.SubVersion, nil))
		require.ErrorIs(t, err, winrs.ErrAuthRefused, name)
	}
	e.m.ClearWinRMAccount()
	_, err := e.run(t, winproto.SubVersion, nil)
	require.ErrorIs(t, err, winrs.ErrAuthRefused, "no account set")
	assert.Empty(t, actions(e.m.WinRMLog()), "no shell was created")

	// A request on a connection that is not signed in, without credentials or with Basic, is offered the sign-in.
	post := e.raw(t, "", "")
	status, _ := post(e.createBody(t))
	assert.Equal(t, http.StatusUnauthorized, status)
	tr := &http.Transport{TLSClientConfig: pinTo(e.s.SPKI)}
	t.Cleanup(tr.CloseIdleConnections)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+e.s.Addr+"/wsman", bytes.NewReader(e.createBody(t)))
	require.NoError(t, err)
	e.m.SetWinRMAccount("alice", e.password)
	req.SetBasicAuth("alice", e.password)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Basic is never accepted")
	assert.Equal(t, []string{"Negotiate", `Basic realm="WSMAN"`}, resp.Header.Values("WWW-Authenticate"))
	assert.Empty(t, actions(e.m.WinRMLog()))
	assert.True(t, slices.ContainsFunc(e.m.WinRMLog(), func(r WinRMRequest) bool { return r.Auth == "basic" }), "the log names the Basic try")
}

func TestWinRMEmulatorServesAnAuthenticatedConnection(t *testing.T) {
	e := newWinRMEnv(t)
	post := e.raw(t, "alice", e.password)
	status, body := post(e.createBody(t))
	require.Equal(t, http.StatusOK, status, string(body))
	shell, err := winrs.ParseShellCreated(body)
	require.NoError(t, err)
	// A later request on the signed-in connection carries no credentials and is served (Ruling 20).
	del, err := winrs.DeleteRequest(e.header(), shell)
	require.NoError(t, err)
	status, body = post(del)
	require.Equal(t, http.StatusOK, status, string(body))
	auths := []string{}
	for _, r := range e.m.WinRMLog() {
		auths = append(auths, r.Auth)
	}
	assert.Equal(t, []string{"none", "negotiate", "authenticate", "none"}, auths[:4], "anonymous, type 1, type 3 then the Delete")
	assert.Equal(t, 1, e.s.Connections())
	// A request for a shell that does not exist faults.
	status, body = post(del)
	assert.Equal(t, uint32(faultShellNotFound), faultCode(t, status, body))
	// A body the subset does not parse faults.
	status, body = post([]byte("<nope/>"))
	assert.Equal(t, uint32(faultBadRequest), faultCode(t, status, body))
}

func TestWinRMEmulatorRefusesOtherPrograms(t *testing.T) {
	e := newWinRMEnv(t)
	c := e.client("alice", e.password)
	// winrs.Client.Run sends only the helper's entry (helperCall), so the other shapes are hand-made.
	rp := e.raw(t, "alice", e.password)
	for name, args := range map[string][]string{"other args": {"ssh", "version"}, "no args": nil} {
		status, body := rp(e.createBody(t))
		require.Equal(t, http.StatusOK, status, string(body))
		shell, err := winrs.ParseShellCreated(body)
		require.NoError(t, err)
		cmd, err := winrs.CommandRequest(e.header(), shell, winproto.HelperPath, args)
		require.NoError(t, err, name)
		status, body = rp(cmd)
		assert.Equal(t, uint32(2), faultCode(t, status, body), name)
		del, err := winrs.DeleteRequest(e.header(), shell)
		require.NoError(t, err)
		status, _ = rp(del)
		require.Equal(t, http.StatusOK, status, name)
	}
	// F29 as measured (runner run 7): WinRS starts a program that does not exist through cmd.exe /C, so the command
	// runs and ends with exit 1, cmd.exe's "not recognized" text on stderr, nothing on stdout.
	cl := e.call(winproto.SubVersion, nil)
	cl.Program = `C:\Windows\System32\alice-absent.exe`
	r, err := c.Run(context.Background(), cl)
	require.NoError(t, err, "another program")
	assert.Equal(t, notRecognizedExit, r.ExitCode)
	assert.Empty(t, r.Stdout)
	e.m.SetHelperMissing(true)
	r, err = e.run(t, winproto.SubVersion, []byte("stdin"))
	require.NoError(t, err, "a host without the helper")
	assert.Equal(t, notRecognizedExit, r.ExitCode)
	assert.Empty(t, r.Stdout)
	e.m.SetHelperMissing(false)
	assert.Zero(t, e.m.WinRMShells())
	other := bytes.Replace(e.createBody(t), []byte(`Name="SSH_ORIGINAL_COMMAND"`), []byte(`Name="PATH"`), 1)
	status, body := rp(other)
	assert.Equal(t, uint32(faultBadRequest), faultCode(t, status, body), "another variable")

	// A second variable (which winrs never builds).
	post := e.raw(t, "alice", e.password)
	two := bytes.Replace(e.createBody(t), []byte("</rsp:Environment>"), []byte(`<rsp:Variable Name="PATH">x</rsp:Variable></rsp:Environment>`), 1)
	status, body = post(two)
	assert.Equal(t, uint32(faultBadRequest), faultCode(t, status, body))
	assert.Equal(t, 0, e.m.WinRMShells())
}

func TestWinRMEmulatorKill(t *testing.T) {
	e := newWinRMEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, e.m.Serve(ctx, "127.0.0.1:0"))
	t.Cleanup(func() { cancel(); e.m.serving.Wait() })
	old, _, _ := e.m.Served("0.0.0.0", 8443, "")
	loc := winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 8443, AppID: winproto.AppIDIIS}
	ca := pki.NewCA("WinRM", pki.ECDSA256, time.Now())
	nl := ca.Issue(pki.Opts{CommonName: "intranet.win.example.test", SANs: []string{"intranet.win.example.test"}}, time.Now())
	op := opID(2)
	e.m.KillAt("deploy.prepared")
	res, err := e.run(t, winproto.SubIISDeploy+" --op "+op, deployInput(t, loc, old, nl))
	require.NoError(t, err)
	assert.Equal(t, winhelper.ExitKilled, res.ExitCode, "over WinRS the killed helper's own exit (F29, run 7); SSH keeps KilledExit")
	assert.Empty(t, res.Stdout, "a killed helper prints nothing")
	assert.Contains(t, e.m.Points(), "deploy.prepared")
	e.m.Reboot()
	res, err = e.run(t, winproto.SubIISStatus+" --op "+op, nil)
	require.NoError(t, err)
	var s winproto.StatusResponse
	require.NoError(t, json.Unmarshal(res.Stdout, &s), string(res.Stdout))
	assert.Equal(t, winproto.PhasePrepared, s.Phase, "the journal as on SSH")
	assert.False(t, s.Active)
}

func TestWinRMEmulatorFaultsAndLimits(t *testing.T) {
	e := newWinRMEnv(t)
	e.m.FailWinRM(2150858770)
	_, err := e.run(t, winproto.SubVersion, nil)
	var fe *winrs.FaultError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, uint32(2150858770), fe.Code)
	_, err = e.run(t, winproto.SubVersion, nil)
	require.NoError(t, err, "only the next request faults")

	post := e.raw(t, "alice", e.password)
	var shells []string
	for range maxShellsPerUser {
		status, body := post(e.createBody(t))
		require.Equal(t, http.StatusOK, status, string(body))
		id, err := winrs.ParseShellCreated(body)
		require.NoError(t, err)
		shells = append(shells, id)
	}
	assert.Equal(t, maxShellsPerUser, e.m.WinRMShells())
	status, body := post(e.createBody(t))
	assert.Equal(t, uint32(faultMaxShells), faultCode(t, status, body), "the 31st open shell")
	del, err := winrs.DeleteRequest(e.header(), shells[0])
	require.NoError(t, err)
	status, _ = post(del)
	require.Equal(t, http.StatusOK, status)
	status, body = post(e.createBody(t))
	assert.Equal(t, http.StatusOK, status, "a deleted shell frees its place")
	id, err := winrs.ParseShellCreated(body)
	require.NoError(t, err)
	for _, id := range append(shells[1:], id) {
		del, err := winrs.DeleteRequest(e.header(), id)
		require.NoError(t, err)
		status, _ = post(del)
		require.Equal(t, http.StatusOK, status)
	}

	big := append(e.createBody(t), bytes.Repeat([]byte(" "), winrs.MaxEnvelopeSize)...)
	status, body = post(big)
	assert.Equal(t, uint32(faultEnvelopeTooLarge), faultCode(t, status, body))

	// A command that does not finish within the Receive's OperationTimeout is asked again; the call's timeout ends it
	// with Signal and Delete.
	e.m.Delay(winproto.SubVersion, 3*time.Second)
	cl := e.call(winproto.SubVersion, nil)
	cl.Timeout = time.Second
	_, err = e.client("alice", e.password).Run(context.Background(), cl)
	require.ErrorIs(t, err, winrs.ErrTimeout)
	log := actions(e.m.WinRMLog())
	assert.Equal(t, []string{"Signal", "Delete"}, log[len(log)-2:])
}

func TestWinRMEmulatorReceivesInChunks(t *testing.T) {
	e := newWinRMEnv(t)
	post := e.raw(t, "alice", e.password)
	status, body := post(e.createBody(t))
	require.Equal(t, http.StatusOK, status)
	shell, err := winrs.ParseShellCreated(body)
	require.NoError(t, err)
	cmd, err := winrs.CommandRequest(e.header(), shell, winproto.HelperPath, []string{"ssh"})
	require.NoError(t, err)
	status, body = post(cmd)
	require.Equal(t, http.StatusOK, status, string(body))
	cmdID, err := winrs.ParseCommandStarted(body)
	require.NoError(t, err)
	// A second Command on the shell, and a Send for another command, fault.
	status, body = post(cmd)
	assert.Equal(t, uint32(faultBadRequest), faultCode(t, status, body))
	other, err := winrs.SendRequest(e.header(), shell, strings.Repeat("A", 8)+"-0000-0000-0000-000000000000", nil, true)
	require.NoError(t, err)
	status, body = post(other)
	assert.Equal(t, uint32(faultBadRequest), faultCode(t, status, body))
	// stdin over the bound faults.
	for range maxWinRMStdin/winrs.MaxSendChunk + 1 {
		send, err := winrs.SendRequest(e.header(), shell, cmdID, make([]byte, winrs.MaxSendChunk), false)
		require.NoError(t, err)
		if status, body = post(send); status != http.StatusOK {
			break
		}
	}
	assert.Equal(t, uint32(faultBadRequest), faultCode(t, status, body))

	// The model's output in chunks of at most 64 KiB.
	e.m.mu.Lock()
	sh := e.m.winrmShells[shell]
	require.NotNil(t, sh)
	sh.cmd.stdout = bytes.Repeat([]byte("x"), 100<<10)
	sh.cmd.stdin = nil
	e.m.mu.Unlock()
	close(sh.cmd.done)
	recv, err := winrs.ReceiveRequest(e.header(), shell, cmdID)
	require.NoError(t, err)
	var got []byte
	for {
		status, body = post(recv)
		require.Equal(t, http.StatusOK, status, string(body))
		r, err := winrs.ParseReceived(body, cmdID)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(r.Stdout), maxReceiveChunk)
		got = append(got, r.Stdout...)
		if r.Done {
			break
		}
	}
	assert.Len(t, got, 100<<10)
	sig, err := winrs.SignalRequest(e.header(), shell, cmdID, winrs.SignalTerminate)
	require.NoError(t, err)
	status, _ = post(sig)
	assert.Equal(t, http.StatusOK, status)
}

func TestWinRMLogIsBounded(t *testing.T) {
	m := NewModel()
	for range maxWinRMLog + 5 {
		m.logWinRM(WinRMRequest{Action: "Create"})
	}
	assert.Len(t, m.WinRMLog(), maxWinRMLog)
}

func TestNewWinRMServerNeedsTheRecord(t *testing.T) {
	m := NewModel()
	_, ok := m.WinRMSPKI()
	assert.False(t, ok, "no WinRM record")
	d, err := Demo(time.Now())
	require.NoError(t, err)
	spki, ok := d.WinRMSPKI()
	require.True(t, ok)
	s := NewWinRMServer(t, d)
	assert.Equal(t, spki, s.SPKI)
	_, err = x509.ParsePKIXPublicKey(spki)
	assert.NoError(t, err)
}

// The demo host's WinRM record serves WS-Man through Serve, as the container does.
func TestServeAnswersWinRMOnTheRecordsPort(t *testing.T) {
	m, err := Demo(time.Now())
	require.NoError(t, err)
	pw := winrmPassword(t)
	m.SetWinRMAccount("alice", pw)
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, m.Serve(ctx, "127.0.0.1:0"))
	t.Cleanup(func() { cancel(); m.serving.Wait() })
	spki, ok := m.WinRMSPKI()
	require.True(t, ok)
	c := &winrs.Client{TLS: pinTo(spki), User: "alice", Password: pw}
	res, err := c.Run(context.Background(), winrs.Call{Addr: m.Endpoint(5986), Program: winproto.HelperPath, Args: []string{"ssh"},
		Env: map[string]string{"SSH_ORIGINAL_COMMAND": winproto.SubVersion}, Timeout: 30 * time.Second, MaxOutput: 1 << 20})
	require.NoError(t, err)
	assert.Contains(t, string(res.Stdout), `"protocol":1`)
	// The 9444 binding of the WinRM journey (Ruling 23) is plain TLS.
	cs, err := tlsDial(t, m.Endpoint(demoWinRMJourneyPort), "")
	require.NoError(t, err)
	assert.NotEmpty(t, cs.PeerCertificates)
}
