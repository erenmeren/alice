package windows

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/netaddr"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/providertest"
	"alice/internal/providers/tlspin"
	"alice/internal/providers/windows/winproto"
	"alice/internal/providers/windows/winrs"
	"alice/internal/providers/windows/wintest"
	"alice/internal/secrets"
	"alice/internal/testutil/pki"
)

// winrmAppID is WinRM's http.sys application id (winproto.KnownApps).
const winrmAppID = "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}"

// winrmLocator is the http.sys record of the WinRM listener the tests add.
var winrmLocator = winproto.Locator{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 5986, AppID: winrmAppID}

// winrmCred is the platform credential source of a WinRM Windows server (providers.WinRMPasswordSource): pw "" answers
// as inventory does for a server without one, a non-nil err is answered instead. It counts the reads and the releases
// and keeps every Plaintext it gave out.
type winrmCred struct {
	*fakeCred
	mu       sync.Mutex
	pw       string
	err      error
	reads    int
	releases int
	given    []secrets.Plaintext
}

func (c *winrmCred) WinRMPassword(_ context.Context, target uuid.UUID) (secrets.Plaintext, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	switch {
	case target != testTarget:
		return secrets.Plaintext{}, nil, errors.New("another target")
	case c.err != nil:
		return secrets.Plaintext{}, nil, c.err
	case c.pw == "":
		return secrets.Plaintext{}, nil, fmt.Errorf("%w: %w", errors.New("inventory: not found"), providers.ErrNoWinRMPassword)
	}
	pt := secrets.NewPlaintext([]byte(c.pw))
	c.given = append(c.given, pt)
	return pt, func() {
		c.mu.Lock()
		c.releases++
		c.mu.Unlock()
		pt.Zero()
	}, nil
}

func (c *winrmCred) set(pw string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pw, c.err = pw, err
}

// balanced reports whether every password read was released and zeroed.
func (c *winrmCred) balanced(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	assert.Positive(t, c.reads, "the password was read")
	assert.Equal(t, len(c.given), c.releases, "one release per password given out")
	for _, pt := range c.given {
		for _, b := range pt.Bytes() {
			require.Zero(t, b, "the password is zeroed after the call")
		}
	}
}

// winrmEnv is wenv's host with a WinRM listener (wintest.NewWinRMServer, the record 0.0.0.0:5986 of WinRM's appid) and
// a target whose transport is winrm: the account alice with a password generated now, the listener's SPKI pinned.
type winrmEnv struct {
	*wenv
	ws    *wintest.WinRMServer
	wcred *winrmCred
	whk   *memHostKeys
	wref  providers.TargetRef
	key   pki.Leaf // the listener's certificate
	pw    string   // the account's password
}

func newWinRMEnv(t *testing.T) *winrmEnv {
	t.Helper()
	w := &winrmEnv{wenv: newWEnv(t)}
	w.key = w.ca.Issue(pki.Opts{CommonName: "iis-01", SANs: []string{"iis-01"}}, time.Now())
	sha1 := w.model.AddCertificate("My", w.key.CertPEM, w.key.KeyPEM, wintest.CertOptions{FriendlyName: "WinRM"})
	w.model.AddBinding(winproto.SSLBinding{Type: winproto.BindingIPPort, IP: "0.0.0.0", Port: 5986, AppID: winrmAppID, CertSHA1: sha1, Store: "My"})
	w.ws = wintest.NewWinRMServer(t, w.model)
	w.pw = "W7-" + rand.Text()
	w.model.SetWinRMAccount("alice", w.pw)
	w.wcred = &winrmCred{fakeCred: w.cred, pw: w.pw}
	id := providers.TLSIdentity(w.ws.SPKI)
	w.whk = &memHostKeys{pinned: &id}
	host, port, err := net.SplitHostPort(w.ws.Addr)
	require.NoError(t, err)
	p, err := strconv.Atoi(port)
	require.NoError(t, err)
	w.wref = providers.TargetRef{ID: testTarget, Name: "iis-01", Kind: providers.KindWindows,
		Config: providers.TargetConfig{"host": host, "port": p, "username": "alice", "transport": TransportWinRM}}
	return w
}

func (w *winrmEnv) openErr(cred providers.CredentialSource) (providers.Session, error) {
	return w.prov.Open(context.Background(), w.wref, cred, providers.Env{HostKeys: w.whk})
}

func (w *winrmEnv) wopen(t *testing.T) *session {
	t.Helper()
	s, err := w.openErr(w.wcred)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	ws, ok := s.(*session)
	require.True(t, ok)
	return ws
}

// serveWinRM makes the WinRM record serve l (added to My).
func (w *winrmEnv) serveWinRM(t *testing.T, l pki.Leaf) {
	t.Helper()
	sha1 := w.model.AddCertificate("My", l.CertPEM, l.KeyPEM, wintest.CertOptions{})
	b, ok := w.model.Binding(winrmLocator)
	require.True(t, ok)
	b.CertSHA1 = sha1
	require.NoError(t, w.model.Host().UpdateBinding(context.Background(), b))
}

// count is the number of logged requests of action.
func (w *winrmEnv) count(action string) int {
	n := 0
	for _, r := range w.model.WinRMLog() {
		if r.Action == action {
			n++
		}
	}
	return n
}

// Review Focus 5: a target without transport, or with ssh, takes the pool path with the same lines, and never reads a
// WinRM password or env.HostKeys.
func TestSSHTransportIsW6(t *testing.T) {
	for _, tr := range []any{nil, TransportSSH} {
		t.Run(fmt.Sprint(tr), func(t *testing.T) {
			e := newEnv(t)
			if tr != nil {
				e.ref.Config["transport"] = tr
			}
			cred := &winrmCred{fakeCred: e.cred, pw: "unused-" + rand.Text()}
			hk := &memHostKeys{}
			s, err := e.prov.Open(context.Background(), e.ref, cred, providers.Env{HostKeys: hk})
			require.NoError(t, err)
			_, err = s.TestConnection(context.Background())
			require.NoError(t, err)
			_, err = s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
			require.NoError(t, err)
			assert.Equal(t, []string{winproto.SubVersion, winproto.SubWinFacts, winproto.SubIISDump, winproto.SubRDPDump}, e.srv.Commands())
			assert.Equal(t, []string{`CORP\alice-svc`, `CORP\alice-svc`, `CORP\alice-svc`, `CORP\alice-svc`}, e.sshUsers())
			assert.Zero(t, cred.reads, "no WinRM password is read")
			reads, seen := hk.counts()
			assert.Zero(t, reads+seen, "env.HostKeys is not used")
			assert.Equal(t, TransportSSH, s.(*session).cfg.Transport)
		})
	}
}

// Ruling 4: every call is one connection and one shell running the helper with ssh, the line in SSH_ORIGINAL_COMMAND.
func TestWinRMCallShape(t *testing.T) {
	w := newWinRMEnv(t)
	s := w.wopen(t)
	_, err := s.TestConnection(context.Background())
	require.NoError(t, err)
	t.Run("TestEachWinRMCallUsesItsOwnConnection", func(t *testing.T) {
		_, err := s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		creates := map[int]int{}
		for _, r := range w.model.WinRMLog() {
			if r.Action == "Create" {
				creates[r.Conn]++
			}
		}
		for conn, n := range creates {
			assert.Equal(t, 1, n, "connection %d holds one shell", conn)
		}
		assert.Len(t, creates, w.ws.Connections(), "one connection per call")
		assert.Len(t, creates, 4, "version, win-facts, iis-dump, rdp-dump")
	})
	for _, r := range w.model.WinRMLog() {
		switch r.Action {
		case "":
			assert.Contains(t, []string{"none", "negotiate"}, r.Auth, "only the NTLM exchange before WS-Man")
		case "Create":
			assert.Equal(t, []string{"SSH_ORIGINAL_COMMAND"}, r.EnvNames)
			assert.Equal(t, "authenticate", r.Auth, "Create carries the NTLM type 3")
		case "Command":
			assert.Equal(t, winproto.HelperPath, r.Program)
			assert.Equal(t, []string{"ssh"}, r.Args)
			assert.Equal(t, "none", r.Auth)
		default:
			assert.Contains(t, []string{"Send", "Receive", "Delete"}, r.Action)
			assert.Equal(t, "none", r.Auth)
		}
	}
	assert.Zero(t, w.model.WinRMShells(), "every shell is deleted")
}

// Review Focus 1 and 4: the listener's identity is pinned by its SPKI with the SSH host key's flow, checked before any
// HTTP request; a renewal with the same key changes nothing, an expired certificate is accepted.
func TestWinRMIdentityFlow(t *testing.T) {
	w := newWinRMEnv(t)
	presented := providers.TLSIdentity(w.ws.SPKI)

	pinned := w.whk.pinned
	w.whk.pinned = nil
	_, err := w.openErr(w.wcred)
	pe := providerErr(t, err)
	assert.Equal(t, tlspin.CodeUnconfirmed, pe.Code)
	assert.Equal(t, presented.Fingerprint, pe.Params["fingerprint"])
	assert.Equal(t, TransportWinRM, pe.Params["transport"])
	assert.False(t, pe.Retryable)
	assert.True(t, errors.Is(err, winrs.ErrNotSent))
	assert.Equal(t, []providers.HostKey{presented}, w.whk.seen, "the store saw the sighting")
	assert.Empty(t, w.model.WinRMLog(), "no request, so no NTLM message, reached the listener")

	w.whk.pinned = pinned
	rep, err := w.wopen(t).TestConnection(context.Background())
	require.NoError(t, err)
	assert.Equal(t, presented, rep.HostKey, "the report's host key is the TLS identity")

	before := len(w.model.WinRMLog())
	renewed := w.ca.Issue(pki.Opts{CommonName: "iis-01", SANs: []string{"iis-01"}}, time.Now())
	w.serveWinRM(t, renewed)
	_, err = w.openErr(w.wcred)
	pe = providerErr(t, err)
	assert.Equal(t, tlspin.CodeChanged, pe.Code)
	assert.Equal(t, presented.Fingerprint, pe.Params["old_fingerprint"])
	assert.Equal(t, providers.TLSIdentity(renewed.Cert.RawSubjectPublicKeyInfo).Fingerprint, pe.Params["new_fingerprint"])
	assert.Len(t, w.model.WinRMLog(), before, "no request reached the listener")

	now := time.Now()
	for name, o := range map[string]pki.Opts{
		"the same key, a new certificate": {CommonName: "iis-01", Key: w.key.Key},
		"the same key, expired":           {CommonName: "iis-01", Key: w.key.Key, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)},
	} {
		w.serveWinRM(t, w.ca.Issue(o, now))
		_, err = w.wopen(t).TestConnection(context.Background())
		assert.NoError(t, err, name)
	}
}

// Ruling 8: without a password nothing is dialled; the source's errors map as the CCS password's.
func TestWinRMPasswordMissing(t *testing.T) {
	w := newWinRMEnv(t)
	for _, c := range []struct {
		name      string
		cred      providers.CredentialSource
		code      string
		retryable bool
	}{
		{"a source without the interface", w.cred, ReasonWinRMPasswordMissing, false},
		{"none set", &winrmCred{fakeCred: w.cred}, ReasonWinRMPasswordMissing, false},
		{"unusable", &winrmCred{fakeCred: w.cred, err: fmt.Errorf("inventory: %w", providers.ErrWinRMPasswordUnusable)}, reasonUnexpected, false},
		{"a database error", &winrmCred{fakeCred: w.cred, err: errors.New("db: connection reset")}, ReasonIOError, true},
	} {
		_, err := w.openErr(c.cred)
		pe := providerErr(t, err)
		assert.Equal(t, c.code, pe.Code, c.name)
		assert.Equal(t, c.retryable, pe.Retryable, c.name)
		assert.Equal(t, TransportWinRM, pe.Params["transport"], c.name)
		assert.Equal(t, winproto.SubVersion, pe.Params["subcommand"], c.name)
		assert.True(t, errors.Is(err, winrs.ErrNotSent), c.name)
	}
	assert.Zero(t, w.ws.Connections(), "nothing was dialled")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pe := providerErr(t, winrmPasswordRefusal(ctx, errors.New("db: canceled"), winproto.SubVersion))
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.True(t, pe.Retryable)
}

// Ruling 13 through the emulator: faults at Create, a wrong password, the helper missing at Command, a stalled
// Receive, an unreachable listener; and every row of the table through winrmError.
func TestWinRMErrorTable(t *testing.T) {
	w := newWinRMEnv(t)
	s := w.wopen(t)
	check := func(t *testing.T, err error, code string, retryable, notSent bool, params map[string]string) {
		t.Helper()
		pe := providerErr(t, err)
		assert.Equal(t, code, pe.Code)
		assert.Equal(t, retryable, pe.Retryable, "retryable")
		assert.Equal(t, notSent, errors.Is(err, winrs.ErrNotSent), "not sent")
		assert.Equal(t, TransportWinRM, pe.Params["transport"])
		assert.Equal(t, winproto.SubWinFacts, pe.Params["subcommand"])
		for k, v := range params {
			assert.Equal(t, v, pe.Params[k], k)
		}
		_, has := pe.Params["wsman_code"]
		assert.Equal(t, params["wsman_code"] != "", has, "wsman_code")
	}
	t.Run("a fault at Create", func(t *testing.T) {
		w.model.FailWinRM(87)
		_, err := s.TestConnection(context.Background())
		check(t, err, ReasonWinRMFault, false, true, map[string]string{"wsman_code": "87"})
	})
	t.Run("access denied at Create", func(t *testing.T) {
		w.model.FailWinRM(faultAccessDenied)
		_, err := s.TestConnection(context.Background())
		check(t, err, ReasonWinRMAuthRefused, false, true, nil)
	})
	t.Run("a wrong password", func(t *testing.T) {
		w.wcred.set("wrong-"+rand.Text(), nil)
		t.Cleanup(func() { w.wcred.set(w.pw, nil) })
		_, err := s.TestConnection(context.Background())
		check(t, err, ReasonWinRMAuthRefused, false, true, nil)
	})
	t.Run("the helper missing at Command", func(t *testing.T) {
		w.model.SetHelperMissing(true)
		t.Cleanup(func() { w.model.SetHelperMissing(false) })
		_, err := s.TestConnection(context.Background())
		check(t, err, ReasonHelperMissing, false, false, nil)
	})
	t.Run("a stalled Receive", func(t *testing.T) {
		w.model.Delay(winproto.SubWinFacts, time.Minute)
		t.Cleanup(func() { w.model.Delay(winproto.SubWinFacts, 0) })
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := s.TestConnection(ctx)
		check(t, err, "ssh.timeout", true, false, nil)
	})
	_, err := s.TestConnection(context.Background())
	require.NoError(t, err, "the listener works again")

	sub := winproto.SubWinFacts
	v, err := tlspin.New(context.Background(), tlspin.Options{Target: testTarget, Store: w.whk})
	require.NoError(t, err)
	ns := func(err error) error { return fmt.Errorf("%w (%w)", err, winrs.ErrNotSent) }
	for _, r := range []struct {
		name      string
		err       error
		code      string
		retryable bool
		params    map[string]string
	}{
		{"address refused", ns(fmt.Errorf("%w: %w", winrs.ErrUnreachable, netaddr.ErrNotAllowed)), "ssh.unreachable", true, nil},
		{"dial or TLS", ns(fmt.Errorf("%w: %w", winrs.ErrUnreachable, errors.New("tls: handshake"))), "ssh.unreachable", true, nil},
		{"a refused configuration", ns(winrs.ErrBadConfig), reasonUnexpected, false, nil},
		{"auth refused", ns(winrs.ErrAuthRefused), ReasonWinRMAuthRefused, false, nil},
		{"auth refused after Create", winrs.ErrAuthRefused, ReasonWinRMAuthRefused, false, nil},
		{"access denied at Create", ns(&winrs.FaultError{Code: faultAccessDenied, Action: winrs.ActionCreate}), ReasonWinRMAuthRefused, false, nil},
		{"a fault at Create", ns(&winrs.FaultError{Code: 2150859173, Action: winrs.ActionCreate}), ReasonWinRMFault, false, map[string]string{"wsman_code": "2150859173"}},
		{"file not found at Command", &winrs.FaultError{Code: faultFileNotFound, Action: winrs.ActionCommand}, "ssh.helper_missing", false, nil},
		{"code 2 at Send", &winrs.FaultError{Code: faultFileNotFound, Action: winrs.ActionSend}, ReasonWinRMFault, false, map[string]string{"wsman_code": "2"}},
		{"code 2 at Receive", &winrs.FaultError{Code: faultFileNotFound, Action: winrs.ActionReceive}, ReasonWinRMFault, false, map[string]string{"wsman_code": "2"}},
		{"access denied after Create", &winrs.FaultError{Code: faultAccessDenied, Action: winrs.ActionCommand}, ReasonWinRMFault, false, map[string]string{"wsman_code": "5"}},
		{"a fault after Command", &winrs.FaultError{Code: 87, Action: winrs.ActionReceive}, ReasonWinRMFault, false, map[string]string{"wsman_code": "87"}},
		{"a timeout", fmt.Errorf("%w: %w", winrs.ErrTimeout, context.DeadlineExceeded), "ssh.timeout", true, nil},
		{"a timeout before Create", ns(winrs.ErrTimeout), "ssh.timeout", true, nil},
		{"output too large", winrs.ErrOutputTooLarge, "ssh.output_too_large", false, nil},
		{"a protocol error at Create", ns(winrs.ErrProtocol), "ssh.protocol_error", false, nil},
		{"a protocol error after Command", winrs.ErrProtocol, "ssh.protocol_error", false, nil},
	} {
		got := winrmError(r.err, v, context.Background(), sub)
		pe := providerErr(t, got)
		assert.Equal(t, r.code, pe.Code, r.name)
		assert.Equal(t, r.retryable, pe.Retryable, r.name)
		assert.Equal(t, errors.Is(r.err, winrs.ErrNotSent), errors.Is(got, winrs.ErrNotSent), "%s: ErrNotSent stays in the chain", r.name)
		want := map[string]string{"subcommand": sub, "transport": TransportWinRM}
		for k, v := range r.params {
			want[k] = v
		}
		assert.Equal(t, want, pe.Params, r.name)
	}
	// The helper missing at Command becomes windows.helper_missing through mapHelper, keeping the params.
	pe := providerErr(t, mapHelper(winrmError(&winrs.FaultError{Code: faultFileNotFound, Action: winrs.ActionCommand}, v, context.Background(), sub)))
	assert.Equal(t, ReasonHelperMissing, pe.Code)
	assert.Equal(t, TransportWinRM, pe.Params["transport"])

	t.Run("an unreachable listener", func(t *testing.T) {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		require.NoError(t, ln.Close())
		p, _ := strconv.Atoi(port)
		w.wref.Config["port"] = p
		t.Cleanup(func() { w.wref.Config["port"] = s.cfg.Port })
		_, err = w.openErr(w.wcred)
		pe := providerErr(t, err)
		assert.Equal(t, "ssh.unreachable", pe.Code)
		assert.True(t, pe.Retryable)
		assert.True(t, errors.Is(err, winrs.ErrNotSent))
	})
}

// Review Focus 3: a write over WinRM is a refusal only when nothing reached the helper.
func TestWinRMWriteOutcomeTable(t *testing.T) {
	for _, r := range []struct {
		name      string
		setup     func(t *testing.T, w *winrmEnv)
		timeout   time.Duration
		result    providers.DeployResult
		code      string
		retryable bool
	}{
		{"a fault at Create", func(_ *testing.T, w *winrmEnv) { w.model.FailWinRM(87) }, 0, providers.DeployNoChange, ReasonWinRMFault, false},
		{"a wrong password", func(_ *testing.T, w *winrmEnv) { w.wcred.set("wrong-"+rand.Text(), nil) }, 0,
			providers.DeployNoChange, ReasonWinRMAuthRefused, false},
		{"the helper missing at Command", func(_ *testing.T, w *winrmEnv) { w.model.SetHelperMissing(true) }, 0,
			providers.DeployUncertain, ReasonHelperMissing, false},
		{"a timeout after Command", func(_ *testing.T, w *winrmEnv) { w.model.Delay(winproto.SubIISDeploy, time.Minute) },
			500 * time.Millisecond, providers.DeployUncertain, "ssh.timeout", true},
	} {
		t.Run(r.name, func(t *testing.T) {
			w := newWinRMEnv(t)
			s := w.wopen(t)
			r.setup(t, w)
			ctx := context.Background()
			if r.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, r.timeout)
				defer cancel()
			}
			req := w.deployReq(w.issue())
			commands := w.count("Command")
			out, err := s.DeployCertificate(ctx, req, &stepLog{})
			providertest.CheckDeployOutcome(t, out, err)
			assert.Equal(t, r.result, out.Result)
			pe := providerErr(t, err)
			assert.Equal(t, r.code, pe.Code)
			assert.Equal(t, r.retryable, pe.Retryable)
			assert.Equal(t, TransportWinRM, pe.Params["transport"])
			if r.result == providers.DeployNoChange {
				assert.Equal(t, derSHA256(w.old.Cert.Raw), w.served(), "a refusal changed nothing")
			}
			assert.Equal(t, r.result == providers.DeployUncertain, w.count("Command") > commands, "only an uncertain outcome sent the Command")
		})
	}
}

// Review Focus 2: the password is released, and zeroed, on every path.
func TestWinRMReleasesThePassword(t *testing.T) {
	for _, r := range []struct {
		name   string
		setup  func(w *winrmEnv)
		ctx    time.Duration
		reopen bool // the refusal comes at Open: the pin is read there
	}{
		{"success", func(*winrmEnv) {}, 0, false},
		{"a timeout", func(w *winrmEnv) { w.model.Delay(winproto.SubWinFacts, time.Minute) }, 300 * time.Millisecond, false},
		{"a fault", func(w *winrmEnv) { w.model.FailWinRM(87) }, 0, false},
		{"an auth refusal", func(w *winrmEnv) { w.model.SetWinRMAccount("alice", "other-"+rand.Text()) }, 0, false},
		{"an output overflow", func(*winrmEnv) {}, 0, false},
		{"an identity refusal", func(w *winrmEnv) {
			other := providers.TLSIdentity(pki.SelfSigned("other", pki.ECDSA256, time.Now()).Cert.RawSubjectPublicKeyInfo)
			w.whk.pinned = &other
		}, 0, true},
	} {
		t.Run(r.name, func(t *testing.T) {
			w := newWinRMEnv(t)
			s := w.wopen(t)
			r.setup(w)
			ctx := context.Background()
			if r.ctx > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, r.ctx)
				defer cancel()
			}
			if r.name == "an output overflow" {
				c, err := linuxssh.ForcedCommand([]string{winproto.SubVersion}, nil, time.Minute, 1)
				require.NoError(t, err)
				_, _, err = s.run(ctx, c)
				assert.Equal(t, "ssh.output_too_large", providerErr(t, err).Code)
			} else if r.reopen {
				_, err := w.openErr(w.wcred)
				require.Error(t, err)
			} else {
				_, err := s.TestConnection(ctx)
				assert.Equal(t, r.name != "success", err != nil, "%v", err)
			}
			w.wcred.balanced(t)
		})
	}
}

// Ruling 11: the WinRM listener's own binding is never deployable, over either transport.
func TestWinRMListenerBindingStaysUnsupported(t *testing.T) {
	check := func(t *testing.T, w *winrmEnv, s providers.Session, calls func() int) {
		t.Helper()
		res, err := s.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		var loc *providers.CertLocation
		for i := range res.Certificates {
			if res.Certificates[i].Location.CertPath == "http.sys/ipport/0.0.0.0:5986" {
				loc = &res.Certificates[i].Location
			}
		}
		require.NotNil(t, loc, "the WinRM record is discovered")
		assert.False(t, loc.Supported)
		assert.Equal(t, UnsupportedForeignApp, loc.Unsupported)
		req := w.deployReq(w.issue())
		req.Location = *loc
		before := calls()
		out, err := s.DeployCertificate(context.Background(), req, &stepLog{})
		assert.Equal(t, providers.DeployNoChange, out.Result)
		assert.Equal(t, ReasonLocationUnsupported, providerErr(t, err).Code)
		assert.Equal(t, before, calls(), "nothing was sent")
	}
	t.Run("ssh", func(t *testing.T) {
		w := newWinRMEnv(t)
		check(t, w, w.open(t), func() int { return len(w.srv.Commands()) })
	})
	t.Run("winrm", func(t *testing.T) {
		w := newWinRMEnv(t)
		check(t, w, w.wopen(t), func() int { return w.count("Create") })
	})
}

func TestWinRMDialTimeoutMatchesSSH(t *testing.T) {
	assert.Equal(t, linuxssh.DefaultDialTimeout, winrs.DefaultDialTimeout)
	assert.Equal(t, linuxssh.DefaultHandshakeTimeout, winrs.DefaultHandshakeTimeout)
}

// Ruling 13: the WinRM path's own refusals before any dial carry transport and subcommand too: a forgotten target's
// slot, and a host-key store the verifier cannot read.
func TestWinRMEarlyRefusalsCarryTheParams(t *testing.T) {
	w := newWinRMEnv(t)
	s := w.wopen(t)
	w.prov.ForgetTarget(testTarget)
	_, err := s.TestConnection(context.Background())
	pe := providerErr(t, err)
	assert.Equal(t, TransportWinRM, pe.Params["transport"], pe.Code)
	assert.Equal(t, winproto.SubWinFacts, pe.Params["subcommand"])
	assert.True(t, errors.Is(err, winrs.ErrNotSent))

	_, err = w.prov.Open(context.Background(), w.wref, w.wcred, providers.Env{}) // no HostKeys: tlspin refuses
	pe = providerErr(t, err)
	assert.Equal(t, reasonUnexpected, pe.Code)
	assert.Equal(t, map[string]string{"transport": TransportWinRM, "subcommand": winproto.SubVersion}, pe.Params)
}
