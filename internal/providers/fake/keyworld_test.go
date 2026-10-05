package fake

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/providers/providertest"
)

type keySource struct{ s ssh.Signer }

func (k keySource) SSHSigner(context.Context) (ssh.Signer, func(), error) { return k.s, func() {}, nil }

func newKey(t *testing.T) (line, fp string, src providers.CredentialSource) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " c", ssh.FingerprintSHA256(s.PublicKey()), keySource{s}
}

func worldSession(t *testing.T, w *KeyWorld, target uuid.UUID) providers.Session {
	t.Helper()
	p := New(providers.KindLinuxSSH, providers.CapTestConnection, providers.CapAuthorizedKeys, providers.CapKeyLogin)
	p.Configure(func(c *Config) { c.World = w; c.SkipHostKeyCheck = true })
	s, err := p.Open(context.Background(), providers.TargetRef{ID: target, Kind: providers.KindLinuxSSH}, nil, providers.Env{})
	require.NoError(t, err)
	return s
}

func TestKeyWorldAddLoginRemove(t *testing.T) {
	ctx := context.Background()
	w := NewKeyWorld()
	target := uuid.New()
	oldLine, oldFP, oldKey := newKey(t)
	newLine, newFP, newKey := newKey(t)
	w.Put(target, "deploy", "/home/deploy/.ssh/authorized_keys", "# comment", oldLine)
	s := worldSession(t, w, target)

	r, err := s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: oldKey})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginAccepted, r.Outcome)
	r, err = s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: newKey})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginRefused, r.Outcome)

	res, err := s.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Line: newLine}, nil)
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.Equal(t, 3, res.LineNo)
	res, err = s.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Line: newLine}, nil)
	require.NoError(t, err)
	assert.False(t, res.Changed, "adding a present key changes nothing")
	assert.Equal(t, 3, res.LineNo)
	r, err = s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: newKey})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginAccepted, r.Outcome)

	_, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Fingerprint: oldFP, ProtectedFingerprints: []string{oldFP}}, nil)
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "sshkey.own_key_protected", pe.Code)

	res, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Fingerprint: oldFP}, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Removed)
	assert.Equal(t, []string{"# comment", newLine}, w.Lines(target, "/home/deploy/.ssh/authorized_keys"))
	assert.False(t, w.Has(target, "/home/deploy/.ssh/authorized_keys", oldFP))
	assert.True(t, w.Has(target, "/home/deploy/.ssh/authorized_keys", newFP))
	// three logins, two adds, one removal; the refused protected removal never reached the world
	assert.Len(t, w.Events(), 6)
}

func TestKeyWorldSharedFileServesEveryUser(t *testing.T) {
	ctx := context.Background()
	w := NewKeyWorld()
	target := uuid.New()
	line, _, key := newKey(t)
	w.Put(target, "deploy", "/etc/ssh/keys/shared", line)
	w.Put(target, "backup", "/etc/ssh/keys/shared", line)
	s := worldSession(t, w, target)
	for _, u := range []string{"deploy", "backup"} {
		r, err := s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: u, Key: key})
		require.NoError(t, err)
		assert.Equal(t, providers.KeyLoginAccepted, r.Outcome, u)
	}
	assert.Equal(t, []string{line}, w.Lines(target, "/etc/ssh/keys/shared"), "one file, not one per user")
}

func TestKeyWorldFaults(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	file := "/home/deploy/.ssh/authorized_keys"
	add := func(s providers.Session, line string) (providers.AuthKeyResult, []string, error) {
		var steps []string
		res, err := s.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Line: line},
			stepFunc(func(name string, st providers.StepStatus) { steps = append(steps, name+":"+string(st)) }))
		return res, steps, err
	}
	cases := []struct {
		fault      Fault
		code       string
		changed    bool
		writeStart bool
	}{
		{FaultRefuse, "ssh.helper_refused", false, false},
		{FaultUnreachable, "ssh.unreachable", false, false},
		{FaultAfterWrite, "ssh.timeout", true, true},
		{FaultFileChanged, "ssh.file_changed", false, true},
	}
	for _, c := range cases {
		w := NewKeyWorld()
		w.Put(target, "deploy", file)
		w.SetFault(func(p FaultPoint) Fault {
			if p.Method == "AddAuthorizedKey" {
				return c.fault
			}
			return FaultNone
		})
		line, fp, _ := newKey(t)
		res, steps, err := add(worldSession(t, w, target), line)
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, c.code, pe.Code)
		assert.Equal(t, c.changed, w.Has(target, file, fp))
		assert.Equal(t, c.changed, res.Changed)
		assert.Equal(t, c.writeStart, slicesContains(steps, "write:started"))
	}

	w := NewKeyWorld()
	w.Put(target, "deploy", file)
	w.SetFault(func(p FaultPoint) Fault { return FaultHang })
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	line, fp, _ := newKey(t)
	_, err := worldSession(t, w, target).AddAuthorizedKey(cctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: file, Line: line}, nil)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, w.Has(target, file, fp))

	w = NewKeyWorld()
	line, _, key := newKey(t)
	w.Put(target, "deploy", file, line)
	for fault, want := range map[Fault]providers.KeyLoginOutcome{FaultRefuse: providers.KeyLoginRefused, FaultUnprovable: providers.KeyLoginUnprovable} {
		w.SetFault(func(FaultPoint) Fault { return fault })
		r, err := worldSession(t, w, target).VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: key})
		require.NoError(t, err)
		assert.Equal(t, want, r.Outcome)
	}
	w.SetFault(func(FaultPoint) Fault { return FaultUnreachable })
	_, err = worldSession(t, w, target).VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: key})
	assert.Error(t, err)
	n := 0
	for _, e := range w.Events() {
		assert.Equal(t, n+1, e.N)
		n = e.N
	}
}

type stepFunc func(name string, st providers.StepStatus)

func (f stepFunc) Step(name string, st providers.StepStatus, _ map[string]string) { f(name, st) }

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestScriptedKeyLoginWithoutWorld(t *testing.T) {
	p := New(providers.KindLinuxSSH, providers.CapKeyLogin)
	p.Configure(func(c *Config) {
		c.SkipHostKeyCheck = true
		c.KeyLogin = func(providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
			return providers.KeyLoginResult{Outcome: providers.KeyLoginUnprovable}, nil
		}
	})
	s, err := p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	r, err := s.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy"})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginUnprovable, r.Outcome)
	assert.Equal(t, 1, p.Count("VerifyKeyLogin"))

	q := New(providers.KindLinuxSSH) // no CapKeyLogin
	q.Configure(func(c *Config) { c.SkipHostKeyCheck = true })
	s2, err := q.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	_, err = s2.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
}

func TestFakeKeyLoginConforms(t *testing.T) {
	p := New(providers.KindLinuxSSH, providers.CapKeyLogin)
	p.Configure(func(c *Config) {
		c.SkipHostKeyCheck = true
		c.KeyLogin = func(req providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
			if req.OSUser == "" {
				return providers.KeyLoginResult{}, providers.NewError("ssh.helper_refused", false, nil, map[string]string{"field": "os_user"})
			}
			return providers.KeyLoginResult{Outcome: providers.KeyLoginAccepted}, nil
		}
	})
	providertest.CheckSession(t, providertest.SessionHarness{
		Capabilities: p.Capabilities(),
		Open: func(ctx context.Context) (providers.Session, error) {
			if err := ctx.Err(); err != nil {
				return nil, providers.NewError("ssh.timeout", true, err, nil)
			}
			return p.Open(ctx, providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
		},
	})
	// the default answers accepted, a cancelled context is a timeout, and the call is recorded without its key
	q := New(providers.KindLinuxSSH, providers.CapKeyLogin)
	q.Configure(func(c *Config) { c.SkipHostKeyCheck = true })
	s, err := q.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	_, _, key := newKey(t)
	r, err := s.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "u", Key: key})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginAccepted, r.Outcome)
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.VerifyKeyLogin(cctx, providers.KeyLoginRequest{OSUser: "u", Key: key})
	assert.ErrorIs(t, err, context.Canceled)
	for _, c := range q.Calls() {
		if c.Method == "VerifyKeyLogin" {
			assert.Equal(t, "u", c.Login.OSUser)
			assert.Nil(t, c.Login.Key)
		}
	}
}

func TestKeyWorldOwnerRuleForSharedFiles(t *testing.T) {
	ctx := context.Background()
	w := NewKeyWorld()
	target := uuid.New()
	file := "/etc/ssh/keys/shared"
	line, fp, _ := newKey(t)
	newL, _, _ := newKey(t)
	w.Put(target, "deploy", file, line)
	w.Put(target, "backup", file, line) // backup reads the file but deploy owns it
	s := worldSession(t, w, target)
	var pe *providers.Error

	_, err := s.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "backup", FilePath: file, Line: newL}, nil)
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.helper_refused", pe.Code)
	assert.Equal(t, "os_user", pe.Params["field"])
	_, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "backup", FilePath: file, Fingerprint: fp}, nil)
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.helper_refused", pe.Code)
	assert.Equal(t, []string{line}, w.Lines(target, file), "a refused change touches nothing")

	// the owner may change it, and its removal serves every user of the file
	_, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Fingerprint: fp}, nil)
	require.NoError(t, err)
	assert.Empty(t, w.Lines(target, file))
}

func TestKeyWorldLateWriteLandsAfterTheClockPasses(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	file := "/home/deploy/.ssh/authorized_keys"
	now := time.Unix(1_000_000, 0)
	w := NewKeyWorld()
	w.SetClock(func() time.Time { return now })
	w.SetLateDelay(5 * time.Minute)
	oldL, oldFP, _ := newKey(t)
	newL, newFP, newK := newKey(t)
	w.Put(target, "deploy", file, oldL)
	w.SetFault(func(p FaultPoint) Fault {
		if p.Method == "VerifyKeyLogin" {
			return FaultNone
		}
		if p.N == 1 || p.N == 4 {
			return FaultLateWrite
		}
		return FaultNone
	})
	s := worldSession(t, w, target)

	var pe *providers.Error
	_, err := s.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Line: newL}, nil)
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.False(t, w.Has(target, file, newFP), "nothing has changed when the call gives up")

	// an undo that looks now finds nothing to remove ...
	res, err := s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Fingerprint: newFP}, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, res.Removed)
	// ... and the write lands afterwards (S3)
	now = now.Add(4 * time.Minute)
	assert.False(t, w.Has(target, file, newFP), "not yet due")
	now = now.Add(2 * time.Minute)
	assert.True(t, w.Has(target, file, newFP), "the stalled write lands once the clock has passed")
	r, err := s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: newK})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginAccepted, r.Outcome)

	// a late removal; FlushLate lands it at once
	_, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Fingerprint: oldFP}, nil)
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.timeout", pe.Code)
	assert.True(t, w.Has(target, file, oldFP))
	w.FlushLate()
	assert.False(t, w.Has(target, file, oldFP))
	w.FlushLate() // nothing pending

	// a login hit by the fault is a timeout, not an outcome
	w.SetFault(func(FaultPoint) Fault { return FaultLateWrite })
	_, err = s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: newK})
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.timeout", pe.Code)

	// without a clock a late write waits for FlushLate; the default delay is a minute
	w2 := NewKeyWorld()
	w2.Put(target, "deploy", file)
	w2.SetFault(func(FaultPoint) Fault { return FaultLateWrite })
	_, err = worldSession(t, w2, target).AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Line: newL}, nil)
	require.Error(t, err)
	assert.Empty(t, w2.Lines(target, file))
	w2.FlushLate()
	assert.Equal(t, []string{newL}, w2.Lines(target, file))
	w2.SetFault(nil)
	w3 := NewKeyWorld()
	w3.SetClock(func() time.Time { return now })
	w3.Put(target, "deploy", file)
	w3.SetFault(func(FaultPoint) Fault { return FaultLateWrite })
	_, err = worldSession(t, w3, target).AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Line: newL}, nil)
	require.Error(t, err)
	now = now.Add(59 * time.Second)
	assert.Empty(t, w3.Lines(target, file))
	now = now.Add(2 * time.Second)
	assert.Equal(t, []string{newL}, w3.Lines(target, file))
}

func TestKeyWorldListsWhatItHolds(t *testing.T) {
	ctx := context.Background()
	w := NewKeyWorld()
	a, afp, _ := newKey(t)
	target, other := uuid.New(), uuid.New()
	w.Put(target, "deploy", "/h/deploy/ak", "# note", `from="10.0.0.1" `+a, "garbage")
	w.Put(target, "backup", "/h/backup/ak", a)
	w.Put(other, "deploy", "/h/deploy/ak", a)
	s := worldSession(t, w, target)
	keys, err := s.ListAuthorizedKeys(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Equal(t, "backup", keys[0].OSUser)
	assert.Equal(t, "deploy", keys[1].OSUser)
	assert.Equal(t, 2, keys[1].LineNo)
	assert.Equal(t, `from="10.0.0.1"`, keys[1].Options)
	assert.Equal(t, afp, keys[1].Fingerprint)
	assert.Equal(t, "ssh-ed25519", keys[1].KeyType)

	p := New(providers.KindLinuxSSH, providers.CapAuthorizedKeys, providers.CapDiscoverSSHKeys)
	p.Configure(func(c *Config) {
		c.World, c.SkipHostKeyCheck = w, true
		c.ListErr = providers.NewError("ssh.unreachable", true, nil, nil)
		c.Discovery.KeyFiles = []providers.UserKeyFiles{{OSUser: "deploy", Files: []string{"/h/deploy/ak"}}}
	})
	s2, err := p.Open(ctx, providers.TargetRef{ID: target}, nil, providers.Env{})
	require.NoError(t, err)
	_, err = s2.ListAuthorizedKeys(ctx)
	assert.Error(t, err, "a scripted ListErr still wins")

	d, err := s2.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []providers.UserKeyFiles{{OSUser: "deploy", Files: []string{"/h/deploy/ak"}}}, d.KeyFiles)
	d.KeyFiles[0].Files[0] = "changed"
	d, err = s2.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, "/h/deploy/ak", d.KeyFiles[0].Files[0], "a caller cannot change the scripted result")
	d, err = s2.Discover(ctx, providers.DiscoverRequest{})
	require.NoError(t, err)
	assert.Nil(t, d.KeyFiles, "the SSH half was not asked for")
}

func TestKeyWorldRemoveAndLoginFaults(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	file := "/home/deploy/.ssh/authorized_keys"
	line, fp, key := newKey(t)
	cases := []struct {
		fault   Fault
		code    string
		removed bool
	}{
		{FaultRefuse, "ssh.helper_refused", false},
		{FaultUnreachable, "ssh.unreachable", false},
		{FaultAfterWrite, "ssh.timeout", true},
		{FaultFileChanged, "ssh.file_changed", false},
	}
	for _, c := range cases {
		w := NewKeyWorld()
		w.Put(target, "deploy", file, line)
		w.SetFault(func(FaultPoint) Fault { return c.fault })
		res, err := worldSession(t, w, target).RemoveAuthorizedKey(ctx,
			providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Fingerprint: fp}, nil)
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, c.code, pe.Code)
		assert.Equal(t, c.removed, !w.Has(target, file, fp))
		assert.Equal(t, c.removed, res.Changed)
	}

	// removing an absent key changes nothing
	w := NewKeyWorld()
	w.Put(target, "deploy", file, line)
	other, otherFP, _ := newKey(t)
	_ = other
	res, err := worldSession(t, w, target).RemoveAuthorizedKey(ctx,
		providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Fingerprint: otherFP}, nil)
	require.NoError(t, err)
	assert.False(t, res.Changed)
	assert.Equal(t, 0, res.Removed)

	// hangs end with the context
	w.SetFault(func(FaultPoint) Fault { return FaultHang })
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	_, err = worldSession(t, w, target).RemoveAuthorizedKey(cctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Fingerprint: fp}, nil)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.True(t, w.Has(target, file, fp))
	_, err = worldSession(t, w, target).VerifyKeyLogin(cctx, providers.KeyLoginRequest{OSUser: "deploy", Key: key})
	assert.Error(t, err)
	cctx2, cancel2 := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel2()
	// the session refuses a context that is already done; a live one reaches the world and hangs
	_, err = worldSession(t, w, target).VerifyKeyLogin(cctx2, providers.KeyLoginRequest{OSUser: "deploy", Key: key})
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	// the world refuses a login without user or key, and reports a key source that fails
	w.SetFault(nil)
	s := worldSession(t, w, target)
	var pe *providers.Error
	_, err = s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy"})
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.helper_refused", pe.Code)
	_, err = s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: failingSource{}})
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "internal.unexpected", pe.Code)
}

type failingSource struct{}

func (failingSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return nil, func() {}, assert.AnError
}
