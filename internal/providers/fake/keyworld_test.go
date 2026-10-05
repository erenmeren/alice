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
	"alice/internal/providers/linuxssh/helperproto"
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

	// without a clock a late write waits for FlushLate; the default delay stays inside the helper budget
	w2 := NewKeyWorld()
	w2.SetClock(nil) // flush-only: stated, never implied
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
	now = now.Add(DefaultLateDelay - time.Second)
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

// T3-I1: a login reads only the files Put for that user; an add never extends them.
func TestKeyWorldLoginReadsOnlyTheUsersFiles(t *testing.T) {
	ctx := context.Background()
	w := NewKeyWorld()
	target := uuid.New()
	lineA, _, keyA := newKey(t)
	lineB, _, keyB := newKey(t)
	w.Put(target, "deploy", "/home/deploy/.ssh/authorized_keys", lineA)
	w.Put(target, "backup", "/home/backup/.ssh/authorized_keys", lineB)
	s := worldSession(t, w, target)
	for _, c := range []struct {
		user string
		key  providers.CredentialSource
		want providers.KeyLoginOutcome
	}{
		{"deploy", keyA, providers.KeyLoginAccepted},
		{"backup", keyB, providers.KeyLoginAccepted},
		{"deploy", keyB, providers.KeyLoginRefused},
		{"backup", keyA, providers.KeyLoginRefused},
	} {
		r, err := s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: c.user, Key: c.key})
		require.NoError(t, err)
		assert.Equal(t, c.want, r.Outcome, c.user)
	}

	// an add to a file that was never declared for the user is refused and logs nobody in
	newL, _, newK := newKey(t)
	var pe *providers.Error
	_, err := s.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: "/home/deploy/.ssh/other", Line: newL}, nil)
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.helper_refused", pe.Code)
	assert.Equal(t, "os_user", pe.Params["field"])
	assert.Empty(t, w.Lines(target, "/home/deploy/.ssh/other"))
	r, err := s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: newK})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginRefused, r.Outcome)
}

// T3-I2: a late write cannot be queued without a stated clock; a landing is recorded and counted.
func TestKeyWorldLateWriteCannotPassVacuously(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	file := "/home/deploy/.ssh/authorized_keys"
	line, fp, _ := newKey(t)
	w := NewKeyWorld()
	w.Put(target, "deploy", file)
	w.SetFault(func(FaultPoint) Fault { return FaultLateWrite })
	s := worldSession(t, w, target)
	req := providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Line: line}
	assert.Panics(t, func() { _, _ = s.AddAuthorizedKey(ctx, req, nil) }, "no clock and no explicit flush-only mode")

	now := time.Unix(5_000, 0)
	w = NewKeyWorld()
	w.SetClock(func() time.Time { return now })
	w.Put(target, "deploy", file)
	w.SetFault(func(p FaultPoint) Fault {
		if p.N == 1 {
			return FaultLateWrite
		}
		return FaultNone
	})
	s = worldSession(t, w, target)
	_, err := s.AddAuthorizedKey(ctx, req, nil)
	require.Error(t, err)
	assert.Equal(t, 1, w.PendingLate())
	assert.Equal(t, 0, w.LateLanded())
	now = now.Add(DefaultLateDelay + time.Second)
	assert.True(t, w.Has(target, file, fp))
	assert.Equal(t, 0, w.PendingLate())
	assert.Equal(t, 1, w.LateLanded())
	evs := w.Events()
	require.Len(t, evs, 2)
	assert.True(t, evs[1].Landed)
	assert.True(t, evs[1].Changed)
	assert.Equal(t, 1, evs[1].N, "numbered as the call that stalled")
	assert.Equal(t, "AddAuthorizedKey", evs[1].Method)
	assert.False(t, evs[0].Landed)

	assert.Less(t, DefaultLateDelay, helperproto.HelperBudget, "the helper never writes after its own deadline")
}

// The late write obeys the owner rule at the moment it lands.
func TestKeyWorldLateWriteObeysTheOwnerRule(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	file := "/etc/ssh/keys/shared"
	line, fp, _ := newKey(t)
	w := NewKeyWorld()
	w.SetClock(nil)
	w.Put(target, "deploy", file)
	w.Put(target, "backup", file)
	w.SetFault(func(FaultPoint) Fault { return FaultLateWrite })
	// the call itself is refused before it can stall, as the real provider would
	_, err := worldSession(t, w, target).AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "backup", FilePath: file, Line: line}, nil)
	require.Error(t, err)
	w.FlushLate()
	assert.False(t, w.Has(target, file, fp), "a non-owner's stalled add never lands")
	assert.Equal(t, 0, w.LateLanded())
}

// T3-m6: a fault decision may read the world (it runs outside the lock).
func TestKeyWorldFaultMayReadTheWorld(t *testing.T) {
	target := uuid.New()
	file := "/home/deploy/.ssh/authorized_keys"
	w := NewKeyWorld()
	w.Put(target, "deploy", file)
	w.SetFault(func(FaultPoint) Fault {
		_ = w.Lines(target, file)
		_ = w.Events()
		return FaultNone
	})
	line, _, _ := newKey(t)
	done := make(chan error, 1)
	go func() {
		_, err := worldSession(t, w, target).AddAuthorizedKey(context.Background(), providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Line: line}, nil)
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the fault decision deadlocked on the world's lock")
	}
}

// T3-m3: the listed keys carry the flags and sizes the real provider's discovery sets.
func TestKeyWorldListCarriesFlagsAndBits(t *testing.T) {
	w := NewKeyWorld()
	target := uuid.New()
	a, _, _ := newKey(t)
	b, _, _ := newKey(t)
	ca, _, _ := newKey(t)
	w.Put(target, "root", "/root/.ssh/authorized_keys", a, `command="x" `+b, `cert-authority `+ca)
	keys, err := worldSession(t, w, target).ListAuthorizedKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 3)
	assert.ElementsMatch(t, []string{providers.FlagRootWithoutFrom}, keys[0].Flags)
	assert.Positive(t, keys[0].Bits)
	assert.Contains(t, keys[1].Flags, providers.FlagCommand)
	assert.Contains(t, keys[2].Flags, providers.FlagCertAuthority)

	w2 := NewKeyWorld()
	w2.Put(target, "deploy", "/h/ak", a, a)
	keys, err = worldSession(t, w2, target).ListAuthorizedKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 2)
	assert.Contains(t, keys[0].Flags, providers.FlagDuplicate)
	assert.Contains(t, keys[1].Flags, providers.FlagDuplicate)
}

// T3-m4: every provider refuses an empty request, the default fake included.
func TestDefaultFakeRefusesAnEmptyKeyLogin(t *testing.T) {
	p := New(providers.KindLinuxSSH, providers.CapKeyLogin)
	p.Configure(func(c *Config) { c.SkipHostKeyCheck = true })
	s, err := p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	_, err = s.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.helper_refused", pe.Code)
	assert.Equal(t, "os_user", pe.Params["field"])
}

// T3-m5: the fake key world and the real provider run one script of key semantics.
func TestKeyWorldKeyLifecycleConforms(t *testing.T) {
	providertest.CheckKeyLifecycle(t, providertest.KeyLifecycleHarness{New: func(tb testing.TB) providertest.KeyLifecycleEnv {
		w := NewKeyWorld()
		target := uuid.New()
		p := New(providers.KindLinuxSSH, providers.CapTestConnection, providers.CapAuthorizedKeys, providers.CapKeyLogin, providers.CapDiscoverSSHKeys)
		p.Configure(func(c *Config) { c.World = w; c.SkipHostKeyCheck = true })
		return providertest.KeyLifecycleEnv{
			Open: func(ctx context.Context) (providers.Session, error) {
				return p.Open(ctx, providers.TargetRef{ID: target, Kind: providers.KindLinuxSSH}, nil, providers.Env{})
			},
			OwnFile: func(u string) string { return "/home/" + u + "/.ssh/authorized_keys" },
			Seed:    func(u, f string, lines ...string) { w.Put(target, u, f, lines...) },
			SeedShared: func(f string, lines ...string) {
				for _, u := range []string{"root", "alice-svc", "deploy", "backup"} {
					w.Put(target, u, f, lines...)
				}
			},
			Lines:   func(f string) []string { return w.Lines(target, f) },
			Unread:  func(f string) { w.SetCoverage(target, f, providers.CoverageUnread) },
			Partial: func(f string) { w.SetCoverage(target, f, providers.CoveragePartial) },
		}
	}})
}

// Follow-up: key-files completeness in the fake key world.
func TestKeyWorldReportsKeyFilesAndTheirCompleteness(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	w := NewKeyWorld()
	w.Put(target, "deploy", "/h/deploy/ak")
	w.Put(target, "backup", "/h/backup/ak")
	w.Put(target, "ghost", "/h/ghost/ak")
	w.Put(uuid.New(), "other", "/h/other/ak")
	w.MarkKeyFilesIncomplete(target, "backup")
	w.HideKeyFiles(target, "ghost")
	p := New(providers.KindLinuxSSH, providers.CapDiscoverSSHKeys)
	p.Configure(func(c *Config) { c.World, c.SkipHostKeyCheck = w, true })
	s, err := p.Open(ctx, providers.TargetRef{ID: target}, nil, providers.Env{})
	require.NoError(t, err)
	d, err := s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []providers.UserKeyFiles{
		{OSUser: "backup", Files: []string{"/h/backup/ak"}, Complete: false},
		{OSUser: "deploy", Files: []string{"/h/deploy/ak"}, Complete: true},
	}, d.KeyFiles, "complete by default, incomplete when marked, absent when hidden")
	d, err = s.Discover(ctx, providers.DiscoverRequest{})
	require.NoError(t, err)
	assert.Nil(t, d.KeyFiles)

	// a scripted result wins over the world's
	p.Configure(func(c *Config) { c.Discovery.KeyFiles = []providers.UserKeyFiles{{OSUser: "x"}} })
	d, err = s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []providers.UserKeyFiles{{OSUser: "x"}}, d.KeyFiles)
}

// Follow-up 2: the world's listing states coverage; knobs make a file unread or the answer partial.
func TestKeyWorldFileWithAnUnreadableLineIsPartial(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	file := "/home/deploy/.ssh/authorized_keys"
	line, _, _ := newKey(t)
	_, otherFP, _ := newKey(t)
	w := NewKeyWorld()
	w.Put(target, "deploy", file, line, "garbage that is not a key")
	p := New(providers.KindLinuxSSH, providers.CapAuthorizedKeys)
	p.Configure(func(c *Config) { c.World, c.SkipHostKeyCheck = w, true })
	s, err := p.Open(ctx, providers.TargetRef{ID: target}, nil, providers.Env{})
	require.NoError(t, err)
	l, err := s.ListKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, providers.CoveragePartial, l.Coverage("deploy", file))
	assert.False(t, l.Absent("deploy", file, otherFP))
	assert.Len(t, l.Keys, 1, "the readable line is still listed")
	w.Put(target, "deploy", file, line, "# comment", "")
	l, err = s.ListKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, providers.CoverageComplete, l.Coverage("deploy", file))
	assert.True(t, l.Absent("deploy", file, otherFP))
}

func TestKeyWorldListKeysCoverage(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	file := "/home/deploy/.ssh/authorized_keys"
	line, fp, _ := newKey(t)
	_, otherFP, _ := newKey(t)
	w := NewKeyWorld()
	w.Put(target, "deploy", file, line)
	p := New(providers.KindLinuxSSH, providers.CapAuthorizedKeys)
	p.Configure(func(c *Config) { c.World, c.SkipHostKeyCheck = w, true })
	s, err := p.Open(ctx, providers.TargetRef{ID: target}, nil, providers.Env{})
	require.NoError(t, err)

	l, err := s.ListKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, providers.CoverageComplete, l.Coverage("deploy", file), "complete by default")
	assert.False(t, l.Absent("deploy", file, fp))
	assert.True(t, l.Absent("deploy", file, otherFP))

	// persistent knobs
	w.SetCoverage(target, file, providers.CoverageUnread)
	l, err = s.ListKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, providers.CoverageUnread, l.Coverage("deploy", file))
	assert.Empty(t, l.Keys, "an unread file lists no keys")
	assert.False(t, l.Absent("deploy", file, otherFP))
	w.SetCoverage(target, file, providers.CoveragePartial)
	l, err = s.ListKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, providers.CoveragePartial, l.Coverage("deploy", file))
	assert.False(t, l.Absent("deploy", file, otherFP))
	w.SetCoverage(target, file, providers.CoverageComplete)

	// fault points at a chosen call index: every call of the world is numbered, listings included
	base := len(w.Events())
	w.SetFault(func(p FaultPoint) Fault {
		switch {
		case p.Method == "ListKeys" && p.N == base+3:
			return FaultUnread
		case p.Method == "ListKeys" && p.N == base+4:
			return FaultPartial
		case p.Method == "ListKeys" && p.N == base+5:
			return FaultUnreachable
		}
		return FaultNone
	})
	want := []providers.CoverageState{providers.CoverageComplete, providers.CoverageComplete, providers.CoverageUnread, providers.CoveragePartial}
	for i, st := range want {
		l, err = s.ListKeys(ctx)
		require.NoError(t, err, i)
		assert.Equal(t, st, l.Coverage("deploy", file), "call %d", i+1)
	}
	_, err = s.ListKeys(ctx)
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.unreachable", pe.Code)
	assert.Equal(t, "ListKeys", w.Events()[base+4].Method)

	w.SetFault(func(FaultPoint) Fault { return FaultHang })
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	_, err = s.ListKeys(cctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	w.SetFault(nil)
	cc, cancel2 := context.WithCancel(ctx)
	cancel2()
	_, err = s.ListKeys(cc)
	assert.ErrorIs(t, err, context.Canceled)

	// without a world and without the capability
	q := New(providers.KindLinuxSSH, providers.CapAuthorizedKeys)
	q.Configure(func(c *Config) {
		c.SkipHostKeyCheck = true
		c.Keys = []providers.DiscoveredSSHKey{{OSUser: "u", FilePath: "/f", Fingerprint: "SHA256:a"}}
	})
	s2, err := q.Open(ctx, providers.TargetRef{ID: target}, nil, providers.Env{})
	require.NoError(t, err)
	l, err = s2.ListKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, l.Keys, 1)
	assert.Equal(t, providers.CoverageComplete, l.Coverage("u", "/f"), "scripted keys: their files count as read")
	r := New(providers.KindLinuxSSH, providers.CapTestConnection)
	r.Configure(func(c *Config) { c.SkipHostKeyCheck = true })
	s3, err := r.Open(ctx, providers.TargetRef{ID: target}, nil, providers.Env{})
	require.NoError(t, err)
	_, err = s3.ListKeys(ctx)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
}
