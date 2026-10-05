package providertest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
)

// KeyLifecycleEnv is one fresh world for CheckKeyLifecycle: a provider whose authorized_keys files
// the test can seed and read. The accounts root, deploy (uid order 1), backup (uid order 2) and
// alice-svc (the connection account) exist.
type KeyLifecycleEnv struct {
	// Open opens a session of the provider on the world.
	Open func(ctx context.Context) (providers.Session, error)
	// OwnFile is a file osUser's sshd reads and that belongs to osUser.
	OwnFile func(osUser string) string
	// Seed makes file one of osUser's own files, holding exactly these lines.
	Seed func(osUser, file string, lines ...string)
	// SeedShared makes file the one file every account reads, holding exactly these lines; root
	// owns it (the account the helper resolves it to: the first in uid order).
	SeedShared func(file string, lines ...string)
	// Lines returns the file's current lines.
	Lines func(file string) []string
	// Unread makes the next listings unable to read file (too large to read, skipped) without failing
	// the call; Partial makes them come back with a failed read or a cut answer for it.
	Unread, Partial func(file string)
}

// KeyLifecycleHarness builds a fresh world per scenario.
type KeyLifecycleHarness struct {
	New func(t testing.TB) KeyLifecycleEnv
}

type lifecycleSource struct{ s ssh.Signer }

func (l lifecycleSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return l.s, func() {}, nil
}

type lifecycleKey struct {
	line, fp string
	src      providers.CredentialSource
}

func newLifecycleKey(t testing.TB, options string) lifecycleKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " lifecycle"
	if options != "" {
		line = options + " " + line
	}
	return lifecycleKey{line: line, fp: ssh.FingerprintSHA256(s.PublicKey()), src: lifecycleSource{s}}
}

// CheckKeyLifecycle runs one script of key semantics against a provider, so the fake key world and
// the real provider cannot drift apart: add, list, test login, remove; the line number of an
// added or present key; a file the user does not read; a file shared by several users (changed
// only by its owner, read by all); refused lines; the last-key guards; logins by user. It does
// not model from= options (the real sshd would apply them to Alice's address).
func CheckKeyLifecycle(t testing.TB, h KeyLifecycleHarness) {
	t.Helper()
	ctx := context.Background()
	ok := func(env KeyLifecycleEnv) providers.Session {
		t.Helper()
		s, err := env.Open(ctx)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		return s
	}
	change := func(user, file, line, fp string) providers.AuthKeyChange {
		return providers.AuthKeyChange{OperationID: uuid.New(), OSUser: user, FilePath: file, Line: line, Fingerprint: fp}
	}
	login := func(s providers.Session, user string, k lifecycleKey) providers.KeyLoginOutcome {
		t.Helper()
		r, err := s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: user, Key: k.src})
		if err != nil {
			t.Errorf("login %s: %v", user, err)
		}
		return r.Outcome
	}
	wantLogin := func(s providers.Session, user string, k lifecycleKey, want providers.KeyLoginOutcome, why string) {
		t.Helper()
		if got := login(s, user, k); got != want {
			t.Errorf("%s: login as %s = %q, want %q", why, user, got, want)
		}
	}
	// keyFiles: a discovery names the user's file and says the list is complete.
	keyFiles := func(s providers.Session, user, file, why string) {
		t.Helper()
		d, err := s.Discover(ctx, providers.DiscoverRequest{SSHKeys: true})
		if err != nil {
			t.Errorf("%s: discover: %v", why, err)
			return
		}
		for _, k := range d.KeyFiles {
			if k.OSUser == user {
				if !slices.Contains(k.Files, file) || !k.Complete {
					t.Errorf("%s: key files of %s = %+v, want %s and Complete", why, user, k, file)
				}
				return
			}
		}
		t.Errorf("%s: no key files for %s in %+v", why, user, d.KeyFiles)
	}
	wantCode := func(err error, code, field, why string) {
		t.Helper()
		var pe *providers.Error
		if !errors.As(err, &pe) {
			t.Errorf("%s: got %v, want a *providers.Error %s", why, err, code)
			return
		}
		if pe.Code != code || (field != "" && pe.Params["field"] != field) {
			t.Errorf("%s: got %s %v, want %s field %q", why, pe.Code, pe.Params, code, field)
		}
	}
	reason := func(err error, code, why, want string) {
		t.Helper()
		var pe *providers.Error
		if !errors.As(err, &pe) || pe.Code != code || pe.Params["reason"] != want {
			t.Errorf("%s: got %v, want %s reason %q", why, err, code, want)
		}
	}

	// 1. add, number, idempotence, login, remove, login refused.
	{
		env := h.New(t)
		file := env.OwnFile("deploy")
		a, k, b, c := newLifecycleKey(t, ""), newLifecycleKey(t, ""), newLifecycleKey(t, ""), newLifecycleKey(t, "")
		env.Seed("deploy", file, "# comment", a.line, b.line)
		s := ok(env)
		defer func() { _ = s.Close() }()
		wantLogin(s, "deploy", k, providers.KeyLoginRefused, "a key not in the file")
		keyFiles(s, "deploy", file, "a plain account")
		res, err := s.AddAuthorizedKey(ctx, change("deploy", file, k.line, ""), nil)
		if err != nil || !res.Changed || res.LineNo != 4 {
			t.Errorf("add: %+v %v, want Changed on line 4", res, err)
		}
		res, err = s.AddAuthorizedKey(ctx, change("deploy", file, k.line, ""), nil)
		if err != nil || res.Changed || res.LineNo != 4 {
			t.Errorf("add again: %+v %v, want unchanged, line 4", res, err)
		}
		res, err = s.AddAuthorizedKey(ctx, change("deploy", file, b.line, ""), nil)
		if err != nil || res.Changed || res.LineNo != 3 {
			t.Errorf("add a key in the middle: %+v %v, want unchanged, line 3", res, err)
		}
		res, err = s.AddAuthorizedKey(ctx, change("deploy", file, a.line, ""), nil)
		if err != nil || res.Changed || res.LineNo != 2 {
			t.Errorf("add the first key: %+v %v, want unchanged, line 2", res, err)
		}
		keys, err := s.ListAuthorizedKeys(ctx)
		if err != nil {
			t.Errorf("list: %v", err)
		}
		found := false
		for _, dk := range keys {
			if dk.OSUser == "deploy" && dk.FilePath == file && dk.Fingerprint == k.fp && dk.LineNo == 4 {
				found = true
			}
		}
		if !found {
			t.Errorf("list does not show the added key on line 4: %+v", keys)
		}
		wantLogin(s, "deploy", k, providers.KeyLoginAccepted, "after the add")
		wantLogin(s, "backup", k, providers.KeyLoginRefused, "another user's login does not read deploy's file")
		wantLogin(s, "ghost", k, providers.KeyLoginRefused, "an account that has no such key")
		wantLogin(s, "deploy", c, providers.KeyLoginRefused, "a key that was never added")
		_, err = s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "bad user", Key: k.src})
		wantCode(err, "ssh.helper_refused", "os_user", "an account name that cannot exist")

		rm, err := s.RemoveAuthorizedKey(ctx, change("deploy", file, "", k.fp), nil)
		if err != nil || rm.Removed != 1 {
			t.Errorf("remove: %+v %v", rm, err)
		}
		if got := env.Lines(file); !slices.Equal(got, []string{"# comment", a.line, b.line}) {
			t.Errorf("file after the removal: %q", got)
		}
		wantLogin(s, "deploy", k, providers.KeyLoginRefused, "after the removal")
		rm, err = s.RemoveAuthorizedKey(ctx, change("deploy", file, "", k.fp), nil)
		if err != nil || rm.Removed != 0 || rm.Changed {
			t.Errorf("remove an absent key: %+v %v", rm, err)
		}
	}

	// 1b. a listing states what it read: only a completely read file proves a key absent.
	for _, mode := range []string{"unread", "partial"} {
		env := h.New(t)
		file := env.OwnFile("deploy")
		a, c := newLifecycleKey(t, ""), newLifecycleKey(t, "")
		env.Seed("deploy", file, a.line)
		s := ok(env)
		l, err := s.ListKeys(ctx)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if got := l.Coverage("deploy", file); got != providers.CoverageComplete || !l.Absent("deploy", file, c.fp) || l.Absent("deploy", file, a.fp) {
			t.Errorf("%s: a file read completely: coverage %q, absent(other) %v, absent(held) %v", mode, got, l.Absent("deploy", file, c.fp), l.Absent("deploy", file, a.fp))
		}
		want := providers.CoverageUnread
		if mode == "unread" {
			env.Unread(file)
		} else {
			env.Partial(file)
			want = providers.CoveragePartial
		}
		l, err = s.ListKeys(ctx)
		if err != nil {
			t.Fatalf("list after %s: %v", mode, err)
		}
		if got := l.Coverage("deploy", file); got != want {
			t.Errorf("%s: coverage %q, want %q", mode, got, want)
		}
		if l.Absent("deploy", file, c.fp) || l.Absent("deploy", file, a.fp) {
			t.Errorf("%s: a file that was not read completely must not prove any key absent", mode)
		}
		if got := l.Coverage("deploy", "/home/deploy/.ssh/not-a-candidate"); got != providers.CoverageUnknown {
			t.Errorf("%s: a file the listing does not name has coverage %q, want unknown", mode, got)
		}
		_ = s.Close()
	}

	// 1c. only a file whose every line was read and understood proves a key absent: a line that is
	// not a key (and not a comment or blank) makes the file partial; comments, blank lines and an
	// empty file are read completely.
	{
		env := h.New(t)
		file := env.OwnFile("deploy")
		a, c := newLifecycleKey(t, ""), newLifecycleKey(t, "")
		env.Seed("deploy", file, "# a comment", "", a.line)
		s := ok(env)
		l, err := s.ListKeys(ctx)
		if err != nil || l.Coverage("deploy", file) != providers.CoverageComplete || !l.Absent("deploy", file, c.fp) {
			t.Errorf("comments and blank lines: %q %v, want complete", l.Coverage("deploy", file), err)
		}
		env.Seed("deploy", file)
		l, err = s.ListKeys(ctx)
		if err != nil || l.Coverage("deploy", file) != providers.CoverageComplete || !l.Absent("deploy", file, c.fp) {
			t.Errorf("an empty file: %q %v, want complete", l.Coverage("deploy", file), err)
		}
		env.Seed("deploy", file, a.line, "this line is not a key", "ssh-ed25519 not-base64 broken")
		l, err = s.ListKeys(ctx)
		if err != nil {
			t.Errorf("list: %v", err)
		}
		if got := l.Coverage("deploy", file); got != providers.CoveragePartial {
			t.Errorf("a file with unreadable lines: coverage %q, want partial", got)
		}
		if l.Absent("deploy", file, c.fp) {
			t.Errorf("a key was proven absent from a file with lines that could not be read")
		}
		_ = s.Close()
	}

	// 2. a file the user does not read: refused, and the key does not log in.
	{
		env := h.New(t)
		a, k := newLifecycleKey(t, ""), newLifecycleKey(t, "")
		env.Seed("deploy", env.OwnFile("deploy"), a.line)
		s := ok(env)
		defer func() { _ = s.Close() }()
		_, err := s.AddAuthorizedKey(ctx, change("deploy", "/home/deploy/.ssh/other", k.line, ""), nil)
		wantCode(err, "ssh.helper_refused", "", "an add to a file the user does not read")
		wantLogin(s, "deploy", k, providers.KeyLoginRefused, "a key added to the wrong file")
	}

	// 3. a shared file: changed only by its owner, read by every user.
	{
		env := h.New(t)
		shared := "/etc/ssh/keys/shared"
		a, k := newLifecycleKey(t, ""), newLifecycleKey(t, "")
		env.SeedShared(shared, a.line)
		s := ok(env)
		defer func() { _ = s.Close() }()
		_, err := s.AddAuthorizedKey(ctx, change("backup", shared, k.line, ""), nil)
		wantCode(err, "ssh.helper_refused", "os_user", "a non-owner's add")
		_, err = s.RemoveAuthorizedKey(ctx, change("backup", shared, "", a.fp), nil)
		wantCode(err, "ssh.helper_refused", "os_user", "a non-owner's removal")
		if got := env.Lines(shared); !slices.Equal(got, []string{a.line}) {
			t.Errorf("a refused change touched the file: %q", got)
		}
		_, err = s.AddAuthorizedKey(ctx, change("deploy", shared, k.line, ""), nil)
		wantCode(err, "ssh.helper_refused", "os_user", "deploy is not the owner of the shared file")
		if res, err := s.AddAuthorizedKey(ctx, change("root", shared, k.line, ""), nil); err != nil || !res.Changed || res.LineNo != 2 {
			t.Errorf("the owner's add: %+v %v", res, err)
		}
		wantLogin(s, "root", k, providers.KeyLoginAccepted, "the owner reads the shared file")
		wantLogin(s, "backup", k, providers.KeyLoginAccepted, "every user reads the shared file")
		keyFiles(s, "backup", shared, "a shared file is a candidate of every user")
	}

	// 4. lines that are refused, and lines that never log in.
	{
		env := h.New(t)
		file := env.OwnFile("deploy")
		ca := newLifecycleKey(t, "cert-authority")
		env.Seed("deploy", file, ca.line)
		s := ok(env)
		defer func() { _ = s.Close() }()
		wantLogin(s, "deploy", ca, providers.KeyLoginRefused, "a cert-authority line is not a key that logs in")
		other := newLifecycleKey(t, "cert-authority")
		_, err := s.AddAuthorizedKey(ctx, change("deploy", file, other.line, ""), nil)
		wantCode(err, "ssh.helper_refused", "line", "a cert-authority line")
		_, err = s.AddAuthorizedKey(ctx, change("deploy", file, "not a key", ""), nil)
		wantCode(err, "ssh.helper_refused", "line", "a line that is not a key")
		_, err = s.RemoveAuthorizedKey(ctx, change("deploy", file, "", ca.fp), nil)
		reason(err, "sshkey.not_removable", "removing a cert-authority line", "cert_authority")
		if got := env.Lines(file); !slices.Equal(got, []string{ca.line}) {
			t.Errorf("a refused change touched the file: %q", got)
		}
	}

	// 5. the last-key guards.
	{
		env := h.New(t)
		rootFile, svcFile := env.OwnFile("root"), env.OwnFile("alice-svc")
		r, v, w := newLifecycleKey(t, ""), newLifecycleKey(t, ""), newLifecycleKey(t, "")
		env.Seed("root", rootFile, r.line)
		env.Seed("alice-svc", svcFile, v.line, w.line)
		s := ok(env)
		defer func() { _ = s.Close() }()
		_, err := s.RemoveAuthorizedKey(ctx, change("root", rootFile, "", r.fp), nil)
		var pe *providers.Error
		if !errors.As(err, &pe) || pe.Code != "sshkey.last_root_key" {
			t.Errorf("last key of root: got %v, want sshkey.last_root_key", err)
		}
		req := change("root", rootFile, "", r.fp)
		req.AllowLastRootKey = true
		if res, err := s.RemoveAuthorizedKey(ctx, req, nil); err != nil || res.Removed != 1 {
			t.Errorf("confirmed removal of root's last key: %+v %v", res, err)
		}
		if res, err := s.RemoveAuthorizedKey(ctx, change("alice-svc", svcFile, "", v.fp), nil); err != nil || res.Removed != 1 {
			t.Errorf("one of two keys of the connection account: %+v %v", res, err)
		}
		_, err = s.RemoveAuthorizedKey(ctx, change("alice-svc", svcFile, "", w.fp), nil)
		reason(err, "sshkey.own_key_protected", "the last key of the connection account", "last_key_of_connection_account")
	}
}
