package plan

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/sshkeys/keymat"
)

var (
	t1    = uuid.MustParse("00000000-0000-7000-8000-000000000001")
	t2    = uuid.MustParse("00000000-0000-7000-8000-000000000002")
	keyID = uuid.MustParse("00000000-0000-7000-8000-0000000000aa")
)

func okTarget(id uuid.UUID, name string) Target {
	return Target{ID: id, Name: name, Status: "ok", ConnectionUser: "alice-svc", SSHDRead: true, PermitRootLogin: "prohibit-password",
		PubkeyAuthentication: "yes", ConnectionFilesKnown: true, ConnectionFiles: []string{"/home/alice-svc/.ssh/authorized_keys"}}
}

func loc(target uuid.UUID, user, file, options string) Location {
	return Location{ID: uuid.Must(uuid.NewV7()), TargetID: target, OSUser: user, FilePath: file, Options: options, Comment: "old"}
}

func input(locs ...Location) Input {
	return Input{
		Key: Key{ID: keyID, Fingerprint: "SHA256:" + "A0aB1bC2cD3dE4eF5fG6gH7hI8iJ9jK0kL1lM2mN3nO", PublicKey: "ssh-ed25519 AAAA",
			Label: "ci", Managed: true, KeyType: "ed25519"},
		Locations:      locs,
		Targets:        map[uuid.UUID]Target{t1: okTarget(t1, "web-01"), t2: okTarget(t2, "db-01")},
		Protected:      []string{"SHA256:platformplatformplatformplatformplatformpla"},
		NewKeyType:     "same",
		OverlapMinutes: 7 * 1440,
		NewComment:     "alice:ci:2026-10-05",
	}
}

func TestFlagNameMatchesProviders(t *testing.T) {
	assert.Equal(t, providers.FlagCertAuthority, flagCertAuthority)
	assert.Equal(t, providers.FlagDuplicate, flagDuplicate)
}

func TestOnlyManagedKeys(t *testing.T) {
	in := input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
	in.Key.Managed = false
	_, err := Build(in)
	assert.ErrorIs(t, err, ErrNotManaged)
	in.Key.Managed, in.Key.Retired = true, true
	_, err = Build(in)
	assert.ErrorIs(t, err, ErrRetired)
}

// F-36, SEC-081: Alice's own key is refused by its flag, by fingerprint (any comment or options) and
// when any of its locations is Alice's connection key.
func TestNeverAlicesOwnKey(t *testing.T) {
	in := input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
	in.Key.IsPlatform = true
	_, err := Build(in)
	assert.ErrorIs(t, err, ErrOwnKey)

	in = input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
	in.Protected = append(in.Protected, in.Key.Fingerprint)
	_, err = Build(in)
	assert.ErrorIs(t, err, ErrOwnKey)

	l := loc(t1, "alice-svc", "/home/alice-svc/.ssh/authorized_keys", "")
	l.IsAliceConnectionKey = true
	_, err = Build(input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""), l))
	assert.ErrorIs(t, err, ErrOwnKey)
}

func TestSkipReasons(t *testing.T) {
	cases := []struct {
		name   string
		target func(*Target)
		loc    func(*Location)
		want   string
	}{
		{"deleted", func(t *Target) { t.Deleted = true }, nil, SkipTargetDeleted},
		{"pending", func(t *Target) { t.Status = "pending_host_key" }, nil, SkipHostKeyUnconfirmed},
		{"changed", func(t *Target) { t.Status = "host_key_changed" }, nil, SkipHostKeyChanged},
		{"unreachable", func(t *Target) { t.Status = "unreachable" }, nil, SkipTargetNotConnected},
		{"auth failed", func(t *Target) { t.Status = "auth_failed" }, nil, SkipTargetNotConnected},
		{"missing", nil, func(l *Location) { l.Missing = true }, SkipMissing},
		{"cert authority", nil, func(l *Location) { l.Flags = []string{"cert_authority"} }, SkipCertAuthority},
		{"duplicate lines", nil, func(l *Location) { l.Flags = []string{"duplicate"} }, SkipDuplicateLines},
		{"altered options", nil, func(l *Location) { l.Options = "command=\"a\ufffdb\"" }, SkipOptionsUnreadable},
		{"options cut in the inventory", nil, func(l *Location) { l.Options = "no-pty,environment=\"K=vvvv…" }, SkipOptionsTruncated},
		{"connection account", nil, func(l *Location) { l.OSUser = "alice-svc" }, SkipConnectionAccount},
		// Task 9 re-review N1: what BeginAdd refuses at send time is skipped at plan time.
		{"connection files unknown", func(t *Target) { t.ConnectionFilesKnown = false }, nil, SkipConnectionFilesUnknown},
		{"connection account's file", func(t *Target) { t.ConnectionFiles = []string{"/etc/ssh/keys", "/home/deploy/.ssh/authorized_keys"} }, nil,
			SkipConnectionAccountFile},
		{"keys elsewhere", func(t *Target) { t.KeysManagedElsewhere = true }, nil, SkipKeysManagedElsewhere},
		{"keys elsewhere for user", func(t *Target) { t.ManagedElsewhereUsers = []string{"deploy"} }, nil, SkipKeysManagedElsewhere},
		{"sshd unread", func(t *Target) { t.SSHDRead = false }, nil, SkipSSHDUnreadable},
		{"sshd unread for user", func(t *Target) { t.SSHDUnreadUsers = []string{"deploy"} }, nil, SkipSSHDUnreadable},
		{"pubkey off", func(t *Target) { t.PubkeyAuthentication = "no" }, nil, SkipPubkeyDisabled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			other := loc(t2, "deploy", "/home/deploy/.ssh/authorized_keys", "")
			l := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
			if c.loc != nil {
				c.loc(&l)
			}
			in := input(l, other)
			if c.target != nil {
				tg := in.Targets[t1]
				c.target(&tg)
				in.Targets[t1] = tg
			}
			p, err := Build(in)
			require.NoError(t, err)
			i := slices.IndexFunc(p.Actions, func(a Action) bool { return a.LocationID == l.ID })
			assert.Equal(t, c.want, p.Actions[i].Skip)
			assert.False(t, p.Actions[i].Verify)
			assert.Equal(t, 1, p.Changes)
			assert.Equal(t, 1, p.Skips)
		})
	}
	// A location whose target is not in the map at all is a deleted target.
	in := input(loc(uuid.Must(uuid.NewV7()), "deploy", "/x", ""), loc(t2, "deploy", "/y", ""))
	p, err := Build(in)
	require.NoError(t, err)
	assert.Equal(t, SkipTargetDeleted, p.Actions[slices.IndexFunc(p.Actions, func(a Action) bool { return a.TargetID != t2 })].Skip)
}

func TestNothingToRotateStillReturnsThePlan(t *testing.T) {
	l := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	l.Missing = true
	p, err := Build(input(l))
	assert.ErrorIs(t, err, ErrNothingToRotate)
	assert.Equal(t, 1, p.Skips)
	assert.Equal(t, SkipMissing, p.Actions[0].Skip)
}

// Review Focus 1, S10: a file that holds the key for several users is skipped as a whole, never
// changed, whether or not one of its users would be skipped anyway.
func TestSharedFileSkippedTogether(t *testing.T) {
	a := loc(t1, "deploy", "/etc/ssh/keys/shared", "")
	b := loc(t1, "backup", "/etc/ssh/keys/shared", "")
	c := loc(t1, "app", "/home/app/.ssh/authorized_keys", "")
	in := input(a, b, c)
	p, err := Build(in)
	require.NoError(t, err)
	byLoc := map[uuid.UUID]Action{}
	for _, x := range p.Actions {
		byLoc[x.LocationID] = x
	}
	assert.Equal(t, SkipSharedFile, byLoc[a.ID].Skip)
	assert.Equal(t, SkipSharedFile, byLoc[b.ID].Skip)
	assert.False(t, byLoc[a.ID].Verify)
	assert.Equal(t, "", byLoc[c.ID].Skip)
	assert.Equal(t, 1, p.Changes)
	assert.Equal(t, 2, p.Skips)

	// A user skipped for its own reason keeps that reason; the other user's location is skipped as shared.
	tg := in.Targets[t1]
	tg.SSHDUnreadUsers = []string{"backup"}
	in.Targets[t1] = tg
	p, err = Build(in)
	require.NoError(t, err)
	byLoc = map[uuid.UUID]Action{}
	for _, x := range p.Actions {
		byLoc[x.LocationID] = x
	}
	assert.Equal(t, SkipSharedFile, byLoc[a.ID].Skip)
	assert.Equal(t, SkipSSHDUnreadable, byLoc[b.ID].Skip)

	// The same path on another server is another file.
	_, err = Build(input(loc(t1, "deploy", "/etc/ssh/keys/shared", ""), loc(t2, "deploy", "/etc/ssh/keys/shared", "")))
	assert.NoError(t, err)
	// Only shared locations: nothing changes.
	p, err = Build(input(a, b))
	assert.ErrorIs(t, err, ErrNothingToRotate)
	assert.Equal(t, 2, p.Skips)
}

// S8: a file that holds the key twice, or options altered when they were read, is not rotated: the
// stored row is not what sshd applies.
func TestDuplicateOrAlteredOptionsAreSkipped(t *testing.T) {
	d := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	d.Flags = []string{"duplicate"}
	o := loc(t1, "app", "/home/app/.ssh/authorized_keys", "from=\"10.0.0.\ufffd\"")
	ok := loc(t1, "web", "/home/web/.ssh/authorized_keys", "restrict")
	p, err := Build(input(d, o, ok))
	require.NoError(t, err)
	got := map[string]string{}
	for _, a := range p.Actions {
		got[a.OSUser] = a.Skip
	}
	assert.Equal(t, map[string]string{"deploy": SkipDuplicateLines, "app": SkipOptionsUnreadable, "web": ""}, got)
	assert.Equal(t, 1, p.Changes)
}

func TestRootLoginDisabledIsNotVerifiable(t *testing.T) {
	r := loc(t1, "root", "/root/.ssh/authorized_keys", "")
	z := loc(t1, "toor", "/root/.ssh/authorized_keys2", "")
	d := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", `from="10.0.0.0/8"`)
	in := input(r, z, d)
	tg := in.Targets[t1]
	tg.PermitRootLogin = "no"
	tg.UID0Users = []string{"root", "toor"}
	in.Targets[t1] = tg
	p, err := Build(in)
	require.NoError(t, err)
	require.Len(t, p.Actions, 3)
	seen := map[string]bool{}
	for _, a := range p.Actions {
		seen[a.OSUser] = true
		switch a.OSUser {
		case "root", "toor":
			assert.False(t, a.Verify)
			assert.Equal(t, "root_login_disabled", a.VerifyNote)
		case "deploy":
			assert.True(t, a.Verify)
			assert.Equal(t, "from_option", a.VerifyNote)
		}
	}
	assert.Equal(t, map[string]bool{"root": true, "toor": true, "deploy": true}, seen)
}

// A root location on a server with PermitRootLogin forced-commands-only is skipped unless its line
// carries command=: the test login of a plain key can never pass there.
func TestRootForcedCommandsOnlyIsSkipped(t *testing.T) {
	r := loc(t1, "root", "/root/.ssh/authorized_keys", "")
	z := loc(t1, "toor", "/root/.ssh/authorized_keys2", `restrict,Command="/usr/bin/backup, now"`)
	d := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	in := input(r, z, d)
	tg := in.Targets[t1]
	tg.PermitRootLogin = "forced-commands-only"
	tg.UID0Users = []string{"toor"}
	in.Targets[t1] = tg
	p, err := Build(in)
	require.NoError(t, err)
	got := map[string]string{}
	for _, a := range p.Actions {
		got[a.OSUser] = a.Skip
	}
	assert.Equal(t, map[string]string{"root": SkipRootForcedCommands, "toor": "", "deploy": ""}, got)
	// Another PermitRootLogin value does not skip.
	tg.PermitRootLogin = "prohibit-password"
	in.Targets[t1] = tg
	p, err = Build(in)
	require.NoError(t, err)
	assert.Equal(t, 0, p.Skips)
}

func TestNewKeyTypeIsValidated(t *testing.T) {
	for _, bad := range []string{"dsa", "rsa-2048", "RSA-4096"} {
		in := input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
		in.NewKeyType = bad
		_, err := Build(in)
		assert.ErrorIs(t, err, ErrNewKeyType, bad)
	}
	in := input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
	in.Key.KeyType = ""
	_, err := Build(in) // "same" of a key with no known type
	assert.ErrorIs(t, err, ErrNewKeyType)
	for _, good := range []string{"same", "", "ed25519", "rsa-3072", "rsa-4096", "ecdsa-p256"} {
		in := input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
		in.NewKeyType = good
		_, err := Build(in)
		assert.NoError(t, err, good)
	}
}

func TestLinesAndNewType(t *testing.T) {
	in := input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "restrict"))
	in.NewKeyType = "rsa-4096"
	p, err := Build(in)
	require.NoError(t, err)
	assert.Equal(t, "rsa-4096", p.NewKeyType)
	assert.Equal(t, "restrict ssh-ed25519 AAAA old", p.Actions[0].RemoveLine)
	assert.Equal(t, "restrict rsa-4096 (new key) alice:ci:2026-10-05", p.Actions[0].AddLine)
	in.NewKeyType = "same"
	p, err = Build(in)
	require.NoError(t, err)
	assert.Equal(t, "ed25519", p.NewKeyType)
	in.NewKeyType = ""
	p, err = Build(in)
	require.NoError(t, err)
	assert.Equal(t, "ed25519", p.NewKeyType)
}

// Dry run equals the actual plan: the same state in any order gives the same plan and digest.
func TestPlanIsDeterministic(t *testing.T) {
	a := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	b := loc(t2, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	c := loc(t1, "app", "/home/app/.ssh/authorized_keys", "restrict")
	p1, err := Build(input(a, b, c))
	require.NoError(t, err)
	p2, err := Build(input(c, a, b))
	require.NoError(t, err)
	assert.Equal(t, p1.Actions, p2.Actions)
	assert.Equal(t, p1.Digest(), p2.Digest())
	for i, x := range p1.Actions {
		assert.Equal(t, i+1, x.N)
	}
}

func TestDigestIgnoresOrderAndDisplayFields(t *testing.T) {
	a := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	in := input(a)
	p1, err := Build(in)
	require.NoError(t, err)
	in.Targets[t1] = func() Target { x := in.Targets[t1]; x.Name = "renamed"; return x }()
	in.NewComment = "alice:ci:2027-01-01"
	l := in.Locations[0]
	l.Comment = "a different old comment"
	in.Locations[0] = l
	p2, err := Build(in)
	require.NoError(t, err)
	assert.Equal(t, p1.Digest(), p2.Digest())
	assert.Regexp(t, `^[0-9a-f]{64}$`, p1.Digest())
}

func TestDigestChangesWithEveryDecision(t *testing.T) {
	fixed := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	base := func() Input { return input(fixed) }
	ref, err := Build(base())
	require.NoError(t, err)
	changes := map[string]func(*Input){
		"overlap":                  func(in *Input) { in.OverlapMinutes = 1 },
		"new key type":             func(in *Input) { in.NewKeyType = "rsa-3072" },
		"options":                  func(in *Input) { in.Locations[0].Options = "restrict" },
		"user":                     func(in *Input) { in.Locations[0].OSUser = "app" },
		"file":                     func(in *Input) { in.Locations[0].FilePath = "/home/deploy/.ssh/authorized_keys2" },
		"skip":                     func(in *Input) { x := in.Targets[t1]; x.Status = "unreachable"; in.Targets[t1] = x },
		"connection files unknown": func(in *Input) { x := in.Targets[t1]; x.ConnectionFilesKnown = false; in.Targets[t1] = x },
		"connection account's file": func(in *Input) {
			x := in.Targets[t1]
			x.ConnectionFiles = []string{"/home/deploy/.ssh/authorized_keys"}
			in.Targets[t1] = x
		},
		"verify note": func(in *Input) { in.Locations[0].Options = `from="10.0.0.0/8"` },
		"another location": func(in *Input) {
			in.Locations = append(in.Locations, loc(t2, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
		},
	}
	again, err := Build(base())
	require.NoError(t, err)
	assert.Equal(t, ref.Digest(), again.Digest(), "the same state gives the same digest")
	for name, change := range changes {
		in := base()
		change(&in)
		p, _ := Build(in) // "skip" leaves nothing to rotate: the plan is still returned
		assert.NotEqual(t, ref.Digest(), p.Digest(), name)
	}
}

// Every input of the digest is pinned by a change of exactly that field. The field lists are checked
// against the structs by reflection, so a field added later fails here until it is classified.
func TestDigestPinsEveryField(t *testing.T) {
	base := func() Plan {
		return Plan{KeyID: keyID, Fingerprint: "SHA256:a", NewKeyType: "ed25519", Overlap: 60, Actions: []Action{
			{N: 1, LocationID: t1, TargetID: t2, TargetName: "web", OSUser: "u", FilePath: "/f", Options: "o", Skip: "s",
				Verify: true, VerifyNote: "n", RemoveLine: "r", AddLine: "a"}}}
	}
	planDigested := map[string]func(*Plan){
		"KeyID":       func(p *Plan) { p.KeyID = t1 },
		"Fingerprint": func(p *Plan) { p.Fingerprint = "SHA256:b" },
		"NewKeyType":  func(p *Plan) { p.NewKeyType = "rsa-4096" },
		"Overlap":     func(p *Plan) { p.Overlap++ },
		"Actions":     func(p *Plan) { p.Actions = append(p.Actions, p.Actions[0]) },
	}
	planIgnored := []string{"Changes", "Skips"} // derived from Actions
	actionDigested := map[string]func(*Action){
		"LocationID": func(a *Action) { a.LocationID = t2 },
		"TargetID":   func(a *Action) { a.TargetID = t1 },
		"OSUser":     func(a *Action) { a.OSUser = "v" },
		"FilePath":   func(a *Action) { a.FilePath = "/g" },
		"Options":    func(a *Action) { a.Options = "p" },
		"Skip":       func(a *Action) { a.Skip = "" },
		"Verify":     func(a *Action) { a.Verify = false },
		"VerifyNote": func(a *Action) { a.VerifyNote = "" },
	}
	actionIgnored := []string{"N", "TargetName", "RemoveLine", "AddLine"} // order and display text
	check := func(typ reflect.Type, digested []string, ignored []string) {
		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Name
			assert.True(t, slices.Contains(digested, name) != slices.Contains(ignored, name),
				"%s.%s must be classified as digested or ignored, exactly one", typ, name)
		}
		for _, name := range slices.Concat(digested, ignored) {
			_, ok := typ.FieldByName(name)
			assert.True(t, ok, "%s has no field %s", typ, name)
		}
	}
	check(reflect.TypeOf(Plan{}), slices.Collect(maps.Keys(planDigested)), planIgnored)
	check(reflect.TypeOf(Action{}), slices.Collect(maps.Keys(actionDigested)), actionIgnored)

	ref := base().Digest()
	assert.Equal(t, ref, base().Digest())
	for name, change := range planDigested {
		p := base()
		change(&p)
		assert.NotEqual(t, ref, p.Digest(), "Plan.%s", name)
	}
	for name, change := range actionDigested {
		p := base()
		change(&p.Actions[0])
		assert.NotEqual(t, ref, p.Digest(), "Action.%s", name)
	}
	for _, name := range actionIgnored {
		p := base()
		a := &p.Actions[0]
		switch name {
		case "N":
			a.N = 9
		case "TargetName":
			a.TargetName = "other"
		case "RemoveLine":
			a.RemoveLine = "x"
		case "AddLine":
			a.AddLine = "x"
		}
		assert.Equal(t, ref, p.Digest(), "Action.%s is display only", name)
	}
	p := base()
	p.Changes, p.Skips = 7, 7
	assert.Equal(t, ref, p.Digest())
}

// The digest is injective: strings that differ only in invalid UTF-8, or whose boundaries move
// between fields, give different digests.
func TestDigestIsInjective(t *testing.T) {
	mk := func(user, file string) Plan {
		return Plan{Actions: []Action{{OSUser: user, FilePath: file}}}
	}
	assert.NotEqual(t, mk("\xff", "/f").Digest(), mk("\xfe", "/f").Digest())
	assert.NotEqual(t, mk("\xff", "/f").Digest(), mk("\ufffd", "/f").Digest())
	assert.NotEqual(t, mk("ab", "c").Digest(), mk("a", "bc").Digest())
	assert.NotEqual(t, Plan{}.Digest(), Plan{Actions: []Action{{}}}.Digest())
}

// Review Focus 4: a server fact that changes only a verification rule, or only a skip reason, changes
// the digest although every location and option stays the same.
func TestDigestFollowsVerifyAndSkipDecisions(t *testing.T) {
	root := loc(t1, "root", "/root/.ssh/authorized_keys", "")
	gone := loc(t2, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	gone.Missing = true
	other := loc(t1, "app", "/home/app/.ssh/authorized_keys", "")
	base := func() Input { return input(root, gone, other) }
	ref, err := Build(base())
	require.NoError(t, err)

	in := base()
	tg := in.Targets[t1]
	tg.PermitRootLogin = "no"
	in.Targets[t1] = tg
	p, err := Build(in)
	require.NoError(t, err)
	assert.Equal(t, ref.Changes, p.Changes)
	assert.Equal(t, ref.Skips, p.Skips)
	assert.NotEqual(t, ref.Digest(), p.Digest(), "only Verify and VerifyNote differ")

	in = base()
	tg = in.Targets[t2]
	tg.Status = "unreachable"
	in.Targets[t2] = tg
	p, err = Build(in)
	require.NoError(t, err)
	assert.Equal(t, ref.Changes, p.Changes)
	assert.Equal(t, ref.Skips, p.Skips)
	assert.NotEqual(t, ref.Digest(), p.Digest(), "only Skip differs (missing -> target_not_connected)")
}

func TestSkipForIsTheBuildRule(t *testing.T) {
	tg := okTarget(t1, "web-01")
	l := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	assert.Equal(t, "", SkipFor(tg, true, l))
	tg.KeysManagedElsewhere = true
	assert.Equal(t, SkipKeysManagedElsewhere, SkipFor(tg, true, l))
	assert.Equal(t, SkipTargetDeleted, SkipFor(tg, false, l))
}

// Re-review A-m2: the send-time rule is the planner's rule on the same facts, without the connection
// states (a stale unreachable, checking or auth_failed status is not a reason not to try), and with
// the shared-file rule over the key's locations in the file.
func TestSkipAtSendReevaluatesTheDurableReasonsOnly(t *testing.T) {
	durable := []struct {
		name   string
		target func(*Target)
		loc    func(*Location)
		want   string
	}{
		{"deleted", func(t *Target) { t.Deleted = true }, nil, SkipTargetDeleted},
		{"pending host key", func(t *Target) { t.Status = "pending_host_key" }, nil, SkipHostKeyUnconfirmed},
		{"changed host key", func(t *Target) { t.Status = "host_key_changed" }, nil, SkipHostKeyChanged},
		{"disabled", func(t *Target) { t.Status = "disabled" }, nil, SkipTargetNotConnected},
		{"missing", nil, func(l *Location) { l.Missing = true }, SkipMissing},
		{"cert authority", nil, func(l *Location) { l.Flags = []string{"cert_authority"} }, SkipCertAuthority},
		{"duplicate lines", nil, func(l *Location) { l.Flags = []string{"duplicate"} }, SkipDuplicateLines},
		{"options unreadable", nil, func(l *Location) { l.Options = "command=\"a�b\"" }, SkipOptionsUnreadable},
		{"options truncated", nil, func(l *Location) { l.Options = "no-pty,environment=\"K=vvvv…" }, SkipOptionsTruncated},
		{"connection account", nil, func(l *Location) { l.OSUser = "alice-svc" }, SkipConnectionAccount},
		{"connection files unknown", func(t *Target) { t.ConnectionFilesKnown = false }, nil, SkipConnectionFilesUnknown},
		{"connection account's file", func(t *Target) { t.ConnectionFiles = []string{"/home/deploy/.ssh/authorized_keys"} }, nil,
			SkipConnectionAccountFile},
		{"keys managed elsewhere", func(t *Target) { t.KeysManagedElsewhere = true }, nil, SkipKeysManagedElsewhere},
		{"keys managed elsewhere for the user", func(t *Target) { t.ManagedElsewhereUsers = []string{"deploy"} }, nil, SkipKeysManagedElsewhere},
		{"sshd unreadable", func(t *Target) { t.SSHDRead = false }, nil, SkipSSHDUnreadable},
		{"sshd unreadable for the user", func(t *Target) { t.SSHDUnreadUsers = []string{"deploy"} }, nil, SkipSSHDUnreadable},
		{"pubkey off", func(t *Target) { t.PubkeyAuthentication = "no" }, nil, SkipPubkeyDisabled},
		{"root forced commands only", func(t *Target) { t.PermitRootLogin = "forced-commands-only" }, func(l *Location) {
			l.OSUser, l.FilePath = "root", "/root/.ssh/authorized_keys"
		}, SkipRootForcedCommands},
	}
	for _, c := range durable {
		t.Run(c.name, func(t *testing.T) {
			tg, l := okTarget(t1, "web-01"), loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
			if c.target != nil {
				c.target(&tg)
			}
			if c.loc != nil {
				c.loc(&l)
			}
			assert.Contains(t, SkipsAtSend, c.want)
			assert.Equal(t, c.want, SkipAtSend(tg, true, l, 1))
			assert.Equal(t, SkipFor(tg, true, l), SkipAtSend(tg, true, l, 1), "the planner's rule")
		})
	}
	tg, l := okTarget(t1, "web-01"), loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	assert.Equal(t, SkipSharedFile, SkipAtSend(tg, true, l, 2), "another location of the key in the file")
	assert.Contains(t, SkipsAtSend, SkipSharedFile)
	assert.Equal(t, SkipTargetDeleted, SkipAtSend(tg, false, l, 1), "a target gone")
	assert.Equal(t, "", SkipAtSend(tg, true, l, 1))
	for _, status := range ConnectionStates {
		tg.Status = status
		assert.Equal(t, SkipTargetNotConnected, SkipFor(tg, true, l), "the planner skips %s", status)
		assert.Equal(t, "", SkipAtSend(tg, true, l, 1), "a %s status is not re-evaluated at send time", status)
		tg.KeysManagedElsewhere = true
		assert.Equal(t, SkipKeysManagedElsewhere, SkipAtSend(tg, true, l, 1), "the durable reasons still apply while %s", status)
		tg.KeysManagedElsewhere = false
	}
	assert.ElementsMatch(t, []string{"unreachable", "checking", "auth_failed"}, ConnectionStates)
}

// A location whose options the inventory stored cut (longer than the cap, so the text ends in "…") is
// skipped in the preview: the new key's line is built from the stored options (keymat.Line), which
// refuses a cut list, so without the skip the place would fail after the run started.
func TestCutOptionsAreSkippedBeforeTheLineIsBuilt(t *testing.T) {
	cut := `environment="K1=` + strings.Repeat("v", 8180) + "…"
	_, err := keymat.Line(cut, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", "c")
	require.Error(t, err, "keymat.Line refuses a cut option list, which is why the planner must skip it")

	l := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", cut)
	p, err := Build(input(l, loc(t2, "deploy", "/home/deploy/.ssh/authorized_keys", "no-pty")))
	require.NoError(t, err)
	i := slices.IndexFunc(p.Actions, func(a Action) bool { return a.LocationID == l.ID })
	assert.Equal(t, SkipOptionsTruncated, p.Actions[i].Skip)
	assert.Equal(t, 1, p.Changes)
	assert.Equal(t, 1, p.Skips)
	assert.Equal(t, SkipOptionsTruncated, SkipAtSend(okTarget(t1, "web-01"), true, l, 1), "the send-time rule skips it too")

	_, err = Build(input(l))
	assert.ErrorIs(t, err, ErrNothingToRotate, "a key whose only place has cut options has nothing to rotate")

	// An option list that merely contains "…" inside a quoted value is not cut.
	l.Options = `environment="K=a…b"`
	assert.Empty(t, SkipFor(okTarget(t1, "web-01"), true, l))
}
