package plan

import (
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
)

var (
	t1    = uuid.MustParse("00000000-0000-7000-8000-000000000001")
	t2    = uuid.MustParse("00000000-0000-7000-8000-000000000002")
	keyID = uuid.MustParse("00000000-0000-7000-8000-0000000000aa")
)

func okTarget(id uuid.UUID, name string) Target {
	return Target{ID: id, Name: name, Status: "ok", ConnectionUser: "alice-svc", SSHDRead: true, PermitRootLogin: "prohibit-password",
		PubkeyAuthentication: "yes"}
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
		{"connection account", nil, func(l *Location) { l.OSUser = "alice-svc" }, SkipConnectionAccount},
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
	for _, a := range p.Actions {
		switch a.OSUser {
		case "root", "toor":
			assert.False(t, a.Verify)
			assert.Equal(t, "root_login_disabled", a.VerifyNote)
		case "deploy":
			assert.True(t, a.Verify)
			assert.Equal(t, "from_option", a.VerifyNote)
		}
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
		"overlap":      func(in *Input) { in.OverlapMinutes = 1 },
		"new key type": func(in *Input) { in.NewKeyType = "rsa-3072" },
		"options":      func(in *Input) { in.Locations[0].Options = "restrict" },
		"user":         func(in *Input) { in.Locations[0].OSUser = "app" },
		"file":         func(in *Input) { in.Locations[0].FilePath = "/home/deploy/.ssh/authorized_keys2" },
		"skip":         func(in *Input) { x := in.Targets[t1]; x.Status = "unreachable"; in.Targets[t1] = x },
		"verify note":  func(in *Input) { in.Locations[0].Options = `from="10.0.0.0/8"` },
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
