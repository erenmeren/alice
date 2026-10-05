package sshkeys

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/sshkeys/plan"
)

// What deployOptions writes, parseDeployOptions reads back unchanged; nothing else passes (S7).
func TestDeployOptionsRoundTrip(t *testing.T) {
	for _, c := range []struct {
		from     string
		restrict bool
	}{{"", false}, {"", true}, {`from="10.0.0.0/8"`, false}, {`from="10.0.0.0/8,2001:db8::1"`, true}} {
		opts := deployOptions(c.from, c.restrict)
		got, err := parseDeployOptions(opts)
		require.NoError(t, err, opts)
		assert.Equal(t, opts, got)
	}
	for _, opts := range []string{",restrict", "restrict,", `from=10.0.0.0/8`, `from="10.0.0.0/8`, `from="10.0.0.0/8""`,
		`from="10.0.0.0/8",from="10.0.0.0/8"`, `x,restrict`, `from="10.0.0.0/08"`} {
		_, err := parseDeployOptions(opts)
		assert.ErrorIs(t, err, errForeignOptions, opts)
	}
}

func TestCheckDeployInput(t *testing.T) {
	opts, errs := checkDeployInput(DeployInput{OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys", From: "10.0.0.1", Restrict: true})
	assert.Empty(t, errs)
	assert.Equal(t, `from="10.0.0.1",restrict`, opts)
	for _, c := range []struct {
		in    DeployInput
		field string
		code  string
	}{
		{DeployInput{FilePath: "/f"}, "os_user", validate.Required},
		{DeployInput{OSUser: strings.Repeat("u", 257), FilePath: "/f"}, "os_user", validate.TooLong},
		{DeployInput{OSUser: "a b", FilePath: "/f"}, "os_user", validate.Pattern},
		{DeployInput{OSUser: "a\u202e", FilePath: "/f"}, "os_user", validate.Pattern},
		{DeployInput{OSUser: "u"}, "file_path", validate.Required},
		{DeployInput{OSUser: "u", FilePath: "/" + strings.Repeat("f", 4096)}, "file_path", validate.TooLong},
		{DeployInput{OSUser: "u", FilePath: "f"}, "file_path", validate.Pattern},
		{DeployInput{OSUser: "u", FilePath: "/f\x00"}, "file_path", validate.Pattern},
		{DeployInput{OSUser: "u", FilePath: "/f", From: "10.0.0.1/8"}, "from", validate.Pattern},
	} {
		_, errs := checkDeployInput(c.in)
		require.Len(t, errs, 1, "%+v", c.in)
		assert.Equal(t, c.field, errs[0].Field)
		assert.Equal(t, c.code, errs[0].Code)
	}
}

func TestFileName(t *testing.T) {
	name := fileName("CI deploy / prod \u202e", "SHA256:abc")
	assert.Regexp(t, regexp.MustCompile(`^alice-ci-deploy-prod-[0-9a-f]{8}\.key$`), name)
	assert.NotEqual(t, name, fileName("CI deploy / prod", "SHA256:abd"))
	assert.Regexp(t, `^alice-key-[0-9a-f]{8}\.key$`, fileName("ÇÖ", "SHA256:x"))
}

func TestDeployDedupe(t *testing.T) {
	k, tg := uuid.New(), uuid.New()
	a := deployDedupe(k, tg, "deploy", "/a")
	assert.Regexp(t, `^sshkey\.add:`+k.String()+`:`+tg.String()+`:[0-9a-f]{16}$`, a)
	assert.NotEqual(t, a, deployDedupe(k, tg, "deploy", "/b"))
}

func TestGenerationSlots(t *testing.T) {
	release := HoldGenerationSlots(t)
	_, ok := acquireGenSlot()
	assert.False(t, ok)
	release()
	r, ok := acquireGenSlot()
	require.True(t, ok)
	r()
}

func TestSmallHelpers(t *testing.T) {
	d := &denial{reason: DenyOwnKey, err: ErrNotManaged}
	assert.Equal(t, ErrNotManaged.Error(), d.Error())
	assert.ErrorIs(t, d, ErrNotManaged)
	assert.Equal(t, "system", jobKind(inventory.Actor{}))
	assert.Equal(t, "user", jobKind(inventory.Actor{UserID: uuid.New()}))
	assert.Nil(t, nullableUser(uuid.Nil))
	assert.Equal(t, inventory.ServiceUser, connectionUser(inventory.Target{}))
	assert.Equal(t, "ops", connectionUser(inventory.Target{Username: "ops"}))
}

func TestPlanMappings(t *testing.T) {
	assert.ErrorIs(t, planError(plan.ErrOwnKey), ErrOwnKeyProtected)
	assert.ErrorIs(t, planError(plan.ErrNotManaged), ErrNotManaged)
	assert.ErrorIs(t, planError(plan.ErrRetired), ErrRetired)
	assert.ErrorIs(t, planError(plan.ErrNothingToRotate), ErrNothingToRotate)
	assert.ErrorIs(t, planError(plan.ErrNewKeyType), plan.ErrNewKeyType)
	assert.Equal(t, "own_key", plannerDisableReason(plan.ErrOwnKey))
	assert.Equal(t, "not_managed", plannerDisableReason(plan.ErrNotManaged))
	assert.Equal(t, "retired", plannerDisableReason(plan.ErrRetired))
	assert.Equal(t, "new_key_type", plannerDisableReason(plan.ErrNewKeyType))
	assert.Equal(t, "other", plannerDisableReason(errors.New("plan: other")))
	assert.ErrorIs(t, policyWriteError(&pgconn.PgError{Code: "23505"}), ErrPolicyExists)
	assert.ErrorIs(t, policyWriteError(&pgconn.PgError{Code: "Z1010"}), ErrRetired)
	assert.Error(t, policyWriteError(errors.New("x")))
	assert.Equal(t, uuid.Nil, orNil(nil))
}

// toPlanInput reads per-user and server-wide warnings and the sshd summary the way the planner
// expects them.
func TestToPlanInput(t *testing.T) {
	tid, lid := uuid.New(), uuid.New()
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	key := keyRow{id: uuid.New(), privateKeyID: uuid.New(), fingerprint: "SHA256:x", publicKey: "ssh-ed25519 AAAA", label: "CI",
		algorithm: "rsa", bits: 3072}
	tg := inventory.Target{Name: "web", Status: "ok", Username: "ops", Facts: inventory.Facts{
		SSHD: &providers.SSHDSummary{Read: true, PermitRootLogin: "no", PubkeyAuthentication: "yes"}, UID0Users: []string{"root"},
		Warnings: []providers.Warning{{Code: "keys_managed_elsewhere", Params: map[string]string{"user": "bob"}},
			{Code: "sshd_unreadable", Params: map[string]string{"user": "eve"}}, {Code: "keys_managed_elsewhere", Params: map[string]string{}},
			{Code: "other"}}}}
	missing := now
	in := toPlanInput(key, []inventory.KeyLocation{{ID: lid, TargetID: tid, OSUser: "deploy", FilePath: "/f", MissingSince: &missing}},
		map[uuid.UUID]inventory.Target{tid: tg}, []string{"SHA256:p"}, Policy{NewKeyType: "same", OverlapMinutes: 5}, now)
	assert.Equal(t, "rsa-3072", in.Key.KeyType)
	assert.True(t, in.Key.Managed)
	assert.Equal(t, "alice:ci:2026-10-05", in.NewComment)
	pt := in.Targets[tid]
	assert.Equal(t, plan.Target{ID: tid, Name: "web", Status: "ok", ConnectionUser: "ops", SSHDRead: true, PermitRootLogin: "no",
		PubkeyAuthentication: "yes", UID0Users: []string{"root"}, ManagedElsewhereUsers: []string{"bob"}, SSHDUnreadUsers: []string{"eve"}}, pt)
	assert.True(t, in.Locations[0].Missing)
	tg.Facts.Warnings = []providers.Warning{{Code: "sshd_unreadable", Params: map[string]string{}}}
	in = toPlanInput(key, nil, map[uuid.UUID]inventory.Target{tid: tg}, nil, Policy{}, now)
	assert.False(t, in.Targets[tid].SSHDRead, "a server-wide unreadable warning")
}
