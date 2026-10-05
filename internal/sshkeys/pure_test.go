package sshkeys

import (
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
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
