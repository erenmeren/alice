package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/providers"
)

func readyTarget() Target {
	return Target{Status: StatusOK, Username: "alice-svc", Facts: Facts{SSHD: &providers.SSHDSummary{Read: true}}}
}

func TestKeyChangeRefusal(t *testing.T) {
	assert.NoError(t, KeyChangeRefusal(readyTarget(), "deploy"))
	cases := map[string]struct {
		edit func(*Target)
		want error
	}{
		"pending":   {func(t *Target) { t.Status = StatusPendingHostKey }, ErrHostKeyUnconfirmed},
		"changed":   {func(t *Target) { t.Status = StatusHostKeyChanged }, ErrHostKeyChanged},
		"disabled":  {func(t *Target) { t.Status = StatusDisabled }, ErrTargetDisabled},
		"elsewhere": {func(t *Target) { t.KeysManagedElsewhere = true }, ErrKeysManagedElsewhere},
		"elsewhere for user": {func(t *Target) {
			t.Facts.Warnings = []providers.Warning{{Code: "keys_managed_elsewhere", Params: map[string]string{"user": "deploy"}}}
		}, ErrKeysManagedElsewhere},
		"sshd unread":   {func(t *Target) { t.Facts.SSHD = &providers.SSHDSummary{Read: false} }, ErrSSHDUnreadable},
		"no sshd facts": {func(t *Target) { t.Facts.SSHD = nil }, ErrSSHDUnreadable},
		"sshd unread user": {func(t *Target) {
			t.Facts.Warnings = []providers.Warning{{Code: "sshd_unreadable", Params: map[string]string{"user": "deploy"}}}
		}, ErrSSHDUnreadable},
	}
	for name, c := range cases {
		tg := readyTarget()
		c.edit(&tg)
		assert.ErrorIs(t, KeyChangeRefusal(tg, "deploy"), c.want, name)
	}
	for _, st := range []string{StatusUnreachable, StatusChecking, StatusAuthFailed} {
		tg := readyTarget()
		tg.Status = st
		assert.NoError(t, KeyChangeRefusal(tg, "deploy"), "the job reports a connection problem itself: %s", st)
	}
}

func TestValidateReasonIsExported(t *testing.T) {
	assert.Empty(t, ValidateReason("Rotating the CI key after an audit"))
	assert.NotEmpty(t, ValidateReason("short"))
	assert.NotEmpty(t, ValidateReason("-----BEGIN "+"OPENSSH PRIVATE KEY----- pasted"))
}

func TestCleanKeyFiles(t *testing.T) {
	long := "/" + string(make([]byte, 0)) + func() string {
		b := make([]byte, maxKeyFileLen)
		for i := range b {
			b[i] = 'a'
		}
		return string(b)
	}()
	in := []providers.UserKeyFiles{
		{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys", "relative/path", "/with\x00nul", "/bad\xffutf8", "/ctrl\nline", long, ""}},
		{OSUser: "ev\x00il", Files: []string{"/home/evil/.ssh/authorized_keys"}},
		{OSUser: "", Files: []string{"/x"}},
		{OSUser: "nofiles", Files: []string{"relative"}},
		{OSUser: "root", Files: []string{"/root/.ssh/authorized_keys"}},
	}
	assert.Equal(t, []providers.UserKeyFiles{
		{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}},
		{OSUser: "root", Files: []string{"/root/.ssh/authorized_keys"}},
	}, cleanKeyFiles(in), "entries clean() would change, relative paths, controls and over-long text are dropped; a user without files goes")
	assert.Nil(t, cleanKeyFiles(nil))

	many := make([]providers.UserKeyFiles, 0, 300)
	for i := 0; i < 300; i++ {
		files := make([]string, 12)
		for j := range files {
			files[j] = "/f" + string(rune('a'+j))
		}
		many = append(many, providers.UserKeyFiles{OSUser: "u" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Files: files})
	}
	got := cleanKeyFiles(many)
	assert.Len(t, got, maxKeyFileUsers)
	assert.Len(t, got[0].Files, maxKeyFiles)
}
