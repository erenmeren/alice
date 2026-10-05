package inventory

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		{OSUser: "spoof", Files: []string{"/home/spoof/ok", "/home/spoof\u202e/gpj.keys", "/zero\u200bwidth", "/line\u2028sep", "/para\u2029sep"}, Complete: true},
		{OSUser: "ev\u202eil", Files: []string{"/home/evil/ak"}},
	}
	assert.Equal(t, []providers.UserKeyFiles{
		{OSUser: "deploy", Files: []string{"/home/deploy/.ssh/authorized_keys"}},
		{OSUser: "root", Files: []string{"/root/.ssh/authorized_keys"}},
		{OSUser: "spoof", Files: []string{"/home/spoof/ok"}},
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

func TestCleanKeyFilesKeepsCompleteness(t *testing.T) {
	in := []providers.UserKeyFiles{
		{OSUser: "alice-svc", Files: []string{"/a/ak"}, Complete: true},
		{OSUser: "dropped", Files: []string{"/d/ak", "/bad\x00"}, Complete: true},
		{OSUser: "relative", Files: []string{"/r/ak", "rel"}, Complete: true},
		{OSUser: "unknown", Files: []string{"/u/ak"}},
		{OSUser: "gone", Files: []string{"rel"}, Complete: true},
	}
	many := make([]string, maxKeyFiles+1)
	for i := range many {
		many[i] = "/f" + string(rune('a'+i))
	}
	in = append(in, providers.UserKeyFiles{OSUser: "cut", Files: many, Complete: true},
		providers.UserKeyFiles{OSUser: "exact", Files: many[:maxKeyFiles], Complete: true})
	got := map[string]bool{}
	for _, u := range cleanKeyFiles(in) {
		got[u.OSUser] = u.Complete
	}
	assert.Equal(t, map[string]bool{"alice-svc": true, "dropped": false, "relative": false, "unknown": false, "cut": false, "exact": true}, got,
		"complete survives only when nothing was dropped or cut; an account with no file left is absent")
}

// Facts stored before the flag existed read as incomplete; the flag round-trips.
func TestKeyFilesOldShapeReadsIncomplete(t *testing.T) {
	var f Facts
	require.NoError(t, json.Unmarshal([]byte(`{"key_files":[{"os_user":"alice-svc","files":["/a/ak"]}]}`), &f))
	require.Len(t, f.KeyFiles, 1)
	assert.False(t, f.KeyFiles[0].Complete)
	raw, err := json.Marshal(Facts{KeyFiles: []providers.UserKeyFiles{{OSUser: "u", Files: []string{"/x"}, Complete: true}}})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &f))
	assert.True(t, f.KeyFiles[0].Complete)
}

func TestSpoofingText(t *testing.T) {
	for _, bad := range []string{
		"/a b",                            // no-break space (Zs)
		"/a　b",                            // ideographic space (Zs)
		"/a b",                            // thin space (Zs)
		"/a b",                            // narrow no-break space (Zs)
		"/a" + string(rune(0x200b)) + "b", // zero width space (Cf)
		"/a" + string(rune(0x202e)) + "b", // right-to-left override (Cf)
		"/a" + string(rune(0x2066)) + "b", // isolate (Cf)
		"/a b",                            // line separator (Zl)
		"/a b",                            // paragraph separator (Zp)
		"/a\tb",                           // control (Cc)
		"/aᅟb",                            // Hangul fillers
		"/aᅠb", "/aㅤb", "/aﾠb",
		"/a⠀b",       // braille blank
		"́/a",        // a combining mark (Mn) at the start
		"/️a",        // a variation selector (Mn) at the start of a segment
		"/dir/͏name", // a combining grapheme joiner at the start of a segment
		"/dir/⃝name", // an enclosing mark (Me) at the start of a segment
	} {
		assert.True(t, spoofingText(bad), "%q", bad)
	}
	for _, good := range []string{"/home/deploy/.ssh/authorized_keys", "/home/my dir/ak", "/home/josé/ak", "/home/é/ak", "/a/b️", "/üser/ak"} {
		assert.False(t, spoofingText(good), "%q", good)
	}
}
