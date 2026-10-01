package sshdconf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sshdT = `port 22
addressfamily any
pubkeyauthentication yes
passwordauthentication no
permitrootlogin prohibit-password
strictmodes yes
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
authorizedkeyscommand none
authorizedkeyscommanduser none
authorizedprincipalsfile none
trustedusercakeys none
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ecdsa_key
hostkey /etc/ssh/ssh_host_ed25519_key
`

func TestParseSSHDT(t *testing.T) {
	c, err := Parse([]byte(sshdT))
	require.NoError(t, err)
	assert.Equal(t, []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}, c.AuthorizedKeysFile)
	assert.Equal(t, "none", c.AuthorizedKeysCommand)
	assert.Equal(t, "none", c.AuthorizedKeysCommandUser)
	assert.Equal(t, "none", c.AuthorizedPrincipalsFile)
	assert.Equal(t, "none", c.TrustedUserCAKeys)
	assert.Equal(t, "yes", c.PubkeyAuthentication)
	assert.Equal(t, "no", c.PasswordAuthentication)
	assert.Equal(t, "prohibit-password", c.PermitRootLogin)
	assert.Equal(t, "yes", c.StrictModes)
	assert.Equal(t, []string{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"}, c.HostKeys)
}

func TestParseAppliesOpenSSHDefaults(t *testing.T) {
	c, err := Parse(nil)
	require.NoError(t, err)
	assert.Equal(t, DefaultAuthorizedKeysFile, c.AuthorizedKeysFile)
	assert.Equal(t, "none", c.AuthorizedKeysCommand)
	assert.Empty(t, c.HostKeys)
	c.AuthorizedKeysFile[0] = "changed"
	assert.Equal(t, ".ssh/authorized_keys", DefaultAuthorizedKeysFile[0], "Parse returns a copy of the defaults")
}

func TestParseConfigFileSyntax(t *testing.T) {
	text := "# Managed by the security team\r\n" +
		"  AuthorizedKeysFile = \"/etc/ssh/keys/%u\" .ssh/authorized_keys\r\n" +
		"PubkeyAuthentication\tno\r\n" +
		"AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys %u\n" +
		"HostKey=/etc/ssh/a\n" +
		"Match User bob\n" +
		"  AuthorizedKeysFile /bob/keys\n" +
		"  PubkeyAuthentication yes\n" +
		"HostKey /etc/ssh/after_match\n"
	c, err := Parse([]byte(text))
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc/ssh/keys/%u", ".ssh/authorized_keys"}, c.AuthorizedKeysFile)
	assert.Equal(t, "no", c.PubkeyAuthentication, "values inside a Match block are ignored")
	assert.Equal(t, "/usr/bin/sss_ssh_authorizedkeys %u", c.AuthorizedKeysCommand)
	assert.Equal(t, []string{"/etc/ssh/a"}, c.HostKeys, "parsing stops at the first Match")
}

func TestParseFirstValueWinsAndNone(t *testing.T) {
	c, err := Parse([]byte("authorizedkeysfile /first\nauthorizedkeysfile /second\npermitrootlogin no\npermitrootlogin yes\n"))
	require.NoError(t, err)
	assert.Equal(t, []string{"/first"}, c.AuthorizedKeysFile)
	assert.Equal(t, "no", c.PermitRootLogin)

	c, err = Parse([]byte("authorizedkeysfile none\n"))
	require.NoError(t, err)
	require.NotNil(t, c.AuthorizedKeysFile)
	assert.Empty(t, c.AuthorizedKeysFile, "AuthorizedKeysFile none means no files")
}

func TestParseRejectsHugeInput(t *testing.T) {
	_, err := Parse([]byte(strings.Repeat("#", MaxConfigSize+1)))
	require.ErrorIs(t, err, ErrTooLarge)
	_, err = Parse([]byte(strings.Repeat("#", MaxConfigSize)))
	require.NoError(t, err)
}

func TestExpand(t *testing.T) {
	for _, tc := range []struct {
		pattern, user, home string
		uid                 int
		want                string
	}{
		{".ssh/authorized_keys", "deploy", "/home/deploy", 1001, "/home/deploy/.ssh/authorized_keys"},
		{"%h/.ssh/authorized_keys2", "deploy", "/home/deploy", 1001, "/home/deploy/.ssh/authorized_keys2"},
		{"/etc/ssh/keys/%u", "deploy", "/home/deploy", 1001, "/etc/ssh/keys/deploy"},
		{"/var/keys/%U", "deploy", "/home/deploy", 1001, "/var/keys/1001"},
		{"/k/100%%", "deploy", "/home/deploy", 1001, "/k/100%"},
		{"%h", "root", "/", 0, "/"},
		{".ssh//authorized_keys", "deploy", "/home/deploy/", 1001, "/home/deploy/.ssh/authorized_keys"},
	} {
		got, err := Expand(tc.pattern, tc.user, tc.home, tc.uid)
		require.NoError(t, err, tc.pattern)
		assert.Equal(t, tc.want, got, tc.pattern)
	}
}

func TestExpandRefusesEscapesAndUnknownTokens(t *testing.T) {
	for _, tc := range []struct{ pattern, user, home string }{
		{"%x/keys", "deploy", "/home/deploy"},
		{"keys%", "deploy", "/home/deploy"},
		{"../../etc/shadow", "deploy", "/home/deploy"},
		{"/etc/%u/../shadow", "deploy", "/home/deploy"},
		{"%h/../root/.ssh/authorized_keys", "deploy", "/home/deploy"},
		{"", "deploy", "/home/deploy"},
		{".ssh/a\nb", "deploy", "/home/deploy"},
		{".ssh/authorized_keys", "dep\x00loy", "/home/deploy"},
		{".ssh/authorized_keys", "deploy", "home/deploy"},
		{"/keys/%u", "..", "/home/deploy"},
	} {
		_, err := Expand(tc.pattern, tc.user, tc.home, 1001)
		require.ErrorIs(t, err, ErrInvalidPattern, "%q user %q home %q", tc.pattern, tc.user, tc.home)
	}
}

// FuzzParseSSHDConfig (spec §25.6): Parse never panics, and every AuthorizedKeysFile it returns
// expands to a clean absolute path that never climbs out with "..".
func FuzzParseSSHDConfig(f *testing.F) {
	for _, seed := range []string{
		sshdT,
		"",
		"authorizedkeysfile none\n",
		"AuthorizedKeysFile %h/.ssh/authorized_keys /etc/ssh/keys/%u /var/%U/%%\n",
		"AuthorizedKeysFile \"/etc/ssh/keys/%u\" \"unterminated\n",
		"Match User bob\n AuthorizedKeysFile /bob\n",
		"authorizedkeysfile ../../etc/shadow %h/../x\r\nmatch all\r\n",
		"hostkey=/a\nhostkey = /b\nHostKey\t/c\n",
		"#only a comment",
		"authorizedkeysfile %",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse(data)
		if err != nil {
			return
		}
		for _, p := range c.AuthorizedKeysFile {
			got, err := Expand(p, "u", "/home/u", 1000)
			if err != nil {
				continue
			}
			if !strings.HasPrefix(got, "/") || strings.Contains(got, "/../") || strings.HasSuffix(got, "/..") ||
				strings.ContainsAny(got, "\x00\n\r") {
				t.Fatalf("Expand(%q) = %q escapes or is not absolute", p, got)
			}
		}
	})
}
