package windows

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk alice-platform"

// withChecksums sets both helper checksums for one test.
func withChecksums(t *testing.T, amd, arm string) {
	t.Helper()
	oldAMD, oldARM := helperSHA256WindowsAMD64, helperSHA256WindowsARM64
	t.Cleanup(func() { helperSHA256WindowsAMD64, helperSHA256WindowsARM64 = oldAMD, oldARM })
	helperSHA256WindowsAMD64, helperSHA256WindowsARM64 = amd, arm
}

func TestAuthorizedKeysLine(t *testing.T) {
	assert.Equal(t, "restrict "+testKey, AuthorizedKeysLine(testKey, ""))
	assert.Equal(t, `restrict,from="192.0.2.10" `+testKey, AuthorizedKeysLine(testKey, "192.0.2.10"))
	assert.Equal(t, `restrict,from="2001:db8::5" `+testKey, AuthorizedKeysLine(testKey, "2001:db8::5"))
	for _, bad := range []string{`192.0.2.10"`, `192.0.2.10",command="x`, "web-01", "10.0.0.1 "} {
		assert.Empty(t, AuthorizedKeysLine(testKey, bad), "from %q", bad)
	}
}

func TestSetupScriptEmbedsTheHelperChecksums(t *testing.T) {
	amd, arm := strings.Repeat("ab", 32), strings.Repeat("01", 32)
	withChecksums(t, amd, arm)
	line := AuthorizedKeysLine(testKey, "")
	s, err := SetupScript(line, false)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(s, "#Requires -RunAsAdministrator\n"), "the first line asks for an elevated PowerShell")
	assert.Contains(t, s, "Set-StrictMode -Version 3\n")
	assert.Contains(t, s, "$ErrorActionPreference = 'Stop'\n")
	assert.Contains(t, s, "$AliceUser = 'alice'")
	assert.Contains(t, s, "DOMAIN\\alice-svc", "the comment names the domain setup")
	assert.Contains(t, s, "$AuthorizedKey = '"+line+"'\n", "the key line inside single quotes")
	assert.Regexp(t, `'AMD64' = '`+amd+`'`, s)
	assert.Regexp(t, `'ARM64' = '`+arm+`'`, s)
	assert.Contains(t, s, "Get-FileHash")
	assert.Contains(t, s, "is not the alice-helper.exe of this Alice version (its SHA-256 checksum differs)")
	assert.Contains(t, s, "alice-winhelper-windows-amd64.exe or alice-winhelper-windows-arm64.exe")
	assert.NotContains(t, s, "cannot verify alice-helper.exe")

	assert.Contains(t, s, "$MatchUser = $AliceUser.ToLowerInvariant()")
	assert.Contains(t, s, "$MatchBlock = @\"\n"+strings.ReplaceAll(MatchBlock, "__USER__", "$MatchUser")+"\"@\n",
		"the Match block of the guide, for the account the script names (alice unless it is edited)")
	assert.Contains(t, s, "# BEGIN Alice")
	assert.Contains(t, s, "# END Alice")
	assert.Contains(t, s, "'OpenSSH.Server~~~~0.0.1.0'")
	assert.Contains(t, s, "Add-WindowsCapability")
	assert.Contains(t, s, "OpenSSH-Win64-v10.0.0.0.msi", "the air-gapped message names the MSI")
	assert.Contains(t, s, "S-1-5-32-544")
	assert.Contains(t, s, "SeDenyInteractiveLogonRight")
	assert.Contains(t, s, "SeDenyRemoteInteractiveLogonRight")
	assert.Contains(t, s, "secedit")
	assert.Contains(t, s, "[System.Security.Cryptography.RandomNumberGenerator]")
	assert.Contains(t, s, `C:\ProgramData\ssh\administrators_authorized_keys`)
	assert.Contains(t, s, "'"+winproto.HelperPath+"'")
	assert.Contains(t, s, "'"+winproto.DataDir+"'")
	assert.Contains(t, s, "'Alice-SSH-In'")
	assert.Contains(t, s, "'Alice Helper'")
	assert.Contains(t, s, "ssh-keygen.exe")
	assert.Contains(t, s, "-t")
	assert.True(t, strings.HasSuffix(s, "Write-Output 'This server is ready for Alice.'\n}\n"))
	assert.Contains(t, s, "\n& {\nSet-StrictMode -Version 3\n", "the body is one block, so a pasted copy stops as a whole")

	// Review round 1: no ACL change follows junctions, and an existing directory is checked first.
	assert.NotContains(t, s, "'/T'", "icacls never recurses (it follows junctions)")
	assert.Contains(t, s, "Get-ChildItem -LiteralPath $Path -Recurse -Force -Attributes ReparsePoint", "a link or junction below is refused")
	assert.Contains(t, s, ".GetOwner([System.Security.Principal.SecurityIdentifier])", "an existing directory's owner is checked")
	assert.Contains(t, s, "if (Test-Path -LiteralPath $Path) { Assert-SafeDirectory $Path }")
	assert.Contains(t, s, "New-AdminOnlyDirectory (Split-Path -Parent $HelperPath) -ReadExecute @($UserSid)\n")
	assert.Contains(t, s, "foreach ($d in @((Split-Path -Parent $DataDir), $DataDir)) { New-AdminOnlyDirectory $d }\n")
	assert.Contains(t, s, "Remove-NetFirewallRule -Name 'Alice-SSH-In' -ErrorAction SilentlyContinue\n")
	assert.Contains(t, s, "-cnotcontains $keyBlob", "key blobs are compared with case")
	assert.Regexp(t, `(?s)Test-Helper \$staging\n\} catch \{\n\s+Remove-Item -LiteralPath \$staging`, s, "a staged copy that fails the check is removed")
	assert.NotContains(t, s, "LocalAccountTokenFilterPolicy", "the script never sets the policy (W0 F3)")
	assert.NotContains(t, s, "StrictHostKeyChecking")
	for i, r := range s {
		require.Less(t, r, rune(0x80), "the script is ASCII (PowerShell 5.1 reads a file without BOM as ANSI), at %d", i)
	}
	assert.NotContains(t, s, "\r", "line ends are the administrator's editor's choice")

	// From a development build without checksums: a warning and no check.
	withChecksums(t, "", "")
	_, err = SetupScript(line, false)
	require.ErrorIs(t, err, ErrHelperUnverified)
	s, err = SetupScript(line, true)
	require.NoError(t, err)
	assert.Contains(t, s, "cannot verify alice-helper.exe (development build without checksums)")
	assert.NotContains(t, s, "Get-FileHash")
	assert.NotContains(t, s, "'AMD64' = '")

	// A malformed checksum is never embedded.
	withChecksums(t, amd, "not hex")
	_, err = SetupScript(line, false)
	require.ErrorIs(t, err, ErrHelperUnverified)
}

func TestSetupScriptRefusesALineItCannotQuote(t *testing.T) {
	withChecksums(t, "", "")
	good := AuthorizedKeysLine(testKey, "")
	for _, bad := range []string{
		"",
		good + "'",
		"restrict ssh-ed25519 AAAA'; Remove-Item C:\\ -Recurse; '",
		good + "\r",
		good + "\n",
		"restrict ssh-ed25519 AA\x00AA",
		good + "\x7f",
		good + " \u00e9",
		testKey,                          // no restrict
		"no-pty " + testKey,              // other options
		`restrict,from="a b" ` + testKey, // from outside the address vocabulary
		`restrict,from="192.0.2.10"` + testKey,
		`restrict,command="x" ` + testKey,
		"restrict ",
	} {
		_, err := SetupScript(bad, true)
		require.ErrorIs(t, err, errBadKeyLine, "%q", bad)
	}
}

func TestSetupScriptFirewallAddress(t *testing.T) {
	withChecksums(t, "", "")
	s, err := SetupScript(AuthorizedKeysLine(testKey, "192.0.2.10"), true)
	require.NoError(t, err)
	assert.Contains(t, s, "$AliceAddress = '192.0.2.10'\n")
	assert.NotContains(t, s, "allows port 22 from any address")

	s, err = SetupScript(AuthorizedKeysLine(testKey, "192.0.2.10,198.51.100.0/24"), true)
	require.NoError(t, err)
	assert.Contains(t, s, "$AliceAddress = '192.0.2.10', '198.51.100.0/24'\n", "a list is a PowerShell array")

	for _, from := range []string{"", "10.0.0.*", "!10.0.0.1,10.0.0.0/8", "10.0.0.?"} {
		s, err = SetupScript(AuthorizedKeysLine(testKey, from), true)
		require.NoError(t, err, from)
		assert.Contains(t, s, "$AliceAddress = 'Any'\n", "the firewall cannot express %q", from)
		assert.Contains(t, s, "allows port 22 from any address", "and says so")
	}
}

// The account's random password is never written anywhere but the account itself.
func TestSetupScriptNeverPrintsThePassword(t *testing.T) {
	withChecksums(t, "", "")
	s, err := SetupScript(AuthorizedKeysLine(testKey, ""), true)
	require.NoError(t, err)
	require.Contains(t, s, "$password", "the script has a password variable")
	out := regexp.MustCompile(`(?i)\b(Write-Host|Write-Output|Write-Warning|Write-Verbose|Write-Information|Write-Error|echo|Out-File|Set-Content|Add-Content|Out-String|Tee-Object|Export-|ConvertTo-|throw)\b`)
	pw := regexp.MustCompile(`(?i)\$password\b`)
	for i, l := range strings.Split(s, "\n") {
		if pw.MatchString(l) {
			assert.False(t, out.MatchString(l), "line %d writes the password: %s", i+1, l)
		}
	}
	assert.Regexp(t, `(?m)^\s*\$u\.SetPassword\(\$password\)$`, s, "it goes only to the account")
	assert.Contains(t, s, "Remove-Variable password")
}

func TestSetupSnippets(t *testing.T) {
	withChecksums(t, "", "")
	p := New(Options{AllowUnverifiedHelper: true})
	line := AuthorizedKeysLine(testKey, "")
	snips := p.SetupSnippets(line)
	require.Len(t, snips, 1)
	s := snips["windows"]
	assert.Equal(t, "windows", s.Profile)
	assert.Empty(t, s.Sudoers, "Windows has no sudoers file")
	want, err := SetupScript(line, true)
	require.NoError(t, err)
	assert.Equal(t, want, s.Script)

	// A build without checksums that is no development build offers no script (Ruling 15).
	s = New(Options{}).SetupSnippets(line)["windows"]
	assert.Empty(t, s.Script)

	path, protocol := p.HelperInfo()
	assert.Equal(t, winproto.HelperPath, path)
	assert.Equal(t, winproto.Protocol, protocol)
	assert.Contains(t, MatchBlock, "    ForceCommand \""+winproto.HelperPath+"\" ssh\n", "sshd runs the installed helper")
	var _ providers.SetupGuide = p
}
