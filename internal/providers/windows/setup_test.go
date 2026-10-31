package windows

import (
	"crypto/ed25519"
	"crypto/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

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

// The forced command is in the key line itself (final review C1): administrators_authorized_keys is read for every
// member of Administrators, so the line, not the Match User block, confines Alice's key to the helper.
const testCommand = `command="\"C:\Program Files\Alice\alice-helper.exe\" ssh"`

func TestAuthorizedKeysLine(t *testing.T) {
	assert.Equal(t, `C:\Program Files\Alice\alice-helper.exe`, winproto.HelperPath)
	assert.Equal(t, "restrict,"+testCommand+" "+testKey, AuthorizedKeysLine(testKey, ""))
	assert.Equal(t, "restrict,"+testCommand+`,from="192.0.2.10" `+testKey, AuthorizedKeysLine(testKey, "192.0.2.10"))
	assert.Equal(t, "restrict,"+testCommand+`,from="2001:db8::5" `+testKey, AuthorizedKeysLine(testKey, "2001:db8::5"))
	for _, bad := range []string{`192.0.2.10"`, `192.0.2.10",command="x`, "web-01", "10.0.0.1 "} {
		assert.Empty(t, AuthorizedKeysLine(testKey, bad), "from %q", bad)
	}
}

// OpenSSH's option parser un-escapes only \" inside a quoted option value: the command sshd runs is the helper path
// in double quotes, then ssh. The Go parser (what the e2e fake uses) reads the same options.
func TestAuthorizedKeysLineParsesAsTheForcedCommand(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sp, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	for _, from := range []string{"", "192.0.2.10"} {
		line := AuthorizedKeysLine(key, from)
		_, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
		require.NoError(t, err)
		want := []string{"restrict", testCommand}
		if from != "" {
			want = append(want, `from="`+from+`"`)
		}
		assert.Equal(t, want, opts)
		v := strings.TrimSuffix(strings.TrimPrefix(opts[1], `command="`), `"`)
		assert.Equal(t, `"`+winproto.HelperPath+`" ssh`, strings.ReplaceAll(v, `\"`, `"`), "the command sshd runs")
		assert.Equal(t, ForcedKeyCommand, `"`+winproto.HelperPath+`" ssh`)
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
	// R63 Ruling 14: both messages name the package folder the Windows helpers ship in.
	assert.Contains(t, s, `Copy helper\alice-winhelper-windows-amd64.exe or helper\alice-winhelper-windows-arm64.exe from the package of this Alice version as .\alice-helper.exe.'`)
	assert.Contains(t, s, `throw 'Copy helper\alice-winhelper-windows-amd64.exe or helper\alice-winhelper-windows-arm64.exe from the package of this Alice version into this directory as alice-helper.exe first.'`)
	assert.NotContains(t, s, "from the Alice bundle into this directory")
	assert.NotContains(t, s, "from the bundle of this Alice version")
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
	assert.Contains(t, s, "$keyBlob = 'AAAAC3NzaC1lZDI1NTE5AAAAIGVtdWxhdGVk'\n",
		"the blob comes from Go: the forced command holds spaces, so splitting the line on spaces would not find it")
	assert.NotContains(t, s, "-split ' ')[2]")
	assert.Regexp(t, `(?s)Test-Helper \$staging\n\} catch \{\n\s+Remove-Item -LiteralPath \$staging`, s, "a staged copy that fails the check is removed")

	// Real-Windows smoke test, second run: IsMember did not recognise the member Add had added.
	assert.NotContains(t, s, "IsMember", "membership is compared by SID")
	assert.Contains(t, s, "$Group.Invoke('Members')")
	assert.Contains(t, s, "InvokeMember('objectSid', 'GetProperty', $null, $_, $null)")
	assert.Contains(t, s, "if ((Get-GroupMemberSids $group) -notcontains $UserSid) {")
	assert.Regexp(t, `(?s)\$group\.Add\(\$memberPath\)\n\s+\} catch \{\n\s+if \(-not \(Test-AlreadyMember \$_\.Exception\)\) \{ throw \}`, s,
		"already a member is success")
	assert.Contains(t, s, "-2147023518", "ERROR_MEMBER_IN_ALIAS as HRESULT 0x80070562")
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
		testKey,               // no restrict
		"no-pty " + testKey,   // other options
		"restrict " + testKey, // no forced command (final review C1)
		`restrict,from="192.0.2.10" ` + testKey,
		"restrict," + testCommand + `,from="a b" ` + testKey, // from outside the address vocabulary
		"restrict," + testCommand + `,from="" ` + testKey,
		"restrict," + testCommand + `,from="192.0.2.10"` + testKey,
		`restrict,command="x" ` + testKey,
		`restrict,command="\"C:\Windows\System32\cmd.exe\" ssh" ` + testKey,
		"restrict," + testCommand + ",no-pty " + testKey,
		`restrict,from="192.0.2.10",` + testCommand + " " + testKey, // options out of order
		"restrict," + testCommand,
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

// R71 Ruling 18, first part (Task 5): the WinRM setup script checks the helper like the SSH script, takes the account in
// Ruling 6's forms (without the .\ of a local account) and refuses anything it cannot quote. Task 7 completes its body.
func TestSetupScriptWinRMMinimal(t *testing.T) {
	amd, arm := strings.Repeat("a", 64), strings.Repeat("b", 64)
	withChecksums(t, amd, arm)
	for user, want := range map[string]string{`.\alice`: "alice", "alice": "alice", `CORP\alice-svc`: `CORP\alice-svc`} {
		s, err := SetupScriptWinRM(user, "", false)
		require.NoError(t, err, user)
		assert.Contains(t, s, "$AliceUser = '"+want+"'", user)
		assert.Contains(t, s, "'AMD64' = '"+amd+"'", "the SSH script's helper check")
		assert.True(t, strings.HasPrefix(s, "#Requires -RunAsAdministrator\n"))
		for i, r := range s {
			require.Less(t, r, rune(0x80), "ASCII only, at %d", i)
		}
	}
	for _, bad := range []string{"al'ice", "alice@corp.example", `..\alice`, "", `.\`, "alice\n"} {
		_, err := SetupScriptWinRM(bad, "", false)
		assert.Error(t, err, "%q", bad)
	}
	_, err := SetupScriptWinRM("alice", "10.0.0.0/8 ';", false)
	assert.Error(t, err, "a from it cannot quote")

	withChecksums(t, "", "")
	_, err = SetupScriptWinRM("alice", "", false)
	require.ErrorIs(t, err, ErrHelperUnverified)
	s, err := SetupScriptWinRM("alice", "", true)
	require.NoError(t, err)
	assert.Contains(t, s, "cannot verify alice-helper.exe")
}

// R71 Ruling 19: the provider answers the WinRM script through providers.WinRMSetupGuide, "" when the build cannot
// verify the helper.
func TestWinRMSetupScriptGuide(t *testing.T) {
	var g providers.WinRMSetupGuide = New(Options{AllowUnverifiedHelper: true})
	withChecksums(t, "", "")
	want, err := SetupScriptWinRM(`.\alice`, "", true)
	require.NoError(t, err)
	assert.Equal(t, want, g.WinRMSetupScript(`.\alice`))
	assert.Empty(t, New(Options{}).WinRMSetupScript(`.\alice`), "no checksums, no development build")
	assert.Empty(t, g.WinRMSetupScript("al'ice"))
}
