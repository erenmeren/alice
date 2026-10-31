package windows

import (
	"errors"
	"regexp"
	"strings"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/windows/winproto"
)

// MatchBlock is what the setup script adds to C:\ProgramData\ssh\sshd_config for the account (design §4.3), between
// "# BEGIN Alice" and "# END Alice": sshd runs alice-helper.exe for every session of the account, which reads the
// line Alice sent from SSH_ORIGINAL_COMMAND (Ruling 5), and allows the key only. __USER__ is the account name in
// lower case. docs/windows-host-preparation.md quotes it for alice (TestPreparationGuideQuotesTheMatchBlock).
const MatchBlock = "Match User __USER__\n" +
	"    ForceCommand \"C:\\Program Files\\Alice\\alice-helper.exe\" ssh\n" +
	"    AuthenticationMethods publickey\n" +
	"    PermitTTY no\n" +
	"    AllowTcpForwarding no\n" +
	"    AllowStreamLocalForwarding no\n" +
	"    X11Forwarding no\n" +
	"    PermitTunnel no\n"

// ForcedKeyCommand is the command the key line forces: the installed helper with its forced-command entry "ssh".
const ForcedKeyCommand = `"` + winproto.HelperPath + `" ssh`

// keyOptions are the options of the key line before from=: "restrict" (no forwarding, no pty, no ~/.ssh/rc; sshd
// 8.1p1 and 9.5p2 accept it, W0 F3) and command= with ForcedKeyCommand. OpenSSH's option parser un-escapes only \"
// inside a quoted value, so the Windows path is written as it is and only its double quotes are escaped.
const keyOptions = `restrict,command="` + `\"` + winproto.HelperPath + `\" ssh"`

// AuthorizedKeysLine is the line of administrators_authorized_keys that authorizes Alice's key (design §4.3). sshd
// reads that file for every member of Administrators (the default Match Group administrators block), so the line
// itself forces the helper (command=, which sshd applies whatever the account and which keeps SSH_ORIGINAL_COMMAND):
// Alice's key reaches only alice-helper.exe on every administrator account (final review C1; MatchBlock's
// ForceCommand is a second layer for the account). When from is given the line also names the source addresses. An
// invalid from (linuxssh.ValidateFrom) gives "": the caller asked for a restriction, so a line without it is never
// produced (SetupScript refuses the empty line).
func AuthorizedKeysLine(publicKey, from string) string {
	if linuxssh.ValidateFrom(from) != nil {
		return ""
	}
	if from == "" {
		return keyOptions + " " + publicKey
	}
	return keyOptions + `,from="` + from + `" ` + publicKey
}

// keyLineRE is the only shape SetupScript embeds: AuthorizedKeysLine's options, then an OpenSSH public key (type,
// base64 blob, optional comment), printable ASCII only. A ' is refused separately (the line sits in single quotes).
// Group 1 is the from= value, group 2 the key blob.
var keyLineRE = regexp.MustCompile(`^` + regexp.QuoteMeta(keyOptions) +
	`(?:,from="([^"]*)")? [a-z0-9@.-]{1,64} ([A-Za-z0-9+/]{16,}={0,2})(?: [ -~]*)?$`)

var errBadKeyLine = errors.New("windows: the administrators_authorized_keys line cannot be embedded in the setup script")

// ErrHelperUnverified means this build has no alice-helper.exe checksums and is not a development build: it offers
// no setup script rather than one that installs an unchecked helper for an administrator account.
var ErrHelperUnverified = errors.New("windows: this Alice build has no alice-helper.exe checksums; build it with make build or the image build")

// firewallAddress is the PowerShell value of $AliceAddress: the from= addresses of the line as a list, or 'Any' when
// the line has none or uses what a firewall rule cannot express (sshd's wildcards and negation).
func firewallAddress(from string) (string, bool) {
	if from == "" || strings.ContainsAny(from, "*?!") {
		return "'Any'", false
	}
	return "'" + strings.Join(strings.Split(from, ","), "', '") + "'", true
}

const addressNotice = `Write-Warning 'Alice''s address is not in these commands, so the firewall rule Alice-SSH-In allows port 22 from any address. To limit it, set $AliceAddress above, or get the commands with Alice''s address (docs/windows-host-preparation.md).'
`

const helperUnverified = `# This Alice build has no alice-helper.exe checksums (it was built without "make winhelper"),
# so the helper below is installed without checking it.
Write-Warning 'This Alice build cannot verify alice-helper.exe (development build without checksums).'
function Test-Helper([string]$Path) { }
`

const helperVerify = `$HelperSHA256 = @{ 'AMD64' = '__AMD64__'; 'ARM64' = '__ARM64__' }
function Test-Helper([string]$Path) {
    $arch = "$env:PROCESSOR_ARCHITECTURE"
    if (-not $HelperSHA256.ContainsKey($arch)) {
        throw "alice-helper.exe is built for AMD64 and ARM64 only (this PowerShell reports '$arch'; use the 64-bit PowerShell)."
    }
    $got = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $HelperSHA256[$arch]) {
        throw '.\alice-helper.exe is not the alice-helper.exe of this Alice version (its SHA-256 checksum differs). Copy helper\alice-winhelper-windows-amd64.exe or helper\alice-winhelper-windows-arm64.exe from the package of this Alice version as .\alice-helper.exe.'
    }
}
`

// helperCheck defines Test-Helper, which checks a file against the checksum of this Alice version for the server's
// processor (R37 item 2 for Windows). Unless both checksums are well formed it embeds neither and warns instead.
func helperCheck(amd64, arm64 string) string {
	if !sha256Hex.MatchString(amd64) || !sha256Hex.MatchString(arm64) {
		return helperUnverified
	}
	return strings.NewReplacer("__AMD64__", amd64, "__ARM64__", arm64).Replace(helperVerify)
}

// SetupScript is the PowerShell script of design §6.1 (R60 Ruling 15): run once as an administrator in the
// directory that holds .\alice-helper.exe, on Windows PowerShell 5.1 or PowerShell 7, and safe to run again. It
// checks the helper, installs OpenSSH Server when sshd is absent, creates the local account (or takes the domain
// account's name), puts the key line into administrators_authorized_keys once, adds MatchBlock to sshd_config only
// after sshd -t accepted it, installs the helper and the data directory with an ACL of Administrators and SYSTEM,
// adds the firewall rule and the event source, and prints the host key fingerprints. It never sets
// LocalAccountTokenFilterPolicy (W0 F3: a key logon of a local administrator is elevated without it).
//
// Without the helper checksums only a development build (allowUnverified) gets a script, and it says that it cannot
// verify the helper; any other build gets ErrHelperUnverified. A line that is not AuthorizedKeysLine's shape (or holds
// a ', a control or a non-ASCII character) is errBadKeyLine.
func SetupScript(authorizedKeysLine string, allowUnverified bool) (string, error) {
	if !allowUnverified && !HelperChecksumsKnown() {
		return "", ErrHelperUnverified
	}
	idx := keyLineRE.FindStringSubmatchIndex(authorizedKeysLine)
	if idx == nil || strings.ContainsRune(authorizedKeysLine, '\'') {
		return "", errBadKeyLine
	}
	from, blob := "", authorizedKeysLine[idx[4]:idx[5]]
	if idx[2] >= 0 {
		// from= is present: it must name addresses (an empty from="" would mean none).
		from = authorizedKeysLine[idx[2]:idx[3]]
		if from == "" || linuxssh.ValidateFrom(from) != nil {
			return "", errBadKeyLine
		}
	}
	address, restricted := firewallAddress(from)
	notice := addressNotice
	if restricted {
		notice = ""
	}
	return strings.NewReplacer(
		"__ADDRESS__", address,
		"__ADDRESS_NOTICE__", notice,
		"__LINE__", authorizedKeysLine,
		"__KEY_BLOB__", blob,
		"__HELPER_CHECK__", helperCheck(helperSHA256WindowsAMD64, helperSHA256WindowsARM64),
		"__USER_RE__", userRE.String(),
		"__MATCH_BLOCK__", strings.ReplaceAll(MatchBlock, "__USER__", "$MatchUser"),
		"__HELPER_PATH__", winproto.HelperPath,
		"__DATA_DIR__", winproto.DataDir,
	).Replace(scriptTemplate), nil
}

// SetupSnippets implements providers.SetupGuide: the one profile "windows", a PowerShell script and no sudoers
// file. Its Script is "" when SetupScript refuses (a build that cannot verify the helper).
func (p *Provider) SetupSnippets(authorizedKeysLine string) map[string]providers.SetupSnippet {
	script, _ := SetupScript(authorizedKeysLine, p.allowUnverified)
	return map[string]providers.SetupSnippet{"windows": {Profile: "windows", Script: script}}
}

var errBadWinRMSetup = errors.New("windows: the account or the address cannot be embedded in the WinRM setup script")

// SetupScriptWinRM is the PowerShell script that prepares a Windows server for the WinRM transport (R71 Ruling 18): run
// once as an administrator in the directory that holds .\alice-helper.exe. user is the target's account in Ruling 6's
// forms; the script names it without the .\ of a local account. from is the platform key line's from= value ("" for
// any address). Without the helper checksums only a development build (allowUnverified) gets a script, as SetupScript.
//
// shortcut: the header and the SSH script's helper check only; Task 7 of the W7 plan writes the account, listener and
// firewall steps of Ruling 18.
func SetupScriptWinRM(user, from string, allowUnverified bool) (string, error) {
	if !allowUnverified && !HelperChecksumsKnown() {
		return "", ErrHelperUnverified
	}
	if (!ValidUser(user) && !localUserRE.MatchString(user)) || linuxssh.ValidateFrom(from) != nil {
		return "", errBadWinRMSetup
	}
	return "#Requires -RunAsAdministrator\n" +
		"# Prepares this Windows server for Alice over WinRM (HTTPS, NTLMv2). Run it once in an elevated PowerShell, in the\n" +
		"# directory that holds alice-helper.exe from the helper folder of the Alice package.\n" +
		"& {\n" +
		"Set-StrictMode -Version 3\n" +
		"$ErrorActionPreference = 'Stop'\n" +
		"$AliceUser = '" + strings.TrimPrefix(user, `.\`) + "'\n" +
		helperCheck(helperSHA256WindowsAMD64, helperSHA256WindowsARM64) +
		"Test-Helper '.\\alice-helper.exe'\n" +
		"Write-Warning 'This Alice version checks the helper only: prepare the account, the WinRM HTTPS listener and the firewall as docs/windows-host-preparation.md says.'\n" +
		"}\n", nil
}

// WinRMSetupScript implements providers.WinRMSetupGuide: SetupScriptWinRM for user, without an address restriction;
// "" when SetupScriptWinRM refuses (a build that cannot verify the helper).
func (p *Provider) WinRMSetupScript(user string) string {
	script, _ := SetupScriptWinRM(user, "", p.allowUnverified)
	return script
}

// HelperInfo implements providers.SetupGuide.
func (p *Provider) HelperInfo() (string, int) { return winproto.HelperPath, winproto.Protocol }

// scriptTemplate is ASCII only (Windows PowerShell 5.1 reads a file without a byte order mark in the ANSI code page).
// Native programs run through Invoke-Native, so their standard error never becomes a terminating error under
// $ErrorActionPreference = 'Stop' (Windows PowerShell 5.1) and their exit code is checked instead.
const scriptTemplate = `#Requires -RunAsAdministrator
# Prepares this Windows server for Alice. Run it once in an elevated PowerShell (Windows PowerShell 5.1 or
# PowerShell 7), in the directory that holds alice-helper.exe from the helper folder of the Alice package.
# Running it again is safe.
# What it changes and how to undo it: docs/windows-host-preparation.md.
# The whole script is one block, so a pasted copy also stops as a whole at the first error.
& {
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# The Windows account Alice signs in as. The local account 'alice' is created by this script. For the domain
# setup (a domain account that a group policy adds to the Administrators group of the servers), set the account
# here before you run the script, for example 'DOMAIN\alice-svc', and enter the same name in Alice.
$AliceUser = 'alice'
# The addresses the firewall rule Alice-SSH-In accepts on port 22 ('Any', or a list such as '192.0.2.10').
$AliceAddress = __ADDRESS__
# Alice's key, as it goes into administrators_authorized_keys.
$AuthorizedKey = '__LINE__'

$HelperPath = '__HELPER_PATH__'
$DataDir = '__DATA_DIR__'
$SshDir = 'C:\ProgramData\ssh'
$AuthorizedKeysFile = 'C:\ProgramData\ssh\administrators_authorized_keys'
$SshdConfig = 'C:\ProgramData\ssh\sshd_config'
$AdministratorsSid = 'S-1-5-32-544'
$SystemSid = 'S-1-5-18'
$CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$NL = [string][char]13 + [char]10

function Invoke-Native([string]$FilePath, [string[]]$Arguments) {
    $PSNativeCommandUseErrorActionPreference = $false
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = -1
    try {
        $out = @(& $FilePath @Arguments 2>&1 | ForEach-Object { "$_" })
        $code = $global:LASTEXITCODE
    } finally {
        $ErrorActionPreference = $eap
    }
    return [pscustomobject]@{ ExitCode = $code; Output = ($out -join [Environment]::NewLine) }
}

function Invoke-Checked([string]$What, [string]$FilePath, [string[]]$Arguments) {
    $r = Invoke-Native $FilePath $Arguments
    if ($r.ExitCode -ne 0) { throw "$What failed (exit code $($r.ExitCode)): $($r.Output)" }
    return $r.Output
}

function Assert-RealDirectory([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Path is not a plain directory (a file, link or junction). Remove it, then run this script again."
    }
}

# An existing directory must be owned by Administrators, SYSTEM or the administrator running the script, and hold
# no link or junction anywhere below it (anyone may create folders in C:\ProgramData before this script runs).
function Assert-OwnedByAdministrators([string]$Path) {
    $owner = (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (@($AdministratorsSid, $SystemSid, $CurrentSid) -notcontains $owner) {
        throw "$Path is owned by $owner, not by Administrators or SYSTEM, so someone else may have created it. Check and remove it, then run this script again."
    }
}

function Assert-SafeDirectory([string]$Path) {
    Assert-RealDirectory $Path
    Assert-OwnedByAdministrators $Path
    $link = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -Attributes ReparsePoint | Select-Object -First 1)
    if ($link.Count -gt 0) {
        throw "$Path holds a link or junction ($($link[0].FullName)). Remove it, then run this script again."
    }
    foreach ($c in @(Get-ChildItem -LiteralPath $Path -Recurse -Force)) { Assert-OwnedByAdministrators $c.FullName }
}

# Creates a directory, or checks an existing one (Assert-SafeDirectory), and gives it Set-AdminOnlyAcl.
function New-AdminOnlyDirectory([string]$Path, [string[]]$ReadExecute = @()) {
    if (Test-Path -LiteralPath $Path) { Assert-SafeDirectory $Path } else { New-Item -ItemType Directory -Path $Path | Out-Null }
    Assert-RealDirectory $Path
    Set-AdminOnlyAcl $Path -Container -ReadExecute $ReadExecute
}

# Owner Administrators; full control for Administrators and SYSTEM only (plus read and execute for the SIDs in
# $ReadExecute), inheritance from the parent removed. Only the path itself is changed (never /T, which follows
# junctions): a directory's children inherit the new entries.
function Set-AdminOnlyAcl([string]$Path, [switch]$Container, [string[]]$ReadExecute = @()) {
    $icacls = "$env:WINDIR\System32\icacls.exe"
    $inherit = ''
    if ($Container) { $inherit = '(OI)(CI)' }
    Invoke-Checked "icacls (owner of $Path)" $icacls @($Path, '/setowner', "*$AdministratorsSid", '/C', '/Q') | Out-Null
    Invoke-Checked "icacls (reset of $Path)" $icacls @($Path, '/reset', '/C', '/Q') | Out-Null
    $grants = @('/grant:r', "*$($AdministratorsSid):$($inherit)F", "*$($SystemSid):$($inherit)F")
    foreach ($s in $ReadExecute) { $grants += "*$($s):$($inherit)RX" }
    Invoke-Checked "icacls (access of $Path)" $icacls (@($Path, '/inheritance:r') + $grants + @('/Q')) | Out-Null
}

# The SIDs of a local group's direct members (orphaned SIDs included), compared instead of ADSI paths: the path
# Add takes (WinNT://COMPUTER/alice) is not a form the ADSI membership test recognises on every server. No SIDs when the members
# cannot be read; the Add below then decides.
function Get-GroupMemberSids($Group) {
    try {
        return @(@($Group.Invoke('Members')) | ForEach-Object {
            $bytes = [byte[]]$_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null)
            (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
        })
    } catch {
        return @()
    }
}

# Whether an exception (or one it wraps) is ERROR_MEMBER_IN_ALIAS (1378, HRESULT 0x80070562): the account is
# already a member, which is what Add was for.
function Test-AlreadyMember($Exception) {
    for ($e = $Exception; $null -ne $e; $e = $e.InnerException) {
        if ($e.HResult -eq -2147023518 -or $e.HResult -eq 1378) { return $true }
    }
    return $false
}

function Get-AccountSid([string]$Name) {
    try {
        return (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

# 32 characters from a cryptographic generator, with upper and lower case letters, digits and symbols.
function New-RandomPassword {
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+-=?@_'
    $limit = 256 - (256 % $alphabet.Length)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] 1
    try {
        do {
            $sb = New-Object System.Text.StringBuilder
            while ($sb.Length -lt 32) {
                $rng.GetBytes($buf)
                if ($buf[0] -lt $limit) { [void]$sb.Append($alphabet[$buf[0] % $alphabet.Length]) }
            }
            $s = $sb.ToString()
        } until ($s -cmatch '[A-Z]' -and $s -cmatch '[a-z]' -and $s -match '[0-9]' -and $s -match '[^A-Za-z0-9]')
    } finally {
        $rng.Dispose()
    }
    return $s
}

# 1. Checks before any change.
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script in an elevated PowerShell (Run as administrator).'
}
if ($AliceUser -notmatch '__USER_RE__') {
    throw "'$AliceUser' is not an account name Alice accepts: a local name such as alice, or DOMAIN\name."
}
$IsDomainAccount = $AliceUser.Contains('\')
if ($IsDomainAccount) { $QualifiedUser = $AliceUser } else { $QualifiedUser = "$env:COMPUTERNAME\$AliceUser" }

# 2. The helper.
__HELPER_CHECK__$HelperSource = Join-Path (Get-Location).ProviderPath 'alice-helper.exe'
if (-not (Test-Path -LiteralPath $HelperSource -PathType Leaf)) {
    throw 'Copy helper\alice-winhelper-windows-amd64.exe or helper\alice-winhelper-windows-arm64.exe from the package of this Alice version into this directory as alice-helper.exe first.'
}
Test-Helper $HelperSource

# 3. OpenSSH Server: the Windows capability when sshd is absent; an sshd installed another way (the Win32-OpenSSH
# MSI) is used as it is.
if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
    Write-Host 'Installing OpenSSH Server (the Windows capability OpenSSH.Server; this takes about a minute).'
    try {
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
        if ("$($cap.State)" -ne 'Installed') { Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null }
    } catch {
        throw "OpenSSH Server could not be installed as a Windows capability ($($_.Exception.Message)). Without access to Windows Update, install the Win32-OpenSSH package OpenSSH-Win64-v10.0.0.0.msi named in docs/windows-host-preparation.md, then run this script again."
    }
}
$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'"
if (-not $service) { throw 'The OpenSSH Server service sshd is not installed. Install OpenSSH Server, then run this script again.' }
$servicePath = "$($service.PathName)".Trim()
if ($servicePath.StartsWith('"')) { $SshdExe = $servicePath.Substring(1, $servicePath.IndexOf('"', 1) - 1) } else { $SshdExe = ($servicePath -split ' ')[0] }
$SshKeygen = Join-Path (Split-Path -Parent $SshdExe) 'ssh-keygen.exe'
Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd
for ($i = 0; $i -lt 30 -and -not (Test-Path -LiteralPath $SshdConfig); $i++) { Start-Sleep -Seconds 1 }
if (-not (Test-Path -LiteralPath $SshdConfig)) { throw "sshd did not create $SshdConfig." }

# 4. The account, a member of Administrators (by its SID, whatever the language of Windows), denied local and
# Remote Desktop sign-in. Its password is random, never shown, and sshd refuses password sign-in for it.
$UserSid = Get-AccountSid $QualifiedUser
if (-not $UserSid) {
    if ($IsDomainAccount) {
        throw "The domain account $AliceUser is not known to this server. Create it in the domain first (docs/windows-host-preparation.md, the domain setup)."
    }
    Write-Host "Creating the local account $AliceUser."
    $password = New-RandomPassword
    $computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
    $u = $computer.Create('User', $AliceUser)
    $u.SetPassword($password)
    $u.SetInfo()
    Remove-Variable password
    $u.Put('Description', 'Alice certificate manager (SSH key sign-in only)')
    $u.Put('UserFlags', ([int]$u.Get('UserFlags')) -bor 0x10000)
    $u.SetInfo()
    $UserSid = Get-AccountSid $QualifiedUser
    if (-not $UserSid) { throw "The local account $AliceUser was created but cannot be found." }
}
$adminsName = (New-Object System.Security.Principal.SecurityIdentifier($AdministratorsSid)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
$group = [ADSI]"WinNT://$env:COMPUTERNAME/$adminsName,group"
$memberPath = 'WinNT://' + $QualifiedUser.Replace('\', '/')
if ((Get-GroupMemberSids $group) -notcontains $UserSid) {
    Write-Host "Adding $AliceUser to $adminsName."
    try {
        $group.Add($memberPath)
    } catch {
        if (-not (Test-AlreadyMember $_.Exception)) { throw }
    }
}

$work = Join-Path $env:TEMP ('alice-setup-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $secedit = "$env:WINDIR\System32\secedit.exe"
    $export = Join-Path $work 'export.inf'
    Invoke-Checked 'secedit /export' $secedit @('/export', '/cfg', $export, '/areas', 'USER_RIGHTS', '/quiet') | Out-Null
    $rights = @{}
    foreach ($l in @(Get-Content -LiteralPath $export -Encoding Unicode)) {
        if ($l -match '^\s*(Se\w+)\s*=\s*(.*)$') { $rights[$Matches[1]] = $Matches[2].Trim() }
    }
    if (-not $IsDomainAccount -and $rights.ContainsKey('SeDenyNetworkLogonRight') -and $rights['SeDenyNetworkLogonRight'] -match '\*S-1-5-11[34]\b') {
        Write-Warning 'This server denies network sign-in to local accounts ("Deny access to this computer from the network" holds S-1-5-113 or S-1-5-114, as hardened baselines do), so sshd may refuse the local account. Use the domain setup of docs/windows-host-preparation.md.'
    }
    $inf = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]')
    $changed = $false
    foreach ($right in @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight')) {
        $entries = @()
        if ($rights.ContainsKey($right) -and $rights[$right]) { $entries = @($rights[$right].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        if ($entries -notcontains "*$UserSid") { $entries += "*$UserSid"; $changed = $true }
        $inf += "$right = " + ($entries -join ',')
    }
    if ($changed) {
        Write-Host "Denying $AliceUser local and Remote Desktop sign-in."
        $infFile = Join-Path $work 'alice.inf'
        Set-Content -LiteralPath $infFile -Value $inf -Encoding Unicode
        Invoke-Checked 'secedit /configure' $secedit @('/configure', '/db', (Join-Path $work 'alice.sdb'), '/cfg', $infFile, '/areas', 'USER_RIGHTS', '/quiet') | Out-Null
    }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

# 5. Alice's key, once: every other line with the same key (an earlier from= value) is replaced.
$keyBlob = '__KEY_BLOB__'
$existing = @()
if (Test-Path -LiteralPath $AuthorizedKeysFile) { $existing = @([System.IO.File]::ReadAllLines($AuthorizedKeysFile)) }
$others = @($existing | Where-Object { @($_ -split '\s+') -cnotcontains $keyBlob })
$same = @($existing | Where-Object { $_.TrimEnd() -ceq $AuthorizedKey })
if ($same.Count -ne 1 -or ($others.Count + 1) -ne $existing.Count) {
    [System.IO.File]::WriteAllText($AuthorizedKeysFile, ((@($others) + $AuthorizedKey) -join $NL) + $NL, $Utf8)
}
Set-AdminOnlyAcl $AuthorizedKeysFile

# 6. sshd_config: the Alice block at the end, replacing an earlier one, kept only when sshd -t accepts it.
$MatchUser = $AliceUser.ToLowerInvariant()
$MatchBlock = @"
__MATCH_BLOCK__"@
$old = [System.IO.File]::ReadAllText($SshdConfig)
$text = $old
$begin = $text.IndexOf('# BEGIN Alice')
if ($begin -ge 0) {
    $end = $text.IndexOf('# END Alice', $begin)
    if ($end -lt 0) { throw "$SshdConfig has '# BEGIN Alice' without '# END Alice'. Remove the partial block, then run this script again." }
    $after = $text.IndexOf([char]10, $end)
    if ($after -lt 0) { $after = $text.Length } else { $after++ }
    $text = $text.Substring(0, $begin) + $text.Substring($after)
}
$new = $text.TrimEnd([char[]]$NL) + $NL + $NL + '# BEGIN Alice' + $NL + (($MatchBlock -replace '\r?\n', $NL).TrimEnd([char[]]$NL)) + $NL + '# END Alice' + $NL
if ($new -notmatch 'administrators_authorized_keys') {
    Write-Warning "$SshdConfig does not name administrators_authorized_keys (the Match Group administrators block of the default file), so sshd may not read Alice's key."
}
if ($new -cne $old) {
    [System.IO.File]::WriteAllText($SshdConfig, $new, $Utf8)
    $check = Invoke-Native $SshdExe @('-t')
    if ($check.ExitCode -ne 0) {
        [System.IO.File]::WriteAllText($SshdConfig, $old, $Utf8)
        throw "sshd refused the new configuration, so the previous sshd_config was put back: $($check.Output)"
    }
    Restart-Service -Name sshd
}

# 7. The helper and its data directory: Administrators and SYSTEM only (the account may also read and run the
# helper, so an unelevated sign-in is told so by the helper itself).
New-AdminOnlyDirectory (Split-Path -Parent $HelperPath) -ReadExecute @($UserSid)
$staging = "$HelperPath.new"
Copy-Item -LiteralPath $HelperSource -Destination $staging -Force
try {
    Test-Helper $staging
} catch {
    Remove-Item -LiteralPath $staging -Force -ErrorAction SilentlyContinue
    throw
}
Move-Item -LiteralPath $staging -Destination $HelperPath -Force
foreach ($d in @((Split-Path -Parent $DataDir), $DataDir)) { New-AdminOnlyDirectory $d }

# 8. The firewall rule for sshd, from Alice's address.
__ADDRESS_NOTICE__Remove-NetFirewallRule -Name 'Alice-SSH-In' -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'Alice-SSH-In' -DisplayName 'Alice SSH (TCP 22)' -Description 'Alice signs in to alice-helper.exe over SSH.' -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress $AliceAddress -Action Allow -Profile Any | Out-Null
if ("$AliceAddress" -ne 'Any' -and @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Where-Object { "$($_.Enabled)" -eq 'True' }).Count -gt 0) {
    Write-Warning 'The firewall rule OpenSSH-Server-In-TCP (added with OpenSSH Server) still accepts port 22 from every address. Disable it if nobody else signs in over SSH.'
}

# 9. The event source of the helper.
if (-not [System.Diagnostics.EventLog]::SourceExists('Alice Helper')) {
    [System.Diagnostics.EventLog]::CreateEventSource('Alice Helper', 'Application')
}

# 10. The host key fingerprints, to compare with the fingerprint Alice shows when the server is added.
Write-Host 'Host key fingerprints of this server (compare them with the fingerprint Alice shows):'
foreach ($k in @(Get-ChildItem -Path (Join-Path $SshDir 'ssh_host_*_key.pub'))) {
    Write-Host (Invoke-Checked 'ssh-keygen' $SshKeygen @('-lf', $k.FullName))
}
Write-Output 'This server is ready for Alice.'
}
`
