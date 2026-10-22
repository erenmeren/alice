# Preparing a Windows server for Alice

Alice reads the certificates of a Windows server: every HTTPS binding of http.sys (the Windows HTTP server that IIS,
WinRM, SSTP and other applications share), the IIS sites that use each binding, and the certificate bound there
from the machine store, with its expiry and store. The bindings appear under **Websites on this server** with the
column **IIS site**, and the certificates under **Certificates** like any certificate Alice found. **On a Windows
server Alice only reads in this release.** It never imports, binds or removes a certificate, never changes IIS or
http.sys and never restarts a service. The deploy controls on a Windows server's page are shown disabled with the
note "Not available for IIS servers yet".

Alice signs in over SSH (the OpenSSH Server of Windows) with its own key. It never gets a shell: sshd runs
**alice-helper.exe** for every sign-in of Alice's account, and the helper does only a fixed list of things. This
guide prepares a server once; you can undo it completely (see [Removing Alice from a Windows server](#removing-alice-from-a-windows-server)).
Alice does not manage the SSH keys of a Windows server.

Supported systems: Windows Server 2019, 2022 and 2025, with Desktop Experience or Server Core, on x64 (AMD64) or
ARM64, with IIS 10 when the server runs IIS. Alice is tested on Windows Server 2022 and 2025 with Desktop
Experience. Windows Server 2019, Server Core and a domain-joined server under a security baseline are supported but
are checked by hand before each release, not by the automated tests. A server without IIS can be added as well: its
other bindings (WinRM, SSTP, AD FS) are listed, as not supported.

## Two ways to set up the account

Alice needs an administrator account on the server: the machine certificate stores and the http.sys configuration
can only be read by administrators. Choose one of two setups.

- **A local account (workgroup or default).** The setup script creates the local account `alice` in the
  Administrators group, with a random 32-character password that is never shown or stored anywhere (sshd also
  refuses password sign-in for the account), and denies it "Log on locally" and "Log on through Remote Desktop
  Services". On Windows Server 2022 and 2025 the key sign-in of a local administrator through OpenSSH gets a full
  administrator token without any change to User Account Control.
- **A domain account (a domain with a hardened baseline).** Security baselines such as the Microsoft one put *Local
  account and member of Administrators group* (S-1-5-114) into "Deny access to this computer from the network",
  which blocks a local administrator's sign-in over SSH. Then use a dedicated domain account, for example
  `CORP\alice-svc`: create it in the domain (no mailbox, password never expires, no interactive sign-in), add it to
  the local Administrators group of the managed servers with a group policy (Restricted Groups or Group Policy
  Preferences, "Local Users and Groups"), and deny it "Log on locally" and "Log on through Remote Desktop Services"
  in the same policy. Edit the line `$AliceUser = 'alice'` of the setup script to `$AliceUser = 'CORP\alice-svc'`
  before you run it, and enter the same name as **Windows account** in Alice.

The script warns when it finds that "Deny access to this computer from the network" holds S-1-5-113 or S-1-5-114 and
the account is local.

## Steps

1. Get the helper. In a development checkout run `make winhelper`; it writes `bin/alice-winhelper-windows-amd64.exe`,
   `bin/alice-winhelper-windows-arm64.exe` and `bin/alice-winhelper.sha256`. Copy the file for the server's
   processor (`amd64` for x64, `arm64` for ARM64) to the server as `alice-helper.exe`, in a new folder that only
   administrators can write, for example `C:\AliceSetup`. You can compare it yourself:
   `Get-FileHash .\alice-helper.exe -Algorithm SHA256` must print the value from `alice-winhelper.sha256` (in upper
   case); the setup script checks it again.
2. In Alice, sign in as an administrator and open **Servers**. Under **Prepare a server for Alice** choose **Server
   type** **Windows server** and **Copy commands**. The script contains Alice's public key; **Fingerprint of Alice's
   key** above it shows its fingerprint.
3. On the server, save the script as `prepare-alice.ps1` in the folder that holds `alice-helper.exe`, open
   PowerShell with **Run as administrator**, change to that folder and run it: `.\prepare-alice.ps1` (if the
   execution policy refuses it, `powershell -ExecutionPolicy Bypass -File .\prepare-alice.ps1`). Run it once in an elevated PowerShell (Windows PowerShell
   5.1 or PowerShell 7); running it again is safe. At the end it prints the host key fingerprints of the server and
   "This server is ready for Alice."
4. In Alice choose **Add server**, enter a **Name**, the server's **Address**, the **SSH port** (22), the **Windows
   account** (`alice`, or the domain account of the domain setup, such as `CORP\alice-svc`) and **Server type**
   **Windows server**, and choose **Connect**.
5. Alice shows **Is this your server?** with the server's **Fingerprint**. Compare it character by character with
   the `SHA256:...` line of the same key type that the script printed in step 3. You can print them again with
   `ssh-keygen.exe -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub`, where `ssh-keygen.exe` lies next to `sshd.exe`:
   `C:\Windows\System32\OpenSSH\ssh-keygen.exe` for the Windows capability, `C:\Program Files\OpenSSH\ssh-keygen.exe`
   for the Win32-OpenSSH MSI (`(Get-CimInstance Win32_Service -Filter "Name='sshd'").PathName` shows which). Only if it
   is the same, choose **Yes, this is my server**. If it differs, choose **No, cancel** and ask your network or
   security team.
6. Alice tests the connection (the helper version, the Windows version, IIS, the token's elevation and the machine
   stores) and then reads the bindings. Choose **Discover** on the server's page to read it again at any time; Alice
   also does it on its own once per discovery interval.

A restriction to Alice's source address is not added by the **Servers** page. If you want it, ask for the script
through the API with `GET /api/v1/ssh-keys/platform-key?from=<Alice's IP address>`: the key line then carries
`from="<address>"` and the firewall rule accepts port 22 only from that address. Without it the script warns that the
rule accepts any address; you can also set `$AliceAddress` in the script yourself (one address, a range such as
`192.0.2.0/24`, or a list such as `'192.0.2.10', '192.0.2.11'`).

### OpenSSH Server without Windows Update

The script installs OpenSSH Server from the Windows capability `OpenSSH.Server~~~~0.0.1.0` when the service `sshd`
is absent (about 30 seconds on Windows Server 2022; Windows Server 2025 has it already). An `sshd` installed another
way is used as it is. When the server cannot reach Windows Update or a configured source, the script stops and
names the alternative: download the Win32-OpenSSH package on a machine with access, check it, copy it to the server,
install it and run the script again.

- Package: `https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-Win64-v10.0.0.0.msi`
- SHA-256: `ddec9c53864280759cf9f74791cefd387100e3946aa849a1c138a4ed1b96b7d9` (`Get-FileHash` prints it in upper case)
- Install: `msiexec /i OpenSSH-Win64-v10.0.0.0.msi /qn /norestart`

## The sshd configuration

The script adds this block to the end of `C:\ProgramData\ssh\sshd_config`, between the lines `# BEGIN Alice` and
`# END Alice` (exactly as the setup script writes it for the account `alice`; the account name is written in lower
case):

```
Match User alice
    ForceCommand "C:\Program Files\Alice\alice-helper.exe" ssh
    AuthenticationMethods publickey
    PermitTTY no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
```

`ForceCommand` makes sshd run the helper for every session of the account, whatever Alice asks for; the helper reads
Alice's request from `SSH_ORIGINAL_COMMAND`, checks every word against its own fixed vocabulary (no shell, no
`cmd.exe`) and refuses anything else. `AuthenticationMethods publickey` refuses passwords. The other lines refuse a
terminal and every kind of forwarding. The block must stay the last `Match` block of the file: a line you add after
`# END Alice` would apply to Alice's account only. Running the script again replaces the block.

The default `sshd_config` has a `Match Group administrators` block that makes sshd read the keys of every
administrator from `C:\ProgramData\ssh\administrators_authorized_keys`; Alice's key goes there. The script warns if
the file no longer names it.

## What the script changes

The script stops at the first error. It changes nothing before it has checked the helper.

1. Checks that it runs elevated, that `$AliceUser` is an account name Alice accepts, that `.\alice-helper.exe` exists
   and that its SHA-256 checksum is the one built into this Alice version for the processor
   (`$env:PROCESSOR_ARCHITECTURE` `AMD64` or `ARM64`). If they differ, it stops: the file is not the
   `alice-helper.exe` of this Alice version. (A development build of Alice without checksums prints a warning
   instead and installs the file unchecked.)
2. Installs OpenSSH Server when `sshd` is absent (above), sets `sshd` to start automatically and starts it (the first
   start creates the host keys and `sshd_config`).
3. Creates the local account when it does not exist (a domain account must exist), adds it to the local group with
   the SID S-1-5-32-544 (Administrators, whatever the language of Windows), and grants it the user rights "Deny log on
   locally" (`SeDenyInteractiveLogonRight`) and "Deny log on through Remote Desktop Services"
   (`SeDenyRemoteInteractiveLogonRight`) with `secedit`. A group policy that sets these rights replaces the local
   setting; set them in the policy for the domain setup.
4. Writes Alice's key line into `C:\ProgramData\ssh\administrators_authorized_keys`, exactly once: a line with the
   same key (an earlier `from=` value) is replaced, every other line is kept. The line is `restrict` (no
   forwarding, no terminal), with `from="<address>"` when the script was asked for with Alice's address, then the key.
   The file's owner becomes Administrators and its access Administrators and SYSTEM only, as sshd requires.
5. Adds the block above to `sshd_config`. The new file is checked with `sshd -t` first; when sshd refuses it, the
   previous file is put back and the script stops. Then `sshd` is restarted.
6. Copies the checked helper into `C:\Program Files\Alice` (owner Administrators, full control for Administrators
   and SYSTEM, read and execute for Alice's account, nothing inherited), checks the copy's checksum again and
   installs it as `C:\Program Files\Alice\alice-helper.exe`. Creates `C:\ProgramData\Alice` and
   `C:\ProgramData\Alice\helper` for the helper's data with access for Administrators and SYSTEM only. Each folder's
   access is set on the folder itself (its contents inherit it; the script never changes a whole tree, which would
   follow junctions). A folder that already exists is refused when it is a link or junction, when it or anything in it
   is owned by someone other than Administrators, SYSTEM or you, or when anything below it is a link or junction:
   any user may create folders in `C:\ProgramData` before the script runs. Check and remove such a folder, then run
   the script again.
7. Adds the firewall rule `Alice-SSH-In` (inbound TCP 22 from `$AliceAddress`), replacing an earlier one. OpenSSH
   Server's own rule `OpenSSH-Server-In-TCP` accepts port 22 from every address; when Alice's address is set the
   script warns about it, and you can disable it if nobody else signs in over SSH.
8. Registers the event source `Alice Helper` in the Application log.
9. Prints the host key fingerprints (`ssh-keygen.exe -lf` of each `C:\ProgramData\ssh\ssh_host_*_key.pub`).

The script never changes User Account Control and never sets `LocalAccountTokenFilterPolicy`.

## Troubleshooting

### ALC-WIN-0001: the helper is not set up

Alice signed in, but what answered was not `alice-helper.exe`: sshd ran a shell instead (the `Match` block is
missing or does not name the account) or the helper is not at `C:\Program Files\Alice\alice-helper.exe`. Run the
setup script again in an elevated PowerShell, with `$AliceUser` set to the account you entered in Alice. Check that
`C:\ProgramData\ssh\sshd_config` ends with the `# BEGIN Alice` block and that sshd was restarted
(`Restart-Service sshd`). For a domain account, check that the name in the block is the account's name in lower case.

### ALC-WIN-0002: the helper is outdated

The helper on the server does not know what this Alice version asks for. Repeat steps 1 to 3 of [Steps](#steps)
with the `alice-helper.exe` of this Alice version, then choose **Test connection** on the server's page. **Update the
helpers first, then Alice**: a new helper works with the previous Alice release.

### ALC-WIN-0003: the account is not elevated

The helper runs, but its token is not an administrator's, so it cannot read the machine stores or the http.sys
bindings. UAC remote restrictions on local accounts are the usual cause: they give a local administrator's network
sign-in a filtered token. On Windows Server 2022 and 2025 an OpenSSH key sign-in of a local administrator is
elevated with the default settings, so this points to a hardened baseline or a changed UAC policy. Fixes, in this
order:

1. Use the domain setup ([Two ways to set up the account](#two-ways-to-set-up-the-account)): a domain account in the
   local Administrators group is not filtered by UAC remote restrictions.
2. Check that the account is in Administrators directly or through a group (`net localgroup` with the group's name
   for S-1-5-32-544) and that "Deny access to this computer from the network" does not hold the account or
   S-1-5-114.
3. As a last resort for a local account, turn off UAC remote restrictions:
   `Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord`.
   This gives every local administrator's network sign-in (SMB, WMI, WinRM as well) a full token, so weigh it with
   your security team; the setup script never sets it. Then choose **Test connection** again.

### Antivirus and EDR

Antivirus or endpoint protection that blocks or inspects `C:\Program Files\Alice\alice-helper.exe` can make a
discovery fail or time out. Allow the program `C:\Program Files\Alice\alice-helper.exe` and the folder
`C:\ProgramData\Alice\helper` in its exclusions. Alice is tested with Defender real-time protection off.

## Removing Alice from a Windows server

Choose **Remove server** in Alice, then on the server, in an elevated PowerShell:

1. Remove the lines from `# BEGIN Alice` to `# END Alice` from `C:\ProgramData\ssh\sshd_config`, and run
   `Restart-Service sshd`.
2. Remove Alice's key line from `C:\ProgramData\ssh\administrators_authorized_keys` (the line that ends with Alice's
   key, as shown under **Prepare a server for Alice**).
3. Remove `C:\Program Files\Alice` and `C:\ProgramData\Alice`, the firewall rule
   (`Remove-NetFirewallRule -Name Alice-SSH-In`) and the event source
   (`[System.Diagnostics.EventLog]::DeleteEventSource('Alice Helper')`).
4. Remove the account's two deny rights first: removing an account does not remove it from the User Rights
   Assignment, where its SID stays as an orphaned entry. Either open **Local Security Policy** (`secpol.msc`),
   **Local Policies**, **User Rights Assignment**, and remove the account from "Deny log on locally" and "Deny log on
   through Remote Desktop Services"; or note its SID (`(Get-LocalUser alice).SID.Value`), run
   `secedit /export /cfg C:\AliceSetup\rights.inf /areas USER_RIGHTS`, delete `*<SID>` (and its comma) from the
   lines `SeDenyInteractiveLogonRight` and `SeDenyRemoteInteractiveLogonRight` of that file, and run
   `secedit /configure /db C:\AliceSetup\rights.sdb /cfg C:\AliceSetup\rights.inf /areas USER_RIGHTS`. An entry left
   behind after the account was removed shows as a bare SID (`S-1-5-21-...`) and can be removed the same ways.
   Then remove the local account `alice` (`Remove-LocalUser alice`), or the domain account from the group policy of
   the domain setup.
5. If nothing else uses it, remove OpenSSH Server
   (`Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`) or keep it.

IIS, http.sys and the certificates stay as they are; Alice never changed them.
