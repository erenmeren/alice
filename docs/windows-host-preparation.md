# Preparing a Windows server for Alice

Alice reads the certificates of a Windows server: every HTTPS binding of http.sys (the Windows HTTP server that IIS,
WinRM, SSTP and other applications share), the IIS sites that use each binding, and the certificate bound there
from the machine store, with its expiry and store. The bindings appear under **Websites on this server** with the
column **IIS site**, grouped by the certificate they serve, and the certificates under **Certificates** like any
certificate Alice found. Alice deploys certificates to the bindings IIS uses: it imports the certificate into the
machine store and points the binding to it ([What a deployment changes](#what-a-deployment-changes)), and to the
files of IIS's Centralized Certificate Store, which it replaces in place ([Centralized Certificate
Store](#centralized-certificate-store)). It never
changes IIS's own configuration (`applicationHost.config`) and never restarts a service. It removes a certificate
only when it imported it itself and nothing has used it for 7 days ([What the cleanup removes](#what-the-cleanup-removes)).

Alice signs in over SSH (the OpenSSH Server of Windows) with its own key. It never gets a shell: sshd runs
**alice-helper.exe** for every sign-in of Alice's account, and the helper does only a fixed list of things. This
guide prepares a server once; you can undo it completely (see [Removing Alice from a Windows server](#removing-alice-from-a-windows-server)).
Alice does not manage the SSH keys of a Windows server. For a server that cannot run OpenSSH, Alice can sign in over
WinRM instead, with a password and without the helper-only limit; see [WinRM transport](#winrm-transport).

Supported systems: Windows Server 2019, 2022 and 2025, with Desktop Experience or Server Core, on x64 (AMD64) or
ARM64, with IIS 10 when the server runs IIS. Alice is tested on Windows Server 2022 and 2025 with Desktop
Experience. Windows Server 2019, Server Core and a domain-joined server under a security baseline are supported but
are checked by hand before each release, not by the automated tests; ARM64 and AD FS servers when available
(otherwise the release notes say so). A server without IIS can be added as well: its
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

1. Get the helper. The Alice package's `helper\` folder holds `alice-winhelper-windows-amd64.exe`,
   `alice-winhelper-windows-arm64.exe` and their checksum file `alice-winhelper.sha256`, which the package's signed
   `SHA256SUMS` covers (`install.sh` checks that signature before it installs or updates Alice). Take the helper
   from the package of the Alice version you run. (In a development checkout, `make winhelper` writes the same three
   files to `bin/`.)
   Copy the file for the server's processor (`amd64` for x64, `arm64` for ARM64) to the server as `alice-helper.exe`,
   in a new folder that only administrators can write, for example `C:\AliceSetup`. You can compare it yourself:
   `Get-FileHash .\alice-helper.exe -Algorithm SHA256` must print the value from `helper\alice-winhelper.sha256` (in
   upper case); the setup script checks it again.
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

### Code signing

`alice-helper.exe` is not signed with Authenticode. Its integrity rests on the package's `SHA256SUMS`, signed
offline with the release key, and on the checksum built into Alice that the setup script checks before it installs
the file. If the server runs an application control policy (Windows Defender Application Control or AppLocker), allow
`C:\Program Files\Alice\alice-helper.exe` with a hash rule (or a path rule on that folder, which only administrators
can write); a publisher rule cannot name it. Add the new hash when you update the helper.

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
the file no longer names it. Because sshd reads that file for **every** member of Administrators, not only for
Alice's account, the key line forces the helper itself:

```
restrict,command="\"C:\Program Files\Alice\alice-helper.exe\" ssh" ssh-ed25519 AAAA... alice-platform
```

sshd applies `command=` whatever account signs in with the key, and still passes Alice's request in
`SSH_ORIGINAL_COMMAND` (inside the quoted value only `\"` is an escape; the other backslashes are the path's own).
So Alice's key reaches only `alice-helper.exe`, on every administrator account: someone who stole the key and
signs in as `Administrator` gets the helper's refusal, never a shell. The `Match User` block above is a second layer
for Alice's own account. Never remove the `command=` option from the line.

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
   forwarding, no terminal) and `command=` with the helper (above), with `from="<address>"` when the script was asked
   for with Alice's address, then the key.
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

## What a deployment changes

A deployment changes only the binding it names and the machine certificate stores:

- **`LocalMachine\CA`** (Intermediate Certification Authorities): each intermediate certificate of the chain that is
  not there yet. Intermediates are never replaced or removed (other certificates may need them).
- **The binding's own store** (`LocalMachine\My`, Personal, or `LocalMachine\WebHosting`): the certificate, with its
  private key as a machine key in the Microsoft Software Key Storage Provider that cannot be exported, usable by
  SYSTEM and Administrators. Its friendly name is `Alice <name> <expiry date> <operation>`. A copy that is already in
  the store with a usable key is used as it is. Alice never moves a binding to another store.
- **The http.sys binding**: one change that points it to the new certificate and keeps every other setting
  (client-certificate negotiation, revocation checks, the TLS 1.3 and legacy TLS switches, the HTTP/2 and other
  extended settings). IIS serves the new certificate to the next connection; nothing is restarted and IIS's own
  configuration is not touched.
- **`C:\ProgramData\Alice\helper`**: the helper's journal (`journal\<operation>.json`), one record per binding
  (`bindings\`), the list of certificates it imported (`imports.json`) and its lock file (`helper.lock`). No private
  key is ever written there. The folder must stay Administrators and SYSTEM only, as the script makes it: the helper
  refuses to change anything when it is a link or junction, owned by someone else or not writable
  (`ALC-WIN-0007`).
- **The Application event log**, source `Alice Helper`: event **1001** after a deployment and **1002** after the
  previous certificate was put back, each with the operation, the binding and the old and new SHA-256 of the
  certificate (never a key).

When the check after the change fails, the helper points the binding back to the previous certificate, which stays in
its store. The previous certificate stays at least 7 days; after that the daily cleanup removes it if Alice imported
it and nothing uses it (below).

## What the cleanup removes

Once a day (helper 0.3.0 or later) Alice asks the helper which certificates it imported are no longer used, and the
helper removes them from `LocalMachine\My` or `LocalMachine\WebHosting` with their private keys. Every rule is checked
again on the server, under the helper's lock, at the moment of the removal:

- **Only what Alice imported**: the certificate is listed in `imports.json` (or in a journal of a deployment that found
  the store without it), and its friendly name is Alice's `Alice <name> <expiry date> <operation>` for that operation.
  A certificate you or another tool imported is never removed, even an identical copy of one Alice deployed.
- **Only what nothing uses**: no http.sys binding of any application (IIS, WinRM, SSTP, any other) names it, the
  Remote Desktop listener does not use it and no WinRM HTTPS listener names it, and no unfinished change of the helper
  names it. The helper reads these registry values here and never writes them in a cleanup (only a deployment to the
  Remote Desktop listener writes the first one, see [Remote Desktop](#remote-desktop)):
  - `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, value `SSLCertificateSHA1Hash`
    (absent when Remote Desktop uses its self-signed certificate);
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener\*+HTTPS`, value `certThumbprint`.

  If the bindings or one of these values cannot be read (or a value is malformed), nothing is removed that day.
- **Only after a waiting time**: unused for 7 days as the server's own clock counts them (a clock set back never
  shortens the wait), or expired; and Alice keeps it while a deployment of the server finished less than 7 days ago
  with it, a deployment is running with it or a binding it knows holds it. A certificate replaced after a
  key-compromise incident is removed at once.

The private key is deleted first (the CNG key file under `C:\ProgramData\Microsoft\Crypto\Keys`), then the
certificate; Alice also forgets it in `imports.json`. Each removal writes event **1003** to the Application log
(source `Alice Helper`): `removed store <store> sha1 <thumbprint> sha256 <hash> reason <reason>`, where the reason is
`aged`, `expired` or `incident`. Intermediate certificates in `LocalMachine\CA` are never removed.

The same run removes the helper's old files under `C:\ProgramData\Alice\helper\journal`: journals of finished
changes older than 7 days, and of failed ones older than 30 days; never one of a change still under way.

A copy of an Alice certificate that you made in another store by hand and that shares its key loses its key when
Alice removes its own copy, unless that copy is bound. To keep a certificate Alice imported, bind it, or switch
**Remove certificates Alice imported once nothing uses them** off on the server's page in Alice (off, Alice removes
nothing on that server).

## Centralized Certificate Store

When IIS reads its certificates from a Centralized Certificate Store (CCS; IIS Manager, **Centralized Certificates**),
Alice can manage the PFX files of the store as well (helper 1.1.0 or later). Each file is a location of its own in
Alice, linked to the IIS sites IIS serves from it. Prepare the store like this:

- **A local folder.** The store's **Physical path** must be a folder on the server itself, with a drive letter, for
  example `D:\CCS`. A share of another computer (`\\fileserver\certs`), a `\\?\` or `\\.\` path, or a folder that is a
  link or junction is not managed: Alice names the reason on the server's page and lists no files. The helper reads the
  folder under Alice's administrator account, so the folder's permissions must let Administrators read and write it
 . The account IIS uses to read the store needs read access only.
- **The private-key password.** Every file of the store is encrypted with the store's one private-key password (IIS
  Manager, **Edit Feature Settings** of **Centralized Certificates**). Alice manages a store whose password has 12 to
  128 printable ASCII characters and no spaces; choose such a password in IIS before you export the files with it. An
  Administrator enters the same password in Alice on the server's page (**CCS password**, with step-up). Alice never
  reads the password IIS keeps in the registry; a file the password in Alice does not open is shown as a problem and
  never written.
- **File names.** `<host>.pfx` for a host (`www.example.com.pfx`) and `_.<domain>.pfx` for a wildcard
  (`_.example.com.pfx`, which IIS uses for every name below `example.com`, also two or more labels down, but not for
  `example.com` itself). IIS compares names without regard to case and prefers the exact file. A name that gives no
  host is ignored and counted on the server's page.
- **The first file is yours.** Alice replaces existing files and never creates a new one: place the first file for a
  host in the folder yourself. Do it before the site's first request: IIS may take several minutes to serve a file for
  a host it has never served (on the test systems not within 40 seconds, even with a short polling interval). IIS
  checks the folder every `PollingInterval` seconds (registry key
  `HKLM\SOFTWARE\Microsoft\IIS\CentralCertProvider`, default 300).
- **The http.sys entry of the port.** IIS serves CCS files through an http.sys entry `ccs=<port>` (`netsh http show
  sslcert`). A binding added with `appcmd` alone did not create it on the test systems; then add it with
  `netsh http add sslcert ccs=<port> appid={4dc3e181-e14b-4a21-b022-59fc669b0914}`.

What a deployment to a CCS file changes:

- **`LocalMachine\CA`**: the intermediate certificates, as for a binding (never replaced or removed).
- **The file**, in place. The helper writes the new PFX (certificate, private key and intermediates, encrypted with
  the CCS password) as `.alice-<operation>.tmp` in the same folder, then replaces the file with it in one step
  (Windows' `ReplaceFile`, which keeps the file's permissions) and keeps the previous file as
  `<file>.alice-<8 hex>.bak` (the last 8 characters of the operation). Neither name ends in `.pfx`, so IIS never serves
  them.
- **The http.sys `ccs` entries.** IIS does not pick up a replaced CCS file by itself (on the test systems it kept
  serving the old certificate). After every write and every restore, the helper refreshes every http.sys `ccs` entry of
  the server with its own values, a same-value update that changes nothing else (the test systems compare every entry
  and its extended settings before and after); IIS then serves the new file to the next connection. If the refresh
  fails, the deployment's step says so and the check of the sites decides.
- **`C:\ProgramData\Alice\helper`**: the journal of the change, as for a binding. The password is never written there,
  nor to an event or a log.
- **The Application event log**, source `Alice Helper`: event **1004** `ccs file <name> sha256 <old> -> <new> op
  <operation>` after a write (the SHA-256 of the old and the new certificate), **1002** after the previous file was put
  back.

When the check after the change fails, the helper moves the backup back over the file. The `.bak` file holds the
previous certificate and its private key, encrypted with the CCS password and protected by the folder's permissions.
It lives at most 7 days: the daily cleanup removes the backups and temporary files of changes finished 7 days ago
(also of the latest change of a file, whose journal it keeps), so after that Alice can no longer roll that change back.
The cleanup removes a backup only when its bytes are still those of the previous file, and never touches another
file of the folder.

## Remote Desktop

Alice can manage the certificate of the server's Remote Desktop listener (`RDP-Tcp`, helper 1.2.0 or later). The
listener is one location of its own in Alice. Until a certificate is deployed to it, Remote Desktop uses a
certificate Windows made itself (the single certificate of the **Remote Desktop** store, `LocalMachine\Remote
Desktop`). Alice reads the listener's settings and never changes them, so prepare it like this:

- **Remote Desktop on.** `fDenyTSConnections` 0 under `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` (System
  Properties, **Remote**, or the Group Policy setting). With Remote Desktop off the listener is not deployable
  (`ALC-WIN-0021`).
- **A security layer with TLS.** `SecurityLayer` of `RDP-Tcp` is 1 (Negotiate) or 2 (SSL, the default of Windows
  Server 2022 and 2025). With 0 (RDP security) the listener never uses a certificate and is not deployable
  (`ALC-WIN-0022`). A value set by Group Policy (`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`)
  counts, as Windows applies it.
- **The port reachable for the check.** Alice checks the listener on its port (`PortNumber` of `RDP-Tcp`, 3389 by
  default) with the Remote Desktop negotiation and a TLS handshake. Allow that port from the Alice server, or leave it
  closed: the helper then checks the listener from the server itself (`127.0.0.1`). The check stops after the TLS
  handshake: it never signs in and sends no credentials. With Network Level Authentication on, ten such checks on
  the test systems (Windows Server 2022 and 2025, logon auditing on) left no failed logon (Security event 4625) and no
  account lockout (4740).
- **No autoenrolment of the Remote Desktop certificate.** When a Group Policy setting autoenrols it (a certificate
  template under **Remote Desktop Services**, `CertTemplateName`), Windows may replace the certificate Alice
  deployed. Alice deploys anyway, shows a warning, and names autoenrolment as the likely cause when the listener
  changes outside Alice. Turn autoenrolment off for servers whose Remote Desktop certificate Alice manages.
- **One listener.** Other listeners (custom WinStations), RD Gateway, RD Web Access, RD Connection Broker and
  RemoteApp certificates are not managed.

What a deployment to the Remote Desktop listener changes:

- **`LocalMachine\CA`**: the intermediate certificates, as for a binding (never replaced or removed).
- **`LocalMachine\My`** (Personal): the certificate, with a private key that cannot be exported, as for a binding.
  Remote Desktop certificates always go to `My`.
- **The key's access list.** Remote Desktop runs as NETWORK SERVICE, which cannot read a key Alice imported
  (SYSTEM and Administrators only). Unless NETWORK SERVICE can already read it, the helper adds one entry to that
  key's access list: allow NETWORK SERVICE (S-1-5-20) to read, with no inheritance. Nothing else of the key changes,
  and the key still cannot be exported. The helper never changes another key. A rollback takes the entry back; a
  later deployment of another certificate leaves it, so a rollback to this certificate still works, and the cleanup
  removes it with the key when Alice imported the certificate. On a certificate you imported yourself the entry
  stays until you remove it (certificates console, **Manage Private Keys**). The helper never gives NETWORK SERVICE
  access to a key that can be exported: a copy of the certificate already in `My` with an exportable key (or one
  whose export policy cannot be read) is refused before anything changes. Replace that copy, or remove it and import
  the certificate again without marking the key exportable. A key whose access list holds an entry that denies
  NETWORK SERVICE or Everyone the read right ends the deployment at the key-access step (`ALC-WIN-0023`): the
  certificate and its chain are imported, but the helper adds no access entry and leaves the listener as it was;
  remove the deny entry (**Manage Private Keys**) or deploy another certificate. A deny entry of another account, or
  one without the read right, does not refuse.
- **The registry value `SSLCertificateSHA1Hash`** of `HKLM\SYSTEM\CurrentControlSet\Control\Terminal
  Server\WinStations\RDP-Tcp`: set to the certificate's SHA-1 thumbprint. It is the only registry value the helper
  writes. Remote Desktop serves the new certificate to the next connection (on the test systems within about 20 ms),
  without a restart. When the listener already names the certificate and the deployment changes its key access or
  chain, the helper removes the value and sets it again, because only that makes Windows send the new chain: Remote
  Desktop serves its self-signed certificate for about 10 ms in between.
- **`C:\ProgramData\Alice\helper`**: the journal of the change, as for a binding. It records whether NETWORK SERVICE
  could read the key before, so an interrupted change takes back only the entry it added.
- **The Application event log**, source `Alice Helper`: event **1005** `operation <operation> rdp RDP-Tcp old
  <sha256> new <sha256> key_read_granted <true|false>` after the change, **1002** after the previous certificate was
  put back.

When the check after the change fails, the helper points the listener back to the previous certificate, or, after
the first deployment, removes the value so Remote Desktop uses its self-signed certificate again (Windows should make
a new one if it was removed; this was not measured), and takes back the NETWORK SERVICE entry it added. A certificate Remote Desktop cannot use
stops new Remote Desktop sessions, so keep another way in: the server's console or SSH. The account `alice` itself cannot sign in over Remote Desktop.

## WinRM transport

Use this only when the server cannot run OpenSSH. OpenSSH stays the recommended connection.

**Under WinRM, anyone with this account's password can run any command on the server as an administrator. With
OpenSSH, Alice's key can run only alice-helper.exe.** The password is an ordinary Windows password: it also signs in to
the server's other network services that accept the account (file sharing, remote management), not only WinRM. Use a
dedicated account, a different password on every server, and keep port 5986 open to the Alice server only.

Over WinRM Alice runs the same `alice-helper.exe`, with the same subcommands, journal and rollback as over SSH. It
connects to the server's WinRM HTTPS listener (TLS 1.2 or later, port 5986), signs in with the account's name and
password using NTLMv2, and checks the listener's certificate key against the one an administrator confirmed in Alice.
Each call is one connection and one WinRS shell, which runs `"C:\Program Files\Alice\alice-helper.exe" ssh` with
Alice's subcommand in the shell's environment variable `SSH_ORIGINAL_COMMAND`; certificates and keys travel only on
the helper's standard input. Alice never uses Basic authentication, unencrypted HTTP (port 5985), Kerberos, CredSSP
or client certificates, and sends no PowerShell.

### The account

- **A local account** (`alice`, `.\alice`, or `SERVER\alice` with the computer's name): the WinRM setup script creates
  it, or sets the password of an existing one (for example the account the OpenSSH script made), adds it to
  Administrators and sets **Password never expires**. Enter the name in Alice as you would on the server.
- **A domain account** (`DOMAIN\alice`): create it in the domain and make it a member of the server's Administrators
  group (directly or through a group, as in [the domain setup](#two-ways-to-set-up-the-account)). The script only
  checks that it exists and warns when it is not a direct member of Administrators; it never creates it, changes its
  password or adds it to a group. A domain account over WinRM is not tested automatically: check it by hand.
- **Hardened baselines.** Where "Deny access to this computer from the network" holds *Local account and member of
  Administrators group* (S-1-5-114), a local account cannot sign in over WinRM (measured on Windows Server 2022 and
  2025): use a domain account.
- A name such as `alice@corp.example` is not accepted.

On Windows Server 2022 and 2025 as shipped, `LocalAccountTokenFilterPolicy` is 1, and the WinRM sign-in of a local
administrator gets an elevated token (Security event 4624: logon type 3, package NTLM, `NTLM V2`). With the value 0 the
WinRM sign-in of a local administrator is refused (measured: remote UAC gives the network logon a filtered token), so
for a local account the script sets the value to 1 when it finds 0 or no value; it prints the value it found (`LocalAccountTokenFilterPolicy found: ...`). This lifts remote
UAC filtering for every local administrator's network sign-in, so weigh it with your security team. A domain account
needs no change.

### What the WinRM setup script changes

Get the script from Alice (**Add server** with **WinRM over HTTPS**, or **Show setup script again** on the server's
page). Run it once in an elevated PowerShell (Windows PowerShell 5.1 or PowerShell 7) in the folder that holds
`alice-helper.exe`; running it again is safe. It holds no secret. It names the account and Alice's address at the top:

```powershell
$AliceUser = 'alice'
$AliceAddress = 'Any'
```

(Alice fills in the server's account, and Alice's address when it is known; with `'Any'` the script warns that port
5986 is open to every address: set `$AliceAddress` to the Alice server's address.) In order, it:

1. Checks that it runs elevated, the account name, and that WinRM's Negotiate authentication is on (read from
   `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service`, value `auth_negotiate`). With Negotiate off it
   stops before any change: Alice signs in with NTLM through Negotiate. It never changes the setting.
2. Checks the SHA-256 checksum of `.\alice-helper.exe` as the OpenSSH script does.
3. Prepares the account. For a local account it asks for the password twice (`Read-Host -AsSecureString`: nothing is
   shown, printed, logged or written to a file) and refuses a password outside Alice's rule (12 to 128 printable ASCII
   characters, no spaces) or two entries that differ; for an existing account an empty answer keeps its password. It
   adds a local account to Administrators and denies the account "Log on locally" and "Log on through Remote Desktop
   Services", as the OpenSSH script does; these rights do not block a network sign-in such as WinRM's (measured). It
   never sets "Deny access to this computer from the network".
4. Installs the helper in `C:\Program Files\Alice`, the data folder `C:\ProgramData\Alice\helper` and the event source
   `Alice Helper`, exactly as the OpenSSH script does (both scripts may run on one server, in either order).
5. For a local account, sets `LocalAccountTokenFilterPolicy` to 1 when it finds 0 or no value (above).
6. Sets the WinRM service to start automatically and starts it. If the server has no WinRM HTTPS listener, it creates a
   self-signed certificate for the computer's names (key not exportable, valid 10 years, friendly name
   `Alice WinRM listener`) and a listener on port 5986 of every address:

   ```powershell
   New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{ Address = '*'; Transport = 'HTTPS' } -ValueSet @{ Hostname = $names[0]; CertificateThumbprint = $listenerCert.Thumbprint } | Out-Null
   ```

   An existing HTTPS listener and its certificate are kept.
7. Adds the firewall rule `Alice-WinRM-In`, replacing an earlier one:

   ```powershell
   New-NetFirewallRule -Name 'Alice-WinRM-In' -DisplayName 'Alice WinRM (TCP 5986)' -Description 'Alice runs alice-helper.exe over WinRM (HTTPS).' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress $AliceAddress -Action Allow -Profile Any | Out-Null
   ```

8. Prints each HTTPS listener as `Listener <address> port <port>: SPKI SHA256:... (SHA-1 thumbprint ...)`, and the
   settings it never changes: Basic, Kerberos, Negotiate, Certificate, CredSSP, `CbtHardeningLevel`,
   `AllowUnencrypted` and the number of HTTP listeners. It warns when Basic or `AllowUnencrypted` is on or an HTTP
   (port 5985) listener exists (Alice never uses them; Windows Server 2022 and 2025 ship Basic on and a 5985 listener),
   and when `CbtHardeningLevel` is `Strict`.

It never installs or changes OpenSSH, never changes Basic, Negotiate, Kerberos, CredSSP, `CbtHardeningLevel`,
`AllowUnencrypted` or the 5985 listener, maps no client certificate and never runs `Enable-PSRemoting`.

Then enter the same password in Alice (**WinRM password** on the server's page; an Administrator with a fresh
authenticator code). Alice tests the connection as soon as it is saved.

### The settings Alice needs

Alice needs, and never changes:

- **Negotiate on** (`Service\Auth\Negotiate`, on by default).
- **`CbtHardeningLevel` not `Strict`** (`Relaxed`, the default, works). Alice sends no channel binding, so `Strict`
  refuses its sign-in (measured); supporting it needs a later Alice version.
- **NTLM not restricted**: `LmCompatibilityLevel` 5 (NTLMv2 only) works; a policy that denies NTLM to the server
  (Network security: Restrict NTLM) refuses Alice.
- **The account in Administrators** and not in "Deny access to this computer from the network".

A refused sign-in is `ALC-WIN-0024` ([troubleshooting.md](troubleshooting.md)).

### The password

- Alice keeps it sealed, uses it only during each call to the server and never shows it again. It never leaves the
  Alice server: NTLMv2 sends a proof, not the password.
- The account's password never expires (the script sets that for a local account). When you change it on the server
  (run the script again, or `net user`), set the same password in Alice: until then every call is refused
  (`ALC-WIN-0024`), and the password Alice still holds no longer works (measured).
- Use a different password on every server, so one password opens one server.

### Checking the listener's fingerprint

At the first connection Alice shows the fingerprint of the listener's certificate key as **TLS certificate key (SPKI
SHA-256)**. Compare it with the line the setup script printed for port 5986 (`SPKI SHA256:...`); run the script again
to print it again. The fingerprint is the SHA-256 of the certificate's public key (its SubjectPublicKeyInfo), so it
differs from the certificate's thumbprint, which `Get-ChildItem WSMan:\localhost\Listener` shows. A certificate renewed
with the same key, a WinRM service restart and an expired listener certificate change nothing (Alice checks the key
only). A certificate with a new key blocks the server in Alice until an administrator compares and accepts the new
fingerprint. Alice never deploys to the WinRM listener's own binding (`0.0.0.0:5986`, listed as another
application's), so it never replaces the key it pinned.

### What Windows logs

- No PowerShell runs for Alice, so PowerShell script block logging (event 4104) and transcription record nothing.
- WinRS starts the helper through `cmd.exe` (measured: also when Alice asks it not to), so process creation auditing
  with command lines (Security event 4688) records `cmd.exe /C "C:\Program Files\Alice\alice-helper.exe" ssh` and the
  helper's own line, never Alice's subcommand. `cmd.exe` reads only that fixed line; the subcommand is in the
  environment variable `SSH_ORIGINAL_COMMAND`, which `cmd.exe` never parses, and key material is only on the helper's
  standard input.
- Security event 4624 records one network sign-in per call (logon type 3, package NTLM, `NTLM V2`); a refused one is
  4625 with the account name. A domain account's sign-in is also checked by a domain controller (4776 there).
- `Microsoft-Windows-WinRM/Operational` records each shell and its user, never what it carries.
- The helper's Application events (source `Alice Helper`) are the same as over SSH.

### Revoking Alice's access

Disable the account or change its password on the server: Alice's next call is refused. To remove the WinRM setup,
remove the firewall rule (`Remove-NetFirewallRule -Name Alice-WinRM-In`), and, if nothing else uses them, the listener
the script created (its certificate's friendly name is `Alice WinRM listener`) and the `LocalAccountTokenFilterPolicy`
value it set (the script printed the value it found). Then follow [Removing Alice from a Windows server](#removing-alice-from-a-windows-server)
for the helper, its folders, the event source and the account.

## Troubleshooting

### ALC-WIN-0001: the helper is not set up

Alice signed in, but what answered was not `alice-helper.exe`: the helper is not at
`C:\Program Files\Alice\alice-helper.exe`, or sshd ran a shell instead (Alice's line in
`administrators_authorized_keys` lost its `command=` option and the `Match` block is missing or does not name the
account). Run the
setup script again in an elevated PowerShell, with `$AliceUser` set to the account you entered in Alice. Check that
`C:\ProgramData\ssh\sshd_config` ends with the `# BEGIN Alice` block and that sshd was restarted
(`Restart-Service sshd`). For a domain account, check that the name in the block is the account's name in lower case.

### ALC-WIN-0002: the helper is outdated

The helper on the server does not know what this Alice version asks for (a helper older than 0.3.0 still deploys,
but Alice cleans up nothing on it). Repeat steps 1 to 3 of [Steps](#steps)
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
discovery or a deployment fail or time out (an interrupted deployment is finished or undone by Alice later). Allow
the program `C:\Program Files\Alice\alice-helper.exe` and the folder `C:\ProgramData\Alice\helper` in its
exclusions. Alice's automated tests run with Defender real-time protection off; a setup, a deployment and a cleanup
with it on are checked by hand before each release. The first connection to a server prepared a
moment ago can take longer than later ones (Windows may still be creating the new account's profile at its first sign-in): if the
first **Test connection** times out, choose it again.

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

IIS, http.sys and the certificates stay as they are: the bindings keep serving the certificates Alice deployed. To
remove a certificate Alice imported, find it by its friendly name (`Alice ...`) in the certificate store and delete
it with its key (`Remove-Item -DeleteKey`) once no binding uses it.
