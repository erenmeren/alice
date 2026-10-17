# Preparing an Apache server for Alice

Alice reads the certificates of an Apache server: it finds every certificate file that Apache's configuration uses
for HTTPS, shows each website with its certificate, expiry and file, and lists the certificates under
**Certificates** like any certificate it found. **On an Apache server Alice only reads.** It never deploys a
certificate, never changes a file of Apache or of its configuration, never reloads or restarts Apache and never
publishes HTTP-01 challenges. The deploy controls on an Apache server's page are shown disabled with the note "Not
available for Apache servers yet".

Alice also manages the SSH keys of an Apache server, exactly as on a Linux server.

Supported systems: as in [nginx-host-preparation.md](nginx-host-preparation.md) (Ubuntu 20.04 or later, Debian 11
or later, RHEL, Rocky Linux or AlmaLinux 8 or later, on x86_64 or aarch64, with the OpenSSH server, `sudo` and
`sha256sum`). Apache must come from the distribution's packages: `apache2` on Debian and Ubuntu (control program
`/usr/sbin/apache2ctl`), `httpd` on the Red Hat family (program `/usr/sbin/httpd`), with `mod_ssl` for HTTPS
(`a2enmod ssl` on Debian and Ubuntu, the `mod_ssl` package on the Red Hat family). Alice is tested with Apache 2.4.52
(Ubuntu 22.04), 2.4.62 (Rocky Linux 9) and 2.4.68 (Debian 12). Apache in a container and builds installed under
other paths are not supported. Apache does not have to be running: Alice reads its configuration, not the running
server.

## Steps

The preparation is the one of every server, with **Server type** **Apache server**:

1. Get the helper (`make helper` in a development checkout, or the `helper/` directory of a release package) and
   copy the file for the server's processor to the server as `alice-helper`, in a new directory that only you can
   write (step 1 of "Steps" in [nginx-host-preparation.md](nginx-host-preparation.md#steps)).
2. In Alice, sign in as an administrator, open **Servers**, and under **Prepare a server for Alice** choose
   **Server type** **Apache server** and **Copy commands**.
3. On the server, save the commands as a file next to `alice-helper` and run it as root:
   `sudo sh ./prepare-alice.sh`. Expected last line: "This server is ready for Alice."
4. In Alice choose **Add server** with **Server type** **Apache server**, compare the fingerprint on the server and
   choose **Yes, this is my server** (steps 4 and 5 of the same section).
5. Alice tests the connection and then reads the SSH keys and Apache's configuration together. Its websites appear
   under **Websites on this server**. Choose **Discover** there to read the server again at any time; Alice also does
   it on its own once per discovery interval.

The setup commands are the same script as for a Linux or Nginx server: they check and install
`/usr/local/libexec/alice-helper`, create the account `alice-svc` with Alice's key, create `/var/lib/alice-helper`
and install `/etc/sudoers.d/alice`. What each step does is described in "What the setup commands do" in
[nginx-host-preparation.md](nginx-host-preparation.md#what-the-setup-commands-do). Only the sudoers file differs.

## The Apache profile

The `apache` profile adds these lines to `/etc/sudoers.d/alice` (exactly as the setup commands write them):

```
Cmnd_Alias ALICE_APACHE_ONLY = \
    /usr/local/libexec/alice-helper apache-dump

alice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_APACHE_ONLY
```

`ALICE_COMMON` is the SSH-key part that every profile has. `apache-dump` takes no arguments: sudo refuses any further
word, and the helper refuses any argument itself. The profile allows nothing that changes a file: none of the
`nginx-*` deployment commands and no HTTP-01 challenge commands.

| Line | What it allows |
|---|---|
| `apache-dump` | Runs Apache's control program four times (below), reads the configuration files Apache loads, and answers a summary: the Apache version, the main configuration file and the names of the configuration files, each HTTPS website's names and ports, each `SSLCertificateFile`/`SSLCertificateKeyFile` pair, and for each certificate file its owner, group, mode, size, SHA-256 and the certificates in it; for each key file only its owner, group, mode and size. It never sends the configuration text, Apache's own messages or anything from a key file. |

`/etc/sudoers.d/alice` holds one profile. A server has either the Linux, the Nginx or the Apache lines: running the
Apache commands on a server prepared as an Nginx server replaces its Nginx lines, and the other way round.

### Changing a server into an Apache server

The server type cannot be changed in Alice. Run the setup commands again with **Server type** **Apache server**,
then remove the server in Alice (**Remove server**) and add it again as an **Apache server**. Its SSH keys are read
again by the first scan. If you add the server as an Apache server but keep the Linux commands on it, Alice still
reads its SSH keys and shows "The Apache permissions are not installed on this server" (`ALC-APC-0003`).

## The helper version

Reading Apache needs `alice-helper` 1.7.0 (protocol 8), the helper of this release. It adds `apache-dump`; nothing
changes for Linux and Nginx servers, which keep working with `alice-helper` 1.6.x. A server added as an Apache
server whose helper is older keeps working for its SSH keys: **Test connection** succeeds with the warning "The
alice-helper on this server is too old to read Apache. Update the helper; SSH keys are still read.", and **Discover**
reads the SSH keys but no websites (`ALC-APC-0004`).

### Updating the helper

Repeat steps 1 to 3 of "Steps" with the `alice-helper` of the new release and the commands from the **Servers**
page (**Server type** **Apache server**), then choose **Test connection** and **Discover** on the server's page. The
commands install the new helper and the new sudoers file together. **Update the helpers first, then Alice**: a new
helper works with the previous Alice release ("Updating the helper" in
[nginx-host-preparation.md](nginx-host-preparation.md#updating-the-helper)).

## What Alice reads on an Apache server

### The control program

The helper runs Apache's own control program, never a program Alice chooses:

- On Debian and Ubuntu `/usr/sbin/apache2ctl`. It reads `/etc/apache2/envvars` (the `APACHE_*` variables: run user,
  run and lock directories, log directory) and passes the arguments to `apache2`. Like before every start, it may
  create Apache's runtime and lock directories (for example `/run/apache2` and `/run/lock/apache2`) when they do not
  exist yet. That is the only thing on the server that a discovery can create; Alice itself writes nothing.
- On the Red Hat family `/usr/sbin/httpd` directly. `apachectl` is not used: the Red Hat family's `apachectl` refuses
  any argument ("Passing arguments to httpd using apachectl is no longer supported").
- When neither exists, Alice reports that Apache was not found (`ALC-APC-0001`).

The program runs as root with a fixed environment (`PATH`, `LANG=C`), in `/`, for at most 30 seconds per run. Keep
the control program, `/etc/apache2/envvars` and the Apache binary owned by root and writable only by root: whoever
can change them can run commands as root at the next discovery, as at the next start of Apache.

### The four runs

| Run | What Alice uses from it |
|---|---|
| `-V` | The Apache version and the main configuration file (`SERVER_CONFIG_FILE`, joined to `HTTPD_ROOT` when relative). Without a `Server version: Apache/…` line Alice reports Apache as not found. |
| `-D DUMP_INCLUDES -t` | The tree of configuration files Apache loads (`Include`, `IncludeOptional`), with the line of each `Include`. When this run fails, the configuration is invalid and nothing else is used (`ALC-APC-0002`). |
| `-D DUMP_MODULES -t` | The compiled-in modules; `LoadModule` lines are followed in read order, for `<IfModule>`. |
| `-D DUMP_RUN_CFG -t` | `ServerRoot` (for relative certificate paths) and the defines that are set (for `<IfDefine>`). |

The helper never uses what Apache prints on standard error (for example the `AH00558` notice about the server's
name). A run that fails after the first one also means the configuration is invalid: it changed between the runs.

Each run may take at most 30 seconds, and all four, with the reading of the files, share one budget of 50 seconds
for the whole `apache-dump` call; Alice waits 60 seconds for the answer. A run still going when the budget ends is
stopped and the discovery fails with the helper's own error, not with a connection timeout. Apache resolves the
host names of `<VirtualHost>` lines while it parses the configuration, in each of the three `-t` runs, so a slow DNS
resolver on the server is the usual cause.

### The configuration files

The helper then reads every file of the include tree itself, through the same root-controlled walk as for Nginx:
every directory and symbolic link on the way must belong to root, no directory may be writable by its group or by
others, and no file may be on a pseudo or FUSE file system. A file that cannot be read this way, a tree that does not
start with the main configuration file, or a file that no longer matches the tree makes Alice refuse the whole
server ("Alice cannot read this configuration safely"), with the reason and, where it can, the file. Limits: at most
4096 files, 20 MiB in total, 100 levels of nested sections and includes, and 65,536 certificate/key pairs.

From these files Alice reads the `<VirtualHost>` sections with `SSLEngine on` and their `ServerName`, `ServerAlias`,
`SSLCertificateFile` and `SSLCertificateKeyFile`, following Apache's rules for `<IfModule>`, `<IfDefine>`,
`<IfVersion>`, `Define`, `UnDefine` and `${VAR}`:

- A website is a `<VirtualHost>` with `SSLEngine on` (`optional` is not on) and at least one certificate. Its row
  shows its names (`ServerName` without scheme and port, then the `ServerAlias` names), its HTTPS ports and the file
  and line of its `<VirtualHost>`. Like Apache, Alice counts the first website of each address and port (and a
  `_default_` one) as that address's default.
- Each `SSLCertificateFile` is paired with the `SSLCertificateKeyFile` in the same position. A certificate without a
  key line has its key in the certificate file itself; Alice supports that.
- A website that sets no certificate of its own uses the main server's certificates. Like mod_ssl, Alice merges the
  lists position by position: a website with one certificate line also inherits the main server's second and later
  certificate lines.
- The main server (outside every `<VirtualHost>`) is listed only when it sets `SSLEngine on` and a certificate itself.
- A relative certificate path is read from `ServerRoot`.

### Certificates and keys

For each certificate file Alice reads its owner, group, mode, size, SHA-256 and the certificates in it. Of a key file
it reads only the owner, group, mode and size (with `stat`); it never opens a private key and never sends one.
Alice shows the same notes as on an Nginx server: **Custom location** (the file is outside `/etc/ssl`,
`/etc/apache2`, `/etc/httpd`, `/etc/pki` and `/etc/letsencrypt`), "This file is a link", and the notes about a key
file that more users can read than needed.

### A certificate file that does not exist

Whether Apache's checks report a missing certificate file depends on the Apache version:

- Apache 2.4.52 (Ubuntu 22.04) refuses the configuration in the runs above. Alice then shows that the configuration
  has an error (`ALC-APC-0002`) and no websites.
- Apache 2.4.62 and later (Rocky Linux 9 with 2.4.62, Debian 12 with 2.4.68) does not check the file in these runs.
  Alice shows the configuration as valid and the website with "The file does not exist." Apache itself would still
  refuse to start with this configuration (`apache2ctl -t` or `httpd -t` says so).

Either way, put the file back or fix the path, then choose **Discover**. On a new Rocky Linux or RHEL server whose
Apache has never started, the `localhost.crt` of the stock `ssl.conf` does not exist yet: Alice lists it with that
note, which is expected.

## What Alice never changes

Alice changes nothing of Apache: no configuration file, no certificate or key file, no owner or mode, no service.
`apache-dump` writes, renames and changes the mode of nothing; the only change a discovery can cause is the one
Apache's control program makes on its own (the runtime and lock directories above). Alice never starts, reloads or
restarts Apache. Only the SSH-key work of the `linux` part (removing a key, a rotation) changes files, exactly as on
a Linux server.

## Configurations Alice cannot read

Alice lists these websites as **Not supported** with the reason, or shows the problem above the list:

- A certificate or key line inside `<If>`, `<ElseIf>`, `<Else>`, `<IfFile>`, `<IfDirective>`, `<IfSection>`, an
  `<IfVersion>` with a regular expression or an `<IfModule>` with a name Alice cannot map: "This file, or the name of
  its website, is set inside a conditional section of the configuration" (`conditional`). Alice cannot tell when it
  is used. The same holds for a `ServerName` or `ServerAlias` line in such a section: the website's names may not be
  the ones Apache uses, so its certificates are `conditional` too.
- `Use` and `<Macro>` (mod_macro) are not expanded: certificates set through a macro are not seen.
- Environment variables are not expanded: a path, name or address with `${APACHE_…}` from `envvars` or another
  variable that no `Define` sets is not supported ("The path uses a variable", `variable`).
- Defines given only on the service's command line (for example `-DFOREGROUND` or `$OPTIONS` of the service unit)
  are not known: Alice sees only the defines of the configuration and those Apache reports in `DUMP_RUN_CFG`, so an
  `<IfDefine>` on such a define may be evaluated differently from the running Apache.
- `SSLCertificateChainFile` is not read. The chain Alice shows is the one in the certificate file.
- A certificate path with a `.` or `..` component, a space or another character the helper does not accept
  (`path_not_allowed`).
- **Any** configuration file that a user other than root owns or that its group or others can write makes **every**
  website of the server **Not supported** ("A configuration file can be changed by users other than root"), and the
  page names the file. A `Define` or `Include` in one file reaches the whole configuration, so Alice cannot limit
  this to one website. Make the file root-owned and not group or other writable, then **Discover**. The names of the
  websites are still listed.
- The whole server, when a configuration directory is not root-controlled, a configuration file name contains a
  space, the configuration is larger than the limits above, contains a NUL byte, or changed while Alice read it.
- No deployment: Alice never deploys to an Apache server in this release. Renew the certificates with your own tools;
  Alice shows the new certificate after the next discovery.

## Removing Alice from an Apache server

As in "Removing Alice from a server" in
[nginx-host-preparation.md](nginx-host-preparation.md#removing-alice-from-a-server): choose **Remove server** in
Alice, then remove `/etc/sudoers.d/alice`, the helper, the account and its directories on the server. Apache and its
files stay as they are; Alice never changed them.
