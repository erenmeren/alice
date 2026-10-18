# Preparing a HAProxy server for Alice

Alice reads the certificates of a HAProxy server: it finds every certificate file that HAProxy's configuration
loads for a TLS `bind`, shows each frontend (or `listen` section) with its certificate, expiry and file, and lists
the certificates under **Certificates** like any certificate it found. **On a HAProxy server Alice only reads.** It
never deploys a certificate, never changes a file of HAProxy or of its configuration, never reloads or restarts
HAProxy and never publishes HTTP-01 challenges. The deploy controls on a HAProxy server's page are shown disabled
with the note "Not available for HAProxy servers yet".

Alice also manages the SSH keys of a HAProxy server, exactly as on a Linux server.

Supported systems: as in [nginx-host-preparation.md](nginx-host-preparation.md) (Ubuntu 20.04 or later, Debian 11
or later, RHEL, Rocky Linux or AlmaLinux 8 or later, on x86_64 or aarch64, with the OpenSSH server, `sudo` and
`sha256sum`). HAProxy must come from the distribution's packages (`haproxy`, program `/usr/sbin/haproxy`, main
configuration file `/etc/haproxy/haproxy.cfg`). Alice is tested with HAProxy 2.4 (Ubuntu 22.04), 2.6 (Debian 12)
and 2.8 (Rocky Linux 9). Other versions are read with the same rules but are not tested. HAProxy 3.0 and later add
ways to name a certificate's key that Alice does not follow (a `crt-store` section, and file keywords in a `crt-list`
line's options); Alice shows those places as conditional instead of guessing (see
[Configurations Alice cannot read](#configurations-alice-cannot-read)). A build installed under another path and
HAProxy in a container are not supported. HAProxy does not have to be running: Alice reads its
configuration, not the running server.

## Steps

The preparation is the one of every server, with **Server type** **HAProxy server**:

1. Get the helper (`make helper` in a development checkout, or the `helper/` directory of a release package) and
   copy the file for the server's processor to the server as `alice-helper`, in a new directory that only you can
   write (step 1 of "Steps" in [nginx-host-preparation.md](nginx-host-preparation.md#steps)).
2. In Alice, sign in as an administrator, open **Servers**, and under **Prepare a server for Alice** choose
   **Server type** **HAProxy server** and **Copy commands**.
3. On the server, save the commands as a file next to `alice-helper` and run it as root:
   `sudo sh ./prepare-alice.sh`. Expected last line: "This server is ready for Alice."
4. In Alice choose **Add server** with **Server type** **HAProxy server**, compare the fingerprint on the server and
   choose **Yes, this is my server** (steps 4 and 5 of the same section).
5. Alice tests the connection and then reads the SSH keys and HAProxy's configuration together. The frontends appear
   under **Websites on this server**; the first column is called **Frontend**. Choose **Discover** there to read the
   server again at any time; Alice also does it on its own once per discovery interval.

The setup commands are the same script as for a Linux, Nginx or Apache server: they check and install
`/usr/local/libexec/alice-helper`, create the account `alice-svc` with Alice's key, create `/var/lib/alice-helper`
and install `/etc/sudoers.d/alice`. What each step does is described in "What the setup commands do" in
[nginx-host-preparation.md](nginx-host-preparation.md#what-the-setup-commands-do). Only the sudoers file differs.

## The HAProxy profile

The `haproxy` profile adds these lines to `/etc/sudoers.d/alice` (exactly as the setup commands write them):

```
Cmnd_Alias ALICE_HAPROXY_ONLY = \
    /usr/local/libexec/alice-helper haproxy-dump

alice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_HAPROXY_ONLY
```

`ALICE_COMMON` is the SSH-key part that every profile has. `haproxy-dump` takes no arguments: sudo refuses any
further word, and the helper refuses any argument itself. The profile allows nothing that changes a file: none of the
`nginx-*` deployment commands and no HTTP-01 challenge commands.

| Line | What it allows |
|---|---|
| `haproxy-dump` | Runs HAProxy's program twice (below), reads `/etc/haproxy/haproxy.cfg` and the certificate lists and folders it names, and answers a summary: the HAProxy version, the main configuration file, each TLS `bind`'s frontend, addresses, ports and (for a certificate list) server names, each certificate file with its key file, and for each certificate file its owner, group, mode, size, SHA-256 and the certificates in it; for each key file only its owner, group, mode and size. It never sends the configuration text, HAProxy's own messages or anything from a key file. |

`/etc/sudoers.d/alice` holds one profile. A server has either the Linux, the Nginx, the Apache or the HAProxy lines:
running the HAProxy commands on a server prepared as another type replaces its lines, and the other way round.

### Changing a server into a HAProxy server

The server type cannot be changed in Alice. Run the setup commands again with **Server type** **HAProxy server**,
then remove the server in Alice (**Remove server**) and add it again as a **HAProxy server**. Its SSH keys are read
again by the first scan. If you add the server as a HAProxy server but keep the Linux commands on it, Alice still
reads its SSH keys and shows "The HAProxy permissions are not installed on this server" (`ALC-HAP-0003`).

## The helper version

Reading HAProxy needs `alice-helper` 1.8.0 (protocol 9), the helper of this release. It adds `haproxy-dump`; nothing
changes for Linux, Nginx and Apache servers, which keep working with `alice-helper` 1.6.x and 1.7.x. A server added
as a HAProxy server whose helper is older keeps working for its SSH keys: **Test connection** succeeds with the
warning "The alice-helper on this server is too old to read HAProxy. Update the helper; SSH keys are still read.",
and **Discover** reads the SSH keys but no frontends (`ALC-HAP-0004`).

### Updating the helper

Repeat steps 1 to 3 of "Steps" with the `alice-helper` of the new release and the commands from the **Servers**
page (**Server type** **HAProxy server**), then choose **Test connection** and **Discover** on the server's page.
The commands install the new helper and the new sudoers file together. **Update the helpers first, then Alice**: a
new helper works with the previous Alice release ("Updating the helper" in
[nginx-host-preparation.md](nginx-host-preparation.md#updating-the-helper)).


## What Alice reads on a HAProxy server

### The program

The helper runs HAProxy's own program, `/usr/sbin/haproxy`, never a program Alice chooses, and only after checking
that the program and every directory above it belong to root and that nobody but root can write them (the same
check as for Nginx and Apache; a program that fails it is not run and the page says the configuration cannot be
trusted, naming the file). It runs as root with a fixed environment (`PATH`, `LANG=C`), in `/`, for at most 30
seconds per run, and never uses what HAProxy prints on standard error. Keep `/usr/sbin/haproxy` owned by root and
writable only by root.

The environment of the service is not reproduced. The helper does not read `/etc/default/haproxy`,
`/etc/sysconfig/haproxy` or the systemd unit, so variables and options that the unit sets are not known to the check.

### The two runs

| Run | What Alice uses from it |
|---|---|
| `-v` | The first line, `HAProxy version <version> …`. Without it Alice reports that HAProxy was not found (`ALC-HAP-0001`). |
| `-c -f /etc/haproxy/haproxy.cfg` | Only whether HAProxy accepts the configuration: exit status 0, or 2 ("no listener"; HAProxy only warns). When it does not, the configuration is invalid and nothing else is read (`ALC-HAP-0002`). |

Alice reads `haproxy.cfg` (and checks its owner and mode) after `-v` and before `-c`. When `haproxy.cfg` cannot be
read safely, that is reported and `-c` is not run. When a user other than root can change it, `-c` is not run either:
the check would load, as root, every file that user names and run its `lua-load`, so the page shows the places of
the file as written, each **Not supported** because the configuration can be changed (see
[Configurations Alice cannot read](#configurations-alice-cannot-read)).

Both runs and the reading of the files together share one budget of 50 seconds for the whole `haproxy-dump` call;
Alice waits 60 seconds for the answer. A run still going when the budget ends is stopped and the discovery fails with
the helper's own error, not with a connection timeout.

### A configuration error

`haproxy -c` does more than parse the file: it loads every certificate and key a TLS `bind` names and it resolves
the host names of `server` lines. So a missing certificate file, a missing key file or a server name that does not
resolve **on this server, now** is read as a configuration error, with class `syntax` (`ALC-HAP-0002`), although
HAProxy may be running with the configuration it loaded earlier. Two consequences:

- Whether the check passes depends on DNS (and `/etc/hosts`) at the moment of the discovery. A slow resolver can make
  the run exceed its 30 seconds. Fix the name resolution, or make the `server` addresses IP addresses.
- The check runs without the environment of the service. A configuration that uses `${VAR}` or `setenv` values that
  only the unit provides, or `-f` paths the unit adds, can pass under the service and fail here, or the other way
  round. Run exactly `/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg` as root, with an empty environment
  (`env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C /usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg`), and fix what it reports.

`-c` also runs what the configuration chooses to load: a `lua-load` line, for example, runs its script as root while
the configuration is checked, as `LoadModule` does for Apache. Keep `/etc/haproxy` and what it names owned by root and
writable only by root.

On Rocky Linux, RHEL and AlmaLinux the unit starts HAProxy with `-f /etc/haproxy/conf.d` as well, and `haproxy -c`
on the main file alone may print a warning about it. The warning is harmless: Alice looks only at the exit status
(next section for what that means for `conf.d`).

### The configuration files

The helper reads `/etc/haproxy/haproxy.cfg` itself, and then the files and folders it names, through the same
root-controlled walk as for Nginx: every directory and symbolic link on the way must belong to root, no directory may
be writable by its group or by others, and no file may be on a pseudo or FUSE file system. A file that cannot be read
this way makes Alice refuse the whole server ("Alice cannot read this configuration safely"), with the reason and,
where it can, the file. A certificate list that does not exist or is not a regular file, and that the configuration
names only in a part Alice cannot evaluate, does not do that: the places that depend on it are listed as conditional
and the page warns that a certificate list or folder could not be read (`config_file_not_read`).

Limits: 20 MiB per file and 20 MiB of bytes in all (`haproxy.cfg`, each certificate list once, and the names in the
folders it lists), 1 MiB per line, one budget of about one million words (1,048,576) shared by `haproxy.cfg` and all
certificate lists together, 100 levels of `.if` blocks, 256 certificate lists, 256 folders with at most 4096 entries
each, 65,536 certificate/key pairs and 65,536 listen addresses. Going over one is a refusal with the reason `too_large`
or `too_complex`, or, for the listen addresses, a cut list with the warning `list_truncated`. Two limits apply to the
result: the parser refuses a configuration whose servers would take more than 32 MiB on the wire (`too_complex`), and
the helper's answer is capped at 16 MiB (`output_too_large`). Either way the answer is refused, never silently
truncated.

The lexer follows HAProxy's own reader: blanks separate words, `#` outside quotes starts a comment, double and single
quotes group words, a backslash escapes a fixed set of characters and an unknown escape is kept as written (as
HAProxy does), there is no line continuation, and a carriage return in the middle of a line ends the line.
`crt-list` lines have their own, simpler syntax: no quotes and no escapes, and a line that starts with `#` or with a
carriage return is skipped. The option block in `[` and `]` is not interpreted, only looked at: on HAProxy 2.x it
holds TLS settings (`alpn`, `ssl-min-ver`, `verify`, ...) that do not change which files are loaded, but from HAProxy
3.0 on it may also name files of the line's own with `crt`, `key`, `ocsp`, `issuer` or `sctl`. A line whose block holds
one of these words (anywhere in the block), or a quote, a backslash or a `$` (which Alice does not interpret), is
shown as conditional, whatever the version.

From these files Alice reads the `frontend` and `listen` sections (and, for settings that reach them, `global` and
`defaults`), following HAProxy's rules:

- A `bind` with the keyword `ssl` and at least one `crt` or `crt-list` argument is a place. Its row shows the frontend (or `listen`) name, the addresses and ports
  of the bind, and the certificate file and line of the `bind`. A `bind` without `ssl` is not listed.
- Each `crt` argument is one certificate file, or, when it names a folder, one per certificate in it (in byte order;
  files ending in `.key`, `.ocsp`, `.issuer` or `.sctl` are not certificates, and dotfiles are skipped from HAProxy
  2.6 on and loaded below it). A symbolic link in the folder is listed unless it certainly leads to nothing HAProxy
  loads (a missing file, or a folder or special file reached through root-controlled folders). A link whose target
  lies below a folder not controlled by root is listed with that problem (`not_root_controlled`), as the same file
  named by `crt` would be, rather than left out. At most 4096 links are followed in all the folders of one discovery
  together; past that the server is refused as `too_complex`. A folder that is itself not root-controlled (another
  owner, or writable by its group or others) is not listed: it is one place whose problem is `not_root_controlled`.
- Each `crt-list` argument is a file of lines `<path> [options] [server names]`: every line is one place with its own
  **server names** (SNI filters, without the negative `!` ones), so a frontend with a certificate list appears once
  for each line. A line without server names shows only the frontend.
- A relative `crt` path is joined to `crt-base` of the `global` section. HAProxy 2.4 and 2.6 refuse a
  second `crt-base`; what 2.8 does is not verified. Alice uses the `crt-base` in effect in read order (a later one
  replaces an earlier one), so a relative path read before any `crt-base`, or without one, is not usable
  (`path_not_allowed`).
- A `disabled` or `enabled` line in a frontend or `listen` section (or in `defaults`) is followed. The `defaults`
  setting is sticky, as in HAProxy: once a `defaults` section has such a line, a later section that sets neither
  itself is shown as conditional.
- `.if`, `.elif`, `.else` and `.endif` are evaluated when the condition is empty (false) or one plain integer, which may be negative (0 is false, any other number true);
  any other condition is not evaluated and the lines it holds are conditional.

### Certificates and keys

HAProxy takes the private key from the certificate file first, and looks for a companion file (`<certificate>.key`,
or with `ssl-load-extra-del-ext` the name without `.crt` plus `.key`) only when the certificate file holds none. For
each certificate file Alice reads its owner, group, mode, size, SHA-256 and the certificates in it. Of a key file it
reads only the owner, group, mode and size (with `stat`); it never opens a private key and never sends one. The one
exception is deciding which file holds the key: a certificate file is read once more, in the helper only, to see
whether it contains a `PRIVATE KEY` header line; only the yes or no leaves the helper.

Alice shows the same notes as on an Nginx server: **Custom location** (the file is outside `/etc/ssl`,
`/etc/haproxy`, `/etc/pki` and `/etc/letsencrypt`), "This file is a link", and the notes
about a key file that more users can read than needed.

A certificate or key file name must end in `.pem`, `.crt`, `.cer`, `.cert`, `.key`, `.chained` or `.fullchain`, like
everywhere in Alice: the helper refuses to read other names so that a link cannot lead it to a file such as
`/etc/shadow`. HAProxy itself loads files such as `w.pem.rsa` (the RSA file of a certificate set) or names without an
extension in a `crt` folder, so such a certificate is listed with the problem `bad_name` and is not described. This
is on purpose and Alice cannot work around it: the name is checked after links are followed, so a link does not help
either. Use usual names where Alice should show the certificate.

The key settings `ssl-load-extra-files` and `ssl-load-extra-del-ext` decide where the companion key is looked for.
Alice uses them only when they are stable: in the `global` section, outside any `.if` block and before the first line
that can load a certificate (a `bind`, or any line with a `crt` or `crt-list` word), as configurations set them.
Otherwise only a key inside the certificate file is known, and a certificate without one is shown as conditional.
Alice opens at most 1000 certificate files to decide where their keys are (the same limit as the files it describes);
a place whose certificate is past that limit is shown as conditional, never with a guessed key file.

**Certificate sets (`foo.pem.rsa`, `foo.pem.ecdsa`).** With `ssl-load-extra-files` at its default (`all`, which
includes `bundle`), HAProxy 2.3 and later load `foo.pem.rsa`, `foo.pem.ecdsa` and `foo.pem.dsa` when `crt foo.pem`
names a file that does not exist, and `haproxy -c` passes. Alice does not follow this: it lists `foo.pem` as the place's
certificate, and the file shows the problem "missing" although HAProxy serves the set. The `.rsa` and `.ecdsa` files
are not read either (their names are `bad_name`, above). Name the combined PEM files directly where Alice should show
the certificates.

## What Alice never changes

Alice changes nothing of HAProxy: no configuration file, no certificate or key file, no owner or mode, no service.
`haproxy-dump` writes, renames and changes the mode of nothing. Alice never starts, reloads or restarts HAProxy.
Only the SSH-key work of the `linux` part (removing a key, a rotation) changes files, exactly as on a Linux server.

## Configurations Alice cannot read

Alice lists these places as **Not supported** with the reason, or shows the problem above the list:

- **Other `-f` paths.** Alice reads only `/etc/haproxy/haproxy.cfg`. On the Red Hat family the service also loads
  `/etc/haproxy/conf.d`; Alice does not read it. When `conf.d` holds a `*.cfg` file, or exists but cannot be listed
  safely, the page warns that frontends defined there are not listed (`config_dir_not_read`). Move the frontends
  into `haproxy.cfg`, or keep using your own tools for them. A `conf.d` that does not exist or holds no `.cfg` file
  gives no warning. The unit's `-f` options and the `CONFIG` or `OPTIONS` variables of `/etc/sysconfig/haproxy` are
  never read.
- **Conditions.** An `.if` condition other than an empty one or a plain number (`.if streq(...)`, `.if feature(...)`,
  `.if "$X" -eq 1`, ...), or a `disabled` or `enabled` line in a place Alice cannot evaluate, makes the lines it
  covers `conditional`: the page says that the file, or the name of its website, is set inside a conditional part of the
  configuration (such as an `<If>` or `.if` block, or a test Alice cannot evaluate) and that Alice cannot tell when it
  is used. These also make every certificate conditional:
  - any keyword that contains `$` (HAProxy expands it before it reads the keyword, so it may be a `bind`, a key
    setting or a section header);
  - a `crt-store` section (HAProxy 3.0 and later; it can give a certificate a key file of its own);
  - `ssl-load-extra-files` or `ssl-load-extra-del-ext` that are not stable (above).

  A `crt-list` line is conditional when its option block names `crt`, `key`, `ocsp`, `issuer` or `sctl` (HAProxy 3.0
  and later: the line's own certificate or key file, which Alice does not read), or holds a quote, a backslash or a
  `$`. A place past the 1000 certificate files Alice opens to find keys is conditional too.
- **Variables.** A `$` in a path, whatever its quoting (`crt /etc/haproxy/certs/$HOST.pem`, `${CERTDIR}/a.pem`), is
  not expanded: "The path uses a variable" (`variable`).
- **Paths.** A relative `crt-list` path, a relative `crt` path without a usable `crt-base`, a path with a `.` or `..`
  component, a final `/`, a space or another character the helper does not accept (`path_not_allowed`).
- **Newer bind options.** A `bind` with a keyword that Alice does not know (usually one of a newer HAProxy, as `-c`
  accepted it) cannot be split into its arguments: its certificates are listed unread with the reason
  `unknown_keyword`.
- **`peers` and `log-forward` sections.** Their `bind` lines are not read; only `frontend` and `listen` are.
- **Backend client certificates.** The `crt` of a `server` line (the certificate HAProxy shows to a backend) is not
  read, and neither are `ca-file`, `crl-file`, `tls-ticket-keys` or similar files.
- **A writable configuration.** If `haproxy.cfg`, or a `crt-list` file that is read, is owned by a user other than root
  or can be written by its group or others, **every** place of the server is **Not supported** ("A configuration file
  used by HAProxy can be changed by users other than root"), and the page names the file. `crt-base` and the global
  settings reach the whole configuration, so Alice cannot limit this to one place. When `haproxy.cfg` itself is
  writable the helper does not run `haproxy -c` and reads nothing beyond it: no certificate list, no folder listing,
  no certificate file. The
  entries of a writable certificate list are never walked or opened either. Make the file root-owned and not group
  or other writable, then **Discover**.
- **A certificate list that cannot be read.** One that is absent or not a regular file, and that is named only in a
  part Alice cannot evaluate, gives conditional places and the warning `config_file_not_read`. One that is named in a
  part HAProxy certainly reads makes Alice refuse the whole server, as above.
- **The whole server**, when a configuration directory is not root-controlled, a file name contains a space, the
  configuration is larger than the limits above, contains a NUL byte, or changed while Alice read it.
- **Certificate sets.** A `crt foo.pem` that HAProxy loads as `foo.pem.rsa` and `foo.pem.ecdsa` (above) shows the
  problem "missing".
- **Limits of the check.** A path on a FUSE file system can make the root-control check wait; Alice's time limit then
  ends the discovery, but the stall itself is a known limitation. Keep `/etc/haproxy` and the folders of the certificates on a local
  file system.
- **No deployment.** Alice never deploys to a HAProxy server in this release. Renew the certificates with your own
  tools and reload HAProxy yourself; Alice shows the new certificate after the next discovery. A HAProxy certificate
  that is reloaded without Alice stays in the old state in Alice until then.

## Removing Alice from a HAProxy server

As in "Removing Alice from a server" in
[nginx-host-preparation.md](nginx-host-preparation.md#removing-alice-from-a-server): choose **Remove server** in
Alice, then remove `/etc/sudoers.d/alice`, the helper, the account and its directories on the server. HAProxy and
its files stay as they are; Alice never changed them.
