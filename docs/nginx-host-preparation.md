# Preparing a Server for Alice

Alice manages servers over SSH with its own key. It never logs in as `root` and never runs a shell command of its
own choosing: everything that needs root goes through **alice-helper**, a small program that you install on the
server, owned by root, and that only does a fixed list of things. This guide prepares a server once. It takes about
five minutes per server and you can undo it completely (see "Removing Alice from a server").

Supported systems: Ubuntu 20.04 or later, Debian 11 or later, RHEL, Rocky Linux or AlmaLinux 8 or later, on x86_64
or aarch64, with the OpenSSH server, `sudo` and `sha256sum` (coreutils). Alice is tested on Ubuntu 22.04, Debian 12
and Rocky Linux 9. For certificates the server also needs Nginx from the distribution's or nginx.org's packages,
installed as `/usr/sbin/nginx` and run by systemd as `nginx.service` (tested with Nginx 1.18, 1.20 and 1.22).
Nginx in a container, Nginx Plus and OpenResty builds with other paths are not supported.

## What the setup commands do

The commands are one shell script. It stops at the first error and changes nothing after it. Running it again is
safe.

1. Check that it runs as root and that the file `./alice-helper` is in the current directory. Copy it into a new
   directory that only root can open (below `/var/lib/alice-helper`, removed again when the script ends), then
   compare the SHA-256 checksum of that copy with the checksum built into this Alice version (for the server's
   processor). If they differ, the script stops: the file is not the `alice-helper` of this Alice version. (A
   development build of Alice without checksums prints a warning instead and installs the file unchecked.)
2. Install the checked copy as `/usr/local/libexec/alice-helper`, owned by root, mode 0755. Alice cannot change this
   file; you update it yourself when a new Alice release asks for it ("helper outdated"). This release ships
   `alice-helper` 1.11.0 (protocol 11, which reports the certificate chain a website presents in Alice's check from the
   server itself; protocol 10 added the check of "An undo never puts back a revoked or compromised
   certificate"; protocol 9 added `haproxy-dump` for HAProxy servers; protocol 8 added `apache-dump` for Apache servers; protocol 7 added the two HTTP-01
   challenge commands of "Publishing HTTP-01 challenges") and still works with a protocol 6 helper (`alice-helper` 1.5.0) for everything else. Protocol 6:
   accounts with dots, capitals or a final `$` in their names are listed, accounts
   it cannot list are reported by user ID, and a scan reads the key files in one pass (protocol 6); the Nginx
   certificate commands with `nginx-fence` (protocol 5); and the protocol 3 rule that a key-file change whose content
   did not arrive complete is refused. See "Updating the helper".
3. Create the system user `alice-svc` (home `/var/lib/alice-svc`, shell `/bin/bash`, no files from `/etc/skel`) if
   it does not exist. If a user `alice-svc` already exists with another home directory, the script stops. The
   account gets no password (`usermod -p '*'`): nobody can sign in with a password, but the SSH server still accepts
   its key, also with `UsePAM no`.
4. Make `/var/lib/alice-svc` and `/var/lib/alice-svc/.ssh` belong to root (mode 0755), delete everything else in
   `/var/lib/alice-svc` (for example a `.bashrc` that an earlier version left there owned by `alice-svc`) and
   re-create `.ssh`, and write `/var/lib/alice-svc/.ssh/authorized_keys` (root:root, mode 0644) with exactly one line: Alice's public
   key with the options `no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc`. The account
   `alice-svc` itself cannot change this file. Running the script again replaces the file with that one line, so
   any other key you put there is removed.
5. Install `/etc/sudoers.d/alice` (mode 0440, checked with `visudo -cf` before it is installed). It allows
   `alice-svc` to run **only** `alice-helper` with a fixed list of subcommands, without a password.
6. Create `/var/lib/alice-helper` and `/var/lib/alice-helper/backups` (root only, mode 0700). Before Alice changes an
   `authorized_keys` file, the helper keeps a copy of the previous file there; copies older than 30 days are removed
   automatically. The helper also keeps its lock files in `/var/lib/alice-helper/locks`; lock files not used for 30
   days are removed the same way. On an Nginx server the helper also keeps there the backups of replaced
   certificate and key files (see "Backups of certificate files") and, in `/var/lib/alice-helper/pairs`, one small
   record per certificate/key pair it ever changed (which change was the latest).

A restriction to Alice's source address (`from="…"` in the key line) is not added by the **Servers** page. If you
want it, ask for the commands through the API with `GET /api/v1/ssh-keys/platform-key?from=<Alice's IP address>`.

## Profiles

| Profile | For | Allowed helper subcommands (with `sudo`) |
|---|---|---|
| `linux` | Servers where Alice manages SSH keys only | `sshd-dump`, `hostkeys`, `cleanup`, `authkeys-list`, `authkeys-read`, `authkeys-write` |
| `nginx` | Nginx servers: their certificates and their SSH keys | everything in `linux` plus `nginx-dump`, `nginx-test`, `nginx-deploy`, `nginx-restore`, `nginx-status`, `nginx-fence`, `acme-challenge-put`, `acme-challenge-rm` |
| `apache` | Apache servers: reading their certificates, and their SSH keys | everything in `linux` plus `apache-dump` (read-only; see [apache-host-preparation.md](apache-host-preparation.md)) |

Choose the profile under **Server type** (**Linux server**, **Nginx server** or **Apache server**) on the **Servers**
page, and add the server in Alice with the same **Server type**. A Linux server never gets the Nginx permissions. All
profiles
also let `alice-svc` run `alice-helper version` and `alice-helper tls-probe` without `sudo`: these need no root
rights and have no sudoers line.

## The Nginx profile

The `nginx` profile adds these lines to `/etc/sudoers.d/alice` (exactly as the setup commands write them):

```
Cmnd_Alias ALICE_NGINX_ONLY = \
    /usr/local/libexec/alice-helper nginx-dump, \
    /usr/local/libexec/alice-helper nginx-test, \
    /usr/local/libexec/alice-helper nginx-deploy --op ????????-????-????-????-???????????? --cert /* --key /* --expect-cert-sha256 ???????????????????????????????????????????????????????????????? --content-sha256 ????????????????????????????????????????????????????????????????, \
    /usr/local/libexec/alice-helper nginx-restore --op ????????-????-????-????-????????????, \
    /usr/local/libexec/alice-helper nginx-status --op ????????-????-????-????-????????????, \
    /usr/local/libexec/alice-helper nginx-fence --op ????????-????-????-????-????????????, \
    /usr/local/libexec/alice-helper acme-challenge-put --token ??????????????????????*, \
    /usr/local/libexec/alice-helper acme-challenge-rm --token ??????????????????????*

alice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_NGINX_ONLY
```

Each `?` stands for exactly one character, so the operation ID (the deployment's ID) and the two SHA-256 values have
a fixed length, and a challenge token has at least 22 characters. sudo's `*` also matches spaces, so `sudo` alone would let a few extra words through after a path;
the helper checks its whole argument list itself and refuses anything that is not exactly what Alice sends.

| Line | What it allows |
|---|---|
| `nginx-dump` | Runs `/usr/sbin/nginx -V` and `nginx -T` and answers a summary: the Nginx version, the configuration's file names, each `server` block's names and HTTPS ports, each `ssl_certificate`/`ssl_certificate_key` pair, and for each certificate file its owner, group, mode, size, SHA-256 and the certificates in it; for each key file only its owner, group, mode and size. It never sends the configuration text, Nginx's own messages or anything from a key file. No arguments. |
| `nginx-test` | Runs `nginx -t` and answers whether the configuration is valid (and, if not, a short class such as "syntax" or "key does not match"). No arguments. |
| `nginx-deploy` | Replaces one certificate file and its key file with the content Alice sends on standard input, as one transaction (below). The two paths must be a pair that the current Nginx configuration uses. |
| `nginx-restore` | Puts back the previous files of one earlier `nginx-deploy`, from its backup. |
| `nginx-status` | Reports how one earlier `nginx-deploy` ended (from its journal) and whether the helper is busy. |
| `acme-challenge-put` | Writes one file, `/var/www/alice-acme/.well-known/acme-challenge/<token>`, with the text Alice sends on standard input (the "key authorization" a certificate authority asks for in an HTTP-01 challenge). See "Publishing HTTP-01 challenges". |
| `acme-challenge-rm` | Removes that one file again. |
| `nginx-fence` | Makes sure one earlier `nginx-deploy` can never run any more. Alice uses it when it finds no journal for a deployment whose answer it never got, and (when the server answers) before it records an outcome as not confirmed: the helper writes a small "fenced" journal under the lock, after which a late `nginx-deploy` of that deployment (for example one stuck in `sudo` while the connection dropped) refuses before it reads the new key and without changing anything. If the deployment had started after all, the helper answers its journal instead and Alice finishes or undoes it. |

`tls-probe` (no `sudo`) connects to a website on the server itself (for example `127.0.0.1:443`) and reports the
certificate it serves. Alice uses it to check a website it cannot reach from its own network.

### Publishing HTTP-01 challenges (optional)

To prove to a certificate authority (for example Let's Encrypt) that a name belongs to you, Alice can use the HTTP-01
method: the authority fetches `http://<name>/.well-known/acme-challenge/<token>` on port 80 and expects a short text.
Only do this preparation on a server that answers for the name on port 80 and only if you want Alice to use that
method; the DNS method needs nothing on the server.

**Alice never edits the Nginx configuration.** You publish one fixed directory yourself, and the helper only writes
and removes one small file in it while a certificate is being requested.

1. Check `/var/www` first: `stat -c '%U:%G %a' / /var /var/www` (if `/var/www` does not exist yet, the next
   command creates it as root's). The path is fixed: the file always goes to
   `/var/www/alice-acme/.well-known/acme-challenge/`. The helper writes there only when every directory on that path,
   from `/` down, belongs to root, cannot be written by its group or by other users (for example `root:root 755`;
   modes such as `775` or `777` are refused), and is a real directory, not a symbolic link. It never creates a
   directory and never changes an owner or a mode. If `/var/www` belongs to another user (for example the account a
   website is deployed with) or its group can write it, HTTP-01 cannot be used on this server: use the DNS method
   instead. Do not change the owner or mode of an existing website directory just for this unless you know what else
   depends on it.

   When `/var/www` is root's and not writable by others, create the folder Alice uses, owned by root:

   ```sh
   mkdir -p /var/www/alice-acme/.well-known/acme-challenge
   chown root:root /var/www/alice-acme /var/www/alice-acme/.well-known /var/www/alice-acme/.well-known/acme-challenge
   chmod 0755 /var/www/alice-acme /var/www/alice-acme/.well-known /var/www/alice-acme/.well-known/acme-challenge
   ```

   With SELinux (RHEL, Rocky, AlmaLinux) also run `restorecon -R /var/www/alice-acme`.
2. Add these three lines to the `server` block that listens on port 80 for the names:

   ```nginx
   location ^~ /.well-known/acme-challenge/ {
       root /var/www/alice-acme;
   }
   ```

   The `^~` makes this block win over pattern blocks such as `location ~ /\. { deny all; }`, which would otherwise
   refuse the `.well-known` path. A `return` written directly in the `server` block (for example
   `return 301 https://$host$request_uri;`) answers every request before any `location` is looked at: move it into a
   `location / { return 301 https://$host$request_uri; }` block, so only the challenge path is served over plain HTTP
   and everything else is still redirected.

3. Check and reload Nginx yourself: `nginx -t && systemctl reload nginx`.

The helper writes the file `/var/www/alice-acme/.well-known/acme-challenge/<token>` (root's, mode 0644, so Nginx can
read it) under a new temporary name and renames it into place, and removes it when the challenge is over. The token
is 22 to 128 letters, digits, `-` or `_`; the text must be exactly the token, a dot and 43 such characters. Anything
else is refused, and no other path is ever written or removed. Alice checks the file itself by fetching the URL
before it asks the authority to validate, so the Alice server must reach port 80 of the name too (it never follows
a redirect there). A server whose helper is older than protocol 7 keeps working for
everything else; Alice asks you to reinstall the helper there (see "Updating the helper") before it uses this method.

### How the helper decides what it may change

The helper changes only files that Nginx itself uses as a certificate/key pair, never a path Alice chooses:

- It reads the configuration with its own `nginx -T` and compares every configuration file printed there with the
  real file on disk. If they differ, or a file cannot be checked, it trusts none of the configuration and changes
  nothing ("Alice cannot trust what the web server reported for this configuration").
- Every directory and every symbolic link on the way to a configuration file, a certificate file or a key file must
  belong to root, and no directory may be writable by its group or by others. Root-owned links are followed, so
  Let's Encrypt's `live/` links work (the link stays; the file it points to is replaced).
- A certificate or key file must be a regular file with one name (no hard link), on a normal file system, and its
  name must end in `.pem`, `.crt`, `.cer`, `.cert`, `.key`, `.chained` or `.fullchain`. Both files must exist; Alice
  never creates a new file and never edits the Nginx configuration.
- A pair is not used when a configuration file that holds its `server` block or its directives (also through an
  `include`) can be changed by a user other than root.
- The real location of each file (after the links are followed) must use only the characters the helper accepts in
  a path (letters, digits and `._/@:+-`): a link into a folder named like `*.example.com` (acme.sh) is shown as
  **Not supported** ("name not allowed") and never written.
- Nginx must run as the systemd unit `nginx` (`/usr/bin/systemctl is-active nginx`); a server that runs it under
  another unit name or without systemd cannot be deployed to.
- Before replacing anything it checks that the certificate file still has the content Alice saw at the last
  **Discover** and that the new key belongs to the new certificate; that the latest change of this pair is not an
  interrupted one Alice is still finishing (it refuses until then); and that `/usr/bin/systemctl` exists and the
  `nginx` service is active (a reload could not apply the files otherwise, `ALC-NGX-0010`).

### What a deployment does on the server

`nginx-deploy` runs as one transaction under a lock (`/var/lib/alice-helper/locks/nginx.lock`, one change at a time
per server). It writes a journal and copies of the current certificate and key file, writes the new key and then the
new certificate (each through a temporary file next to the original, created root-only, then renamed over it), runs
`nginx -t`, then `systemctl reload nginx` and `systemctl is-active nginx`. If any of this fails, it puts the previous
files back and reloads Nginx again. It finishes even if the SSH connection drops; Alice then reads the journal with
`nginx-status` and finishes or undoes the change. When there is no journal at all, Alice runs `nginx-fence` before it
records "nothing was written", so a `nginx-deploy` that starts late can never change the files afterwards.

The new files keep the owner and group of the files they replace. The key file becomes mode 0600, except a key that
was 0640 (for example `root:ssl-cert` on Debian), which stays 0640. The certificate keeps its mode, limited to 0644.
An SELinux label is copied from the replaced file (`restorecon` is not run).

### An undo never puts back a revoked or compromised certificate

When a certificate is revoked or its private key is marked compromised in Alice (for example by a key-compromise
incident), the files a deployment replaces may hold exactly that certificate and key. If the new files then fail
(`nginx -t`, the reload, or Alice's check of the website), the usual undo would put the compromised key back on the
server. Alice therefore sends the helper, with every deployment and every undo, the list of what must never come back:
the SHA-256 of the public key of every compromised key and the SHA-256 of every revoked certificate (at most 128 of
each). The deployment's journal keeps the list. Before any undo (its own after a failed `nginx -t` or reload, the
undo of an interrupted deployment, and `nginx-restore`, which reads Alice's current list from its standard input) the
helper reads both copies in the deployment's backup folder: when the certificate copy, its public key or the public
key of the key copy is on the list, or a copy cannot be read as a certificate and its key, it puts **nothing** back.
The files stay as the deployment left them, no `nginx -t` or reload runs, and the journal says `restore_forbidden`.
Alice shows the deployment as failed with the reason that the previous certificate was not put back because it is
revoked or compromised, and an incident shows the place as failed.

This is deliberate: the website may stay broken (Nginx keeps serving what it loaded until its next reload or restart,
and that may fail with the new files). Fix the cause and deploy a valid certificate again, for example with **Retry**
on the incident; a `restore_forbidden` deployment never blocks the next deployment of the same files. **Never restore
such a backup by hand** (next sections): it holds the compromised key. The folder is removed 7 days later like any
finished deployment's; you may remove it earlier with `alice-helper cleanup --op <deployment ID>`.

The check needs `alice-helper` 1.9.0 (protocol 10). Alice refuses a deployment that replaces a revoked or compromised
certificate, and every deployment of a key-compromise incident, on a server whose helper is older, before anything is
sent (`ALC-SSH-0014`): an older helper would put the compromised key back on its own after a failed reload. Alice also
checks every undo it asks for itself, against its records read again right before the undo: it never asks an older
helper to undo a deployment whose previous certificate is revoked or compromised (or unknown while any key is
compromised), and a 1.9.0 helper gets that undo with the list, refuses it and records `restore_forbidden`
(`ALC-DEP-0025`).

### Backups of certificate files

Each deployment has its own folder `/var/lib/alice-helper/backups/<deployment ID>` (root only, 0700) with
`journal.json`, `cert.bak` (the previous certificate file) and `key.bak` (the previous private key), each root 0600.
The deployment's page in Alice shows this folder as **Backup on the server**. The helper removes a folder, by the
server's clock:

- 7 days after the deployment succeeded, changed nothing, was undone, was not undone because its backup holds a
  revoked or compromised certificate (`restore_forbidden`), stopped before it replaced anything (`prepared`), or was
  fenced (`nginx-fence`);
- 30 days after a deployment whose undo failed and that the helper can no longer finish, after a journal it cannot
  read, or for a folder without a journal;
- never while a deployment was interrupted (writing or undoing) and has not been finished or undone yet, nor while a
  failed undo can still be finished, unless a later deployment of the same files replaced it (then after 30 days).

`alice-helper cleanup --op <deployment ID>` refuses to remove a folder whose journal exists but cannot be read.

Alice never removes these folders itself. The helper keeps at most 1000 of them; beyond that it refuses new
deployments until old ones are removed. They contain private keys: treat them like the key files themselves.

A folder written by `nginx-fence` (a "tombstone") holds only a `journal.json` with the phase `fenced` and no file
copies: it records that the deployment with that ID must never run. Tombstones do not count against the 1000
folders; the helper keeps at most 10,000 of them (beyond that `nginx-fence` answers that there is no space, and
Alice then records nothing for the deployment it wanted to fence and tries again later). `cleanup --op` never removes
a tombstone; the sweep removes it 7 days after it was written (server clock). The helper refuses to fence an ID whose
folder holds backups of another kind (`authorized_keys` copies).

A change of a certificate/key pair that is still unfinished (its journal says `writing` or `restoring`, or cannot
be read) blocks every new `nginx-deploy` of the same files: the helper answers with the ID of that change, and Alice
undoes it or tells you how (`ALC-DEP-0002`, `ALC-DEP-0023`, `ALC-DEP-0024` in
[troubleshooting.md](troubleshooting.md)).

### Restoring a previous certificate by hand

Alice restores the previous files on its own when a deployment fails. Never restore a backup whose deployment ended
`restore_forbidden`, or whose certificate is revoked or marked compromised in Alice: it would put that key back on the
website. Never restore a backup when a later deployment changed the same files, or when the deployment shows `ALC-DEP-0014` (a later change replaced the files)
or `ALC-DEP-0020` (another program changed one of them): you would put back an older key or overwrite the other
program's file. After `ALC-DEP-0020` Alice put back at most the file it had written itself, so the certificate and
key may not belong together: run `nginx -t` first, and let the other program write a matching pair again or deploy
the intended certificate from Alice. To go back after a deployment that **succeeded**, the easiest way is to deploy the previous certificate
again (Alice needs its private key: upload it first). If that is not possible, restore the backup by hand, as root, while the folder still exists:

1. Find the deployment in Alice (**Deployments**) and note its **Certificate file**, **Key file** and
   **Backup on the server**.
2. On the server read `journal.json` in that folder (`cat /var/lib/alice-helper/backups/<deployment ID>/journal.json`):
   `cert_resolved` and `key_resolved` name the files that were replaced (for a Let's Encrypt link, the file the link
   points to); `cert_meta` and `key_meta` hold each file's previous owner and mode, for example
   `"key_meta":{"mode":416,"uid":0,"gid":110}`. The mode is written in decimal: `printf '%o\n' 416` prints `640`.
3. Copy the backups over those files with exactly those values, the key first. With the example above:
   `install -o 0 -g 110 -m 0640 /var/lib/alice-helper/backups/<deployment ID>/key.bak <key_resolved>`, then the
   same for `cert.bak` and `<cert_resolved>` with the values of `cert_meta`.
4. Run `nginx -t` and, if it passes, `systemctl reload nginx`.
5. In Alice choose **Discover** on the server's page. The website then shows **The certificate changed outside
   Alice.**, which is expected after a manual change.

Do not use `alice-helper nginx-restore` by hand for an older deployment: the helper restores only the latest change
of a certificate/key pair and refuses older ones.

### Changing a Linux server into an Nginx server

The server type cannot be changed in Alice. Run the setup commands again with **Server type** **Nginx server** (this
adds the Nginx lines to the sudoers file), then remove the server in Alice (**Remove server**) and add it again as an
**Nginx server**. Its SSH keys are read again by the first scan. If you only add the server as an Nginx server but
keep the Linux commands on it, Alice still reads its SSH keys and shows "The Nginx permissions are not installed on
this server".

## Steps

1. Get the helper. In a development checkout run `make helper`; it writes `bin/alice-helper-linux-amd64`,
   `bin/alice-helper-linux-arm64` and `bin/alice-helper.sha256`. (Release packages ship the same files in a
   `helper/` directory, listed in the package's signed `SHA256SUMS`.) Copy the file for the server's processor (`amd64` for x86_64, `arm64` for aarch64) to the
   server as `alice-helper`, in a new directory that only you can write, for example one made with
   `mkdir -m 700 ~/alice-setup` in your home. Do not use a shared directory such as `/tmp/alice`: another user of
   the server could create it first and change the file. You can compare it yourself: `sha256sum alice-helper` must
   print the value from `alice-helper.sha256`; the setup commands check it again.
2. In Alice, sign in as an administrator and open **Servers**. Under **Prepare a server for Alice** choose the
   **Server type** and choose **Copy commands**. The commands contain Alice's public key; **Fingerprint of Alice's
   key** above them shows its fingerprint.
3. On the server, save the commands as a file (for example `prepare-alice.sh`) in the directory that holds
   `alice-helper`, and run it there as root: `sudo sh ./prepare-alice.sh`. Expected last line: "This server is
   ready for Alice."
4. In Alice choose **Add server**, enter a **Name**, the server's **Address** (host name or IP address only), the
   **SSH port**, the **User name on the server** `alice-svc` (already filled in) and the **Server type** you chose in
   step 2, and choose **Connect**.
5. Alice shows **Is this your server?** with the server's **Fingerprint** and a **Command to run on the server**
   (for example `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). Run it on the server and compare the
   `SHA256:…` value character by character. Only if it is the same, choose **Yes, this is my server**. If it differs,
   choose **No, cancel** and ask your network or security team: someone may be between Alice and the server. A
   cancelled server stays in the list as **Waiting for fingerprint confirmation**; Alice does nothing on it.
6. Alice tests the connection and then reads the SSH keys. The server shows **Connected** and its keys appear under
   **SSH keys on this server**. On an Nginx server the same scan also reads Nginx's configuration: its websites
   appear under **Websites on this server**. Choose **Discover** there to scan again at any time.

## What Alice reads and changes

- Alice reads the `authorized_keys` files of `root`, of `alice-svc` itself, and of every account in `/etc/passwd`
  with user ID 0 or a user ID of 1000 or more (except `nobody`, user ID 65534) that has an existing home directory
  and a login shell (a shell field that does not end in `/nologin` or `/false`; an empty shell field counts as a
  login shell, because the SSH server treats it as `/bin/sh`), at most 200 accounts. Account names may use letters of
  either case, digits, `_`, `.` and `-` (not first) and one final `$`, up to 32 characters, and must not be only
  digits (`john.doe`, `Deploy2`, `host$`); `John` and `john` are two accounts. A home directory with a trailing `/` is
  read as without it. An entry Alice cannot list (any entry whose name breaks this rule, or whose user or group ID is written with a
  sign or is 4294967295 or more; and, for an account Alice would scan, a home directory with `..` or other
  characters) is never skipped silently: the server's page shows a warning with its
  user ID, and Alice then treats the account list as incomplete (see
  [operator-guide.md](operator-guide.md#keys-of-accounts-alice-no-longer-lists)). The helper reads `/etc/passwd` as
  glibc does (the first line of a name counts; `+`/`-` lines are not accounts); only glibc distributions are
  supported. Keys are read in the places that the SSH server's
  `AuthorizedKeysFile` setting names (also per user, through `Match` blocks), in one pass over the accounts. Alice also reads the server's host key
  fingerprints and its SSH settings (`sshd -T`). It never reads private keys. One scan reads at most 1000 key files
  and 10,000 keys and spends at most 10 minutes reading files; beyond that the scan is marked incomplete (a warning says
  that lists were cut) and keys of files it did not read are not marked **No longer found**. A whole discovery stops after 20
  minutes.
- Alice lists some key files as unsupported and never reads or changes them, because another user could redirect
  them to a file of their choosing (for example `root`'s keys):
  - a file reached through a symbolic link that leaves the user's home;
  - a file named by an absolute `AuthorizedKeysFile` outside the home whose directory is reached through a symbolic
    link, or whose directory or any directory above it is not owned by root or can be written by its group or by
    others. A per-user directory that the user owns, for example `/srv/keys/%u`, is therefore unsupported, although
    the SSH server accepts it;
  - every file of an account when a directory above its home (for example `/home` or `/`) is not owned by root or
    can be written by its group or by others. A symbolic link above the home is accepted only when root owns it,
    its target contains no `..`, and the directories it leads to pass the same check, so `/home -> /data/home` and
    Fedora's `/home -> var/home` work; a home that is itself a symbolic link must lead to a directory that the
    account owns.
- The helper also reports every account in `/etc/passwd` (at most 5000 names; an account whose name breaks the
  rule above only by its user ID). When an account was deleted and that list is complete (no warning about accounts
  Alice did not list, no directory service or systemd accounts, no "more user accounts than Alice lists" warning),
  its keys are marked **No longer found**. An account that still exists but got a shell such as `/usr/sbin/nologin` or
  lost its home directory is not scanned any more: its keys stay in Alice as they were last seen, and Alice cannot
  remove them. How to spot and handle this: [operator-guide.md](operator-guide.md#keys-of-accounts-alice-no-longer-lists).
- Accounts that exist only in a directory service (LDAP, SSSD or any other source in the `passwd:` line of
  `/etc/nsswitch.conf`) or as systemd user records or systemd-homed accounts are not listed; Alice shows a warning
  when the server may have such accounts, and also when it cannot read `/etc/nsswitch.conf` safely or the file is
  missing.
- If the SSH server gets keys from a program (`AuthorizedKeysCommand`), Alice shows the keys it finds in files but
  does not change keys on that server ("This server gets its SSH keys from a program").
- Alice changes an `authorized_keys` file only when an administrator or operator asks it to remove a key. It
  removes exactly the lines of that key, keeps every other line (including lines it cannot read) byte for byte,
  checks that nobody changed the file in the meantime (it tries up to three times), and keeps the previous version
  in the backup directory. It refuses to change a file when its last scan could not read the SSH server settings
  for that user, and it never changes `cert-authority` lines.
- Alice never removes its own key, on any account. Removing the last key of `root`, or of another account with
  user ID 0, needs an administrator's explicit confirmation.

## What Alice reads and changes on an Nginx server

- Alice reads Nginx's configuration through `nginx -T` (on the server, by the helper), the certificates in the
  certificate files it names, and the owner, group, mode and size of the key files. It never reads a private key
  from a server.
- Alice changes only certificate and key files that Nginx already uses, only when an administrator or operator
  deploys a certificate, and only under the rules of "How the helper decides what it may change". It never edits
  the Nginx configuration, never creates a certificate directive or file, and never restarts Nginx (it reloads it).
- Before a deployment Alice checks that it can see the website's current certificate (from its own network, or
  with `tls-probe` from the server itself); after it, that the website serves the new certificate with the expected
  chain. An administrator can change the port and name Alice checks, or turn the check off, per website
  (**Verification settings**).

Alice shows these notes next to a website: **Custom location** (the file is outside `/etc/ssl`, `/etc/nginx`,
`/etc/pki` and `/etc/letsencrypt`), "This file is a link" (another tool such as certbot may replace it), and "The
private key file belongs to a user other than root or can be read by a group or by others" (a deployment keeps
these permissions, so the new key is exactly as exposed as the old one; Debian's `ssl-cert` group also shows it).

## Configurations Alice cannot manage

Alice lists these websites as **Not supported** with the reason, or shows the problem above the list, and changes
nothing:

- A certificate path with a variable, a `data:` value, an `engine:` key, a key protected with `ssl_password_file`, a
  certificate and key in one file, one certificate file used with different key files, TLS in `stream {}` or
  `mail {}` blocks, and a path with a space, a `.` or `..` component or another unusual character.
- A pair whose configuration file can be changed by a user other than root (for example a site file writable by a
  deploy group): make the file and its directories root-owned and not group or other writable, then **Discover**.
- The whole server, when a configuration directory is not root-controlled, a configuration file is included through
  a path with `..` (write the `include` with an absolute path instead), a configuration file name contains a space,
  Nginx was built without a configuration path, or a comment in a real file starts exactly like the marker
  `# configuration file` that `nginx -T` prints. The page names the reason and, where it can, the file.
- A website whose `listen` names a host name that resolves to an address other than 127.0.0.1: Alice cannot
  check it, so deployments are refused before anything changes. Change the `listen` to an IP address or to
  `listen 443 ssl;`, or (if you accept the risk) let an administrator turn the check off for that website.
- A website whose name is answered by another `server` block that listens on the server's own address and port
  (Nginx gives such connections to the address-specific block): Alice sees the other block's certificate and
  refuses the deployment.
- Websites that offer only TLS 1.0 or 1.1, or only RSA key exchange: Alice's check needs TLS 1.2 or later.
- A certificate file whose first certificate Alice cannot read (`leaf_unreadable`, for example a certificate with a
  negative serial number): "The first certificate in the file cannot be read, so Alice does not know which certificate
  this website serves." Replace the certificate with one from a current certificate authority, then **Discover**.

## When the server is rebuilt

A rebuilt server has a new host key. Alice then shows **Server identity changed**, stops all work on it and emails
the administrators. An administrator chooses **Review the new fingerprint**, enters a **Reason** of at least 10
characters (for example the change ticket number) and chooses one of two actions; Alice asks for a new authenticator
code if the last one is more than five minutes old.

- **Accept new fingerprint**: only after comparing the new fingerprint on the server (step 5 above), when the server
  was reinstalled or its keys were replaced on purpose. The previous fingerprint stays in the history. Recorded as
  `hostkey.repinned`.
- **The server still shows the previous fingerprint**: when the previous fingerprint is still the right one, for
  example because the connection reached another machine for a while. Alice keeps the previous fingerprint, drops
  the new one, unblocks the server and tests the connection again. Recorded as `hostkey.change_dismissed`. If the
  server then presents a different key again, Alice blocks it again, emails the administrators again and asks for a
  new review.

The block never ends on its own, also not when the server presents its previous key again. If Alice has no new
fingerprint to offer, the dialog says "Alice has not recorded a new fingerprint for this server." and only
**The server still shows the previous fingerprint** is available.

Alice reuses an open SSH connection for up to 60 seconds for its own work. **Test connection** always opens a new
connection, so it shows a changed host key at once.

## Updating the helper

**Always install both: the new `alice-helper` and the new sudoers file.** Running the setup commands of the new
release does both. A protocol-5 helper without the `nginx-fence` sudoers line works for everything else, but a
deployment whose outcome Alice must check and that left no journal stays **Confirming the outcome** for about a day
and then ends **Outcome not confirmed** (`ALC-DEP-0018`), because Alice cannot fence it.

Each Alice release names the helper protocol it needs. When it needs a newer one than a server has, Alice shows the
server's error "The alice-helper on this server is outdated." (`ALC-SSH-0005`, `required_protocol` 6) and does nothing more on it: no scan, no key
removal, no deployment, no recovery. A protocol 6 helper is enough for everything but the HTTP-01 challenge commands
(protocol 7): only a certificate request that uses that method on the server asks you to reinstall the helper.

**Update the helpers first, then Alice.** The helper of this release (`alice-helper` 1.11.0, protocol 11) also works
with the previous Alice release, so you can update every server ahead of time. If you update Alice first, every
server whose helper is older shows "The alice-helper on this server is outdated." and a deployment that was being
finished waits (**Confirming the outcome**) until that server's helper is updated. To update, repeat steps 1 to 3 of "Steps" with the `alice-helper` of the new
release and the commands from the **Servers** page (same **Server type**), then choose **Test connection** on the
server's page. The commands install the new helper and the new sudoers file together. After any change to
`/etc/sudoers.d/alice` (by these commands or by hand), choose **Test connection** and **Discover** before deploying:
a deployment that sudo refuses is not a clean failure (sudo may already have read the new key), it goes to
**Confirming the outcome** until the lines are back.

`alice-helper` 1.10.0 and later (protocol 11) answer the check of a website from the server itself (`tls-probe`) with the
certificate chain the website presents, so that Alice verifies its trust like the chain its own check sees (see
[admin-guide.md](admin-guide.md#how-alice-verifies-a-deployment)). The sudoers file is the same. An older helper keeps
working: a deployment checked from the server then shows **Certificate chain: Not checked**, never a failure.

`alice-helper` 1.9.0 (protocol 10) added the check of "An undo never puts back a revoked or compromised certificate":
the deployment input and `nginx-restore`'s standard input carry the lists, and the journal phase `restore_forbidden`.
The sudoers file is the same. A server whose helper is older keeps working for everything except a deployment that
replaces a revoked or compromised certificate and the deployments of a key-compromise incident; update it before you
start an incident. `alice-helper` 1.8.0 (protocol 9) added `haproxy-dump` and the `haproxy` profile's sudoers line
([haproxy-host-preparation.md](haproxy-host-preparation.md)); `alice-helper` 1.7.0 (protocol 8) added `apache-dump`
and the `apache` profile's sudoers line ([apache-host-preparation.md](apache-host-preparation.md)). Nothing changed
for Linux and Nginx servers, which keep working with 1.6.x, and their sudoers files are the same.

From 1.8.0 the helper runs the Nginx program (`nginx -V`, `nginx -T`, `nginx -t`, also for a deployment's check) only
when `/usr/sbin/nginx` and every directory above it belong to root and nobody else can write them. Otherwise it does not
run it: the configuration is reported as untrusted (`not_root_controlled`, naming the file) and a connection test
reports the configuration as invalid, although the message does not say that the program itself is the cause. A
standard installation passes. `systemctl reload nginx` is not covered by this check.

`alice-helper` 1.6.1 keeps protocol 7 and the same sudoers file. It changes one answer: a certificate file whose first
certificate the helper cannot read (for example one with a negative serial number, which Nginx still loads) is
reported with the reason `leaf_unreadable` and no certificates. Before, the helper skipped that certificate, so Alice
took the next one in the file (usually the intermediate) as the website's certificate and showed its expiry date. A
server whose helper is still 1.6.0 keeps working; update it to get the correct reason for such a file.

`alice-helper` 1.11.0 keeps protocol 11 and the same sudoers file. It reads a first certificate labelled `TRUSTED
CERTIFICATE` or `X509 CERTIFICATE`, as Nginx does; before, such a file showed its intermediate as the website's
certificate. Trust settings after a `TRUSTED CERTIFICATE` are not sent to Alice.

Protocol 7 (`alice-helper` 1.6.0) adds `acme-challenge-put` and `acme-challenge-rm` and their two sudoers lines in
the `nginx` profile; nothing else changed. Protocol 6 (`alice-helper` 1.5.0) changed what the helper reports about
accounts and how a scan reads key files; its sudoers file is the same as for protocol 5 (which added `nginx-fence` and
its line). A deployment
that was interrupted before the update is finished by the new helper as usual.

## Removing Alice from a server

First choose **Remove server** on the server's page in Alice. Alice forgets the server and its keys, and closes the
SSH connections it kept open to it; it never connects to the server to do this. Then, as root on the server:

```sh
rm -f /etc/sudoers.d/alice /usr/local/libexec/alice-helper
userdel alice-svc
rm -rf /var/lib/alice-svc /var/lib/alice-helper
```

`/var/lib/alice-helper` also holds the backups of replaced certificate and key files (private keys included); the
`rm -rf` removes them. Nginx and its certificate files stay as they are. If you prepared "Publishing HTTP-01
challenges", remove the `location ^~ /.well-known/acme-challenge/` block yourself, reload Nginx and
`rm -rf /var/www/alice-acme`.

`userdel -r` is not used because the home directory belongs to root. If `userdel` reports that `alice-svc` is still
logged in, a job that was already running when you removed the server has not finished yet: wait a minute and run it
again, or end the session with `pkill -u alice-svc` and run `userdel alice-svc` again.
