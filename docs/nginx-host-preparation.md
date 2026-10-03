# Preparing a Server for Alice

Alice manages servers over SSH with its own key. It never logs in as `root` and never runs a shell command of its
own choosing: everything that needs root goes through **alice-helper**, a small program that you install on the
server, owned by root, and that only does a fixed list of things. This guide prepares a server once. It takes about
five minutes per server and you can undo it completely (see "Removing Alice from a server").

Supported systems: Ubuntu 20.04 or later, Debian 11 or later, RHEL, Rocky Linux or AlmaLinux 8 or later, on x86_64
or aarch64, with the OpenSSH server, `sudo` and `sha256sum` (coreutils). Alice is tested on Ubuntu 22.04, Debian 12
and Rocky Linux 9.

## What the setup commands do

The commands are one shell script. It stops at the first error and changes nothing after it. Running it again is
safe.

1. Check that it runs as root and that the file `./alice-helper` is in the current directory, then compare the
   SHA-256 checksum of that file with the checksum built into this Alice version (for the server's processor). If
   they differ, the script stops: the file is not the `alice-helper` of this Alice version. (A development build of
   Alice without checksums prints a warning instead and installs the file unchecked.)
2. Copy `alice-helper` to `/usr/local/libexec/alice-helper`, owned by root, mode 0755. Alice cannot change this
   file; you update it yourself when a new Alice release asks for it ("helper outdated").
3. Create the system user `alice-svc` (home `/var/lib/alice-svc`, shell `/bin/bash`) if it does not exist. If a user
   `alice-svc` already exists with another home directory, the script stops. The account gets no password
   (`usermod -p '*'`): nobody can sign in with a password, but the SSH server still accepts its key, also with
   `UsePAM no`.
4. Make `/var/lib/alice-svc` and `/var/lib/alice-svc/.ssh` belong to root (mode 0755), delete and re-create `.ssh`,
   and write `/var/lib/alice-svc/.ssh/authorized_keys` (root:root, mode 0644) with exactly one line: Alice's public
   key with the options `no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc`. The account
   `alice-svc` itself cannot change this file. Running the script again replaces the file with that one line, so
   any other key you put there is removed.
5. Install `/etc/sudoers.d/alice` (mode 0440, checked with `visudo -cf` before it is installed). It allows
   `alice-svc` to run **only** `alice-helper` with a fixed list of subcommands, without a password.
6. Create `/var/lib/alice-helper` and `/var/lib/alice-helper/backups` (root only, mode 0700). Before Alice changes an
   `authorized_keys` file, the helper keeps a copy of the previous file there; copies older than 30 days are removed
   automatically. The helper also keeps its lock files in `/var/lib/alice-helper/locks`.

A restriction to Alice's source address (`from="…"` in the key line) is not added by the **Servers** page. If you
want it, ask for the commands through the API with `GET /api/v1/ssh-keys/platform-key?from=<Alice's IP address>`.

## Two profiles

| Profile | For | Allowed helper subcommands |
|---|---|---|
| `linux` | Servers where Alice manages SSH keys only | `sshd-dump`, `hostkeys`, `cleanup`, `authkeys-list`, `authkeys-read`, `authkeys-write` |
| `nginx` | Nginx servers (certificates arrive in a later release; SSH keys work now) | everything in `linux` plus `nginx-dump`, `nginx-test`, `nginx-reload`, `stat`, `read-cert`, `install-cert`, `backup`, `restore` |

Choose the profile under **Server type** (**Linux server** or **Nginx server**) on the **Servers** page. A Linux
server never gets the Nginx permissions. The helper of this release answers the Nginx subcommands with
`UNKNOWN_SUBCOMMAND`; Alice adds every server as a Linux server for now.

## Steps

1. Get the helper. In a development checkout run `make helper`; it writes `bin/alice-helper-linux-amd64`,
   `bin/alice-helper-linux-arm64` and `bin/alice-helper.sha256`. (Release packages will ship the same files in a
   `helper/` directory.) Copy the file for the server's processor (`amd64` for x86_64, `arm64` for aarch64) to the
   server as `alice-helper`, in an empty directory. You can compare it yourself: `sha256sum alice-helper` must print
   the value from `alice-helper.sha256`; the setup commands check it again.
2. In Alice, sign in as an administrator and open **Servers**. Under **Prepare a server for Alice** choose the
   **Server type** and choose **Copy commands**. The commands contain Alice's public key; **Fingerprint of Alice's
   key** above them shows its fingerprint.
3. On the server, save the commands as a file (for example `prepare-alice.sh`) in the directory that holds
   `alice-helper`, and run it there as root: `sudo sh ./prepare-alice.sh`. Expected last line: "This server is
   ready for Alice."
4. In Alice choose **Add server**, enter a **Name**, the server's **Address** (host name or IP address only), the
   **SSH port** and the **User name on the server** `alice-svc` (already filled in), and choose **Connect**.
5. Alice shows **Is this your server?** with the server's **Fingerprint** and a **Command to run on the server**
   (for example `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). Run it on the server and compare the
   `SHA256:…` value character by character. Only if it is the same, choose **Yes, this is my server**. If it differs,
   choose **No, cancel** and ask your network or security team: someone may be between Alice and the server. A
   cancelled server stays in the list as **Waiting for fingerprint confirmation**; Alice does nothing on it.
6. Alice tests the connection and then reads the SSH keys. The server shows **Connected** and its keys appear under
   **SSH keys on this server**.

## What Alice reads and changes

- Alice reads the `authorized_keys` files of `root`, of every account in `/etc/passwd` with a user ID of 1000 or
  more, an existing home directory and a login shell, and of `alice-svc` itself (at most 200 accounts), in the
  places that the SSH server's `AuthorizedKeysFile` setting names (also per user, through `Match` blocks). A key
  file reached through a symbolic link that leaves the user's home is reported, not read. Alice also reads the
  server's host key fingerprints and its SSH settings (`sshd -T`). It never reads private keys.
- Accounts that exist only in a directory service (LDAP, SSSD) are not listed; Alice shows a warning when the
  server uses one.
- If the SSH server gets keys from a program (`AuthorizedKeysCommand`), Alice shows the keys it finds in files but
  does not change keys on that server ("This server gets its SSH keys from a program").
- Alice changes an `authorized_keys` file only when an administrator or operator asks it to remove a key. It
  removes exactly the lines of that key, keeps every other line (including lines it cannot read) byte for byte,
  checks that nobody changed the file in the meantime (it tries up to three times), and keeps the previous version
  in the backup directory. It refuses to change a file when its last scan could not read the SSH server settings
  for that user, and it never changes `cert-authority` lines.
- Alice never removes its own key, on any account. Removing the last key of `root` needs an administrator's
  explicit confirmation.

## When the server is rebuilt

A rebuilt server has a new host key. Alice then shows **Server identity changed** and stops all work on it until an
administrator compares the new fingerprint (step 5 above) and accepts it: **Review the new fingerprint**, a reason
of at least 10 characters, **Accept new fingerprint**, and a new authenticator code if Alice asks for one. The
previous fingerprint stays in the history.

The block stays even if the server later presents its previous key again. In that case the page still offers the
key the server no longer presents, and accepting it fails with `ALC-TGT-0003`. In this release the block can then be
ended only through the API: an administrator, signed in to the browser, re-pins the already pinned key
(`POST /api/v1/targets/{id}/host-keys/{pinned key id}/actions/repin`, with its fingerprint and a reason). Alice
records this as `hostkey.change_dismissed`.

Alice reuses an open SSH connection for up to 60 seconds. Until a fix scheduled for this release is in place,
**Test connection** within 60 seconds of Alice's last work on the server can still report success over the old
connection; the change is detected on the next new connection.

## Removing Alice from a server

As root on the server:

```sh
rm -f /etc/sudoers.d/alice /usr/local/libexec/alice-helper
userdel alice-svc
rm -rf /var/lib/alice-svc /var/lib/alice-helper
```

`userdel -r` is not used because the home directory belongs to root. Then choose **Remove server** on the server's
page in Alice. Alice forgets the server and its keys; it never connects to the server to do this.
