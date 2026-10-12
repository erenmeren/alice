# Install Guide

This guide is for the IT administrator who prepares the server and installs Alice from the release package. You do
not need to know Alice to follow it. Allow one hour, most of it for preparing the server.

After the installation, the setup wizard in the browser finishes the work: see [first-run.md](first-run.md).

## 1. What the server needs

| Item | Minimum | Recommended (hundreds of servers, thousands of certificates) |
|---|---|---|
| Operating system | Linux x86_64: Ubuntu 22.04 or newer, Debian 12 or newer, RHEL/Rocky/Alma 9 or newer | same |
| Docker | Docker Engine 24 or newer with the `docker compose` plugin (v2) | Docker Engine 26 or newer |
| OpenSSL | OpenSSL 3 (the installer checks the package signature with it) | same |
| CPU | 2 vCPU | 4 vCPU |
| Memory | 4 GB (the installer warns from 3 GB and refuses less) | 8 GB |
| Disk | 20 GB free on the partition that will hold `/opt/alice` | 50 GB (backups, audit log growth, database) |
| Incoming network | TCP 443 (or the port you choose) from the workstations of the people who use Alice | same |
| Outgoing network | TCP 22 to the managed Linux and Nginx servers; TCP 443 to Azure (`login.microsoftonline.com`, `*.vault.azure.net`) only if you use Azure Key Vault; your mail server if you want e-mail; your identity provider if you use single sign-on; your syslog server if you forward the audit log | same |
| Time | A clock synchronised with NTP (licenses and certificate dates depend on it) | same |
| Rights | `root` through `sudo`, for the installation and for maintenance commands | same |

Alice needs no internet access: neither the installation, nor updates, nor licensing, nor daily work contact the
vendor or any other site. Alice sends no telemetry.

The server disk must use full-disk encryption: the database and Alice's master key are on it
([security-overview.md](security-overview.md)).

## 2. Prepare the server

### 2.1 Docker Engine and the compose plugin

Install Docker from Docker's own package repository. The packages of the distribution are often older than
version 24 or lack the compose plugin.

**Ubuntu 22.04 and Debian 12** (on Debian replace `ubuntu` with `debian` in both URLs):

```
sudo apt-get update
sudo apt-get install -y ca-certificates curl openssl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
```

**Rocky Linux 9 (and RHEL or Alma 9):**

```
sudo dnf install -y dnf-plugins-core openssl
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
```

Expected: `sudo docker version` shows a server version of 24 or newer, and `sudo docker compose version` prints a
version.

**Rocky 9 with SELinux enforcing.** An installation on Rocky 9 with SELinux in enforcing mode has not been verified
yet: the VM installation that proves it is an open owner step of this release (owner-pending). If a container
cannot read its mounted directory there, send `install.log` to support (see
[troubleshooting.md](troubleshooting.md#install-and-start-problems)).

**A server without internet access.** Download the same packages on a machine that has access, with the same
operating system version (`apt-get download <package>` on Ubuntu and Debian, `dnf download --resolve <package>` on
Rocky), copy them to the server and install them there (`sudo apt-get install ./*.deb` or `sudo dnf install ./*.rpm`).
The Alice package itself needs no download during the installation: it carries its images.

Docker's socket must not be usable by every user. Docker creates it with mode 660 for the `docker` group, which is
what the installer expects. Add only trusted administrators to the `docker` group: membership is equivalent to root.

### 2.2 Firewall

Open the HTTPS port to the people who use Alice, and nothing else. Alice's database has no published port.

```
sudo ufw allow 443/tcp                                         # Ubuntu, Debian with ufw
sudo firewall-cmd --permanent --add-service=https && sudo firewall-cmd --reload   # Rocky with firewalld
```

Docker publishes container ports with its own packet filter rules, which ufw's rules do not see. To limit who
reaches the port, use a network firewall in front of the server, or rules in Docker's `DOCKER-USER` chain.

### 2.3 DNS name and time

- Give the server a DNS name that people will type, for example `alice.example.com`, and ask for a certificate
  for that name from your certificate authority. You upload it in the setup wizard; until then Alice uses a
  temporary certificate and browsers warn.
- Turn on time synchronisation and check it:

  ```
  sudo timedatectl set-ntp true
  timedatectl show -p NTPSynchronized --value
  ```

  Expected: `yes`. Set the server's time zone too (`sudo timedatectl set-timezone Europe/Istanbul`): Alice takes it
  over as the time zone of the daily backup.

## 3. Check the package before you extract it

Your vendor delivers three files and publishes, on a separate channel (the vendor's website or the license e-mail),
the **release public key** and its **SHA-256 fingerprint**:

```
alice-1.0.0.tar.gz                the package
alice-1.0.0.tar.gz.sha256         its checksum
alice-1.0.0.tar.gz.sha256.sig     the vendor's signature of the checksum file
rk-2026-01.pem                    the release public key (from the vendor's website)
```

Do these three checks first, on the server or on any machine with OpenSSL 3, in the directory that holds the files.

1. Check that the release key is the one the vendor published:

   ```
   openssl pkey -pubin -in rk-2026-01.pem -outform DER | sha256sum
   ```

   Expected: the 64 hexadecimal characters equal the fingerprint the vendor published. If they differ, stop: this is
   not your vendor's key.

2. Check the vendor's signature of the checksum file with that key:

   ```
   openssl pkeyutl -verify -pubin -inkey rk-2026-01.pem -rawin -in alice-1.0.0.tar.gz.sha256 -sigfile alice-1.0.0.tar.gz.sha256.sig
   ```

   Expected: `Signature Verified Successfully`. Anything else: do not install the package; download it again and
   ask your vendor.

3. Check the package against the signed checksum:

   ```
   sha256sum -c alice-1.0.0.tar.gz.sha256
   ```

   Expected: `alice-1.0.0.tar.gz: OK`.

The installer checks the package again (a signature over every file inside it) and shows the release key's
fingerprint for a last comparison, but only these three steps tie the package to the key your vendor published.

## 4. Extract and install

Extract the package as root, in a directory that only root can change (for example `/root`), and run the installer
with `sudo` (not `sudo -E`: the installer must not take over your shell's environment). The installer works on the
package it belongs to, from whatever directory you start it:

```
sudo mkdir -p /root/alice-1.0.0
sudo tar --no-same-owner -xzf alice-1.0.0.tar.gz -C /root/alice-1.0.0
sudo /root/alice-1.0.0/alice/install.sh --hostname alice.example.com
```

The installer first copies the package into a new directory that only root can read (beside the installation
directory) and checks and installs only that copy, so the extracted files cannot change behind its back while it
waits for you. The copy is removed when the installer ends.

What happens, in order:

1. **Preflight.** Every check prints `[ OK ] <check>` or `[FAIL] <message>` (warnings: `[WARN] <message>`). All checks
   run, then the installer stops if one failed. Nothing is changed in this step. The checks and their fixes are in
   [Preflight messages](#preflight-messages).
2. **Package check and fingerprint.** The installer verifies the package's signature over its file list, every
   file's checksum, and that the package holds exactly the listed files (no extra file, no link). Then it prints:

   ```
   Package signed by release key rk-2026-01 (SHA-256 fingerprint <64 hex>). Compare this fingerprint with the one your vendor published.
   Does this fingerprint match the one your vendor published? Type yes to continue:
   ```

   Compare the fingerprint with the one the vendor published and type `yes`. Anything else prints
   `Nothing was changed.` and stops (exit code 1).
3. **Layout.** The installation directory `/opt/alice` with its sub-directories and files
   ([operator-guide.md](operator-guide.md#production-layout)).
4. **Secrets.** Three random database passwords in `/opt/alice/secrets/`, and the master key
   `/opt/alice/keys/master.key`. The installer prints
   `The master key file is included in encrypted backups. Do not copy it by hand.`
5. **Images.** The two container images from the package are loaded into Docker (no download), and their image IDs
   are compared with the package's `RELEASE` file.
6. **Start.** The database starts, the database tables are created, then Alice starts. Each part has 3 minutes to
   become healthy.
7. **Setup code.** The closing text with the address and the one-time setup code:

   ```
   Alice 1.0.0 is installed and running.

     Open this address in your web browser:   https://alice.example.com/setup
     (Your browser will warn about the certificate. This is expected until you
      install your own certificate in the setup wizard.)

     One-time setup code (needed once, write it down now, it is not shown again):

          K7QX2M-9TPD4R-WB5H8N-3VZC6A

     The setup code stops working as soon as the first administrator is created.
     Lost the code? Run:  sudo /opt/alice/alicectl setup-token --reset
     Daily backups are stored in /opt/alice/backups. Copy them to another machine.
   ```

   The setup code is printed to the terminal only. `install.log` records
   `Setup code printed to the terminal (not logged).`

Expected: the closing text, and exit code 0. Continue with [first-run.md](first-run.md).

Everything the installer printed is also in `/opt/alice/install.log` (mode 0600), except the setup code.

### Options of install.sh

| Option | What it does |
|---|---|
| `--dir DIR` | Installation directory (default `/opt/alice`). Every parent directory must belong to root and must not be writable by group or others, else the installer stops with exit code 2. |
| `--port N` | The HTTPS port (default 443). |
| `--hostname NAME` | The name (or several, comma-separated) for the certificate and the printed address. Default: the output of `hostname -f`. |
| `--non-interactive --fingerprint HEX` | Asks nothing. The 64 hexadecimal characters of the release-key fingerprint your vendor published are then required; a different fingerprint stops the installer with `The package fingerprint does not match --fingerprint. Nothing was changed.` (exit code 1). |
| `--restore-mode` | Prepares an empty installation for a restore: no master key, only the database is started. See [backup-restore.md](backup-restore.md#restore-on-a-new-server). |
| `--uninstall` | Stops Alice and removes its containers. Data and backups stay. |
| `--uninstall --purge` | Also deletes the installation directory with all data and backups, after you type `DELETE` (or with `--confirm DELETE`). |
| `--bind ADDRESS`, `--project NAME` | For the vendor's test harness: publish the port on one local address only, and use another Docker Compose project name. Leave both at their defaults on a production server. |

An unattended installation, for example from a configuration management tool:

```
sudo /root/alice-1.0.0/alice/install.sh --non-interactive --fingerprint <64 hex> --hostname alice.example.com
```

Exit codes: `0` success, `1` failure, `2` a wrong option or option value.

**A package signed with a test key.** If the installer prints
`[WARN] This package is signed with a TEST key. Never install it for production.`, the package was built for the
vendor's tests. Do not use it on a production server; ask your vendor for the release package.

### Preflight messages

| Check | `[FAIL]` message | What to do |
|---|---|---|
| Running as root | `This installer must be run with administrator rights. Run it again as: sudo ./install.sh` | Run it with `sudo`. |
| Linux x86_64 | `Alice needs a 64-bit Intel/AMD Linux server. This machine is <arch>.` | Use an x86_64 server. |
| Docker installed and running | `Docker is not installed or not running. Install Docker Engine 24 or newer (see docs/install-guide.md), then run this installer again.` | [Section 2.1](#21-docker-engine-and-the-compose-plugin); `sudo systemctl enable --now docker`. |
| Docker 24 or newer with the compose plugin | `Your Docker is too old (found <version>). Alice needs version 24 or newer.` or `The Docker compose plugin is missing. Install docker-compose-plugin (see docs/install-guide.md), then run this installer again.` | Install Docker from Docker's repository (section 2.1). |
| Docker socket restricted | `The Docker socket /var/run/docker.sock can be used by every user on this server. Restrict it to the docker group (chmod 660), then run this installer again.` | `sudo chmod 660 /var/run/docker.sock`, and find what widened it. |
| OpenSSL 3 | `OpenSSL 3 is needed to check the package signature. Install the openssl package, then run this installer again.` | Install the `openssl` package. |
| Free disk ≥ 20 GB | `Not enough free disk space in <directory>: <n> GB free, 20 GB needed.` | Free space, or use `--dir` on a larger partition. |
| Memory ≥ 4 GB, CPU ≥ 2 | `This server has <n> GB of memory. Alice needs at least 4 GB.` (a warning from 3 GB) or `This server has <n> CPU. Alice needs at least 2.` | Give the server more memory or CPUs. |
| Port free | `Another program is already using port <port> (<program>, pid <pid>). Stop it or run the installer with --port 8443.` | Stop the other program, or choose another port with `--port`. |
| Package signature | `The package signature is not valid. Do not install this package; download it again and check it with your vendor.` | Download the package again; do the checks of section 3. |
| Package complete, package lists exactly its files | `The installation package is damaged or incomplete. Download it again and compare the checksum.` | Download the package again and check it (section 3). |
| (copy of the package) | `The package could not be copied next to <dir> for checking. Check the free disk space, then run this installer again.` | Free disk space on the partition of the installation directory. |
| Clock sane | `The server clock looks wrong (it says <year>). Fix the date/time first; licenses depend on it.` | Set the date and time, turn on NTP (section 2.3). |
| No installation yet | `Alice is already installed in <dir>. To upgrade use ./alice-update.sh.` | Use the update ([upgrade.md](upgrade.md)), or remove the old installation first. |
| No installation yet | `Docker already has containers of the project alice. Choose another --project, or update the installation that uses it with its own alice-update.sh.` | Another Alice runs on this server; update that one instead. |

Warnings that do not stop the installer:

- `[WARN] Alice could not confirm that the clock is synchronised. Make sure NTP is running; licenses depend on the time.`
  Turn on NTP (section 2.3).
- `[WARN] The time zone of this server could not be read; Alice uses UTC.` The daily backup runs at 02:30 UTC; you
  can choose another time zone later in **Settings → Backups**.

When Alice does not start in step 6, the installer prints the last 30 log lines of each container and
`Alice did not start. Send /opt/alice/install.log to support.` See
[troubleshooting.md](troubleshooting.md#install-and-start-problems).

## 5. Uninstall

```
sudo /opt/alice/install.sh --uninstall
```

Expected: `Alice was stopped and its containers removed. Your data and backups are still in /opt/alice.`

To delete everything, including the data and every backup, after copying the backups you want to keep elsewhere:

```
sudo /opt/alice/install.sh --uninstall --purge
```

The installer asks `This deletes <dir> with all data and backups. Type DELETE to continue: ` (with `/opt/alice` for `<dir>`). Anything but
`DELETE` prints `Nothing was deleted.` For a script, add `--confirm DELETE`. The loaded Docker images stay; remove
them with `sudo docker image rm` if you need the space.

Neither runs while an update or a restore is running: they stop with
`[FAIL] Another update or restore of Alice is running in /opt/alice. Wait until it has finished, then run this again.`
