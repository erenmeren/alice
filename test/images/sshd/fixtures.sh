#!/bin/sh
# Fixture users and keys for the real-OpenSSH tests (spec §22.6). Runs once at image build time
# as root. Keys are generated here and their private halves deleted at once: nothing secret is
# committed. /root/fixture-keys.tsv lists every key Alice's inventory must show
# (user, fingerprint, comment); keys Alice must NOT show are not listed.
set -eu
out=/root/fixture-keys.tsv
: > "$out"
tmp="$(mktemp -d)"

# newkey <type> <bits or -> <comment>: prints a new public key line.
newkey() {
	if [ "$2" = - ]; then
		ssh-keygen -q -t "$1" -N '' -C "$3" -f "$tmp/k"
	else
		ssh-keygen -q -t "$1" -b "$2" -N '' -C "$3" -f "$tmp/k"
	fi
	cat "$tmp/k.pub"
	rm -f "$tmp/k" "$tmp/k.pub"
}

# record <user> <public key line>: the inventory must list this key for this user.
record() {
	fp="$(printf '%s\n' "$2" | ssh-keygen -lf - | awk '{print $2}')"
	printf '%s\t%s\t%s\n' "$1" "$fp" "$(printf '%s\n' "$2" | awk '{print $3}')" >> "$out"
}

# user <name> <uid> <shell>: a user with a private .ssh directory.
user() {
	useradd --uid "$2" --create-home --shell "$3" "$1"
	install -d -m 0700 -o "$1" -g "$1" "/home/$1/.ssh"
}

# deploy: two keys, file ends with a newline.
user deploy 1001 /bin/bash
k1="$(newkey ed25519 - deploy@laptop)"
k2="$(newkey rsa 3072 ci@build)"
printf '%s\n%s\n' "$k1" "$k2" > /home/deploy/.ssh/authorized_keys
record deploy "$k1"
record deploy "$k2"

# noshell: a key, but no login shell: Alice does not list it (spec §13.1).
user noshell 1002 /usr/sbin/nologin
printf '%s\n' "$(newkey ed25519 - noshell@x)" > /home/noshell/.ssh/authorized_keys

# nonl: one key and no trailing newline (F-37).
user nonl 1003 /bin/bash
k4="$(newkey ed25519 - nonl@desk)"
printf '%s' "$k4" > /home/nonl/.ssh/authorized_keys
record nonl "$k4"

# linky: authorized_keys is a symlink to /etc/shadow (A-13): never read, only reported.
user linky 1004 /bin/bash
ln -s /etc/shadow /home/linky/.ssh/authorized_keys

# root: one key restricted with from= (so no root_without_from flag).
install -d -m 0700 /root/.ssh
k5="$(newkey ed25519 - root@bastion)"
printf 'from="10.0.0.0/8" %s\n' "$k5" > /root/.ssh/authorized_keys
record root "$k5"

for u in deploy noshell nonl; do
	chown "$u:$u" "/home/$u/.ssh/authorized_keys"
	chmod 0600 "/home/$u/.ssh/authorized_keys"
done
chmod 0600 /root/.ssh/authorized_keys
rm -rf "$tmp"
