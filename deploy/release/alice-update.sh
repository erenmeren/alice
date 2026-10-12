#!/usr/bin/env bash
# alice-update.sh: updates this installation of Alice to a new release package (C4, spec §20.1).
# Run it from the installation directory: cd /opt/alice && sudo ./alice-update.sh <tarball | dir>
#
# 1 preflight and package intake: the package is copied into .update-<ts>/ first and only the copy
#   is verified (signature of the .sha256 with the installed release keys, the tarball hash, then
#   the S-7 checks of its content) and used (S-3); 2 the recovery passphrase; 3 stop Alice and end
#   leftover database sessions; 4 a pre-update backup and its deep verification; 5 rollback copy;
#   6 load and check the new images; 7 new compose file and .env, migrations; 8 start and selfcheck;
#   9 install the new scripts and release keys. A failure in 3-6 starts the installed version again
#   (exit 1); a failure in 7-8 returns to the installed version and its pre-update backup (exit 1),
#   and when that also fails prints the manual command (exit 3). Exit 2: usage.
set -Eeuo pipefail
umask 077
export LC_ALL=C

here=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/alice-lib.sh
. "$here/lib/alice-lib.sh"

dir=$here
ts=$(date -u +%Y%m%dT%H%M%SZ)
log="$dir/update-$ts.log"
work="$dir/.update-$ts"
package_arg=""
passphrase_file=""
non_interactive=0
stage=pre # pre: nothing changed; stopped: Alice stopped; changed: installation changed; finishing
handling=0
keep_work=0
installed=""
new=""
pkg=""
backup_host=""
backup_time=""
rollback=""
env_hosts=""
env_bind=""
env_port=""
env_zone=""

usage() {
  cat <<'USAGE'
Usage: cd /opt/alice && sudo ./alice-update.sh <alice-VERSION.tar.gz | extracted directory>
                                             [--passphrase-file FILE] [--non-interactive]

The tarball's .sha256 and .sha256.sig files must lie beside it. The recovery passphrase is needed
for the automatic backup (and a return to this version if the update fails); without
--passphrase-file it is asked on the terminal.
USAGE
}

usage_error() {
  printf '%s\n' "$1" >&2
  printf 'Run ./alice-update.sh --help for the options.\n' >&2
  exit 2
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      --passphrase-file)
        (($# >= 2)) || usage_error "$1 needs a value."
        passphrase_file=$2
        shift 2
        ;;
      --non-interactive) non_interactive=1; shift ;;
      -h | --help)
        usage
        exit 0
        ;;
      -*) usage_error "Unknown option: $1" ;;
      *)
        [[ -z "$package_arg" ]] || usage_error "Give one package."
        package_arg=$1
        shift
        ;;
    esac
  done
  [[ -n "$package_arg" ]] || usage_error "Give the update package (the tarball or its extracted directory)."
  if ((non_interactive == 1)) && [[ -z "$passphrase_file" ]]; then
    usage_error "--non-interactive needs --passphrase-file."
  fi
}

# shellcheck disable=SC2329 # called from the EXIT trap
cleanup() {
  if ((keep_work == 0)) && [[ -n "$work" && -d "$work" ]]; then rm -rf -- "$work"; fi
}

# fail_before_change: steps 3-6 failed; the installation is unchanged, so start it again.
fail_before_change() {
  handling=1
  trap '' INT TERM
  alice_pass=""
  if alice_quiet alice_wait_healthy alice; then
    alice_log "The update was stopped before any change; Alice is running version $installed again."
    exit 1
  fi
  alice_log "Alice could not be started again. Details: $log. Please send this file to support."
  keep_work=1
  exit 3
}

# fail_after_change: steps 7-8 failed; return to the installed version and its pre-update backup.
fail_after_change() {
  local f rc=0
  handling=1
  trap '' INT TERM
  alice_log "The update failed; returning to version $installed."
  alice_quiet alice_compose stop alice || true
  alice_quiet alice_terminate_leftover_sessions || alice_log "[WARN] Leftover database sessions could not be ended."
  for f in docker-compose.yml .env RELEASE VERSION; do
    if [[ -f "$rollback/$f" ]]; then cp -p -- "$rollback/$f" "$dir/$f" || rc=1; fi
  done
  if ((rc == 0)); then
    printf '%s\n' "$alice_pass" | "$dir/alicectl" restore "$backup_host" --db-only --confirm RESTORE --passphrase-stdin 2>&1 |
      alice_log_stream || rc=1
  fi
  alice_pass=""
  if ((rc == 0)); then
    alice_log "The update to $new failed and Alice was returned to $installed. Your data is unchanged as of $backup_time. Details: $log. Please send this file to support."
    exit 1
  fi
  alice_log "The update to $new failed and Alice could not be returned to $installed automatically. Your backup is $backup_host. Restore it by hand: cd $dir && sudo ./alicectl restore $backup_host   (details: $log)"
  keep_work=1
  exit 3
}

fail_now() {
  case "$stage" in
    pre)
      alice_pass=""
      exit 1
      ;;
    stopped) fail_before_change ;;
    changed) fail_after_change ;;
    *)
      alice_log "Alice $new is running, but the update could not install all its files. Details: $log. Please send this file to support."
      keep_work=1
      exit 3
      ;;
  esac
}

# shellcheck disable=SC2329 # called from the INT and TERM trap
on_interrupt() {
  if ((handling == 1)); then return 0; fi
  trap '' INT TERM
  if [[ "$stage" == pre ]]; then
    alice_log "Interrupted. Nothing was changed."
  else
    alice_log "Interrupted."
  fi
  fail_now
}

# shellcheck disable=SC2329 # called from the ERR trap
on_error() {
  local line=$1
  if [[ "$BASHPID" != "$$" ]] || ((handling == 1)); then return 0; fi
  trap - ERR
  alice_log "Unexpected error (line $line)."
  fail_now
}

refuse_signature() {
  alice_fail "The update package signature is not valid. Do not install this package; download it again and check it with your vendor."
  exit 1
}

refuse_damaged() {
  alice_fail "$alice_damaged"
  exit 1
}

# recover_release_keys puts release-keys/ back when an earlier update stopped between the two
# renames of replace_release_keys: release-keys.new is then complete (it is renamed only after it
# was written), else the keys that were in place before are in release-keys.old.
recover_release_keys() {
  local k=$dir/release-keys
  if [[ -e "$k" || -L "$k" ]]; then return 0; fi
  if [[ -d "$k.new" && ! -L "$k.new" ]]; then
    mv -T -- "$k.new" "$k"
  elif [[ -d "$k.old" && ! -L "$k.old" ]]; then
    mv -T -- "$k.old" "$k"
  fi
}

# intake_space refuses before the copy when the installation's file system lacks room for the
# package copy and its extraction: 3 × the package's size + 1 GiB (final review B M-1). The copy
# would otherwise fill the disk under the running database. preflight checks the exact need for
# the update itself after intake.
intake_space() {
  local size avail need
  if [[ ! -e "$package_arg" ]]; then usage_error "No such package: $package_arg"; fi
  size=$(du -sbL -- "$package_arg" 2>/dev/null | tail -n 1) || size=0
  size=${size%%[!0-9]*}
  [[ "$size" =~ ^[0-9]+$ ]] || size=0
  avail=$(df -B1 --output=avail -- "$dir" 2>/dev/null | tail -n 1 | tr -d ' ') || avail=0
  [[ "$avail" =~ ^[0-9]+$ ]] || avail=0
  need=$((3 * size + 1073741824))
  if ((avail < need)); then
    alice_log "Not enough free disk space in $dir to unpack the update package: $((avail / 1073741824)) GB free, $(((need + 1073741823) / 1073741824)) GB needed."
    exit 1
  fi
}

# intake copies the package into the work directory and verifies the copy only (S-3, S-7).
intake() {
  local name hex line actual rc=0
  install -d -m 0700 -- "$work/in" "$work/pkg"
  if [[ -d "$package_arg" ]]; then
    install -d -m 0700 -- "$work/pkg/alice"
    cp -a --no-preserve=ownership -- "$package_arg/." "$work/pkg/alice/" || refuse_damaged
  elif [[ -f "$package_arg" ]]; then
    name=$(basename -- "$package_arg")
    [[ "$name" =~ ^alice-[A-Za-z0-9.-]+\.tar\.gz$ ]] || usage_error "The package file must be named alice-<version>.tar.gz."
    install -m 0600 -- "$package_arg" "$work/in/$name" || refuse_damaged
    install -m 0600 -- "$package_arg.sha256" "$work/in/$name.sha256" 2>/dev/null || refuse_signature
    install -m 0600 -- "$package_arg.sha256.sig" "$work/in/$name.sha256.sig" 2>/dev/null || refuse_signature
    alice_verify_sig "$work/in/$name.sha256" "$work/in/$name.sha256.sig" "$dir/release-keys" || refuse_signature
    IFS= read -r line <"$work/in/$name.sha256" || true
    hex=${line%% *}
    [[ "$hex" =~ ^[0-9a-f]{64}$ ]] || refuse_signature
    actual=$(sha256sum <"$work/in/$name")
    actual=${actual%% *}
    [[ "$actual" == "$hex" ]] || refuse_signature
    tar --no-same-owner --no-same-permissions -xzf "$work/in/$name" -C "$work/pkg" || refuse_damaged
  else
    usage_error "No such package: $package_arg"
  fi
  pkg="$work/pkg/alice"
  [[ -d "$pkg" && ! -L "$pkg" ]] || refuse_damaged
  alice_check_package "$pkg" "$dir/release-keys" || rc=$?
  case "$rc" in
    0) ;;
    1) refuse_signature ;;
    *) refuse_damaged ;;
  esac
  alice_read_release "$pkg" || refuse_damaged
  print_key_fingerprints
}

# print_key_fingerprints prints the fingerprint of the installed release key that signed the
# package and of every key the package brings, which replace the installed ones (S-35): after a
# suspected key leak the customer compares them with the fingerprints the vendor published
# (final review B M-3).
print_key_fingerprints() {
  local f fp
  fp=$(alice_fingerprint "$alice_sig_key") || refuse_damaged
  alice_ok "Update package signed by release key $(basename -- "$alice_sig_key" .pem) (SHA-256 fingerprint $fp). Compare this fingerprint with the one your vendor published."
  for f in "$pkg"/release-keys/rk-*.pem; do
    [[ -f "$f" ]] || continue
    fp=$(alice_fingerprint "$f") || refuse_damaged
    alice_log "The package brings release key $(basename -- "$f" .pem) (SHA-256 fingerprint $fp)."
  done
  alice_log "After the update only the release keys the package brings are trusted."
}

preflight() {
  local cmp env_project db avail need gb_free gb_need
  if [[ "$(id -u)" != 0 ]]; then
    printf '[FAIL] This update must be run with administrator rights. Run it again as: sudo ./alice-update.sh\n'
    exit 1
  fi
  if [[ ! -f "$dir/VERSION" || ! -f "$dir/docker-compose.yml" || ! -f "$dir/.env" ]]; then
    printf '[FAIL] No installation of Alice was found in %s. Run this script from the installation directory: cd /opt/alice && sudo ./alice-update.sh <package>\n' "$dir"
    exit 1
  fi
  alice_dir=$dir
  if ! alice_lock; then
    alice_lock_busy "[FAIL] "
    exit 1
  fi
  alice_log_open "$log"
  mkdir -m 0700 -- "$work"
  trap 'cleanup' EXIT
  alice_log "Updating Alice in $dir (log $log)."
  if ! alice_docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    alice_fail "Docker is not installed or not running. Install Docker Engine 24 or newer (see docs/install-guide.md), then run this installer again."
    exit 1
  fi
  installed=$(<"$dir/VERSION")
  [[ "$installed" =~ $alice_version_re ]] || {
    alice_fail "The file $dir/VERSION does not hold a version."
    exit 1
  }
  env_project=$(alice_env_get COMPOSE_PROJECT_NAME "$dir/.env")
  alice_valid_project "$env_project" || {
    alice_fail "The project name in $dir/.env is not valid."
    exit 1
  }
  alice_dir=$dir
  alice_project=$env_project
  env_hosts=$(alice_env_get ALICE_TLS_HOSTS "$dir/.env")
  env_bind=$(alice_env_get ALICE_BIND "$dir/.env")
  env_port=$(alice_env_get ALICE_PORT "$dir/.env")
  env_zone=$(alice_env_get ALICE_TZ "$dir/.env")
  if ! alice_validate_env_values "$env_hosts" "$env_bind" "$env_port" "$env_project" 2>&1 | alice_log_stream; then
    alice_fail "The file $dir/.env holds a value that is not valid (see above)."
    exit 1
  fi
  alice_valid_zone "$env_zone" || env_zone=UTC
  recover_release_keys

  intake_space
  intake
  new=$rel_version
  cmp=$(alice_version_cmp "$new" "$installed")
  if [[ "$cmp" == 0 ]]; then
    alice_log "This installation is already at version $installed."
    exit 1
  elif [[ "$cmp" == -1 ]]; then
    alice_log "Going back to an older version is only possible by restoring a backup."
    exit 1
  fi
  if [[ -n "$rel_min" && "$(alice_version_cmp "$installed" "$rel_min")" == -1 ]]; then
    alice_log "Alice $installed cannot be updated directly to $new. Install $rel_min first."
    exit 1
  fi
  if [[ "$rel_test_signed" == 1 ]]; then alice_warn "$alice_test_warning"; fi

  if ! alice_quiet "$dir/alicectl" selfcheck </dev/null; then
    alice_log "Alice is not healthy now (selfcheck failed). Fix it before updating; see $log."
    exit 1
  fi
  alice_ok "Alice is healthy"

  db=$(alice_compose exec -T postgres psql -U postgres -d postgres -tA -c "SELECT pg_database_size('alice')" </dev/null 2>/dev/null | tr -d ' \r') || db=""
  [[ "$db" =~ ^[0-9]+$ ]] || db=0
  avail=$(df -B1 --output=avail -- "$dir" 2>/dev/null | tail -n 1 | tr -d ' ') || avail=0
  [[ "$avail" =~ ^[0-9]+$ ]] || avail=0
  need=$((2 * db + 5 * 1073741824))
  if ((avail < need)); then
    gb_free=$((avail / 1073741824))
    gb_need=$(((need + 1073741823) / 1073741824))
    alice_log "Not enough free disk space in $dir: $gb_free GB free, $gb_need GB needed for the update."
    exit 1
  fi
  alice_ok "Free disk space for the update"
}

read_passphrase() {
  local rc=0
  if [[ -n "$passphrase_file" ]]; then
    alice_read_passphrase_file "$passphrase_file" || rc=$?
    if ((rc != 0)); then exit 2; fi
  elif [[ -t 0 ]]; then
    IFS= read -r -s -p "Recovery passphrase (needed for the automatic backup): " alice_pass </dev/tty || true
    printf '\n'
  fi
  if [[ -z "$alice_pass" ]]; then
    printf 'A passphrase is needed. Run this command in a terminal, or pass --passphrase-file.\n' >&2
    exit 2
  fi
}

backup_and_verify() {
  local out name
  backup_time=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
  out=$("$dir/alicectl" backup --reason "pre-upgrade-$new" </dev/null 2>&1) || {
    alice_log_write "$out"
    alice_fail "The pre-update backup failed."
    return 1
  }
  alice_log_write "$out"
  if ! [[ "$out" =~ Backup\ written:\ /opt/alice/backups/([A-Za-z0-9._-]+\.alicebak)\  ]]; then
    alice_fail "The pre-update backup did not report its file."
    return 1
  fi
  name=${BASH_REMATCH[1]}
  backup_host="$dir/backups/$name"
  alice_ok "Backup written: $backup_host"
  if ! printf '%s\n' "$alice_pass" | alice_quiet "$dir/alicectl" backup verify "$backup_host" --deep --passphrase-stdin; then
    alice_fail "The pre-update backup could not be opened with this passphrase."
    return 1
  fi
  alice_ok "Backup verified with the passphrase"
}

save_rollback() {
  local f
  rollback="$dir/rollback/$installed"
  if [[ ! -d "$dir/rollback" ]]; then install -d -m 0700 -- "$dir/rollback" || return 1; fi
  rm -rf -- "$rollback" || return 1
  install -d -m 0700 -- "$rollback" || return 1
  for f in docker-compose.yml .env RELEASE VERSION install.sh alice-update.sh alicectl lib release-keys; do
    if [[ -e "$dir/$f" ]]; then cp -a -- "$dir/$f" "$rollback/$f" || return 1; fi
  done
  alice_ok "Rollback copy in $rollback"
}

load_images() {
  local id
  alice_quiet alice_docker load -i "$pkg/images/alice-$new.tar" || return 1
  alice_quiet alice_docker load -i "$pkg/images/postgres-$new.tar" || return 1
  id=$(alice_docker image inspect --format '{{.Id}}' "$rel_alice_image" 2>/dev/null) || id=""
  alice_image_id_ok "$id" "$rel_alice_id" "$rel_alice_digest" || {
    alice_fail "$alice_damaged"
    return 1
  }
  id=$(alice_docker image inspect --format '{{.Id}}' "$rel_pg_image" 2>/dev/null) || id=""
  alice_image_id_ok "$id" "$rel_pg_id" "$rel_pg_digest" || {
    alice_fail "$alice_damaged"
    return 1
  }
  alice_ok "Images of $new loaded and checked"
}

# new_configuration installs the new compose file and .env (image tags from the new RELEASE, the
# other values kept and checked again, S-9).
new_configuration() {
  install -m 0644 -- "$pkg/docker-compose.yml" "$dir/docker-compose.yml" || return 1
  alice_write_env "$dir/.env" "$alice_project" "$rel_alice_image" "$rel_pg_image" "$env_bind" "$env_port" "$env_hosts" "$env_zone"
}

migrate_and_start() {
  alice_log "Updating the database."
  alice_quiet alice_wait_healthy postgres || return 1
  alice_quiet alice_compose run --pull never --rm -T migrate </dev/null || return 1
  alice_log "Starting Alice $new."
  alice_quiet alice_wait_healthy alice || return 1
  alice_quiet "$dir/alicectl" selfcheck </dev/null || {
    alice_fail "Alice $new is not healthy (selfcheck failed)."
    return 1
  }
}

# replace_release_keys replaces release-keys/ with the keys of the new release, not merging them
# (S-35): release-keys.new is written completely, then put in place by renames only, so there is
# no moment with a partly written key directory. When the second rename fails the old keys are
# renamed back; recover_release_keys repairs a crash between the two renames.
replace_release_keys() {
  local f k=$dir/release-keys
  rm -rf -- "$k.new" "$k.old" || return 1
  install -d -m 0755 -- "$k.new" || return 1
  for f in "$pkg"/release-keys/rk-*.pem; do
    if [[ -f "$f" ]]; then install -m 0644 -- "$f" "$k.new/" || return 1; fi
  done
  mv -T -- "$k" "$k.old" || return 1
  if ! mv -T -- "$k.new" "$k"; then
    mv -T -- "$k.old" "$k"
    return 1
  fi
  rm -rf -- "$k.old"
}

# finish installs the files of the new release.
finish() {
  local f
  for f in install.sh alice-update.sh alicectl; do install -m 0755 -- "$pkg/$f" "$dir/$f"; done
  install -m 0644 -- "$pkg/lib/alice-lib.sh" "$dir/lib/alice-lib.sh"
  if [[ ! -d "$dir/lib/initdb" ]]; then install -d -m 0755 -- "$dir/lib/initdb"; fi
  install -m 0644 -- "$pkg/lib/initdb/10-alice-roles.sh" "$dir/lib/initdb/10-alice-roles.sh"
  replace_release_keys
  alice_copy_extras "$pkg" "$dir"
  install -m 0644 -- "$pkg/RELEASE" "$dir/RELEASE"
  install -m 0644 -- "$pkg/VERSION" "$dir/VERSION"
}

main() {
  parse_args "$@"
  trap 'on_interrupt' INT TERM
  trap 'on_error "$LINENO"' ERR
  preflight
  read_passphrase

  stage=stopped
  alice_log "Stopping Alice $installed for the update."
  alice_quiet alice_compose stop alice </dev/null || fail_now
  alice_quiet alice_terminate_leftover_sessions </dev/null || alice_warn "Leftover database sessions could not be ended."
  backup_and_verify || fail_now
  save_rollback || fail_now
  load_images || fail_now

  stage=changed
  new_configuration || fail_now
  migrate_and_start || fail_now

  stage=finishing
  alice_pass=""
  finish
  alice_log "Alice is now version $new."
  exit 0
}

main "$@"
