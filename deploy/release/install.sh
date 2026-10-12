#!/usr/bin/env bash
# install.sh: installs Alice from this package (C4, spec §18.3). Run it as root from the extracted
# package: tar xzf alice-<version>.tar.gz && cd alice && sudo ./install.sh
#
# Steps: 1 preflight (every check, then stop when one failed; nothing is changed), 2 package check
# (signature, checksums, exact file list) and the release-key fingerprint confirmation, 3 layout,
# 4 secrets and master key, 5 image load and image-ID check, 6 start, 7 the one-time setup code
# (printed to the terminal only). Exit codes: 0 success, 1 failure, 2 usage.
#
# Test-only overrides (read in the preflight only, never passed to docker, announced with a
# [WARN] line on the terminal and in install.log): ALICE_PROC_DIR replaces /proc for the memory
# check, ALICE_DOCKER_SOCK replaces /var/run/docker.sock for the socket check.
#
# The package is copied first into a new root-only directory (mode 0700, beside the installation
# directory) and only that copy is checked, fingerprinted, installed and loaded: the extracted
# package belongs to whoever extracted it and may change while the installer waits for the
# operator (as alice-update.sh does, S-3). The copy is removed on exit.
set -Eeuo pipefail
umask 077
export LC_ALL=C

here=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/alice-lib.sh
. "$here/lib/alice-lib.sh"

dir=/opt/alice
port=443
bind=0.0.0.0
hostname_arg=""
non_interactive=0
fingerprint=""
restore_mode=0
uninstall=0
purge=0
confirm=""
project=alice
project_set=0
changed=0
failures=0
openssl_ok=0
package_ok=0
zone=UTC
stage=""
pkg=""

usage() {
  cat <<'USAGE'
Usage: sudo ./install.sh [--dir DIR] [--port N] [--bind ADDRESS] [--hostname NAME]
                         [--non-interactive --fingerprint HEX] [--restore-mode] [--project NAME]
       sudo ./install.sh --uninstall [--purge [--confirm DELETE]] [--dir DIR]

  --dir DIR           installation directory (default /opt/alice)
  --port N            HTTPS port (default 443)
  --bind ADDRESS      publish the port on this local address only (default: every address)
  --hostname NAME     host name(s) of the certificate and the printed address, comma-separated
                      (default: hostname -f)
  --non-interactive   ask nothing; needs --fingerprint with the release-key fingerprint your
                      vendor published (64 hex characters)
  --restore-mode      prepare an empty installation for a restore (no master key; only the
                      database is started)
  --project NAME      Docker Compose project name (default alice); no other containers may use
                      it. With --uninstall it may only repeat the name in DIR/.env
  --uninstall         stop Alice and remove its containers; data and backups stay
  --purge             with --uninstall: also delete DIR with all data and backups
  --confirm DELETE    with --purge: confirm without a prompt
USAGE
}

usage_error() {
  printf '%s\n' "$1" >&2
  printf 'Run ./install.sh --help for the options.\n' >&2
  exit 2
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      --dir | --port | --bind | --hostname | --fingerprint | --confirm | --project)
        (($# >= 2)) || usage_error "$1 needs a value."
        case "$1" in
          --dir) dir=$2 ;;
          --port) port=$2 ;;
          --bind) bind=$2 ;;
          --hostname) hostname_arg=$2 ;;
          --fingerprint) fingerprint=$2 ;;
          --confirm) confirm=$2 ;;
          --project) project=$2; project_set=1 ;;
        esac
        shift 2
        ;;
      --non-interactive) non_interactive=1; shift ;;
      --restore-mode) restore_mode=1; shift ;;
      --uninstall) uninstall=1; shift ;;
      --purge) purge=1; shift ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) usage_error "Unknown option: $1" ;;
    esac
  done
}

# check_args validates every option before anything is read or changed (S-9).
check_args() {
  [[ "$dir" == /* ]] || usage_error "--dir needs an absolute path."
  dir=$(realpath -m -- "$dir")
  [[ "$dir" != / ]] || usage_error "--dir cannot be /."
  [[ "$dir" != *[[:cntrl:]]* ]] || usage_error "--dir may not contain control characters."
  if ((purge == 1 && uninstall == 0)); then usage_error "--purge needs --uninstall."; fi
  if [[ -n "$confirm" && "$purge" == 0 ]]; then usage_error "--confirm needs --purge."; fi
  if ((uninstall == 1)); then return 0; fi
  if [[ -z "$hostname_arg" ]]; then
    hostname_arg=$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)
  fi
  if ! alice_validate_env_values "$hostname_arg" "$bind" "$port" "$project"; then
    usage_error "Fix the value above (or pass --hostname, --bind, --port or --project)."
  fi
  if ((non_interactive == 1)); then
    fingerprint=${fingerprint,,}
    [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] ||
      usage_error "--non-interactive needs --fingerprint with the 64 hex characters of the release-key fingerprint your vendor published."
  fi
}

# check_dir_safe refuses a --dir that another user could change (S-8): every existing ancestor,
# and the directory itself when it exists, must be owned by root and not group- or world-writable.
check_dir_safe() {
  local p=$dir info uid mode
  if [[ ! -e "$p" ]]; then p=$(dirname -- "$p"); fi
  while :; do
    if [[ -e "$p" ]]; then
      info=$(stat -c '%u %a' -- "$p") || info="unknown 777"
      uid=${info%% *}
      mode=${info##* }
      if [[ "$uid" != 0 ]] || ((8#$mode & 8#022)); then
        alice_fail "The installation directory $dir has a parent that other users can change ($p). Choose another --dir."
        exit 2
      fi
    fi
    [[ "$p" != / ]] || break
    p=$(dirname -- "$p")
  done
}

# shellcheck disable=SC2329 # called from the EXIT trap
cleanup() {
  if [[ -n "$stage" && -d "$stage" ]]; then rm -rf -- "$stage"; fi
}

# stage_package copies the package into a new root-only directory on the file system of the
# installation (the nearest existing ancestor of --dir, which check_dir_safe found safe) and sets
# pkg to the copy.
stage_package() {
  local p
  p=$(dirname -- "$dir")
  while [[ ! -d "$p" ]]; do p=$(dirname -- "$p"); done
  stage=$(mktemp -d -- "$p/.alice-install-XXXXXX" 2>/dev/null) || {
    stage=""
    return 1
  }
  cp -a --no-preserve=ownership -- "$here" "$stage/alice" 2>/dev/null || return 1
  pkg="$stage/alice"
}

on_error() {
  local line=$1
  if [[ "$BASHPID" != "$$" ]]; then return 0; fi
  trap - ERR
  if ((changed == 0)); then
    alice_log "Unexpected error (line $line). Nothing was changed."
  else
    alice_log "Unexpected error (line $line). Alice was not installed completely. Send $dir/install.log to support."
  fi
  exit 1
}

on_interrupt() {
  trap '' INT TERM
  if ((changed == 0)); then
    alice_log "Interrupted. Nothing was changed."
  else
    alice_log "Interrupted. Alice was not installed completely. Send $dir/install.log to support."
  fi
  exit 1
}

fail_check() {
  alice_fail "$1"
  failures=$((failures + 1))
}

preflight() {
  local proc_dir=/proc sock=/var/run/docker.sock m ver major mode avail parent p kb gb cpus line proc pid
  local year build_year ntp reported docker_ok=0 rc ids
  if [[ -n "${ALICE_PROC_DIR:-}" ]]; then
    alice_warn "Test override ALICE_PROC_DIR is set; results of this check are not real."
    proc_dir=$ALICE_PROC_DIR
  fi
  if [[ -n "${ALICE_DOCKER_SOCK:-}" ]]; then
    alice_warn "Test override ALICE_DOCKER_SOCK is set; results of this check are not real."
    sock=$ALICE_DOCKER_SOCK
  fi
  unset ALICE_PROC_DIR ALICE_DOCKER_SOCK

  if [[ "$(id -u)" == 0 ]]; then
    alice_ok "Running as root"
  else
    fail_check "This installer must be run with administrator rights. Run it again as: sudo ./install.sh"
  fi

  m=$(uname -m)
  if [[ "$m" == x86_64 ]]; then
    alice_ok "Linux x86_64"
  else
    fail_check "Alice needs a 64-bit Intel/AMD Linux server. This machine is $m."
  fi

  if ver=$(alice_docker version --format '{{.Server.Version}}' 2>/dev/null) && [[ -n "$ver" ]]; then
    alice_ok "Docker installed and running"
    docker_ok=1
  else
    fail_check "Docker is not installed or not running. Install Docker Engine 24 or newer (see docs/install-guide.md), then run this installer again."
  fi

  if ((docker_ok == 1)); then
    major=${ver%%.*}
    if ! [[ "$major" =~ ^[0-9]+$ ]] || ((10#$major < 24)); then
      fail_check "Your Docker is too old (found $ver). Alice needs version 24 or newer."
    elif ! alice_docker compose version >/dev/null 2>&1; then
      fail_check "The Docker compose plugin is missing. Install docker-compose-plugin (see docs/install-guide.md), then run this installer again."
    else
      alice_ok "Docker 24 or newer with the compose plugin"
    fi
    if mode=$(stat -L -c '%a' -- "$sock" 2>/dev/null); then
      if ((8#$mode & 8#006)); then
        fail_check "The Docker socket $sock can be used by every user on this server. Restrict it to the docker group (chmod 660), then run this installer again."
      else
        alice_ok "Docker socket restricted"
      fi
    else
      fail_check "Docker is not installed or not running. Install Docker Engine 24 or newer (see docs/install-guide.md), then run this installer again."
    fi
  fi

  if [[ "$(openssl version 2>/dev/null || true)" =~ ^OpenSSL\ [3-9]\. ]]; then
    alice_ok "OpenSSL 3"
    openssl_ok=1
  else
    fail_check "OpenSSL 3 is needed to check the package signature. Install the openssl package, then run this installer again."
  fi

  parent=$(dirname -- "$dir")
  p=$parent
  while [[ ! -d "$p" ]]; do p=$(dirname -- "$p"); done
  avail=$(df -B1 --output=avail -- "$p" 2>/dev/null | tail -n 1 | tr -d ' ') || avail=0
  [[ "$avail" =~ ^[0-9]+$ ]] || avail=0
  gb=$((avail / 1073741824))
  if ((gb >= 20)); then
    alice_ok "Free disk ≥ 20 GB"
  else
    fail_check "Not enough free disk space in $parent: $gb GB free, 20 GB needed."
  fi

  reported=0
  kb=$(sed -n 's/^MemTotal: *\([0-9]*\) kB$/\1/p' -- "$proc_dir/meminfo" 2>/dev/null || true)
  [[ "$kb" =~ ^[0-9]+$ ]] || kb=0
  gb=$((kb / 1048576))
  if ((kb < 3 * 1048576)); then
    fail_check "This server has $gb GB of memory. Alice needs at least 4 GB."
    reported=1
  elif ((kb < 4 * 1048576)); then
    alice_warn "This server has $gb GB of memory. Alice needs at least 4 GB."
    reported=1
  fi
  cpus=$(nproc 2>/dev/null || echo 0)
  [[ "$cpus" =~ ^[0-9]+$ ]] || cpus=0
  if ((cpus < 2)); then
    fail_check "This server has $cpus CPU. Alice needs at least 2."
    reported=1
  fi
  if ((reported == 0)); then alice_ok "Memory ≥ 4 GB, CPU ≥ 2"; fi

  line=$(ss -H -ltnp "sport = :$port" 2>/dev/null | head -n 1 || true)
  if [[ -z "$line" ]]; then
    alice_ok "Port free"
  else
    proc=unknown
    pid=unknown
    if [[ "$line" =~ users:\(\(\"([^\"]*)\",pid=([0-9]+) ]]; then
      proc=${BASH_REMATCH[1]}
      pid=${BASH_REMATCH[2]}
    fi
    fail_check "Another program is already using port $port ($proc, pid $pid). Stop it or run the installer with --port 8443."
  fi

  if ((openssl_ok == 1)); then
    rc=0
    if ! stage_package; then
      rc=4
    else
      alice_check_package "$pkg" "$pkg/release-keys" || rc=$?
      if ((rc == 0)) && ! alice_read_release "$pkg"; then rc=2; fi
    fi
    case "$rc" in
      0)
        alice_ok "Package signature"
        alice_ok "Package complete"
        alice_ok "Package lists exactly its files"
        package_ok=1
        ;;
      1) fail_check "The package signature is not valid. Do not install this package; download it again and check it with your vendor." ;;
      2)
        alice_ok "Package signature"
        fail_check "$alice_damaged"
        ;;
      4) fail_check "The package could not be copied next to $dir for checking. Check the free disk space, then run this installer again." ;;
      *)
        alice_ok "Package signature"
        alice_ok "Package complete"
        fail_check "$alice_damaged"
        ;;
    esac
  fi

  reported=0
  year=$(date -u +%Y)
  if ((package_ok == 1)); then
    build_year=${rel_build_time:0:4}
    if [[ "$build_year" =~ ^[0-9]{4}$ ]] && ((10#$year < 10#$build_year)); then
      fail_check "The server clock looks wrong (it says $year). Fix the date/time first; licenses depend on it."
      reported=1
    fi
  fi
  ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
  if [[ "$ntp" != yes ]]; then
    alice_warn "Alice could not confirm that the clock is synchronised. Make sure NTP is running; licenses depend on the time."
    reported=1
  fi
  if ((reported == 0)); then alice_ok "Clock sane"; fi

  # Containers of the same compose project, from another directory, would be taken over by
  # "up" and removed by "down": the project must be unused (the default name alice included).
  ids=""
  if ((docker_ok == 1)); then
    ids=$(alice_docker ps -a -q --filter "label=com.docker.compose.project=$project" 2>/dev/null) || ids="?"
  fi
  if [[ -e "$dir/docker-compose.yml" || -e "$dir/VERSION" ]]; then
    fail_check "Alice is already installed in $dir. To upgrade use ./alice-update.sh."
  elif [[ "$ids" == "?" ]]; then
    fail_check "The containers of the project $project could not be listed. Check that Docker is running, then run this installer again."
  elif [[ -n "$ids" ]]; then
    fail_check "Docker already has containers of the project $project. Choose another --project, or update the installation that uses it with its own alice-update.sh."
  else
    alice_ok "No installation yet"
  fi

  if ((failures > 0)); then exit 1; fi

  if [[ "$rel_test_signed" == 1 ]]; then alice_warn "$alice_test_warning"; fi
  zone=$(timedatectl show -p Timezone --value 2>/dev/null || true)
  if ! alice_valid_zone "$zone"; then
    alice_warn "The time zone of this server could not be read; Alice uses UTC."
    zone=UTC
  fi
}

# confirm_fingerprint shows the release key that signed the package and asks the operator to
# compare it with the fingerprint the vendor published (S-23).
confirm_fingerprint() {
  local fp key_id answer=""
  fp=$(alice_fingerprint "$alice_sig_key")
  key_id=$(basename -- "$alice_sig_key" .pem)
  alice_log "Package signed by release key $key_id (SHA-256 fingerprint $fp). Compare this fingerprint with the one your vendor published."
  if ((non_interactive == 1)); then
    if [[ "$fp" != "$fingerprint" ]]; then
      alice_log "The package fingerprint does not match --fingerprint. Nothing was changed."
      exit 1
    fi
    return 0
  fi
  printf 'Does this fingerprint match the one your vendor published? Type yes to continue: '
  IFS= read -r answer || true
  alice_log_write "Does this fingerprint match the one your vendor published? Type yes to continue: $answer"
  if [[ "$answer" != yes ]]; then
    alice_log "Nothing was changed."
    exit 1
  fi
}

# make_dir PATH MODE [OWNER] creates a directory that does not exist yet; an existing symbolic
# link is refused and an existing directory is left as it is (S-8).
make_dir() {
  if [[ -L "$1" ]]; then
    alice_fail "$1 is a symbolic link. Remove it, then run this installer again."
    exit 1
  fi
  if [[ ! -d "$1" ]]; then
    install -d -m "$2" -- "$1"
    if (($# > 2)); then chown "$3" -- "$1"; fi
  fi
}

# new_file PATH writes standard input to PATH, which must not exist yet.
new_file() {
  (set -o noclobber && cat >"$1")
}

layout() {
  local f
  make_dir "$dir" 0750
  alice_log_open "$dir/install.log"
  alice_log "Installing Alice $rel_version in $dir."
  for f in secrets rollback; do make_dir "$dir/$f" 0700; done
  for f in lib lib/initdb release-keys; do make_dir "$dir/$f" 0755; done
  make_dir "$dir/keys" 0700
  make_dir "$dir/state" 0700 10001:10001
  make_dir "$dir/backups" 0700 10001:10001
  make_dir "$dir/data" 0700
  make_dir "$dir/data/postgres" 0700 70:70

  install -m 0644 -- "$pkg/VERSION" "$dir/VERSION"
  install -m 0644 -- "$pkg/RELEASE" "$dir/RELEASE"
  for f in install.sh alice-update.sh alicectl; do install -m 0755 -- "$pkg/$f" "$dir/$f"; done
  install -m 0644 -- "$pkg/lib/alice-lib.sh" "$dir/lib/alice-lib.sh"
  install -m 0644 -- "$pkg/lib/initdb/10-alice-roles.sh" "$dir/lib/initdb/10-alice-roles.sh"
  for f in "$pkg"/release-keys/rk-*.pem; do
    if [[ -f "$f" ]]; then install -m 0644 -- "$f" "$dir/release-keys/"; fi
  done
  alice_copy_extras "$pkg" "$dir"
  alice_write_env "$dir/.env" "$project" "$rel_alice_image" "$rel_pg_image" "$bind" "$port" "$hostname_arg" "$zone"
  install -m 0644 -- "$pkg/docker-compose.yml" "$dir/docker-compose.yml"
}

# write_secret NAME OWNER MODE writes a new random database password (C2).
write_secret() {
  alice_random_password | new_file "$dir/secrets/$1"
  chown "$2" -- "$dir/secrets/$1"
  chmod "$3" -- "$dir/secrets/$1"
}

secrets() {
  write_secret db_postgres_password 70:70 0400
  write_secret db_owner_password 70:10001 0440
  write_secret db_app_password 70:10001 0440
  if ((restore_mode == 0)); then
    # 32 random bytes in base64 plus a newline: the format secrets.LoadOrCreateMasterKey adopts.
    head -c 32 /dev/urandom | base64 | new_file "$dir/keys/master.key"
    chown 10001:10001 -- "$dir/keys/master.key"
    chmod 0400 -- "$dir/keys/master.key"
    alice_log "The master key file is included in encrypted backups. Do not copy it by hand."
  fi
  chown 10001:10001 -- "$dir/keys"
  alice_log "Secrets written."
}

# ---- end of the layout step (S-8) ----
# From here on nothing reads, writes, chowns or chmods anything inside keys/, state/, backups/ or
# data/: code in a container can write there.

load_images() {
  local id
  alice_quiet alice_docker load -i "$pkg/images/alice-$rel_version.tar"
  alice_quiet alice_docker load -i "$pkg/images/postgres-$rel_version.tar"
  id=$(alice_docker image inspect --format '{{.Id}}' "$rel_alice_image" 2>/dev/null || true)
  if ! alice_image_id_ok "$id" "$rel_alice_id" "$rel_alice_digest"; then
    alice_fail "$alice_damaged"
    exit 1
  fi
  id=$(alice_docker image inspect --format '{{.Id}}' "$rel_pg_image" 2>/dev/null || true)
  if ! alice_image_id_ok "$id" "$rel_pg_id" "$rel_pg_digest"; then
    alice_fail "$alice_damaged"
    exit 1
  fi
  alice_ok "Images loaded and checked"
}

start_failed() {
  local s
  for s in postgres alice; do
    alice_log "---- last 30 log lines of $s ----"
    alice_compose logs --no-color --tail 30 "$s" 2>&1 | alice_log_stream || true
  done
  alice_log "Alice did not start. Send $dir/install.log to support."
  exit 1
}

start() {
  alice_log "Starting the database."
  alice_quiet alice_wait_healthy postgres || start_failed
  if ((restore_mode == 1)); then return 0; fi
  alice_log "Preparing the database."
  alice_quiet alice_compose run --pull never --rm -T migrate || start_failed
  alice_log "Starting Alice."
  alice_quiet alice_wait_healthy alice || start_failed
}

# closing prints the next steps with the one-time setup code to the terminal only (S-4).
closing() {
  local out code address
  if ((restore_mode == 1)); then
    : >"$dir/.restore-mode"
    alice_log "Alice is ready for a restore. Copy the backup file into $dir/backups, then run: sudo $dir/alicectl restore $dir/backups/<file>"
    return 0
  fi
  out=$(alice_compose exec -T alice /usr/local/bin/alice setup-token --reset 2>/dev/null) || out=""
  code=${out%%$'\n'*}
  code=${code#One-time setup code: }
  out=""
  if ! [[ "$code" =~ ^[A-Za-z0-9-]{4,64}$ ]]; then
    alice_log "Alice is running, but the setup code could not be read. Run: sudo $dir/alicectl setup-token --reset"
    return 0
  fi
  address="https://${hostname_arg%%,*}"
  if [[ "$port" != 443 ]]; then address="$address:$port"; fi
  alice_log_write "Alice $rel_version is installed and running."
  alice_log_write "Setup code printed to the terminal (not logged)."
  printf '\nAlice %s is installed and running.\n\n' "$rel_version"
  printf '  Open this address in your web browser:   %s/setup\n' "$address"
  printf '  (Your browser will warn about the certificate. This is expected until you\n'
  printf '   install your own certificate in the setup wizard.)\n\n'
  printf '  One-time setup code (needed once, write it down now, it is not shown again):\n\n'
  printf '       %s\n\n' "$code"
  printf '  The setup code stops working as soon as the first administrator is created.\n'
  printf '  Lost the code? Run:  sudo %s/alicectl setup-token --reset\n' "$dir"
  printf '  Daily backups are stored in %s/backups. Copy them to another machine.\n' "$dir"
  code=""
}

uninstall_alice() {
  local answer="" env_project
  if [[ "$(id -u)" != 0 ]]; then
    alice_fail "This installer must be run with administrator rights. Run it again as: sudo ./install.sh"
    exit 1
  fi
  if [[ ! -f "$dir/docker-compose.yml" || ! -f "$dir/VERSION" ]]; then
    alice_log "Alice is not installed in $dir."
    exit 1
  fi
  # Only the project recorded in .env is removed: --project may repeat it, never name another one.
  env_project=$(alice_env_get COMPOSE_PROJECT_NAME "$dir/.env" 2>/dev/null) || env_project=""
  alice_valid_project "$env_project" ||
    usage_error "The project name in $dir/.env is not valid. Fix COMPOSE_PROJECT_NAME there, then run this again."
  if ((project_set == 1)) && [[ "$project" != "$env_project" ]]; then
    usage_error "--project $project is not the project of the installation in $dir ($env_project). Leave out --project."
  fi
  project=$env_project
  alice_project=$project
  if ((purge == 1)) && [[ "$confirm" != DELETE ]]; then
    if [[ -z "$confirm" ]]; then
      printf 'This deletes %s with all data and backups. Type DELETE to continue: ' "$dir"
      IFS= read -r answer || true
    fi
    if [[ "$answer" != DELETE ]]; then
      alice_log "Nothing was deleted."
      exit 1
    fi
  fi
  # The lock of an update or restore (final review B M-4): never stop or delete under one.
  if ! alice_lock; then
    alice_lock_busy "[FAIL] "
    exit 1
  fi
  alice_compose down
  if ((purge == 1)); then
    rm -rf -- "$dir"
    alice_log "Alice and all its data were deleted from $dir."
  else
    alice_log "Alice was stopped and its containers removed. Your data and backups are still in $dir."
  fi
}

main() {
  parse_args "$@"
  check_args
  alice_dir=$dir
  alice_project=$project
  check_dir_safe
  trap 'cleanup' EXIT
  trap 'on_interrupt' INT TERM
  trap 'on_error "$LINENO"' ERR
  if ((uninstall == 1)); then
    uninstall_alice
    exit 0
  fi
  preflight
  confirm_fingerprint
  changed=1
  layout
  secrets
  load_images
  start
  closing
}

main "$@"
