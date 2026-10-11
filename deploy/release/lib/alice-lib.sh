# shellcheck shell=bash
# The globals below are set here and read by the scripts that source this file.
# shellcheck disable=SC2034
# Shared functions of install.sh, alice-update.sh and alicectl (C4). Each script sources this file
# from its own directory only (never from a package being installed); it is never executed.
#
# Rules kept by every function here: every expansion is quoted; nothing is evaluated; docker runs
# only through alice_docker/alice_compose with an emptied environment (S-6); a passphrase is kept in
# the unexported shell variable alice_pass and reaches a child only through the printf builtin on
# standard input (S-25); a key=value file is read with sed for allowlisted keys, never sourced.

set -Eeuo pipefail
umask 077

alice_dir=""     # the installation directory
alice_project="" # the compose project name (COMPOSE_PROJECT_NAME of .env)
alice_pass=""    # the recovery passphrase of this run (never exported)
alice_sig_key="" # the release key that verified the last alice_verify_sig/alice_check_package

alice_damaged="The installation package is damaged or incomplete. Download it again and compare the checksum."
alice_test_warning="This package is signed with a TEST key. Never install it for production."

# ---- output and log ----

alice_log_file=""
alice_log_pending=()

# File descriptor 3 is the script's own standard output: a message printed from a trap handler
# reaches the terminal even when the trap interrupted a command whose output goes to the log.
exec 3>&1

# alice_log_write LINE appends LINE to the log, or keeps it until alice_log_open.
alice_log_write() {
  if [[ -n "$alice_log_file" ]]; then
    printf '%s\n' "$1" >>"$alice_log_file"
  else
    alice_log_pending+=("$1")
  fi
}

# alice_log_open FILE starts the log (mode 0600) and writes the lines kept so far.
alice_log_open() {
  local f=$1 l
  if [[ -L "$f" ]]; then
    printf 'The log file %s is a symbolic link.\n' "$f" >&2
    return 1
  fi
  : >>"$f"
  chmod 0600 -- "$f"
  alice_log_file=$f
  for l in "${alice_log_pending[@]}"; do printf '%s\n' "$l" >>"$f"; done
  alice_log_pending=()
}

# alice_log LINE prints LINE and appends it to the log.
alice_log() {
  printf '%s\n' "$1" >&3
  alice_log_write "$1"
}

alice_ok() { alice_log "[ OK ] $1"; }
alice_warn() { alice_log "[WARN] $1"; }
alice_fail() { alice_log "[FAIL] $1"; }

# alice_log_stream prints and logs every line of its standard input.
alice_log_stream() {
  local l
  while IFS= read -r l || [[ -n "$l" ]]; do alice_log "$l"; done
}

# alice_quiet CMD... runs CMD with its output appended to the log only (or discarded without a log).
alice_quiet() {
  if [[ -n "$alice_log_file" ]]; then
    "$@" >>"$alice_log_file" 2>&1
  else
    "$@" >/dev/null 2>&1
  fi
}

# ---- docker (S-6) ----

# alice_docker ARGS... runs docker with only PATH, HOME and LC_ALL in its environment, so variables
# such as ALICE_IMAGE, COMPOSE_FILE, DOCKER_HOST or DOCKER_CONFIG of the caller never reach it.
alice_docker() {
  env -i PATH="$PATH" HOME=/root LC_ALL=C docker "$@" 3>&- 9>&-
}

# alice_compose ARGS... runs docker compose for the installation in alice_dir.
alice_compose() {
  alice_docker compose --project-name "$alice_project" -f "$alice_dir/docker-compose.yml" \
    --env-file "$alice_dir/.env" "$@"
}

# alice_wait_healthy SERVICE starts SERVICE and waits up to 180 s until it is healthy.
alice_wait_healthy() {
  alice_compose up --pull never -d --wait --wait-timeout 180 "$1"
}

# alice_running reports whether the alice container runs.
alice_running() {
  local s
  s=$(alice_compose ps --status running --services 2>/dev/null) || return 1
  [[ $'\n'"$s"$'\n' == *$'\n'alice$'\n'* ]]
}

# alice_terminate_leftover_sessions ends the sessions of alice_app and alice_owner on database
# alice (M-4). Alice is stopped when this runs, so these can only be leftovers such as a killed
# migrate container; only the postgres superuser may end them.
alice_terminate_leftover_sessions() {
  alice_compose exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'alice' AND usename IN ('alice_app','alice_owner')"
}

# ---- the installation lock ----

# alice_lock_busy PREFIX prints why the lock could not be taken.
alice_lock_busy() {
  printf '%sAnother update or restore of Alice is running in %s. Wait until it has finished, then run this again.\n' "$1" "$alice_dir"
}

# alice_lock takes the lock of the installation in alice_dir without waiting: an flock on the file
# .lock, open on file descriptor 9 until the script ends. One update or restore runs at a time. A
# child that inherited descriptor 9 from the parent holding the lock (the alicectl restore of an
# update's rollback) shares that lock: flock on the same open file succeeds again.
alice_lock() {
  if ! [[ /dev/fd/9 -ef "$alice_dir/.lock" ]]; then
    if [[ -L "$alice_dir/.lock" ]]; then return 1; fi
    exec 9>>"$alice_dir/.lock" || return 1
  fi
  flock -n 9
}

# ---- versions ----

alice_version_re='^([0-9]+)\.([0-9]+)\.([0-9]+)(-rc\.([0-9]+))?$'

# alice_num_cmp A B compares two decimal numbers of any length; prints -1, 0 or 1.
alice_num_cmp() {
  local a=$1 b=$2
  a=${a#"${a%%[!0]*}"}
  b=${b#"${b%%[!0]*}"}
  if ((${#a} != ${#b})); then
    if ((${#a} > ${#b})); then echo 1; else echo -1; fi
  elif [[ "$a" > "$b" ]]; then
    echo 1
  elif [[ "$a" < "$b" ]]; then
    echo -1
  else
    echo 0
  fi
}

# alice_version_cmp A B prints -1, 0 or 1 (C4); a value that is not a version is a usage error
# (return 2). A release candidate is lower than its release; rc.N compares numerically.
alice_version_cmp() {
  local -a pa pb
  local i r
  if ! [[ "$1" =~ $alice_version_re ]]; then
    printf 'Not a version: %s\n' "$1" >&2
    return 2
  fi
  pa=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[5]}")
  if ! [[ "$2" =~ $alice_version_re ]]; then
    printf 'Not a version: %s\n' "$2" >&2
    return 2
  fi
  pb=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[5]}")
  for i in 0 1 2; do
    r=$(alice_num_cmp "${pa[i]}" "${pb[i]}")
    if [[ "$r" != 0 ]]; then
      echo "$r"
      return 0
    fi
  done
  if [[ -z "${pa[3]}" && -z "${pb[3]}" ]]; then
    echo 0
  elif [[ -z "${pa[3]}" ]]; then
    echo 1
  elif [[ -z "${pb[3]}" ]]; then
    echo -1
  else
    alice_num_cmp "${pa[3]}" "${pb[3]}"
  fi
}

# ---- key=value files (RELEASE, .env) ----

alice_release_keys=" VERSION MIN_UPGRADE_FROM SCHEMA_VERSION ALICE_IMAGE ALICE_IMAGE_ID POSTGRES_IMAGE POSTGRES_IMAGE_ID BUILD_COMMIT BUILD_TIME RELEASE_KEY_ID TEST_SIGNED "
alice_env_keys=" COMPOSE_PROJECT_NAME ALICE_IMAGE POSTGRES_IMAGE ALICE_BIND ALICE_PORT ALICE_TLS_HOSTS ALICE_TZ "

# alice_kv_get KEY FILE prints the value of the first KEY= line (KEY is allowlisted by the callers).
alice_kv_get() {
  sed -n "/^$1=/{s/^$1=//;p;q;}" -- "$2"
}

# alice_release_get KEY FILE reads one value of a RELEASE file (C5).
alice_release_get() {
  if [[ "$alice_release_keys" != *" $1 "* ]]; then
    printf 'Unknown RELEASE key: %s\n' "$1" >&2
    return 2
  fi
  alice_kv_get "$1" "$2"
}

# alice_env_get KEY FILE reads one value of an installation's .env.
alice_env_get() {
  if [[ "$alice_env_keys" != *" $1 "* ]]; then
    printf 'Unknown .env key: %s\n' "$1" >&2
    return 2
  fi
  alice_kv_get "$1" "$2"
}

# alice_read_release PKGDIR checks the RELEASE and VERSION of a verified package and sets the
# rel_* variables; it fails when a value has the wrong form or an image file is missing.
alice_read_release() {
  local d=$1 v
  rel_version=$(alice_release_get VERSION "$d/RELEASE") || return 1
  rel_min=$(alice_release_get MIN_UPGRADE_FROM "$d/RELEASE") || return 1
  rel_alice_image=$(alice_release_get ALICE_IMAGE "$d/RELEASE") || return 1
  rel_alice_id=$(alice_release_get ALICE_IMAGE_ID "$d/RELEASE") || return 1
  rel_pg_image=$(alice_release_get POSTGRES_IMAGE "$d/RELEASE") || return 1
  rel_pg_id=$(alice_release_get POSTGRES_IMAGE_ID "$d/RELEASE") || return 1
  rel_build_time=$(alice_release_get BUILD_TIME "$d/RELEASE") || return 1
  rel_test_signed=$(alice_release_get TEST_SIGNED "$d/RELEASE") || return 1
  [[ "$rel_version" =~ $alice_version_re ]] || return 1
  [[ -z "$rel_min" || "$rel_min" =~ $alice_version_re ]] || return 1
  [[ "$rel_alice_image" =~ ^[a-z0-9][a-z0-9._/-]{0,127}:[A-Za-z0-9._-]{1,128}$ ]] || return 1
  [[ "$rel_pg_image" =~ ^[a-z0-9][a-z0-9._/-]{0,127}:[A-Za-z0-9._-]{1,128}$ ]] || return 1
  [[ "$rel_alice_id" =~ ^sha256:[0-9a-f]{64}$ && "$rel_pg_id" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  v=$(<"$d/VERSION")
  [[ "$v" == "$rel_version" ]] || return 1
  [[ -f "$d/images/alice-$rel_version.tar" && -f "$d/images/postgres-$rel_version.tar" ]] || return 1
  [[ -f "$d/docker-compose.yml" ]] || return 1
}

# ---- values written into .env (S-9) ----

alice_valid_hosts() {
  local rest=$1 h
  while :; do
    h=${rest%%,*}
    [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || return 1
    [[ "$rest" == *,* ]] || return 0
    rest=${rest#*,}
  done
}

alice_valid_bind() {
  local o='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
  [[ "$1" =~ ^$o\.$o\.$o\.$o$ ]] && return 0
  [[ "$1" == *:*:* && "$1" =~ ^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$ ]]
}

alice_valid_port() {
  [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535))
}

alice_valid_project() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]
}

alice_valid_zone() {
  [[ "$1" =~ ^[A-Za-z0-9/_+-]{1,64}$ ]]
}

# alice_validate_env_values HOSTS BIND PORT PROJECT prints the first bad value and returns 2.
alice_validate_env_values() {
  if ! alice_valid_hosts "$1"; then
    printf 'Not a valid host name (letters, digits, dots and hyphens; several separated by commas): %s\n' "$1" >&2
    return 2
  fi
  if ! alice_valid_bind "$2"; then
    printf 'Not an IPv4 or IPv6 address: %s\n' "$2" >&2
    return 2
  fi
  if ! alice_valid_port "$3"; then
    printf 'Not a port number (1 to 65535): %s\n' "$3" >&2
    return 2
  fi
  if ! alice_valid_project "$4"; then
    printf 'Not a valid project name (lower-case letters, digits, _ and -; 63 at most): %s\n' "$4" >&2
    return 2
  fi
}

# alice_write_env FILE PROJECT ALICE_IMAGE POSTGRES_IMAGE BIND PORT HOSTS ZONE writes .env (0640).
alice_write_env() {
  local f=$1
  {
    printf '# Written by install.sh; no secret belongs in this file.\n'
    printf 'COMPOSE_PROJECT_NAME=%s\n' "$2"
    printf 'ALICE_IMAGE=%s\n' "$3"
    printf 'POSTGRES_IMAGE=%s\n' "$4"
    printf 'ALICE_BIND=%s\n' "$5"
    printf 'ALICE_PORT=%s\n' "$6"
    printf 'ALICE_TLS_HOSTS=%s\n' "$7"
    printf 'ALICE_TZ=%s\n' "$8"
  } >"$f.new" || return 1
  chmod 0640 -- "$f.new" || return 1
  mv -f -- "$f.new" "$f"
}

# alice_random_password prints 32 random bytes as base64url without padding (43 characters).
alice_random_password() {
  head -c 32 /dev/urandom | base64 -w 0 | tr '+/' '-_' | tr -d '='
}

# ---- signatures and packages (C5, S-7) ----

# alice_verify_sig FILE SIG KEYDIR succeeds when one release key of KEYDIR verifies SIG over FILE;
# alice_sig_key names that key.
alice_verify_sig() {
  local key
  alice_sig_key=""
  for key in "$3"/*.pem; do
    [[ -f "$key" && ! -L "$key" ]] || continue
    if openssl pkeyutl -verify -pubin -inkey "$key" -rawin -in "$1" -sigfile "$2" >/dev/null 2>&1; then
      alice_sig_key=$key
      return 0
    fi
  done
  return 1
}

# alice_fingerprint KEY prints the SHA-256 of the DER form of a public key (64 hex).
alice_fingerprint() {
  local out
  out=$(openssl pkey -pubin -in "$1" -outform DER | sha256sum) || return 1
  printf '%s\n' "${out%% *}"
}

# alice_check_package DIR KEYDIR checks an extracted package in the S-7 order and reads nothing
# else of it before: 1 the signature of SHA256SUMS by a key of KEYDIR; 2 no symbolic link, special
# file or unusual file name, and every checksum; 3 the files are exactly those of SHA256SUMS.
# Returns 0, or the number of the failed step.
alice_check_package() {
  local d=$1 listed found
  [[ -f "$d/SHA256SUMS" && ! -L "$d/SHA256SUMS" && -f "$d/SHA256SUMS.sig" && ! -L "$d/SHA256SUMS.sig" ]] || return 1
  alice_verify_sig "$d/SHA256SUMS" "$d/SHA256SUMS.sig" "$2" || return 1
  # A symbolic link or a FIFO is refused before sha256sum would follow or block on it.
  found=$(cd -- "$d" && find . ! -type f ! -type d) || return 2
  [[ -z "$found" ]] || return 2
  found=$(cd -- "$d" && find . -name '*[!A-Za-z0-9._+-]*') || return 2
  [[ -z "$found" ]] || return 2
  if grep -Evq '^[0-9a-f]{64}  [A-Za-z0-9._+-][A-Za-z0-9._/+-]*$' "$d/SHA256SUMS"; then return 2; fi
  if grep -Eq '  (.*/)?\.\.(/|$)|//' "$d/SHA256SUMS"; then return 2; fi
  (cd -- "$d" && sha256sum -c --strict --quiet SHA256SUMS) >/dev/null 2>&1 || return 2
  listed=$(sed 's/^[0-9a-f]\{64\}  //; s|^\./||' "$d/SHA256SUMS" | LC_ALL=C sort)
  found=$(cd -- "$d" && find . -type f ! -path ./SHA256SUMS ! -path ./SHA256SUMS.sig | sed 's|^\./||' | LC_ALL=C sort) || return 3
  [[ "$listed" == "$found" ]] || return 3
}

# alice_copy_extras SRC DST copies the documents of a verified package (docs, licenses, sbom,
# helper, CHANGELOG.md) with modes 0755 for directories and 0644 for files.
alice_copy_extras() {
  local sub f
  for sub in docs licenses sbom helper; do
    [[ -d "$1/$sub" ]] || continue
    if [[ ! -d "$2/$sub" ]]; then install -d -m 0755 -- "$2/$sub"; fi
    for f in "$1/$sub"/*; do
      if [[ -f "$f" ]]; then install -m 0644 -- "$f" "$2/$sub/"; fi
    done
  done
  for f in CHANGELOG.md SECURITY-REPORT.md RELEASE-CHECKLIST-SIGNED.txt; do
    if [[ -f "$1/$f" ]]; then install -m 0644 -- "$1/$f" "$2/$f"; fi
  done
}

# ---- passphrase (S-25) ----

# alice_read_passphrase_file FILE reads the first line of FILE into alice_pass. A file that other
# users can read is refused (return 2).
alice_read_passphrase_file() {
  local mode
  if [[ ! -f "$1" ]]; then
    printf 'The passphrase file %s does not exist.\n' "$1" >&2
    return 2
  fi
  mode=$(stat -L -c '%a' -- "$1") || return 2
  if ((8#$mode & 8#077)); then
    alice_warn "The passphrase file $1 can be read by other users. Restrict it (chmod 600), then run this again."
    return 2
  fi
  IFS= read -r alice_pass <"$1" || [[ -n "$alice_pass" ]] || true
  if [[ -z "$alice_pass" ]]; then
    printf 'The passphrase file %s is empty.\n' "$1" >&2
    return 2
  fi
}
