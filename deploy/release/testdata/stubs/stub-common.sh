# shellcheck shell=bash
# Shared code of the test stubs (sourced by each stub). Test data of scripts_test.go; never shipped.
#
# The scripts run docker through "env -i" (S-6), so the stubs cannot rely on their environment:
# scripts_test.go writes the stub settings (STUB_*) into stub.env next to the stubs of each test,
# and every stub reads that file. Each call is appended to $STUB_LOG as one "C" line (name and
# arguments), one "E" line (the exported environment) and, for a call that reads a passphrase,
# one "I" line (standard input). Fields are separated by 0x1f; a newline in a field is written \n.

stub_dir=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ -f "$stub_dir/stub.env" ]]; then
  # shellcheck source=/dev/null  # written per test by scripts_test.go
  . "$stub_dir/stub.env"
fi

stub_esc() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//$'\n'/\\n}
  printf '%s' "$s"
}

stub_record() {
  local line envline a v
  line="C"$'\x1f'"$1"
  shift
  for a in "$@"; do line+=$'\x1f'"$(stub_esc "$a")"; done
  envline="E"
  while IFS= read -r v; do
    envline+=$'\x1f'"$(stub_esc "$v=${!v}")"
  done < <(compgen -e)
  printf '%s\n%s\n' "$line" "$envline" >>"$STUB_LOG"
}

stub_record_stdin() {
  local data
  data=$(cat; printf x)
  data=${data%x}
  printf 'I\x1f%s\n' "$(stub_esc "$data")" >>"$STUB_LOG"
}

# stub_real runs the real command of that name (the PATH of the test without the stubs).
stub_real() {
  PATH=$STUB_REAL_PATH command "$@"
}
