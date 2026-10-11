#!/usr/bin/env bash
# make release-gates (spec §22.7 stage 6, §17.7): every release gate that runs on one machine, in
# order, also after one fails, so the log shows every result; release-keycheck is last, because it
# fails until the vendor's production keys are committed. Each gate is recorded in
# bin/release-gates.log, which the log starts afresh with the line "commit<TAB><git rev-parse HEAD>"
# (Task 12 review I-5), then "<gate><TAB><exit status><TAB><tool version>" per gate. make release
# turns the log into RELEASE-CHECKLIST-SIGNED.txt and the production stage refuses a log of another
# commit or with a failed gate (tools/releasebuild). Gates named in RELEASE_GATES_SKIP (space
# separated; CI skips release-keycheck) do not run and get no line: the log never claims a gate that
# did not run. The tracked files must equal HEAD, or the log would name a commit the gates did not test.
# zap-full and fuzz-release are not here: they run for hours on the owner's or CI's machine.
set -Euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo" || exit 2
log=bin/release-gates.log
skip=" ${RELEASE_GATES_SKIP:-} "
make=${MAKE:-make}

if ! git diff --quiet HEAD --; then
  echo "release-gates: the tracked files differ from HEAD; commit or stash first (the log names the commit the gates ran on)" >&2
  exit 2
fi
mkdir -p bin
printf 'commit\t%s\n' "$(git rev-parse HEAD)" > "$log"

go_version=$(go env GOVERSION)
node_version=$(node --version 2>/dev/null || echo none)
playwright_version=$(cd web && npx --no-install playwright --version 2>/dev/null | tr -d '\t' || echo none)
failed=()

# gate NAME VERSION COMMAND... runs one gate and records it.
gate() {
  local name=$1 version=$2 status=0
  shift 2
  if [[ "$skip" == *" $name "* ]]; then
    echo "=== release gate $name: skipped (RELEASE_GATES_SKIP)"
    return 0
  fi
  echo "=== release gate $name: $*"
  "$@" || status=$?
  printf '%s\t%s\t%s\n' "$name" "$status" "$version" >> "$log"
  echo "=== release gate $name: exit $status"
  ((status == 0)) || failed+=("$name")
}

browsers() {
  local status=0
  "$make" e2e-up && "$make" e2e-browsers || status=$?
  "$make" e2e-down || true
  return "$status"
}

gate ci "$go_version, golangci-lint ${GOLANGCI_LINT_VERSION:-v2.14.0}, node $node_version" "$make" ci
gate matrix-check "$go_version" go run ./tools/matrixcheck -strict -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md
gate reproducible-check "$go_version" "$make" reproducible-check
gate test-release "$go_version, docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo none)" "$make" test-release
gate test-systemd "$go_version, ubuntu 22.04 systemd" "$make" test-systemd
gate zap-baseline "${ZAP_IMAGE:-zap}" "$make" zap-baseline
gate testssl "${TESTSSL_IMAGE:-testssl}" "$make" testssl
gate test-backup-cycle "$go_version" "$make" test-backup-cycle
gate e2e-browsers "playwright ${playwright_version#Version }" browsers
gate release-keycheck "$go_version" "$make" release-keycheck

echo "release-gates: log in $log"
if ((${#failed[@]} > 0)); then
  echo "release-gates: failed: ${failed[*]}" >&2
  exit 1
fi
echo "release-gates: every gate passed"
