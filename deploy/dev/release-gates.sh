#!/usr/bin/env bash
# make release-gates (spec §22.7 stage 6, §17.7): every release gate that runs on one machine, in
# order, also after one fails, so the log shows every result; release-keycheck is last, because it
# fails until the vendor's production keys are committed. The gate list is defined once, in
# tools/releasebuild (releaseGates, printed by "releasebuild gates"); this script runs exactly that
# list and the production stage requires each of its gates exactly once with exit 0 (Task 15 review
# I-1). Each gate is recorded in bin/release-gates.log, which starts afresh with the line
# "commit<TAB><git rev-parse HEAD>" (Task 12 review I-5), then "<gate><TAB><exit status><TAB><tool
# version>" per gate. make release turns the log into RELEASE-CHECKLIST-SIGNED.txt. Gates named in
# RELEASE_GATES_SKIP (space separated; a local partial run) do not run and get the line
# "<gate><TAB>skipped<TAB>-", which the production stage refuses: the log never claims a gate that
# did not run. The tracked files must equal HEAD and no untracked source may exist, or the log would
# name a commit the gates did not test; when HEAD or the tree changed during the run (a shared
# working tree), the log gets a failing "tree-unchanged" line (Task 15 review M-2).
# zap-full and fuzz-release are not here: they run for hours on the owner's or CI's machine.
set -Euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo" || exit 2
log=bin/release-gates.log
skip=" ${RELEASE_GATES_SKIP:-} "
make=${MAKE:-make}

# A log of an earlier run never survives a refused or failed start.
rm -f "$log"
# untracked lists the untracked files that would be compiled or packaged into what the gates test.
untracked() {
  git ls-files --others --exclude-standard -- cmd internal tools web/src api migrations deploy
}
if ! git diff --quiet HEAD --; then
  echo "release-gates: the tracked files differ from HEAD; commit or stash first (the log names the commit the gates ran on)" >&2
  exit 2
fi
if [[ -n "$(untracked)" ]]; then
  echo "release-gates: untracked source files would be tested but are not in the commit; commit or remove them first:" >&2
  untracked >&2
  exit 2
fi
gates_list=$(go run ./tools/releasebuild gates) || { echo "release-gates: go run ./tools/releasebuild gates failed" >&2; exit 2; }
mapfile -t gates <<<"$gates_list"
((${#gates[@]} > 0)) && [[ -n "${gates[0]}" ]] || { echo "release-gates: releasebuild printed no gate" >&2; exit 2; }
head=$(git rev-parse HEAD)
mkdir -p bin
printf 'commit\t%s\n' "$head" > "$log"

go_version=$(go env GOVERSION)
node_version=$(node --version 2>/dev/null || echo none)
playwright_version=$(cd web && npx --no-install playwright --version 2>/dev/null | tr -d '\t' || echo none)
failed=()

# gate NAME VERSION COMMAND... runs one gate and records it.
gate() {
  local name=$1 version=$2 status=0
  shift 2
  if [[ "$skip" == *" $name "* ]]; then
    echo "=== release gate $name: skipped (RELEASE_GATES_SKIP; a production stage refuses this log)"
    printf '%s\tskipped\t-\n' "$name" >> "$log"
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

for name in "${gates[@]}"; do
  case $name in
    ci) gate ci "$go_version, golangci-lint ${GOLANGCI_LINT_VERSION:-v2.14.0}, node $node_version" "$make" ci ;;
    matrix-check) gate matrix-check "$go_version" go run ./tools/matrixcheck -strict -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md ;;
    reproducible-check) gate reproducible-check "$go_version" "$make" reproducible-check ;;
    test-release) gate test-release "$go_version, docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo none)" "$make" test-release ;;
    test-systemd) gate test-systemd "$go_version, ubuntu 22.04 systemd" "$make" test-systemd ;;
    zap-baseline) gate zap-baseline "${ZAP_IMAGE:-zap}" "$make" zap-baseline ;;
    testssl) gate testssl "${TESTSSL_IMAGE:-testssl}" "$make" testssl ;;
    test-backup-cycle) gate test-backup-cycle "$go_version" "$make" test-backup-cycle ;;
    e2e-browsers) gate e2e-browsers "playwright ${playwright_version#Version }" browsers ;;
    release-keycheck) gate release-keycheck "$go_version" "$make" release-keycheck ;;
    *)
      # A gate added to releaseGates without a command here: recorded as failed, never as passed.
      echo "release-gates: no command for gate $name (tools/releasebuild releaseGates); add it here" >&2
      printf '%s\t127\t-\n' "$name" >> "$log"
      failed+=("$name")
      ;;
  esac
done

# The log names the commit read at the start; on a shared working tree another commit or edit
# during the hours-long run would make it name a tree the gates did not test (Task 15 review M-2).
if [[ "$(git rev-parse HEAD)" != "$head" ]] || ! git diff --quiet HEAD -- || [[ -n "$(untracked)" ]]; then
  echo "release-gates: HEAD or the working tree changed during the run; the log does not describe commit $head" >&2
  printf 'tree-unchanged\t1\t-\n' >> "$log"
  failed+=(tree-unchanged)
fi

echo "release-gates: log in $log"
if ((${#failed[@]} > 0)); then
  echo "release-gates: failed: ${failed[*]}" >&2
  exit 1
fi
echo "release-gates: every gate passed"
