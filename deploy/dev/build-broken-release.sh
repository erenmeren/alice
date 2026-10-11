#!/usr/bin/env bash
# Builds a release package whose image carries one extra migration that fails (BROKEN=fail:
# 99990_phase8_broken_test.sql, "SELECT 1/0;") or sleeps for two minutes (BROKEN=sleep:
# 99991_phase8_slow_test.sql, "SELECT pg_sleep(120);"), for the update rollback tests: the release
# harness (Task 13) and the owner's VM test (release checklist, owner step 5). M-27, R43 row 30.
#
#   build-broken-release.sh VERSION fail|sleep test|offline RELEASE_DIR RELEASE_TEST_KEY
#
# The migration exists only in a git archive copy of HEAD, never in this tree. The copy is built
# with this tree's commit (RELEASE_COMMIT), its gates log when there is one, and the absolute
# RELEASE_DIR and RELEASE_TEST_KEY, so the package lands beside the others and shares their test
# key. SIGN=test runs make release-test (a test-signed package; VERSION must be x.y.z-rc.N);
# SIGN=offline runs make release (an unsigned stage the vendor signs in the offline ceremony, then
# make release-pack). A broken package is never a customer version: SIGN=offline also needs
# x.y.z-rc.N and refuses when any output of that version exists in RELEASE_DIR (Task 12 review
# I-4). The copy is removed afterwards.
set -Eeuo pipefail

usage() {
  echo "usage: build-broken-release.sh VERSION fail|sleep test|offline RELEASE_DIR RELEASE_TEST_KEY" >&2
  exit 2
}

[[ $# -eq 5 ]] || usage
version=$1
broken=$2
sign=$3
release_dir=$4
test_key=$5

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || usage
case "$broken" in
  fail)
    migration=99990_phase8_broken_test.sql
    statement='SELECT 1/0;'
    ;;
  sleep)
    migration=99991_phase8_slow_test.sql
    statement='SELECT pg_sleep(120);'
    ;;
  *) usage ;;
esac
case "$sign" in
  test) target=release-test ;;
  offline) target=release ;;
  *) usage ;;
esac
if [[ "$version" != *-rc.* ]]; then
  echo "build-broken-release.sh: SIGN=$sign needs VERSION=x.y.z-rc.N (a broken package is never a customer version)" >&2
  exit 2
fi
if [[ "$release_dir" != /* || "$test_key" != /* ]]; then
  echo "build-broken-release.sh: RELEASE_DIR and RELEASE_TEST_KEY must be absolute paths" >&2
  exit 2
fi
if [[ "$sign" == offline ]]; then
  for f in "$release_dir/alice-$version" "$release_dir/sbom-$version" "$release_dir/alice-$version.tar.gz" \
    "$release_dir/alice-$version.tar.gz.sha256" "$release_dir/alice-$version.tar.gz.sha256.sig"; do
    if [[ -e "$f" ]]; then
      echo "build-broken-release.sh: $f already exists; a package is never replaced (choose the next -rc.N)" >&2
      exit 2
    fi
  done
fi

repo=$(cd "$(dirname "$0")/../.." && pwd)
commit=$(git -C "$repo" rev-parse HEAD)
short=$(git -C "$repo" rev-parse --short HEAD)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git -C "$repo" archive HEAD | tar -x -C "$work"
printf -- '-- +goose Up\n-- Test-only migration of a broken update package (deploy/dev/build-broken-release.sh).\n%s\n' "$statement" >"$work/migrations/$migration"
if [[ -f "$repo/bin/release-gates.log" ]]; then
  mkdir -p "$work/bin"
  cp -- "$repo/bin/release-gates.log" "$work/bin/release-gates.log"
fi

make -C "$work" web-install
make -C "$work" "$target" VERSION="$version" RELEASE_COMMIT="$commit" COMMIT="$short" \
  RELEASE_DIR="$release_dir" RELEASE_TEST_KEY="$test_key"
echo "build-broken-release.sh: $target VERSION=$version with $migration done (packages in $release_dir)"
