#!/usr/bin/env bash
# Builds the alice binary and both alice-helper binaries and both alice-helper.exe binaries twice, from two clean copies of HEAD
# (git archive) in two different directories, each with its own Go build cache, and compares the
# bytes (make reproducible-check; spec §17.1, §26.10). The binaries are reproducible; the release
# as a whole is not claimed to be (image layers carry build metadata, R43 row 52, S-38). A CI-built
# stage is compared with the release machine's build through this check and is never what the
# offline key signs (S-26).
#
# Each copy runs what make build runs, with fixed inputs: npm ci --ignore-scripts and the web build,
# the helper builds of make helper and make winhelper (Linux and Windows) and their checksums, then alice with -trimpath
# -buildvcs=false and the ldflags of make build (VERSION=reproducible, COMMIT=the short HEAD,
# BUILD_TIME=the commit time of HEAD). Uncommitted changes are not part of the check.
# Prints "reproducible-check: ok (<five hashes>)", or the files that differ and exits 1.
set -Eeuo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
commit=$(git -C "$repo" rev-parse --short HEAD)
build_time=$(git -C "$repo" log -1 --format=%cI HEAD)
work_a=$(mktemp -d)
work_b=$(mktemp -d)
trap 'rm -rf "$work_a" "$work_b"' EXIT

files=(alice alice-helper-linux-amd64 alice-helper-linux-arm64 alice-winhelper-windows-amd64.exe alice-winhelper-windows-arm64.exe)

# build_copy DIR extracts HEAD into DIR and builds the three binaries into DIR/bin.
build_copy() {
  local src=$1 amd arm wamd warm
  mkdir -p "$src"
  git -C "$repo" archive HEAD | tar -x -C "$src"
  (cd "$src/web" && npm ci --ignore-scripts --no-audit --no-fund >/dev/null && npm run build >/dev/null)
  (
    cd "$src"
    export CGO_ENABLED=0 GOCACHE="$src/.gocache" GOFLAGS=-mod=readonly
    GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-helper-linux-amd64 ./cmd/alice-helper
    GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-helper-linux-arm64 ./cmd/alice-helper
    amd=$(sha256sum bin/alice-helper-linux-amd64 | cut -d ' ' -f 1)
    arm=$(sha256sum bin/alice-helper-linux-arm64 | cut -d ' ' -f 1)
    GOOS=windows GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-winhelper-windows-amd64.exe ./cmd/alice-winhelper
    GOOS=windows GOARCH=arm64 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-winhelper-windows-arm64.exe ./cmd/alice-winhelper
    wamd=$(sha256sum bin/alice-winhelper-windows-amd64.exe | cut -d ' ' -f 1)
    warm=$(sha256sum bin/alice-winhelper-windows-arm64.exe | cut -d ' ' -f 1)
    go build -trimpath -buildvcs=false -ldflags "-s -w -X alice/internal/version.Version=reproducible \
-X alice/internal/version.Commit=$commit -X alice/internal/version.BuildTime=$build_time \
-X alice/internal/providers/linuxssh.helperSHA256LinuxAMD64=$amd -X alice/internal/providers/linuxssh.helperSHA256LinuxARM64=$arm \
-X alice/internal/providers/windows.helperSHA256WindowsAMD64=$wamd -X alice/internal/providers/windows.helperSHA256WindowsARM64=$warm" \
      -o bin/alice ./cmd/alice
  )
}

build_copy "$work_a/a/src"
build_copy "$work_b/b/other/path/src"

status=0
hashes=()
for f in "${files[@]}"; do
  a=$(sha256sum "$work_a/a/src/bin/$f" | cut -d ' ' -f 1)
  b=$(sha256sum "$work_b/b/other/path/src/bin/$f" | cut -d ' ' -f 1)
  if [[ "$a" != "$b" ]]; then
    echo "reproducible-check: $f differs ($a vs $b)"
    status=1
  fi
  hashes+=("$f $a")
done
if [[ "$status" -ne 0 ]]; then
  exit 1
fi
printf 'reproducible-check: ok (%s, %s, %s, %s, %s)\n' "${hashes[@]}"
