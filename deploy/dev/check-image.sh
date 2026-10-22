#!/usr/bin/env bash
# Checks a built release image of Alice without a database or a network (make image-check, audit
# AUD-23): how it runs (user, entrypoint, healthcheck), what its file system holds (no shell, no
# test artefacts, only the alice binary is executable, the keys, state and backups directories), and what
# the binary is (a release build: no build tags, no test license key, no /test routes, both
# alice-helper checksums, a plain version). Usage: check-image.sh <tag> checks alice:<tag>.
#
# TEST_LICENSE_LABEL, TEST_ROUTE_MARKER, E2E_AZURE_MARKER and E2E_ACME_MARKER come from the Makefile, whose
# release-symcheck proves that an e2e build contains all three (so their absence here means something). HELPER_SHA256_AMD64 and
# HELPER_SHA256_ARM64 (and WINHELPER_SHA256_AMD64/ARM64, of make winhelper) are the checksums of make helper: the helper build is reproducible, so the
# image's binary must hold exactly the checksums of the helper built from the same source with the
# same Go version (the two checks are skipped, with a skip: line, when the host's Go differs).
#
# Docker: one stopped container (docker create, for docker export and docker cp) and short-lived
# docker run --rm containers of alice:<tag> only, with no network, a read-only root file system and
# no capabilities, as Compose runs Alice. Everything is removed again; the make up stack's alice:dev
# is refused.
set -euo pipefail
tag="${1:-}"
case "$tag" in
  "") echo "usage: $0 <tag> (checks alice:<tag>)"; exit 2 ;;
  dev) echo "check-image: never alice:dev, the make up stack's image; build alice:ci with make image"; exit 2 ;;
esac
label="${TEST_LICENSE_LABEL:?set TEST_LICENSE_LABEL (make image-check does)}"
marker="${TEST_ROUTE_MARKER:?set TEST_ROUTE_MARKER (make image-check does)}"
azure_marker="${E2E_AZURE_MARKER:?set E2E_AZURE_MARKER (make image-check does)}"
acme_marker="${E2E_ACME_MARKER:?set E2E_ACME_MARKER (make image-check does)}"
sum_amd64="${HELPER_SHA256_AMD64:?set HELPER_SHA256_AMD64 (make image-check does)}"
sum_arm64="${HELPER_SHA256_ARM64:?set HELPER_SHA256_ARM64 (make image-check does)}"
wsum_amd64="${WINHELPER_SHA256_AMD64:?set WINHELPER_SHA256_AMD64 (make image-check does)}"
wsum_arm64="${WINHELPER_SHA256_ARM64:?set WINHELPER_SHA256_ARM64 (make image-check does)}"

work="$(mktemp -d)"
id=""
# shellcheck disable=SC2329 # run by the EXIT trap below, which ShellCheck does not follow
cleanup() {
  if [[ -n "$id" ]]; then docker rm "$id" >/dev/null; fi
  rm -rf "$work"
}
trap cleanup EXIT

fail=0
check() {
  if [[ "$2" == "$3" ]]; then echo "ok:   $1"; else echo "FAIL: $1 (got '$2', want '$3')"; fail=1; fi
}
count() { grep "$@" || true; }

# How the image runs.
inspect() { docker image inspect -f "$1" "alice:$tag"; }
check "runs as UID 10001, not root" "$(inspect '{{.Config.User}}')" "10001:10001"
check "entrypoint is the alice binary" "$(inspect '{{json .Config.Entrypoint}}')" '["/usr/local/bin/alice"]'
check "default command is serve" "$(inspect '{{json .Config.Cmd}}')" '["serve"]'
check "healthcheck runs alice healthcheck (exec form)" "$(inspect '{{json .Config.Healthcheck.Test}}')" '["CMD","/usr/local/bin/alice","healthcheck"]'
check "exposes only 8443/tcp" "$(inspect '{{json .Config.ExposedPorts}}')" '{"8443/tcp":{}}'
check "declares no volume (Compose mounts keys and state)" "$(inspect '{{json .Config.Volumes}}')" "null"
check "sets no ALICE_ variable" "$(inspect '{{range .Config.Env}}{{println .}}{{end}}' | count -c '^ALICE_')" "0"

# What its file system holds. tar -tv: mode, owner/group, size, date, time, path. The tree is also
# unpacked (modes made writable for the owner, so it can be removed again) to look inside files.
id="$(docker create "alice:$tag")"
docker export "$id" >"$work/rootfs.tar"
docker rm "$id" >/dev/null
id=""
tar -tvf "$work/rootfs.tar" >"$work/files"
mkdir "$work/root"
tar -xf "$work/rootfs.tar" -C "$work/root" --no-same-owner --mode=u+rwX
paths() { awk '{ print $6 }' "$work/files"; }
check "has no shell or busybox (distroless)" "$(paths | count -Ec '(^|/)(sh|bash|ash|dash|zsh|busybox)$')" "0"
check "has no package manager, toolchain or debugger" \
  "$(paths | count -Ec '(^|/)(apk|apt|apt-get|dpkg|go|gofmt|node|npm|npx|dlv|gdb|strace)$')" "0"
# A program is an ELF file or a #! script. The distroless base ships one script, base-files'
# etc/update-motd.d/10-uname, which nothing can run without a shell.
programs=""
while IFS= read -r -d '' f; do
  magic=""
  IFS= read -r -N 4 magic <"$f" || true
  if [[ "$magic" == $'\x7fELF' || "${magic:0:2}" == '#!' ]]; then programs+="${f#"$work/root/"} "; fi
done < <(find "$work/root" -type f -size +0 -print0 | sort -z)
check "the only programs are /usr/local/bin/alice and the base's inert motd script" "$programs" "etc/update-motd.d/10-uname usr/local/bin/alice "
check "has no test artefacts (test CA, shims, fixtures, sources, web modules, files in a home)" \
  "$(paths | count -Eic 'test|fixture|systemctl|nginx|node_modules|\.go$|^src/|^opt/alice-|^(root|home)/.*[^/]$')" "0"
check "/opt/alice holds only the empty keys, state and backups directories" \
  "$(paths | count -E '^opt/alice/.' | sort | tr '\n' ' ')" "opt/alice/backups/ opt/alice/keys/ opt/alice/state/ "
check "keys directory belongs to 10001" "$(awk '$6 == "opt/alice/keys/" { print $2 }' "$work/files")" "10001/10001"
check "state directory belongs to 10001 with mode 0700" \
  "$(awk '$6 == "opt/alice/state/" { print $1, $2 }' "$work/files")" "drwx------ 10001/10001"
check "backups directory belongs to 10001 with mode 0700" \
  "$(awk '$6 == "opt/alice/backups/" { print $1, $2 }' "$work/files")" "drwx------ 10001/10001"

# What the binary is.
bin="$work/root/usr/local/bin/alice"
info="$(go version -m "$bin")"
check "binary was built without build tags" "$(count -Ec '^\s+build\s+-tags=' <<<"$info")" "0"
check "binary is static (CGO_ENABLED=0)" "$(count -Ec '^\s+build\s+CGO_ENABLED=0$' <<<"$info")" "1"
check "binary links no testify or testcontainers" "$(count -Ec '\s(github.com/stretchr/testify|github.com/testcontainers)' <<<"$info")" "0"
# The setup script checks the helper an administrator installs against these checksums. The helper
# build is reproducible only with the same Go version: when the host's Go (which built the checksums
# of make helper) differs from the Go that built the image's binary, the two checks are skipped with
# a message instead of failing, except in CI (CI set), where both Go versions must match and a
# difference fails.
host_go="$(go env GOVERSION)"
bin_go="$(awk 'NR == 1 { print $2 }' <<<"$info")"
if [[ "$host_go" == "$bin_go" ]]; then
  check "binary holds the amd64 helper checksum of make helper" "$(count -acF "$sum_amd64" "$bin")" "1"
  check "binary holds the arm64 helper checksum of make helper" "$(count -acF "$sum_arm64" "$bin")" "1"
  check "binary holds the Windows amd64 helper checksum of make winhelper" "$(count -acF "$wsum_amd64" "$bin")" "1"
  check "binary holds the Windows arm64 helper checksum of make winhelper" "$(count -acF "$wsum_arm64" "$bin")" "1"
elif [[ -n "${CI:-}" ]]; then
  echo "FAIL: host Go $host_go differs from the Go that built the image's binary ($bin_go); in CI they must match (deploy/Dockerfile's Go image and go.mod), so the helper checksums cannot be skipped"
  fail=1
else
  echo "skip: binary holds the helper checksums of make helper (host Go $host_go, image binary built with $bin_go; the helper build is reproducible only with the same Go version)"
fi
check "binary does not hold the test license key label" "$(count -acF "$label" "$bin")" "0"
check "binary does not hold the e2e /test routes" "$(count -acF "$marker" "$bin")" "0"
check "binary does not know where the fake Azure CA lives (no e2e trust hook)" "$(count -acF "$azure_marker" "$bin")" "0"
check "binary does not know where the fake ACME CA lives (no e2e trust hook)" "$(count -acF "$acme_marker" "$bin")" "0"

# Run it as Compose does, minus the network: read-only root, no capabilities, no new privileges.
in_image() { docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true "alice:$tag" "$@"; }
version="$(in_image version)"
echo "      $version"
check "alice version runs read-only without network" "$(count -c '^alice ' <<<"$version")" "1"
check "version is a release build (no +e2e, no +testlicense)" "$(count -Ec '\+(e2e|testlicense)' <<<"$version")" "0"
check "trusts no test license key" "$(in_image license keys 2>&1 | count -c 'vk-test')" "0"
check "help lists the healthcheck command" "$(in_image help | count -c '^  healthcheck ')" "1"
status=0
in_image healthcheck >/dev/null 2>&1 || status=$?
check "healthcheck fails closed with no server (exit 1, not an unknown command)" "$status" "1"

if [[ "$fail" == 0 ]]; then echo "image-check: ok (alice:$tag)"; else echo "image-check: FAILED (alice:$tag)"; fi
exit "$fail"
