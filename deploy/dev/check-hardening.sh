#!/usr/bin/env bash
# Verifies the running containers match the hardening rules in the design spec.
set -euo pipefail
cd "$(dirname "$0")/.."
# ALICE_PROJECT is the compose project (default "alice", the make up stack; make e2e-hardening-check
# passes "alice-e2e"); ALICE_COMPOSE_FILES are the compose files relative to deploy/.
project="${ALICE_PROJECT:-alice}"
files=()
for f in ${ALICE_COMPOSE_FILES:-docker-compose.yml}; do files+=(-f "$f"); done
compose=(docker compose -p "$project" "${files[@]}" --env-file .env)
alice="$("${compose[@]}" ps -q alice)"
pg="$("${compose[@]}" ps -q postgres)"
[[ -n "$alice" && -n "$pg" ]] || { echo "FAIL: stack is not running (run make up)"; exit 1; }

fail=0
check() {
  if [[ "$2" == "$3" ]]; then echo "ok:   $1"; else echo "FAIL: $1 (got '$2', want '$3')"; fail=1; fi
}
check "alice runs as UID 10001" "$(docker inspect -f '{{.Config.User}}' "$alice")" "10001:10001"
check "alice root filesystem is read-only" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$alice")" "true"
check "alice drops all capabilities" "$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$alice")" '["ALL"]'
check "alice has no-new-privileges" "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$alice")" '["no-new-privileges:true"]'
check "alice has a pids limit" "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$alice")" "256"
check "alice has core dumps disabled" "$(docker inspect -f '{{json .HostConfig.Ulimits}}' "$alice")" '[{"Name":"core","Hard":0,"Soft":0}]'
check "alice is healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$alice")" "healthy"
check "alice state volume is mounted read-write" \
  "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/opt/alice/state"}}{{.Type}} {{.RW}}{{end}}{{end}}' "$alice")" "volume true"
# docker cp streams a tar archive, which carries owner and mode (distroless has no shell or stat).
check "alice state directory is owned by 10001 with mode 0700" \
  "$(docker cp "$alice:/opt/alice/state" - | tar -tvf - | awk 'NR==1 {print $1, $2}')" "drwx------ 10001/10001"
check "alice state volume holds the time record" \
  "$(docker cp "$alice:/opt/alice/state" - | tar -tf - | grep -c '^state/hwm.dat$')" "1"
# The published host port: ALICE_PORT (default 443) for the make up stack, ALICE_E2E_PORT (default 9443)
# for the e2e stack. Like compose, the shell's value wins over deploy/.env.
env_value() {
  local v="${!1:-}"
  [[ -n "$v" ]] || v="$(sed -n "s/^$1=//p" .env | tail -n 1)"
  echo "${v:-$2}"
}
if [[ " ${ALICE_COMPOSE_FILES:-} " == *" docker-compose.e2e.yml "* ]]; then
  want_port="$(env_value ALICE_E2E_PORT 9443)"
else
  want_port="$(env_value ALICE_PORT 443)"
fi
check "alice publishes only host port $want_port" \
  "$(docker port "$alice" | sed 's/.*://' | sort -u | tr '\n' ' ')" "$want_port "
check "postgres publishes no ports" "$(docker port "$pg" | wc -l | tr -d ' ')" "0"
check "backend network is internal" "$(docker network inspect -f '{{.Internal}}' "${project}_backend")" "true"
# The e2e overlay adds the SSH test target: it must publish nothing and sit only on the internal network.
if "${compose[@]}" config --services | grep -qx sshtarget; then
  target="$("${compose[@]}" ps -q sshtarget)"
  if [[ -z "$target" ]]; then
    echo "FAIL: the e2e SSH target is not running"; fail=1
  else
    check "sshtarget publishes no ports" "$(docker port "$target" | wc -l | tr -d ' ')" "0"
    check "sshtarget is only on the internal backend network" \
      "$(docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}' "$target")" "${project}_backend "
    check "sshtarget is healthy (sshd and nginx run)" "$(docker inspect -f '{{.State.Health.Status}}' "$target")" "healthy"
    check "sshtarget's test CA key is root-only" \
      "$(docker exec "$target" stat -c '%U %a' /opt/alice-test-ca/ca.key 2>/dev/null)" "root 600"
    check "sshtarget's website key is root-only" \
      "$(docker exec "$target" stat -c '%U %a' /etc/nginx/ssl/www.key 2>/dev/null)" "root 600"
    # The test PKI is created at container start, never in an image layer: a fresh container of the
    # image (no network, removed at once) has none of it.
    check "sshtarget's image holds no test key or certificate" \
      "$(docker run --rm --network none --entrypoint /bin/sh "$(docker inspect -f '{{.Config.Image}}' "$target")" \
        -c 'ls /opt/alice-test-ca /etc/nginx/ssl 2>/dev/null | wc -l')" "0"
  fi
fi
# The test shims and the test PKI exist only in the SSH target, never in the Alice image.
check "alice image has no systemctl shim" \
  "$(docker cp "$alice:/usr/bin/systemctl" - >/dev/null 2>&1 && echo present || echo absent)" "absent"
check "alice image has no test CA" \
  "$(docker cp "$alice:/opt/alice-test-ca" - >/dev/null 2>&1 && echo present || echo absent)" "absent"
exit "$fail"
