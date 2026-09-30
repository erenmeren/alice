#!/usr/bin/env bash
# Verifies the running containers match the hardening rules in the design spec.
set -euo pipefail
cd "$(dirname "$0")/.."
compose=(docker compose -f docker-compose.yml --env-file .env)
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
check "alice is healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$alice")" "healthy"
check "postgres publishes no ports" "$(docker port "$pg" | wc -l | tr -d ' ')" "0"
check "backend network is internal" "$(docker network inspect -f '{{.Internal}}' alice_backend)" "true"
exit "$fail"
