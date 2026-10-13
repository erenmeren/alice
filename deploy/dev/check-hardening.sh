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
if [[ " ${ALICE_COMPOSE_FILES:-} " == *" docker-compose.e2e.yml "* ]]; then
  # The e2e build answers the unauthenticated /test/* endpoints: its port is bound to loopback only
  # (AUD-07), so every published binding must be 127.0.0.1 (no 0.0.0.0, no [::]).
  check "alice (e2e) publishes only on 127.0.0.1" \
    "$(docker port "$alice" | sed 's/.* -> //; s/:[0-9]*$//' | sort -u | tr '\n' ' ')" "127.0.0.1 "
fi
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
# The e2e overlay adds the fake Azure service (Entra ID and Key Vault for the Phase 5 journeys): it must
# publish nothing, sit only on the internal network, be read-only, drop every capability, run as a
# non-root user and be healthy; alice reads its CA through a read-only mount and carries none of the
# SDK logging or region variables the Key Vault provider refuses.
if "${compose[@]}" config --services | grep -qx fakeazure; then
  fake="$("${compose[@]}" ps -q fakeazure)"
  if [[ -z "$fake" ]]; then
    echo "FAIL: the e2e fake Azure service is not running"; fail=1
  else
    check "fakeazure publishes no ports" "$(docker port "$fake" | wc -l | tr -d ' ')" "0"
    check "fakeazure is only on the internal backend network" \
      "$(docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}' "$fake")" "${project}_backend "
    check "fakeazure root filesystem is read-only" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$fake")" "true"
    check "fakeazure drops all capabilities and adds none" \
      "$(docker inspect -f '{{json .HostConfig.CapDrop}} {{json .HostConfig.CapAdd}}' "$fake")" '["ALL"] null'
    check "fakeazure has no-new-privileges" "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$fake")" '["no-new-privileges:true"]'
    check "fakeazure runs as a non-root user" \
      "$(docker inspect -f '{{.Config.User}}' "$fake" | grep -Ec '^[1-9][0-9]*:[1-9][0-9]*$' || true)" "1"
    check "fakeazure has a pids limit" "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$fake")" "128"
    check "fakeazure is healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$fake")" "healthy"
    check "alice mounts the fake's CA read-only" \
      "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/alice-e2e-azure"}}{{.Type}} {{.RW}}{{end}}{{end}}' "$alice")" "volume false"
    check "alice can read the fake's CA" \
      "$(docker cp "$alice:/run/alice-e2e-azure/ca.pem" - 2>/dev/null | tar -xOf - 2>/dev/null | grep -c 'BEGIN CERTIFICATE' || true)" "1"
    check "alice has no Azure SDK logging or region variable (the provider would refuse every session)" \
      "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$alice" | grep -Ec '^(AZURE_SDK_GO_LOGGING|MSAL_FORCE_REGION|AZURE_REGIONAL_AUTHORITY_NAME)=' || true)" "0"
  fi
fi
# The e2e overlay adds the fake ACME CA (certificate issuance journeys): the same hardening as the fake Azure
# service, and alice reads its TLS CA through a read-only mount.
if "${compose[@]}" config --services | grep -qx fakeacme; then
  acme="$("${compose[@]}" ps -q fakeacme)"
  if [[ -z "$acme" ]]; then
    echo "FAIL: the e2e fake ACME service is not running"; fail=1
  else
    check "fakeacme publishes no ports" "$(docker port "$acme" | wc -l | tr -d ' ')" "0"
    check "fakeacme is only on the internal backend network" \
      "$(docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}' "$acme")" "${project}_backend "
    check "fakeacme root filesystem is read-only" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$acme")" "true"
    check "fakeacme drops all capabilities and adds none" \
      "$(docker inspect -f '{{json .HostConfig.CapDrop}} {{json .HostConfig.CapAdd}}' "$acme")" '["ALL"] null'
    check "fakeacme has no-new-privileges" "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$acme")" '["no-new-privileges:true"]'
    check "fakeacme runs as a non-root user" \
      "$(docker inspect -f '{{.Config.User}}' "$acme" | grep -Ec '^[1-9][0-9]*:[1-9][0-9]*$' || true)" "1"
    check "fakeacme has a pids limit" "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$acme")" "128"
    check "fakeacme is healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$acme")" "healthy"
    check "alice mounts the fake ACME CA read-only" \
      "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/alice-e2e-acme"}}{{.Type}} {{.RW}}{{end}}{{end}}' "$alice")" "volume false"
    check "alice can read the fake ACME CA" \
      "$(docker cp "$alice:/run/alice-e2e-acme/ca.pem" - 2>/dev/null | tar -xOf - 2>/dev/null | grep -c 'BEGIN CERTIFICATE' || true)" "1"
  fi
fi
# The e2e overlay adds the fake SMTP server (Phase 7 journeys): it must publish nothing, sit only on the internal
# backend network, be read-only, drop every capability, run as a non-root user, have a pids limit and be healthy.
if "${compose[@]}" config --services | grep -qx fakesmtp; then
  smtp="$("${compose[@]}" ps -q fakesmtp)"
  if [[ -z "$smtp" ]]; then
    echo "FAIL: the e2e fake SMTP service is not running"; fail=1
  else
    check "fakesmtp publishes no ports" "$(docker port "$smtp" | wc -l | tr -d ' ')" "0"
    check "fakesmtp is only on the internal backend network" \
      "$(docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}' "$smtp")" "${project}_backend "
    check "fakesmtp root filesystem is read-only" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$smtp")" "true"
    check "fakesmtp drops all capabilities and adds none" \
      "$(docker inspect -f '{{json .HostConfig.CapDrop}} {{json .HostConfig.CapAdd}}' "$smtp")" '["ALL"] null'
    check "fakesmtp has no-new-privileges" "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$smtp")" '["no-new-privileges:true"]'
    check "fakesmtp runs as a non-root user" \
      "$(docker inspect -f '{{.Config.User}}' "$smtp" | grep -Ec '^[1-9][0-9]*:[1-9][0-9]*$' || true)" "1"
    check "fakesmtp has a pids limit" "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$smtp")" "128"
    check "fakesmtp is healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$smtp")" "healthy"
  fi
fi
# The e2e overlay adds the fake identity provider (Phase 7 SSO journeys): the browser reaches it on this host, so it
# is the one fake that publishes a port, and only 127.0.0.1:9444; it sits only on the frontend network and is hardened
# like the others.
if "${compose[@]}" config --services | grep -qx fakeidp; then
  idp="$("${compose[@]}" ps -q fakeidp)"
  if [[ -z "$idp" ]]; then
    echo "FAIL: the e2e fake identity provider service is not running"; fail=1
  else
    check "fakeidp publishes exactly 127.0.0.1:9444" "$(docker port "$idp")" "9444/tcp -> 127.0.0.1:9444"
    check "fakeidp is only on the frontend network" \
      "$(docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}' "$idp")" "${project}_frontend "
    check "fakeidp root filesystem is read-only" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$idp")" "true"
    check "fakeidp drops all capabilities and adds none" \
      "$(docker inspect -f '{{json .HostConfig.CapDrop}} {{json .HostConfig.CapAdd}}' "$idp")" '["ALL"] null'
    check "fakeidp has no-new-privileges" "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$idp")" '["no-new-privileges:true"]'
    check "fakeidp runs as a non-root user" \
      "$(docker inspect -f '{{.Config.User}}' "$idp" | grep -Ec '^[1-9][0-9]*:[1-9][0-9]*$' || true)" "1"
    check "fakeidp has a pids limit" "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$idp")" "128"
    check "fakeidp is healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$idp")" "healthy"
  fi
fi
# The test shims and the test PKI exist only in the SSH target, never in the Alice image.
check "alice image has no systemctl shim" \
  "$(docker cp "$alice:/usr/bin/systemctl" - >/dev/null 2>&1 && echo present || echo absent)" "absent"
check "alice image has no test CA" \
  "$(docker cp "$alice:/opt/alice-test-ca" - >/dev/null 2>&1 && echo present || echo absent)" "absent"
exit "$fail"
