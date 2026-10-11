#!/usr/bin/env bash
# Dynamic security gates of the release image (spec §25.7, §26.4; make zap-baseline, make zap-full,
# make testssl): a disposable Alice of the release image (alice:ci from make image, no /test routes)
# as compose project alice-zap on https://127.0.0.1:9445 only, scanned with OWASP ZAP and testssl.sh.
#
#   zap-stack.sh up OUT                         start the stack, run the wizard (HTTPS: a certificate of a
#                                               throwaway test CA, OUT/test-ca.crt), sign in Administrator,
#                                               Operator and Auditor (tools/zapsession -> OUT/<role>.env)
#   zap-stack.sh scan baseline OUT              zap-baseline.py unauthenticated and as each role, then
#                                               zap-api-scan.py of api/openapi.yaml as Administrator
#   zap-stack.sh scan full OUT                  zap-full-scan.py (active) as Administrator (hours)
#   zap-stack.sh testssl OUT                    testssl.sh against the stack, trusting OUT/test-ca.crt:
#                                               grade A or A+ required (the temporary self-signed
#                                               certificate has no chain of trust and caps the grade at B)
#   zap-stack.sh testssl-target HOST:PORT [CA] OUT   the same against a host the owner names; no stack
#   zap-stack.sh down                           remove the stack and its volumes
#   zap-stack.sh run baseline|full|testssl OUT  up, then the scan or testssl, then down, also when the
#                                               run fails or is interrupted (make zap-baseline, zap-full,
#                                               testssl; Task 15 review M-3)
#
# The authenticated scans must stay authenticated (Task 15 review I-3): requests that end a session
# (sign-out, and the user actions revoke-sessions, reset-mfa and reset-password) are excluded from
# the spiders and the scanners (ZAP's global URL exclusions) and, should one still be sent (the Ajax
# spider's browser clicking "Sign out"), its request line is rewritten to a path that does not exist
# (a replacer rule), so it never reaches a session-ending route. Before the scans every role's session
# must be alive, and after each authenticated scan GET /api/v1/auth/session with that role's cookie
# must still answer 200 for that role; otherwise the scan fails, because the rest of it would have
# run anonymously under the role's name.
#
# A scan fails when any report has an alert of level Medium or High not ignored by .zap/rules.tsv
# (tools/zaprules prints the counts per level and role into OUT/zap-summary.txt). The scanner images
# come from ZAP_IMAGE and TESTSSL_IMAGE (exported by the Makefile) with the pinned defaults below,
# never from arguments (M-21). Only the compose project alice-zap and the containers started here
# are touched; the stack publishes on 127.0.0.1 only. The session cookies of OUT/<role>.env belong
# to the disposable stack and are passed to ZAP on its command line.
set -Eeuo pipefail

ZAP_IMAGE=${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2}
TESTSSL_IMAGE=${TESTSSL_IMAGE:-ghcr.io/testssl/testssl.sh:3.2@sha256:51918b1e954df0acee8c08d3ad5ce306710e4fefe49ed0e0f92728ecf9e7ff34}

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
project=alice-zap
port=9445
base="https://127.0.0.1:$port"
roles=(admin operator auditor)

usage() {
  awk 'NR > 1 && !/^#/ { exit } NR > 1 { print }' "$0" >&2
  exit 2
}

# compose runs docker compose on the alice-zap project with the release image and the loopback port.
compose() {
  local override=$1
  shift
  local files=(-f deploy/docker-compose.yml)
  [[ -z "$override" ]] || files+=(-f "$override")
  ALICE_VERSION=ci ALICE_PORT=$port ALICE_TLS_HOSTS='' docker compose -p "$project" "${files[@]}" --env-file deploy/.env "$@"
}

# workdir OUT prepares OUT (mode 0700) and its subdirectories the scanner containers write to: their
# users are not this one, so those two are world-writable; OUT itself keeps the session files.
workdir() {
  local out=$1
  mkdir -p "$out" "$out/wrk" "$out/testssl"
  chmod 0700 "$out"
  chmod 0777 "$out/wrk" "$out/testssl"
}

up() {
  local out=$1
  workdir "$out"
  ./deploy/dev/init-env.sh >/dev/null
  docker image inspect alice:ci >/dev/null 2>&1 || { echo "zap-stack: alice:ci is missing; run make image" >&2; exit 1; }
  # The development compose file publishes on every address; this override publishes on loopback only.
  cat > "$out/compose.loopback.yml" <<YML
services:
  alice:
    ports: !override
      - "127.0.0.1:$port:8443"
YML
  compose "$out/compose.loopback.yml" up -d --no-build --wait
  local code
  code=$(compose "$out/compose.loopback.yml" exec -T alice /usr/local/bin/alice setup-token --reset | sed -n 's/^One-time setup code: \([0-9A-Z-]*\)$/\1/p')
  [[ -n "$code" ]] || { echo "zap-stack: alice setup-token printed no setup code" >&2; exit 1; }
  compose "$out/compose.loopback.yml" cp alice:/opt/alice/keys/tls.crt "$out/tls.crt"
  go run ./tools/zapsession -base "$base" -ca "$out/tls.crt" -setup-code "$code" -out "$out"
}

down() {
  compose "" down -v --remove-orphans
}

# session_ending lists the API paths whose requests end a session (the caller's, or a user's): the
# scans never send them (Task 15 review I-3).
session_ending=(
  '/api/v1/auth/logout'
  '/api/v1/users/[^/?]+/actions/revoke-sessions'
  '/api/v1/users/[^/?]+/actions/reset-mfa'
  '/api/v1/users/[^/?]+/actions/reset-password'
)

# exclusions prints ZAP's -z options that keep the session-ending paths out of every scan: global
# URL exclusions (spider, Ajax spider, active scanner) and, for a request sent anyway, a replacer
# rule from index FIRST on that rewrites its request line to /api/v1/zap-excluded, which no route
# serves. The options hold no space and no backslash: ZAP's scripts split -z on blanks.
exclusions() {
  local first=$1 i=0 opts=() path
  for path in "${session_ending[@]}"; do
    opts+=("-config globalexcludeurl.url_list.url($i).regex=^https?://[^/]+${path}([?#].*)?\$")
    opts+=("-config globalexcludeurl.url_list.url($i).description=session-ending-$i -config globalexcludeurl.url_list.url($i).enabled=true")
    local r=$((first + i))
    opts+=("-config replacer.full_list($r).description=session-ending-$i -config replacer.full_list($r).enabled=true")
    opts+=("-config replacer.full_list($r).matchtype=REQ_HEADER_STR -config replacer.full_list($r).regex=true")
    opts+=("-config replacer.full_list($r).matchstr=^([A-Z]+.(https?://[^/]+)?)${path}(?=[^-a-zA-Z0-9_/])")
    opts+=("-config replacer.full_list($r).replacement=\$1/api/v1/zap-excluded")
    i=$((i + 1))
  done
  echo "${opts[*]}"
}

# session_field ROLE OUT FIELD prints COOKIE or CSRF of OUT/ROLE.env, or fails when it is missing.
session_field() {
  local role=$1 out=$2 field=$3 value
  [[ -f "$out/$role.env" ]] || { echo "zap-stack: $out/$role.env is missing; run zap-stack.sh up $out" >&2; return 1; }
  value=$(sed -n "s/^$field=//p" "$out/$role.env")
  [[ -n "$value" ]] || { echo "zap-stack: $out/$role.env has no $field; run zap-stack.sh up $out" >&2; return 1; }
  printf '%s\n' "$value"
}

# replacer ROLE OUT prints ZAP's -z options that put the role's session cookie, its CSRF token and the
# activity marker (the session stays alive while ZAP reads, R39) on every request, and keep the
# session-ending paths out of the scan (exclusions).
replacer() {
  local role=$1 out=$2 cookie csrf
  cookie=$(session_field "$role" "$out" COOKIE) || return 1
  csrf=$(session_field "$role" "$out" CSRF) || return 1
  local i=0 opts=() header value
  for header in Cookie X-CSRF-Token X-Alice-Activity; do
    case $header in
      Cookie) value=$cookie ;;
      X-CSRF-Token) value=$csrf ;;
      *) value=1 ;;
    esac
    opts+=("-config replacer.full_list($i).description=$role-$header -config replacer.full_list($i).enabled=true")
    opts+=("-config replacer.full_list($i).matchtype=REQ_HEADER -config replacer.full_list($i).matchstr=$header")
    opts+=("-config replacer.full_list($i).regex=false -config replacer.full_list($i).replacement=$value")
    i=$((i + 1))
  done
  opts+=("$(exclusions "$i")")
  echo "${opts[*]}"
}

# load_zopts ROLE OUT sets the global zopts to replacer's options; a missing or empty session file stops
# the scan here instead of letting it run anonymously under the role's name (Task 15 review I-4:
# an exit inside -z "$(replacer ...)" would only end the command substitution).
zopts=
load_zopts() {
  zopts=$(replacer "$1" "$2") || { echo "zap-stack: no session options for $1; the scan stops" >&2; exit 1; }
  [[ -n "$zopts" ]] || { echo "zap-stack: empty session options for $1; the scan stops" >&2; exit 1; }
}

# alive ROLE OUT checks that the role's session still answers GET /api/v1/auth/session with 200 and
# that role (Task 15 review I-3). The cookie goes to curl on stdin, not on its command line.
alive() {
  local role=$1 out=$2 cookie response status body got
  cookie=$(session_field "$role" "$out" COOKIE) || return 1
  response=$(printf 'Cookie: %s\n' "$cookie" | curl -sS --max-time 30 --cacert "$out/test-ca.crt" -H @- \
    -w '\n%{http_code}' "$base/api/v1/auth/session") || { echo "zap-stack: GET /api/v1/auth/session as $role failed" >&2; return 1; }
  status=${response##*$'\n'}
  body=${response%$'\n'*}
  if [[ "$status" != 200 ]]; then
    echo "zap-stack: the $role session ended during the scan (GET /api/v1/auth/session: $status)" >&2
    return 1
  fi
  got=$(jq -r '.user.role // empty' <<<"$body") || got=
  if [[ "$got" != "$role" ]]; then
    echo "zap-stack: GET /api/v1/auth/session as $role answered role '${got:-none}'" >&2
    return 1
  fi
  echo "zap-stack: the $role session is alive"
}

# check_alive LABEL ROLE OUT records a session lost during the scan LABEL in the global lost array.
lost=()
check_alive() {
  local label=$1 role=$2 out=$3
  alive "$role" "$out" || lost+=("$label ($role)")
}

# zap SCRIPT ARGS... runs one ZAP packaged scan with OUT/wrk as /zap/wrk. ZAP's own exit status 1
# (a FAIL rule) and 2 (a WARN) are left to tools/zaprules; 3 and above mean the scan itself failed.
zap() {
  local out=$1 script=$2
  shift 2
  local status=0
  docker run --rm --network host -v "$(cd "$out/wrk" && pwd):/zap/wrk:rw" "$ZAP_IMAGE" "$script" "$@" || status=$?
  if ((status > 2)); then
    echo "zap-stack: $script ended with status $status (the scan did not complete)" >&2
    exit "$status"
  fi
}

scan() {
  local kind=$1 out=$2 role expect
  for role in "${roles[@]}"; do
    alive "$role" "$out" || { echo "zap-stack: no live $role session in $out; run zap-stack.sh up $out first" >&2; exit 1; }
  done
  workdir "$out"
  rm -f "$out"/wrk/*.json "$out"/wrk/*.html
  cp .zap/rules.tsv "$out/wrk/rules.tsv"
  case $kind in
    baseline)
      local anon
      anon=$(exclusions 0)
      zap "$out" zap-baseline.py -t "$base" -c rules.tsv -I -j -J unauthenticated.json -r unauthenticated.html -z "$anon"
      for role in "${roles[@]}"; do
        load_zopts "$role" "$out"
        zap "$out" zap-baseline.py -t "$base" -c rules.tsv -I -j -J "$role.json" -r "$role.html" -z "$zopts"
        check_alive "baseline" "$role" "$out"
      done
      # The API, from the OpenAPI file with its server set to the stack, as Administrator.
      sed "s#^  - url: /\$#  - url: $base/#" api/openapi.yaml > "$out/wrk/openapi.yaml"
      grep -q "url: $base/" "$out/wrk/openapi.yaml" || { echo "zap-stack: could not set the server URL of api/openapi.yaml" >&2; exit 1; }
      load_zopts admin "$out"
      zap "$out" zap-api-scan.py -t /zap/wrk/openapi.yaml -f openapi -c rules.tsv -I -J api-admin.json -r api-admin.html -z "$zopts"
      check_alive "api" admin "$out"
      expect=unauthenticated,admin,operator,auditor,api-admin
      ;;
    full)
      load_zopts admin "$out"
      zap "$out" zap-full-scan.py -t "$base" -c rules.tsv -I -j -J full-admin.json -r full-admin.html -z "$zopts"
      check_alive "full" admin "$out"
      expect=full-admin
      ;;
    *) usage ;;
  esac
  local status=0
  go run ./tools/zaprules -reports "$out/wrk" -expect "$expect" .zap/rules.tsv | tee "$out/zap-summary.txt" || status=${PIPESTATUS[0]}
  if ((${#lost[@]} > 0)); then
    echo "zap-stack: a session ended during the scan, so the rest of it ran unauthenticated: ${lost[*]}" | tee -a "$out/zap-summary.txt" >&2
    status=1
  else
    echo "zap-stack: every authenticated scan kept its session" | tee -a "$out/zap-summary.txt"
  fi
  echo "zap-stack: reports in $out/wrk (summary $out/zap-summary.txt)"
  return "$status"
}

# run KIND OUT brings the stack up, runs the scan (baseline, full) or testssl, and always brings it
# down: on success, failure, or an interrupt of make (Task 15 review M-3).
run() {
  local kind=$1 out=$2
  case $kind in baseline | full | testssl) ;; *) usage ;; esac
  trap 'down || echo "zap-stack: removing the stack failed" >&2' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  up "$out"
  case $kind in
    testssl) testssl_run "$base" "$out/test-ca.crt" "$out" ;;
    *) scan "$kind" "$out" ;;
  esac
}

# testssl_run TARGET CA OUT runs testssl.sh and requires the overall grade A or A+.
testssl_run() {
  local target=$1 ca=$2 out=$3 args=()
  workdir "$out"
  rm -f "$out/testssl/testssl.json"
  if [[ -n "$ca" ]]; then
    cp "$ca" "$out/testssl/ca.crt"
    chmod 0644 "$out/testssl/ca.crt"
    args+=(--add-ca /out/ca.crt)
  fi
  docker run --rm --network host -v "$(cd "$out/testssl" && pwd):/out:rw" "$TESTSSL_IMAGE" \
    "${args[@]}" --quiet --color 0 --jsonfile-pretty /out/testssl.json "$target" || true
  [[ -s "$out/testssl/testssl.json" ]] || { echo "zap-stack: testssl.sh wrote no $out/testssl/testssl.json" >&2; exit 1; }
  local grade
  grade=$(jq -r '[.scanResult[]?.rating[]? | select(.id == "overall_grade") | .finding][0] // empty' "$out/testssl/testssl.json")
  jq -r '.scanResult[]?.rating[]? | select(.id | test("grade|grade_cap_reason|final_score")) | "  \(.id): \(.finding)"' "$out/testssl/testssl.json" | tee "$out/testssl-summary.txt"
  echo "testssl: $target overall grade ${grade:-none}" | tee -a "$out/testssl-summary.txt"
  [[ "$grade" == "A" || "$grade" == "A+" ]] || { echo "testssl: grade A or A+ required" >&2; exit 1; }
}

[[ $# -ge 1 ]] || usage
case $1 in
  up) [[ $# -eq 2 ]] || usage; up "$2" ;;
  down) [[ $# -eq 1 ]] || usage; down ;;
  run) [[ $# -eq 3 ]] || usage; run "$2" "$3" ;;
  scan) [[ $# -eq 3 ]] || usage; scan "$2" "$3" ;;
  testssl) [[ $# -eq 2 ]] || usage; testssl_run "$base" "$2/test-ca.crt" "$2" ;;
  testssl-target)
    case $# in
      3) testssl_run "$2" "" "$3" ;;
      4) testssl_run "$2" "$3" "$4" ;;
      *) usage ;;
    esac
    ;;
  *) usage ;;
esac
