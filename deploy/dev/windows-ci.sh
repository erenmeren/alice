#!/usr/bin/env bash
# The decisions of the Windows workflow (.github/workflows/windows.yml, W4, R63).
#
#   windows-ci.sh changed <list-file>
#     Reads changed file names, one per line, on standard input. Prints the first name an entry of
#     <list-file> matches and exits 0; exits 1 when none matches. Entries (Ruling 6), one per line,
#     blank lines and lines starting with # ignored:
#       dir/**   every file below dir
#       dir/*    every file directly in dir
#       path     that file only
#     Any other form (a/**/b, a leading /, a .. element, white space inside, another * or ?) is refused.
#
#   windows-ci.sh gate <changes_result> <windows> <linux_build_result> <helper_result>
#     The one required check (Ruling 4). Passes when changes succeeded and either answered
#     windows=false with both legs skipped, or answered windows=true with both legs succeeded.
#     Every other combination fails. Prints one line saying why.
#     Results are success|failure|cancelled|skipped; windows is true|false.
#
# Exit 2: a usage error, an unreadable list or a refused entry.
# internal/archtest/windowsci_test.go drives this script and checks the list covers every package the
# Windows tests build.
set -euo pipefail

usage() {
  echo "usage: windows-ci.sh changed <list-file> < names" >&2
  echo "       windows-ci.sh gate <changes_result> <windows> <linux_build_result> <helper_result>" >&2
  exit 2
}

# check_entry ENTRY exits 2 unless ENTRY is dir/**, dir/* or a plain path.
check_entry() {
  local entry=$1 body elem
  body=$entry
  case $body in
    */\*\*) body=${body%/\*\*} ;;
    */\*) body=${body%/\*} ;;
  esac
  local why=""
  if [[ -z $body ]]; then
    why="no directory"
  elif [[ $body == /* ]]; then
    why="a leading /"
  elif [[ $body == */ ]]; then
    why="a trailing /"
  elif [[ $body =~ [[:space:]] ]]; then
    why="white space inside"
  elif [[ $body == *[\*\?\[]* ]]; then
    why="a wildcard outside a final /** or /*"
  else
    local -a elems
    IFS=/ read -r -a elems <<<"$body"
    for elem in "${elems[@]}"; do
      if [[ $elem == ".." || $elem == "." || -z $elem ]]; then
        why="a . , .. or empty element"
      fi
    done
  fi
  if [[ -n $why ]]; then
    echo "windows-ci: refused entry \"$entry\": $why" >&2
    exit 2
  fi
}

# matches NAME ENTRY: exit 0 when ENTRY matches NAME.
matches() {
  local name=$1 entry=$2 dir rest
  case $entry in
    */\*\*)
      dir=${entry%/\*\*}
      [[ $name == "$dir/"?* ]]
      ;;
    */\*)
      dir=${entry%/\*}
      [[ $name == "$dir/"?* ]] || return 1
      rest=${name#"$dir/"}
      [[ $rest != */* ]]
      ;;
    *)
      [[ $name == "$entry" ]]
      ;;
  esac
}

changed() {
  [[ $# -eq 1 ]] || usage
  local list=$1 line name entry
  if [[ ! -f $list || ! -r $list ]]; then
    echo "windows-ci: cannot read $list" >&2
    exit 2
  fi
  local -a entries=()
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    # Trim surrounding white space; white space inside is refused by check_entry.
    line=${line#"${line%%[![:space:]]*}"}
    line=${line%"${line##*[![:space:]]}"}
    [[ -z $line || $line == \#* ]] && continue
    check_entry "$line"
    entries+=("$line")
  done <"$list"
  while IFS= read -r name || [[ -n $name ]]; do
    name=${name%$'\r'}
    [[ -z $name ]] && continue
    for entry in "${entries[@]}"; do
      if matches "$name" "$entry"; then
        echo "$name"
        exit 0
      fi
    done
  done
  exit 1
}

result_ok() {
  case $1 in success | failure | cancelled | skipped) return 0 ;; esac
  echo "windows-ci: \"$1\" is no job result (success|failure|cancelled|skipped)" >&2
  exit 2
}

gate() {
  [[ $# -eq 4 ]] || usage
  local changes=$1 windows=$2 build=$3 helper=$4
  result_ok "$changes"
  result_ok "$build"
  result_ok "$helper"
  if [[ $windows != true && $windows != false ]]; then
    echo "windows-ci: windows is \"$windows\", not true or false" >&2
    exit 2
  fi
  if [[ $changes != success ]]; then
    echo "gate: fail: the changes job ended $changes"
    exit 1
  fi
  if [[ $windows == false ]]; then
    if [[ $build == skipped && $helper == skipped ]]; then
      echo "gate: pass: no Windows change, both legs skipped"
      exit 0
    fi
    echo "gate: fail: no Windows change, yet linux-build ended $build and helper ended $helper"
    exit 1
  fi
  if [[ $build == success && $helper == success ]]; then
    echo "gate: pass: Windows change, both legs succeeded"
    exit 0
  fi
  echo "gate: fail: Windows change, linux-build ended $build and helper ended $helper"
  exit 1
}

[[ $# -ge 1 ]] || usage
cmd=$1
shift
case $cmd in
  changed) changed "$@" ;;
  gate) gate "$@" ;;
  *) usage ;;
esac
