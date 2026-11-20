#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
note() { printf '%s\n' "$*" >&2; }
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die 'Run as root.'; }
have() { command -v "$1" >/dev/null 2>&1; }
stamp() { date -u +%Y%m%dT%H%M%SZ; }
host_name() { hostname -s | tr -c 'A-Za-z0-9_.-' '_'; }
init_report_dir() {
  local base=$1
  mkdir -p -- "$base" || die "Cannot create $base"
  chmod 700 -- "$base"
  RUN_DIR=$(mktemp -d "$base/$(host_name)-$(stamp)-XXXXXX") || die 'Cannot create run directory'
  chmod 700 -- "$RUN_DIR"
}

# Manifest records are TAB-separated: service<TAB>unit<TAB>protocol<TAB>port,
# account<TAB>name, data<TAB>absolute-path, hook<TAB>absolute-executable-path.
load_config() {
  CONFIG=${1:-}
  SERVICES=() PORTS=() ACCOUNTS=() DATA_PATHS=() HOOKS=()
  [[ -n $CONFIG ]] || { SCORING_STATUS=unknown; return; }
  [[ -f $CONFIG && ! -L $CONFIG ]] || die "Manifest not a regular file: $CONFIG"
  SCORING_STATUS=configured
  local kind a b c extra line=0
  while IFS=$'\t' read -r kind a b c extra || [[ -n ${kind:-} ]]; do
    ((line+=1))
    [[ -z ${kind//[[:space:]]/} || $kind == \#* ]] && continue
    [[ -z ${extra:-} ]] || die "Manifest line $line has too many fields"
    case $kind in
      service)
        [[ $a =~ ^[A-Za-z0-9@_.:-]+$ && $b =~ ^(tcp|udp)$ && $c =~ ^[0-9]{1,5}$ ]] || die "Invalid service at line $line"
        ((10#$c >= 1 && 10#$c <= 65535)) || die "Invalid port at line $line"
        SERVICES+=("$a"); PORTS+=("$b:$c") ;;
      account) [[ $a =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ && -z ${b:-} && -z ${c:-} ]] || die "Invalid account at line $line"; ACCOUNTS+=("$a") ;;
      data|hook)
        [[ $a == /* && $a != *$'\n'* && -z ${b:-} && -z ${c:-} ]] || die "Invalid path at line $line"
        [[ $kind == data ]] && DATA_PATHS+=("$a") || HOOKS+=("$a") ;;
      *) die "Unknown manifest record at line $line: $kind" ;;
    esac
  done < "$CONFIG"
}

capture() {
  local dest=$1; shift
  if have "$1"; then
    if have timeout; then timeout 30 "$@" >"$dest" 2>&1; else "$@" >"$dest" 2>&1; fi
  else
    printf 'UNAVAILABLE: %s\n' "$1" >"$dest"
    return 127
  fi
}
capture_shell() {
  local dest=$1; shift
  if have timeout; then timeout 30 bash -c "$*" >"$dest" 2>&1; else bash -c "$*" >"$dest" 2>&1; fi
}
