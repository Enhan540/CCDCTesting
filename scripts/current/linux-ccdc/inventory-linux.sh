#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
usage() { echo 'Usage: inventory-linux.sh [--config manifest.tsv] [--output-dir DIR]'; }
config='' output=/var/log/ccdc-linux
while (($#)); do
  case $1 in
    --config|--output-dir) (($# >= 2)) || die "Missing value for $1"; case $1 in --config) config=$2;; *) output=$2;; esac; shift 2 ;;
    -h|--help) usage; exit 0;; *) die "Unknown argument: $1";;
  esac
done
need_root; load_config "$config"; init_report_dir "$output"
printf 'host=%s\nutc=%s\nscoring_coverage=%s\n' "$(hostname -f 2>/dev/null || hostname)" "$(date -u +%FT%TZ)" "$SCORING_STATUS" >"$RUN_DIR/summary.txt"
capture "$RUN_DIR/users.txt" getent passwd || true
capture "$RUN_DIR/groups.txt" getent group || true
capture "$RUN_DIR/login-state.txt" passwd -S -a || true
capture "$RUN_DIR/processes.txt" ps auxww || true
capture "$RUN_DIR/services-running.txt" systemctl list-units --type=service --state=running --no-pager --plain || true
capture "$RUN_DIR/services-enabled.txt" systemctl list-unit-files --type=service --state=enabled --no-pager --plain || true
: >"$RUN_DIR/service-definitions.txt"
if have systemctl; then
  while read -r unit _; do
    [[ $unit == *.service ]] || continue
    printf '\n### %s\n' "$unit" >>"$RUN_DIR/service-definitions.txt"
    systemctl cat --no-pager "$unit" >>"$RUN_DIR/service-definitions.txt" 2>&1 || true
  done <"$RUN_DIR/services-running.txt"
fi
capture "$RUN_DIR/sockets.txt" ss -tulpen || true
capture "$RUN_DIR/connections.txt" ss -tunap || true
capture "$RUN_DIR/network.txt" ip address || true
capture "$RUN_DIR/routes.txt" ip route show table all || true
capture "$RUN_DIR/mounts.txt" findmnt -a || true
capture "$RUN_DIR/disk.txt" df -hT || true
capture "$RUN_DIR/packages-deb.txt" dpkg-query -W || true
capture "$RUN_DIR/packages-rpm.txt" rpm -qa || true
capture "$RUN_DIR/firewall-nft.txt" nft list ruleset || true
capture "$RUN_DIR/firewall-iptables4.txt" iptables-save || true
capture "$RUN_DIR/firewall-iptables6.txt" ip6tables-save || true
capture "$RUN_DIR/firewall-firewalld.txt" firewall-cmd --list-all-zones || true
capture "$RUN_DIR/timers.txt" systemctl list-timers --all --no-pager || true
capture_shell "$RUN_DIR/cron.txt" 'for f in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do if [[ -f $f ]]; then printf "\n### %s\n" "$f"; cat -- "$f"; fi; done' || true
capture "$RUN_DIR/containers.txt" docker ps -a --no-trunc || true
capture "$RUN_DIR/podman.txt" podman ps -a --no-trunc || true
: >"$RUN_DIR/scored-checks.txt"
if [[ $SCORING_STATUS == unknown ]]; then
  echo 'UNKNOWN: no scored manifest supplied; discovered services are candidates, not proof of scoring.' >>"$RUN_DIR/scored-checks.txt"
else
  for i in "${!SERVICES[@]}"; do
    s=${SERVICES[$i]}; p=${PORTS[$i]}
    if systemctl is-active --quiet "$s"; then state=running; else state=NOT_RUNNING; fi
    printf 'service\t%s\t%s\t%s\n' "$s" "$p" "$state" >>"$RUN_DIR/scored-checks.txt"
    proto=${p%%:*}; port=${p##*:}
    if have ss && ss -H -ltnu 2>/dev/null | awk -v port="$port" -v proto="$proto" '$1 == proto && $5 ~ ":" port "$" {found=1} END {exit !found}'; then
      printf 'port\t%s\tLISTENING\n' "$p" >>"$RUN_DIR/scored-checks.txt"
    else
      printf 'port\t%s\tNOT_LISTENING\n' "$p" >>"$RUN_DIR/scored-checks.txt"
    fi
  done
  for u in "${ACCOUNTS[@]}"; do
    if getent passwd "$u" >/dev/null; then state=present; else state=MISSING; fi
    printf 'account\t%s\t%s\n' "$u" "$state" >>"$RUN_DIR/scored-checks.txt"
  done
  for p in "${DATA_PATHS[@]}"; do
    if [[ -e $p ]]; then state=present; else state=MISSING; fi
    printf 'data\t%s\t%s\n' "$p" "$state" >>"$RUN_DIR/scored-checks.txt"
  done
fi
note "Inventory: $RUN_DIR"
