#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
usage() { echo 'Usage: audit-linux.sh [--config manifest.tsv] [--output-dir DIR] [--patch [--security-updates]]'; }
config='' output=/var/log/ccdc-linux patch=0 updates=0
while (($#)); do
  case $1 in
    --config|--output-dir) (($# >= 2)) || die "Missing value for $1"; case $1 in --config) config=$2;; *) output=$2;; esac; shift 2 ;;
    --patch) patch=1; shift;; --security-updates) updates=1; shift;;
    -h|--help) usage; exit 0;; *) die "Unknown argument: $1";;
  esac
done
(( !updates || patch )) || die '--security-updates requires --patch'
need_root; load_config "$config"; init_report_dir "$output"
printf 'category\tseverity\tpath_or_item\tfinding\taction\n' >"$RUN_DIR/findings.tsv"
finding() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >>"$RUN_DIR/findings.tsv"; }
printf 'host=%s\nutc=%s\nscoring_coverage=%s\npatch=%s\n' "$(hostname)" "$(date -u +%FT%TZ)" "$SCORING_STATUS" "$patch" >"$RUN_DIR/summary.txt"
if ((patch)); then
  args=(); [[ -n $config ]] && args=(--config "$config")
  if ! bash "$(dirname "${BASH_SOURCE[0]}")/backup-linux.sh" "${args[@]}" >"$RUN_DIR/prepatch-backup.log" 2>&1; then
    finding backup high backup 'Backup incomplete or failed' 'No changes applied'; note "Audit: $RUN_DIR"; exit 2
  fi
  cat "$RUN_DIR/prepatch-backup.log" >>"$RUN_DIR/summary.txt"
fi
check_mode() {
  local file=$1 policy=$2 mode owner
  [[ -f $file && ! -L $file ]] || return 0
  mode=$(stat -c %a -- "$file") || return 0
  owner=$(stat -c %U -- "$file") || return 0
  if [[ $owner != root && $policy == root ]]; then
    finding permissions high "$file" "Owner is $owner" 'Review ownership manually'; return
  fi
  if (( (8#$mode & 0022) != 0 )); then
    if ((patch)); then chmod go-w -- "$file" && finding permissions medium "$file" "Writable by group or other ($mode)" 'Removed group/other write' || finding permissions high "$file" 'Permission repair failed' 'Review manually'
    else finding permissions medium "$file" "Writable by group or other ($mode)" 'Patch can remove write'; fi
  fi
  if [[ $policy == private ]] && (( (8#$mode & 0077) != 0 )); then
    if ((patch)); then chmod go-rwx -- "$file" && finding permissions medium "$file" "Private file exposed ($mode)" 'Removed group/other access' || finding permissions high "$file" 'Permission repair failed' 'Review manually'
    else finding permissions medium "$file" "Private file exposed ($mode)" 'Patch can remove access'; fi
  fi
}
check_mode /etc/shadow root
check_mode /etc/gshadow root
check_mode /etc/sudoers root
for f in /etc/sudoers.d/* /etc/pam.d/* /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; do check_mode "$f" root; done
for f in /etc/ssh/ssh_host_*_key; do check_mode "$f" private; done
: >"$RUN_DIR/ssh-keys.txt"
for home in /root /home/*; do
  [[ -d $home/.ssh && ! -L $home/.ssh ]] || continue
  for f in "$home"/.ssh/id_* "$home"/.ssh/authorized_keys; do
    [[ $f == *.pub ]] || check_mode "$f" private
    if [[ -f $f && ! -L $f ]]; then stat -c '%n %U:%G %a' -- "$f" >>"$RUN_DIR/ssh-keys.txt"; fi
  done
  auth="$home/.ssh/authorized_keys"
  if [[ -f $auth && ! -L $auth ]]; then
    if grep -En '(^|,)(command|environment)=' "$auth" >>"$RUN_DIR/ssh-key-options.txt"; then finding ssh medium "$auth" 'Authorized key has forced command or environment option' 'Review manually'; fi
    if have ssh-keygen; then ssh-keygen -lf "$auth" >>"$RUN_DIR/ssh-keys.txt" 2>&1 || finding ssh medium "$auth" 'Could not parse authorized keys' 'Review manually'; fi
  fi
done
if have sshd; then
  if ! sshd -t >"$RUN_DIR/sshd-validation.txt" 2>&1; then finding ssh high sshd 'Configuration validation failed' 'Review; no content change applied'; fi
  sshd -T >"$RUN_DIR/sshd-effective.txt" 2>&1 || true
  for setting in 'permitrootlogin yes' 'permitemptypasswords yes' 'passwordauthentication yes'; do
    if grep -Eiq "^${setting// /[[:space:]]+}$" "$RUN_DIR/sshd-effective.txt"; then finding ssh medium "$setting" 'Access policy needs review against scoring requirements' 'Review manually'; fi
  done
else finding ssh info sshd 'sshd unavailable' 'Review if SSH is expected'; fi
if have visudo && ! visudo -c >"$RUN_DIR/sudoers-validation.txt" 2>&1; then finding sudoers high sudoers 'Syntax validation failed' 'Review manually'; fi
if grep -RInE '(^|[[:space:]])NOPASSWD:' /etc/sudoers /etc/sudoers.d 2>/dev/null >"$RUN_DIR/sudo-nopasswd.txt"; then finding sudoers medium sudoers 'NOPASSWD entries present' 'Review manually'; fi
if grep -RInE '(^|[[:space:]])nullok([[:space:]]|$)' /etc/pam.d 2>/dev/null >"$RUN_DIR/pam-nullok.txt"; then finding pam high pam 'nullok setting present' 'Review manually'; fi
if grep -RInE '(curl|wget).*(\|[[:space:]]*(sh|bash))|(/tmp/|/dev/shm/)' /etc/cron* /var/spool/cron 2>/dev/null >"$RUN_DIR/cron-indicators.txt"; then finding cron medium cron 'Potentially risky cron command or temporary path' 'Review manually'; fi
if have systemctl; then
  systemctl list-units --type=service --state=running --no-legend --no-pager >"$RUN_DIR/running-services.txt" 2>&1 || true
  : >"$RUN_DIR/service-commands.txt"
  while read -r unit _; do
    [[ $unit == *.service ]] || continue
    command_line=$(systemctl show --property=ExecStart --value "$unit" 2>/dev/null || true)
    printf '%s\t%s\n' "$unit" "$command_line" >>"$RUN_DIR/service-commands.txt"
    [[ $command_line != *'/tmp/'* && $command_line != *'/dev/shm/'* ]] || finding service medium "$unit" 'Running service executes from a temporary path' 'Review manually'
  done <"$RUN_DIR/running-services.txt"
  for i in "${!SERVICES[@]}"; do
    s=${SERVICES[$i]}; p=${PORTS[$i]}
    systemctl is-active --quiet "$s" || finding scored high "$s" 'Scored service is not running' 'Investigate manually'
    proto=${p%%:*}; port=${p##*:}
    if ! have ss || ! ss -H -ltnu 2>/dev/null | awk -v port="$port" -v proto="$proto" '$1 == proto && $5 ~ ":" port "$" {found=1} END {exit !found}'; then
      finding scored high "$p" 'Scored port is not listening or ss is unavailable' 'Investigate manually'
    fi
  done
fi
for u in "${ACCOUNTS[@]}"; do getent passwd "$u" >/dev/null || finding scored high "$u" 'Scored account missing' 'Investigate manually'; done
updates_metadata_ok=0
if have apt-get; then
  if have apt; then apt list --upgradable >"$RUN_DIR/pending-updates.txt" 2>&1 || true; fi
elif have dnf; then dnf updateinfo list security >"$RUN_DIR/pending-updates.txt" 2>&1 && updates_metadata_ok=1 || finding updates info dnf 'Security update metadata unavailable' 'Review manually'
elif have yum; then yum updateinfo list security >"$RUN_DIR/pending-updates.txt" 2>&1 && updates_metadata_ok=1 || finding updates info yum 'Security update metadata unavailable' 'Review manually'
fi
if ((updates)); then
  if have dnf && ((updates_metadata_ok)); then dnf -y upgrade --security >"$RUN_DIR/update-result.txt" 2>&1 || finding updates high dnf 'Security update command failed' 'Review log'
  elif have yum && ((updates_metadata_ok)); then yum -y update-minimal --security >"$RUN_DIR/update-result.txt" 2>&1 || finding updates high yum 'Security update command failed' 'Review log'
  elif have apt-get && have unattended-upgrade; then
    policy=/etc/apt/apt.conf.d/50unattended-upgrades
    if [[ -f $policy ]] && awk '
      /Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)/ {inside=1; next}
      inside && /};/ {inside=0}
      inside && /^[[:space:]]*"/ {count++; if ($0 !~ /[Ss][Ee][Cc][Uu][Rr][Ii][Tt][Yy]/) bad=1}
      END {exit !(count > 0 && bad == 0)}' "$policy"; then
      apt-get update >"$RUN_DIR/apt-refresh.txt" 2>&1 && unattended-upgrade -v >"$RUN_DIR/update-result.txt" 2>&1 || finding updates high apt 'Security update command failed' 'Review logs'
    else finding updates medium apt 'Allowed origins are not exclusively security repositories' 'Configure security-only origins before updating'; fi
  else finding updates medium apt 'Security-only update tool unavailable' 'Install/configure unattended-upgrades first'; fi
fi
note "Audit: $RUN_DIR"
[[ $(wc -l <"$RUN_DIR/findings.tsv") -eq 1 ]] || exit 1
