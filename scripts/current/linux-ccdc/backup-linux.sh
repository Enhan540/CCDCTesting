#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
usage() { echo 'Usage: backup-linux.sh [--config manifest.tsv] [--output-dir DIR]'; }
config='' output=/var/backups/ccdc-linux
while (($#)); do
  case $1 in
    --config|--output-dir) (($# >= 2)) || die "Missing value for $1"; case $1 in --config) config=$2;; *) output=$2;; esac; shift 2 ;;
    -h|--help) usage; exit 0;; *) die "Unknown argument: $1";;
  esac
done
need_root; have tar || die 'tar is required'; have sha256sum || die 'sha256sum is required'
load_config "$config"
[[ $output == /* ]] || die 'Output directory must be absolute'
paths=(/etc /root /home /boot /srv /opt /usr/local /var/spool/cron /var/www)
paths+=("${DATA_PATHS[@]}")
for p in "${paths[@]}"; do
  [[ $output != "$p" && $output != "$p/"* ]] || die "Backup output is inside an included path: $p"
done
init_report_dir "$output"
stage=$(mktemp -d) || die 'Cannot create temporary staging directory'
trap 'rm -rf -- "$stage"' EXIT
mkdir -m 700 "$stage/evidence" "$stage/dumps"
status=complete
{
  printf 'host=%s\nutc=%s\nscoring_coverage=%s\n' "$(hostname -f 2>/dev/null || hostname)" "$(date -u +%FT%TZ)" "$SCORING_STATUS"
} >"$RUN_DIR/status.txt"
: >"$stage/include.txt"
for p in "${paths[@]}"; do
  if [[ ! -e $p ]]; then
    printf 'ABSENT\t%s\n' "$p" >>"$RUN_DIR/coverage.tsv"
    for configured in "${DATA_PATHS[@]}"; do [[ $configured == "$p" ]] && status=partial; done
    continue
  fi
  printf '%s\n' "${p#/}" >>"$stage/include.txt"
  printf 'INCLUDED\t%s\n' "$p" >>"$RUN_DIR/coverage.tsv"
done
if [[ -n $config ]]; then cp -- "$config" "$stage/evidence/scored-manifest.tsv"; fi
inv_args=()
[[ -n $config ]] && inv_args=(--config "$config")
if ! bash "$(dirname "${BASH_SOURCE[0]}")/inventory-linux.sh" "${inv_args[@]}" --output-dir "$stage/evidence" >"$stage/evidence/inventory.log" 2>&1; then
  status=partial; echo 'inventory_failed=1' >>"$RUN_DIR/status.txt"
fi
for hook in "${HOOKS[@]}"; do
  if [[ ! -f $hook || ! -x $hook || -L $hook ]]; then
    status=partial; printf 'HOOK_UNAVAILABLE\t%s\n' "$hook" >>"$RUN_DIR/coverage.tsv"; continue
  fi
  name=$(basename "$hook")
  target="$stage/dumps/$name-$(stamp)"
  mkdir -m 700 "$target"
  if have timeout; then timeout 300 "$hook" "$target" >"$target/stdout.log" 2>"$target/stderr.log" || hook_result=failed; else "$hook" "$target" >"$target/stdout.log" 2>"$target/stderr.log" || hook_result=failed; fi
  if [[ ${hook_result:-} == failed ]]; then status=partial; printf 'HOOK_FAILED\t%s\n' "$hook" >>"$RUN_DIR/coverage.tsv"; else printf 'HOOK_OK\t%s\n' "$hook" >>"$RUN_DIR/coverage.tsv"; fi
  unset hook_result
done
# GNU tar is available on the supported distributions. Keep the archive outside
# the selected source paths to avoid recursive capture.
if ! tar --create --gzip --file "$RUN_DIR/backup.tar.gz" --directory / --files-from "$stage/include.txt" --directory "$stage" evidence dumps >"$RUN_DIR/tar.stdout" 2>"$RUN_DIR/tar.stderr"; then
  status=partial
fi
if [[ -s "$RUN_DIR/backup.tar.gz" ]] && tar -tzf "$RUN_DIR/backup.tar.gz" >/dev/null 2>"$RUN_DIR/verify.stderr"; then
  (cd "$RUN_DIR" && sha256sum backup.tar.gz >backup.tar.gz.sha256)
  echo 'archive_verified=1' >>"$RUN_DIR/status.txt"
else
  status=partial; echo 'archive_verified=0' >>"$RUN_DIR/status.txt"
fi
printf 'result=%s\n' "$status" >>"$RUN_DIR/status.txt"
note "Backup $status: $RUN_DIR"
[[ $status == complete ]] || exit 1
