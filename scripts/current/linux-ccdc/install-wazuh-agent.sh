#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
usage() { echo 'Usage: install-wazuh-agent.sh --manager HOST --version VERSION [--agent-name NAME] [--group GROUP] [--enrollment-password-file FILE] [--config manifest.tsv]'; }
manager='' version='' agent='' group='' password_file='' config=''
while (($#)); do
  case $1 in
    --manager|--version|--agent-name|--group|--enrollment-password-file|--config)
      (($# >= 2)) || die "Missing value for $1"
      case $1 in --manager) manager=$2;; --version) version=$2;; --agent-name) agent=$2;; --group) group=$2;; --enrollment-password-file) password_file=$2;; --config) config=$2;; esac; shift 2 ;;
    -h|--help) usage; exit 0;; *) die "Unknown argument: $1";;
  esac
done
need_root; load_config "$config"
[[ $manager =~ ^[A-Za-z0-9.:-]+$ && $version =~ ^[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9._]+$ ]] || die 'Valid --manager and exact --version (for example 4.14.10-1) are required'
[[ -z $agent || $agent =~ ^[A-Za-z0-9_.-]+$ ]] || die 'Invalid agent name'
[[ -z $group || $group =~ ^[A-Za-z0-9_,.-]+$ ]] || die 'Invalid group'
if [[ -n $password_file ]]; then
  [[ -f $password_file && ! -L $password_file ]] || die 'Password file must be a regular file'
  [[ $(stat -c %a "$password_file") == 600 ]] || die 'Password file must have mode 600'
  export WAZUH_REGISTRATION_PASSWORD
  IFS= read -r WAZUH_REGISTRATION_PASSWORD <"$password_file" || true
  [[ -n $WAZUH_REGISTRATION_PASSWORD ]] || die 'Password file is empty'
fi
export WAZUH_MANAGER=$manager
[[ -z $agent ]] || export WAZUH_AGENT_NAME=$agent
[[ -z $group ]] || export WAZUH_AGENT_GROUP=$group
[[ -f /etc/os-release ]] || die 'Cannot identify distribution'
# shellcheck disable=SC1091
source /etc/os-release
case ${ID:-} in
  debian|ubuntu) family=apt;; centos) family=rpm;; *) die "Unsupported distribution: ${ID:-unknown}";;
esac
if [[ $family == rpm ]]; then
  major=${VERSION_ID%%.*}; [[ $major =~ ^[0-9]+$ ]] && ((major >= 7)) || die 'CentOS 7 or newer required'
fi
if [[ $family == apt ]]; then
  installed=$(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null || true)
else
  installed=$(rpm -q --qf '%{VERSION}-%{RELEASE}' wazuh-agent 2>/dev/null || true)
fi
if [[ -n $installed ]]; then
  [[ $installed == "$version" ]] || die "Installed agent is $installed; requested $version. Resolve version change manually."
  note "Agent $version already installed; preserving its enrollment configuration."
  if [[ $family == apt && -f /etc/apt/sources.list.d/wazuh.list ]]; then
    sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list
    apt-mark hold wazuh-agent >/dev/null
  elif [[ $family == rpm && -f /etc/yum.repos.d/wazuh.repo ]]; then
    sed -i 's/^enabled=1$/enabled=0/' /etc/yum.repos.d/wazuh.repo
  fi
else
  if [[ $family == apt ]]; then
    have apt-get || die 'apt-get is required'
    if ! have gpg || ! have curl; then apt-get update && apt-get install -y gnupg curl ca-certificates; fi
    have gpg && have curl || die 'Could not install gpg and curl'
    key=/usr/share/keyrings/wazuh.gpg
    mkdir -p /usr/share/keyrings /etc/apt/sources.list.d
    tmp=$(mktemp); trap 'rm -f -- "$tmp"' EXIT
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "$tmp"
    gpg --batch --yes --dearmor -o "$key" "$tmp"
    chmod 644 "$key"
    repo=/etc/apt/sources.list.d/wazuh.list
    [[ ! -e $repo ]] || cp -a -- "$repo" "$repo.ccdc-$(date +%s).bak"
    printf 'deb [signed-by=%s] https://packages.wazuh.com/4.x/apt/ stable main\n' "$key" >"$repo"
    apt-get update
    apt-cache madison wazuh-agent | awk '{print $3}' | grep -Fxq "$version" || die "Agent version $version is not available in apt"
    apt-get install -y "wazuh-agent=$version"
    sed -i 's/^deb /#deb /' "$repo"
    apt-mark hold wazuh-agent >/dev/null
  else
    have rpm && have curl || die 'rpm and curl are required'
    if have dnf; then pm=dnf; elif have yum; then pm=yum; else die 'yum or dnf required'; fi
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    repo=/etc/yum.repos.d/wazuh.repo
    mkdir -p /etc/yum.repos.d
    [[ ! -e $repo ]] || cp -a -- "$repo" "$repo.ccdc-$(date +%s).bak"
    cat >"$repo" <<'REPO'
[wazuh]
name=Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
enabled=1
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
REPO
    "$pm" makecache
    "$pm" --showduplicates list wazuh-agent | awk '$1 ~ /^wazuh-agent([.]|$)/ {print $2}' | grep -Fxq "$version" || die "Agent version $version is not available in $pm"
    "$pm" -y install "wazuh-agent-$version"
    sed -i 's/^enabled=1$/enabled=0/' "$repo"
  fi
fi
have systemctl || die 'systemd is required for supported distributions'
systemctl daemon-reload
systemctl enable --now wazuh-agent
systemctl is-active --quiet wazuh-agent || die 'Agent service did not start'
note "Wazuh agent $version active; manager requested: $manager"
note 'Confirm enrollment and connectivity on the Wazuh manager.'
