# Linux CCDC toolkit

Run these Bash scripts as root on Debian, Ubuntu, CentOS 7, or CentOS Stream 8+. They use systemd and standard GNU tools. Copy `scored.example.tsv` to a host-specific manifest, then list every scored unit, account, and application data path. Records are TAB separated. `service` takes a systemd unit, `tcp` or `udp`, and a port; `account`, `data`, and `hook` each take one name or absolute path. Hooks are trusted executable scripts that receive one output-directory argument and must write a consistent application dump there. Keep manifests and hooks root-owned. Without `--config`, reports say scoring coverage is unknown.

```bash
sudo bash inventory-linux.sh --config scored.tsv
sudo bash backup-linux.sh --config scored.tsv
sudo bash audit-linux.sh --config scored.tsv
sudo bash audit-linux.sh --config scored.tsv --patch
sudo bash audit-linux.sh --config scored.tsv --patch --security-updates
sudo bash install-wazuh-agent.sh --manager 192.0.2.10 --version 4.14.10-1 --agent-name web01 --group linux
```

The Wazuh version must be compatible with your manager. The installer accepts `--enrollment-password-file /root/wazuh-enrollment.txt` (mode 600), preserves an already installed agent at the requested version, enables and checks its service, and disables its package repository after installation. It does not prove manager enrollment; check the agent in Wazuh. The optional `--config` validates the same scored manifest.

Inventory and audit reports default to `/var/log/ccdc-linux/`; backups default to `/var/backups/ccdc-linux/`. Use `--output-dir /absolute/path` to override either default. Every run gets a private timestamped directory. Inventory captures accounts, services, processes, ports, connections, firewall state, cron, packages, mounts, and containers. An unavailable command is recorded in its own report file. Inventory lists scored services and accounts separately from discovered ones.

Backups include `/etc`, `/root`, `/home`, `/boot`, `/srv`, `/opt`, `/usr/local`, cron spools, `/var/www`, manifest data paths, inventory evidence, and hook output. `coverage.tsv` records included, absent, and failed items. `status.txt` says `result=complete` only when the archive verifies and no configured data or hook failed. Exit 1 means partial. An absent default path is informational; an absent manifest data path is partial. Review free space before use; the backup is file-level and live files can change during capture. Database consistency requires a suitable dump hook. Copy the bundle off-host promptly.

To verify and inspect a bundle, run `sha256sum -c backup.tar.gz.sha256` and `tar -tzf backup.tar.gz`. Restore only the required files into a maintenance environment first. For example, from the bundle directory, `tar -xzf backup.tar.gz -C /tmp/ccdc-restore etc/ssh/sshd_config`; then compare and validate before copying it into place. The archive can contain secrets, SSH keys, and password hashes; keep it root-only.

Audit writes `findings.tsv` and supporting evidence. It is a rule-based configuration audit, not a complete CVE scanner. Its default mode reads only. `--patch` first requires a complete backup, then removes group/other write access from sensitive access files and group/other access from SSH private keys and `authorized_keys`. It does not rewrite SSH, PAM, or sudoers contents, remove keys or cron jobs, or stop services. Findings identify those changes for manual review. `--security-updates` requires `--patch`; on apt systems it runs only when the host's `unattended-upgrade` allowed origins are exclusively security repositories. On yum/dnf it uses security update metadata. Missing metadata or tools are reported. Audit exit codes are 0 for no findings, 1 for findings, and 2 if a pre-patch backup fails.

The Wazuh repository procedure and deployment variables follow the [official Linux installation guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html) and [deployment variable reference](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-linux.html).
