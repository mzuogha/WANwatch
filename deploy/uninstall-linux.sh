#!/usr/bin/env bash
# Remove the WANWatch service. Add --purge to also delete /opt/wanwatch (config, data, reports).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
systemctl disable --now wanwatch 2>/dev/null || true
rm -f /etc/systemd/system/wanwatch.service
systemctl daemon-reload
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf /opt/wanwatch
  userdel wanwatch 2>/dev/null || true
  echo "WANWatch removed, including /opt/wanwatch."
else
  echo "Service removed. Config, data and reports remain in /opt/wanwatch (use --purge to delete)."
fi
