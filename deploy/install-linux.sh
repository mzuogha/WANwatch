#!/usr/bin/env bash
# Install WANWatch as a systemd service. Run from the project folder: sudo ./deploy/install-linux.sh
set -euo pipefail
PREFIX=/opt/wanwatch
SRC="$(cd "$(dirname "$0")/.." && pwd)"
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
command -v python3 >/dev/null || { echo "python3 (3.10+) is required."; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || { echo "Python 3.10+ is required."; exit 1; }

id wanwatch &>/dev/null || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin wanwatch
mkdir -p "$PREFIX"/{data,logs,reports}
cp -r "$SRC/wanwatch" "$SRC/requirements.txt" "$PREFIX/"
[[ -f "$PREFIX/config.yaml" ]] || cp "$SRC/config.example.yaml" "$PREFIX/config.yaml"
[[ -f "$PREFIX/wanwatch.env" ]] || cp "$SRC/wanwatch.env.example" "$PREFIX/wanwatch.env"

python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet -r "$PREFIX/requirements.txt"

chown -R root:wanwatch "$PREFIX"
chmod 750 "$PREFIX"
chown -R wanwatch:wanwatch "$PREFIX"/{data,logs,reports}
chown root:wanwatch "$PREFIX"/config.yaml "$PREFIX"/wanwatch.env
chmod 640 "$PREFIX"/config.yaml "$PREFIX"/wanwatch.env

cp "$SRC/deploy/wanwatch.service" /etc/systemd/system/wanwatch.service
systemctl daemon-reload
systemctl enable wanwatch >/dev/null

cat <<MSG

Installed to $PREFIX. Before starting:
  1. sudo nano $PREFIX/wanwatch.env        (FortiGate API token, SMTP password)
  2. sudo nano $PREFIX/config.yaml         (firewall URL, link names, alert channels)
  3. sudo -u wanwatch $PREFIX/venv/bin/python -m wanwatch hash-password   -> paste into web.password_hash
  4. sudo -u wanwatch $PREFIX/venv/bin/python -m wanwatch check -c $PREFIX/config.yaml
  5. sudo systemctl start wanwatch && journalctl -u wanwatch -f
MSG
