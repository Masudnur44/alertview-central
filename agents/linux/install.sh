#!/bin/sh
# Installs the FINPAY SOC Linux agent as a systemd service.
#   sudo ./install.sh --url https://soc.finpaytech.com --key soc_xxxxxxxx
set -eu

URL=""; KEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
done
[ -n "$URL" ] && [ -n "$KEY" ] || { echo "usage: sudo $0 --url https://soc.example.com --key soc_..."; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }

DIR="$(cd "$(dirname "$0")" && pwd)"
install -d -m 755 /opt/finpay-soc-agent /var/lib/finpay-soc-agent
install -m 755 "$DIR/finpay-soc-agent.py" /opt/finpay-soc-agent/finpay-soc-agent.py

umask 077
printf '{"url": "%s", "key": "%s"}\n' "$URL" "$KEY" > /etc/finpay-soc-agent.json
chmod 600 /etc/finpay-soc-agent.json

cat > /etc/systemd/system/finpay-soc-agent.service <<'UNIT'
[Unit]
Description=FINPAY SOC security agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/finpay-soc-agent/finpay-soc-agent.py
Restart=always
RestartSec=5
# Needs to read the journal / auth log; otherwise locked down.
User=root
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/finpay-soc-agent
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

python3 /opt/finpay-soc-agent/finpay-soc-agent.py --test
systemctl daemon-reload
systemctl enable --now finpay-soc-agent
echo "finpay-soc-agent installed and running. Logs: journalctl -u finpay-soc-agent -f"
