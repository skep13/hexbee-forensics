#!/usr/bin/env bash
# HexBee Hive installer for Raspberry Pi OS Lite (64-bit).
# Run as root from the repo's hive/ directory:  sudo bash install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash install.sh" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

echo "==> Installing OS packages (Mosquitto broker, Python venv)"
apt-get update
apt-get install -y --no-install-recommends mosquitto python3-venv python3-pip

echo "==> Creating hexbee service user and directories"
id hexbee &>/dev/null || useradd --system --home /var/lib/hexbee --shell /usr/sbin/nologin hexbee
mkdir -p /var/lib/hexbee /etc/hexbee /opt/hexbee
chown hexbee:hexbee /var/lib/hexbee

echo "==> Installing the Hive into a virtualenv"
python3 -m venv /opt/hexbee/venv
/opt/hexbee/venv/bin/pip install --upgrade pip
/opt/hexbee/venv/bin/pip install "$HERE"

if [[ ! -f /etc/hexbee/hive.env ]]; then
    echo "==> Writing default /etc/hexbee/hive.env"
    INGEST_KEY="$(tr -dc 'a-f0-9' < /dev/urandom | head -c 32)"
    cat > /etc/hexbee/hive.env <<EOF
HEXBEE_DATA_DIR=/var/lib/hexbee
HEXBEE_MQTT_HOST=127.0.0.1
HEXBEE_MQTT_PORT=1883
HEXBEE_WEB_HOST=0.0.0.0
HEXBEE_WEB_PORT=8080
# Shared key Scouts use for REST ingest (also generated for you):
HEXBEE_INGEST_KEY=${INGEST_KEY}
EOF
    chmod 640 /etc/hexbee/hive.env
    chown root:hexbee /etc/hexbee/hive.env
fi

echo "==> Restricting Mosquitto to the LAN listener defaults"
# Mosquitto 2.x refuses anonymous remote connections unless configured; give
# it an explicit listener. Tighten with per-Scout credentials + TLS later.
cat > /etc/mosquitto/conf.d/hexbee.conf <<'EOF'
listener 1883
allow_anonymous true
EOF

echo "==> Initializing the database"
sudo -u hexbee HEXBEE_DATA_DIR=/var/lib/hexbee /opt/hexbee/venv/bin/hexbee-hive init

echo "==> Installing systemd units"
cp "$HERE/systemd/hexbee-engine.service" "$HERE/systemd/hexbee-web.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mosquitto hexbee-engine hexbee-web

echo
echo "HexBee Hive installed."
echo "  Dashboard:   http://$(hostname -I | awk '{print $1}'):8080"
echo "  Ingest key:  see /etc/hexbee/hive.env"
echo
echo "Create your first user (administrator):"
echo "  sudo -u hexbee HEXBEE_DATA_DIR=/var/lib/hexbee /opt/hexbee/venv/bin/hexbee-hive user add admin administrator"
