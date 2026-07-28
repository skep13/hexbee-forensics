#!/usr/bin/env bash
# Install HexBee as a desktop app on Linux — Fedora/Asahi, Debian/Kali, Arch.
#
#   bash scripts/make-linux-app.sh
#   bash scripts/make-linux-app.sh --uninstall
#
# Gives the same behaviour as HexBee.app on macOS: a launcher in the
# applications menu that starts the Hive dashboard and the Comb UI and opens
# the browser, and a second entry that stops them. Nothing keeps a terminal
# open, and nothing is left listening after you stop it.
#
# The services are systemd *user* units, which is the Linux equivalent of an
# app owning its own processes: they are tied to your login session and stop
# when you log out, with no root anywhere in the picture.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.local/bin:$PATH"

BIN_DIR="$HOME/.local/bin"
UNIT_DIR="$HOME/.config/systemd/user"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/512x512/apps"
CTL="$BIN_DIR/hexbee-ctl"

if [ "$(uname -s)" != "Linux" ]; then
    echo "This installs a Linux desktop app. On macOS use: bash scripts/make-macos-app.sh" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    echo "==> Removing HexBee desktop integration"
    systemctl --user stop hexbee-hive.service hexbee-comb.service 2>/dev/null || true
    systemctl --user disable hexbee-hive.service hexbee-comb.service 2>/dev/null || true
    rm -f "$UNIT_DIR/hexbee-hive.service" "$UNIT_DIR/hexbee-comb.service"
    rm -f "$APP_DIR/hexbee.desktop" "$APP_DIR/hexbee-stop.desktop"
    rm -f "$ICON_DIR/hexbee.png" "$CTL"
    systemctl --user daemon-reload 2>/dev/null || true
    update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
    # Deliberately kept: the evidence, and the env file holding your ingest
    # key. Reinstalling should not silently change which key collectors use,
    # and no uninstaller should delete evidence.
    echo "Removed the launcher, services and hexbee-ctl."
    echo "Left alone: evidence in ~/.local/share/hexbee, and your ingest key"
    echo "in ~/.config/hexbee-app.env — delete that by hand if you want it gone."
    exit 0
fi

command -v systemctl >/dev/null 2>&1 \
    || { echo "systemd is required for the service units." >&2; exit 1; }

HIVE_BIN="$(command -v hexbee-hive || true)"
[ -n "$HIVE_BIN" ] || HIVE_BIN="$REPO_ROOT/.venv/bin/hexbee-hive"
[ -x "$HIVE_BIN" ] \
    || { echo "hexbee-hive not found. Install it with: pipx install \"$REPO_ROOT/hive\"" >&2; exit 1; }
COMB_BIN="$(command -v hexbee-comb || true)"

DATA_DIR="${HEXBEE_DATA_DIR:-$HOME/.local/share/hexbee}"

mkdir -p "$BIN_DIR" "$UNIT_DIR" "$APP_DIR" "$ICON_DIR" "$DATA_DIR"
echo "==> Installing HexBee desktop app"

# -- environment -----------------------------------------------------------
# One file both units read, so the ingest key is never baked into a unit file
# that ends up in a backup or a git diff.
ENV_FILE="$HOME/.config/hexbee-app.env"
if [ ! -f "$ENV_FILE" ]; then
    mkdir -p "$(dirname "$ENV_FILE")"
    cat > "$ENV_FILE" <<EOF
HEXBEE_DATA_DIR=$DATA_DIR
HEXBEE_INGEST_KEY=devkey
EOF
    chmod 600 "$ENV_FILE"
    echo "    wrote $ENV_FILE (change HEXBEE_INGEST_KEY before real use)"
fi

# -- systemd user units ----------------------------------------------------
cat > "$UNIT_DIR/hexbee-hive.service" <<EOF
[Unit]
Description=HexBee Hive — evidence dashboard and API
After=default.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$HIVE_BIN web
Restart=on-failure
RestartSec=3
# The Pi runs this on 1 GB; keeping the cap here too means a runaway query
# fails visibly on the workstation instead of only in the field.
MemoryMax=512M

[Install]
WantedBy=default.target
EOF

if [ -n "$COMB_BIN" ] && [ -x "$COMB_BIN" ]; then
    cat > "$UNIT_DIR/hexbee-comb.service" <<EOF
[Unit]
Description=HexBee Comb — local triage UI
After=default.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$COMB_BIN serve --port 8091
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF
fi

# -- control script --------------------------------------------------------
cat > "$CTL" <<'CTLEOF'
#!/usr/bin/env bash
# HexBee control — start/stop/status the user services behind the desktop app.
set -euo pipefail
HIVE_PORT=8080
COMB_PORT=8091

units() {
    echo hexbee-hive.service
    [ -f "$HOME/.config/systemd/user/hexbee-comb.service" ] && echo hexbee-comb.service
}

wait_for_port() {
    local i
    for i in $(seq 1 40); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3<&-; return 0; }
        sleep 0.25
    done
    return 1
}

open_browser() {
    command -v xdg-open >/dev/null 2>&1 && xdg-open "$1" >/dev/null 2>&1 &
}

case "${1:-}" in
    start)
        # shellcheck disable=SC2046
        systemctl --user start $(units | tr '\n' ' ')
        if wait_for_port "$HIVE_PORT"; then
            open_browser "http://127.0.0.1:$HIVE_PORT/"
        else
            echo "The Hive did not start. Logs:" >&2
            echo "  journalctl --user -u hexbee-hive.service -n 40 --no-pager" >&2
            exit 1
        fi
        ;;
    stop)
        # shellcheck disable=SC2046
        systemctl --user stop $(units | tr '\n' ' ')
        ;;
    restart) "$0" stop; "$0" start ;;
    status)
        # shellcheck disable=SC2046
        systemctl --user --no-pager status $(units | tr '\n' ' ') || true
        ;;
    logs) journalctl --user -u hexbee-hive.service -n 50 --no-pager ;;
    *) echo "usage: hexbee-ctl {start|stop|restart|status|logs}" >&2; exit 2 ;;
esac
CTLEOF
chmod +x "$CTL"

# -- icon + desktop entries ------------------------------------------------
LOGO="$REPO_ROOT/hive/hexbee_hive/static/logo-512.png"
[ -f "$LOGO" ] && cp "$LOGO" "$ICON_DIR/hexbee.png"

cat > "$APP_DIR/hexbee.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=HexBee Forensics
Comment=Start the HexBee evidence dashboard and open it
Exec=$CTL start
Icon=hexbee
Terminal=false
Categories=System;Network;Security;
Keywords=forensics;dfir;evidence;incident;
StartupNotify=true
EOF

cat > "$APP_DIR/hexbee-stop.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Stop HexBee
Comment=Stop the HexBee dashboard and triage UI
Exec=$CTL stop
Icon=hexbee
Terminal=false
Categories=System;Security;
NoDisplay=false
EOF

systemctl --user daemon-reload
update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true

cat <<EOF

Installed.

  Launch          "HexBee Forensics" in your applications menu
  Stop            "Stop HexBee", or: hexbee-ctl stop
  From a shell    hexbee-ctl {start|stop|restart|status|logs}
  Dashboard       http://127.0.0.1:8080
  Comb UI         http://127.0.0.1:8091
  Evidence        $DATA_DIR
  Logs            journalctl --user -u hexbee-hive.service

The services stop when you log out. To keep the Hive running after logout
(useful if this machine is acting as the evidence hub):

  systemctl --user enable hexbee-hive.service
  loginctl enable-linger \$USER

Remove everything with: bash scripts/make-linux-app.sh --uninstall
EOF
