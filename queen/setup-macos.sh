#!/usr/bin/env bash
# HexBee Queen setup for macOS (Intel or Apple Silicon).
#
# Installs the analyst CLI (hexbee-queen) and the Comb forensic toolkit
# (hexbee-comb) into isolated venvs via pipx, plus the system tooling Comb
# and the engagement tools can use. The macOS counterpart of setup-kali.sh.
#
# Run from the repo root:  bash queen/setup-macos.sh
#
# Options:
#   --minimal     analyst CLI + Comb only; skip optional system tooling
#   --with-ai     also install Ollama and pull a model for Hive Mind
#   --no-yara     skip the YARA malware-matching extra
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

MINIMAL=0
WITH_AI=0
WITH_YARA=1

while [ $# -gt 0 ]; do
    case "$1" in
        --minimal)  MINIMAL=1 ;;
        --with-ai)  WITH_AI=1 ;;
        --no-yara)  WITH_YARA=0 ;;
        -h|--help)  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This installer is for macOS. On Kali/Debian use: bash queen/setup-kali.sh" >&2
    exit 1
fi

echo "==> HexBee Queen setup (macOS $(sw_vers -productVersion), $(uname -m))"

# -- Homebrew --------------------------------------------------------------
# Not installed automatically: Homebrew asks for your password and changes
# system directories, which is your call to make, not this script's.
if ! command -v brew >/dev/null 2>&1; then
    for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
        [ -x "$candidate" ] && eval "$("$candidate" shellenv)" && break
    done
fi

if ! command -v brew >/dev/null 2>&1; then
    cat >&2 <<'EOF'

Homebrew is required and was not found.

Install it, then re-run this script:

  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

EOF
    exit 1
fi

brew_install() {  # brew_install <formula> <what it gives you>
    local formula="$1" purpose="$2"
    if brew list --formula "$formula" >/dev/null 2>&1; then
        echo "    $formula — already installed"
    elif brew install "$formula"; then
        echo "    $formula — installed ($purpose)"
    else
        echo "    $formula — FAILED to install; $purpose will be unavailable" >&2
    fi
}

# -- pipx ------------------------------------------------------------------
echo "==> Installing pipx (isolated Python app installs)"
brew_install pipx "installing the HexBee commands"
pipx ensurepath >/dev/null 2>&1 || true

# pipx's bin directory is not on PATH until a new shell starts; add it here so
# the verification at the end of this run actually finds the commands.
PIPX_BIN="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || echo "$HOME/.local/bin")"
case ":$PATH:" in
    *":$PIPX_BIN:"*) ;;
    *) PATH="$PIPX_BIN:$PATH" ;;
esac
export PATH

# -- system forensics tooling ---------------------------------------------
if [ "$MINIMAL" -eq 1 ]; then
    echo "==> Skipping optional system tooling (--minimal)"
else
    echo "==> Installing system forensics tooling"
    # Sleuth Kit powers `hexbee-comb tsk-ls` and carving out of disk images
    # without mounting them. This is the one that materially changes what
    # Comb can do, so it is not gated behind a flag.
    brew_install sleuthkit  "opening disk images (hexbee-comb tsk-ls)"
    brew_install libewf     "E01/EWF evidence images (ewfmount needs macFUSE)"
    brew_install nmap       "hexbee-queen recon"
    brew_install smartmontools "disk health in forager diagnostics mode"
fi

# -- HexBee commands -------------------------------------------------------
echo "==> Installing hexbee-queen (analyst CLI)"
pipx install --force "$REPO_ROOT/queen"

echo "==> Installing hexbee-comb (forensic triage toolkit)"
pipx install --force "$REPO_ROOT/comb"

if [ "$WITH_YARA" -eq 1 ]; then
    echo "==> Adding YARA malware matching to Comb"
    # Optional by design: without it Comb skips the YARA pass and says so.
    pipx inject hexbee-comb "yara-python>=4.3" \
        || echo "    yara-python unavailable — Comb will scan without malware matching" >&2
fi

# -- optional local AI -----------------------------------------------------
if [ "$WITH_AI" -eq 1 ]; then
    echo "==> Installing Ollama for Hive Mind (runs locally, stays offline)"
    brew_install ollama "the local AI assistant"
    echo "    Start it and pull a model:"
    echo "      brew services start ollama"
    echo "      ollama pull llama3.2"
fi

# -- verification ----------------------------------------------------------
echo
echo "==> Verifying"
check() {  # check <binary> <label>
    if command -v "$1" >/dev/null 2>&1; then
        echo "    ok      $2 ($(command -v "$1"))"
    else
        echo "    MISSING $2"
    fi
}
check hexbee-queen "hexbee-queen"
check hexbee-comb  "hexbee-comb"
check mmls         "Sleuth Kit — disk image support"
check nmap         "nmap — hexbee-queen recon"

cat <<EOF

Installed. If a command is not found, open a new terminal (pipx added
$PIPX_BIN to your PATH) or run: exec \$SHELL -l

Connect to your Hive:
  hexbee-queen connect http://<hive-address>:8080 -u <user>
  hexbee-queen status

Check in plain English what is working and what is missing (run on the Hive,
or fetch it from this Mac once connected):
  hexbee-hive doctor
  curl -s http://<hive-address>:8080/api/v1/doctor

Point-and-click disk triage:
  hexbee-comb serve          # http://127.0.0.1:8091

What macOS cannot do, so you plan around it rather than debug it:
  * Memory capture           Apple blocks the access this needs. Acquire
                             memory from Windows or Linux targets instead.
  * hexbee-netmon            Raw packet capture belongs on the Pi (Linux);
                             macOS needs extra drivers for it.
  * PDF export (--pdf)       wkhtmltopdf is no longer packaged by Homebrew
                             (upstream archived it). The HTML report is the
                             real deliverable — open it and use
                             File > Print > Save as PDF.
  * Responder                Linux-only. \`hexbee-queen responder\` reads a
                             Responder log directory, so run Responder on the
                             Pi or the Kali box and point this at its Logs/.

Optional local AI for Hive Mind (skipped unless you passed --with-ai):
  brew install ollama && brew services start ollama && ollama pull llama3.2
  # then on the Hive set HEXBEE_AI_URL=http://<this-mac>:11434
EOF
