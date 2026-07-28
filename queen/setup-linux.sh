#!/usr/bin/env bash
# HexBee Queen setup for Linux — Fedora (including Asahi Remix on Apple
# Silicon), Debian/Kali/Ubuntu, Arch, and openSUSE.
#
# Installs the analyst CLI (hexbee-queen) and the Comb forensic toolkit
# (hexbee-comb) into isolated venvs via pipx, plus the system tooling Comb and
# the engagement tools use.
#
# Run from the repo root:  bash queen/setup-linux.sh
#
# Options:
#   --minimal     analyst CLI + Comb only; skip optional system tooling
#   --with-netmon also install hexbee-netmon (Linux-only; needs capabilities)
#   --with-ai     also install Ollama for Hive Mind
#   --no-yara     skip the YARA malware-matching extra
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.local/bin:$PATH"

MINIMAL=0
WITH_NETMON=0
WITH_AI=0
WITH_YARA=1

while [ $# -gt 0 ]; do
    case "$1" in
        --minimal)     MINIMAL=1 ;;
        --with-netmon) WITH_NETMON=1 ;;
        --with-ai)     WITH_AI=1 ;;
        --no-yara)     WITH_YARA=0 ;;
        -h|--help)     sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

if [ "$(uname -s)" != "Linux" ]; then
    echo "This installer is for Linux. On macOS use: bash queen/setup-macos.sh" >&2
    exit 1
fi

# -- distro detection ------------------------------------------------------
# By which binary exists, not by parsing /etc/os-release, so derivatives work
# with no entry here. Asahi Remix is Fedora, so it lands on dnf.
if   command -v dnf    >/dev/null 2>&1; then PKG=dnf
elif command -v apt-get>/dev/null 2>&1; then PKG=apt
elif command -v pacman >/dev/null 2>&1; then PKG=pacman
elif command -v zypper >/dev/null 2>&1; then PKG=zypper
else
    echo "No supported package manager found (dnf/apt/pacman/zypper)." >&2
    echo "Install pipx and sleuthkit yourself, then: pipx install ./queen ./comb" >&2
    exit 1
fi

ARCH="$(uname -m)"
echo "==> HexBee Queen setup (Linux $ARCH, $PKG)"
if [ "$ARCH" = "aarch64" ] && [ -d /proc/device-tree ] \
   && grep -qi apple /proc/device-tree/compatible 2>/dev/null; then
    echo "    Apple Silicon detected — Asahi. Everything below is native aarch64."
    IS_ASAHI=1
else
    IS_ASAHI=0
fi

# Already root (containers, minimal installs) means no sudo — and plenty of
# those images do not ship sudo at all, so calling it would fail on a machine
# that needed no privilege escalation in the first place.
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    echo "Not root and sudo is not installed — install the system packages" >&2
    echo "yourself, then re-run with --minimal." >&2
    SUDO=""
fi

pkg_install() {  # pkg_install <name...> — never fatal; report and continue
    local pkgs=("$@")
    case "$PKG" in
        dnf)    $SUDO dnf install -y "${pkgs[@]}" ;;
        apt)    $SUDO apt-get install -y "${pkgs[@]}" ;;
        pacman) $SUDO pacman -S --needed --noconfirm "${pkgs[@]}" ;;
        zypper) $SUDO zypper install -y "${pkgs[@]}" ;;
    esac || echo "    could not install: ${pkgs[*]} — continuing" >&2
}

# Package names that differ between distributions. EWF (E01 evidence images)
# is the awkward one: Debian and Kali call it ewf-tools, Fedora and openSUSE
# libewf-tools, Arch ships the tools inside libewf itself.
name_for() {  # name_for <generic-name>
    local p="$1"
    case "$PKG:$p" in
        apt:ewf)    echo "ewf-tools" ;;
        dnf:ewf)    echo "libewf-tools" ;;
        zypper:ewf) echo "libewf-tools" ;;
        pacman:ewf) echo "libewf" ;;
        *)          echo "$p" ;;
    esac
}

# -- pipx ------------------------------------------------------------------
echo "==> Installing pipx"
if ! command -v pipx >/dev/null 2>&1; then
    [ "$PKG" = "apt" ] && $SUDO apt-get update
    pkg_install pipx
    command -v pipx >/dev/null 2>&1 && pipx ensurepath >/dev/null 2>&1 || true
else
    echo "    already installed"
fi
command -v pipx >/dev/null 2>&1 \
    || { echo "pipx is required and could not be installed." >&2; exit 1; }

# -- system tooling --------------------------------------------------------
if [ "$MINIMAL" -eq 1 ]; then
    echo "==> Skipping optional system tooling (--minimal)"
else
    echo "==> Installing system forensics tooling"
    # Sleuth Kit is the one that materially changes what Comb can do.
    pkg_install sleuthkit
    pkg_install "$(name_for ewf)"
    pkg_install nmap
    pkg_install smartmontools
fi

# -- HexBee commands -------------------------------------------------------
echo "==> Installing hexbee-queen (analyst CLI)"
pipx install --force "$REPO_ROOT/queen"

echo "==> Installing hexbee-comb (forensic triage toolkit)"
pipx install --force "$REPO_ROOT/comb"

if [ "$WITH_YARA" -eq 1 ]; then
    echo "==> Adding YARA malware matching to Comb"
    # Optional by design: without it Comb skips the YARA pass and says so.
    # aarch64 wheels exist; if pip has to build, it needs a compiler and
    # openssl headers, which is why a failure here is not fatal.
    pipx inject hexbee-comb "yara-python>=4.3" \
        || echo "    yara-python unavailable — Comb will scan without malware matching" >&2
fi

# -- netmon (Linux only) ---------------------------------------------------
if [ "$WITH_NETMON" -eq 1 ]; then
    echo "==> Installing hexbee-netmon (passive network monitoring)"
    pipx install --force "$REPO_ROOT/netmon"
    cat <<'EOF'
    Netmon needs raw-socket capability. Grant it to your interpreter with:
      sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"
    Then: hexbee-netmon run --mode ids --iface <interface>
EOF
fi

# -- optional local AI -----------------------------------------------------
if [ "$WITH_AI" -eq 1 ]; then
    echo "==> Installing Ollama for Hive Mind (runs locally, stays offline)"
    curl -fsSL https://ollama.com/install.sh | sh \
        || echo "    Ollama install failed — see https://ollama.com/download" >&2
    echo "    Then: ollama pull llama3.2"
fi

# -- verification ----------------------------------------------------------
echo
echo "==> Verifying"
check() {
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
~/.local/bin to your PATH) or run: exec \$SHELL -l

Connect to your Hive:
  hexbee-queen connect http://<hive-address>:8080 -u <user>
  hexbee-queen status

Point-and-click disk triage:
  hexbee-comb serve          # http://127.0.0.1:8091

Run it as a desktop app (no terminal left open):
  bash scripts/make-linux-app.sh

EOF

if [ "$IS_ASAHI" -eq 1 ]; then
    cat <<'EOF'
Asahi notes:

  * Netmon works here — unlike macOS, Linux gives you raw packet capture.
    Install it with --with-netmon.
  * Memory acquisition needs a LiME module built against the Asahi kernel:
      sudo dnf install kernel-devel-$(uname -r) gcc make
    then build LiME and point HEXBEE_LIME_MODULE at the .ko.
  * Asahi kernels use 16K pages. Python wheels are fine; if you ever add a
    prebuilt third-party binary, check it is not 4K-page-only.
  * wkhtmltopdf is not packaged for Fedora. The HTML engagement report is the
    deliverable — print it to PDF from your browser.
EOF
fi
