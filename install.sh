#!/usr/bin/env bash
#
# HexBee installer — macOS and Linux.
#
#   ./install.sh              install everything appropriate for this machine
#   ./install.sh --minimal    just the core, skip the optional extras
#   ./install.sh --check      show what would happen, change nothing
#
# Safe to re-run: every step checks whether it has already been done.
#
# It explains what it is installing and why, because a beginner running an
# install script should end up understanding what they now have.

set -uo pipefail

MINIMAL=0
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --minimal) MINIMAL=1 ;;
        --check|--dry-run) CHECK_ONLY=1 ;;
        -h|--help) sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $arg (try --help)"; exit 1 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS="$(uname -s)"
FAILED=()
INSTALLED=()
SKIPPED=()

# -- output helpers -------------------------------------------------------
if [ -t 1 ]; then
    B=$'\033[1m'; DIM=$'\033[2m'; GRN=$'\033[32m'; YEL=$'\033[33m'
    RED=$'\033[31m'; RST=$'\033[0m'
else
    B=""; DIM=""; GRN=""; YEL=""; RED=""; RST=""
fi

step()  { printf "\n%s==> %s%s\n" "$B" "$1" "$RST"; }
info()  { printf "    %s\n" "$1"; }
why()   { printf "    %s%s%s\n" "$DIM" "$1" "$RST"; }
ok()    { printf "    %s[ok]%s %s\n" "$GRN" "$RST" "$1"; }
warn()  { printf "    %s[--]%s %s\n" "$YEL" "$RST" "$1"; }
fail()  { printf "    %s[!!]%s %s\n" "$RED" "$RST" "$1"; }
have()  { command -v "$1" >/dev/null 2>&1; }

run() {
    if [ "$CHECK_ONLY" = "1" ]; then
        printf "    %swould run:%s %s\n" "$DIM" "$RST" "$*"
        return 0
    fi
    "$@"
}

# -- preflight ------------------------------------------------------------
cat <<'BANNER'

  HexBee — digital forensics and authorised security testing
  ==========================================================

  This installs HexBee and the tools it works with. It will tell you what
  each thing is for as it goes, and skip anything already present.

  Nothing is installed system-wide except through your normal package
  manager (Homebrew on macOS, apt on Debian/Ubuntu/Kali). HexBee itself
  installs into isolated environments via pipx.

BANNER

if [ "$CHECK_ONLY" = "1" ]; then
    warn "Check mode — nothing will actually be installed."
fi

step "Checking this machine"
info "Operating system: $OS $(uname -m)"

case "$OS" in
    Darwin)
        PKG="brew"
        if ! have brew; then
            fail "Homebrew is not installed."
            info ""
            info "Homebrew is the standard way to install command-line tools"
            info "on macOS. Install it first with the line from https://brew.sh,"
            info "then run this script again."
            exit 1
        fi
        ok "Homebrew found"
        ;;
    Linux)
        if have apt-get; then
            PKG="apt"
            ok "apt found"
        else
            PKG="none"
            warn "No apt — you'll need to install system packages yourself."
        fi
        ;;
    *)
        fail "Unsupported system: $OS. HexBee runs on macOS and Linux."
        exit 1
        ;;
esac

# Python 3.9+
if have python3; then
    PYV="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'; then
        ok "Python $PYV"
    else
        fail "Python $PYV is too old — HexBee needs 3.9 or newer."
        exit 1
    fi
else
    fail "Python 3 not found."
    [ "$PKG" = "brew" ] && info "Install it with: brew install python"
    [ "$PKG" = "apt" ] && info "Install it with: sudo apt install python3 python3-pip"
    exit 1
fi

# pipx keeps each tool in its own environment, so they cannot break each
# other's dependencies — and nothing lands in your system Python.
if ! have pipx; then
    step "Installing pipx"
    why "pipx installs each command-line tool into its own isolated"
    why "environment, so they can't conflict with each other or with"
    why "anything else on your system."
    case "$PKG" in
        brew) run brew install pipx && run pipx ensurepath ;;
        apt)  run sudo apt-get install -y pipx && run pipx ensurepath ;;
        *)    run python3 -m pip install --user pipx ;;
    esac
    have pipx && INSTALLED+=("pipx") || FAILED+=("pipx")
else
    ok "pipx already installed"
fi

# -- system packages ------------------------------------------------------
install_pkg() {
    local pkg="$1" binary="$2" what="$3"
    if have "$binary"; then
        ok "$pkg — already installed"
        SKIPPED+=("$pkg")
        return 0
    fi
    why "$what"
    case "$PKG" in
        brew) run brew install "$pkg" >/dev/null 2>&1 ;;
        apt)  run sudo apt-get install -y "$pkg" >/dev/null 2>&1 ;;
        *)    warn "$pkg — install it yourself"; return 1 ;;
    esac
    if have "$binary" || [ "$CHECK_ONLY" = "1" ]; then
        ok "$pkg — installed"
        INSTALLED+=("$pkg")
    else
        warn "$pkg — install failed, HexBee will work without it"
        FAILED+=("$pkg")
    fi
}

step "Installing the tools HexBee works with"

install_pkg sleuthkit tsk_recover \
    "Opens forensic disk images and pulls the files out without mounting them.
    This is how you examine a USB stick or a disk image safely."

if [ "$MINIMAL" = "0" ]; then
    install_pkg nmap nmap \
        "Scans a network to find machines and the services they run.
    Used by the authorised-testing tools."

    install_pkg smartmontools smartctl \
        "Reads a disk's own health report, so you get warned before a
    drive fails."

    if [ "$OS" = "Linux" ]; then
        install_pkg mosquitto mosquitto \
            "Receives events from the Scout hardware sensors."
    fi
fi

# -- HexBee itself --------------------------------------------------------
step "Installing HexBee"

install_component() {
    local dir="$1" binary="$2" what="$3"
    why "$what"
    if have "$binary"; then
        run pipx upgrade "$binary" >/dev/null 2>&1 || \
            run pipx install --force "$ROOT/$dir" >/dev/null 2>&1
        ok "$binary — updated"
    else
        if run pipx install "$ROOT/$dir" >/dev/null 2>&1; then
            ok "$binary — installed"
            INSTALLED+=("$binary")
        else
            fail "$binary — install failed"
            FAILED+=("$binary")
        fi
    fi
}

install_component hive hexbee-hive \
    "The Hive: stores evidence in a tamper-evident log and serves the
    web dashboard you investigate from. This is the centre of everything."

install_component queen hexbee-queen \
    "The analyst command line: cases, searching, reports, and the
    authorised-testing tools."

install_component comb hexbee-comb \
    "Examines disk images, USB sticks and folders — file inventory,
    fingerprints, deleted-file recovery, malware signatures."

install_component forager hexbee-forager \
    "Collects evidence from a computer that is switched on, without
    changing anything on it."

if [ "$OS" = "Linux" ] || [ "$MINIMAL" = "0" ]; then
    install_component netmon hexbee-netmon \
        "Watches network traffic for scanning, spoofing and other attacks.
    Raw capture is Linux-only, so this belongs on the Raspberry Pi."
fi

# -- optional Python extras ----------------------------------------------
if [ "$MINIMAL" = "0" ]; then
    step "Adding optional capabilities"
    add_extra() {
        local target="$1" package="$2" what="$3"
        why "$what"
        if run pipx inject "$target" "$package" >/dev/null 2>&1; then
            ok "$package"
        else
            warn "$package — skipped (HexBee works without it)"
        fi
    }
    add_extra hexbee-comb yara-python \
        "Matches files against malware signatures during a scan."
    add_extra hexbee-comb pillow \
        "Reads photo metadata, including GPS coordinates from images."
    add_extra hexbee-forager psutil \
        "Richer process and network detail when collecting from a live
    computer."
    add_extra hexbee-hive segno \
        "Generates QR labels for evidence bags."
fi

# -- network capture permission (Linux only) ------------------------------
if [ "$OS" = "Linux" ] && [ "$MINIMAL" = "0" ] && have hexbee-netmon; then
    step "Granting network capture permission"
    why "Reading raw network traffic is privileged. This grants that one"
    why "capability to Python rather than running the monitor as root."
    PYBIN="$(readlink -f "$(command -v python3)")"
    if run sudo setcap cap_net_raw,cap_net_admin=eip "$PYBIN" 2>/dev/null; then
        ok "granted to $PYBIN"
    else
        warn "could not grant — run this yourself if you want network monitoring:"
        info "    sudo setcap cap_net_raw,cap_net_admin=eip $PYBIN"
    fi
fi

# -- local AI (optional) --------------------------------------------------
if [ "$MINIMAL" = "0" ]; then
    step "Local AI assistant (optional)"
    why "HexBee can answer questions and draft report text using a model"
    why "running on your own machine. Nothing is sent to the internet."
    why "Everything works without it — you just get less conversation."
    if have ollama; then
        ok "Ollama already installed"
        info ""
        info "Pull a small model when you're ready. On 8 GB of RAM:"
        info "    ollama pull llama3.2:3b"
        info "    export OLLAMA_KEEP_ALIVE=30s"
    elif [ "$PKG" = "brew" ]; then
        info "Install with:  brew install ollama"
    else
        info "Install from:  https://ollama.com"
    fi
fi

# -- summary --------------------------------------------------------------
step "Summary"
[ ${#INSTALLED[@]} -gt 0 ] && ok "Installed: ${INSTALLED[*]}"
[ ${#SKIPPED[@]} -gt 0 ]   && info "Already present: ${SKIPPED[*]}"
[ ${#FAILED[@]} -gt 0 ]    && warn "Could not install: ${FAILED[*]}"

if [ "$CHECK_ONLY" = "1" ]; then
    printf "\n%sCheck complete — nothing was changed.%s\n\n" "$B" "$RST"
    exit 0
fi

cat <<'NEXT'

  ------------------------------------------------------------------
  Installed. Two commands from here:
  ------------------------------------------------------------------

  1. Set it up — creates the evidence log and your login, and explains
     each step as it goes:

         hexbee-hive setup

  2. Then start the dashboard and click "Start Here":

         hexbee-hive web

  If a command isn't found, your shell needs to pick up pipx's path.
  Open a new terminal, or run:  pipx ensurepath

  To see exactly what works on this machine and how to fix what doesn't:

         hexbee-hive doctor

NEXT
