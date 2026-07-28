#!/usr/bin/env bash
# HexBee Queen setup for Kali Linux — kept as the name the docs and muscle
# memory use. The actual work is in setup-linux.sh, which handles apt, dnf,
# pacman and zypper from one code path; two scripts doing the same job on
# different distributions is how they drift apart.
#
# Run from the repo root:  bash queen/setup-kali.sh [options]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
exec bash "$HERE/setup-linux.sh" "$@"
