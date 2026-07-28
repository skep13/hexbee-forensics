"""What to type to install a missing system tool, on *this* machine.

"Linux" is not a package manager. Kali says apt, Fedora — including Asahi
Remix on Apple Silicon — says dnf, and an operator told to run a command their
machine does not have is no better off than one told "not found".

Detection is by which binary exists, not by parsing /etc/os-release, so
derivative distributions work without an entry here.

Comb installs without the Hive, so this is deliberately a copy of the same
few lines in `hexbee_hive.doctor` rather than a shared import — the packages
are independently installable by design.
"""

from __future__ import annotations

import platform
import shutil

_MANAGERS = [
    ("apt", "sudo apt install {}"),
    ("dnf", "sudo dnf install {}"),
    ("pacman", "sudo pacman -S {}"),
    ("zypper", "sudo zypper install {}"),
    ("apk", "sudo apk add {}"),
]


def install_hint(package: str) -> str:
    """The exact command to install `package`, or a plain fallback."""
    if platform.system() == "Darwin":
        return f"brew install {package}"
    for name, template in _MANAGERS:
        if shutil.which(name):
            return template.format(package)
    return f"install {package} and put it on your PATH"
