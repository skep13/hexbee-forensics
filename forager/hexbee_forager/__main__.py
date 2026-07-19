"""Entry point for `python -m hexbee_forager` and the PyInstaller build."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
