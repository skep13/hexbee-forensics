"""PyInstaller entry point (absolute import, run as a top-level script)."""

from hexbee_forager.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
