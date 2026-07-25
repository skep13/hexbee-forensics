#!/usr/bin/env python3
"""Snapshot every HexBee CLI into the Hive's knowledge base.

The Hive cannot import the Queen, Comb, Forager, or Netmon packages — they
install separately and may not be present on the Pi at all. This script runs
from the repo root, where all five are importable, walks each argparse tree,
and writes what it finds to `hive/hexbee_hive/knowledge_commands.json`.

The point is that the assistant's command reference is *generated*. A
hand-written manual drifts the moment someone renames a flag; a generated one
cannot tell an operator to run something that no longer exists.

Run it after changing any CLI, and commit the result:

    python scripts/build_knowledge.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for component in ("hive", "queen", "comb", "forager", "netmon"):
    sys.path.insert(0, str(ROOT / component))

OUTPUT = ROOT / "hive" / "hexbee_hive" / "knowledge_commands.json"

# (module path, factory that returns a parser, program name)
CLIS = [
    ("hexbee_hive.cli", "hexbee-hive"),
    ("hexbee_queen.cli", "hexbee-queen"),
    ("hexbee_comb.cli", "hexbee-comb"),
    ("hexbee_forager.cli", "hexbee-forager"),
    ("hexbee_netmon.cli", "hexbee-netmon"),
]


def capture_parser(module_name: str) -> argparse.ArgumentParser | None:
    """Get the parser a CLI module builds, without running its command.

    Every HexBee CLI builds its parser inside `main()` and then calls
    `parse_args`. Rather than refactor five modules to expose the parser, we
    intercept `parse_args` — it is called exactly once, at the end of
    construction, with the parser fully assembled.
    """
    import importlib

    module = importlib.import_module(module_name)
    captured: dict[str, argparse.ArgumentParser] = {}
    original = argparse.ArgumentParser.parse_args

    def intercept(self, args=None, namespace=None):
        captured.setdefault("parser", self)
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = intercept
    try:
        module.main([])
    except SystemExit:
        pass
    except Exception as exc:
        print(f"  warning: {module_name} raised {type(exc).__name__}: {exc}")
    finally:
        argparse.ArgumentParser.parse_args = original
    return captured.get("parser")


def describe(prog: str, parser: argparse.ArgumentParser) -> list[dict]:
    """One record per leaf subcommand, with its help text and options."""
    records: list[dict] = []

    def subcommand_help(node, name: str) -> str:
        for action in getattr(node, "_actions", []):
            if isinstance(action, argparse._SubParsersAction):
                for choice in action._choices_actions:
                    if choice.dest == name:
                        return choice.help or ""
        return ""

    def walk(node, path: list[str]) -> None:
        subparser_actions = [a for a in getattr(node, "_actions", [])
                             if isinstance(a, argparse._SubParsersAction)]
        if not subparser_actions:
            return
        for action in subparser_actions:
            seen: set[int] = set()
            for name, sub in action.choices.items():
                if id(sub) in seen:      # aliases point at the same parser
                    continue
                seen.add(id(sub))
                sub_path = path + [name]
                nested = [a for a in getattr(sub, "_actions", [])
                          if isinstance(a, argparse._SubParsersAction)]
                if nested:
                    walk(sub, sub_path)
                    continue

                positionals, options = [], []
                for a in getattr(sub, "_actions", []):
                    if a.dest == "help":
                        continue
                    if a.option_strings:
                        label = ", ".join(a.option_strings)
                        options.append(f"{label} — {a.help}" if a.help else label)
                    else:
                        label = a.dest.upper()
                        if a.choices:
                            label += " {" + "|".join(str(c) for c in a.choices) + "}"
                        positionals.append(
                            f"{label} — {a.help}" if a.help else label)

                full = " ".join([prog] + sub_path)
                body_parts = [subcommand_help(node, name) or sub.description or ""]
                if positionals:
                    body_parts.append("Arguments: " + "; ".join(positionals))
                if options:
                    body_parts.append("Options: " + "; ".join(options))
                records.append({
                    "id": "cmd-" + "-".join([prog] + sub_path),
                    "title": full,
                    "body": "\n".join(p for p in body_parts if p),
                    "commands": [full],
                })
        return None

    walk(parser, [])
    return records


def main() -> int:
    all_records: list[dict] = []
    for module_name, prog in CLIS:
        print(f"walking {prog} …")
        try:
            parser = capture_parser(module_name)
        except ImportError as exc:
            print(f"  skipped: {exc}")
            continue
        if parser is None:
            print("  skipped: could not capture parser")
            continue
        records = describe(prog, parser)
        print(f"  {len(records)} command(s)")
        all_records.extend(records)

    OUTPUT.write_text(json.dumps(
        {"generated_by": "scripts/build_knowledge.py",
         "commands": all_records}, indent=2), encoding="utf-8")
    print(f"\nwrote {len(all_records)} command(s) to "
          f"{OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
