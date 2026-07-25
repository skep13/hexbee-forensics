"""YARA matching — turns Comb from a cataloguer into a malware detector.

Comb already walks every file and reads it once for hashing. YARA is one
extra pass over the same bytes, which is why this is cheap: no additional
directory traversal, no additional I/O pattern, just rule evaluation.

Everything here is optional and degrades cleanly:

  * `yara-python` missing  -> `available()` is False, scans run exactly as
                              before, and the CLI says why.
  * no rules found         -> same, with a pointer to where rules are looked
                              for.

Rules are compiled **once** at scan start, never per file. Compilation is the
expensive part; matching a compiled ruleset against a few MB is milliseconds.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("hexbee.comb.yara")

try:  # pragma: no cover - import availability is environment-dependent
    import yara  # type: ignore
    HAVE_YARA = True
except ImportError:  # pragma: no cover
    yara = None  # type: ignore
    HAVE_YARA = False

# Where a HexBee kit keeps its offline ruleset. The external HDD is the
# intended home — a community bundle is ~10 MB of text, which is nothing on
# the HDD and unwelcome on the Pi's SD card.
DEFAULT_RULE_PATHS = [
    Path("/mnt/evidence/yara"),
    Path("/opt/hexbee/yara"),
    Path.home() / ".hexbee" / "yara",
    Path("yara-rules"),
]

RULE_SUFFIXES = (".yar", ".yara")

# Files larger than this are skipped: YARA over a multi-GB disk image or VM
# disk inside a triage window is not a good trade, and the T470 has 4 GB.
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024


@dataclass
class Match:
    path: str
    rule: str
    namespace: str
    tags: list[str]
    meta: dict
    strings: list[str]      # matched identifiers only, never matched data
    sha256: str = ""


def available() -> bool:
    return HAVE_YARA


def find_rule_dir(explicit: str | Path | None = None) -> Path | None:
    """First readable rules location: explicit -> env -> known paths."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("HEXBEE_YARA_RULES")
    if env:
        candidates.append(Path(env))
    candidates.extend(DEFAULT_RULE_PATHS)
    for path in candidates:
        if path.is_dir() and any(_rule_files(path)):
            return path
        if path.is_file() and path.suffix.lower() in RULE_SUFFIXES:
            return path
    return None


def _rule_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.rglob("*")
                  if p.is_file() and p.suffix.lower() in RULE_SUFFIXES)


class RuleSet:
    """A compiled YARA ruleset. Compile once, match many."""

    def __init__(self, rules, sources: list[str], path: Path):
        self._rules = rules
        self.sources = sources
        self.path = path

    @property
    def count(self) -> int:
        return len(self.sources)

    def match_file(self, path: Path, timeout: int = 20,
                   max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> list[Match]:
        try:
            if path.stat().st_size > max_bytes:
                return []
        except OSError:
            return []
        try:
            hits = self._rules.match(str(path), timeout=timeout)
        except Exception as exc:   # yara.Error, TimeoutError, OSError
            log.debug("yara match failed on %s: %s", path, exc)
            return []
        return [self._to_match(str(path), hit) for hit in hits]

    def match_bytes(self, data: bytes, label: str = "<memory>",
                    timeout: int = 20) -> list[Match]:
        try:
            hits = self._rules.match(data=data, timeout=timeout)
        except Exception as exc:
            log.debug("yara match failed on %s: %s", label, exc)
            return []
        return [self._to_match(label, hit) for hit in hits]

    @staticmethod
    def _to_match(path: str, hit) -> Match:
        # Only string *identifiers* are recorded. Matched bytes could be the
        # very content under investigation (a password, a key, PII), and a
        # detection record is not the place to copy it.
        identifiers = []
        for s in getattr(hit, "strings", []) or []:
            identifier = getattr(s, "identifier", None)
            if identifier is None and isinstance(s, tuple) and len(s) > 1:
                identifier = s[1]        # yara-python < 4.3 tuple form
            if identifier:
                identifiers.append(str(identifier))
        return Match(
            path=path,
            rule=hit.rule,
            namespace=getattr(hit, "namespace", "default"),
            tags=list(getattr(hit, "tags", []) or []),
            meta=dict(getattr(hit, "meta", {}) or {}),
            strings=sorted(set(identifiers))[:20],
        )


def compile_rules(rule_path: str | Path | None = None,
                  externals: dict | None = None) -> RuleSet | None:
    """Compile every rule file under `rule_path`. Returns None if YARA is
    unavailable or no rules were found.

    Individual broken rule files are skipped with a warning rather than
    failing the scan — a community bundle usually has a few files that need a
    module you do not have compiled in.
    """
    if not HAVE_YARA:
        return None
    root = find_rule_dir(rule_path)
    if root is None:
        return None

    files = [root] if root.is_file() else _rule_files(root)
    if not files:
        return None

    sources, namespaces = [], {}
    for path in files:
        namespace = path.stem
        try:
            # Compile each file alone first so one bad file cannot poison the set.
            yara.compile(filepath=str(path))
        except Exception as exc:
            log.warning("skipping unusable rule file %s: %s", path.name, exc)
            continue
        namespaces[namespace] = str(path)
        sources.append(namespace)
    if not namespaces:
        return None
    try:
        compiled = yara.compile(filepaths=namespaces,
                                externals=externals or {})
    except Exception as exc:
        log.warning("ruleset compilation failed: %s", exc)
        return None
    log.info("compiled %d YARA rule file(s) from %s", len(sources), root)
    return RuleSet(compiled, sources, root if root.is_dir() else root.parent)


def status(rule_path: str | Path | None = None) -> dict:
    """Human-readable capability report for the CLI and the Comb web UI."""
    root = find_rule_dir(rule_path)
    if not HAVE_YARA:
        return {"available": False, "reason": "yara-python is not installed "
                                              "(pip install yara-python)",
                "rules_dir": str(root) if root else None, "rule_files": 0}
    if root is None:
        return {"available": False,
                "reason": "no rules found — set HEXBEE_YARA_RULES or place "
                          ".yar files in " +
                          ", ".join(str(p) for p in DEFAULT_RULE_PATHS),
                "rules_dir": None, "rule_files": 0}
    files = [root] if root.is_file() else _rule_files(root)
    return {"available": True, "reason": "ready", "rules_dir": str(root),
            "rule_files": len(files)}
