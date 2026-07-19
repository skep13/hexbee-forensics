"""Offline reference library: Wikipedia (ZIM) + local documents.

Two sources, both fully offline, both served from `<data_dir>/reference/`:

1. **ZIM archives** — the Kiwix format used for offline Wikipedia,
   WikiMed, iFixit, etc. Download a .zim (e.g. wikipedia_en_all_mini) from
   https://download.kiwix.org/zim/ on any online machine and drop it in.
   Requires the `libzim` python package (available for the Pi's aarch64
   Linux); when it isn't installed, ZIM files are listed but marked
   unavailable rather than crashing anything.

2. **Plain documents** — any .html/.md/.txt/.pdf files in the folder
   (procedure checklists, statute extracts, hardware manuals).
"""

from __future__ import annotations

import html
from pathlib import Path

DOC_TYPES = {".html": "text/html", ".htm": "text/html",
             ".md": "text/plain; charset=utf-8", ".txt": "text/plain; charset=utf-8",
             ".pdf": "application/pdf"}

try:
    from libzim.reader import Archive as _ZimArchive  # type: ignore
    from libzim.search import Query as _ZimQuery, Searcher as _ZimSearcher  # type: ignore
    HAVE_LIBZIM = True
except ImportError:
    HAVE_LIBZIM = False


class ReferenceLibrary:
    def __init__(self, ref_dir: Path):
        self.ref_dir = Path(ref_dir)
        self.ref_dir.mkdir(parents=True, exist_ok=True)
        self._zims: dict[str, object] = {}

    # -- listing ----------------------------------------------------------

    def catalog(self) -> dict:
        docs = sorted(
            p.name for p in self.ref_dir.iterdir()
            if p.is_file() and p.suffix.lower() in DOC_TYPES
        )
        zims = sorted(p.name for p in self.ref_dir.glob("*.zim"))
        return {"documents": docs, "zims": zims, "zim_supported": HAVE_LIBZIM}

    # -- plain documents --------------------------------------------------

    def document(self, name: str) -> tuple[bytes, str] | None:
        """(content, mime) for a doc in the library; None if absent/illegal."""
        if "/" in name or "\\" in name or name.startswith("."):
            return None
        path = self.ref_dir / name
        mime = DOC_TYPES.get(path.suffix.lower())
        if mime is None or not path.is_file():
            return None
        return path.read_bytes(), mime

    # -- ZIM --------------------------------------------------------------

    def _zim(self, name: str):
        if not HAVE_LIBZIM or "/" in name or "\\" in name:
            return None
        if name not in self._zims:
            path = self.ref_dir / name
            if not path.is_file():
                return None
            self._zims[name] = _ZimArchive(str(path))
        return self._zims[name]

    def zim_search(self, name: str, query: str, limit: int = 25) -> list[dict]:
        archive = self._zim(name)
        if archive is None or not query.strip():
            return []
        searcher = _ZimSearcher(archive)
        search = searcher.search(_ZimQuery().set_query(query))
        count = min(search.getEstimatedMatches(), limit)
        results = []
        for path in search.getResults(0, count):
            entry = archive.get_entry_by_path(path)
            results.append({"path": path, "title": entry.title})
        return results

    def zim_article(self, name: str, path: str) -> tuple[bytes, str] | None:
        archive = self._zim(name)
        if archive is None:
            return None
        try:
            entry = archive.get_entry_by_path(path)
        except KeyError:
            return None
        item = entry.get_item()
        return bytes(item.content), item.mimetype

    def zim_main_page(self, name: str) -> str | None:
        archive = self._zim(name)
        if archive is None:
            return None
        try:
            return archive.main_entry.get_item().path
        except Exception:
            return None


def render_markdown_basic(text: str) -> str:
    """Tiny offline-safe markdown-ish renderer (headers, code, paragraphs).
    Reference docs deserve readability without shipping a parser dependency."""
    out = []
    in_code = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(html.escape(line))
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            level = min(len(stripped) - len(stripped.lstrip("#")), 4)
            out.append(f"<h{level}>{html.escape(stripped.lstrip('# '))}</h{level}>")
        elif stripped.startswith(("- ", "* ")):
            out.append(f"<li>{html.escape(stripped[2:])}</li>")
        elif stripped:
            out.append(f"<p>{html.escape(stripped)}</p>")
    if in_code:
        out.append("</pre>")
    return "\n".join(out)
