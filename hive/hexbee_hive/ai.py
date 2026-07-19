"""Hive Mind — local AI assistance, fully offline.

Talks to a locally-hosted LLM (Ollama on the Queen, or any llama.cpp server
exposing the Ollama generate API) for case summaries and analyst Q&A over
evidence. No model, no problem: a deterministic rule-based summarizer covers
the essentials so the feature degrades gracefully instead of breaking in the
field.

Nothing here ever leaves the LAN; the endpoint is whatever
HEXBEE_AI_URL points at (default http://127.0.0.1:11434).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections import Counter

SYSTEM_PROMPT = (
    "You are Hive Mind, the analyst assistant inside HexBee, a digital "
    "forensics platform. Answer concisely and factually from the evidence "
    "context provided. If the evidence doesn't support an answer, say so. "
    "Never invent artifacts, timestamps, or conclusions."
)


class LocalAI:
    def __init__(self, url: str, model: str, timeout: int = 120):
        self.url = url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def available(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.url}/api/tags", timeout=3) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def generate(self, prompt: str) -> str:
        body = json.dumps({
            "model": self.model,
            "system": SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }).encode()
        req = urllib.request.Request(
            f"{self.url}/api/generate", data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read()).get("response", "").strip()


# -- evidence context building -------------------------------------------

def case_context(db, case_id: int) -> str | None:
    from .cases import get_case
    from .timeline import case_timeline

    case = get_case(db, case_id)
    if case is None:
        return None
    lines = [
        f"Case {case['case_number']}: {case['title']} (status {case['status']})",
        f"Description: {case['description'] or 'none'}",
        "Incidents:",
    ]
    for i in case["incidents"]:
        lines.append(f"  #{i['id']} [{i['status']}, severity {i['severity']}] {i['title']}")
    lines.append("Timeline:")
    for t in case_timeline(db, case_id)[:120]:
        lines.append(f"  {t['at']} [{t['device']}] {t['narrative']}")
    lines.append("Investigator notes:")
    for n in case["notes"]:
        lines.append(f"  {n['created_at']} {n['author']}: {n['body']}")
    return "\n".join(lines)


def hive_context(db) -> str:
    from .search import stats

    s = stats(db)
    lines = [
        f"Hive totals: {s['events']} events from {s['devices']} devices; "
        f"{s['incidents_open']} open incidents; {s['cases_open']} open cases.",
        "Events by type: " + ", ".join(f"{t}={n}" for t, n in
                                       list(s["events_by_type"].items())[:15]),
    ]
    return "\n".join(lines)


# -- rule-based fallback --------------------------------------------------

def rule_based_case_summary(db, case_id: int) -> str | None:
    """Deterministic summary: what happened, where, how bad. Works with no
    model installed — the floor, not the ceiling."""
    from .cases import get_case
    from .timeline import case_timeline

    case = get_case(db, case_id)
    if case is None:
        return None
    timeline = case_timeline(db, case_id)
    if not timeline:
        return (f"Case {case['case_number']} ({case['title']}) has no evidence "
                f"assigned yet. {len(case['notes'])} investigator note(s) on file.")

    devices = sorted({t["device"] for t in timeline})
    types = Counter(t["event_type"] for t in timeline)
    critical = [t for t in timeline if t["severity"] >= 2]
    span = f"{timeline[0]['at']} to {timeline[-1]['at']}"

    parts = [
        f"Case {case['case_number']} — {case['title']} [{case['status']}].",
        f"{len(timeline)} events from {', '.join(devices)} spanning {span}.",
        "Activity: " + ", ".join(f"{t} ×{n}" for t, n in types.most_common(6)) + ".",
    ]
    if critical:
        parts.append(
            f"{len(critical)} high-severity event(s), first: "
            f"{critical[0]['narrative']} at {critical[0]['at']}; last: "
            f"{critical[-1]['narrative']} at {critical[-1]['at']}."
        )
    else:
        parts.append("No high-severity events recorded.")
    if case["notes"]:
        parts.append(f"Latest note ({case['notes'][-1]['author']}): "
                     f"{case['notes'][-1]['body']}")
    parts.append("[rule-based summary — start a local model for deeper analysis]")
    return " ".join(parts)


def summarize_case(db, engine: LocalAI, case_id: int) -> dict | None:
    context = case_context(db, case_id)
    if context is None:
        return None
    if engine.available():
        prompt = (f"Summarize this forensic case for a report: key activity, "
                  f"affected devices, severity, and recommended next steps.\n\n{context}")
        try:
            return {"summary": engine.generate(prompt), "engine": engine.model}
        except (urllib.error.URLError, OSError, ValueError):
            pass
    return {"summary": rule_based_case_summary(db, case_id), "engine": "rule-based"}


def ask(db, engine: LocalAI, question: str, case_id: int | None = None) -> dict:
    context = case_context(db, case_id) if case_id else hive_context(db)
    if context is None:
        context = hive_context(db)
    if engine.available():
        prompt = f"Evidence context:\n{context}\n\nAnalyst question: {question}"
        try:
            return {"answer": engine.generate(prompt), "engine": engine.model}
        except (urllib.error.URLError, OSError, ValueError):
            pass
    return {
        "answer": ("No local model is reachable, so here is the raw evidence "
                   "context for your question instead:\n\n" + context),
        "engine": "rule-based",
    }
