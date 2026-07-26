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
import re
import urllib.error
import urllib.request
from collections import Counter

SYSTEM_PROMPT = (
    "You are Hive Mind, the analyst assistant inside HexBee, a digital "
    "forensics platform. Answer concisely and factually from the evidence "
    "context provided. If the evidence doesn't support an answer, say so. "
    "Never invent artifacts, timestamps, or conclusions."
)

# The operator-assistance prompt is deliberately much stricter than the
# evidence one. The model running this is a 1-3B local model; asked how to do
# something in HexBee without grounding, it will produce a plausible command
# that does not exist, and the operator will try it. Inventing a command is
# worse than refusing, so the model is given the exact manual section and told
# it may not go beyond it.
OPERATOR_PROMPT = (
    "You are the HexBee operator assistant. HexBee is a digital forensics and "
    "authorised-security-testing toolkit.\n"
    "Answer ONLY from the HexBee reference given to you. Follow these rules "
    "exactly:\n"
    "1. Give the exact command from the reference, verbatim. Do not alter "
    "flags, invent flags, or guess at syntax.\n"
    "2. Replace only obvious placeholders (<case_id>, <name>) with the user's "
    "values.\n"
    "3. If the reference does not answer the question, say 'The HexBee "
    "reference does not cover that' and name the closest command it does "
    "describe.\n"
    "4. Be brief. A sentence of explanation, then the command.\n"
    "5. Never invent a command, subcommand, flag, file path, or event type."
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

    def generate(self, prompt: str, system: str | None = None,
                 temperature: float = 0.2) -> str:
        body = json.dumps({
            "model": self.model,
            "system": system or SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            # Near-greedy for operator answers: there is one right command,
            # and sampling variety only invents flags.
            "options": {"temperature": temperature},
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


# -- operator assistance (how to use HexBee) ------------------------------

# Phrasings that mean "teach me the tool" rather than "tell me about the
# evidence". Used to break ties — retrieval score does most of the work.
_HOWTO_HINTS = (
    "how do i", "how to", "how can i", "what command", "which command",
    "what's the command", "show me how", "walk me through", "syntax for",
    "usage of", "set up", "configure", "install", "enable", "run the",
    "explain how", "steps to", "teach me",
)

# Concrete artifacts: a filename with an extension, an IPv4 address, a hash,
# or a device name like Scout01. Lexical retrieval cannot tell these apart
# from vocabulary — "was evil.exe seen anywhere" scores highly against the
# manual because 'evil' and 'exe' both appear in it — so they are detected
# directly and veto the manual route.
_EVIDENCE_MARKERS = re.compile(
    r"\b(?:"
    r"[\w-]+\.(?:exe|dll|scr|com|bat|cmd|ps1|vbs|js|jar|msi|lnk|sh|elf"
    r"|txt|pdf|docx?|xlsx?|pptx?|zip|rar|7z|tar|gz"
    r"|jpe?g|png|gif|bmp|heic|db|sqlite|raw|dmp|mem|log|evtx|pcap)"
    r"|\d{1,3}(?:\.\d{1,3}){3}"
    r"|[0-9a-fA-F]{32,64}"
    r"|[A-Z][A-Za-z]{2,}\d{2,}"
    r")\b"
)

# Words that look like a device name to the pattern above but are ordinary
# technical vocabulary. Without this, "what is a SHA256 hash" is treated as a
# question about a specific machine and answered with hive statistics —
# exactly the question a beginner asks, answered exactly wrong.
_NOT_DEVICE_NAMES = {
    "sha1", "sha224", "sha256", "sha384", "sha512", "sha3", "md5", "crc32",
    "base64", "utf8", "utf16", "ascii", "iso8601", "rfc3164", "rfc5424",
    "x509", "pbkdf2", "hmac256", "aes256", "rsa2048", "ipv4", "ipv6",
    "windows7", "windows8", "windows10", "windows11", "win10", "win11",
    "python3", "python2", "esp32", "rp2040", "pico2", "usb2", "usb3",
    "wpa2", "wpa3", "http2", "tls12", "tls13", "ntlmv1", "ntlmv2",
}

# Question shapes that are about what the evidence says, not how to operate.
_EVIDENCE_HINTS = (
    "what happened", "summarise", "summarize", "when did", "who logged",
    "was seen", "seen anywhere", "anything suspicious", "any alerts",
    "most alerts", "what did", "tell me about the", "in this case",
    "on this host", "today", "yesterday", "last night", "overnight",
)


def looks_operational(question: str) -> bool:
    lowered = question.lower()
    return any(hint in lowered for hint in _HOWTO_HINTS)


def looks_evidential(question: str) -> bool:
    """True when the question names actual evidence rather than the tool."""
    lowered = question.lower()
    if any(hint in lowered for hint in _EVIDENCE_HINTS):
        return True
    for match in _EVIDENCE_MARKERS.finditer(question):
        if match.group(0).lower() not in _NOT_DEVICE_NAMES:
            return True
    return False


def how_to(engine: LocalAI, question: str) -> dict:
    """Answer a 'how do I use HexBee' question from the grounded manual.

    The retrieval result is the answer. The model's only job is to phrase it
    and fill in placeholders — which is why this works on a 1B model and why
    the fallback, which just prints the matched section, is nearly as good.
    """
    from . import knowledge

    kb = knowledge.get()
    docs = kb.relevant(question)

    if not docs:
        return {
            "answer": ("The HexBee reference does not cover that. Try asking "
                       "about scope, recon, Responder, BloodHound, Comb, "
                       "YARA, Forager, memory acquisition, Netmon, syslog, "
                       "threat intel, IOCs, reports, evidence sealing, or the "
                       "Picos."),
            "engine": "knowledge-base",
            "sources": [],
            "grounded": False,
        }

    # Cited sources are exactly the sections the model was shown — anything
    # else would make the citation a fiction.
    sources = [doc.id for doc in docs]
    reference = "\n\n".join(doc.render() for doc in docs)

    if engine.available():
        prompt = (f"HexBee reference:\n{reference}\n\n"
                  f"Operator question: {question}")
        try:
            return {"answer": engine.generate(prompt, system=OPERATOR_PROMPT,
                                              temperature=0.1),
                    "engine": engine.model, "sources": sources,
                    "grounded": True}
        except (urllib.error.URLError, OSError, ValueError):
            pass

    # No model: hand back the best manual section verbatim. For a command
    # lookup this is arguably the better answer anyway — it is exactly right.
    return {
        "answer": docs[0].render(),
        "engine": "knowledge-base",
        "sources": sources,
        "grounded": True,
    }


def ask(db, engine: LocalAI, question: str, case_id: int | None = None) -> dict:
    """Answer an analyst question about the evidence, or about HexBee itself.

    Routing is by retrieval score first and phrasing second: if the manual has
    a confident match for the question, it is a usage question and gets the
    grounded path. Otherwise it is about the evidence.
    """
    from . import knowledge

    kb = knowledge.get()
    # "What is X" always means the glossary, never the evidence. Checked
    # first because a definition question can contain something that looks
    # like an artifact — "what is a SHA256 hash" being the obvious one.
    if kb.define(question) is not None:
        return how_to(engine, question)
    # A question naming a real artifact is about the evidence, whatever it
    # scores against the manual — unless it is also plainly instructional
    # ("how do I add evil.exe as an IOC").
    if looks_evidential(question) and not looks_operational(question):
        return _ask_evidence(db, engine, question, case_id)
    # Otherwise: scored over curated docs only (see Knowledge.routing_score).
    # A high score means the manual plainly covers it; a moderate score plus
    # an instructional phrasing is enough.
    score = kb.routing_score(question)
    if score >= 12.0 or (score >= 5.0 and looks_operational(question)):
        return how_to(engine, question)
    return _ask_evidence(db, engine, question, case_id)


def _ask_evidence(db, engine: LocalAI, question: str,
                  case_id: int | None) -> dict:

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
