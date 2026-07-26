"""The grounded HexBee manual.

These tests exist because an ungrounded small model invents commands, and an
invented command is worse than a refusal — the operator will try it. So the
things worth asserting are: the manual covers what it claims to, retrieval
returns the *right* section, usage questions and evidence questions go
different ways, and anything outside the manual is refused rather than
answered.
"""

import json

import pytest

from hexbee_hive import knowledge
from hexbee_hive.ai import LocalAI, how_to, looks_evidential, looks_operational


@pytest.fixture(autouse=True)
def fresh_index():
    knowledge.reset()
    yield
    knowledge.reset()


class OfflineAI(LocalAI):
    """No model reachable — exercises the deterministic path."""

    def __init__(self):
        super().__init__("http://127.0.0.1:1", "none")

    def available(self) -> bool:
        return False


# -- corpus integrity ------------------------------------------------------

def test_corpus_builds_and_has_all_kinds():
    kb = knowledge.get()
    kinds = {doc.kind for doc in kb.docs}
    assert {"recipe", "concept", "reference"} <= kinds
    assert len(kb.docs) > 30


def test_document_ids_are_unique():
    ids = [doc.id for doc in knowledge.get().docs]
    assert len(ids) == len(set(ids)), "duplicate document ids break citation"


def test_every_recipe_has_a_command_or_is_a_concept():
    for doc in knowledge.get().docs:
        if doc.kind == "recipe":
            assert doc.commands, f"{doc.id} is a recipe with no command"


def test_recipe_commands_reference_real_binaries():
    """A recipe telling the operator to run something that isn't ours is a bug."""
    known = ("hexbee-hive", "hexbee-queen", "hexbee-comb", "hexbee-forager",
             "hexbee-netmon", "sudo", "export", "cp", "mkdir", "pip", "ollama",
             "curl", "vol", "esptool.py", "mpremote", "powershell",
             "RUN-WINDOWS.bat")
    for doc in knowledge.get().docs:
        for command in doc.commands:
            assert command.split()[0] in known, f"{doc.id}: {command}"


def test_keyword_table_has_no_orphans():
    """Every alias must point at a document that exists."""
    ids = {doc.id for doc in knowledge.get().docs}
    orphans = set(knowledge.KEYWORDS) - ids
    assert not orphans, f"KEYWORDS references missing docs: {orphans}"


def test_keywords_are_applied_to_documents():
    docs = {doc.id: doc for doc in knowledge.get().docs}
    assert "usb stick" in docs["recipe-triage-usb"].keywords


# -- extraction stays in step with the code -------------------------------

def test_event_type_reference_is_generated_from_normalize():
    """If someone adds an event type, the manual must already know."""
    from hexbee_hive.normalize import EVENT_SEVERITY

    doc = next(d for d in knowledge.get().docs if d.id == "ref-event-types")
    for event_type in ("yara_match", "scope_violation", "wireless_sighting",
                       "diagnostic_alert", "case_seal"):
        assert event_type in doc.body
    assert len(EVENT_SEVERITY) > 40


def test_attack_reference_is_generated_from_the_mapping():
    doc = next(d for d in knowledge.get().docs if d.id == "ref-attack-map")
    assert "powershell_launched" in doc.body
    assert "T1059.001" in doc.body
    assert "arp_spoof" in doc.body


def test_command_snapshot_loads_when_present():
    docs = [d for d in knowledge.get().docs if d.kind == "command"]
    if not knowledge.SNAPSHOT.is_file():
        pytest.skip("run scripts/build_knowledge.py to generate the snapshot")
    assert docs, "snapshot exists but produced no command documents"
    titles = {d.title for d in docs}
    assert "hexbee-queen recon" in titles
    assert "hexbee-hive sync-intel" in titles


def test_snapshot_is_current_with_the_clis():
    """Catches a renamed command that nobody regenerated the snapshot for."""
    if not knowledge.SNAPSHOT.is_file():
        pytest.skip("no snapshot")
    data = json.loads(knowledge.SNAPSHOT.read_text(encoding="utf-8"))
    titles = {item["title"] for item in data["commands"]}
    # A representative command from each component.
    for expected in ("hexbee-hive verify", "hexbee-queen scope add",
                     "hexbee-comb scan", "hexbee-forager memory",
                     "hexbee-netmon run"):
        assert expected in titles, (
            f"{expected} missing — run scripts/build_knowledge.py")


def test_missing_snapshot_degrades_quietly(monkeypatch, tmp_path):
    monkeypatch.setattr(knowledge, "SNAPSHOT", tmp_path / "absent.json")
    knowledge.reset()
    kb = knowledge.get()
    assert kb.docs                                  # recipes still present
    assert not [d for d in kb.docs if d.kind == "command"]


def test_corrupt_snapshot_degrades_quietly(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(knowledge, "SNAPSHOT", bad)
    knowledge.reset()
    assert knowledge.get().docs


# -- retrieval -------------------------------------------------------------

@pytest.mark.parametrize("question,expected", [
    ("how do I seal a case with a witness", "recipe-seal"),
    ("how do I scan a usb stick", "recipe-triage-usb"),
    ("what command exports a signed evidence bundle", "recipe-export-bundle"),
    ("how do I authorise a target range", "recipe-start-engagement"),
    ("how do I check if an IP is in scope", "recipe-check-scope"),
    ("run an nmap scan into a case", "recipe-recon"),
    ("import bloodhound output", "recipe-bloodhound"),
    ("how do I dump memory from a target", "recipe-memory"),
    ("set up yara rules", "recipe-yara"),
    ("capture credentials with responder", "recipe-responder"),
    ("how do I sync threat intel feeds", "recipe-intel"),
    ("passive network monitoring on the pi", "recipe-netmon"),
    ("what env var sets the ollama url", "ref-config"),
    ("what severity is autorun_found", "ref-event-types"),
    ("what can a viewer do", "concept-roles"),
    ("does this work offline", "concept-offline"),
    ("netmon permission denied raw socket", "troubleshoot-capture-permission"),
    ("how do I connect the queen to the hive", "recipe-connect-queen"),
    ("how do I add an ioc", "recipe-iocs"),
    ("collect from a live host", "recipe-forager-collect"),
])
def test_retrieval_finds_the_right_section(question, expected):
    top = knowledge.get().search(question, 1)
    assert top, f"no result for {question!r}"
    assert top[0][0].id == expected, (
        f"{question!r} returned {top[0][0].id}, expected {expected}")


def test_tokenizer_splits_compound_command_names():
    tokens = knowledge.tokenize("hexbee-queen recon")
    assert "queen" in tokens and "recon" in tokens


def test_tokenizer_drops_stopwords():
    tokens = knowledge.tokenize("how do I run the scan for a case")
    assert "how" not in tokens and "the" not in tokens and "for" not in tokens
    assert "run" in tokens and "scan" in tokens and "case" in tokens


def test_weak_single_term_matches_are_rejected():
    """One incidental word in common is not an answer. 'write me a poem'
    matched the report recipe purely because that recipe mentions writing."""
    kb = knowledge.get()
    hits = kb.search("write me a poem", 1)
    assert hits, "expected a raw lexical hit to exist"
    assert kb.best("write me a poem") is None, "coverage check should reject it"


def test_unknown_topics_return_no_reference():
    """The manual must refuse rather than hand over a loosely-related page."""
    kb = knowledge.get()
    for question in ("how do I launch a satellite",
                     "what is the capital of France",
                     "write me a poem"):
        assert kb.reference_for(question) == "", question


# -- routing ---------------------------------------------------------------

@pytest.mark.parametrize("question", [
    "what happened on Scout01 today",
    "was evil.exe seen anywhere",
    "summarise the malware found on the front desk PC",
    "did anything connect to 203.0.113.9",
    "have we seen d41d8cd98f00b204e9800998ecf8427e before",
])
def test_evidence_questions_are_detected(question):
    assert looks_evidential(question), question


@pytest.mark.parametrize("question", [
    "how do I seal a case",
    "set up yara",
    "what command exports a bundle",
    "how do I run a recon scan",
])
def test_usage_questions_are_not_flagged_as_evidential(question):
    assert not looks_evidential(question), question


def test_operational_phrasing_detected():
    assert looks_operational("how do I export a case")
    assert not looks_operational("which host had the most alerts")


def test_instructional_question_about_an_artifact_still_routes_to_usage():
    """'how do I add evil.exe as an IOC' is a usage question despite naming
    a file — the instructional phrasing has to win."""
    question = "how do I add evil.exe as an ioc"
    assert looks_evidential(question) and looks_operational(question)


def test_routing_score_ignores_command_documents():
    """Command docs are full of ordinary words; letting them vote sent
    evidence questions to the manual."""
    kb = knowledge.get()
    everything = kb.search("was evil.exe seen anywhere", 1)
    curated = kb.search("was evil.exe seen anywhere", 1,
                        kinds=knowledge.ROUTING_KINDS)
    assert everything and curated
    assert kb.routing_score("was evil.exe seen anywhere") == pytest.approx(
        curated[0][1])


# -- the answer path -------------------------------------------------------

def test_how_to_without_a_model_returns_the_manual_verbatim():
    result = how_to(OfflineAI(), "how do I seal a case with a witness")
    assert result["grounded"] is True
    assert result["engine"] == "knowledge-base"
    assert "hexbee-queen seal" in result["answer"]
    assert "recipe-seal" in result["sources"]


def test_how_to_refuses_what_it_does_not_know():
    result = how_to(OfflineAI(), "how do I launch a satellite")
    assert result["grounded"] is False
    assert "does not cover that" in result["answer"]
    assert result["sources"] == []


def test_how_to_answer_contains_a_runnable_command():
    for question in ("how do I run an nmap scan",
                     "how do I acquire memory",
                     "how do I export a signed bundle"):
        answer = how_to(OfflineAI(), question)["answer"]
        assert "hexbee-" in answer, question


def test_ask_routes_usage_questions_to_the_manual(db):
    from hexbee_hive.ai import ask

    result = ask(db, OfflineAI(), "how do I seal a case with a witness")
    assert result["engine"] == "knowledge-base"
    assert "hexbee-queen seal" in result["answer"]


def test_ask_routes_evidence_questions_to_the_evidence(db):
    from hexbee_hive.ai import ask

    result = ask(db, OfflineAI(), "was evil.exe seen anywhere")
    assert result["engine"] == "rule-based"
    assert "Hive totals" in result["answer"]


def test_prompt_forbids_inventing_commands():
    from hexbee_hive.ai import OPERATOR_PROMPT

    lowered = OPERATOR_PROMPT.lower()
    assert "never invent" in lowered
    assert "verbatim" in lowered
    assert "does not cover" in lowered
