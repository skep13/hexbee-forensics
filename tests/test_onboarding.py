"""The beginner-facing surfaces: doctor, guided workflows, glossary.

The thing worth asserting here is not that the code runs — it is that a
person who has never used a forensics tool is never left with a dead end. So:
every gap the doctor reports has a fix, every workflow step explains why it
exists, and the words the UI uses are defined somewhere.
"""

import pytest

from hexbee_hive import doctor, knowledge, workflows
from hexbee_hive.api import create_app
from hexbee_hive.auth import create_user
from hexbee_hive.config import HiveConfig


@pytest.fixture
def cfg(tmp_path):
    return HiveConfig(data_dir=tmp_path, ingest_key="testkey-long-enough-yes")


@pytest.fixture
def app(db, cfg):
    create_user(db, "admin", "admin-strong-pass1", "administrator")
    application = create_app(cfg, db)
    application.testing = True
    return application


@pytest.fixture
def client(app):
    handle = app.test_client()
    handle.post("/login", data={"username": "admin",
                                "password": "admin-strong-pass1"})
    return handle


# -- doctor ----------------------------------------------------------------

def test_doctor_runs_and_reports(cfg, db):
    report = doctor.run(cfg, db)
    assert report.checks
    assert {c.status for c in report.checks} <= {doctor.OK, doctor.WARN,
                                                 doctor.MISSING, doctor.INFO}


def test_every_gap_tells_you_how_to_fix_it(cfg, db):
    """A beginner reading 'not found' learns nothing."""
    for check in doctor.run(cfg, db).checks:
        if check.status in (doctor.MISSING, doctor.WARN):
            assert check.fix, f"{check.name} reports a problem with no fix"


def test_every_check_explains_what_it_is(cfg, db):
    for check in doctor.run(cfg, db).checks:
        assert check.what, f"{check.name} has no plain-English description"
        assert len(check.what) > 20, f"{check.name}: description too terse"


def test_missing_admin_blocks_readiness(cfg, db):
    """No login means not ready, and setup is offered."""
    report = doctor.run(cfg, db)
    assert not report.ready
    rendered = doctor.render(report)
    assert "hexbee-hive setup" in rendered


def test_ready_once_the_core_exists(cfg, db):
    create_user(db, "admin", "admin-strong-pass1", "administrator")
    report = doctor.run(cfg, db)
    assert report.ready
    assert "ready to use" in doctor.render(report)


def test_render_never_shows_a_bare_failure(cfg, db):
    rendered = doctor.render(doctor.run(cfg, db), verbose=True)
    assert "NEEDS ATTENTION" in rendered or "WORKING" in rendered
    assert "Start Here" in rendered or "setup" in rendered


def test_optional_gaps_are_not_failures(cfg, db):
    """Missing YARA is a smaller world, not a broken install."""
    create_user(db, "admin", "admin-strong-pass1", "administrator")
    report = doctor.run(cfg, db)
    optional = [c for c in report.checks if c.name == "yara-python"]
    assert optional and optional[0].status != doctor.MISSING
    assert report.ready


# -- workflows -------------------------------------------------------------

def test_workflows_are_phrased_as_situations():
    """Beginners think in situations, not features."""
    for wf in workflows.WORKFLOWS:
        assert wf.situation
        # A situation reads like a sentence, not a noun phrase.
        assert " " in wf.situation and len(wf.situation.split()) >= 4


def test_every_step_says_why_it_exists():
    for wf in workflows.WORKFLOWS:
        assert wf.steps, f"{wf.id} has no steps"
        for step in wf.steps:
            assert step.why, f"{wf.id}/{step.title} does not explain why"
            assert len(step.why) > 40, f"{wf.id}/{step.title}: why is too thin"


def test_workflow_commands_are_real():
    known = ("hexbee-hive", "hexbee-queen", "hexbee-comb", "hexbee-forager",
             "hexbee-netmon", "sudo")
    for wf in workflows.WORKFLOWS:
        for step in wf.steps:
            for command in step.commands:
                assert command.split()[0] in known, f"{wf.id}: {command}"


def test_workflow_dashboard_links_are_real_routes(app):
    routes = {rule.rule for rule in app.url_map.iter_rules()}
    for wf in workflows.WORKFLOWS:
        for step in wf.steps:
            if step.where:
                base = step.where.split("#")[0]
                assert base in routes, f"{wf.id}: {step.where} is not a route"


def test_workflow_modes_are_valid():
    from hexbee_hive.cases import MODES

    for wf in workflows.WORKFLOWS:
        assert wf.mode in MODES, f"{wf.id} has mode {wf.mode}"


def test_workflows_reach_the_assistant():
    """Clicking Start Here and asking must give the same guidance."""
    kb = knowledge.get()
    ids = {doc.id for doc in kb.docs}
    for wf in workflows.WORKFLOWS:
        assert wf.id in ids, f"{wf.id} is not in the knowledge base"


@pytest.mark.parametrize("question,expected", [
    ("someone gave me a usb stick", "wf-usb"),
    ("i think this computer is infected", "wf-infected"),
    ("i need to hand evidence over to someone", "wf-handover"),
    ("i want to monitor the network for attacks", "wf-monitor"),
])
def test_situations_are_findable_in_the_words_a_beginner_uses(question, expected):
    knowledge.reset()
    top = knowledge.get().search(question, 1)
    assert top and top[0][0].id == expected, (
        f"{question!r} found {top[0][0].id if top else 'nothing'}")


# -- glossary --------------------------------------------------------------

def test_glossary_defines_the_words_the_ui_uses():
    terms = {term.lower() for term, _ in knowledge.GLOSSARY}
    for word in ("event", "incident", "case", "hash", "scope", "triage",
                 "chain of custody", "ioc"):
        assert word in terms, f"{word} is used in the UI but not defined"


def test_glossary_definitions_avoid_defining_by_jargon():
    for term, definition in knowledge.GLOSSARY:
        assert len(definition) > 60, f"{term}: definition too thin"
        assert definition[0].isupper(), f"{term}: definition not a sentence"


def test_glossary_terms_are_individually_retrievable():
    knowledge.reset()
    kb = knowledge.get()
    for question in ("what is a case", "what is chain of custody",
                     "what does IOC mean"):
        assert kb.best(question) is not None, question


# -- pages render ----------------------------------------------------------

@pytest.mark.parametrize("path", ["/start", "/glossary"])
def test_beginner_pages_render(client, path):
    resp = client.get(path)
    assert resp.status_code == 200
    assert b"Start Here" in resp.data or b"glossary" in resp.data.lower()


def test_every_workflow_has_a_page(client):
    for wf in workflows.WORKFLOWS:
        resp = client.get(f"/start/{wf.id}")
        assert resp.status_code == 200, wf.id
        assert b"Why:" in resp.data, f"{wf.id} page omits the explanations"


def test_unknown_workflow_404s(client):
    assert client.get("/start/wf-nonsense").status_code == 404


def test_start_page_lists_every_workflow(client):
    from markupsafe import escape

    body = client.get("/start").get_data(as_text=True)
    for wf in workflows.WORKFLOWS:
        # Jinja escapes apostrophes, so compare against the escaped form.
        assert str(escape(wf.situation)) in body, f"{wf.id} missing"


def test_doctor_api_is_admin_only(app):
    anon = app.test_client()
    assert anon.get("/api/v1/doctor").status_code == 401


def test_doctor_api_returns_checks(client):
    body = client.get("/api/v1/doctor").get_json()
    assert "ready" in body and body["checks"]
    assert all("fix" in c and "what" in c for c in body["checks"])
