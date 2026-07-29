"""'Was that us?' — the question every engagement eventually argues about.

The value here is a *conservative* answer. A confident wrong verdict in a
dispute about whether the testers caused an outage is worse than admitting the
log cannot tell, so most of these tests pin down when it refuses to commit.
"""

import pytest

from hexbee_hive.api import create_app
from hexbee_hive.attribution import (
    attribute,
    classify,
    engagement_activity,
    identifiers,
    summary,
)
from hexbee_hive.auth import create_user
from hexbee_hive.config import HiveConfig
from hexbee_hive.scope import add_rule


@pytest.fixture
def app(db, tmp_path):
    cfg = HiveConfig(data_dir=tmp_path, ingest_key="testkey")
    create_user(db, "op", "operator-strong-pass1", "administrator")
    application = create_app(cfg, db)
    application.testing = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def ingest(client, event_type, payload=None, at="2026-07-18T10:00:00Z",
           device="Scout01"):
    resp = client.post("/api/v1/ingest",
                       json={"device": device, "event_type": event_type,
                             "occurred_at": at, "payload": payload or {}},
                       headers={"X-HexBee-Ingest-Key": "testkey"})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["results"][0]["event_id"]


# -- classification --------------------------------------------------------

def test_our_tooling_is_told_apart_from_the_environment():
    assert classify("recon_finding") == "engagement"
    assert classify("hid_deployment") == "engagement"
    assert classify("scope_violation") == "engagement"   # a refusal is still ours
    assert classify("network_alert") == "observed"
    assert classify("process_snapshot") == "observed"


def test_identifiers_are_extracted_and_normalised():
    assert identifiers({"target": "10.0.0.5"}) == {"10.0.0.5"}
    assert identifiers({"host": "HOST-A"}) == {"host-a"}     # case-folded
    assert identifiers({"unrelated": "x"}) == set()
    assert identifiers('{"ip": "10.0.0.9"}') == {"10.0.0.9"}  # raw JSON
    assert identifiers(None) == set()


# -- the verdicts ----------------------------------------------------------

def test_an_alert_we_caused_is_attributable(client, db):
    add_rule(db, "cidr", "10.0.0.0/24", actor="op", auth_ref="ENG-2026-01")
    ingest(client, "recon_finding", {"target": "10.0.0.5"},
           at="2026-07-18T10:00:00Z")
    alert = ingest(client, "network_alert", {"dest_ip": "10.0.0.5"},
                   at="2026-07-18T10:01:00Z")

    result = attribute(db, alert)
    assert result["verdict"] == "attributable"
    assert result["candidates"][0]["matches_target"] is True
    assert result["candidates"][0]["seconds_apart"] == 60
    # The authorisation is what makes this defensible rather than merely true.
    assert result["authorisation"][0]["auth_ref"] == "ENG-2026-01"


def test_an_alert_against_a_different_host_is_inconclusive_not_denied(client, db):
    ingest(client, "recon_finding", {"target": "10.0.0.5"},
           at="2026-07-18T10:00:00Z")
    alert = ingest(client, "network_alert", {"dest_ip": "10.0.0.99"},
                   at="2026-07-18T10:01:00Z")

    result = attribute(db, alert)
    assert result["verdict"] == "inconclusive", \
        "we were active nearby; the log cannot exonerate us"


def test_an_alert_outside_the_window_is_not_ours(client, db):
    ingest(client, "recon_finding", {"target": "10.0.0.5"},
           at="2026-07-18T10:00:00Z")
    alert = ingest(client, "network_alert", {"dest_ip": "10.0.0.5"},
                   at="2026-07-18T14:00:00Z")

    result = attribute(db, alert)
    assert result["verdict"] == "not_ours"
    assert result["confidence"] == "good"


def test_with_no_engagement_record_at_all_it_refuses_to_answer(client, db):
    alert = ingest(client, "network_alert", {"dest_ip": "10.0.0.5"})
    result = attribute(db, alert)
    assert result["verdict"] == "inconclusive"
    assert result["confidence"] == "none", \
        "an empty log must not be read as proof of innocence"


def test_our_own_action_is_reported_as_certainly_ours(client, db):
    event_id = ingest(client, "hid_deployment", {"target": "host-a"})
    result = attribute(db, event_id)
    assert result["verdict"] == "ours"
    assert result["confidence"] == "certain"


def test_the_window_is_adjustable(client, db):
    ingest(client, "recon_finding", {"target": "10.0.0.5"},
           at="2026-07-18T10:00:00Z")
    alert = ingest(client, "network_alert", {"dest_ip": "10.0.0.5"},
                   at="2026-07-18T10:30:00Z")

    assert attribute(db, alert, window_seconds=300)["verdict"] == "not_ours"
    assert attribute(db, alert, window_seconds=3600)["verdict"] == "attributable"


def test_unknown_event_returns_none(db):
    assert attribute(db, 9999) is None


# -- supporting views ------------------------------------------------------

def test_engagement_activity_lists_only_our_actions(client, db):
    ingest(client, "recon_finding", {"target": "10.0.0.5"})
    ingest(client, "process_snapshot", {"name": "bash"})
    ingest(client, "hid_deployment", {"target": "host-a"})

    actions = engagement_activity(db)
    assert {a["event_type"] for a in actions} == {"recon_finding", "hid_deployment"}
    assert actions[0]["targets"]


def test_summary_counts_both_sides(client, db):
    add_rule(db, "cidr", "10.0.0.0/24", actor="op", auth_ref="ENG-1")
    ingest(client, "recon_finding", {"target": "10.0.0.5"})
    ingest(client, "process_snapshot", {"name": "bash"})
    ingest(client, "network_alert", {"dest_ip": "10.0.0.5"})

    counts = summary(db)
    assert counts["engagement_events"] == 1
    assert counts["observed_events"] == 2
    assert counts["attributable"] is True


def test_without_scope_rules_nothing_is_attributable(client, db):
    ingest(client, "recon_finding", {"target": "10.0.0.5"})
    assert summary(db)["attributable"] is False, \
        "activity without authorisation is not an attribution story"


# -- HTTP surface ----------------------------------------------------------

def test_attribution_is_investigator_only_and_the_page_renders(client, db):
    add_rule(db, "cidr", "10.0.0.0/24", actor="op", auth_ref="ENG-1")
    ingest(client, "recon_finding", {"target": "10.0.0.5"},
           at="2026-07-18T10:00:00Z")
    alert = ingest(client, "network_alert", {"dest_ip": "10.0.0.5"},
                   at="2026-07-18T10:01:00Z")

    # A viewer must not see engagement activity: it names targets and
    # authorisation references.
    create_user(db, "watcher", "watcher-strong-pass1", "viewer")
    viewer = client.post("/api/v1/login",
                         json={"username": "watcher",
                               "password": "watcher-strong-pass1"}).get_json()
    viewer_headers = {"Authorization": f"Bearer {viewer['token']}"}
    assert client.get("/api/v1/attribution/summary",
                      headers=viewer_headers).status_code == 403

    op = client.post("/api/v1/login",
                     json={"username": "op",
                           "password": "operator-strong-pass1"}).get_json()
    headers = {"Authorization": f"Bearer {op['token']}"}

    assert client.get("/api/v1/attribution/summary", headers=headers).status_code == 200
    assert client.get("/api/v1/attribution/activity", headers=headers).status_code == 200
    answer = client.get(f"/api/v1/attribution/{alert}", headers=headers).get_json()
    assert answer["verdict"] == "attributable"
    assert client.get("/api/v1/attribution/9999", headers=headers).status_code == 404

    client.post("/login", data={"username": "op",
                                "password": "operator-strong-pass1"})
    page = client.get("/attribution")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert 'id="at-result"' in body and "/api/v1/attribution/summary" in body
