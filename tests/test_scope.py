"""Engagement scope enforcement.

The behaviour that matters legally is the *refusal*, so most of these tests
are about what gets denied and why.
"""

import pytest

from hexbee_hive import scope
from hexbee_hive.correlate import Correlator


def test_empty_scope_denies_everything(db):
    decision = scope.check(db, "10.0.0.5")
    assert not decision
    assert "no engagement scope" in decision.reason


def test_empty_scope_allows_in_permissive_mode(db):
    decision = scope.check(db, "10.0.0.5", mode="permissive")
    assert decision
    assert "permissive" in decision.reason


def test_cidr_match_and_miss(db):
    scope.add_rule(db, "cidr", "10.10.0.0/24", "tester", auth_ref="SOW-1")
    inside = scope.check(db, "10.10.0.77")
    assert inside
    assert inside.auth_ref == "SOW-1"
    assert not scope.check(db, "10.10.1.1")


def test_cidr_is_normalised(db):
    scope.add_rule(db, "cidr", "10.10.0.5/24", "tester")
    rules = scope.list_rules(db)
    assert rules[0]["value"] == "10.10.0.0/24"


def test_host_and_domain_rules(db):
    scope.add_rule(db, "host", "web01.client.test", "tester")
    scope.add_rule(db, "domain", "client.test", "tester")
    assert scope.check(db, "web01.client.test")
    assert scope.check(db, "mail.client.test")       # subdomain of the domain rule
    assert scope.check(db, "client.test")
    assert not scope.check(db, "client.test.evil.example")


def test_hostname_is_never_resolved_against_a_cidr_rule(db):
    """A CIDR rule must not authorise a hostname.

    Letting DNS decide what is in scope would hand an attacker-controlled
    record the power to widen the engagement.
    """
    scope.add_rule(db, "cidr", "127.0.0.0/8", "tester")
    assert not scope.check(db, "localhost")


def test_time_window_is_enforced(db):
    scope.add_rule(db, "cidr", "10.0.0.0/8", "tester",
                   starts_at="2026-08-01T00:00:00Z",
                   ends_at="2026-08-05T00:00:00Z")
    assert scope.check(db, "10.1.2.3", now_iso="2026-08-02T12:00:00Z")
    early = scope.check(db, "10.1.2.3", now_iso="2026-07-01T12:00:00Z")
    assert not early
    assert "time window" in early.reason
    assert not scope.check(db, "10.1.2.3", now_iso="2026-09-01T12:00:00Z")


def test_inactive_rule_does_not_authorise(db):
    rule_id = scope.add_rule(db, "cidr", "10.0.0.0/8", "tester")
    assert scope.check(db, "10.0.0.1")
    scope.set_active(db, rule_id, False, "tester")
    assert not scope.check(db, "10.0.0.1")


def test_case_scoped_rule_visible_to_that_case(db):
    from hexbee_hive.cases import create_case

    case = create_case(db, "Engagement", "", "tester")
    scope.add_rule(db, "cidr", "192.168.5.0/24", "tester", case_id=case["id"])
    assert scope.check(db, "192.168.5.10", case_id=case["id"])


def test_malformed_values_are_rejected(db):
    for kind, value in [("cidr", "not-a-network"), ("cidr", "10.0.0.0/99"),
                        ("host", "bad host name"), ("domain", "!!!")]:
        with pytest.raises(ValueError):
            scope.add_rule(db, kind, value, "tester")


def test_bad_timestamp_is_rejected(db):
    with pytest.raises(ValueError):
        scope.add_rule(db, "cidr", "10.0.0.0/8", "tester", starts_at="tomorrow")


def test_violation_is_written_into_the_evidence_chain(db):
    """A blocked attempt is evidence: it proves the operator stayed inside
    the authorisation."""
    correlator = Correlator(db, 600)
    decision = scope.check(db, "8.8.8.8")
    event_id = scope.record_violation(db, correlator, "8.8.8.8",
                                      "hexbee-recon", "tester", decision)
    assert event_id is not None
    row = db.query_one("SELECT event_type, payload FROM events WHERE id = ?",
                       (event_id,))
    assert row["event_type"] == "scope_violation"
    assert "8.8.8.8" in row["payload"]
    assert '"blocked": true' in row["payload"].replace('"blocked":true',
                                                       '"blocked": true')


def test_scope_summary_counts_live_rules(db):
    scope.add_rule(db, "cidr", "10.0.0.0/8", "tester", auth_ref="SOW-1")
    scope.add_rule(db, "cidr", "172.16.0.0/12", "tester",
                   ends_at="2020-01-01T00:00:00Z")
    summary = scope.scope_summary(db)
    assert summary["total"] == 2
    assert summary["active"] == 2
    assert summary["in_window"] == 1
    assert summary["auth_refs"] == ["SOW-1"]
