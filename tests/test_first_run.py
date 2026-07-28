"""First run in a browser: create the first administrator without a terminal.

The security property that matters is the *closing* of this route. While it is
open anyone reaching the port can claim the machine; the moment an account
exists it must be gone, or it is an unauthenticated admin-creation back door.
"""

import pytest

from hexbee_hive.api import create_app
from hexbee_hive.auth import create_user
from hexbee_hive.config import HiveConfig


@pytest.fixture
def app(db, tmp_path):
    application = create_app(HiveConfig(data_dir=tmp_path, ingest_key="k"), db)
    application.testing = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def users(db):
    return db.query("SELECT COUNT(*) AS n FROM users")[0]["n"]


def setup_form(client, **fields):
    """POST /setup the way the browser does.

    No CSRF token: the token is derived from the session cookie and there is
    no session before an account exists — the same reason /login is exempt.
    What protects this route is that it stops working the moment a user
    exists, which `test_setup_closes_once_an_account_exists` pins down.
    """
    return client.post("/setup", data=fields)


def test_fresh_install_sends_you_to_setup_not_login(client):
    assert client.get("/login").status_code == 302
    assert "/setup" in client.get("/login").headers["Location"]
    assert client.get("/setup").status_code == 200


def test_creating_the_first_administrator_works(client, db):
    resp = setup_form(client, username="examiner",
                      password="a-long-enough-pass-1",
                      confirm="a-long-enough-pass-1")
    assert resp.status_code == 302
    assert users(db) == 1
    assert db.query("SELECT role FROM users")[0]["role"] == "administrator"


def test_setup_closes_once_an_account_exists(client, db):
    create_user(db, "examiner", "a-long-enough-pass-1", "administrator")

    # The page redirects away...
    assert client.get("/setup").status_code == 302
    # ...and, more importantly, the POST refuses to make a second admin.
    client.post("/setup", data={"username": "attacker",
                                "password": "another-long-pass-1",
                                "confirm": "another-long-pass-1"})  # no token needed: must fail anyway
    assert users(db) == 1
    assert not db.query("SELECT id FROM users WHERE username = 'attacker'")


def test_mismatched_passwords_are_rejected(client, db):
    resp = setup_form(client, username="examiner",
                      password="a-long-enough-pass-1",
                      confirm="something-else-entirely")
    assert resp.status_code == 400
    assert users(db) == 0


def test_weak_password_is_rejected_with_the_policy_reason(client, db):
    resp = setup_form(client, username="examiner", password="short",
                      confirm="short")
    assert resp.status_code == 400
    assert "12 characters" in resp.get_data(as_text=True)
    assert users(db) == 0


def test_login_works_immediately_after_setup(client):
    setup_form(client, username="examiner", password="a-long-enough-pass-1",
               confirm="a-long-enough-pass-1")
    assert client.get("/login").status_code == 200
    resp = client.post("/login", data={"username": "examiner",
                                       "password": "a-long-enough-pass-1"})
    assert resp.status_code == 302
