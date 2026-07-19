import sys
from pathlib import Path

import pytest

# Make hive/ and queen/ importable without installation.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hive"))
sys.path.insert(0, str(ROOT / "queen"))

from hexbee_hive.db import Database  # noqa: E402


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "test.db")
    yield database
    database.close()
