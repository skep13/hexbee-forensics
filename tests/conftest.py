import sys
from pathlib import Path

import pytest

# Make every component importable without installation.
ROOT = Path(__file__).resolve().parent.parent
for component in ("hive", "queen", "comb", "forager", "netmon"):
    sys.path.insert(0, str(ROOT / component))

from hexbee_hive.db import Database  # noqa: E402


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "test.db")
    yield database
    database.close()
