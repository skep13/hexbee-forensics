"""Seed a demo administrator so you can log in immediately.

Creates admin / hexbee-demo-1 if it doesn't already exist. Uses whatever
HEXBEE_DATA_DIR points at (set by try-hexbee.ps1).
"""

from hexbee_hive.auth import create_user
from hexbee_hive.config import load_config
from hexbee_hive.db import Database

cfg = load_config()
db = Database(cfg.db_path)
if db.query_one("SELECT 1 FROM users WHERE username = 'admin'"):
    print("admin user already exists")
else:
    create_user(db, "admin", "hexbee-demo-1", "administrator")
    print("created admin / hexbee-demo-1")
