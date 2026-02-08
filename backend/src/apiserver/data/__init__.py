"""Data layer — database table definitions and operations.

DB_TABLES lists every table used by the application. It is the single
source of truth for both storage initialisation (start_storage_thread)
and full-reset (cmdhandler_reset).
"""

from apiserver.sync import SYSTEM_USERS_TABLE
from apiserver.tokens import TOKENS_TABLE

DB_TABLES = [
    "users",
    "users_by_email",
    "newusers",
    "registration_state",
    "metadata",
    "session_cache",
    "userdata",
    "sync",
    SYSTEM_USERS_TABLE,
    TOKENS_TABLE,
]
