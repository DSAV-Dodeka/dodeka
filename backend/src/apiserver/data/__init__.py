"""Data layer — database table definitions and operations.

DB_TABLES lists every table used by the application. It is the single
source of truth for both storage initialisation (start_storage_thread)
and full-reset (cmdhandler_reset).
"""

from apiserver.data.features.birthdays import BIRTHDAYS_TABLE
from apiserver.sync import SYSTEM_USERS_TABLE
from apiserver.tooling.codes import CODES_TABLE

DB_TABLES = [
    "users",
    "users_by_email",
    "newusers",
    "registration_state",
    "metadata",
    "session_cache",
    "userdata",
    "sync",
    "users_by_bondsnummer",
    BIRTHDAYS_TABLE,
    SYSTEM_USERS_TABLE,
    CODES_TABLE,
]
