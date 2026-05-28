"""Data layer — database table definitions and operations.

DB_TABLES lists every table used by the application. It is the single
source of truth for both storage initialisation (start_storage_thread)
and full-reset (cmdhandler_reset).
"""

from apiserver.data.features.birthdays import BIRTHDAYS_TABLE
from apiserver.data.features.private_kv import PRIVATE_TABLE
from apiserver.data.outbox import OUTBOX_TABLE
from apiserver.data.registrations import (
    REGISTRATIONS_BY_BONDSNUMMER_TABLE,
    REGISTRATIONS_BY_EMAIL_TABLE,
    REGISTRATIONS_TABLE,
)
from apiserver.sync import SYSTEM_USERS_TABLE
from apiserver.tooling.codes import CODES_TABLE

DB_TABLES = [
    "users",
    "users_by_email",
    "users_by_bondsnummer",
    REGISTRATIONS_TABLE,
    REGISTRATIONS_BY_EMAIL_TABLE,
    REGISTRATIONS_BY_BONDSNUMMER_TABLE,
    OUTBOX_TABLE,
    "sync_state",
    "sync",
    "sync_decisions",
    "volta_data",
    "metadata",
    "session_cache",
    BIRTHDAYS_TABLE,
    PRIVATE_TABLE,
    SYSTEM_USERS_TABLE,
    CODES_TABLE,
]
