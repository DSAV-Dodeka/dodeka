"""Sync operations for importing member data from the Atletiekunie CSV export.

Member permission lifecycle:
  1. Signup grants member permission automatically (see auth.create_user).
  2. update_existing renews the permission (1-year TTL) each sync cycle.
  3. remove_departed revokes it when a member leaves or cancels.
"""

import csv
import io
import time as time_mod
from dataclasses import dataclass

from freetser import Storage

from apiserver.data.newuser import serialize_newuser
from apiserver.data.permissions import (
    Permissions,
    UserNotFoundError,
    add_permission,
    read_permissions,
    remove_permission,
)
from apiserver.data.registration_state import create_registration_state
from apiserver.data.userdata import (
    SYNC_TABLE,
    USERDATA_TABLE,
    UserDataEntry,
    delete,
    get,
    listall,
    upsert,
)

SYSTEM_USERS_TABLE = "system_users"


@dataclass
class ExistingPair:
    sync: UserDataEntry
    current: UserDataEntry | None


@dataclass
class SyncGroups:
    departed: list[str]
    new: list[UserDataEntry]
    pending: list[str]
    existing: list[ExistingPair]


def serialize_groups(groups: SyncGroups) -> dict:
    """Convert SyncGroups to JSON-serializable dict."""
    existing = []
    for pair in groups.existing:
        existing.append(
            {
                "sync": {
                    "email": pair.sync.email,
                    "voornaam": pair.sync.voornaam,
                    "tussenvoegsel": pair.sync.tussenvoegsel,
                    "achternaam": pair.sync.achternaam,
                    "bondsnummer": pair.sync.bondsnummer,
                    "geslacht": pair.sync.geslacht,
                    "geboortedatum": pair.sync.geboortedatum,
                },
                "current": {
                    "email": pair.current.email,
                    "voornaam": pair.current.voornaam,
                    "tussenvoegsel": pair.current.tussenvoegsel,
                    "achternaam": pair.current.achternaam,
                    "bondsnummer": pair.current.bondsnummer,
                    "geslacht": pair.current.geslacht,
                    "geboortedatum": pair.current.geboortedatum,
                }
                if pair.current
                else None,
            }
        )
    return {
        "departed": groups.departed,
        "new": [
            {
                "email": e.email,
                "voornaam": e.voornaam,
                "tussenvoegsel": e.tussenvoegsel,
                "achternaam": e.achternaam,
            }
            for e in groups.new
        ],
        "pending": groups.pending,
        "existing": existing,
    }


def parse_csv(content: str) -> list[UserDataEntry]:
    """Parse CSV content string into UserDataEntry objects."""
    # Strip BOM (common in Excel/Atletiekunie exports)
    if content.startswith("\ufeff"):
        content = content[1:]
    entries = []
    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames is not None:
        for row in reader:
            email = row.get("Email", "").strip().lower()
            if not email:
                continue
            entries.append(
                UserDataEntry(
                    bondsnummer=row.get("Bondsnummer", "").strip(),
                    voornaam=row.get("Voornaam", "").strip(),
                    tussenvoegsel=row.get("Tussenvoegsel", "").strip(),
                    achternaam=row.get("Achternaam", "").strip(),
                    geslacht=row.get("Geslacht", "").strip(),
                    geboortedatum=row.get("Geboortedatum", "").strip(),
                    email=email,
                    opzegdatum=row.get("Club lidmaatschap opzegdatum", "").strip(),
                )
            )
    return entries


def import_sync(store: Storage, entries: list[UserDataEntry]) -> int:
    """Clear sync table and import entries. Returns count imported."""
    store.clear(SYNC_TABLE)
    for entry in entries:
        upsert(store, SYNC_TABLE, entry)
    return len(entries)


def add_system_user(store: Storage, email: str) -> bool:
    """Mark a user as system-only (excluded from sync comparison)."""
    key = email.lower()
    if store.get(SYSTEM_USERS_TABLE, key) is not None:
        return False
    store.add(SYSTEM_USERS_TABLE, key, b"1", expires_at=0)
    return True


def list_system_users(store: Storage) -> list[str]:
    """Return emails of all system-only users."""
    return store.list_keys(SYSTEM_USERS_TABLE)


def cleanup_orphaned_userdata(store: Storage) -> int:
    """Delete userdata entries that have no corresponding registered user.

    Can happen if a user account is deleted without cleaning up userdata.
    """
    registered_emails = set(store.list_keys("users_by_email"))
    count = 0
    for key in store.list_keys("userdata"):
        if key not in registered_emails:
            delete(store, USERDATA_TABLE, key)
            count += 1
    return count


def has_member_permission(store: Storage, timestamp: int, email: str) -> bool:
    """Check if a registered user has an active member permission."""
    result = store.get("users_by_email", email)
    if result is None:
        return False
    user_id = result[0].decode("utf-8")
    perms = read_permissions(store, timestamp, user_id)
    if isinstance(perms, UserNotFoundError):
        return False
    return Permissions.MEMBER in perms


def compute_groups(store: Storage) -> SyncGroups:
    """Compare sync table against registered users. Returns grouped results.

    System users (see add_system_user) are excluded from comparison.
    Only users with an active member permission are considered "departed"
    (users whose permission was already revoked have been handled).
    Sync entries with a cancellation date (opzegdatum) are treated as departed.
    Runs cleanup_orphaned_userdata as a maintenance step.
    """
    cleanup_orphaned_userdata(store)
    timestamp = int(time_mod.time())

    sync_entries = listall(store, SYNC_TABLE)
    sync_by_email = {e.email.lower(): e for e in sync_entries}

    # Split sync entries into active (no cancellation) and cancelled
    active_sync_emails: set[str] = set()
    cancelled_sync_emails: set[str] = set()
    for e in sync_entries:
        if e.opzegdatum:
            cancelled_sync_emails.add(e.email.lower())
        else:
            active_sync_emails.add(e.email.lower())

    registered_emails = set(store.list_keys("users_by_email"))
    newuser_emails = set(store.list_keys("newusers"))
    system_emails = set(store.list_keys(SYSTEM_USERS_TABLE))
    comparable_emails = registered_emails - system_emails
    known_emails = registered_emails | newuser_emails

    # Departed: registered users not in active sync OR in cancelled sync,
    # who still have member permission
    departed = [
        email
        for email in comparable_emails
        if (email not in active_sync_emails or email in cancelled_sync_emails)
        and has_member_permission(store, timestamp, email)
    ]
    new = [
        sync_by_email[email]
        for email in active_sync_emails
        if email not in known_emails
    ]
    pending = [
        email
        for email in active_sync_emails & newuser_emails
        if email not in registered_emails
    ]
    existing = []
    for email in active_sync_emails & comparable_emails:
        existing.append(
            ExistingPair(
                sync=sync_by_email[email], current=get(store, USERDATA_TABLE, email)
            )
        )

    return SyncGroups(departed=departed, new=new, pending=pending, existing=existing)


def revoke_member(store: Storage, timestamp: int, email: str) -> bool:
    """Revoke member permission and delete userdata for a departed user."""
    result = store.get("users_by_email", email.lower())
    if result is None:
        return False
    user_id_bytes, _ = result
    user_id = user_id_bytes.decode("utf-8")
    remove_permission(store, user_id, "member")
    delete(store, USERDATA_TABLE, email)
    return True


def add_accepted(store: Storage, email: str) -> bool:
    """Add a sync entry to newusers as board-accepted."""
    entry = get(store, SYNC_TABLE, email)
    if entry is None:
        return False

    # Skip if already in newusers or users
    if store.get("users_by_email", email.lower()) is not None:
        return False
    if store.get("newusers", email.lower()) is not None:
        return False

    lastname_parts = []
    if entry.tussenvoegsel:
        lastname_parts.append(entry.tussenvoegsel)
    lastname_parts.append(entry.achternaam)
    lastname = " ".join(lastname_parts)

    data = serialize_newuser(email.lower(), entry.voornaam, lastname, True)
    store.add("newusers", email.lower(), data, expires_at=0)
    create_registration_state(store, email.lower())
    return True


def grant_member_permission(store: Storage, timestamp: int, email: str) -> bool:
    """Grant or renew member permission for a registered user."""
    result = store.get("users_by_email", email.lower())
    if result is None:
        return False
    user_id = result[0].decode("utf-8")
    add_permission(store, timestamp, user_id, Permissions.MEMBER)
    return True


def sync_userdata(store: Storage, timestamp: int, email: str) -> bool:
    """Copy sync entry data into userdata and renew member permission."""
    entry = get(store, SYNC_TABLE, email)
    if entry is None:
        return False
    upsert(store, USERDATA_TABLE, entry)
    grant_member_permission(store, timestamp, email)
    return True


def remove_departed(store: Storage, timestamp: int, email: str | None = None) -> dict:
    """Remove single departed user or all departed. Returns result dict."""
    if email:
        if revoke_member(store, timestamp, email):
            return {"removed": 1}
        return {"error": f"User {email} not found"}

    groups = compute_groups(store)
    count = sum(1 for e in groups.departed if revoke_member(store, timestamp, e))
    return {"removed": count}


def accept_new(store: Storage, email: str | None = None) -> dict:
    """Accept single new user or all new. Returns result dict."""
    if email:
        if add_accepted(store, email):
            return {"added": 1, "skipped": 0}
        return {"added": 0, "skipped": 1}

    groups = compute_groups(store)
    added = skipped = 0
    for entry in groups.new:
        if add_accepted(store, entry.email):
            added += 1
        else:
            skipped += 1
    return {"added": added, "skipped": skipped}


def update_existing(store: Storage, email: str | None = None) -> dict:
    """Update single existing user or all existing. Returns result dict."""
    timestamp = int(time_mod.time())
    if email:
        if sync_userdata(store, timestamp, email):
            return {"updated": 1}
        return {"error": f"No sync entry for {email}"}

    groups = compute_groups(store)
    count = sum(
        1 for p in groups.existing if sync_userdata(store, timestamp, p.sync.email)
    )
    return {"updated": count}
