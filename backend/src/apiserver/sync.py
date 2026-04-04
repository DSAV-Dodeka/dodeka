"""Sync operations for importing member data from the Atletiekunie CSV export.

Member permission lifecycle:
  1. Signup grants member permission automatically (see auth.create_user).
  2. update_existing renews the permission (1-year TTL) each sync cycle.
  3. remove_departed deletes the account when a member leaves.
"""

import csv
import io
import json
import time as time_mod
from dataclasses import dataclass
from datetime import date, datetime

from freetser import Storage

from apiserver.data.permissions import (
    Permissions,
    UserNotFoundError,
    add_permission,
    read_permissions,
    remove_permission,
)
from apiserver.data.registrations import (
    Registration,
    create_or_reuse_registration,
    delete_registration,
    get_registration,
    migrate_registration_email,
    normalize_email,
    upsert_registration,
)
from apiserver.data.features.birthdays import (
    BIRTHDAYS_TABLE,
    delete_birthday,
    set_birthday,
)
from apiserver.data.userdata import (
    SYNC_TABLE,
    USERDATA_TABLE,
    UserDataEntry,
    delete,
    delete_bondsnummer_index,
    get,
    get_email_by_bondsnummer,
    listall,
    set_bondsnummer_index,
    upsert,
)

SYSTEM_USERS_TABLE = "system_users"


def is_cancelled(opzegdatum: str, today: date | None = None) -> bool:
    """Check if a cancellation date is in the past.

    The Atletiekunie CSV uses DD/MM/YYYY format. Returns False for empty
    strings, unparseable dates, or dates in the future.
    """
    if not opzegdatum:
        return False
    try:
        cancel_date = datetime.strptime(opzegdatum, "%d/%m/%Y").date()
    except ValueError:
        return False
    if today is None:
        today = date.today()
    return cancel_date <= today


@dataclass
class EmailChange:
    old_email: str
    new_email: str
    bondsnummer: int


@dataclass
class ExistingPair:
    sync: UserDataEntry
    current: UserDataEntry | None


@dataclass
class SyncGroups:
    departed: list[str]
    to_accept: list[UserDataEntry]
    pending_signup: list[str]
    existing: list[ExistingPair]
    email_changes: list[EmailChange]


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
        "to_accept": [
            {
                "email": e.email,
                "voornaam": e.voornaam,
                "tussenvoegsel": e.tussenvoegsel,
                "achternaam": e.achternaam,
            }
            for e in groups.to_accept
        ],
        "pending_signup": groups.pending_signup,
        "existing": existing,
        "email_changes": [
            {
                "old_email": ec.old_email,
                "new_email": ec.new_email,
                "bondsnummer": ec.bondsnummer,
            }
            for ec in groups.email_changes
        ],
    }


def parse_csv(content: str) -> list[UserDataEntry]:
    """Parse CSV content string into UserDataEntry objects."""
    if content.startswith("\ufeff"):
        content = content[1:]
    entries = []
    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames is not None:
        for row in reader:
            email = normalize_email(row.get("Email", ""))
            if not email:
                continue
            bondsnummer_raw = row.get("Bondsnummer", "").strip()
            bondsnummer = int(bondsnummer_raw) if bondsnummer_raw else 0
            entries.append(
                UserDataEntry(
                    bondsnummer=bondsnummer,
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


def detect_email_changes(
    store: Storage, sync_entries: list[UserDataEntry]
) -> list[EmailChange]:
    """Detect email mismatches by looking up bondsnummer index."""
    changes: list[EmailChange] = []
    for entry in sync_entries:
        if entry.bondsnummer <= 0:
            continue
        old_email = get_email_by_bondsnummer(store, entry.bondsnummer)
        if old_email is not None and old_email != entry.email:
            changes.append(
                EmailChange(
                    old_email=old_email,
                    new_email=entry.email,
                    bondsnummer=entry.bondsnummer,
                )
            )
    return changes


def import_sync(store: Storage, entries: list[UserDataEntry]) -> int:
    """Clear sync table and import entries. Returns count imported."""
    store.clear(SYNC_TABLE)
    for entry in entries:
        upsert(store, SYNC_TABLE, entry)
    return len(entries)


def add_system_user(store: Storage, email: str) -> bool:
    """Mark a user as system-only (excluded from sync comparison)."""
    key = normalize_email(email)
    if store.get(SYSTEM_USERS_TABLE, key) is not None:
        return False
    store.add(SYSTEM_USERS_TABLE, key, b"1", expires_at=0)
    return True


def list_system_users(store: Storage) -> list[str]:
    """Return emails of all system-only users."""
    return store.list_keys(SYSTEM_USERS_TABLE)


def cleanup_orphaned_userdata(store: Storage) -> int:
    """Delete userdata entries that have no corresponding registered user."""
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
    """Compare sync table against registered users and registrations.

    System users are excluded. Only users with an active member permission
    are considered "departed".
    """
    cleanup_orphaned_userdata(store)
    timestamp = int(time_mod.time())

    sync_entries = listall(store, SYNC_TABLE)
    sync_by_email = {e.email: e for e in sync_entries}

    # Detect email changes via bondsnummer index
    email_changes = detect_email_changes(store, sync_entries)
    change_new_to_old = {ec.new_email: ec.old_email for ec in email_changes}
    changing_old_emails = {ec.old_email for ec in email_changes}

    # Split sync entries into active and cancelled
    active_sync_emails: set[str] = set()
    cancelled_sync_emails: set[str] = set()
    for e in sync_entries:
        if is_cancelled(e.opzegdatum):
            cancelled_sync_emails.add(e.email)
        else:
            active_sync_emails.add(e.email)

    registered_emails = set(store.list_keys("users_by_email"))
    system_emails = set(store.list_keys(SYSTEM_USERS_TABLE))
    comparable_emails = registered_emails - system_emails

    # Departed: registered users not in active sync OR cancelled,
    # who still have member permission. Exclude bondsnummer-matched.
    departed = [
        email
        for email in comparable_emails
        if (email not in active_sync_emails or email in cancelled_sync_emails)
        and email not in changing_old_emails
        and has_member_permission(store, timestamp, email)
    ]

    to_accept: list[UserDataEntry] = []
    pending_signup: list[str] = []
    existing: list[ExistingPair] = []

    def classify_registration(email: str, reg: Registration) -> None:
        """Classify a sync email that has a registrations entry."""
        if not reg.accepted:
            # Self-registered, not yet accepted — goes to to_accept
            to_accept.append(sync_by_email[email])
        elif not reg.account_created:
            # Accepted but no account yet
            pending_signup.append(email)
        else:
            # Has registration with account_created=True and accepted=True
            # (e.g. notify_on_completion still pending). Treat as existing.
            existing.append(
                ExistingPair(
                    sync=sync_by_email[email],
                    current=get(store, USERDATA_TABLE, email),
                )
            )

    bondsnummer_matched_emails = set(change_new_to_old.keys())

    for email in active_sync_emails:
        if email in system_emails:
            continue
        if email in bondsnummer_matched_emails:
            old_email = change_new_to_old[email]
            existing.append(
                ExistingPair(
                    sync=sync_by_email[email],
                    current=get(store, USERDATA_TABLE, old_email),
                )
            )
        elif email in registered_emails:
            # Check if there's a pending registration (e.g. self-reg with account)
            reg = get_registration(store, email)
            if reg is not None and not reg.accepted:
                # Self-registered with account but pending approval
                to_accept.append(sync_by_email[email])
            else:
                existing.append(
                    ExistingPair(
                        sync=sync_by_email[email],
                        current=get(store, USERDATA_TABLE, email),
                    )
                )
        else:
            # Not registered — check registrations table
            reg = get_registration(store, email)
            if reg is not None:
                classify_registration(email, reg)
            else:
                # Truly new
                to_accept.append(sync_by_email[email])

    return SyncGroups(
        departed=departed,
        to_accept=to_accept,
        pending_signup=pending_signup,
        existing=existing,
        email_changes=email_changes,
    )


def build_lastname(entry: UserDataEntry) -> str:
    """Build a full lastname from tussenvoegsel and achternaam."""
    parts = []
    if entry.tussenvoegsel:
        parts.append(entry.tussenvoegsel)
    parts.append(entry.achternaam)
    return " ".join(parts)


def add_accepted(store: Storage, email: str) -> bool:
    """Add a sync entry to registrations as accepted.

    Handles three cases:
    - Truly new: creates registration with accepted=True
    - Self-registered without account: updates to accepted=True
    - Self-registered with account: grants member, sends acceptance, cleans up
    """
    email = normalize_email(email)
    entry = get(store, SYNC_TABLE, email)
    if entry is None:
        return False

    lastname = build_lastname(entry)

    # Check if user already has an account
    user_result = store.get("users_by_email", email)
    if user_result is not None:
        # Scenario 3: user has account but pending approval
        reg = get_registration(store, email)
        if reg is None:
            return False  # Already fully accepted
        user_id = user_result[0].decode("utf-8")
        timestamp = int(time_mod.time())
        add_permission(store, timestamp, user_id, Permissions.MEMBER)
        upsert(store, USERDATA_TABLE, entry)
        sync_user_profile(store, email, entry)
        if entry.bondsnummer > 0:
            set_bondsnummer_index(store, entry.bondsnummer, email)
        set_birthday(
            store,
            email,
            entry.geboortedatum,
            entry.voornaam,
            entry.tussenvoegsel,
            entry.achternaam,
        )
        delete_registration(store, email)
        return True

    # Create or update registration
    reg = get_registration(store, email)
    if reg is not None:
        # Self-registered, update to accepted
        reg.accepted = True
        reg.firstname = entry.voornaam
        reg.lastname = lastname
        upsert_registration(store, reg)
    else:
        # Truly new
        reg = create_or_reuse_registration(
            store, email, entry.voornaam, lastname, accepted=True
        )

    # Store sync data
    upsert(store, USERDATA_TABLE, entry)
    if entry.bondsnummer > 0:
        set_bondsnummer_index(store, entry.bondsnummer, email)
    set_birthday(
        store,
        email,
        entry.geboortedatum,
        entry.voornaam,
        entry.tussenvoegsel,
        entry.achternaam,
    )
    return True


def grant_member_permission(store: Storage, timestamp: int, email: str) -> bool:
    """Grant or renew member permission for a registered user."""
    result = store.get("users_by_email", email)
    if result is None:
        return False
    user_id = result[0].decode("utf-8")
    add_permission(store, timestamp, user_id, Permissions.MEMBER)
    return True


def sync_user_profile(store: Storage, email: str, entry: UserDataEntry) -> None:
    """Update users:profile with name from sync data."""
    result = store.get("users_by_email", email)
    if result is None:
        return
    user_id = result[0].decode("utf-8")

    profile_result = store.get("users", f"{user_id}:profile")
    if profile_result is None:
        return
    _, counter = profile_result

    profile_data = {
        "firstname": entry.voornaam,
        "lastname": build_lastname(entry),
    }
    profile_bytes = json.dumps(profile_data).encode("utf-8")
    store.update("users", f"{user_id}:profile", profile_bytes, counter, expires_at=0)


def sync_userdata(store: Storage, timestamp: int, email: str) -> bool:
    """Copy sync data into userdata and renew member permission."""
    entry = get(store, SYNC_TABLE, email)
    if entry is None:
        return False
    upsert(store, USERDATA_TABLE, entry)
    grant_member_permission(store, timestamp, email)
    sync_user_profile(store, email, entry)
    if entry.bondsnummer > 0:
        set_bondsnummer_index(store, entry.bondsnummer, email)
    set_birthday(
        store,
        email,
        entry.geboortedatum,
        entry.voornaam,
        entry.tussenvoegsel,
        entry.achternaam,
    )
    return True


def revoke_member(store: Storage, timestamp: int, email: str) -> bool:
    """Fully delete a departed user's account and all associated data."""
    email = normalize_email(email)
    result = store.get("users_by_email", email)
    if result is None:
        return False
    user_id_bytes, _ = result
    user_id = user_id_bytes.decode("utf-8")

    # Get bondsnummer before deleting userdata
    userdata = get(store, USERDATA_TABLE, email)
    bondsnummer = userdata.bondsnummer if userdata else 0

    # Delete user account (all keys)
    store.delete("users", f"{user_id}:profile")
    store.delete("users", f"{user_id}:email")
    store.delete("users", f"{user_id}:password")
    store.delete("users", f"{user_id}:disabled")
    store.delete("users", f"{user_id}:sessions_counter")

    store.delete("users_by_email", email)

    remove_permission(store, user_id, "member")

    delete(store, USERDATA_TABLE, email)
    delete_birthday(store, email)

    if bondsnummer > 0:
        delete_bondsnummer_index(store, bondsnummer)

    # Clean up registration
    delete_registration(store, email)

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
    for entry in groups.to_accept:
        if add_accepted(store, entry.email):
            added += 1
        else:
            skipped += 1
    return {"added": added, "skipped": skipped}


def update_user_email(
    store: Storage, old_email: str, new_email: str, bondsnummer: int
) -> bool:
    """Update all references when a user's email changes."""
    old_key = normalize_email(old_email)
    new_key = normalize_email(new_email)

    # 1. users_by_email
    result = store.get("users_by_email", old_key)
    if result is None:
        # No user account — may be a pending registration only
        migrate_registration_email(store, old_key, new_key)
        # Update sync-related tables
        old_entry = get(store, USERDATA_TABLE, old_email)
        if old_entry is not None:
            delete(store, USERDATA_TABLE, old_email)
            old_entry.email = new_key
            upsert(store, USERDATA_TABLE, old_entry)
        if bondsnummer > 0:
            set_bondsnummer_index(store, bondsnummer, new_email)
        bday_result = store.get(BIRTHDAYS_TABLE, old_key)
        if bday_result is not None:
            data_bytes, _ = bday_result
            store.delete(BIRTHDAYS_TABLE, old_key)
            store.add(BIRTHDAYS_TABLE, new_key, data_bytes, expires_at=0)
        return True

    user_id_bytes, _ = result
    user_id = user_id_bytes.decode("utf-8")
    store.delete("users_by_email", old_key)
    store.add("users_by_email", new_key, user_id_bytes, expires_at=0)

    # 2. users:{user_id}:email
    email_result = store.get("users", f"{user_id}:email")
    if email_result is not None:
        _, counter = email_result
        store.update(
            "users",
            f"{user_id}:email",
            new_key.encode("utf-8"),
            counter,
            expires_at=0,
        )

    # 3. userdata
    old_entry = get(store, USERDATA_TABLE, old_email)
    if old_entry is not None:
        delete(store, USERDATA_TABLE, old_email)
        old_entry.email = new_key
        upsert(store, USERDATA_TABLE, old_entry)

    # 4. bondsnummer index
    if bondsnummer > 0:
        set_bondsnummer_index(store, bondsnummer, new_email)

    # 5. registrations
    migrate_registration_email(store, old_key, new_key)

    # 6. birthdays
    bday_result = store.get(BIRTHDAYS_TABLE, old_key)
    if bday_result is not None:
        data_bytes, _ = bday_result
        store.delete(BIRTHDAYS_TABLE, old_key)
        store.add(BIRTHDAYS_TABLE, new_key, data_bytes, expires_at=0)

    return True


def update_existing(store: Storage, email: str | None = None) -> dict:
    """Update single existing user or all existing. Returns result dict."""
    timestamp = int(time_mod.time())
    if email:
        if sync_userdata(store, timestamp, email):
            return {"updated": 1}
        return {"error": f"No sync entry for {email}"}

    groups = compute_groups(store)

    # Apply email changes first
    email_changes_applied = 0
    for ec in groups.email_changes:
        if update_user_email(store, ec.old_email, ec.new_email, ec.bondsnummer):
            email_changes_applied += 1

    count = sum(
        1 for p in groups.existing if sync_userdata(store, timestamp, p.sync.email)
    )
    result: dict = {"updated": count}
    if email_changes_applied > 0:
        result["email_changes_applied"] = email_changes_applied
    return result
