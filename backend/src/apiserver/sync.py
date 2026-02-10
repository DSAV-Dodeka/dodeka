"""Sync operations for importing member data from the Atletiekunie CSV export.

Member permission lifecycle:
  1. Signup grants member permission automatically (see auth.create_user).
  2. update_existing renews the permission (1-year TTL) each sync cycle.
  3. remove_departed revokes it and disables the account when a member leaves.
  4. update_existing re-enables a previously disabled account when a member returns.
"""

import csv
import io
import json
import time as time_mod
from dataclasses import dataclass
from datetime import date, datetime

from freetser import Storage

from apiserver.data.newuser import serialize_newuser, update_accepted_flag
from apiserver.data.permissions import (
    Permissions,
    UserNotFoundError,
    add_permission,
    read_permissions,
    remove_permission,
)
from apiserver.data.registration_state import create_registration_state
from apiserver.data.userdata import (
    BIRTHDAYS_TABLE,
    SYNC_TABLE,
    USERDATA_TABLE,
    UserDataEntry,
    delete,
    delete_birthday,
    delete_bondsnummer_index,
    get,
    get_email_by_bondsnummer,
    listall,
    set_birthday,
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
    """Detect email mismatches by looking up bondsnummer index.

    For each sync entry with bondsnummer > 0, checks if the bondsnummer
    is already mapped to a different email. Returns the list of changes.
    """
    changes: list[EmailChange] = []
    for entry in sync_entries:
        if entry.bondsnummer <= 0:
            continue
        old_email = get_email_by_bondsnummer(store, entry.bondsnummer)
        if old_email is not None and old_email != entry.email.lower():
            changes.append(
                EmailChange(
                    old_email=old_email,
                    new_email=entry.email.lower(),
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

    Bondsnummer matching: if a sync entry's bondsnummer maps to a different
    registered email, the entry is treated as "existing" (not "new") and
    the email mismatch is reported in email_changes.
    """
    cleanup_orphaned_userdata(store)
    timestamp = int(time_mod.time())

    sync_entries = listall(store, SYNC_TABLE)
    sync_by_email = {e.email.lower(): e for e in sync_entries}

    # Detect email changes via bondsnummer index
    email_changes = detect_email_changes(store, sync_entries)
    # Map: new_email → old_email for bondsnummer-matched entries
    change_new_to_old = {ec.new_email: ec.old_email for ec in email_changes}
    # Set of old emails that are being replaced (should not be marked departed)
    changing_old_emails = {ec.old_email for ec in email_changes}

    # Split sync entries into active (no cancellation) and cancelled
    # Only treat as cancelled when opzegdatum is in the past
    active_sync_emails: set[str] = set()
    cancelled_sync_emails: set[str] = set()
    for e in sync_entries:
        if is_cancelled(e.opzegdatum):
            cancelled_sync_emails.add(e.email.lower())
        else:
            active_sync_emails.add(e.email.lower())

    registered_emails = set(store.list_keys("users_by_email"))
    newuser_emails = set(store.list_keys("newusers"))
    system_emails = set(store.list_keys(SYSTEM_USERS_TABLE))
    comparable_emails = registered_emails - system_emails
    known_emails = registered_emails | newuser_emails

    # Emails matched by bondsnummer count as known (even if new_email isn't
    # in registered/newuser yet, it maps to an existing old_email account)
    bondsnummer_matched_emails = set(change_new_to_old.keys())

    # Departed: registered users not in active sync OR in cancelled sync,
    # who still have member permission. Exclude users whose email is being
    # changed (they are still active, just under a new email).
    departed = [
        email
        for email in comparable_emails
        if (email not in active_sync_emails or email in cancelled_sync_emails)
        and email not in changing_old_emails
        and has_member_permission(store, timestamp, email)
    ]
    # to_accept: members in sync who need admin acceptance
    # Includes truly new members AND self-registered users (unaccepted newusers)
    to_accept: list[UserDataEntry] = []
    pending_signup: list[str] = []
    existing: list[ExistingPair] = []

    def classify_newuser(email: str) -> None:
        """Classify a sync email that has a newuser entry."""
        newuser_result = store.get("newusers", email)
        if newuser_result is None:
            # Entry disappeared — if registered, treat as existing
            if email in registered_emails:
                existing.append(
                    ExistingPair(
                        sync=sync_by_email[email],
                        current=get(store, USERDATA_TABLE, email),
                    )
                )
            return
        newuser_data = json.loads(newuser_result[0].decode("utf-8"))
        if not newuser_data.get("accepted", False):
            to_accept.append(sync_by_email[email])
        elif email not in registered_emails:
            pending_signup.append(email)
        else:
            existing.append(
                ExistingPair(
                    sync=sync_by_email[email],
                    current=get(store, USERDATA_TABLE, email),
                )
            )

    for email in active_sync_emails:
        if email in bondsnummer_matched_emails:
            old_email = change_new_to_old[email]
            existing.append(
                ExistingPair(
                    sync=sync_by_email[email],
                    current=get(store, USERDATA_TABLE, old_email),
                )
            )
        elif email not in known_emails:
            to_accept.append(sync_by_email[email])
        elif email in newuser_emails:
            classify_newuser(email)
        elif email in comparable_emails:
            existing.append(
                ExistingPair(
                    sync=sync_by_email[email],
                    current=get(store, USERDATA_TABLE, email),
                )
            )

    return SyncGroups(
        departed=departed,
        to_accept=to_accept,
        pending_signup=pending_signup,
        existing=existing,
        email_changes=email_changes,
    )


def disable_user(store: Storage, email: str) -> bool:
    """Set the disabled flag for a user, blocking signin and invalidating sessions.

    The freetser counter increment serves as the disabled_counter change
    that Faroe uses to detect state transitions.  Idempotent: no-op if
    already disabled.
    """
    result = store.get("users_by_email", email.lower())
    if result is None:
        return False
    user_id = result[0].decode("utf-8")

    disabled_result = store.get("users", f"{user_id}:disabled")
    if disabled_result is None:
        return False

    disabled_bytes, disabled_counter = disabled_result
    if disabled_bytes == b"1":
        return True  # Already disabled

    store.update("users", f"{user_id}:disabled", b"1", disabled_counter, expires_at=0)
    return True


def enable_user(store: Storage, email: str) -> bool:
    """Clear the disabled flag for a user, re-allowing signin.

    The freetser counter increment serves as the disabled_counter change
    that Faroe uses to detect state transitions.  Idempotent: no-op if
    already enabled.
    """
    result = store.get("users_by_email", email.lower())
    if result is None:
        return False
    user_id = result[0].decode("utf-8")

    disabled_result = store.get("users", f"{user_id}:disabled")
    if disabled_result is None:
        return False

    disabled_bytes, disabled_counter = disabled_result
    if disabled_bytes == b"0":
        return True  # Already enabled

    store.update("users", f"{user_id}:disabled", b"0", disabled_counter, expires_at=0)
    return True


def revoke_member(store: Storage, timestamp: int, email: str) -> bool:
    """Fully delete a departed user's account and all associated data.

    Removes: user account (all keys), email index, userdata, birthday,
    bondsnummer index, newusers entry, and registration state.
    """
    result = store.get("users_by_email", email.lower())
    if result is None:
        return False
    user_id_bytes, _ = result
    user_id = user_id_bytes.decode("utf-8")

    # Get bondsnummer before deleting userdata
    userdata = get(store, USERDATA_TABLE, email)
    bondsnummer = userdata.bondsnummer if userdata else 0

    # Delete user account (all keys from users table)
    store.delete("users", f"{user_id}:profile")
    store.delete("users", f"{user_id}:email")
    store.delete("users", f"{user_id}:password")
    store.delete("users", f"{user_id}:disabled")
    store.delete("users", f"{user_id}:sessions_counter")

    # Delete email index
    store.delete("users_by_email", email.lower())

    # Delete permissions
    remove_permission(store, user_id, "member")

    # Delete userdata and birthday
    delete(store, USERDATA_TABLE, email)
    delete_birthday(store, email)

    # Delete bondsnummer index
    if bondsnummer > 0:
        delete_bondsnummer_index(store, bondsnummer)

    # Clean up newusers and registration_state if they exist
    store.delete("newusers", email.lower())

    return True


def add_accepted(store: Storage, email: str) -> bool:
    """Add a sync entry to newusers as board-accepted.

    If the email already exists in newusers (e.g. self-registered), updates
    the entry to accepted=True.

    Scenario 3: If the email already has a user account but also has an
    unaccepted newuser entry, grants member permission and deletes the
    newuser entry.

    Also populates the bondsnummer index for early matching.
    """
    entry = get(store, SYNC_TABLE, email)
    if entry is None:
        return False

    # Check if already registered
    user_result = store.get("users_by_email", email.lower())
    if user_result is not None:
        # User already has an account but is pending approval (in newusers
        # with accepted=False). Grant member permission, update their
        # profile and sync data, and clean up the newuser entry.
        newuser_result = store.get("newusers", email.lower())
        if newuser_result is None:
            return False  # Already fully accepted, nothing to do
        user_id = user_result[0].decode("utf-8")
        timestamp = int(time_mod.time())
        add_permission(store, timestamp, user_id, Permissions.MEMBER)
        store.delete("newusers", email.lower())
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
        return True

    # If already in newusers, update to accepted=True (self-reg + sync)
    if store.get("newusers", email.lower()) is not None:
        update_accepted_flag(store, email.lower(), True)
        if entry.bondsnummer > 0:
            set_bondsnummer_index(store, entry.bondsnummer, email)
        return True

    lastname_parts = []
    if entry.tussenvoegsel:
        lastname_parts.append(entry.tussenvoegsel)
    lastname_parts.append(entry.achternaam)
    lastname = " ".join(lastname_parts)

    data = serialize_newuser(email.lower(), entry.voornaam, lastname, True)
    store.add("newusers", email.lower(), data, expires_at=0)
    create_registration_state(store, email.lower())
    if entry.bondsnummer > 0:
        set_bondsnummer_index(store, entry.bondsnummer, email)
    return True


def grant_member_permission(store: Storage, timestamp: int, email: str) -> bool:
    """Grant or renew member permission for a registered user."""
    result = store.get("users_by_email", email.lower())
    if result is None:
        return False
    user_id = result[0].decode("utf-8")
    add_permission(store, timestamp, user_id, Permissions.MEMBER)
    return True


def sync_user_profile(store: Storage, email: str, entry: UserDataEntry) -> None:
    """Update users:profile with name from sync data.

    The profile is set once at account creation from the newusers table,
    but the sync CSV is the authoritative source for names. This keeps
    the profile in sync with VoltaClub data.
    """
    result = store.get("users_by_email", email.lower())
    if result is None:
        return
    user_id = result[0].decode("utf-8")

    profile_result = store.get("users", f"{user_id}:profile")
    if profile_result is None:
        return
    _, counter = profile_result

    lastname_parts = []
    if entry.tussenvoegsel:
        lastname_parts.append(entry.tussenvoegsel)
    lastname_parts.append(entry.achternaam)

    profile_data = {
        "firstname": entry.voornaam,
        "lastname": " ".join(lastname_parts),
    }
    profile_bytes = json.dumps(profile_data).encode("utf-8")
    store.update("users", f"{user_id}:profile", profile_bytes, counter, expires_at=0)


def sync_userdata(store: Storage, timestamp: int, email: str) -> bool:
    """Copy sync data into userdata and renew member permission.

    Also updates the user profile, bondsnummer index, and birthday table.
    """
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
    """Update all references when a user's email changes.

    The athletics union CSV is the source of truth for email addresses.
    When a bondsnummer maps to a different email, this function migrates
    all stored references from old_email to new_email.
    """
    old_key = old_email.lower()
    new_key = new_email.lower()

    # 1. users_by_email: old → user_id, delete old, add new → user_id
    result = store.get("users_by_email", old_key)
    if result is None:
        return False
    user_id_bytes, _ = result
    user_id = user_id_bytes.decode("utf-8")
    store.delete("users_by_email", old_key)
    store.add("users_by_email", new_key, user_id_bytes, expires_at=0)

    # 2. users table: update {user_id}:email
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

    # 3. userdata: read old entry, delete old key, write new key
    old_entry = get(store, USERDATA_TABLE, old_email)
    if old_entry is not None:
        delete(store, USERDATA_TABLE, old_email)
        old_entry.email = new_key
        upsert(store, USERDATA_TABLE, old_entry)

    # 4. users_by_bondsnummer: update value to new email
    if bondsnummer > 0:
        set_bondsnummer_index(store, bondsnummer, new_email)

    # 5. newusers: if old key exists, migrate to new key
    newuser_result = store.get("newusers", old_key)
    if newuser_result is not None:
        data_bytes, _ = newuser_result
        store.delete("newusers", old_key)
        store.add("newusers", new_key, data_bytes, expires_at=0)

    # 6. registration_state: find by old email, update email field
    reg_keys = store.list_keys("registration_state")
    for key in reg_keys:
        reg_result = store.get("registration_state", key)
        if reg_result is not None:
            data_bytes, counter = reg_result
            state_data = json.loads(data_bytes.decode("utf-8"))
            if state_data.get("email") == old_key:
                state_data["email"] = new_key
                updated = json.dumps(state_data).encode("utf-8")
                store.update("registration_state", key, updated, counter, expires_at=0)
                break

    # 7. birthdays: if old key exists, migrate to new key
    bday_result = store.get(BIRTHDAYS_TABLE, old_key)
    if bday_result is not None:
        data_bytes, _ = bday_result
        store.delete(BIRTHDAYS_TABLE, old_key)
        store.add(BIRTHDAYS_TABLE, new_key, data_bytes, expires_at=0)

    return True


def update_existing(store: Storage, email: str | None = None) -> dict:
    """Update single existing user or all existing. Returns result dict.

    When updating all, first applies any email changes detected by
    bondsnummer matching, then syncs userdata for all existing users.
    """
    timestamp = int(time_mod.time())
    if email:
        if sync_userdata(store, timestamp, email):
            return {"updated": 1}
        return {"error": f"No sync entry for {email}"}

    groups = compute_groups(store)

    # Apply email changes first (bondsnummer-matched users with new emails)
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
