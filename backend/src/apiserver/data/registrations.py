"""Canonical registration data module.

Owns two tables:
  - registrations[email] — keyed by normalized email, stores the full
    registration lifecycle state as JSON.
  - registration_tokens[registration_token] -> email — stable public
    lookup index.

This replaces the old `newuser` + `registration_state` split.
"""

import json
import secrets
from dataclasses import dataclass

from freetser import Storage


def normalize_email(email: str) -> str:
    """Normalize an email address: strip whitespace and lowercase."""
    return email.strip().lower()


@dataclass
class Registration:
    email: str
    firstname: str
    lastname: str
    accepted: bool
    account_created: bool
    registration_token: str
    signup_token: str | None
    email_send_count: int
    notify_on_completion: bool


@dataclass
class RegistrationNotFound:
    email: str


@dataclass
class RegistrationTokenNotFound:
    registration_token: str


@dataclass
class EmailExistsInUserTable:
    email: str


REGISTRATIONS_TABLE = "registrations"
REGISTRATION_TOKENS_TABLE = "registration_tokens"


def generate_registration_token() -> str:
    return secrets.token_urlsafe(32)


def serialize_registration(reg: Registration) -> bytes:
    data = {
        "email": reg.email,
        "firstname": reg.firstname,
        "lastname": reg.lastname,
        "accepted": reg.accepted,
        "account_created": reg.account_created,
        "registration_token": reg.registration_token,
        "signup_token": reg.signup_token,
        "email_send_count": reg.email_send_count,
        "notify_on_completion": reg.notify_on_completion,
    }
    return json.dumps(data).encode("utf-8")


def deserialize_registration(data: bytes) -> Registration:
    d = json.loads(data.decode("utf-8"))
    return Registration(
        email=d["email"],
        firstname=d["firstname"],
        lastname=d["lastname"],
        accepted=d["accepted"],
        account_created=d["account_created"],
        registration_token=d["registration_token"],
        signup_token=d.get("signup_token"),
        email_send_count=d.get("email_send_count", 0),
        notify_on_completion=d.get("notify_on_completion", False),
    )


def get_registration(store: Storage, email: str) -> Registration | None:
    """Get registration by normalized email."""
    result = store.get(REGISTRATIONS_TABLE, email)
    if result is None:
        return None
    data_bytes, _ = result
    return deserialize_registration(data_bytes)


def get_registration_by_token(
    store: Storage, registration_token: str
) -> Registration | None:
    """Resolve registration_token -> email -> registration."""
    result = store.get(REGISTRATION_TOKENS_TABLE, registration_token)
    if result is None:
        return None
    email = result[0].decode("utf-8")
    return get_registration(store, email)


def upsert_registration(store: Storage, reg: Registration) -> None:
    """Create or update a registration entry and its token index."""
    key = reg.email
    data = serialize_registration(reg)
    # Registration rows are canonical state snapshots. When a callback decides
    # on the new state, it should replace the stored row.
    store.overwrite(REGISTRATIONS_TABLE, key, data, expires_at=0)

    # Ensure token index exists
    # The token index is derived from the canonical registration row, so the
    # current email mapping should overwrite any older one.
    store.overwrite(
        REGISTRATION_TOKENS_TABLE,
        reg.registration_token,
        key.encode("utf-8"),
        expires_at=0,
    )


def delete_registration(store: Storage, email: str) -> bool:
    """Delete a registration row and its token index."""
    reg = get_registration(store, email)
    if reg is None:
        return False
    store.delete(REGISTRATIONS_TABLE, email)
    store.delete(REGISTRATION_TOKENS_TABLE, reg.registration_token)
    return True


def create_or_reuse_registration(
    store: Storage,
    email: str,
    firstname: str,
    lastname: str,
    accepted: bool = False,
) -> Registration:
    """Create a new registration or return the existing one for this email.

    If a registration already exists for this email, it is returned as-is
    (the caller can update fields and call upsert_registration).
    """
    existing = get_registration(store, email)
    if existing is not None:
        return existing

    registration_token = generate_registration_token()
    reg = Registration(
        email=email,
        firstname=firstname,
        lastname=lastname,
        accepted=accepted,
        account_created=False,
        registration_token=registration_token,
        signup_token=None,
        email_send_count=0,
        notify_on_completion=False,
    )
    upsert_registration(store, reg)
    return reg


def list_registrations(store: Storage) -> list[Registration]:
    """List all registration entries."""
    keys = store.list_keys(REGISTRATIONS_TABLE)
    regs = []
    for key in keys:
        result = store.get(REGISTRATIONS_TABLE, key)
        if result is not None:
            data_bytes, _ = result
            regs.append(deserialize_registration(data_bytes))
    return regs


def migrate_registration_email(store: Storage, old_email: str, new_email: str) -> bool:
    """Move a registration row from old_email to new_email.

    Preserves the registration_token, clears signup_token.
    If new_email already has a registration, it is deleted first.
    Returns False if no registration exists for old_email.
    """
    reg = get_registration(store, old_email)
    if reg is None:
        return False

    # Remove conflicting registration at new_email if it exists
    existing = get_registration(store, new_email)
    if existing is not None:
        delete_registration(store, new_email)

    # Delete old entry
    store.delete(REGISTRATIONS_TABLE, old_email)

    # Create new entry with same token, cleared signup
    reg.email = new_email
    reg.signup_token = None
    data = serialize_registration(reg)
    store.add(REGISTRATIONS_TABLE, new_email, data, expires_at=0)

    # Update token index to point to new email
    token_result = store.get(REGISTRATION_TOKENS_TABLE, reg.registration_token)
    if token_result is not None:
        # This index entry is derived from the migrated registration row, so it
        # should now point at the new canonical email unconditionally.
        store.overwrite(
            REGISTRATION_TOKENS_TABLE,
            reg.registration_token,
            new_email.encode("utf-8"),
            expires_at=0,
        )

    return True
