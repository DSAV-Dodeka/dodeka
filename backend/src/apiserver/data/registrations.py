"""Canonical registration data module.

Owns three tables:
  - registrations[registration_id] — canonical pending registration state as JSON.
  - registrations_by_email[email] -> registration_id — email lookup index.
  - registrations_by_bondsnummer[str(bondsnummer)] -> registration_id
    — Volta link index.

A registration row is deleted when it successfully becomes a live user.
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
    registration_id: str
    email: str
    firstname: str
    lastname: str
    accepted: bool
    bondsnummer: int | None
    signup_token: str | None
    email_send_count: int


@dataclass
class EmailExistsInUserTable:
    email: str


REGISTRATIONS_TABLE = "registrations"
REGISTRATIONS_BY_EMAIL_TABLE = "registrations_by_email"
REGISTRATIONS_BY_BONDSNUMMER_TABLE = "registrations_by_bondsnummer"


def generate_registration_id() -> str:
    return secrets.token_urlsafe(32)


def serialize_registration(reg: Registration) -> bytes:
    data = {
        "registration_id": reg.registration_id,
        "email": reg.email,
        "firstname": reg.firstname,
        "lastname": reg.lastname,
        "accepted": reg.accepted,
        "bondsnummer": reg.bondsnummer,
        "signup_token": reg.signup_token,
        "email_send_count": reg.email_send_count,
    }
    return json.dumps(data).encode("utf-8")


def deserialize_registration(data: bytes) -> Registration:
    d = json.loads(data.decode("utf-8"))
    return Registration(
        registration_id=d["registration_id"],
        email=d["email"],
        firstname=d["firstname"],
        lastname=d["lastname"],
        accepted=d["accepted"],
        bondsnummer=d.get("bondsnummer"),
        signup_token=d.get("signup_token"),
        email_send_count=d.get("email_send_count", 0),
    )


def get_registration(store: Storage, registration_id: str) -> Registration | None:
    """Get registration by registration_id."""
    result = store.get(REGISTRATIONS_TABLE, registration_id)
    if result is None:
        return None
    data_bytes, _ = result
    return deserialize_registration(data_bytes)


def get_registration_by_email(store: Storage, email: str) -> Registration | None:
    """Resolve email -> registration_id -> registration."""
    result = store.get(REGISTRATIONS_BY_EMAIL_TABLE, email)
    if result is None:
        return None
    registration_id = result[0].decode("utf-8")
    return get_registration(store, registration_id)


def get_registration_by_bondsnummer(
    store: Storage, bondsnummer: int
) -> Registration | None:
    """Resolve bondsnummer -> registration_id -> registration."""
    result = store.get(REGISTRATIONS_BY_BONDSNUMMER_TABLE, str(bondsnummer))
    if result is None:
        return None
    registration_id = result[0].decode("utf-8")
    return get_registration(store, registration_id)


def upsert_registration(store: Storage, reg: Registration) -> None:
    """Create or update a registration entry and its indexes."""
    key = reg.registration_id
    existing = get_registration(store, key)
    if existing is not None:
        if existing.email != reg.email:
            store.delete(REGISTRATIONS_BY_EMAIL_TABLE, existing.email)
        if existing.bondsnummer is not None and existing.bondsnummer != reg.bondsnummer:
            store.delete(REGISTRATIONS_BY_BONDSNUMMER_TABLE, str(existing.bondsnummer))

    data = serialize_registration(reg)
    store.overwrite(REGISTRATIONS_TABLE, key, data, expires_at=0)

    # Email index
    store.overwrite(
        REGISTRATIONS_BY_EMAIL_TABLE,
        reg.email,
        key.encode("utf-8"),
        expires_at=0,
    )

    # Bondsnummer index
    if reg.bondsnummer is not None:
        store.overwrite(
            REGISTRATIONS_BY_BONDSNUMMER_TABLE,
            str(reg.bondsnummer),
            key.encode("utf-8"),
            expires_at=0,
        )


def delete_registration(store: Storage, registration_id: str) -> bool:
    """Delete a registration row and all its indexes."""
    reg = get_registration(store, registration_id)
    if reg is None:
        return False
    store.delete(REGISTRATIONS_TABLE, registration_id)
    store.delete(REGISTRATIONS_BY_EMAIL_TABLE, reg.email)
    if reg.bondsnummer is not None:
        store.delete(REGISTRATIONS_BY_BONDSNUMMER_TABLE, str(reg.bondsnummer))
    return True


def create_or_reuse_registration(
    store: Storage,
    email: str,
    firstname: str,
    lastname: str,
    accepted: bool = False,
) -> Registration:
    """Create a new registration or return the existing one for this email.

    If a registration already exists for this email, it is returned as-is.
    Never clears existing accepted, bondsnummer, or signup_token state on reuse.
    """
    existing = get_registration_by_email(store, email)
    if existing is not None:
        return existing

    registration_id = generate_registration_id()
    reg = Registration(
        registration_id=registration_id,
        email=email,
        firstname=firstname,
        lastname=lastname,
        accepted=accepted,
        bondsnummer=None,
        signup_token=None,
        email_send_count=0,
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


def migrate_registration_email(
    store: Storage, registration_id: str, new_email: str
) -> bool:
    """Update the email on a registration and rewrite indexes.

    Clears signup_token since the old email-based signup session is stale.
    Returns False if the registration does not exist.
    """
    reg = get_registration(store, registration_id)
    if reg is None:
        return False

    old_email = reg.email
    if old_email == new_email:
        return True

    # Remove old email index
    store.delete(REGISTRATIONS_BY_EMAIL_TABLE, old_email)

    # Remove conflicting registration at new_email if it exists
    existing = get_registration_by_email(store, new_email)
    if existing is not None and existing.registration_id != registration_id:
        delete_registration(store, existing.registration_id)

    # Update registration
    reg.email = new_email
    reg.signup_token = None
    upsert_registration(store, reg)

    return True
