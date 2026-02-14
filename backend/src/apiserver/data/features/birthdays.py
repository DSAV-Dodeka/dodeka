"""Birthday data operations."""

import json

from freetser import Storage

BIRTHDAYS_TABLE = "birthdays"


def set_birthday(
    store: Storage,
    email: str,
    geboortedatum: str,
    voornaam: str,
    tussenvoegsel: str,
    achternaam: str,
) -> None:
    """Upsert birthday entry for a member."""
    key = email.lower()
    data = json.dumps(
        {
            "geboortedatum": geboortedatum,
            "voornaam": voornaam,
            "tussenvoegsel": tussenvoegsel,
            "achternaam": achternaam,
        }
    ).encode("utf-8")
    result = store.get(BIRTHDAYS_TABLE, key)
    if result is None:
        store.add(BIRTHDAYS_TABLE, key, data, expires_at=0)
    else:
        _, counter = result
        store.update(BIRTHDAYS_TABLE, key, data, counter, expires_at=0)


def delete_birthday(store: Storage, email: str) -> None:
    """Delete birthday entry for a member."""
    key = email.lower()
    if store.get(BIRTHDAYS_TABLE, key) is not None:
        store.delete(BIRTHDAYS_TABLE, key)


def list_birthdays(store: Storage) -> list[dict]:
    """Return all birthday entries."""
    keys = store.list_keys(BIRTHDAYS_TABLE)
    entries = []
    for key in keys:
        result = store.get(BIRTHDAYS_TABLE, key)
        if result is not None:
            data_bytes, _ = result
            entries.append(json.loads(data_bytes.decode("utf-8")))
    return entries
