"""Birthday data operations keyed by user_id."""

import json

from freetser import Storage

BIRTHDAYS_TABLE = "birthdays"


def replace_birthdays(store: Storage, entries: list[dict]) -> None:
    """Replace the derived birthday table in one storage callback."""
    store.clear(BIRTHDAYS_TABLE)
    for entry in entries:
        store.add(
            BIRTHDAYS_TABLE,
            entry["user_id"],
            json.dumps(entry).encode("utf-8"),
            expires_at=0,
        )


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
