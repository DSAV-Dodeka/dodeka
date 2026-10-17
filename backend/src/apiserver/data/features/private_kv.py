"""Private key-value store: each record holds both the JSON value and the
required role for member-facing reads.

Storage shape (JSON bytes):
    {"role": "<permission name>", "value": <arbitrary JSON>}
"""

from freetser import Storage

PRIVATE_TABLE = "private"


def get_private_record(store: Storage, key: str) -> bytes | None:
    """Return the raw record bytes for ``key`` (``{role, value}``), or None."""
    result = store.get(PRIVATE_TABLE, key)
    if result is None:
        return None
    data_bytes, _ = result
    return data_bytes


def set_private_record(store: Storage, key: str, record_bytes: bytes) -> None:
    """Store the encoded ``{role, value}`` record under ``key``.

    Creates the key, or replaces its current record: the admin Private tab
    re-saves the whole JSON document every time, so replacing is the normal
    case. (``store.add`` only inserts and raised ``EntryAlreadyExists`` for an
    existing key, so every save after the first one failed with a 500.)
    """
    store.overwrite(PRIVATE_TABLE, key, record_bytes, expires_at=0)


def list_private_keys(store: Storage) -> list[str]:
    """Return all keys currently set in the private store."""
    return list(store.list_keys(PRIVATE_TABLE))
