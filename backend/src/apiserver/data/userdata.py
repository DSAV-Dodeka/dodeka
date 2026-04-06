"""Volta-managed data module.

Owns two logical tables:
  - sync[str(bondsnummer)] — latest imported Volta snapshot pending review/apply
  - volta_data[str(bondsnummer)] — current applied Volta-managed data

Both are keyed by bondsnummer (as string). The VoltaRow is the opaque
JSON-like object described in the spec.
"""

import json
from dataclasses import dataclass

from freetser import Storage


SYNC_TABLE = "sync"
VOLTA_DATA_TABLE = "volta_data"
BONDSNUMMER_TABLE = "users_by_bondsnummer"


@dataclass
class VoltaRow:
    bondsnummer: int
    voornaam: str
    tussenvoegsel: str
    achternaam: str
    geslacht: str
    geboortedatum: str
    email: str
    opzegdatum: str = ""


@dataclass
class VoltaFieldDiff:
    field: str
    current: str
    incoming: str


def serialize_volta(row: VoltaRow) -> bytes:
    data = {
        "bondsnummer": row.bondsnummer,
        "voornaam": row.voornaam,
        "tussenvoegsel": row.tussenvoegsel,
        "achternaam": row.achternaam,
        "geslacht": row.geslacht,
        "geboortedatum": row.geboortedatum,
        "email": row.email,
        "opzegdatum": row.opzegdatum,
    }
    return json.dumps(data).encode("utf-8")


def deserialize_volta(data: bytes) -> VoltaRow:
    d = json.loads(data.decode("utf-8"))
    return VoltaRow(
        bondsnummer=int(d.get("bondsnummer", 0) or 0),
        voornaam=d["voornaam"],
        tussenvoegsel=d["tussenvoegsel"],
        achternaam=d["achternaam"],
        geslacht=d["geslacht"],
        geboortedatum=d["geboortedatum"],
        email=d["email"],
        opzegdatum=d.get("opzegdatum", ""),
    )


def volta_to_dict(row: VoltaRow) -> dict:
    return {
        "bondsnummer": row.bondsnummer,
        "voornaam": row.voornaam,
        "tussenvoegsel": row.tussenvoegsel,
        "achternaam": row.achternaam,
        "geslacht": row.geslacht,
        "geboortedatum": row.geboortedatum,
        "email": row.email,
        "opzegdatum": row.opzegdatum,
    }


def upsert_volta(store: Storage, table: str, row: VoltaRow) -> None:
    """Upsert a Volta row keyed by bondsnummer."""
    key = str(row.bondsnummer)
    data = serialize_volta(row)
    store.overwrite(table, key, data, expires_at=0)


def get_volta(store: Storage, table: str, bondsnummer: int) -> VoltaRow | None:
    """Get a Volta row by bondsnummer."""
    result = store.get(table, str(bondsnummer))
    if result is None:
        return None
    data_bytes, _ = result
    return deserialize_volta(data_bytes)


def list_volta(store: Storage, table: str) -> list[VoltaRow]:
    """List all Volta rows in a table."""
    keys = store.list_keys(table)
    rows = []
    for key in keys:
        result = store.get(table, key)
        if result is not None:
            data_bytes, _ = result
            rows.append(deserialize_volta(data_bytes))
    return rows


def delete_volta(store: Storage, table: str, bondsnummer: int) -> bool:
    """Delete a Volta row by bondsnummer."""
    key = str(bondsnummer)
    result = store.get(table, key)
    if result is None:
        return False
    store.delete(table, key)
    return True


def compute_field_diffs(
    current: VoltaRow | None, incoming: VoltaRow
) -> list[VoltaFieldDiff]:
    """Compute generic field diffs between current and incoming Volta data."""
    if current is None:
        return []
    diffs = []
    fields = [
        "voornaam",
        "tussenvoegsel",
        "achternaam",
        "geslacht",
        "geboortedatum",
        "email",
        "opzegdatum",
    ]
    for field in fields:
        cur_val = str(getattr(current, field))
        inc_val = str(getattr(incoming, field))
        if cur_val != inc_val:
            diffs.append(VoltaFieldDiff(field=field, current=cur_val, incoming=inc_val))
    return diffs


def set_user_bondsnummer(store: Storage, bondsnummer: int, user_id: str) -> None:
    """Set users_by_bondsnummer[bondsnummer] -> user_id."""
    key = str(bondsnummer)
    value = user_id.encode("utf-8")
    store.overwrite(BONDSNUMMER_TABLE, key, value, expires_at=0)


def get_user_id_by_bondsnummer(store: Storage, bondsnummer: int) -> str | None:
    """Look up user_id by bondsnummer."""
    result = store.get(BONDSNUMMER_TABLE, str(bondsnummer))
    if result is None:
        return None
    return result[0].decode("utf-8")


def get_bondsnummer_by_user_id(store: Storage, user_id: str) -> int | None:
    """Look up the current bondsnummer for a user_id."""
    for key in store.list_keys(BONDSNUMMER_TABLE):
        result = store.get(BONDSNUMMER_TABLE, key)
        if result is None:
            continue
        if result[0].decode("utf-8") == user_id:
            return int(key)
    return None


def delete_user_bondsnummer(store: Storage, bondsnummer: int) -> None:
    """Delete users_by_bondsnummer entry."""
    key = str(bondsnummer)
    if store.get(BONDSNUMMER_TABLE, key) is not None:
        store.delete(BONDSNUMMER_TABLE, key)


def populate_birthday_for_user(store: Storage, user_id: str, bondsnummer: int) -> None:
    """Populate a birthday row for one new live user from applied volta_data."""
    row = get_volta(store, VOLTA_DATA_TABLE, bondsnummer)
    if row is None:
        return
    entry = json.dumps(
        {
            "user_id": user_id,
            "geboortedatum": row.geboortedatum,
            "voornaam": row.voornaam,
            "tussenvoegsel": row.tussenvoegsel,
            "achternaam": row.achternaam,
        }
    ).encode("utf-8")
    store.overwrite("birthdays", user_id, entry, expires_at=0)
