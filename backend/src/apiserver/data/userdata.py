import json
from dataclasses import dataclass

from freetser import Storage


USERDATA_TABLE = "userdata"
SYNC_TABLE = "sync"
BONDSNUMMER_TABLE = "users_by_bondsnummer"
BIRTHDAYS_TABLE = "birthdays"


@dataclass
class UserDataEntry:
    bondsnummer: int
    voornaam: str
    tussenvoegsel: str
    achternaam: str
    geslacht: str
    geboortedatum: str
    email: str
    opzegdatum: str = ""


def serialize(entry: UserDataEntry) -> bytes:
    data = {
        "bondsnummer": entry.bondsnummer,
        "voornaam": entry.voornaam,
        "tussenvoegsel": entry.tussenvoegsel,
        "achternaam": entry.achternaam,
        "geslacht": entry.geslacht,
        "geboortedatum": entry.geboortedatum,
        "email": entry.email,
        "opzegdatum": entry.opzegdatum,
    }
    return json.dumps(data).encode("utf-8")


def deserialize(data: bytes) -> UserDataEntry:
    d = json.loads(data.decode("utf-8"))
    return UserDataEntry(
        bondsnummer=int(d.get("bondsnummer", 0) or 0),
        voornaam=d["voornaam"],
        tussenvoegsel=d["tussenvoegsel"],
        achternaam=d["achternaam"],
        geslacht=d["geslacht"],
        geboortedatum=d["geboortedatum"],
        email=d["email"],
        opzegdatum=d.get("opzegdatum", ""),
    )


def upsert(store: Storage, table: str, entry: UserDataEntry) -> None:
    key = entry.email.lower()
    data = serialize(entry)
    result = store.get(table, key)
    if result is None:
        store.add(table, key, data, expires_at=0)
    else:
        _, counter = result
        store.update(table, key, data, counter, expires_at=0)


def get(store: Storage, table: str, email: str) -> UserDataEntry | None:
    result = store.get(table, email.lower())
    if result is None:
        return None
    data_bytes, _ = result
    return deserialize(data_bytes)


def listall(store: Storage, table: str) -> list[UserDataEntry]:
    keys = store.list_keys(table)
    entries = []
    for key in keys:
        result = store.get(table, key)
        if result is not None:
            data_bytes, _ = result
            entries.append(deserialize(data_bytes))
    return entries


def delete(store: Storage, table: str, email: str) -> bool:
    key = email.lower()
    result = store.get(table, key)
    if result is None:
        return False
    store.delete(table, key)
    return True


def set_bondsnummer_index(store: Storage, bondsnummer: int, email: str) -> None:
    """Upsert bondsnummer → email mapping."""
    key = str(bondsnummer)
    value = email.lower().encode("utf-8")
    result = store.get(BONDSNUMMER_TABLE, key)
    if result is None:
        store.add(BONDSNUMMER_TABLE, key, value, expires_at=0)
    else:
        _, counter = result
        store.update(BONDSNUMMER_TABLE, key, value, counter, expires_at=0)


def get_email_by_bondsnummer(store: Storage, bondsnummer: int) -> str | None:
    """Look up email by bondsnummer. Returns None if not found."""
    result = store.get(BONDSNUMMER_TABLE, str(bondsnummer))
    if result is None:
        return None
    return result[0].decode("utf-8")


def delete_bondsnummer_index(store: Storage, bondsnummer: int) -> None:
    """Delete a bondsnummer → email mapping."""
    key = str(bondsnummer)
    if store.get(BONDSNUMMER_TABLE, key) is not None:
        store.delete(BONDSNUMMER_TABLE, key)


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
