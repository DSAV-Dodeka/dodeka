import json
from dataclasses import dataclass

from freetser import Storage


USERDATA_TABLE = "userdata"
SYNC_TABLE = "sync"


@dataclass
class UserDataEntry:
    bondsnummer: str
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
        bondsnummer=d["bondsnummer"],
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
