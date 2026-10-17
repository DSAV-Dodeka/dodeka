"""Committee collections: committees write their own data to the backend.

A collection is a list of items one committee manages from its own page, e.g.
the cards of Het Fotoboek (FOCUS). Each collection is its own table with one
row per item (key = item id, value = the item's JSON).

Security boundary: a committee permission (``focus``, ``comcom``, ...) only
ever grants writing to the tables of the collections that name it as
``write_role``. The collection routes touch nothing but the requested
collection's own table, so a committee can't reach users, registrations,
other committees' data or anything else. Who may read and write is fixed here
in code; admins only grant members the committee's tag.

To add a collection for another committee:

1. write a ``validate_<thing>`` function describing one item's shape
   (see ``fotos.py``),
2. add an entry to ``COLLECTIONS`` below,
3. build the page in the frontend; it uses the generic
   ``/members/collections/*`` routes with ``{"collection": "<name>"}``.

The table is created automatically (``COLLECTION_TABLES`` is part of
``DB_TABLES``). No route or admin setup is needed.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from freetser import Storage


@dataclass(frozen=True)
class Collection:
    table: str
    """freetser table holding this collection, one row per item."""
    read_role: str
    """Permission needed to list the items. Admins can always read."""
    write_role: str
    """Permission needed to create, change or delete items. Admins always can."""
    validate: Callable[[dict[str, Any]], list[str]]
    """Returns the problems with one item (without its id); empty = valid."""
    max_item_bytes: int
    """Upper bound on one encoded item, so a single row can't grow unbounded."""


# The committee collections that exist; see the module docstring to add one.
COLLECTIONS: dict[str, Collection] = {}

COLLECTION_TABLES = [c.table for c in COLLECTIONS.values()]


def list_items(store: Storage, collection: Collection) -> list[dict[str, Any]]:
    """All items of a collection as ``{"id": ..., **fields}``, sorted by id."""
    items: list[dict[str, Any]] = []
    for item_id in sorted(store.list_keys(collection.table)):
        result = store.get(collection.table, item_id)
        if result is None:
            continue
        value_bytes, _ = result
        items.append({"id": item_id, **json.loads(value_bytes.decode("utf-8"))})
    return items


def item_exists(store: Storage, collection: Collection, item_id: str) -> bool:
    return store.get(collection.table, item_id) is not None


def put_item(
    store: Storage, collection: Collection, item_id: str, item_bytes: bytes
) -> None:
    """Create the item, or replace it if the id already exists."""
    store.overwrite(collection.table, item_id, item_bytes, expires_at=0)


def delete_item(store: Storage, collection: Collection, item_id: str) -> bool:
    """Delete the item; False if it did not exist."""
    return store.delete(collection.table, item_id)
