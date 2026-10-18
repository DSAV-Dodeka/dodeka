"""Handlers for committee collections (see ``data/features/committee_collections``).

Three generic routes serve every collection; the body names the collection:

- ``POST /members/collections/list/``   ``{collection}``
- ``POST /members/collections/save/``   ``{collection, item}``
- ``POST /members/collections/delete/`` ``{collection, id}``

Access comes from the collection's entry in ``COLLECTIONS``: its read role
(or admin) may list, its write role (or admin) may save and delete. These
handlers only read and write the requested collection's own table: that is
the whole reach of a committee permission. Items are saved and deleted one at
a time, so one edit never touches the others.
"""

import json
import logging
import re
import secrets
import time
from typing import Any

from freetser import Request, Response, Storage
from freetser.server import StorageQueue

from apiserver.data.client import AuthClient
from apiserver.data.features.committee_collections import (
    COLLECTIONS,
    SERVER_FIELDS,
    Collection,
    delete_item,
    item_exists,
    list_items,
    put_item,
)
from apiserver.data.permissions import Permissions
from apiserver.server import (
    SESSION_COOKIE_PRIMARY,
    SESSION_COOKIE_SECONDARY,
    AccessGranted,
    check_session_for_access,
    get_cookie_value,
)

logger = logging.getLogger("apiserver.handlers.features.committee_collections")

ITEM_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def session_has_any_role(
    headers: dict[str, str],
    roles: list[str],
    auth_client: AuthClient,
    store_queue: StorageQueue,
) -> bool:
    """True if the primary or secondary session cookie grants one of ``roles``.

    Makes blocking auth calls, so never call this inside ``store_queue.execute``.
    """
    tokens = [
        get_cookie_value(headers, SESSION_COOKIE_PRIMARY),
        get_cookie_value(headers, SESSION_COOKIE_SECONDARY),
    ]
    for token in tokens:
        if token is None:
            continue
        for role in roles:
            result = check_session_for_access(
                token, frozenset({role}), auth_client, store_queue
            )
            if isinstance(result, AccessGranted):
                return True
    return False


def parse_collection_body(req: Request) -> tuple[Collection, dict[str, Any]] | Response:
    """Decode the JSON body and look up its ``collection``.

    Returns ``(collection, body)``, or an error response to send back as-is.
    """
    try:
        body = json.loads(req.body.decode("utf-8"))
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)
    if not isinstance(body, dict):
        return Response.text("Body must be a JSON object", status_code=400)
    name = body.get("collection")
    collection = COLLECTIONS.get(name) if isinstance(name, str) else None
    if collection is None:
        return Response.text(f"Unknown collection: {name!r}", status_code=404)
    return collection, body


def list_collection_handler(
    req: Request,
    headers: dict[str, str],
    auth_client: AuthClient,
    store_queue: StorageQueue,
) -> Response:
    """Handle POST /members/collections/list/ — returns ``{"items": [...]}``."""
    parsed = parse_collection_body(req)
    if isinstance(parsed, Response):
        return parsed
    collection, _ = parsed

    allowed = [collection.read_role, Permissions.ADMIN]
    if not session_has_any_role(headers, allowed, auth_client, store_queue):
        return Response.text("Forbidden", status_code=403)

    def fetch(store: Storage) -> list[dict[str, Any]]:
        return list_items(store, collection)

    return Response.json({"items": store_queue.execute(fetch)})


def save_collection_item_handler(
    req: Request,
    headers: dict[str, str],
    auth_client: AuthClient,
    store_queue: StorageQueue,
) -> Response:
    """Handle POST /members/collections/save/ — body ``{collection, item}``.

    Creates the item, or replaces the one with the same ``item.id``. Without an
    id the backend generates one. ``created_at`` is set by the backend (kept
    when replacing); a ``created_at`` sent by the client is ignored. Returns
    ``{"item": {"id": ..., "created_at": ..., **fields}}``.
    """
    parsed = parse_collection_body(req)
    if isinstance(parsed, Response):
        return parsed
    collection, body = parsed

    # Blocking auth call, so outside store_queue.execute.
    allowed = [collection.write_role, Permissions.ADMIN]
    if not session_has_any_role(headers, allowed, auth_client, store_queue):
        return Response.text("Forbidden", status_code=403)

    item = body.get("item")
    if not isinstance(item, dict):
        return Response.text("item must be a JSON object", status_code=400)
    fields = {k: v for k, v in item.items() if k not in SERVER_FIELDS}
    item_id = item.get("id")
    if item_id is None:
        item_id = secrets.token_urlsafe(9)
    elif not isinstance(item_id, str) or not ITEM_ID_PATTERN.match(item_id):
        return Response.text(
            "id must be 1-64 letters, digits, '-' or '_'", status_code=400
        )

    problems = collection.validate(fields)
    if problems:
        return Response.text("Invalid item: " + "; ".join(problems), status_code=400)
    item_bytes = json.dumps(fields).encode("utf-8")
    if len(item_bytes) > collection.max_item_bytes:
        return Response.text(
            f"Item is too large ({len(item_bytes)} bytes, "
            f"max {collection.max_item_bytes})",
            status_code=413,
        )

    timestamp = int(time.time())

    def write(store: Storage) -> int:
        return put_item(store, collection, item_id, fields, timestamp)

    created_at = store_queue.execute(write)
    logger.info(
        f"collection save: {collection.table}/{item_id} ({len(item_bytes)} bytes)"
    )
    return Response.json({"item": {"id": item_id, "created_at": created_at, **fields}})


def delete_collection_item_handler(
    req: Request,
    headers: dict[str, str],
    auth_client: AuthClient,
    store_queue: StorageQueue,
) -> Response:
    """Handle POST /members/collections/delete/ — body ``{collection, id}``.

    404 if no item has that id.
    """
    parsed = parse_collection_body(req)
    if isinstance(parsed, Response):
        return parsed
    collection, body = parsed

    item_id = body.get("id")
    if not isinstance(item_id, str) or not ITEM_ID_PATTERN.match(item_id):
        return Response.text("Missing or invalid id", status_code=400)

    allowed = [collection.write_role, Permissions.ADMIN]
    if not session_has_any_role(headers, allowed, auth_client, store_queue):
        return Response.text("Forbidden", status_code=403)

    def remove(store: Storage) -> bool:
        if not item_exists(store, collection, item_id):
            return False
        return delete_item(store, collection, item_id)

    if not store_queue.execute(remove):
        return Response.text(f"No item with id {item_id}", status_code=404)
    logger.info(f"collection delete: {collection.table}/{item_id}")
    return Response.json({"success": True})
