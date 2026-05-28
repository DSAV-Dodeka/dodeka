"""Private key-value store handlers.

A flat string-keyed JSON store where each record is ``{role, value}``. The
required role is part of the stored record (no in-code registry), so admins
can change it through the admin tab. ``DEFAULT_PRIVATE_ROLE`` is used when a
new key is created without an explicit role.
"""

import json
import logging
from typing import Any

from freetser import Request, Response, Storage
from freetser.server import StorageQueue

from apiserver.data.client import AuthClient
from apiserver.data.features.private_kv import (
    get_private_record,
    list_private_keys,
    set_private_record,
)
from apiserver.data.permissions import allowed_permission
from apiserver.server import (
    SESSION_COOKIE_PRIMARY,
    SESSION_COOKIE_SECONDARY,
    AccessGranted,
    check_session_for_access,
    get_cookie_value,
)

logger = logging.getLogger("apiserver.handlers.features.private_kv")

DEFAULT_PRIVATE_ROLE = "member"


def _parse_record(raw: bytes) -> tuple[str, Any] | None:
    """Decode a stored record into ``(role, value)``. Returns None on corruption."""
    try:
        record = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    role = record.get("role")
    if not isinstance(role, str) or not role:
        return None
    return role, record.get("value")


def _encode_record(role: str, value: Any) -> bytes:
    return json.dumps({"role": role, "value": value}).encode("utf-8")


def get_private_handler(
    req: Request,
    headers: dict[str, str],
    auth_client: AuthClient,
    store_queue: StorageQueue,
) -> Response:
    """Handle POST /members/private/ — body ``{"key": str}``.

    Reads ``key``'s record, checks the session has the required role from the
    record, then returns ``{"value": <decoded JSON>}``. 404 if unset.
    """
    try:
        body = json.loads(req.body.decode("utf-8"))
        key = body.get("key")
        if not isinstance(key, str) or not key:
            return Response.text("Missing or invalid key", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    def fetch(store: Storage) -> bytes | None:
        return get_private_record(store, key)

    raw = store_queue.execute(fetch)
    if raw is None:
        return Response.text(f"Key not set: {key}", status_code=404)
    parsed = _parse_record(raw)
    if parsed is None:
        return Response.text("Stored record is corrupted", status_code=500)
    role, value = parsed

    required = frozenset({role})
    tokens = [
        get_cookie_value(headers, SESSION_COOKIE_PRIMARY),
        get_cookie_value(headers, SESSION_COOKIE_SECONDARY),
    ]
    granted = False
    for token in tokens:
        if token is None:
            continue
        result = check_session_for_access(token, required, auth_client, store_queue)
        if isinstance(result, AccessGranted):
            granted = True
            break
    if not granted:
        return Response.text("Forbidden", status_code=403)

    return Response.json({"value": value})


def admin_get_private_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle POST /admin/private_kv/get/ — body ``{"key": str}``.

    Returns ``{"value": <decoded JSON> | null, "required_role": str | null}``.
    A missing key reports ``required_role: null``.
    """
    try:
        body = json.loads(req.body.decode("utf-8"))
        key = body.get("key")
        if not isinstance(key, str) or not key:
            return Response.text("Missing or invalid key", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    def fetch(store: Storage) -> bytes | None:
        return get_private_record(store, key)

    raw = store_queue.execute(fetch)
    if raw is None:
        return Response.json({"value": None, "required_role": None})
    parsed = _parse_record(raw)
    if parsed is None:
        return Response.text("Stored record is corrupted", status_code=500)
    role, value = parsed
    return Response.json({"value": value, "required_role": role})


def admin_set_private_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle POST /admin/private_kv/set/.

    Body: ``{"key": str, "value": <any>, "role": str?}``. If ``role`` is
    omitted, the existing role is preserved (or DEFAULT_PRIVATE_ROLE for a
    new key). The role must be a valid permission name.
    """
    try:
        body = json.loads(req.body.decode("utf-8"))
        key = body.get("key")
        if not isinstance(key, str) or not key:
            return Response.text("Missing or invalid key", status_code=400)
        if "value" not in body:
            return Response.text("Missing value", status_code=400)
        value = body["value"]
        role_input = body.get("role")
        if role_input is not None and not isinstance(role_input, str):
            return Response.text("role must be a string", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    def fetch(store: Storage) -> bytes | None:
        return get_private_record(store, key)

    existing_raw = store_queue.execute(fetch)
    existing_role: str | None = None
    if existing_raw is not None:
        parsed = _parse_record(existing_raw)
        if parsed is not None:
            existing_role = parsed[0]

    role = role_input or existing_role or DEFAULT_PRIVATE_ROLE
    if not allowed_permission(role):
        return Response.text(
            f"Invalid role: {role!r} (must be a permission name)", status_code=400
        )

    record_bytes = _encode_record(role, value)

    def write(store: Storage) -> None:
        set_private_record(store, key, record_bytes)

    store_queue.execute(write)
    logger.info(f"private_kv set: key={key} role={role} ({len(record_bytes)} bytes)")
    return Response.json({"success": True, "required_role": role})


def admin_list_private_handler(store_queue: StorageQueue) -> Response:
    """Handle GET /admin/private_kv/list/ — list of ``{key, required_role}``."""
    def fetch(store: Storage) -> list[tuple[str, bytes | None]]:
        keys = list_private_keys(store)
        return [(k, get_private_record(store, k)) for k in keys]

    rows = store_queue.execute(fetch)
    entries: list[dict[str, str]] = []
    for k, raw in rows:
        if raw is None:
            continue
        parsed = _parse_record(raw)
        role = parsed[0] if parsed is not None else "<corrupt>"
        entries.append({"key": k, "required_role": role})
    entries.sort(key=lambda e: e["key"])
    return Response.json({"keys": entries})
