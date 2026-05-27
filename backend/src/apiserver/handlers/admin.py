"""Admin handlers for the public API."""

import json
import logging
import time

from freetser import Request, Response, Storage, UpdateCounterMismatch
from freetser.server import StorageQueue

from apiserver.data.outbox import create_outbox_row
from apiserver.data.permissions import (
    UserNotFoundError,
    add_permission,
    allowed_permission,
    get_all_permissions,
    read_permissions,
    remove_permission,
)
from apiserver.data.registrations import (
    delete_registration,
    get_registration,
    list_registrations,
    upsert_registration,
)
from apiserver.data.user import list_all_users
from apiserver.data.userdata import (
    BONDSNUMMER_TABLE,
    VOLTA_DATA_TABLE,
    delete_user_bondsnummer,
    get_volta,
    volta_to_dict,
)
from apiserver.handlers.acceptance import (
    dispatch_pending_outbox,
    send_registration_invite,
)
from apiserver.settings import SmtpConfig
from apiserver.sync import (
    CompleteSyncError,
    ImportValidationError,
    StaleCounter,
    complete_sync,
    compute_sync_status,
    import_sync,
    link_bondsnummer,
    list_system_users,
    parse_csv,
    resolve_sync_match,
    serialize_sync_status,
)

logger = logging.getLogger("apiserver.handlers.admin")


def list_registrations_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_registrations/."""

    def list_regs(store: Storage) -> list:
        regs = list_registrations(store)
        result = []
        for reg in regs:
            volta_data = None
            if reg.bondsnummer is not None:
                vd = get_volta(store, VOLTA_DATA_TABLE, reg.bondsnummer)
                if vd is not None:
                    volta_data = volta_to_dict(vd)
            actions = []
            if reg.accepted:
                actions.append({"kind": "resend_registration_invite"})
            result.append(
                {
                    "registration_id": reg.registration_id,
                    "email": reg.email,
                    "firstname": reg.firstname,
                    "lastname": reg.lastname,
                    "accepted": reg.accepted,
                    "bondsnummer": reg.bondsnummer,
                    "signup_active": reg.signup_token is not None,
                    "volta_data": volta_data,
                    "available_actions": actions,
                }
            )
        result.sort(key=lambda r: (r["accepted"], r["email"]))
        return result

    result = store_queue.execute(list_regs)
    logger.info(f"list_registrations: Returning {len(result)} registrations")
    return Response.json(result)


def accept_registration_handler(
    req: Request,
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> Response:
    """Handle /admin/accept_registration/.

    Sets accepted=True and creates a durable outbox row.
    Idempotent if already accepted (no duplicate outbox row).
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        registration_id = body_data.get("registration_id")
        if not registration_id:
            return Response.text("Missing registration_id", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    def accept(store: Storage) -> dict:
        reg = get_registration(store, registration_id)
        if reg is None:
            return {"error": f"Registration {registration_id} not found"}

        invite_needed = not reg.accepted
        if invite_needed:
            reg.accepted = True
            upsert_registration(store, reg)
            create_outbox_row(
                store,
                kind="send_registration_invite",
                subject_kind="registration",
                subject_id=reg.registration_id,
                payload={
                    "registration_id": reg.registration_id,
                    "email": reg.email,
                    "display_name": reg.firstname,
                },
            )

        return {
            "success": True,
            "registration_id": reg.registration_id,
            "email": reg.email,
            "display_name": reg.firstname,
        }

    result = store_queue.execute(accept)
    if "error" in result:
        logger.warning(f"accept_registration: {result['error']}")
        return Response.json(result, status_code=400)

    # Attempt delivery after commit
    dispatch_pending_outbox(store_queue, frontend_origin, smtp_config, smtp_send)

    logger.info(f"accept_registration: Accepted {registration_id}")
    return Response.json(result)


def resend_registration_invite_handler(
    req: Request,
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> Response:
    """Handle /admin/resend_registration_invite/.

    Direct admin command, sends immediately, no outbox.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        registration_id = body_data.get("registration_id")
        if not registration_id:
            return Response.text("Missing registration_id", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    reg = store_queue.execute(lambda store: get_registration(store, registration_id))
    if reg is None:
        return Response.json(
            {"error": f"Registration {registration_id} not found"},
            status_code=404,
        )
    if not reg.accepted:
        return Response.json({"error": "Registration not accepted"}, status_code=400)

    success = send_registration_invite(
        frontend_origin=frontend_origin,
        smtp_config=smtp_config,
        smtp_send=smtp_send,
        registration_id=reg.registration_id,
        email=reg.email,
        display_name=reg.firstname,
    )
    if not success:
        return Response.json({"error": "Failed to send invite"}, status_code=500)

    return Response.json({"success": True, "email": reg.email})


def delete_registration_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/delete_registration/."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        registration_id = body_data.get("registration_id")
        if not registration_id:
            return Response.text("Missing registration_id", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    deleted = store_queue.execute(
        lambda store: delete_registration(store, registration_id)
    )
    if not deleted:
        return Response.json(
            {"error": f"Registration {registration_id} not found"}, status_code=404
        )

    logger.info(f"delete_registration: Deleted {registration_id}")
    return Response.json({"success": True})


def delete_user_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/delete_user/."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        user_id = body_data.get("user_id")
        if not user_id:
            return Response.text("Missing user_id", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    def do_delete(store: Storage) -> dict:
        email_result = store.get("users", f"{user_id}:email")
        if email_result is None:
            return {"error": f"User {user_id} not found"}

        email = email_result[0].decode("utf-8")

        # Check for system user
        system_emails = set(store.list_keys("system_users"))
        if email in system_emails:
            return {"error": "Cannot delete system user"}

        # Remove bondsnummer link if any
        for key in store.list_keys(BONDSNUMMER_TABLE):
            result = store.get(BONDSNUMMER_TABLE, key)
            if result is not None and result[0].decode("utf-8") == user_id:
                delete_user_bondsnummer(store, int(key))
                break

        # Remove user data (same as departed user cleanup)
        store.delete("users", f"{user_id}:profile")
        store.delete("users", f"{user_id}:email")
        store.delete("users", f"{user_id}:password")
        store.delete("users", f"{user_id}:disabled")
        store.delete("users", f"{user_id}:sessions_counter")
        store.delete("users_by_email", email)
        remove_permission(store, user_id, "member")

        return {"success": True}

    result = store_queue.execute(do_delete)
    if "error" in result:
        status = 404 if "not found" in result["error"] else 403
        return Response.json(result, status_code=status)

    logger.info(f"delete_user: Deleted {user_id}")
    return Response.json(result)


def resolve_sync_match_handler(
    req: Request,
    store_queue: StorageQueue,
) -> Response:
    """Handle /admin/resolve_sync_match/ — records a pending decision."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        bondsnummer = body_data.get("bondsnummer")
        kind = body_data.get("kind")
        subject_id = body_data.get("subject_id")
        counter = body_data.get("sync_state_counter")
        if bondsnummer is None or kind is None:
            return Response.text("Missing bondsnummer or kind", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    try:
        result = store_queue.execute(
            lambda store: resolve_sync_match(
                store, int(bondsnummer), kind, subject_id, counter
            )
        )
    except UpdateCounterMismatch:
        return Response.json(
            {"success": False, "message": "Stale sync_state_counter"},
            status_code=400,
        )
    if not result.success:
        logger.warning(f"resolve_sync_match: {result.message}")
        return Response.json(
            {"success": False, "message": result.message}, status_code=400
        )

    logger.info(f"resolve_sync_match: {result.message}")
    return Response.json({"success": True, "message": result.message})


def complete_sync_handler(
    req: Request,
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> Response:
    """Handle /admin/complete_sync/ — apply the pending sync session."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        counter = body_data.get("sync_state_counter")
    except json.JSONDecodeError, ValueError:
        counter = None

    try:
        result = store_queue.execute(lambda store: complete_sync(store, counter))
    except UpdateCounterMismatch:
        return Response.json({"error": "Stale sync_state_counter"}, status_code=409)
    if isinstance(result, CompleteSyncError):
        logger.warning(f"complete_sync: {result.message}")
        return Response.json({"error": result.message}, status_code=400)

    # Attempt outbox delivery after commit
    dispatch_pending_outbox(store_queue, frontend_origin, smtp_config, smtp_send)

    logger.info(f"complete_sync: {result.message}")
    return Response.json(
        {
            "success": True,
            "volta_rows_applied": result.volta_rows_applied,
            "registrations_created": result.registrations_created,
            "registrations_accepted": result.registrations_accepted,
            "registrations_updated": result.registrations_updated,
            "users_refreshed": result.users_refreshed,
            "users_departed": result.users_departed,
        }
    )


def link_bondsnummer_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/link_bondsnummer/."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        kind = body_data.get("kind")
        subject_id = body_data.get("subject_id")
        bn = body_data.get("bondsnummer")
        if not kind or not subject_id or bn is None:
            return Response.text(
                "Missing kind, subject_id, or bondsnummer",
                status_code=400,
            )
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    result = store_queue.execute(
        lambda store: link_bondsnummer(store, kind, subject_id, int(bn))
    )
    if not result.success:
        logger.warning(f"link_bondsnummer: {result.message}")
        return Response.json(
            {"success": False, "message": result.message}, status_code=400
        )

    logger.info(f"link_bondsnummer: {result.message}")
    return Response.json({"success": True, "message": result.message})


def add_user_permission(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/add_permission/."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        user_id = body_data.get("user_id")
        permission = body_data.get("permission")
        if not user_id or not permission:
            return Response.text("Missing user_id or permission", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    if permission == "admin":
        return Response.text("Cannot add admin permission", status_code=403)
    if not allowed_permission(permission):
        return Response.text(f"Invalid permission: {permission}", status_code=400)

    timestamp = int(time.time())

    def add_perm(store: Storage) -> str | UserNotFoundError:
        result = add_permission(store, timestamp, user_id, permission)
        if result is not None:
            return result
        return f"Added permission {permission} to user {user_id}\n"

    result = store_queue.execute(add_perm)
    if isinstance(result, UserNotFoundError):
        return Response.text(f"User {user_id} not found", status_code=404)
    return Response.text(result)


def remove_user_permission(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/remove_permission/."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        user_id = body_data.get("user_id")
        permission = body_data.get("permission")
        if not user_id or not permission:
            return Response.text("Missing user_id or permission", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    if not allowed_permission(permission):
        return Response.text(f"Invalid permission: {permission}", status_code=400)

    def remove_perm(store: Storage) -> str | UserNotFoundError:
        result = remove_permission(store, user_id, permission)
        if result is not None:
            return result
        return f"Removed permission {permission} from user {user_id}\n"

    result = store_queue.execute(remove_perm)
    if isinstance(result, UserNotFoundError):
        return Response.text(f"User {user_id} not found", status_code=404)
    return Response.text(result)


def list_users_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_users/."""
    timestamp = int(time.time())

    def get_users(store: Storage) -> list[dict]:
        users = list_all_users(store, timestamp)
        result = []
        for u in users:
            bn = None
            volta_data = None
            for key in store.list_keys(BONDSNUMMER_TABLE):
                res = store.get(BONDSNUMMER_TABLE, key)
                if res is not None and res[0].decode("utf-8") == u.user_id:
                    bn = int(key)
                    vd = get_volta(store, VOLTA_DATA_TABLE, bn)
                    if vd is not None:
                        volta_data = volta_to_dict(vd)
                    break
            result.append(
                {
                    "user_id": u.user_id,
                    "email": u.email,
                    "firstname": u.firstname,
                    "lastname": u.lastname,
                    "permissions": sorted(u.permissions),
                    "bondsnummer": bn,
                    "volta_data": volta_data,
                }
            )
        return result

    result = store_queue.execute(get_users)
    return Response.json(result)


def available_permissions_handler() -> Response:
    return Response.json({"permissions": get_all_permissions()})


def set_permissions_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/set_permissions/."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        permissions_map = body_data.get("permissions")
        if not permissions_map or not isinstance(permissions_map, dict):
            return Response.text("Missing permissions map", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    for user_id, perms in permissions_map.items():
        if not isinstance(perms, list):
            return Response.text(
                f"Permissions for {user_id} must be a list",
                status_code=400,
            )
        for perm in perms:
            if not allowed_permission(perm):
                return Response.text(f"Invalid permission: {perm}", status_code=400)
            if perm == "admin":
                return Response.text(
                    "Cannot set admin permission via this endpoint",
                    status_code=403,
                )

    timestamp = int(time.time())
    results: dict[str, dict] = {}

    def apply_permissions(store: Storage) -> None:
        for user_id, target_perms in permissions_map.items():
            target_set = set(target_perms)
            current = read_permissions(store, timestamp, user_id)
            if isinstance(current, UserNotFoundError):
                results[user_id] = {"error": "user_not_found"}
                continue
            current_non_admin = current - {"admin"}
            target_non_admin = target_set - {"admin"}
            to_add = target_non_admin - current_non_admin
            to_remove = current_non_admin - target_non_admin
            for perm in to_add:
                add_permission(store, timestamp, user_id, perm)
            for perm in to_remove:
                remove_permission(store, user_id, perm)
            results[user_id] = {
                "added": sorted(to_add),
                "removed": sorted(to_remove),
            }

    store_queue.execute(apply_permissions)
    return Response.json({"results": results})


def import_sync_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/import_sync/."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        csv_content = body_data.get("csv_content")
        if not csv_content:
            return Response.text("Missing csv_content", status_code=400)
        counter = body_data.get("sync_state_counter")
        file_modified_at = body_data.get("file_modified_at")
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    entries = parse_csv(csv_content)
    try:
        result = store_queue.execute(
            lambda store: import_sync(store, entries, counter, file_modified_at)
        )
    except UpdateCounterMismatch:
        return Response.json({"error": "Stale sync_state_counter"}, status_code=409)
    if isinstance(result, (ImportValidationError, StaleCounter)):
        return Response.json({"error": result.message}, status_code=400)
    logger.info(f"import_sync: Imported {result} entries")
    return Response.json({"imported": result})


def sync_status_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/sync_status/."""
    result = store_queue.execute(
        lambda store: serialize_sync_status(compute_sync_status(store))
    )
    return Response.json(result)


def list_system_users_handler(store_queue: StorageQueue) -> Response:
    users = store_queue.execute(list_system_users)
    return Response.json({"system_users": users})
