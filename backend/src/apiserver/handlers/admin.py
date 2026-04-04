"""Admin handlers for the public API.

Handles user management, permissions, sync operations, and related flows.
"""

import json
import logging
import smtplib
import time
from dataclasses import asdict

from freetser import Request, Response, Storage
from freetser.server import StorageQueue

from apiserver.data.permissions import (
    Permissions,
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
    normalize_email,
    upsert_registration,
)
from apiserver.data.user import list_all_users
from apiserver.email import EmailData, sendemail
from apiserver.handlers.acceptance import do_accept_new_with_email
from apiserver.settings import SmtpConfig
from apiserver.sync import (
    compute_groups,
    import_sync,
    list_system_users,
    parse_csv,
    remove_departed,
    serialize_groups,
    update_existing,
)

logger = logging.getLogger("apiserver.handlers.admin")


def list_newusers_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_newusers/ — lists all pending registrations."""

    def list_regs(store: Storage) -> list:
        regs = list_registrations(store)
        result = []
        for reg in regs:
            is_registered = store.get("users_by_email", reg.email) is not None
            result.append(
                {
                    "email": reg.email,
                    "firstname": reg.firstname,
                    "lastname": reg.lastname,
                    "accepted": reg.accepted,
                    "account_created": reg.account_created,
                    "email_send_count": reg.email_send_count,
                    "has_signup_token": reg.signup_token is not None,
                    "is_registered": is_registered,
                    "registration_token": reg.registration_token,
                }
            )
        return result

    result = store_queue.execute(list_regs)
    logger.info(f"list_newusers: Returning {len(result)} registrations")
    return Response.json(result)


def accept_user_handler(
    req: Request,
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> Response:
    """Handle /admin/accept_user/ — accept a user.

    If user already has account: grant member, send acceptance email, clean up.
    If no account yet: mark accepted, set notify_on_completion for deferred email.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email_raw = body_data.get("email")
        if not email_raw:
            logger.warning("accept_user: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"accept_user: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    email = normalize_email(email_raw)
    timestamp = int(time.time())

    def accept(store: Storage) -> dict:
        reg = get_registration(store, email)
        if reg is None:
            return {"error": f"No registration found for {email}"}

        user_result = store.get("users_by_email", email)
        if user_result is not None:
            # User already has an account — grant member + clean up
            user_id = user_result[0].decode("utf-8")
            add_permission(store, timestamp, user_id, Permissions.MEMBER)
            delete_registration(store, email)
            return {
                "success": True,
                "has_account": True,
                "display_name": reg.firstname,
                "message": f"Member permission granted to {email}",
            }

        # No account yet — mark accepted, set notify_on_completion
        reg.accepted = True
        reg.notify_on_completion = True
        upsert_registration(store, reg)

        return {
            "success": True,
            "has_account": False,
            "registration_token": reg.registration_token,
            "display_name": reg.firstname,
            "message": f"User {email} marked as accepted (pending signup completion)",
        }

    result = store_queue.execute(accept)
    if "error" in result:
        logger.warning(f"accept_user: {result['error']}")
        return Response.json(result, status_code=400)

    # Send acceptance email if user already has an account
    if result.get("has_account"):
        try:
            link = frontend_origin
            email_data = EmailData(
                email_type="account_accepted_self",
                to_email=email,
                display_name=result.get("display_name"),
                link=link,
            )
            sendemail(smtp_config, email_data, smtp_send)
        except (smtplib.SMTPException, OSError) as exc:
            logger.error(
                f"accept_user: Failed to send acceptance email to {email}: {exc}"
            )

    logger.info(f"accept_user: {result['message']}")
    return Response.json(result)


def add_user_permission(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/add_permission/ — adds a permission to a user (except admin)."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        user_id = body_data.get("user_id")
        permission = body_data.get("permission")
        if not user_id or not permission:
            logger.warning("add_user_permission: Missing user_id or permission")
            return Response.text("Missing user_id or permission", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"add_user_permission: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    if permission == "admin":
        logger.error(
            f"add_user_permission: Attempted to add admin permission to {user_id}"
        )
        return Response.text("Cannot add admin permission", status_code=403)

    if not allowed_permission(permission):
        logger.warning(f"add_user_permission: Invalid permission {permission}")
        return Response.text(f"Invalid permission: {permission}", status_code=400)

    timestamp = int(time.time())

    def add_perm(store: Storage) -> str | UserNotFoundError:
        result = add_permission(store, timestamp, user_id, permission)
        if result is not None:
            return result
        return f"Added permission {permission} to user {user_id}\n"

    result = store_queue.execute(add_perm)
    if isinstance(result, UserNotFoundError):
        logger.warning(f"add_user_permission: User {user_id} not found")
        return Response.text(f"User {user_id} not found", status_code=404)
    else:
        logger.info(f"add_user_permission: {result.strip()}")
        return Response.text(result)


def remove_user_permission(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/remove_permission/ — removes a permission from a user."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        user_id = body_data.get("user_id")
        permission = body_data.get("permission")
        if not user_id or not permission:
            logger.warning("remove_user_permission: Missing user_id or permission")
            return Response.text("Missing user_id or permission", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"remove_user_permission: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    if not allowed_permission(permission):
        logger.warning(f"remove_user_permission: Invalid permission {permission}")
        return Response.text(f"Invalid permission: {permission}", status_code=400)

    def remove_perm(store: Storage) -> str | UserNotFoundError:
        result = remove_permission(store, user_id, permission)
        if result is not None:
            return result
        return f"Removed permission {permission} from user {user_id}\n"

    result = store_queue.execute(remove_perm)
    if isinstance(result, UserNotFoundError):
        logger.warning(f"remove_user_permission: User {user_id} not found")
        return Response.text(f"User {user_id} not found", status_code=404)
    else:
        logger.info(f"remove_user_permission: {result.strip()}")
        return Response.text(result)


def list_users_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_users/ — lists all users with their permissions."""
    timestamp = int(time.time())

    def get_users(store: Storage) -> list[dict]:
        users = list_all_users(store, timestamp)
        return [
            {
                "user_id": u.user_id,
                "email": u.email,
                "firstname": u.firstname,
                "lastname": u.lastname,
                "permissions": sorted(u.permissions),
            }
            for u in users
        ]

    result = store_queue.execute(get_users)
    logger.info(f"list_users: Returning {len(result)} users")
    return Response.json(result)


def available_permissions_handler() -> Response:
    """Handle /admin/available_permissions/ — lists all valid permissions."""
    permissions = get_all_permissions()
    return Response.json({"permissions": permissions})


def set_permissions_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/set_permissions/ — declaratively set permissions for users."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        permissions_map = body_data.get("permissions")
        if not permissions_map or not isinstance(permissions_map, dict):
            logger.warning("set_permissions: Missing or invalid permissions map")
            return Response.text("Missing permissions map", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"set_permissions: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    for user_id, perms in permissions_map.items():
        if not isinstance(perms, list):
            return Response.text(
                f"Permissions for {user_id} must be a list", status_code=400
            )
        for perm in perms:
            if not allowed_permission(perm):
                return Response.text(f"Invalid permission: {perm}", status_code=400)
            if perm == "admin":
                return Response.text(
                    "Cannot set admin permission via this endpoint", status_code=403
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
    logger.info(f"set_permissions: Updated {len(results)} users")
    return Response.json({"results": results})


def import_sync_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/import_sync/ — import CSV content into sync table."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        csv_content = body_data.get("csv_content")
        if not csv_content:
            return Response.text("Missing csv_content", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    entries = parse_csv(csv_content)
    count = store_queue.execute(lambda store: import_sync(store, entries))
    logger.info(f"import_sync: Imported {count} entries")
    return Response.json({"imported": count})


def sync_status_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/sync_status/ — compute and return sync groups."""
    result = store_queue.execute(lambda store: serialize_groups(compute_groups(store)))
    logger.info(
        f"sync_status: {len(result['to_accept'])} to_accept, "
        f"{len(result['pending_signup'])} pending_signup, "
        f"{len(result['existing'])} existing, "
        f"{len(result['departed'])} departed"
    )
    return Response.json(result)


def accept_new_sync_handler(
    req: Request,
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> Response:
    """Handle /admin/accept_new_sync/ — accept new users and send emails."""
    email = None
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            raw_email = body_data.get("email")
            if raw_email:
                email = normalize_email(raw_email)
        except json.JSONDecodeError, ValueError:
            pass

    result = do_accept_new_with_email(
        store_queue, frontend_origin, smtp_config, smtp_send, email
    )
    return Response.json(asdict(result))


def remove_departed_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/remove_departed/ — remove departed users."""
    email = None
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            raw_email = body_data.get("email")
            if raw_email:
                email = normalize_email(raw_email)
        except json.JSONDecodeError, ValueError:
            pass
    timestamp = int(time.time())
    result = store_queue.execute(lambda store: remove_departed(store, timestamp, email))
    logger.info(f"remove_departed: {result}")
    return Response.json(result)


def update_existing_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/update_existing/ — update existing user data from sync."""
    email = None
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            raw_email = body_data.get("email")
            if raw_email:
                email = normalize_email(raw_email)
        except json.JSONDecodeError, ValueError:
            pass
    result = store_queue.execute(lambda store: update_existing(store, email))
    logger.info(f"update_existing: {result}")
    return Response.json(result)


def list_system_users_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_system_users/ — list system users."""
    users = store_queue.execute(list_system_users)
    return Response.json({"system_users": users})
