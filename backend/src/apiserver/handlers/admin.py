"""Admin handlers for the public API.

Handles user management, permissions, sync operations, and related flows.
"""

import json
import logging
import time

from freetser import Request, Response, Storage
from freetser.server import StorageQueue

from apiserver.data.newuser import (
    EmailNotFoundInNewUserTable,
    list_new_users,
    update_accepted_flag,
)
from apiserver.data.permissions import (
    Permissions,
    UserNotFoundError,
    add_permission,
    allowed_permission,
    get_all_permissions,
    read_permissions,
    remove_permission,
)
from apiserver.data.registration_state import (
    RegistrationStateNotFound,
    get_email_send_count_by_email,
    get_registration_token_by_email,
    get_signup_token_by_email,
    mark_registration_state_accepted,
)
from apiserver.data.user import list_all_users
from apiserver.email import EmailData, sendemail
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
from apiserver.tooling.command_handlers import do_accept_new_with_email

logger = logging.getLogger("apiserver.handlers.admin")


def list_newusers_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_newusers/ - lists all pending user registrations."""

    def list_users(store: Storage) -> list:
        users = list_new_users(store)
        result = []
        for user in users:
            is_registered = store.get("users_by_email", user.email) is not None
            reg_token = get_registration_token_by_email(store, user.email)
            result.append(
                {
                    "email": user.email,
                    "firstname": user.firstname,
                    "lastname": user.lastname,
                    "accepted": user.accepted,
                    "email_send_count": get_email_send_count_by_email(
                        store, user.email
                    ),
                    "has_signup_token": get_signup_token_by_email(store, user.email)
                    is not None,
                    "is_registered": is_registered,
                    "registration_token": reg_token,
                }
            )
        return result

    result = store_queue.execute(list_users)
    logger.info(f"list_newusers: Returning {len(result)} users")
    return Response.json(result)


def accept_user_handler(
    req: Request,
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> Response:
    """Handle /admin/accept_user/ - accept a user and send notification email.

    If the user already completed signup (exists in users table), grants member
    permission and sends acceptance notification with homepage link.
    Otherwise marks accepted=True on the newuser entry and sends acceptance
    email with link to create their account.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        if not email:
            logger.warning("accept_user: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"accept_user: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    timestamp = int(time.time())

    def accept(store: Storage) -> dict:
        # Check if user already completed signup (exists in users table)
        user_result = store.get("users_by_email", email)
        if user_result is not None:
            # User already has an account — grant member + clean up newuser
            user_id = user_result[0].decode("utf-8")
            add_permission(store, timestamp, user_id, Permissions.MEMBER)
            store.delete("newusers", email)
            return {
                "success": True,
                "has_account": True,
                "message": f"Member permission granted to {email}",
            }

        # User hasn't completed signup yet — mark accepted in newusers and
        # registration_state. Set notify_on_completion so set_session sends
        # the deferred acceptance email after signup completes.
        flag_result = update_accepted_flag(store, email, True)
        if isinstance(flag_result, EmailNotFoundInNewUserTable):
            return {"error": f"Email {email} not found in newuser table"}

        reg_result = mark_registration_state_accepted(
            store, email, notify_on_completion=True
        )
        if isinstance(reg_result, RegistrationStateNotFound):
            return {"error": f"No registration state found for {email}"}

        reg_token = get_registration_token_by_email(store, email)

        # Get display name from newuser
        newuser_data = store.get("newusers", email)
        display_name = None
        if newuser_data is not None:
            data = json.loads(newuser_data[0].decode("utf-8"))
            display_name = data.get("firstname")

        return {
            "success": True,
            "has_account": False,
            "registration_token": reg_token,
            "display_name": display_name,
            "message": f"User {email} marked as accepted (pending signup completion)",
        }

    result = store_queue.execute(accept)
    if "error" in result:
        logger.warning(f"accept_user: {result['error']}")
        return Response.json(result, status_code=400)

    # Send acceptance email only if user already has an account.
    # If they haven't completed signup yet, the email is deferred to
    # set_session via the notify_on_completion flag (Scenario 1).
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
        except Exception as exc:
            logger.error(
                f"accept_user: Failed to send acceptance email to {email}: {exc}"
            )

    logger.info(f"accept_user: {result['message']}")
    return Response.json(result)


def add_user_permission(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/add_permission/ - adds a permission to a user (except admin)."""
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

    # Block adding admin permission through public API
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
    """Handle /admin/remove_permission/ - removes a permission from a user."""
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
    """Handle /admin/list_users/ - lists all users with their permissions."""
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
    """Handle /admin/available_permissions/ - lists all valid permissions."""
    permissions = get_all_permissions()
    return Response.json({"permissions": permissions})


def set_permissions_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/set_permissions/ - declaratively set permissions for users.

    Request body (JSON):
        {
            "permissions": {
                "user_id_1": ["permission1", "permission2"],
                "user_id_2": ["permission3"],
                ...
            }
        }

    This will set each user's permissions to exactly the list provided,
    adding missing permissions and removing extra ones (except 'admin').
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        permissions_map = body_data.get("permissions")
        if not permissions_map or not isinstance(permissions_map, dict):
            logger.warning("set_permissions: Missing or invalid permissions map")
            return Response.text("Missing permissions map", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"set_permissions: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Validate all permissions first
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

            # Get current permissions (excluding admin)
            current = read_permissions(store, timestamp, user_id)
            if isinstance(current, UserNotFoundError):
                results[user_id] = {"error": "user_not_found"}
                continue

            # Don't touch admin permission
            current_non_admin = current - {"admin"}
            target_non_admin = target_set - {"admin"}

            # Calculate changes
            to_add = target_non_admin - current_non_admin
            to_remove = current_non_admin - target_non_admin

            # Apply changes
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
    """Handle /admin/import_sync/ - import CSV content into sync table."""
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
    """Handle /admin/sync_status/ - compute and return sync groups."""
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
    """Handle /admin/accept_new_sync/ - accept new users and send acceptance emails."""
    email = None
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            email = body_data.get("email")
        except json.JSONDecodeError, ValueError:
            pass
    result = do_accept_new_with_email(
        store_queue, frontend_origin, smtp_config, smtp_send, email
    )
    return Response.json(result)


def remove_departed_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/remove_departed/ - remove departed users."""
    email = None
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            email = body_data.get("email")
        except json.JSONDecodeError, ValueError:
            pass
    timestamp = int(time.time())
    result = store_queue.execute(lambda store: remove_departed(store, timestamp, email))
    logger.info(f"remove_departed: {result}")
    return Response.json(result)


def update_existing_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/update_existing/ - update existing user data from sync."""
    email = None
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            email = body_data.get("email")
        except json.JSONDecodeError, ValueError:
            pass
    result = store_queue.execute(lambda store: update_existing(store, email))
    logger.info(f"update_existing: {result}")
    return Response.json(result)


def list_system_users_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_system_users/ - list system users."""
    users = store_queue.execute(list_system_users)
    return Response.json({"system_users": users})
