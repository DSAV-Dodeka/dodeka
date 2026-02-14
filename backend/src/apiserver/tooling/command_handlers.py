"""Command handler implementations for the private server.

Each ``cmdhandler_*`` function corresponds to a management command
dispatched by ``handle_command`` in ``apiserver.private``.  Keeping them
here separates the tooling/admin logic from the core private-server
request handling (``/invoke``, ``/email``).
"""

import logging
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from freetser import Response, Storage
from freetser.server import StorageQueue
from tiauth_faroe.client import ActionErrorResult

from apiserver.data import DB_TABLES
from apiserver.data.admin import get_admin_credentials, store_admin_credentials
from apiserver.data.client import AuthClient
from apiserver.data.newuser import (
    EmailExistsInNewUserTable,
    EmailNotFoundInNewUserTable,
    InvalidNamesCount,
    list_new_users,
    prepare_user_store,
    update_accepted_flag,
)
from apiserver.data.permissions import Permissions, add_permission
from apiserver.data.registration_state import (
    RegistrationStateNotFound,
    create_registration_state,
    get_registration_state,
    get_registration_token_by_email,
    mark_registration_state_accepted,
    update_registration_state_accepted,
)
from apiserver.data.features.birthdays import list_birthdays
from apiserver.email import EmailData, sendemail
from apiserver.settings import SmtpConfig
from apiserver.sync import (
    accept_new,
    add_system_user,
    compute_groups,
    import_sync,
    parse_csv,
    remove_departed,
    serialize_groups,
    update_existing,
)
from apiserver.tooling.actions import AdminUserCreationError, create_admin_user
from apiserver.tooling.codes import CODES_TABLE, CodeWaiter, get_code

logger = logging.getLogger("apiserver.command_handlers")

# ---------------------------------------------------------------------------
# Email suppression (used by create_accounts to avoid sending real emails)
# ---------------------------------------------------------------------------

# Thread-safe email suppression for batch accept-new with signup.
# Emails in this set have their tokens stored but sendemail() skipped.
suppressed_emails: set[str] = set()
suppressed_emails_lock = threading.Lock()


def suppress_email(email: str) -> None:
    with suppressed_emails_lock:
        suppressed_emails.add(email.lower())


def unsuppress_email(email: str) -> None:
    with suppressed_emails_lock:
        suppressed_emails.discard(email.lower())


def is_email_suppressed(email: str) -> bool:
    with suppressed_emails_lock:
        return email.lower() in suppressed_emails


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

BOARD_EMAIL = "bestuur@dsavdodeka.nl"


def bootstrap_admin(
    code_waiter: CodeWaiter,
    auth_client: AuthClient,
    store_queue: StorageQueue,
) -> tuple[str, str]:
    """Bootstrap the root admin user."""
    root_email = "root_admin@localhost"
    root_password = secrets.token_urlsafe(32)

    user_id, session_token = create_admin_user(
        store_queue,
        auth_client,
        root_email,
        root_password,
        code_waiter,
        ["Root", "Admin"],
    )

    # Store credentials and mark as system user (excluded from sync)
    def save_credentials(store: Storage) -> None:
        store_admin_credentials(store, root_email, root_password)
        add_system_user(store, root_email)

    store_queue.execute(save_credentials)

    logger.info(f"Root admin bootstrapped: {root_email} (user_id={user_id})")
    logger.info(f"Root admin credentials: email={root_email}, password={root_password}")
    return user_id, session_token


def bootstrap_admin_on_startup(
    ready_event: threading.Event,
    code_waiter: CodeWaiter,
    auth_server_url: str,
    store_queue: StorageQueue,
) -> None:
    """Wait for server readiness, then bootstrap the admin user.

    Creates a separate AuthClient with connection retries to handle the Go auth
    server starting up concurrently (ECONNREFUSED until it's ready).
    """
    ready_event.wait()
    logger.info("Server ready, bootstrapping admin...")

    # The Go auth server may still be starting — use connect retries with backoff
    startup_client = AuthClient(auth_server_url, timeout=10, connect_retries=8)
    try:
        bootstrap_admin(code_waiter, startup_client, store_queue)
    except AdminUserCreationError as e:
        logger.error(f"Failed to bootstrap root admin: {e}")
    except Exception:
        logger.error("Failed to bootstrap admin, auth server may not be running")


# ---------------------------------------------------------------------------
# Accept new with email (used by both public API and CLI)
# ---------------------------------------------------------------------------


def do_accept_new_with_email(
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    email: str | None = None,
) -> dict:
    """Accept new users and send acceptance notification emails.

    Sends sync_please_register to users who still need to create an account,
    and account_accepted_self to users who already have one.

    Returns result dict with added, skipped, emails_sent, emails_failed.
    """

    # Single DB call: accept new users + find who needs notification
    def accept_and_prepare(
        store: Storage,
    ) -> tuple[
        dict,
        list[tuple[str, str, str | None]],
        list[tuple[str, str]],
    ]:
        registered = set(store.list_keys("users_by_email"))

        # accept_new deletes the newusers entry for users who already have
        # an account, so we won't be able to see them afterwards. Snapshot
        # them now so we can send acceptance emails after.
        pending_with_account: dict[str, str] = {}
        for u in list_new_users(store):
            if not u.accepted and u.email in registered:
                pending_with_account[u.email] = u.firstname

        result = accept_new(store, email)

        # Find accepted users without accounts who haven't been notified yet
        users = list_new_users(store)

        signup_targets: list[tuple[str, str, str | None]] = []
        for u in users:
            if not u.accepted or u.email in registered:
                continue

            # Check registration_state to avoid re-sending
            reg_token = get_registration_token_by_email(store, u.email)
            if reg_token is None:
                continue

            state = get_registration_state(store, reg_token)
            if state is not None and state.accepted:
                continue  # Already notified

            # Mark accepted in registration_state and collect for email
            mark_result = mark_registration_state_accepted(store, u.email)
            if isinstance(mark_result, RegistrationStateNotFound):
                logger.error(f"Registration state missing for {u.email}")
                continue
            signup_targets.append((u.email, u.firstname, reg_token))

        # Users who already had an account and were just accepted
        # (newusers entry removed by accept_new).
        accepted_targets: list[tuple[str, str]] = []
        for acc_email, firstname in pending_with_account.items():
            if store.get("newusers", acc_email) is None:
                accepted_targets.append((acc_email, firstname))

        return result, signup_targets, accepted_targets

    accept_result, signup_targets, accepted_targets = store_queue.execute(
        accept_and_prepare
    )

    emails_sent = 0
    emails_failed = 0

    for user_email, display_name, reg_token in signup_targets:
        try:
            link = f"{frontend_origin}/account/signup?token={reg_token}"
            data = EmailData(
                email_type="sync_please_register",
                to_email=user_email,
                display_name=display_name,
                link=link,
            )
            sendemail(smtp_config, data, smtp_send)
            emails_sent += 1
        except Exception as exc:
            logger.error(
                f"accept_new_with_email: Failed to send to {user_email}: {exc}"
            )
            emails_failed += 1

    for user_email, display_name in accepted_targets:
        try:
            data = EmailData(
                email_type="account_accepted_self",
                to_email=user_email,
                display_name=display_name,
                link=frontend_origin,
            )
            sendemail(smtp_config, data, smtp_send)
            emails_sent += 1
        except Exception as exc:
            logger.error(
                f"accept_new_with_email: Failed to send to {user_email}: {exc}"
            )
            emails_failed += 1

    result = {
        **accept_result,
        "emails_sent": emails_sent,
        "emails_failed": emails_failed,
    }
    logger.info(f"accept_new_with_email: {result}")
    return result


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def cmdhandler_reset(
    store_queue: StorageQueue,
    code_waiter: CodeWaiter | None,
    auth_client: AuthClient | None,
) -> Response:
    """Handle the reset command: clear all tables and re-bootstrap admin."""

    def clear_tables(store: Storage) -> None:
        for table in DB_TABLES:
            store.clear(table)

    store_queue.execute(clear_tables)
    logger.info("Tables cleared")

    if code_waiter is None or auth_client is None:
        return Response.text("Tables cleared")

    try:
        bootstrap_admin(code_waiter, auth_client, store_queue)
        logger.info("Admin re-bootstrapped after reset")
        return Response.text("Tables cleared. Admin re-bootstrapped")
    except AdminUserCreationError as e:
        logger.error(f"Failed to bootstrap root admin: {e}")
        return Response.text(f"Tables cleared but admin bootstrap failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error bootstrapping root admin: {e}")
        return Response.text(f"Tables cleared but admin bootstrap failed: {e}")


def cmdhandler_prepare_user(
    store_queue: StorageQueue,
    email: str | None,
    names: list[str],
) -> Response:
    """Handle the prepare_user command."""
    if not email:
        return Response.text("Missing email for prepare_user", status_code=400)

    def do_prepare(store: Storage) -> str | None:
        result = prepare_user_store(store, email, names)
        if isinstance(result, InvalidNamesCount):
            return f"Invalid names count: {result.names_count}"
        if isinstance(result, EmailExistsInNewUserTable):
            return f"Email already exists in newuser table: {result.email}"
        create_registration_state(store, email)
        return None

    error = store_queue.execute(do_prepare)
    if error:
        logger.warning(f"prepare_user failed: {error}")
        return Response.text(error, status_code=400)

    logger.info(f"Prepared user: email={email}, names={names}")
    return Response.text(f"User prepared: {email}")


def cmdhandler_get_admin_credentials(store_queue: StorageQueue) -> Response:
    """Handle the get_admin_credentials command."""
    credentials = store_queue.execute(get_admin_credentials)
    if credentials is None:
        logger.warning("get_admin_credentials: No admin credentials found")
        return Response.text("No admin credentials found", status_code=404)

    logger.info(f"get_admin_credentials: Returning credentials for {credentials.email}")
    return Response.json({"email": credentials.email, "password": credentials.password})


def cmdhandler_get_code(
    store_queue: StorageQueue,
    action: str | None,
    email: str | None,
) -> Response:
    """Handle the get_token command - retrieve confirmation code."""
    if not action or not email:
        logger.warning("get_token: Missing action or email")
        return Response.text("Missing action or email", status_code=400)

    result = store_queue.execute(lambda store: get_code(store, action, email))
    if result is None:
        logger.info(f"get_token: No code found for {action}:{email}")
        return Response.json({"found": False})

    logger.info(f"get_token: Retrieved code for {action}:{email}")
    return Response.json({"found": True, "code": result["code"]})


def cmdhandler_import_sync(store_queue: StorageQueue, csv_content: str) -> Response:
    entries = parse_csv(csv_content)
    count = store_queue.execute(lambda store: import_sync(store, entries))
    logger.info(f"import_sync: Imported {count} entries")
    return Response.json({"imported": count})


def cmdhandler_compute_groups(store_queue: StorageQueue) -> Response:
    groups = store_queue.execute(compute_groups)
    logger.info(
        f"compute_groups: {len(groups.departed)} departed, "
        f"{len(groups.to_accept)} to_accept, "
        f"{len(groups.pending_signup)} pending_signup, "
        f"{len(groups.existing)} existing"
    )
    return Response.json(serialize_groups(groups))


def cmdhandler_remove_departed(
    store_queue: StorageQueue, email: str | None
) -> Response:
    timestamp = int(time.time())
    result = store_queue.execute(lambda store: remove_departed(store, timestamp, email))
    logger.info(f"remove_departed: {result}")
    return Response.json(result)


def cmdhandler_accept_new(store_queue: StorageQueue, email: str | None) -> Response:
    result = store_queue.execute(lambda store: accept_new(store, email))
    logger.info(f"accept_new: {result}")
    return Response.json(result)


def cmdhandler_accept_new_with_email(
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    email: str | None,
) -> Response:
    """Command handler for accept_new with acceptance emails."""
    return Response.json(
        do_accept_new_with_email(
            store_queue, frontend_origin, smtp_config, smtp_send, email
        )
    )


def cmdhandler_update_existing(
    store_queue: StorageQueue, email: str | None
) -> Response:
    result = store_queue.execute(lambda store: update_existing(store, email))
    logger.info(f"update_existing: {result}")
    return Response.json(result)


def cmdhandler_board_setup(
    store_queue: StorageQueue,
    auth_client: AuthClient | None,
) -> Response:
    """One-time setup for the Bestuur (board) account.

    Prepares bestuur@dsavdodeka.nl as an accepted user, marks it as a
    system user (excluded from sync), and initiates Faroe signup which
    sends a verification email so the board can set their password.

    After signup completes, run grant-admin to give admin permission.
    """
    if auth_client is None:
        return Response.text("Auth client not available", status_code=500)

    email = BOARD_EMAIL
    names = ["Bestuur", ""]

    # Prepare user as accepted + mark as system user
    def prepare(store: Storage) -> str | None:
        result = prepare_user_store(store, email, names)
        if isinstance(result, EmailExistsInNewUserTable):
            return f"{email} already exists in newuser table"
        if isinstance(result, InvalidNamesCount):
            return f"Invalid names count: {result.names_count}"
        add_system_user(store, email)
        return None

    error = store_queue.execute(prepare)
    if error:
        return Response.text(error, status_code=400)

    # Initiate Faroe signup (blocking HTTP call — must be outside store_queue)
    signup_result = auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        logger.error(
            f"board_setup: Faroe signup failed for {email}: {signup_result.error_code}"
        )
        return Response.json(
            {"error": "Faroe signup failed", "error_code": signup_result.error_code},
            status_code=500,
        )

    signup_token = signup_result.signup_token

    def save_signup(store: Storage) -> str | None:
        result = update_accepted_flag(store, email, True)
        if isinstance(result, EmailNotFoundInNewUserTable):
            return f"Email {email} not found in newuser table"
        result = update_registration_state_accepted(store, email, signup_token)
        if isinstance(result, RegistrationStateNotFound):
            return f"No registration state found for {email}"
        return None

    error = store_queue.execute(save_signup)
    if error:
        logger.warning(f"board_setup: {error}")
        return Response.text(error, status_code=400)

    logger.info(f"board_setup: Created Bestuur account, signup email sent to {email}")
    return Response.json(
        {
            "success": True,
            "email": email,
            "message": "Signup email sent. After signup completes, run grant-admin.",
        }
    )


def cmdhandler_board_renew(
    store_queue: StorageQueue,
    auth_client: AuthClient | None,
) -> Response:
    """Yearly renewal for the Bestuur account.

    Triggers a password reset (sends temporary password email) and
    renews the admin permission (1-year TTL).  Run this when the board
    rotates so the new board can set their own password.
    """
    if auth_client is None:
        return Response.text("Auth client not available", status_code=500)

    email = BOARD_EMAIL

    # Initiate password reset via Faroe (sends temp password email).
    # Blocking HTTP call — must be outside store_queue.
    reset_result = auth_client.manage_action_invocation_request(
        "create_user_password_reset", {"user_email_address": email}
    )
    if isinstance(reset_result, ActionErrorResult):
        logger.error(
            f"board_renew: Password reset failed for {email}: {reset_result.error_code}"
        )
        return Response.json(
            {
                "error": "Password reset failed",
                "error_code": reset_result.error_code,
            },
            status_code=500,
        )

    # Renew admin permission (1-year TTL)
    timestamp = int(time.time())

    def renew(store: Storage) -> dict:
        result = store.get("users_by_email", email)
        if result is None:
            return {"error": f"No user found with email {email}"}
        user_id = result[0].decode("utf-8")

        perm_result = add_permission(store, timestamp, user_id, "admin")
        if perm_result is not None:
            return {"error": f"Failed to renew admin permission: {perm_result}"}

        return {"user_id": user_id}

    result = store_queue.execute(renew)
    if "error" in result:
        logger.warning(f"board_renew: {result['error']}")
        return Response.json(result, status_code=400)

    logger.info(
        f"board_renew: Password reset email sent and admin renewed for {email} "
        f"(user_id={result['user_id']})"
    )
    return Response.json(
        {
            "success": True,
            "email": email,
            "message": "Password reset email sent and admin permission renewed.",
        }
    )


def cmdhandler_create_accounts(
    store_queue: StorageQueue,
    auth_client: AuthClient | None,
    code_waiter: CodeWaiter | None,
    password: str | None,
) -> Response:
    """Create accounts for all accepted newusers (testing).

    Runs the full signup flow for each: create_signup, verify email,
    set password, complete signup.  Emails are suppressed so no actual
    mail is sent.
    """
    if auth_client is None:
        return Response.text("Auth client not available", status_code=500)
    if code_waiter is None:
        return Response.text("Token waiter not available", status_code=500)
    if not password:
        return Response.text("Missing password", status_code=400)

    # Find accepted newusers that aren't registered yet
    def find_pending(store: Storage) -> list[str]:
        registered = set(store.list_keys("users_by_email"))
        users = list_new_users(store)
        return [u.email for u in users if u.accepted and u.email not in registered]

    emails = store_queue.execute(find_pending)
    if not emails:
        return Response.json({"created": 0, "failed": 0, "message": "No pending users"})

    for e in emails:
        suppress_email(e)

    created = 0
    failures: list[dict[str, str]] = []

    def create_one(email: str) -> tuple[str, str | None]:
        try:
            # Clear stale verification token to avoid wait_for_code returning old code
            store_queue.execute(
                lambda store, e=email: store.delete(
                    CODES_TABLE, f"signup_verification:{e}"
                )
            )

            signup_result = auth_client.create_signup(email)
            if isinstance(signup_result, ActionErrorResult):
                return email, f"create_signup: {signup_result.error_code}"

            token = signup_result.signup_token

            code = code_waiter.wait_for_code("signup_verification", email)

            verify = auth_client.verify_signup_email_address_verification_code(
                token, code
            )
            if isinstance(verify, ActionErrorResult):
                return email, f"verify: {verify.error_code}"

            pwd = auth_client.set_signup_password(token, password)
            if isinstance(pwd, ActionErrorResult):
                return email, f"set_password: {pwd.error_code}"

            complete = auth_client.complete_signup(token)
            if isinstance(complete, ActionErrorResult):
                return email, f"complete: {complete.error_code}"

            return email, None
        except Exception as exc:
            return email, str(exc)

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(create_one, e): e for e in emails}
        for future in as_completed(futures):
            email, error = future.result()
            if error is None:
                created += 1
            else:
                failures.append({"email": email, "error": error})

    for e in emails:
        unsuppress_email(e)

    result: dict[str, Any] = {"created": created, "failed": len(failures)}
    if failures:
        result["failures"] = failures

    logger.info(f"create_accounts: {created} created, {len(failures)} failed")
    return Response.json(result)


def cmdhandler_grant_admin(store_queue: StorageQueue, email: str | None) -> Response:
    """Grant admin permission and mark as system user.

    The user must have completed signup (have a user_id) before admin
    permission can be granted.
    """
    if not email:
        return Response.text("Missing email", status_code=400)

    timestamp = int(time.time())

    def grant(store: Storage) -> dict:
        # Look up user_id by email
        result = store.get("users_by_email", email)
        if result is None:
            return {"error": f"No user found with email {email}"}
        user_id = result[0].decode("utf-8")

        perm_result = add_permission(store, timestamp, user_id, "admin")
        if perm_result is not None:
            return {"error": f"Failed to add admin permission: {perm_result}"}

        add_system_user(store, email)
        return {"success": True, "user_id": user_id, "email": email}

    result = store_queue.execute(grant)
    if "error" in result:
        logger.warning(f"grant_admin: {result['error']}")
        return Response.json(result, status_code=400)

    logger.info(f"grant_admin: Granted admin to {email} (user_id={result['user_id']})")
    return Response.json(result)


def cmdhandler_accept_user(store_queue: StorageQueue, email: str | None) -> Response:
    """Accept a user without HTTP request parsing (for test automation).

    Same logic as accept_user_handler() in app.py:
    - If user already has account: grant member permission, delete from newusers
    - If not: mark accepted=True in newusers + registration_state
    No email sending.
    """
    if not email:
        return Response.text("Missing email for accept_user", status_code=400)

    timestamp = int(time.time())

    def accept(store: Storage) -> dict:
        user_result = store.get("users_by_email", email)
        if user_result is not None:
            user_id = user_result[0].decode("utf-8")
            add_permission(store, timestamp, user_id, Permissions.MEMBER)
            store.delete("newusers", email)
            return {
                "success": True,
                "has_account": True,
                "message": f"Member permission granted to {email}",
            }

        flag_result = update_accepted_flag(store, email, True)
        if isinstance(flag_result, EmailNotFoundInNewUserTable):
            return {"error": f"Email {email} not found in newuser table"}

        mark_result = mark_registration_state_accepted(
            store, email, notify_on_completion=True
        )
        if isinstance(mark_result, RegistrationStateNotFound):
            return {"error": f"No registration state found for {email}"}

        return {
            "success": True,
            "has_account": False,
            "message": f"User {email} marked as accepted",
        }

    result = store_queue.execute(accept)
    if "error" in result:
        logger.warning(f"accept_user: {result['error']}")
        return Response.json(result, status_code=400)

    logger.info(f"accept_user: {result['message']}")
    return Response.json(result)


def cmdhandler_list_birthdays(store_queue: StorageQueue) -> Response:
    """Return all birthday entries."""
    result = store_queue.execute(list_birthdays)
    return Response.json(result)
