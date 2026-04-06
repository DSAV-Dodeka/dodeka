"""Command handler implementations for the private server.

Each ``cmdhandler_*`` function corresponds to a management command
dispatched by ``handle_command`` in ``apiserver.private``.
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
from apiserver.data.outbox import OUTBOX_TABLE, deserialize_outbox
from apiserver.data.permissions import add_permission
from apiserver.data.registrations import (
    create_or_reuse_registration,
    get_registration_by_email,
    list_registrations,
    normalize_email,
    upsert_registration,
)
from apiserver.data.features.birthdays import list_birthdays
from apiserver.sync import (
    CompleteSyncError,
    ImportValidationError,
    StaleCounter,
    add_system_user,
    complete_sync,
    compute_sync_status,
    get_sync_state,
    import_sync,
    link_bondsnummer,
    parse_csv,
    resolve_sync_match,
    serialize_sync_status,
)
from apiserver.tooling.actions import AdminUserCreationError, create_admin_user
from apiserver.tooling.codes import CODES_TABLE, CodeWaiter, get_code, peek_code

logger = logging.getLogger("apiserver.command_handlers")

# ---------------------------------------------------------------------------
# Email suppression (used by create_accounts to avoid sending real emails)
# ---------------------------------------------------------------------------

suppressed_emails: set[str] = set()
suppressed_emails_lock = threading.Lock()


def suppress_email(email: str) -> None:
    with suppressed_emails_lock:
        suppressed_emails.add(normalize_email(email))


def unsuppress_email(email: str) -> None:
    with suppressed_emails_lock:
        suppressed_emails.discard(normalize_email(email))


def is_email_suppressed(email: str) -> bool:
    with suppressed_emails_lock:
        return normalize_email(email) in suppressed_emails


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
    """Wait for server readiness, then bootstrap the admin user."""
    ready_event.wait()
    logger.info("Server ready, bootstrapping admin...")

    startup_client = AuthClient(auth_server_url, timeout=10, connect_retries=8)
    try:
        bootstrap_admin(code_waiter, startup_client, store_queue)
    except AdminUserCreationError as e:
        logger.error(f"Failed to bootstrap root admin: {e}")
    except Exception:
        logger.error("Failed to bootstrap admin, auth server may not be running")


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


MAX_NAMES = 2


def cmdhandler_prepare_user(
    store_queue: StorageQueue,
    email: str | None,
    names: list[str],
) -> Response:
    """Handle the prepare_user command — create an accepted registration."""
    if not email:
        return Response.text("Missing email for prepare_user", status_code=400)

    email = normalize_email(email)

    if len(names) > MAX_NAMES:
        return Response.text(f"Invalid names count: {len(names)}", status_code=400)
    elif len(names) == MAX_NAMES:
        firstname = names[0]
        lastname = names[1]
    elif len(names) == 1:
        firstname = names[0]
        lastname = ""
    else:
        email_prefix = email.split("@", maxsplit=1)[0]
        firstname = email_prefix
        lastname = ""

    def do_prepare(store: Storage) -> str | None:
        existing = get_registration_by_email(store, email)
        if existing is not None:
            return f"Registration already exists for {email}"
        create_or_reuse_registration(store, email, firstname, lastname, accepted=True)
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
    consume: bool = True,
) -> Response:
    """Handle the get_token command — retrieve confirmation code."""
    if not action or not email:
        logger.warning("get_token: Missing action or email")
        return Response.text("Missing action or email", status_code=400)

    getter = get_code if consume else peek_code
    result = store_queue.execute(lambda store: getter(store, action, email))
    if result is None:
        logger.info(f"get_token: No code found for {action}:{email}")
        return Response.json({"found": False})

    logger.info(f"get_token: Retrieved code for {action}:{email}")
    return Response.json({"found": True, "code": result["code"]})


def cmdhandler_import_sync(store_queue: StorageQueue, csv_content: str) -> Response:
    entries = parse_csv(csv_content)

    def do_import(store: Storage) -> int | ImportValidationError | StaleCounter:
        _, counter = get_sync_state(store)
        return import_sync(store, entries, sync_state_counter=counter)

    result = store_queue.execute(do_import)
    if isinstance(result, (ImportValidationError, StaleCounter)):
        logger.warning(f"import_sync: Failed: {result.message}")
        return Response.json({"error": result.message}, status_code=400)
    logger.info(f"import_sync: Imported {result} entries")
    return Response.json({"imported": result})


def cmdhandler_compute_sync_status(store_queue: StorageQueue) -> Response:
    status = store_queue.execute(compute_sync_status)
    result = serialize_sync_status(status)
    logger.info(
        f"compute_sync_status: {len(result['review_required'])} review_required, "
        f"{len(result['linked_registrations'])} linked_registrations, "
        f"{len(result['existing'])} existing, "
        f"{len(result['departed'])} departed"
    )
    return Response.json(result)


def cmdhandler_resolve_sync_match(
    store_queue: StorageQueue,
    bondsnummer: int | None,
    kind: str | None,
    subject_id: str | None,
) -> Response:
    if bondsnummer is None or kind is None:
        return Response.text("Missing bondsnummer or kind", status_code=400)
    result = store_queue.execute(
        lambda store: resolve_sync_match(store, int(bondsnummer), kind, subject_id)
    )
    if not result.success:
        return Response.json(
            {"success": False, "message": result.message}, status_code=400
        )
    return Response.json({"success": True, "message": result.message})


def cmdhandler_link_bondsnummer(
    store_queue: StorageQueue,
    kind: str | None,
    subject_id: str | None,
    bondsnummer: int | None,
) -> Response:
    if not kind or not subject_id or bondsnummer is None:
        return Response.text(
            "Missing kind, subject_id, or bondsnummer",
            status_code=400,
        )
    result = store_queue.execute(
        lambda store: link_bondsnummer(store, kind, subject_id, int(bondsnummer))
    )
    if not result.success:
        return Response.json(
            {"success": False, "message": result.message}, status_code=400
        )
    return Response.json({"success": True, "message": result.message})


def cmdhandler_complete_sync(store_queue: StorageQueue) -> Response:
    result = store_queue.execute(complete_sync)
    if isinstance(result, CompleteSyncError):
        return Response.json({"error": result.message}, status_code=400)
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


def cmdhandler_board_setup(
    store_queue: StorageQueue,
    auth_client: AuthClient | None,
) -> Response:
    """One-time setup for the Bestuur (board) account."""
    if auth_client is None:
        return Response.text("Auth client not available", status_code=500)

    email = BOARD_EMAIL

    def prepare(store: Storage) -> str | None:
        existing = get_registration_by_email(store, email)
        if existing is not None:
            return f"{email} already has a registration"
        create_or_reuse_registration(store, email, "Bestuur", "", accepted=True)
        add_system_user(store, email)
        return None

    error = store_queue.execute(prepare)
    if error:
        return Response.text(error, status_code=400)

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

    def save_signup(store: Storage) -> None:
        reg = get_registration_by_email(store, email)
        if reg is not None:
            reg.signup_token = signup_token
            upsert_registration(store, reg)

    store_queue.execute(save_signup)

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
    """Yearly renewal for the Bestuur account."""
    if auth_client is None:
        return Response.text("Auth client not available", status_code=500)

    email = BOARD_EMAIL

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
    """Create accounts for all accepted registrations (testing)."""
    if auth_client is None:
        return Response.text("Auth client not available", status_code=500)
    if code_waiter is None:
        return Response.text("Token waiter not available", status_code=500)
    if not password:
        return Response.text("Missing password", status_code=400)

    def find_pending(store: Storage) -> list[str]:
        registered = set(store.list_keys("users_by_email"))
        regs = list_registrations(store)
        return [r.email for r in regs if r.accepted and r.email not in registered]

    emails = store_queue.execute(find_pending)
    if not emails:
        return Response.json({"created": 0, "failed": 0, "message": "No pending users"})

    for e in emails:
        suppress_email(e)

    created = 0
    failures: list[dict[str, str]] = []

    def create_one(email: str) -> tuple[str, str | None]:
        try:
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
    """Grant admin permission and mark as system user."""
    if not email:
        return Response.text("Missing email", status_code=400)

    email = normalize_email(email)
    timestamp = int(time.time())

    def grant(store: Storage) -> dict:
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


def cmdhandler_list_birthdays(store_queue: StorageQueue) -> Response:
    """Return all birthday entries."""
    result = store_queue.execute(list_birthdays)
    return Response.json(result)


def cmdhandler_list_outbox(
    store_queue: StorageQueue,
    kind: str | None = None,
    subject_kind: str | None = None,
    subject_id: str | None = None,
    status: str | None = None,
) -> Response:
    """Return outbox rows for test/tooling inspection."""

    def list_rows(store: Storage) -> list[dict[str, Any]]:
        rows = []
        for key in store.list_keys(OUTBOX_TABLE):
            result = store.get(OUTBOX_TABLE, key)
            if result is None:
                continue
            row = deserialize_outbox(result[0])
            if kind is not None and row.kind != kind:
                continue
            if subject_kind is not None and row.subject_kind != subject_kind:
                continue
            if subject_id is not None and row.subject_id != subject_id:
                continue
            if status is not None and row.status != status:
                continue
            rows.append(
                {
                    "outbox_id": row.outbox_id,
                    "kind": row.kind,
                    "status": row.status,
                    "subject_kind": row.subject_kind,
                    "subject_id": row.subject_id,
                    "payload": row.payload,
                    "created_at": row.created_at,
                    "last_attempt_at": row.last_attempt_at,
                    "next_attempt_at": row.next_attempt_at,
                    "attempt_count": row.attempt_count,
                    "last_error": row.last_error,
                }
            )
        rows.sort(key=lambda row: (row["created_at"], row["outbox_id"]))
        return rows

    result = store_queue.execute(list_rows)
    return Response.json(result)
