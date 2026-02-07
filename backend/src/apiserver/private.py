"""Private HTTP server for local inter-process communication.

Binds to 127.0.0.2 (separate loopback address) for isolation.
Handles requests from Go tiauth-faroe and CLI.

Routes:
- POST /invoke - user action invocation (faroe UserServerClient)
- POST /email - email sending from tiauth-faroe (stores tokens, sends via SMTP)
- POST /command - management commands:
    - reset: clear all tables and re-bootstrap admin
    - prepare_user: create user ready for tiauth-faroe signup flow (testing)
    - get_admin_credentials: return bootstrapped admin email/password
    - get_token: retrieve email verification code (for test automation)
    - create_accounts: complete signup for all accepted newusers (testing)
"""

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from freetser import Request, Response, Storage, TcpServerConfig, start_server
from freetser.server import StorageQueue
from tiauth_faroe.client import ActionErrorResult
from tiauth_faroe.user_server import handle_request_sync

from apiserver.data.client import AuthClient
from apiserver.settings import PRIVATE_HOST, SmtpConfig
from apiserver.email import EmailData, EmailType, TOKEN_EMAIL_TYPES, sendemail
from apiserver.tokens import TOKENS_TABLE, TokenWaiter, add_token, get_token

from apiserver.data.admin import get_admin_credentials
from apiserver.data.auth import SqliteSyncServer
from apiserver.data.newuser import (
    EmailExistsInNewUserTable,
    EmailNotFoundInNewUserTable,
    InvalidNamesCount,
    list_new_users,
    prepare_user_store,
    update_accepted_flag,
)
from apiserver.data.registration_state import (
    create_registration_state,
    get_registration_state,
    get_registration_token_by_email,
    increment_email_send_count,
    mark_registration_state_accepted,
    update_registration_state_accepted,
)
from apiserver.data.permissions import add_permission
from apiserver.sync import (
    SYSTEM_USERS_TABLE,
    accept_new,
    add_system_user,
    compute_groups,
    import_sync,
    parse_csv,
    remove_departed,
    serialize_groups,
    update_existing,
)

logger = logging.getLogger("apiserver.private")

# Database tables that can be cleared
DB_TABLES = [
    "users",
    "users_by_email",
    "newusers",
    "registration_state",
    "metadata",
    "session_cache",
    "userdata",
    "sync",
    SYSTEM_USERS_TABLE,
    TOKENS_TABLE,
]

# Thread-safe email suppression for batch accept-new with signup.
# Emails in this set have their tokens stored but sendemail() skipped.
_suppressed_emails: set[str] = set()
_suppressed_emails_lock = threading.Lock()


def suppress_email(email: str) -> None:
    with _suppressed_emails_lock:
        _suppressed_emails.add(email.lower())


def unsuppress_email(email: str) -> None:
    with _suppressed_emails_lock:
        _suppressed_emails.discard(email.lower())


def is_email_suppressed(email: str) -> bool:
    with _suppressed_emails_lock:
        return email.lower() in _suppressed_emails


def add_cors_headers(response: Response, origin: str) -> Response:
    """Add CORS headers to a response."""
    response.headers.append((b"Access-Control-Allow-Origin", origin.encode("utf-8")))
    return response


def handle_options(path: str, origin: str) -> Response:
    """Handle OPTIONS preflight request for CORS."""
    valid_paths = {"/invoke", "/email", "/command"}
    if path not in valid_paths:
        return Response.text("Not Found", status_code=404)

    return Response(
        status_code=204,
        headers=[
            (b"Access-Control-Allow-Methods", b"POST, OPTIONS"),
            (b"Allow", b"POST, OPTIONS"),
            (b"Access-Control-Allow-Origin", origin.encode("utf-8")),
            (b"Access-Control-Allow-Headers", b"Content-Type"),
        ],
        body=b"",
    )


def create_private_handler(
    store_queue: StorageQueue,
    token_waiter: TokenWaiter,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    command_handlers: dict[str, Callable[[], str]] | None = None,
    auth_client: AuthClient | None = None,
) -> Any:
    """Create the handler for the private server."""

    def handler(req: Request, _: StorageQueue | None) -> Response:
        # Handle CORS preflight
        if req.method == "OPTIONS":
            return handle_options(req.path, frontend_origin)

        response: Response
        if req.method == "POST" and req.path == "/invoke":
            response = handle_invoke(req, store_queue)
        elif req.method == "POST" and req.path == "/email":
            response = handle_email(
                req, store_queue, token_waiter, smtp_config, smtp_send, frontend_origin
            )
        elif req.method == "POST" and req.path == "/command":
            response = handle_command(
                req,
                store_queue,
                command_handlers or {},
                auth_client,
                token_waiter,
                (frontend_origin, smtp_config, smtp_send),
            )
        else:
            return Response.text("Not Found", status_code=404)

        return add_cors_headers(response, frontend_origin)

    return handler


def handle_invoke(req: Request, store_queue: StorageQueue) -> Response:
    """Handle user action invocation from Go."""
    try:
        body = json.loads(req.body.decode("utf-8"))
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"invoke: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    def execute(store: Storage) -> str:
        server = SqliteSyncServer(store)
        result = handle_request_sync(body, server)
        if result.error is not None:
            logger.error(f"Action error: {result.error}")
        return result.response_json

    response_json = store_queue.execute(execute)
    return Response(
        status_code=200,
        headers=[(b"Content-Type", b"application/json")],
        body=response_json.encode("utf-8"),
    )


def handle_email(
    req: Request,
    store_queue: StorageQueue,
    token_waiter: TokenWaiter,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    frontend_origin: str,
) -> Response:
    """Handle email request from Go - stores tokens and sends email."""
    try:
        body = json.loads(req.body.decode("utf-8"))
        email_type: EmailType = body.get("type")
        to_email = body.get("email")
        if not email_type or not to_email:
            logger.warning("email: Missing type or email")
            return Response.text("Missing type or email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"email: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Extract optional fields
    display_name = body.get("displayName")
    code = body.get("code")
    timestamp = body.get("timestamp")
    new_email = body.get("newEmail")

    # Construct signup link using registration_token (exists from initial registration)
    # Include the verification code so the form is pre-filled
    link: str | None = None
    if email_type == "signup_verification":
        registration_token = store_queue.execute(
            lambda store: get_registration_token_by_email(store, to_email)
        )
        if registration_token and code:
            link = (
                f"{frontend_origin}/account/signup"
                f"?token={registration_token}&code={code}"
            )
            logger.info(f"Signup link for {to_email}: {link}")

    # Store token if this is a verification/reset email type
    if email_type in TOKEN_EMAIL_TYPES and code:
        store_queue.execute(lambda store: add_token(store, email_type, to_email, code))
        token_waiter.notify()
        logger.debug(f"Stored token: {email_type}:{to_email} code={code}")

    # Send email via SMTP or save to file (unless suppressed)
    if is_email_suppressed(to_email):
        logger.info(f"email: Suppressed for {to_email} (batch accept)")
    else:
        try:
            data = EmailData(
                email_type=email_type,
                to_email=to_email,
                display_name=display_name,
                code=code,
                timestamp=timestamp,
                new_email=new_email,
                link=link,
            )
            sendemail(smtp_config, data, smtp_send)
        except Exception as e:
            logger.error(f"email: Failed to process email: {e}")
            return Response.json(
                {"success": False, "error": str(e)},
                status_code=500,
            )
        if email_type == "signup_verification":
            store_queue.execute(
                lambda store: increment_email_send_count(store, to_email)
            )

    return Response.json({"success": True})


def cmdhandler_reset(
    store_queue: StorageQueue,
    command_handlers: dict[str, Callable[[], str]],
) -> Response:
    """Handle the reset command."""

    def clear_tables(store: Storage) -> None:
        for table in DB_TABLES:
            store.clear(table)

    store_queue.execute(clear_tables)
    logger.info("Tables cleared")

    if "reset" not in command_handlers:
        return Response.text("Tables cleared")

    try:
        result = command_handlers["reset"]()
        logger.info(f"Reset handler result: {result}")
        return Response.text(f"Tables cleared. {result}")
    except Exception as e:
        logger.error(f"Reset handler failed: {e}")
        return Response.text(f"Tables cleared but reset handler failed: {e}")


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


def cmdhandler_get_token(
    store_queue: StorageQueue,
    action: str | None,
    email: str | None,
) -> Response:
    """Handle the get_token command - retrieve email verification code."""
    if not action or not email:
        logger.warning("get_token: Missing action or email")
        return Response.text("Missing action or email", status_code=400)

    token = store_queue.execute(lambda store: get_token(store, action, email))
    if token is None:
        logger.info(f"get_token: No token found for {action}:{email}")
        return Response.json({"found": False})

    logger.info(f"get_token: Retrieved token for {action}:{email}")
    return Response.json({"found": True, "code": token["code"]})


def cmdhandler_import_sync(store_queue: StorageQueue, csv_content: str) -> Response:
    entries = parse_csv(csv_content)
    count = store_queue.execute(lambda store: import_sync(store, entries))
    logger.info(f"import_sync: Imported {count} entries")
    return Response.json({"imported": count})


def cmdhandler_compute_groups(store_queue: StorageQueue) -> Response:
    groups = store_queue.execute(compute_groups)
    logger.info(
        f"compute_groups: {len(groups.departed)} departed, "
        f"{len(groups.new)} new, {len(groups.pending)} pending, "
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


def do_accept_new_with_email(
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    email: str | None = None,
) -> dict:
    """Accept new users and send acceptance notification emails.

    No Faroe signup creation. Accepts users in newusers table, then sends
    acceptance emails to those not yet notified (registration_state.accepted
    still False). Users get a link to create their account.

    Returns result dict with added, skipped, emails_sent, emails_failed.
    """

    # Single DB call: accept new users + find who needs notification
    def accept_and_prepare(
        store: Storage,
    ) -> tuple[dict, list[tuple[str, str, str | None]]]:
        result = accept_new(store, email)

        # Find accepted users without accounts who haven't been notified yet
        registered = set(store.list_keys("users_by_email"))
        users = list_new_users(store)

        targets: list[tuple[str, str, str | None]] = []
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
            mark_registration_state_accepted(store, u.email)
            targets.append((u.email, u.firstname, reg_token))

        return result, targets

    accept_result, targets = store_queue.execute(accept_and_prepare)

    if not targets:
        return {**accept_result, "emails_sent": 0, "emails_failed": 0}

    # Send acceptance emails (outside store_queue to avoid deadlock)
    emails_sent = 0
    emails_failed = 0

    for user_email, display_name, reg_token in targets:
        try:
            link = f"{frontend_origin}/account/signup?token={reg_token}"
            data = EmailData(
                email_type="account_accepted",
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

    result = {
        **accept_result,
        "emails_sent": emails_sent,
        "emails_failed": emails_failed,
    }
    logger.info(f"accept_new_with_email: {result}")
    return result


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


BOARD_EMAIL = "bestuur@dsavdodeka.nl"


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
        if result is not None:
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
    token_waiter: TokenWaiter | None,
    password: str | None,
) -> Response:
    """Create accounts for all accepted newusers (testing).

    Runs the full signup flow for each: create_signup, verify email,
    set password, complete signup.  Emails are suppressed so no actual
    mail is sent.
    """
    if auth_client is None:
        return Response.text("Auth client not available", status_code=500)
    if token_waiter is None:
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
            # Clear stale verification token to avoid wait_for_token returning old code
            store_queue.execute(
                lambda store, e=email: store.delete(
                    TOKENS_TABLE, f"signup_verification:{e}"
                )
            )

            signup_result = auth_client.create_signup(email)
            if isinstance(signup_result, ActionErrorResult):
                return email, f"create_signup: {signup_result.error_code}"

            token = signup_result.signup_token

            code = token_waiter.wait_for_token("signup_verification", email)

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


def handle_command(
    req: Request,
    store_queue: StorageQueue,
    command_handlers: dict[str, Callable[[], str]],
    auth_client: AuthClient | None = None,
    token_waiter: TokenWaiter | None = None,
    email_settings: tuple[str, SmtpConfig | None, bool] = ("", None, False),
) -> Response:
    """Handle management command.

    email_settings is (frontend_origin, smtp_config, smtp_send).
    """
    frontend_origin, smtp_config, smtp_send = email_settings

    try:
        body = json.loads(req.body.decode("utf-8"))
        command = body.get("command")
        if not command:
            logger.warning("command: Missing command field")
            return Response.text("Missing command", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"command: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    logger.debug(f"command: Received {command}")

    dispatch: dict[str, Callable[[], Response]] = {
        "reset": lambda: cmdhandler_reset(store_queue, command_handlers),
        "prepare_user": lambda: cmdhandler_prepare_user(
            store_queue, body.get("email"), body.get("names", [])
        ),
        "get_admin_credentials": lambda: cmdhandler_get_admin_credentials(store_queue),
        "get_token": lambda: cmdhandler_get_token(
            store_queue, body.get("action"), body.get("email")
        ),
        "import_sync": lambda: cmdhandler_import_sync(
            store_queue, body.get("csv_content", "")
        ),
        "compute_groups": lambda: cmdhandler_compute_groups(store_queue),
        "remove_departed": lambda: cmdhandler_remove_departed(
            store_queue, body.get("email")
        ),
        "accept_new": lambda: cmdhandler_accept_new(store_queue, body.get("email")),
        "accept_new_with_signup": lambda: cmdhandler_accept_new_with_email(
            store_queue, frontend_origin, smtp_config, smtp_send, body.get("email")
        ),
        "update_existing": lambda: cmdhandler_update_existing(
            store_queue, body.get("email")
        ),
        "board_setup": lambda: cmdhandler_board_setup(store_queue, auth_client),
        "board_renew": lambda: cmdhandler_board_renew(store_queue, auth_client),
        "grant_admin": lambda: cmdhandler_grant_admin(store_queue, body.get("email")),
        "create_accounts": lambda: cmdhandler_create_accounts(
            store_queue, auth_client, token_waiter, body.get("password")
        ),
    }

    if command in dispatch:
        return dispatch[command]()

    if command in command_handlers:
        try:
            result = command_handlers[command]()
            return Response.text(result)
        except Exception as e:
            logger.error(f"command: Handler for '{command}' failed: {e}")
            return Response.text(f"Command failed: {e}", status_code=500)

    logger.warning(f"command: Unknown command '{command}'")
    return Response.text(f"Unknown command: {command}", status_code=400)


def start_private_server(
    port: int,
    handler: Any,
    store_queue: StorageQueue,
) -> None:
    """Start the private TCP HTTP server in a background thread.

    Binds to PRIVATE_HOST (127.0.0.2) for isolation from the public server.
    Use create_private_handler() to build the handler.
    """
    config = TcpServerConfig(host=PRIVATE_HOST, port=port)

    def run():
        logger.info(f"Private server listening on {PRIVATE_HOST}:{port}")
        start_server(config, handler, store_queue=store_queue)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
