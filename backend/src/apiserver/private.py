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
    get_registration_state,
    get_registration_token_by_email,
    increment_email_send_count,
    update_registration_state_accepted,
)
from apiserver.sync import (
    SYSTEM_USERS_TABLE,
    accept_new,
    add_system_user,
    compute_groups,
    import_sync,
    list_system_users,
    parse_csv,
    remove_departed,
    remove_system_user,
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
                req, store_queue, command_handlers or {}, auth_client
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
        store_queue.execute(
            lambda store: add_token(store, email_type, to_email, code)
        )
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
                lambda store: increment_email_send_count(
                    store, to_email
                )
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


def cmdhandler_import_sync(
    store_queue: StorageQueue, csv_content: str
) -> Response:
    entries = parse_csv(csv_content)
    count = store_queue.execute(lambda store: import_sync(store, entries))
    logger.info(f"import_sync: Imported {count} entries")
    return Response.json({"imported": count})


def cmdhandler_compute_groups(store_queue: StorageQueue) -> Response:
    groups = store_queue.execute(compute_groups)
    logger.info(
        f"compute_groups: {len(groups.departed)} departed, "
        f"{len(groups.new)} new, {len(groups.existing)} existing"
    )
    return Response.json(serialize_groups(groups))


def cmdhandler_remove_departed(
    store_queue: StorageQueue, email: str | None
) -> Response:
    timestamp = int(time.time())
    result = store_queue.execute(
        lambda store: remove_departed(store, timestamp, email)
    )
    logger.info(f"remove_departed: {result}")
    return Response.json(result)


def cmdhandler_accept_new(store_queue: StorageQueue, email: str | None) -> Response:
    result = store_queue.execute(lambda store: accept_new(store, email))
    logger.info(f"accept_new: {result}")
    return Response.json(result)


def cmdhandler_accept_new_with_signup(
    store_queue: StorageQueue,
    auth_client: AuthClient | None,
    email: str | None,
) -> Response:
    """Accept new users AND initiate Faroe signup with email suppressed.

    Combines accept + find-needing-signup into one DB call,
    then parallelizes the Faroe create_signup HTTP calls.
    """
    if auth_client is None:
        return Response.text("Auth client not available", status_code=500)

    # Single DB call: accept new users + find who needs signup
    def accept_and_find(store: Storage) -> tuple[dict, list[str]]:
        result = accept_new(store, email)
        # Build set of emails that have signup_token in one pass
        has_token: set[str] = set()
        for key in store.list_keys("registration_state"):
            entry = store.get("registration_state", key)
            if entry is not None:
                data = json.loads(entry[0].decode("utf-8"))
                if data.get("signup_token") is not None:
                    has_token.add(data["email"])
        # Find accepted users without signup_token
        needing = [
            u.email for u in list_new_users(store)
            if u.accepted and u.email not in has_token
        ]
        return result, needing

    accept_result, emails_needing = store_queue.execute(accept_and_find)

    if not emails_needing:
        return Response.json({
            **accept_result,
            "signup_initiated": 0,
            "signup_failed": 0,
        })

    # Suppress all emails before starting parallel signups
    for e in emails_needing:
        suppress_email(e)

    # Parallel Faroe signup calls
    signup_tokens: dict[str, str] = {}
    failed_emails: list[str] = []

    def do_signup(user_email: str) -> tuple[str, str | None]:
        """Returns (email, signup_token) or (email, None) on failure."""
        try:
            result = auth_client.create_signup(user_email)
            if isinstance(result, ActionErrorResult):
                logger.error(
                    f"accept_new_with_signup: Faroe failed for "
                    f"{user_email}: {result.error_code}"
                )
                return user_email, None
            return user_email, result.signup_token
        except Exception as exc:
            logger.error(
                f"accept_new_with_signup: {user_email}: {exc}"
            )
            return user_email, None

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(do_signup, e): e
            for e in emails_needing
        }
        for future in as_completed(futures):
            user_email, token = future.result()
            if token is not None:
                signup_tokens[user_email] = token
            else:
                failed_emails.append(user_email)

    # Unsuppress all
    for e in emails_needing:
        unsuppress_email(e)

    # Single DB call: save all signup tokens
    if signup_tokens:
        def save_all(store: Storage) -> None:
            for e, t in signup_tokens.items():
                update_registration_state_accepted(store, e, t)

        store_queue.execute(save_all)

    result = {
        **accept_result,
        "signup_initiated": len(signup_tokens),
        "signup_failed": len(failed_emails),
    }
    if failed_emails:
        result["failed_emails"] = failed_emails

    logger.info(f"accept_new_with_signup: {result}")
    return Response.json(result)


def cmdhandler_update_existing(
    store_queue: StorageQueue, email: str | None
) -> Response:
    result = store_queue.execute(lambda store: update_existing(store, email))
    logger.info(f"update_existing: {result}")
    return Response.json(result)


def cmdhandler_initiate_signup(
    store_queue: StorageQueue, auth_client: AuthClient | None, email: str | None
) -> Response:
    """Create Faroe signup for an accepted user and send verification email.

    Calls auth_client.create_signup() OUTSIDE store_queue to avoid deadlock,
    then updates registration_state with the signup_token inside store_queue.
    """
    if not email:
        return Response.text("Missing email", status_code=400)
    if auth_client is None:
        return Response.text("Auth client not available", status_code=500)

    # Blocking HTTP call — must be outside store_queue.execute
    signup_result = auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        logger.error(f"initiate_signup: Faroe signup failed for {email}: "
                     f"{signup_result.error_code}")
        return Response.json(
            {"error": "Faroe signup failed", "error_code": signup_result.error_code},
            status_code=500,
        )

    signup_token = signup_result.signup_token

    def accept(store: Storage) -> str | None:
        result = update_accepted_flag(store, email, True)
        if isinstance(result, EmailNotFoundInNewUserTable):
            return f"Email {email} not found in newuser table"
        result = update_registration_state_accepted(store, email, signup_token)
        if result is not None:
            return f"No registration state found for {email}"
        return None

    error = store_queue.execute(accept)
    if error:
        logger.warning(f"initiate_signup: {error}")
        return Response.text(error, status_code=400)

    logger.info(f"initiate_signup: Signup initiated for {email}")
    return Response.json({"success": True, "email": email})


def cmdhandler_check_registration(
    store_queue: StorageQueue, email: str | None
) -> Response:
    if not email:
        return Response.text("Missing email", status_code=400)

    def check(store: Storage) -> dict:
        token = get_registration_token_by_email(store, email)
        if token is None:
            return {"found": False}
        state = get_registration_state(store, token)
        if state is None:
            return {"found": False}
        return {
            "found": True,
            "registration_token": state.registration_token,
            "accepted": state.accepted,
            "has_signup_token": state.signup_token is not None,
        }

    result = store_queue.execute(check)
    return Response.json(result)


def cmdhandler_mark_system_user(
    store_queue: StorageQueue, email: str | None
) -> Response:
    if not email:
        return Response.text("Missing email", status_code=400)
    marked = store_queue.execute(lambda store: add_system_user(store, email))
    logger.info(f"mark_system_user: {email} marked={marked}")
    return Response.json({"marked": marked})


def cmdhandler_unmark_system_user(
    store_queue: StorageQueue, email: str | None
) -> Response:
    if not email:
        return Response.text("Missing email", status_code=400)
    unmarked = store_queue.execute(lambda store: remove_system_user(store, email))
    logger.info(f"unmark_system_user: {email} unmarked={unmarked}")
    return Response.json({"unmarked": unmarked})


def cmdhandler_list_system_users(store_queue: StorageQueue) -> Response:
    emails = store_queue.execute(list_system_users)
    return Response.json({"system_users": emails})


def handle_command(
    req: Request,
    store_queue: StorageQueue,
    command_handlers: dict[str, Callable[[], str]],
    auth_client: AuthClient | None = None,
) -> Response:
    """Handle management command."""
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
        "accept_new_with_signup": lambda: cmdhandler_accept_new_with_signup(
            store_queue, auth_client, body.get("email")
        ),
        "update_existing": lambda: cmdhandler_update_existing(
            store_queue, body.get("email")
        ),
        "mark_system_user": lambda: cmdhandler_mark_system_user(
            store_queue, body.get("email")
        ),
        "unmark_system_user": lambda: cmdhandler_unmark_system_user(
            store_queue, body.get("email")
        ),
        "list_system_users": lambda: cmdhandler_list_system_users(store_queue),
        "check_registration": lambda: cmdhandler_check_registration(
            store_queue, body.get("email")
        ),
        "initiate_signup": lambda: cmdhandler_initiate_signup(
            store_queue, auth_client, body.get("email")
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
