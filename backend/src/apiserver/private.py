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
from typing import Any, Callable

from freetser import Request, Response, Storage, TcpServerConfig, start_server
from freetser.server import StorageQueue
from tiauth_faroe.user_server import handle_request_sync

from apiserver.settings import PRIVATE_HOST, SmtpConfig
from apiserver.email import EmailData, EmailType, TOKEN_EMAIL_TYPES, sendemail
from apiserver.tokens import TOKENS_TABLE, TokenWaiter, add_token, get_token

from apiserver.data.admin import AdminCredentials, get_admin_credentials
from apiserver.data.auth import SqliteSyncServer
from apiserver.data.newuser import (
    EmailExistsInNewUserTable,
    InvalidNamesCount,
    prepare_user_store,
)
from apiserver.data.registration_state import get_registration_token_by_email

logger = logging.getLogger("apiserver.private")

# Database tables that can be cleared
DB_TABLES = [
    "users",
    "users_by_email",
    "newusers",
    "registration_state",
    "metadata",
    "session_cache",
    TOKENS_TABLE,
]


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
            response = handle_command(req, store_queue, command_handlers or {})
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

        def lookup_registration_token(store: Storage) -> str | None:
            return get_registration_token_by_email(store, to_email)

        registration_token = store_queue.execute(lookup_registration_token)
        if registration_token and code:
            link = (
                f"{frontend_origin}/account/signup"
                f"?token={registration_token}&code={code}"
            )
            logger.info(f"Signup link for {to_email}: {link}")

    # Store token if this is a verification/reset email type
    if email_type in TOKEN_EMAIL_TYPES and code:
        def store_token(store: Storage) -> None:
            add_token(store, email_type, to_email, code)

        store_queue.execute(store_token)
        token_waiter.notify()
        logger.debug(f"Stored token: {email_type}:{to_email} code={code}")

    # Send email via SMTP or save to file
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
        return Response.json({"success": False, "error": str(e)}, status_code=500)

    return Response.json({"success": True})


def _handle_reset(
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


def _handle_prepare_user(
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


def _handle_get_admin_credentials(store_queue: StorageQueue) -> Response:
    """Handle the get_admin_credentials command."""

    def get_creds(store: Storage) -> AdminCredentials | None:
        return get_admin_credentials(store)

    credentials = store_queue.execute(get_creds)
    if credentials is None:
        logger.warning("get_admin_credentials: No admin credentials found")
        return Response.text("No admin credentials found", status_code=404)

    logger.info(f"get_admin_credentials: Returning credentials for {credentials.email}")
    return Response.json({"email": credentials.email, "password": credentials.password})


def _handle_get_token(
    store_queue: StorageQueue,
    action: str | None,
    email: str | None,
) -> Response:
    """Handle the get_token command - retrieve email verification code."""
    if not action or not email:
        logger.warning("get_token: Missing action or email")
        return Response.text("Missing action or email", status_code=400)

    def do_get(store: Storage) -> dict[str, Any] | None:
        return get_token(store, action, email)

    token = store_queue.execute(do_get)
    if token is None:
        logger.info(f"get_token: No token found for {action}:{email}")
        return Response.json({"found": False})

    logger.info(f"get_token: Retrieved token for {action}:{email}")
    return Response.json({"found": True, "code": token["code"]})


def handle_command(
    req: Request,
    store_queue: StorageQueue,
    command_handlers: dict[str, Callable[[], str]],
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

    if command == "reset":
        return _handle_reset(store_queue, command_handlers)

    if command == "prepare_user":
        email = body.get("email")
        names = body.get("names", [])
        return _handle_prepare_user(store_queue, email, names)

    if command == "get_admin_credentials":
        return _handle_get_admin_credentials(store_queue)

    if command == "get_token":
        action = body.get("action")
        email = body.get("email")
        return _handle_get_token(store_queue, action, email)

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
    store_queue: StorageQueue,
    token_waiter: TokenWaiter,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    command_handlers: dict[str, Callable[[], str]] | None = None,
) -> None:
    """Start the private TCP HTTP server in a background thread.

    Binds to PRIVATE_HOST (127.0.0.2) for isolation from the public server.
    """
    handler = create_private_handler(
        store_queue, token_waiter, frontend_origin, smtp_config, smtp_send,
        command_handlers
    )
    config = TcpServerConfig(host=PRIVATE_HOST, port=port)

    def run():
        logger.info(f"Private server listening on {PRIVATE_HOST}:{port}")
        start_server(config, handler, store_queue=store_queue)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
