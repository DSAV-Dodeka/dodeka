"""Private HTTP server for local inter-process communication.

Binds to 127.0.0.2 (separate loopback address) for isolation.
Handles requests from Go tiauth-faroe and CLI.

This module is a command/orchestration layer on top of the data modules
in apiserver.data and apiserver.sync.  It must not define fundamental
state such as table names or schema — those belong in the data layer.

Routes:
- POST /invoke - user action invocation (faroe UserServerClient)
- POST /email - email sending from tiauth-faroe (stores tokens, sends via SMTP)
- POST /command - management commands (dispatched to tooling.command_handlers)
"""

import json
import logging
import sys
import threading
from typing import Callable

from freetser import Request, Response, Storage, TcpServerConfig, start_server
from freetser.server import Handler, StorageQueue

from apiserver.data.auth import SqliteSyncServer
from apiserver.data.client import AuthClient
from apiserver.data.registration_state import (
    get_registration_token_by_email,
    increment_email_send_count,
)
from apiserver.email import TOKEN_EMAIL_TYPES, EmailData, EmailType, sendemail
from apiserver.settings import PRIVATE_HOST, SmtpConfig
from apiserver.tooling.command_handlers import (
    cmdhandler_accept_new,
    cmdhandler_accept_new_with_email,
    cmdhandler_accept_user,
    cmdhandler_board_renew,
    cmdhandler_board_setup,
    cmdhandler_compute_groups,
    cmdhandler_create_accounts,
    cmdhandler_get_admin_credentials,
    cmdhandler_get_code,
    cmdhandler_grant_admin,
    cmdhandler_import_sync,
    cmdhandler_list_birthdays,
    cmdhandler_prepare_user,
    cmdhandler_remove_departed,
    cmdhandler_reset,
    cmdhandler_update_existing,
    is_email_suppressed,
)
from apiserver.tooling.codes import CodeWaiter, add_code

from tiauth_faroe.user_server import handle_request_sync

logger = logging.getLogger("apiserver.private")


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
    code_waiter: CodeWaiter,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    auth_client: AuthClient | None = None,
) -> Handler:
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
                req, store_queue, code_waiter, smtp_config, smtp_send, frontend_origin
            )
        elif req.method == "POST" and req.path == "/command":
            response = handle_command(
                req,
                store_queue,
                auth_client,
                code_waiter,
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
    code_waiter: CodeWaiter,
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
        store_queue.execute(lambda store: add_code(store, email_type, to_email, code))
        code_waiter.notify()
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


def handle_command(
    req: Request,
    store_queue: StorageQueue,
    auth_client: AuthClient | None = None,
    code_waiter: CodeWaiter | None = None,
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
        "reset": lambda: cmdhandler_reset(store_queue, code_waiter, auth_client),
        "prepare_user": lambda: cmdhandler_prepare_user(
            store_queue, body.get("email"), body.get("names", [])
        ),
        "get_admin_credentials": lambda: cmdhandler_get_admin_credentials(store_queue),
        "get_token": lambda: cmdhandler_get_code(
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
        "accept_user": lambda: cmdhandler_accept_user(store_queue, body.get("email")),
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
            store_queue, auth_client, code_waiter, body.get("password")
        ),
        "list_birthdays": lambda: cmdhandler_list_birthdays(store_queue),
    }

    if command in dispatch:
        return dispatch[command]()

    logger.warning(f"command: Unknown command '{command}'")
    return Response.text(f"Unknown command: {command}", status_code=400)


def start_private_server(
    port: int,
    handler: Handler,
    store_queue: StorageQueue,
) -> None:
    """Start the private TCP HTTP server in a background thread.

    Binds to PRIVATE_HOST (127.0.0.2) for isolation from the public server.
    Use create_private_handler() to build the handler.
    """
    config = TcpServerConfig(host=PRIVATE_HOST, port=port)

    def run():
        if PRIVATE_HOST == "127.0.0.1" and sys.platform != "darwin":
            logger.warning(
                "Private server bound to 127.0.0.1 (shared loopback)."
                " Any local process can connect. Set BACKEND_PRIVATE_LOCALHOST"
                " only when 127.0.0.2 is unavailable (e.g. macOS)."
            )
        logger.info(f"Private server listening on {PRIVATE_HOST}:{port}")
        start_server(config, handler, store_queue=store_queue)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
