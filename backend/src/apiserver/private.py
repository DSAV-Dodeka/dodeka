"""Private HTTP server for local inter-process communication.

Binds to 127.0.0.2 (separate loopback address) for isolation.
Handles requests from Go tiauth-faroe and CLI.

Routes:
- POST /invoke - user action invocation (faroe UserServerClient)
- POST /email - email sending from tiauth-faroe (stores tokens, sends via SMTP)
- POST /command - management commands (dispatched to tooling.command_handlers)
"""

import json
import logging
import smtplib
import sys
import threading
from typing import Callable

from freetser import Request, Response, Storage, TcpServerConfig, start_server
from freetser.server import Handler, StorageQueue

from apiserver.data.auth import SqliteSyncServer
from apiserver.data.client import AuthClient
from apiserver.data.registrations import (
    get_registration_by_email,
    normalize_email,
    upsert_registration,
)
from apiserver.email import TOKEN_EMAIL_TYPES, EmailData, EmailType, sendemail
from apiserver.settings import PRIVATE_HOST, SmtpConfig
from apiserver.tooling.command_handlers import (
    cmdhandler_board_renew,
    cmdhandler_board_setup,
    cmdhandler_complete_sync,
    cmdhandler_compute_sync_status,
    cmdhandler_create_accounts,
    cmdhandler_get_admin_credentials,
    cmdhandler_get_code,
    cmdhandler_grant_admin,
    cmdhandler_import_sync,
    cmdhandler_link_bondsnummer,
    cmdhandler_list_birthdays,
    cmdhandler_list_outbox,
    cmdhandler_prepare_user,
    cmdhandler_reset,
    cmdhandler_resolve_sync_match,
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
    """Handle email request from Go — stores tokens and sends email."""
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

    to_email = normalize_email(to_email)

    display_name = body.get("displayName")
    code = body.get("code")
    timestamp = body.get("timestamp")
    new_email = body.get("newEmail")

    # Construct signup link using registration_id
    link: str | None = None
    if email_type == "signup_verification":

        def get_reg_id(store: Storage) -> str | None:
            reg = get_registration_by_email(store, to_email)
            if reg is not None:
                return reg.registration_id
            return None

        registration_id = store_queue.execute(get_reg_id)
        if registration_id and code:
            link = (
                f"{frontend_origin}/account/signup"
                f"?registration_id={registration_id}&code={code}"
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
        except (smtplib.SMTPException, OSError) as e:
            logger.error(f"email: Failed to process email: {e}")
            return Response.json(
                {"success": False, "error": str(e)},
                status_code=500,
            )
        if email_type == "signup_verification":

            def inc_send_count(store: Storage) -> None:
                reg = get_registration_by_email(store, to_email)
                if reg is not None:
                    reg.email_send_count += 1
                    upsert_registration(store, reg)

            store_queue.execute(inc_send_count)

    return Response.json({"success": True})


def handle_command(
    req: Request,
    store_queue: StorageQueue,
    auth_client: AuthClient | None = None,
    code_waiter: CodeWaiter | None = None,
    email_settings: tuple[str, SmtpConfig | None, bool] = ("", None, False),
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
        "reset": lambda: cmdhandler_reset(store_queue, code_waiter, auth_client),
        "prepare_user": lambda: cmdhandler_prepare_user(
            store_queue, body.get("email"), body.get("names", [])
        ),
        "get_admin_credentials": lambda: cmdhandler_get_admin_credentials(store_queue),
        "get_token": lambda: cmdhandler_get_code(
            store_queue,
            body.get("action"),
            body.get("email"),
            body.get("consume", True),
        ),
        "import_sync": lambda: cmdhandler_import_sync(
            store_queue, body.get("csv_content", "")
        ),
        "compute_groups": lambda: cmdhandler_compute_sync_status(store_queue),
        "resolve_sync_match": lambda: cmdhandler_resolve_sync_match(
            store_queue,
            body.get("bondsnummer"),
            body.get("kind"),
            body.get("subject_id"),
        ),
        "link_bondsnummer": lambda: cmdhandler_link_bondsnummer(
            store_queue,
            body.get("kind"),
            body.get("subject_id"),
            body.get("bondsnummer"),
        ),
        "complete_sync": lambda: cmdhandler_complete_sync(store_queue),
        "board_setup": lambda: cmdhandler_board_setup(store_queue, auth_client),
        "board_renew": lambda: cmdhandler_board_renew(store_queue, auth_client),
        "grant_admin": lambda: cmdhandler_grant_admin(store_queue, body.get("email")),
        "create_accounts": lambda: cmdhandler_create_accounts(
            store_queue, auth_client, code_waiter, body.get("password")
        ),
        "list_birthdays": lambda: cmdhandler_list_birthdays(store_queue),
        "list_outbox": lambda: cmdhandler_list_outbox(
            store_queue,
            body.get("kind"),
            body.get("subject_kind"),
            body.get("subject_id"),
            body.get("status"),
        ),
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
    """Start the private TCP HTTP server in a background thread."""
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
