"""Private HTTP server over Unix domain socket.

Handles requests from Go tiauth-faroe:
- POST /invoke - user action invocation (faroe UserServerClient)
- POST /token - token notifications (for testing with --no-smtp)
- POST /command - server management commands (reset, etc.)
"""

import json
import logging
import threading
from typing import Any, Callable

from freetser import Request, Response, Storage, UnixServerConfig, start_server
from freetser.server import StorageQueue
from tiauth_faroe.user_server import handle_request_sync

from apiserver.data.admin import AdminCredentials, get_admin_credentials
from apiserver.data.auth import SqliteSyncServer
from apiserver.data.newuser import (
    EmailExistsInNewUserTable,
    InvalidNamesCount,
    prepare_user_store,
)

logger = logging.getLogger("apiserver.private")

# Token table name
TOKENS_TABLE = "tokens"

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


def add_token(store: Storage, action: str, email: str, code: str) -> None:
    """Store a token notification in the database."""
    key = f"{action}:{email}"
    value = json.dumps({"action": action, "email": email, "code": code}).encode("utf-8")
    # Delete any existing token first, then add new one
    store.delete(TOKENS_TABLE, key)
    store.add(TOKENS_TABLE, key, value)


def get_token(store: Storage, action: str, email: str) -> dict[str, Any] | None:
    """Get and remove a token from the database."""
    key = f"{action}:{email}"
    result = store.get(TOKENS_TABLE, key)
    if result is None:
        return None
    value_bytes, _ = result
    store.delete(TOKENS_TABLE, key)
    return json.loads(value_bytes.decode("utf-8"))


class TokenWaiter:
    """Waits for tokens to appear in the database."""

    def __init__(self, store_queue: StorageQueue):
        self.store_queue = store_queue
        self.condition = threading.Condition()

    def notify(self) -> None:
        """Notify waiters that a new token may be available."""
        with self.condition:
            self.condition.notify_all()

    def wait_for_token(self, action: str, email: str, timeout: float = 30.0) -> str:
        """Wait for a token and return the code."""
        with self.condition:
            while True:
                # Check database
                def check(store: Storage) -> dict[str, Any] | None:
                    return get_token(store, action, email)

                token = self.store_queue.execute(check)
                if token is not None:
                    return token["code"]

                # Wait for notification or timeout
                if not self.condition.wait(timeout=1.0):
                    timeout -= 1.0
                    if timeout <= 0:
                        raise TimeoutError(
                            f"Timeout waiting for {action} token for {email}"
                        )


def create_private_handler(
    store_queue: StorageQueue,
    token_waiter: TokenWaiter,
    command_handlers: dict[str, Callable[[], str]] | None = None,
) -> Any:
    """Create the handler for the private UDS server."""

    def handler(req: Request, _: StorageQueue | None) -> Response:
        if req.method == "POST" and req.path == "/invoke":
            return handle_invoke(req, store_queue)
        elif req.method == "POST" and req.path == "/token":
            return handle_token(req, store_queue, token_waiter)
        elif req.method == "POST" and req.path == "/command":
            return handle_command(req, store_queue, command_handlers or {})
        else:
            return Response.text("Not Found", status_code=404)

    return handler


def handle_invoke(req: Request, store_queue: StorageQueue) -> Response:
    """Handle user action invocation from Go."""
    try:
        body = json.loads(req.body.decode("utf-8"))
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Invalid invoke request: {e}")
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


def handle_token(
    req: Request,
    store_queue: StorageQueue,
    token_waiter: TokenWaiter,
) -> Response:
    """Handle token notification from Go."""
    try:
        body = json.loads(req.body.decode("utf-8"))
        action = body.get("action")
        email = body.get("email")
        code = body.get("code")
        if not all([action, email, code]):
            return Response.text("Missing action, email, or code", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Invalid token request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Store token in database
    def store_token(store: Storage) -> None:
        add_token(store, action, email, code)

    store_queue.execute(store_token)

    # Notify waiters
    token_waiter.notify()

    logger.debug(f"Stored token: action={action}, email={email}, code={code}")
    return Response.text("OK")


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
            return Response.text("Missing command", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Invalid command request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    logger.info(f"Received command: {command}")

    if command == "reset":
        return _handle_reset(store_queue, command_handlers)

    if command == "prepare_user":
        email = body.get("email")
        names = body.get("names", [])
        return _handle_prepare_user(store_queue, email, names)

    if command == "get_admin_credentials":
        return _handle_get_admin_credentials(store_queue)

    if command in command_handlers:
        try:
            result = command_handlers[command]()
            return Response.text(result)
        except Exception as e:
            logger.error(f"Command handler failed: {e}")
            return Response.text(f"Command failed: {e}", status_code=500)

    return Response.text(f"Unknown command: {command}", status_code=400)


def start_private_server(
    socket_path: str,
    store_queue: StorageQueue,
    token_waiter: TokenWaiter,
    command_handlers: dict[str, Callable[[], str]] | None = None,
) -> None:
    """Start the private UDS HTTP server in a background thread."""
    handler = create_private_handler(store_queue, token_waiter, command_handlers)
    config = UnixServerConfig(path=socket_path)

    def run():
        logger.info(f"Private server listening on {socket_path}")
        start_server(config, handler, store_queue=store_queue)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
