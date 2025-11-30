import json
import logging
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Callable

from hfree import Request, Response, ServerConfig, Storage, setup_logging, start_server
from hfree.server import StorageQueue
from tiauth_faroe.client import ActionErrorResult
from tiauth_faroe.user_server import handle_request_sync

from apiserver.data.auth import SqliteSyncServer
from apiserver.data.client import AuthClient
from apiserver.data.newuser import prepare_user_store
from apiserver.data.permissions import add_permission, allowed_permission
from apiserver.data.user import InvalidSession, SessionInfo, get_session
from apiserver.settings import Settings, settings

logger = logging.getLogger("apiserver.app")


@dataclass
class RouteEntry:
    handler: Callable[[], Response]
    requires_credentials: bool = False


def handler_with_client(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue | None
) -> Response:
    if store_queue is None:
        return Response.text("Storage not available", status_code=500)

    path = req.path
    method = req.method

    def invoke_action():
        return invoke_user_action(req, store_queue)

    def clear():
        return clear_tables(store_queue)

    def prepare():
        return prepare_user(req, store_queue)

    def set_sess():
        return set_session(req)

    def clear_sess():
        return clear_session(req)

    def sess_info():
        return session_info(auth_client, req, store_queue)

    def add_perm():
        return add_user_permission(req, store_queue)

    route_table = {
        "/auth/invoke_user_action": {"POST": RouteEntry(invoke_action)},
        "/auth/clear_tables": {"POST": RouteEntry(clear)},
        "/auth/prepare_user": {"POST": RouteEntry(prepare)},
        "/auth/set_session/": {"POST": RouteEntry(set_sess, requires_credentials=True)},
        "/auth/clear_session/": {
            "POST": RouteEntry(clear_sess, requires_credentials=True)
        },
        "/auth/session_info/": {
            "GET": RouteEntry(sess_info, requires_credentials=True)
        },
        "/admin/add_permission/": {"POST": RouteEntry(add_perm)},
    }

    # Check if path exists
    route = route_table.get(path)
    if route is None:
        return Response.text(f"Not Found: {method} {path}", status_code=404)

    # Browsers generally only allow responses that have this set (this is a concept
    # called CORS)
    allow_origin_header = (
        b"Access-Control-Allow-Origin",
        settings.frontend_origin.encode("utf-8"),
    )

    # When sending JSON requests (or basically any non-simple request), browsers will
    # send "pre-flight requests (https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request)
    # This is a request using the 'OPTIONS' method, so we will need to deal with this
    if method == "OPTIONS":
        # Parse the Access-Control-Request-Method header to see which method is being
        # requested
        requested_method = None
        for header_name, header_value in req.headers:
            if header_name.lower() == b"access-control-request-method":
                requested_method = header_value.decode("utf-8")
                break

        # Check if the requested method requires credentials
        requires_credentials = False
        if requested_method:
            route_entry = route.get(requested_method)
            if route_entry:
                requires_credentials = route_entry.requires_credentials

        allowed_methods = ", ".join(sorted(route.keys()))
        headers = [
            # To tell the browser that the method it wants to use is indeed allowed
            # Technically, POST, GET and HEAD are always allowed in the context of
            # CORS, but to not complicate the code we just return the same as what
            # we actually support.
            (b"Access-Control-Allow-Methods", allowed_methods.encode("utf-8")),
            # The same, but in a more general context (not just preflight requests)
            (b"Allow", allowed_methods.encode("utf-8")),
            # We need to tell the frontend we allow requests from their origin
            allow_origin_header,
            # Since we will also receive JSON requests, we need to allow this as well
            (b"Access-Control-Allow-Headers", b"Content-Type"),
        ]
        # We need to tell the frontend they can add credentials (e.g. cookies)
        if requires_credentials:
            headers.append((b"Access-Control-Allow-Credentials", b"true"))

        return Response(
            status_code=204,
            headers=headers,
            body=b"",
        )

    # Check if method is allowed for this path
    route_entry = route.get(method)
    if route_entry is None:
        allowed_methods = ", ".join(sorted(route.keys()))
        return Response(
            status_code=405,
            headers=[(b"Allow", allowed_methods.encode("utf-8")), allow_origin_header],
            body=f"Method Not Allowed: {method} {path}.".encode("utf-8"),
        )

    response = route_entry.handler()
    # This one is basically always necessary for the browser to read it
    response.headers.append(allow_origin_header)
    # Add credentials header if this route requires it
    if route_entry.requires_credentials:
        response.headers.append((b"Access-Control-Allow-Credentials", b"true"))
    return response


def invoke_user_action(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /auth/invoke_user_action - executes user actions via SqliteSyncServer."""
    try:
        request_json = json.loads(req.body.decode("utf-8"))
    except json.JSONDecodeError:
        return Response.text("Invalid JSON", status_code=400)

    def execute_action(store: Storage) -> str:
        server = SqliteSyncServer(store)
        result = handle_request_sync(request_json, server)

        if result.error is not None:
            logger.error(f"Action error: {result.error}")

        logger.debug(f"Action response: {result.response_json}")
        return result.response_json

    response_json = store_queue.execute(execute_action)
    return Response(
        status_code=200,
        headers=[
            (b"Content-Type", b"application/json"),
            (b"Content-Length", str(len(response_json)).encode("ascii")),
        ],
        body=response_json.encode("utf-8"),
    )


def clear_tables(store_queue: StorageQueue) -> Response:
    """Handle /auth/clear_tables - clears user and newuser tables."""

    def clear(store: Storage) -> str:
        store.clear("users_by_email")
        store.clear("users")
        store.clear("newusers")
        store.clear("metadata")
        return "cleared!\n"

    result = store_queue.execute(clear)
    logger.info(result.strip())
    return Response.text(result)


def prepare_user(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /auth/prepare_user - prepares a user in the newuser store."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        names = body_data.get("names", [])
        if not email:
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    def prepare(store: Storage) -> str:
        prepare_user_store(store, email, names)
        return f"prepared {email}\n"

    result = store_queue.execute(prepare)
    logger.info(result.strip())
    return Response.text(result)


def set_session(req: Request) -> Response:
    """Handle /auth/set_session/ - sets session cookie."""
    # Get Origin header
    # TODO: should we really perform this check or is it up to browser?
    origin = None
    for header_name, header_value in req.headers:
        if header_name.lower() == b"origin":
            origin = header_value.decode("utf-8")
            break

    if origin != settings.frontend_origin:
        return Response.text("Invalid origin!", status_code=403)

    try:
        body_data = json.loads(req.body.decode("utf-8"))
        session_token = body_data.get("session_token")
        if not session_token:
            return Response.text("Missing session_token", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    max_session_age = 86400 * 365

    # Build Set-Cookie header using http.cookies
    cookie = SimpleCookie()
    cookie["session_token"] = session_token
    cookie["session_token"]["httponly"] = True
    cookie["session_token"]["samesite"] = "None"
    cookie["session_token"]["secure"] = True
    cookie["session_token"]["path"] = "/"
    cookie["session_token"]["max-age"] = max_session_age

    # SimpleCookie.output() returns "Set-Cookie: name=value; attrs"
    # We just need the value part after "Set-Cookie: "
    cookie_header = cookie["session_token"].OutputString()

    return Response.empty(
        headers=[
            (b"Set-Cookie", cookie_header.encode("utf-8")),
        ],
    )


def clear_session(req: Request) -> Response:
    """Handle /auth/clear_session/ - clears session cookie."""
    # Get Origin header
    origin = None
    for header_name, header_value in req.headers:
        if header_name.lower() == b"origin":
            origin = header_value.decode("utf-8")
            break

    if origin != settings.frontend_origin:
        return Response.text("Invalid origin!", status_code=403)

    # Build Set-Cookie header that clears the cookie (max-age=0)
    cookie = SimpleCookie()
    cookie["session_token"] = ""
    cookie["session_token"]["httponly"] = True
    cookie["session_token"]["samesite"] = "None"
    cookie["session_token"]["secure"] = True
    cookie["session_token"]["path"] = "/"
    cookie["session_token"]["max-age"] = 0

    cookie_header = cookie["session_token"].OutputString()

    return Response.empty(
        headers=[
            (b"Set-Cookie", cookie_header.encode("utf-8")),
        ],
    )


def session_info(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /auth/session_info/ - gets session information."""
    # Parse session_token from Cookie header using http.cookies
    session_token = None
    for header_name, header_value in req.headers:
        if header_name.lower() == b"cookie":
            cookie_str = header_value.decode("utf-8")
            cookie = SimpleCookie()
            cookie.load(cookie_str)
            if "session_token" in cookie:
                session_token = cookie["session_token"].value
            break

    if session_token is None:
        response_data = {"error": "no_session"}
        return Response.json(response_data)

    timestamp = int(time.time())

    # Do HTTP call before entering database thread to avoid deadlock
    session_result = auth_client.get_session(session_token)

    if isinstance(session_result, ActionErrorResult):
        if session_result.error_code != "invalid_session_token":
            invocation_id = session_result.action_invocation_id
            error_code = session_result.error_code
            raise ValueError(
                f"Error getting session from auth server "
                f"(invocation {invocation_id}): {error_code}."
            )
        response_data = {"error": "invalid_session"}
        return Response.json(response_data)

    def get_session_info(store: Storage) -> SessionInfo | InvalidSession:
        return get_session(store, session_result, timestamp)

    session = store_queue.execute(get_session_info)

    if isinstance(session, InvalidSession):
        response_data = {"error": "invalid_session"}
    else:
        response_data = {
            "user": {
                "user_id": session.user.user_id,
                "email": session.user.email,
                "firstname": session.user.firstname,
                "lastname": session.user.lastname,
                "permissions": list(session.user.permissions),
            },
            "created_at": session.created_at,
            "expires_at": session.expires_at,
        }

    response_body = json.dumps(response_data)
    return Response(
        status_code=200,
        headers=[
            (b"Content-Type", b"application/json"),
            (b"Content-Length", str(len(response_body)).encode("ascii")),
        ],
        body=response_body.encode("utf-8"),
    )


def add_user_permission(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/add_permission/ - adds a permission to a user."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        user_id = body_data.get("user_id")
        permission = body_data.get("permission")
        if not user_id or not permission:
            return Response.text("Missing user_id or permission", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    if not allowed_permission(permission):
        return Response.text(f"Invalid permission: {permission}", status_code=400)

    timestamp = int(time.time())

    def add_perm(store: Storage) -> str:
        add_permission(store, timestamp, user_id, permission)
        return f"Added permission {permission} to user {user_id}\n"

    result = store_queue.execute(add_perm)
    return Response.text(result)


def run_with_settings(settings: Settings):
    log_listener = setup_logging()
    log_listener.start()

    # Configure logging level based on debug_logs setting
    log_level = logging.DEBUG if settings.debug_logs else logging.INFO
    logging.getLogger().setLevel(log_level)

    logger.info(
        f"Running with settings:\n\t- frontend_origin={settings.frontend_origin}"
        f"\n\t- debug_logs={settings.debug_logs}"
    )

    auth_client = AuthClient(settings.auth_server_url)

    # hfree doesn't know about the client, so we create a new handler that captures it
    def handler(req: Request, store_queue: StorageQueue | None) -> Response:
        return handler_with_client(auth_client, req, store_queue)

    config = ServerConfig(
        db_file=str(settings.db_file),
        db_tables=["users", "users_by_email", "newusers", "metadata"],
    )
    try:
        start_server(config, handler)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        log_listener.stop()


def run():
    run_with_settings(settings)


if __name__ == "__main__":
    run()
