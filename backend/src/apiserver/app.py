import enum
import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import Callable

from hfree import Request, Response, ServerConfig, Storage, setup_logging, start_server
from hfree.server import StorageQueue
from tiauth_faroe.client import ActionErrorResult
from tiauth_faroe.user_server import handle_request_sync

from apiserver.data.auth import SqliteSyncServer
from apiserver.data.client import AuthClient
from apiserver.data.newuser import (
    EmailExistsInNewUserTable,
    EmailExistsInUserTable,
    EmailNotFoundInNewUserTable,
    InvalidNamesCount,
    add_new_user,
    list_new_users,
    prepare_user_store,
    update_accepted_flag,
)
from apiserver.data.permissions import (
    UserNotFoundError,
    add_permission,
    allowed_permission,
)
from apiserver.data.registration_state import (
    RegistrationStateNotFoundForEmail,
    create_registration_state,
    get_registration_state,
    update_registration_state_accepted,
)
from apiserver.data.user import InvalidSession, SessionInfo, get_session
from apiserver.settings import Settings, settings

logger = logging.getLogger("apiserver.app")


class Visibility(enum.Enum):
    PRIVATE = enum.auto()
    ADMIN_ONLY = enum.auto()
    PUBLIC = enum.auto()


@dataclass
class RouteEntry:
    """
    Stores the handler of a particular route and some other configuration.
    """

    handler: Callable[[], Response]
    # If yes, then we add special headers so that browsers are able to send things
    # like cookies along
    requires_credentials: bool = False
    visibility: Visibility = Visibility.PRIVATE


def check_route_access(
    path: str,
    method: str,
    route_entry: RouteEntry,
    headers: dict[str, str],
    private_key: str,
    admin_key: str,
) -> Response | None:
    """Check private and admin route access, return error response or None if OK."""
    # Check private route access
    is_private = route_entry.visibility == Visibility.PRIVATE or path.startswith(
        "/private"
    )
    req_private_key = headers.get("x-private-route-access-key")
    if is_private and req_private_key != private_key:
        return Response.text(f"Not Found: {method} {path}", status_code=404)

    # Check admin route access
    is_admin = route_entry.visibility == Visibility.ADMIN_ONLY or path.startswith(
        "/admin"
    )
    req_admin_key = headers.get("x-admin-key")
    if is_admin and req_admin_key != admin_key:
        return Response.text(f"Unauthorized: {method} {path}", status_code=401)

    return None


def handle_options_request(
    route: dict[str, RouteEntry],
    route_entry: RouteEntry,
    frontend_origin: str,
) -> Response:
    """Handle OPTIONS preflight requests for CORS."""
    allowed_methods = ", ".join(sorted(route.keys()))
    res_headers = [
        (b"Access-Control-Allow-Methods", allowed_methods.encode("utf-8")),
        (b"Allow", allowed_methods.encode("utf-8")),
        (b"Access-Control-Allow-Origin", frontend_origin.encode("utf-8")),
        (b"Access-Control-Allow-Headers", b"Content-Type"),
    ]
    if route_entry.requires_credentials:
        res_headers.append((b"Access-Control-Allow-Credentials", b"true"))

    return Response(status_code=204, headers=res_headers, body=b"")


def handler_with_client(
    auth_client: AuthClient,
    admin_key: str,
    private_route_access_key: str,
    req: Request,
    store_queue: StorageQueue | None,
) -> Response:
    """
    This function dispatches a request to a specific handler, based on the route. It
    also handles things like CORS (browsers are careful when making requests that are
    not the same 'origin', so different domain)
    """
    if store_queue is None:
        return Response.text("Storage not available", status_code=500)

    path = req.path
    method = req.method

    def h_invoke_action():
        return invoke_user_action(req, store_queue)

    def h_clear():
        return clear_tables(store_queue)

    def h_prepare():
        return prepare_user(req, store_queue)

    def h_request_registration():
        return request_registration(req, store_queue)

    def h_set_sess():
        return set_session(req)

    def h_clear_sess():
        return clear_session(req)

    def h_sess_info():
        return session_info(auth_client, req, store_queue)

    def h_add_perm():
        return add_user_permission(req, store_queue)

    def h_list_newusers():
        return list_newusers_handler(store_queue)

    def h_accept_user():
        return accept_user_handler(auth_client, req, store_queue)

    def h_get_reg_status():
        return get_registration_status_handler(req, store_queue)

    def h_get_sess_token():
        return get_session_token_handler(req)

    # This table maps each route to a specific handler (the RouteEntry)
    route_table = {
        # Private endpoint, only accessible to the Go auth server
        "/private/invoke_user_action": {"POST": RouteEntry(h_invoke_action)},
        # Test endpoints used for the test suite and development
        "/test/prepare_user": {"POST": RouteEntry(h_prepare)},
        "/test/clear_tables": {"POST": RouteEntry(h_clear)},
        # Dodeka-specific actions related to auth
        "/auth/request_registration": {"POST": RouteEntry(h_request_registration)},
        "/auth/registration_status": {"POST": RouteEntry(h_get_reg_status)},
        # We prefix the next with 'admin' to make it clear it's only accessible to
        # admins
        "/admin/accept_user/": {"POST": RouteEntry(h_accept_user)},
        # Admin-only functions
        "/admin/add_permission/": {"POST": RouteEntry(h_add_perm)},
        "/admin/list_newusers/": {"GET": RouteEntry(h_list_newusers)},
        "/auth/session_info/": {
            "GET": RouteEntry(h_sess_info, requires_credentials=True)
        },
        # Since we have HttpOnly cookies, we need server functions to modify them
        "/cookies/session_token/": {
            "GET": RouteEntry(h_get_sess_token, requires_credentials=True)
        },
        "/cookies/set_session/": {
            "POST": RouteEntry(h_set_sess, requires_credentials=True)
        },
        "/cookies/clear_session/": {
            "POST": RouteEntry(h_clear_sess, requires_credentials=True)
        },
    }

    route = route_table.get(path)
    if route is None:
        return Response.text(f"Not Found: {method} {path}", status_code=404)

    # We only use the last header with the same lower-case name, we don't care about any
    # weird practices
    headers: dict[str, str] = {}
    try:
        for header_name, header_value in req.headers:
            headers[header_name.lower().decode("utf-8")] = header_value.decode("utf-8")
    except ValueError:
        # In case there is non-utf-8
        return Response.text("Bad Request: Invalid Header", status_code=400)

    # In order to get a useful method when the method is OPTIONS is sent for many other
    # methods in a so-called pre-flight request during CORS), we get this special header
    if method == "OPTIONS":
        requested_method = headers.get("access-control-request-method")
    else:
        requested_method = method

    # We can now get a route_entry, or just set it to none and then return not found
    route_entry = None if requested_method is None else route.get(requested_method)
    if route_entry is None:
        return Response.text(f"Not Found: {method} {path}", status_code=404)

    # Check private and admin route access
    if error := check_route_access(
        path, method, route_entry, headers, private_route_access_key, admin_key
    ):
        return error

    # Handle OPTIONS preflight requests for CORS
    if method == "OPTIONS":
        return handle_options_request(route, route_entry, settings.frontend_origin)

    # Browsers generally only allow responses that have this set (CORS)
    allow_origin_header = (
        b"Access-Control-Allow-Origin",
        settings.frontend_origin.encode("utf-8"),
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
    """
    Handle /auth/clear_tables.

    Clears user, newuser, and registration_state tables.
    """

    def clear(store: Storage) -> str:
        store.clear("users_by_email")
        store.clear("users")
        store.clear("newusers")
        store.clear("registration_state")
        store.clear("metadata")
        return "cleared!\n"

    result = store_queue.execute(clear)
    logger.info(result.strip())
    return Response.text(result)


def prepare_user(req: Request, store_queue: StorageQueue) -> Response:
    """
    Handle /test/prepare_user.

    Prepares a user in the newuser store with accepted=True (for testing).
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        names = body_data.get("names", [])
        if not email:
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    def prepare(
        store: Storage,
    ) -> str | InvalidNamesCount | EmailExistsInNewUserTable:
        result = prepare_user_store(store, email, names)
        if result is not None:
            return result
        return f"prepared {email}\n"

    result = store_queue.execute(prepare)
    if isinstance(result, InvalidNamesCount):
        return Response.text(
            f"Invalid names count: {result.names_count}", status_code=400
        )
    elif isinstance(result, EmailExistsInNewUserTable):
        return Response.text(
            "User with e-mail already exists in newuser table", status_code=400
        )
    else:
        logger.info(result.strip())
        return Response.text(result)


def request_registration(req: Request, store_queue: StorageQueue) -> Response:
    """
    Creates a new user registration request with accepted=False.
    This is important for Dodeka because first the Volta process needs to succeed.
    Returns a registration_token that can be used to check status.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        firstname = body_data.get("firstname", "")
        lastname = body_data.get("lastname", "")
        if not email:
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    def register(
        store: Storage,
    ) -> str | EmailExistsInUserTable | EmailExistsInNewUserTable:
        result = add_new_user(store, email, firstname, lastname)
        if result is not None:
            return result
        registration_token = create_registration_state(store, email)
        return registration_token

    result = store_queue.execute(register)
    if isinstance(result, EmailExistsInUserTable):
        return Response.text(
            "User with e-mail already exists in user table", status_code=400
        )
    elif isinstance(result, EmailExistsInNewUserTable):
        return Response.text(
            "User with e-mail already exists in newuser table", status_code=400
        )
    else:
        registration_token = result
        logger.info(f"registered {email} with token {registration_token}")
        return Response.json(
            {
                "success": True,
                "message": f"Registration request submitted for {email}",
                "registration_token": registration_token,
            }
        )


def get_registration_status_handler(
    req: Request, store_queue: StorageQueue
) -> Response:
    """
    Handle /auth/registration_status.

    Get registration status by token.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        registration_token = body_data.get("registration_token")
        if not registration_token:
            return Response.text("Missing registration_token", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    def get_status(store: Storage) -> dict | None:
        state = get_registration_state(store, registration_token)
        if state is None:
            return None

        return {
            "email": state.email,
            "accepted": state.accepted,
            "signup_token": state.signup_token,
        }

    result = store_queue.execute(get_status)
    if result is None:
        return Response.text("Registration token not found", status_code=404)

    return Response.json(result)


def list_newusers_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_newusers/ - lists all pending user registrations."""

    def list_users(store: Storage) -> list:
        users = list_new_users(store)
        return [
            {
                "email": user.email,
                "firstname": user.firstname,
                "lastname": user.lastname,
                "accepted": user.accepted,
            }
            for user in users
        ]

    result = store_queue.execute(list_users)
    return Response.json(result)


def accept_user_handler(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /admin/accept_user/ - accepts a user and initiates Faroe signup flow."""
    # Parse and validate request
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        if not email:
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    try:
        # Initiate Faroe signup flow first
        signup_result = auth_client.create_signup(email)

        if isinstance(signup_result, ActionErrorResult):
            return Response.json(
                {
                    "error": "Faroe signup failed",
                    "error_code": signup_result.error_code,
                },
                status_code=500,
            )

        signup_token = signup_result.signup_token

        # Update accepted flag and registration state in database
        def accept(
            store: Storage,
        ) -> str | EmailNotFoundInNewUserTable | RegistrationStateNotFoundForEmail:
            result = update_accepted_flag(store, email, True)
            if result is not None:
                return result
            result = update_registration_state_accepted(store, email, signup_token)
            if result is not None:
                return result
            return f"accepted {email}\n"

        result = store_queue.execute(accept)
        if isinstance(result, EmailNotFoundInNewUserTable):
            return Response.text(
                f"Email {email} not found in newuser table", status_code=400
            )
        elif isinstance(result, RegistrationStateNotFoundForEmail):
            return Response.text(
                f"No registration state found for email: {email}", status_code=400
            )
        else:
            logger.info(result.strip())

            # Return signup token from successful result
            return Response.json(
                {
                    "success": True,
                    "message": f"User {email} accepted and signup initiated",
                    "signup_token": signup_token,
                }
            )
    except Exception as e:
        logger.error(f"Failed to create Faroe signup: {e}")
        return Response.text(f"Failed to create signup: {e}", status_code=500)


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

    def add_perm(store: Storage) -> str | UserNotFoundError:
        result = add_permission(store, timestamp, user_id, permission)
        if result is not None:
            return result
        return f"Added permission {permission} to user {user_id}\n"

    result = store_queue.execute(add_perm)
    if isinstance(result, UserNotFoundError):
        return Response.text(f"User {user_id} not found", status_code=404)
    else:
        return Response.text(result)


def get_session_token_handler(req: Request) -> Response:
    """Handle /auth/get_session_token/ - returns session token from cookie."""
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
        return Response.json({"error": "no_session"}, status_code=401)

    return Response.json({"session_token": session_token})


MIN_ADMIN_KEY_LEN = 16


def run_with_settings(settings: Settings):
    log_listener = setup_logging()
    log_listener.start()

    now = int(datetime.now(timezone.utc).timestamp())

    # Configure logging level based on debug_logs setting
    log_level = logging.DEBUG if settings.debug_logs else logging.INFO
    logging.getLogger().setLevel(log_level)

    logger.info(
        f"Running with settings:\n\t- frontend_origin={settings.frontend_origin}"
        f"\n\t- debug_logs={settings.debug_logs}"
    )

    auth_client = AuthClient(settings.auth_server_url)

    # Each time on startup we generate a key for private access
    private_route_access_key = secrets.token_urlsafe(64)

    # We write this to a file that (presumably) local processes can read to access the
    # route
    with open(settings.private_route_access_file, "w") as f:
        f.write(private_route_access_key)

    # In 'test' we set a dummy value and don't care
    if settings.environment == "test":
        admin_key = "test_key"
    else:
        if (
            settings.admin_key is None
            or len(settings.admin_key.key) < MIN_ADMIN_KEY_LEN
        ):
            raise RuntimeError(
                f"You must set the 'admin_key' to length at least {MIN_ADMIN_KEY_LEN}"
            )

        if settings.admin_key.expiration > now:
            raise RuntimeError("Admin key is expired, please set a new one.")

        admin_key = settings.admin_key.key

    # hfree doesn't know about the client, so we create a new handler that captures it
    def handler(req: Request, store_queue: StorageQueue | None) -> Response:
        # In test we set these headers so that we do actually check, but we just check
        # what we now is right
        if settings.environment == "test":
            req.headers.append(
                (
                    b"x-private-route-access-key",
                    private_route_access_key.encode("utf-8"),
                )
            )
            req.headers.append((b"x-admin-key", admin_key.encode("utf-8")))

        return handler_with_client(
            auth_client, admin_key, private_route_access_key, req, store_queue
        )

    config = ServerConfig(
        db_file=str(settings.db_file),
        db_tables=[
            "users",
            "users_by_email",
            "newusers",
            "registration_state",
            "metadata",
        ],
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
