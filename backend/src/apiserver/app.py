import enum
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any, Callable

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
    remove_permission,
)
from apiserver.data.registration_state import (
    RegistrationStateNotFoundForEmail,
    create_registration_state,
    get_registration_state,
    update_registration_state_accepted,
)
from apiserver.data.user import (
    CachedSessionData,
    InvalidSession,
    SessionInfo,
    get_cached_session,
    get_user_info,
    update_session_cache,
)
from apiserver.settings import Settings, settings

logger = logging.getLogger("apiserver.app")

# Cache session validations for 8 hours to reduce auth server load
SESSION_CACHE_EXPIRY_SECONDS = 8 * 60 * 60


class Visibility(enum.Enum):
    PRIVATE = enum.auto()
    PUBLIC = enum.auto()


class PermissionMode(enum.Enum):
    """Mode for permission checking on routes."""

    PUBLIC = enum.auto()  # No authentication needed
    DENY_ALL = enum.auto()  # Restrictive default - denies all access
    REQUIRE_PERMISSIONS = enum.auto()  # Check specific permissions


@dataclass(frozen=True)
class PermissionConfig:
    mode: PermissionMode
    permissions: frozenset[str] = frozenset()

    @staticmethod
    def public() -> "PermissionConfig":
        return PermissionConfig(PermissionMode.PUBLIC)

    @staticmethod
    def deny_all() -> "PermissionConfig":
        return PermissionConfig(PermissionMode.DENY_ALL)

    @staticmethod
    def require(*permissions: str) -> "PermissionConfig":
        """Require one or more specific permissions (user must have ALL of them)."""
        if not permissions:
            raise ValueError("Must specify at least one permission")
        return PermissionConfig(
            PermissionMode.REQUIRE_PERMISSIONS, frozenset(permissions)
        )


@dataclass
class RouteEntry:
    """
    Stores the handler of a particular route and some other configuration.
    """

    handler: Callable[[], Response]
    # Permission configuration for this route - use PermissionConfig static methods
    # Default is DENY_ALL for security (forces explicit permission configuration)
    permission: PermissionConfig = field(default_factory=PermissionConfig.deny_all)
    # If yes, then we add special headers so that browsers are able to send things
    # like cookies along (automatically true for permission-protected routes)
    requires_credentials: bool = False
    visibility: Visibility = Visibility.PRIVATE

    def needs_credentials(self) -> bool:
        """Check if this route needs credentials (session cookie)."""
        # Explicit override
        if self.requires_credentials:
            return True
        # Automatic: permission-protected routes need credentials
        if self.permission.mode == PermissionMode.REQUIRE_PERMISSIONS:
            return True
        return False


@dataclass
class RouteData:
    entry: RouteEntry
    method: str
    path: str


def parse_headers(req_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    """Parse request headers into a dict. If header keys occur multiple times, we
    use only the last one."""
    headers: dict[str, str] = {}
    try:
        for header_name, header_value in req_headers:
            headers[header_name.lower().decode("utf-8")] = header_value.decode("utf-8")
    except ValueError:
        # In case there is non-utf-8
        logger.debug("Received request with non-utf-8 headers.")
    return headers


def add_cookie_to_header(existing_cookie: str | None, name: str, value: str) -> str:
    cookie = SimpleCookie()
    if existing_cookie:
        cookie.load(existing_cookie)
    cookie[name] = value
    return "; ".join(f"{k}={morsel.value}" for k, morsel in cookie.items())


def get_cookie_value(headers: dict[str, str], cookie_name: str) -> str | None:
    """Parse cookie value from headers dict."""
    cookie_str = headers.get("cookie")
    if cookie_str is None:
        return None

    cookie = SimpleCookie()
    cookie.load(cookie_str)
    if cookie_name in cookie:
        return cookie[cookie_name].value
    return None


def check_access(
    route: RouteData,
    headers: dict[str, str],
    private_key: str,
    auth_client: AuthClient,
    store_queue: StorageQueue,
) -> Response | None:
    # Check invalid error conditions first
    if route.entry.permission.mode == PermissionMode.DENY_ALL:
        raise ValueError(
            f"Route not properly configured - DENY_ALL permission: "
            f"{route.method} {route.path}"
        )

    req_private_key = headers.get("x-private-route-access-key")
    has_private_access = req_private_key is not None and req_private_key == private_key

    # Private access bypasses all other checks
    # This is important for e.g. bootstrapping an admin account
    if has_private_access:
        return None

    # Check if route is private (defense in depth - check both entry and route string)
    is_private = route.entry.visibility == Visibility.PRIVATE or route.path.startswith(
        "/private"
    )
    if is_private:
        logger.warning(f"Access denied to private route: {route.method} {route.path}")
        return Response.text(f"Not Found: {route.method} {route.path}", status_code=404)

    # PUBLIC routes need no authentication
    if route.entry.permission.mode == PermissionMode.PUBLIC:
        return None

    assert route.entry.permission.mode == PermissionMode.REQUIRE_PERMISSIONS
    required_permissions = route.entry.permission.permissions

    # This one is used purely for access, not for determining who you are logged in
    # as. It takes precedence for determining access
    # access_session_token = get_cookie_value(headers, "access_session_token")
    # if access_session_token is not None:
    #     logger.debug("Using access_session_token for access.")
    #     session_token = access_session_token
    # else:
    session_token = get_cookie_value(headers, "session_token")

    if session_token is None:
        logger.warning(
            f"Permission-protected route access denied - no session: "
            f"{route.method} {route.path} "
            f"(requires: {', '.join(sorted(required_permissions))})"
        )
        return Response.text("Unauthorized: No session", status_code=401)

    result = get_or_validate_session(auth_client, session_token, store_queue)
    if isinstance(result, Response):
        logger.warning(
            f"Permission-protected route access denied - invalid session: "
            f"{route.method} {route.path} "
            f"(requires: {', '.join(sorted(required_permissions))})"
        )
        return Response.text("Unauthorized: Invalid session", status_code=401)

    user_id, _, _ = result
    timestamp = int(time.time())

    def get_permissions(store: Storage) -> set[str] | None:
        user = get_user_info(store, timestamp, user_id)
        if user is None:
            return None
        return user.permissions

    user_permissions = store_queue.execute(get_permissions)

    if user_permissions is None:
        logger.warning(
            f"Permission-protected route access denied - user not found: "
            f"{route.method} {route.path} (user_id={user_id}, "
            f"requires: {', '.join(sorted(required_permissions))})"
        )
        return Response.text("Unauthorized: User not found", status_code=401)

    # Check that user has ALL required permissions
    missing_permissions = required_permissions - user_permissions
    if missing_permissions:
        logger.warning(
            f"Permission-protected route access denied - missing permissions: "
            f"{route.method} {route.path} (user_id={user_id}, "
            f"has: {', '.join(sorted(user_permissions))}, "
            f"missing: {', '.join(sorted(missing_permissions))})"
        )
        return Response.text(
            f"Forbidden: Missing required permissions: "
            f"{', '.join(sorted(missing_permissions))}",
            status_code=403,
        )

    logger.debug(
        f"Permission-protected route access granted: {route.method} {route.path} "
        f"(user_id={user_id}, permissions: {', '.join(sorted(required_permissions))})"
    )
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
    if route_entry.needs_credentials():
        res_headers.append((b"Access-Control-Allow-Credentials", b"true"))

    logger.debug("Returning OPTIONS request.")
    return Response(status_code=204, headers=res_headers, body=b"")


def handler_with_client(
    auth_client: AuthClient,
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
        logger.error("Storage not available")
        return Response.text("Storage not available", status_code=500)

    path = req.path
    method = req.method

    # Parse headers once for reuse in handlers
    headers = parse_headers(req.headers)

    def h_invoke_action():
        return invoke_user_action(req, store_queue)

    def h_clear():
        return clear_tables(store_queue)

    def h_prepare():
        return prepare_user(req, store_queue)

    def h_request_registration():
        return request_registration(req, store_queue)

    def h_set_sess():
        return set_session(auth_client, req, headers, store_queue)

    def h_clear_sess():
        return clear_session(headers)

    def h_sess_info():
        return session_info(auth_client, headers, store_queue)

    def h_add_perm():
        return add_user_permission(req, store_queue)

    def h_remove_perm():
        return remove_user_permission(req, store_queue)

    def h_list_newusers():
        return list_newusers_handler(store_queue)

    def h_accept_user():
        return accept_user_handler(auth_client, req, store_queue)

    def h_get_reg_status():
        return get_registration_status_handler(req, store_queue)

    def h_get_sess_token():
        return get_session_token_handler(headers)

    def h_add_admin_perm():
        return add_admin_permission(req, store_queue)

    def h_delete_user():
        return delete_user_account(req, store_queue)

    # This table maps each route to a specific handler (the RouteEntry)
    route_table = {
        # Private endpoint, only accessible to the Go auth server or other local
        # processes
        "/private/invoke_user_action": {
            "POST": RouteEntry(h_invoke_action, PermissionConfig.public())
        },
        "/private/add_admin_permission/": {
            "POST": RouteEntry(h_add_admin_perm, PermissionConfig.public())
        },
        "/private/delete_user/": {
            "POST": RouteEntry(h_delete_user, PermissionConfig.public())
        },
        "/private/prepare_user": {
            "POST": RouteEntry(h_prepare, PermissionConfig.public())
        },
        "/private/clear_tables": {
            "POST": RouteEntry(h_clear, PermissionConfig.public())
        },
        # Dodeka-specific actions related to auth
        "/auth/request_registration": {
            "POST": RouteEntry(
                h_request_registration,
                PermissionConfig.public(),
                visibility=Visibility.PUBLIC,
            )
        },
        "/auth/registration_status": {
            "POST": RouteEntry(
                h_get_reg_status,
                PermissionConfig.public(),
                visibility=Visibility.PUBLIC,
            )
        },
        # We prefix the next with 'admin' to make it clear it's only accessible to
        # admins
        "/admin/accept_user/": {
            "POST": RouteEntry(
                h_accept_user,
                PermissionConfig.require("admin"),
                visibility=Visibility.PUBLIC,
            )
        },
        "/admin/add_permission/": {
            "POST": RouteEntry(
                h_add_perm,
                PermissionConfig.require("admin"),
                visibility=Visibility.PUBLIC,
            )
        },
        "/admin/remove_permission/": {
            "POST": RouteEntry(
                h_remove_perm,
                PermissionConfig.require("admin"),
                visibility=Visibility.PUBLIC,
            )
        },
        "/admin/list_newusers/": {
            "GET": RouteEntry(
                h_list_newusers,
                PermissionConfig.require("admin"),
                visibility=Visibility.PUBLIC,
            )
        },
        "/auth/session_info/": {
            "GET": RouteEntry(
                h_sess_info,
                PermissionConfig.public(),
                requires_credentials=True,
                visibility=Visibility.PUBLIC,
            )
        },
        # Since we have HttpOnly cookies, we need server functions to modify them
        "/cookies/session_token/": {
            "GET": RouteEntry(
                h_get_sess_token,
                PermissionConfig.public(),
                requires_credentials=True,
                visibility=Visibility.PUBLIC,
            )
        },
        "/cookies/set_session/": {
            "POST": RouteEntry(
                h_set_sess,
                PermissionConfig.public(),
                requires_credentials=True,
                visibility=Visibility.PUBLIC,
            )
        },
        "/cookies/clear_session/": {
            "POST": RouteEntry(
                h_clear_sess,
                PermissionConfig.public(),
                requires_credentials=True,
                visibility=Visibility.PUBLIC,
            )
        },
    }

    route = route_table.get(path)
    if route is None:
        logger.info(f"Route not found: {method} {path}")
        return Response.text(f"Not Found: {method} {path}", status_code=404)

    # In order to get a useful method when the method is OPTIONS is sent for many other
    # methods in a so-called pre-flight request during CORS), we get this special header
    if method == "OPTIONS":
        requested_method = headers.get("access-control-request-method")
    else:
        requested_method = method

    # We can now get a route_entry, or just set it to none and then return not found
    route_entry = None if requested_method is None else route.get(requested_method)
    if route_entry is None:
        logger.info(f"Method not supported: {method} {path}")
        return Response.text(f"Not Found: {method} {path}", status_code=404)

    # Check access (private routes, permissions, etc.)
    if error := check_access(
        RouteData(entry=route_entry, method=method, path=path),
        headers,
        private_route_access_key,
        auth_client,
        store_queue,
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
    if route_entry.needs_credentials():
        response.headers.append((b"Access-Control-Allow-Credentials", b"true"))
    return response


def invoke_user_action(req: Request, store_queue: StorageQueue) -> Response:
    """
    Handle /auth/invoke_user_action - executes Faroe user actions via
    SqliteSyncServer. It's important that these are protected.
    """
    try:
        request_json = json.loads(req.body.decode("utf-8"))
    except json.JSONDecodeError:
        logger.warning("invoke_user_action: Invalid JSON in request")
        return Response.text("Invalid JSON", status_code=400)

    def execute_action(store: Storage) -> str:
        server = SqliteSyncServer(store)
        result = handle_request_sync(request_json, server)

        if result.error is not None:
            logger.error(f"invoke_user_action: Action error: {result.error}")

        logger.debug(f"invoke_user_action: Action response: {result.response_json}")
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

    logger.info("clear_tables: Clearing all tables")
    result = store_queue.execute(clear)
    logger.info(f"clear_tables: {result.strip()}")
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
            logger.warning("prepare_user: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"prepare_user: Invalid request: {e}")
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
        logger.warning(f"prepare_user: Invalid names count: {result.names_count}")
        return Response.text(
            f"Invalid names count: {result.names_count}", status_code=400
        )
    elif isinstance(result, EmailExistsInNewUserTable):
        logger.warning(f"prepare_user: Email {email} already exists in newuser table")
        return Response.text(
            "User with e-mail already exists in newuser table", status_code=400
        )
    else:
        logger.info(f"prepare_user: {result.strip()}")
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
            logger.warning("request_registration: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"request_registration: Invalid request: {e}")
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
        logger.error(
            f"request_registration: Email {email} already exists in user table"
        )
        return Response.text(
            "User with e-mail already exists in user table", status_code=400
        )
    elif isinstance(result, EmailExistsInNewUserTable):
        logger.warning(
            f"request_registration: Email {email} already exists in newuser table"
        )
        return Response.text(
            "User with e-mail already exists in newuser table", status_code=400
        )
    else:
        registration_token = result
        logger.info(
            f"request_registration: Registered {email} with token {registration_token}"
        )
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
            logger.warning("get_registration_status: Missing registration_token")
            return Response.text("Missing registration_token", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"get_registration_status: Invalid request: {e}")
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
        logger.info(f"get_registration_status: Token {registration_token} not found")
        return Response.text("Registration token not found", status_code=404)

    logger.info(
        f"get_registration_status: Found status for {result['email']}, "
        f"accepted={result['accepted']}"
    )
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
    logger.info(f"list_newusers: Returning {len(result)} users")
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
            logger.warning("accept_user: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"accept_user: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    try:
        # Initiate Faroe signup flow first
        logger.info(f"accept_user: Creating Faroe signup for {email}")
        signup_result = auth_client.create_signup(email)

        if isinstance(signup_result, ActionErrorResult):
            logger.error(
                f"accept_user: Faroe signup failed for {email}: "
                f"{signup_result.error_code}"
            )
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
            logger.warning(f"accept_user: Email {email} not found in newuser table")
            return Response.text(
                f"Email {email} not found in newuser table", status_code=400
            )
        elif isinstance(result, RegistrationStateNotFoundForEmail):
            logger.warning(f"accept_user: No registration state found for {email}")
            return Response.text(
                f"No registration state found for email: {email}", status_code=400
            )
        else:
            logger.info(f"accept_user: {result.strip()}")

            # Return signup token from successful result
            return Response.json(
                {
                    "success": True,
                    "message": f"User {email} accepted and signup initiated",
                    "signup_token": signup_token,
                }
            )
    except Exception as e:
        logger.error(f"accept_user: Failed to create Faroe signup: {e}")
        return Response.text(f"Failed to create signup: {e}", status_code=500)


def get_or_validate_session(
    auth_client: AuthClient,
    session_token: str,
    store_queue: StorageQueue,
) -> tuple[str, int, int | None] | Response:
    """
    Get session from cache or validate with auth server.

    Returns tuple of (user_id, created_at, expires_at) on success,
    or error Response on failure.
    """
    timestamp = int(time.time())

    # Try to get from cache first
    def check_cache(store: Storage) -> CachedSessionData | None:
        return get_cached_session(store, session_token, timestamp)

    cached_session = store_queue.execute(check_cache)

    # If cache miss, validate with auth server
    if cached_session is None:
        logger.debug("Session cache miss, validating with auth server")
        session_result = auth_client.get_session(session_token)

        if isinstance(session_result, ActionErrorResult):
            if session_result.error_code != "invalid_session_token":
                invocation_id = session_result.action_invocation_id
                error_code = session_result.error_code
                logger.error(
                    f"Auth server error (invocation {invocation_id}): {error_code}"
                )
                raise ValueError(
                    f"Error getting session from auth server "
                    f"(invocation {invocation_id}): {error_code}."
                )
            logger.info("Invalid session token provided")
            return Response.text("Invalid session_token", status_code=401)

        # Cache the validated session
        user_id = session_result.session.user_id
        created_at = session_result.session.created_at
        expires_at = session_result.session.expires_at

        logger.debug(f"Session validated for user {user_id}, updating cache")

        def update_cache(store: Storage):
            # Note that it's fine if it already executes by this point, it will just
            # overwite which should be fine based on session token uniqueness
            update_session_cache(
                store, session_token, user_id, created_at, expires_at, timestamp
            )

        store_queue.execute(update_cache)
    else:
        # Cache hit - use cached session data
        user_id = cached_session.user_id
        created_at = cached_session.created_at
        expires_at = cached_session.expires_at
        logger.debug(f"Session cache hit for user {user_id}")

    return (user_id, created_at, expires_at)


def set_session(
    auth_client: AuthClient,
    req: Request,
    headers: dict[str, str],
    store_queue: StorageQueue,
) -> Response:
    """Handle /auth/set_session/ - validates and sets session cookie."""
    # Get Origin header
    # TODO: should we really perform this check or is it up to browser?
    origin = headers.get("origin")

    if origin != settings.frontend_origin:
        logger.warning(f"set_session: Invalid origin {origin}")
        return Response.text("Invalid origin!", status_code=403)

    try:
        body_data = json.loads(req.body.decode("utf-8"))
        session_token = body_data.get("session_token")
        if not session_token:
            logger.warning("set_session: Missing session_token in request")
            return Response.text("Missing session_token", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"set_session: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Validate session with auth server (and cache it)
    result = get_or_validate_session(auth_client, session_token, store_queue)
    if isinstance(result, Response):
        logger.info("set_session: Session validation failed")
        return result

    user_id, _, _ = result
    logger.info(f"set_session: Setting session cookie for user {user_id}")

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


def clear_session(headers: dict[str, str]) -> Response:
    """Handle /auth/clear_session/ - clears session cookie."""
    # Get Origin header
    origin = headers.get("origin")

    if origin != settings.frontend_origin:
        logger.warning(f"clear_session: Invalid origin {origin}")
        return Response.text("Invalid origin!", status_code=403)

    logger.info("clear_session: Clearing session cookie")

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
    auth_client: AuthClient,
    headers: dict[str, str],
    store_queue: StorageQueue,
) -> Response:
    """Handle /auth/session_info/ - gets session information."""
    session_token = get_cookie_value(headers, "session_token")

    if session_token is None:
        logger.debug("session_info: No session cookie found")
        response_data = {"error": "no_session"}
        return Response.json(response_data)

    # Validate session with auth server (and cache it)
    result = get_or_validate_session(auth_client, session_token, store_queue)
    if isinstance(result, Response):
        logger.info("session_info: Session validation failed")
        # Return error response as JSON with proper error field
        return Response.json({"error": "invalid_session"}, status_code=401)

    user_id, created_at, expires_at = result
    timestamp = int(time.time())

    # Get user info from database
    def get_session_data(store: Storage) -> SessionInfo | InvalidSession:
        user = get_user_info(store, timestamp, user_id)
        if user is None:
            return InvalidSession()
        return SessionInfo(user=user, created_at=created_at, expires_at=expires_at)

    session = store_queue.execute(get_session_data)

    if isinstance(session, InvalidSession):
        logger.warning(f"session_info: User {user_id} not found in database")
        response_data = {"error": "invalid_session"}
    else:
        logger.debug(f"session_info: Returning session info for user {user_id}")
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
    """Handle /admin/add_permission/ - adds a permission to a user (except admin)."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        user_id = body_data.get("user_id")
        permission = body_data.get("permission")
        if not user_id or not permission:
            logger.warning("add_user_permission: Missing user_id or permission")
            return Response.text("Missing user_id or permission", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"add_user_permission: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Block adding admin permission through public API
    if permission == "admin":
        logger.error(
            f"add_user_permission: Attempted to add admin permission to {user_id}"
        )
        return Response.text("Cannot add admin permission", status_code=403)

    if not allowed_permission(permission):
        logger.warning(f"add_user_permission: Invalid permission {permission}")
        return Response.text(f"Invalid permission: {permission}", status_code=400)

    timestamp = int(time.time())

    def add_perm(store: Storage) -> str | UserNotFoundError:
        result = add_permission(store, timestamp, user_id, permission)
        if result is not None:
            return result
        return f"Added permission {permission} to user {user_id}\n"

    result = store_queue.execute(add_perm)
    if isinstance(result, UserNotFoundError):
        logger.warning(f"add_user_permission: User {user_id} not found")
        return Response.text(f"User {user_id} not found", status_code=404)
    else:
        logger.info(f"add_user_permission: {result.strip()}")
        return Response.text(result)


def remove_user_permission(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/remove_permission/ - removes a permission from a user."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        user_id = body_data.get("user_id")
        permission = body_data.get("permission")
        if not user_id or not permission:
            logger.warning("remove_user_permission: Missing user_id or permission")
            return Response.text("Missing user_id or permission", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"remove_user_permission: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    if not allowed_permission(permission):
        logger.warning(f"remove_user_permission: Invalid permission {permission}")
        return Response.text(f"Invalid permission: {permission}", status_code=400)

    def remove_perm(store: Storage) -> str | UserNotFoundError:
        result = remove_permission(store, user_id, permission)
        if result is not None:
            return result
        return f"Removed permission {permission} from user {user_id}\n"

    result = store_queue.execute(remove_perm)
    if isinstance(result, UserNotFoundError):
        logger.warning(f"remove_user_permission: User {user_id} not found")
        return Response.text(f"User {user_id} not found", status_code=404)
    else:
        logger.info(f"remove_user_permission: {result.strip()}")
        return Response.text(result)


def add_admin_permission(req: Request, store_queue: StorageQueue) -> Response:
    """
    Handle /private/add_admin_permission/ - adds admin permission to a user.
    This is a private route only accessible with the private route access key.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        user_id = body_data.get("user_id")
        if not user_id:
            logger.warning("add_admin_permission: Missing user_id")
            return Response.text("Missing user_id", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"add_admin_permission: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    timestamp = int(time.time())

    def add_admin_perm(store: Storage) -> str | UserNotFoundError:
        result = add_permission(store, timestamp, user_id, "admin")
        if result is not None:
            return result
        return f"Added admin permission to user {user_id}\n"

    result = store_queue.execute(add_admin_perm)
    if isinstance(result, UserNotFoundError):
        logger.warning(f"add_admin_permission: User {user_id} not found")
        return Response.text(f"User {user_id} not found", status_code=404)
    else:
        logger.info(f"add_admin_permission: {result.strip()}")
        return Response.text(result)


def delete_user_account(req: Request, store_queue: StorageQueue) -> Response:
    """
    Handle /private/delete_user/ - deletes a user account by email.
    This is a private route only accessible with the private route access key.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        if not email:
            logger.warning("delete_user_account: Missing email")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"delete_user_account: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Look up user_id by email
    def get_user_id_by_email(store: Storage) -> str | None:
        result = store.get("users_by_email", email)
        if result is None:
            return None
        user_id_bytes, _ = result
        return user_id_bytes.decode("utf-8")

    user_id = store_queue.execute(get_user_id_by_email)

    if user_id is None:
        logger.info(f"delete_user_account: User with email {email} not found (OK)")
        return Response.text("User deleted or did not exist\n")

    # Use tiauth_faroe to delete the user through invoke_user_action
    delete_request = {
        "action": "delete_user",
        "arguments": {"user_id": user_id},
    }

    def execute_delete(store: Storage) -> str:
        server = SqliteSyncServer(store)
        result = handle_request_sync(delete_request, server)

        if result.error is not None:
            logger.error(f"delete_user_account: Action error: {result.error}")
            return f"Error deleting user: {result.error}"

        logger.info(f"delete_user_account: Deleted user {user_id} (email={email})")
        return f"User deleted: {email}\n"

    result_msg = store_queue.execute(execute_delete)
    return Response.text(result_msg)


def get_session_token_handler(headers: dict[str, str]) -> Response:
    """Handle /auth/get_session_token/ - returns session token from cookie."""
    session_token = get_cookie_value(headers, "session_token")

    if session_token is None:
        logger.debug("get_session_token: No session cookie found")
        return Response.json({"error": "no_session"}, status_code=401)

    logger.debug("get_session_token: Returning session token")
    return Response.json({"session_token": session_token})


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

    # Each time on startup we generate a key for private access
    private_route_access_key = secrets.token_urlsafe(64)

    # We write this to a file that (presumably) local processes can read to access the
    # route
    with open(settings.private_route_access_file, "w") as f:
        f.write(private_route_access_key)

    # Bootstrap root admin and get test session in test mode
    # Use a list so it's mutable from the thread
    test_admin_session_token: list[str | None] = [None]

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
            # # Add admin session cookie if available
            # # TODO: how useful is this really with private access?
            # if test_admin_session_token[0]:
            #     headers = parse_headers(req.headers)
            #     cookie_value = add_cookie_to_header(
            #         headers.get("cookie"),
            #         "access_session_token",
            #         test_admin_session_token[0],
            #     )
            #     req.headers.append((b"cookie", cookie_value.encode("utf-8")))

        return handler_with_client(
            auth_client, private_route_access_key, req, store_queue
        )

    config = ServerConfig(
        db_file=str(settings.db_file),
        db_tables=[
            "users",
            "users_by_email",
            "newusers",
            "registration_state",
            "metadata",
            "session_cache",
        ],
    )

    # Create ready event for server startup
    ready_event = threading.Event()

    # Run startup actions after server is ready
    def run_startup_actions():
        """Execute startup actions after server is ready."""
        ready_event.wait()
        logger.info("Server ready, running startup actions...")

        # In test mode, bootstrap admin user
        if settings.environment == "test":
            from apiserver.actions import (  # noqa: PLC0415
                AdminUserCreationError,
                AppClient,
                MessageReader,
                create_admin_user,
                start_socket_reader,
            )

            try:
                # Create shared state for socket messages
                socket_messages: list[dict[str, Any]] = []
                socket_condition = threading.Condition()

                # Start socket reader thread
                start_socket_reader(
                    settings.code_socket_path, socket_messages, socket_condition
                )

                # Create message reader for admin user creation
                message_reader = MessageReader(socket_messages, socket_condition)

                client = AppClient(
                    f"http://{config.host}:{config.port}",
                    settings.auth_server_url,
                    private_route_access_key,
                )
                root_email = "root_admin@localhost"
                root_password = secrets.token_urlsafe(32)

                user_id, session_token = create_admin_user(
                    client, root_email, root_password, message_reader, ["Root", "Admin"]
                )

                test_admin_session_token[0] = session_token
                logger.info(
                    f"Root admin bootstrapped: {root_email} (user_id={user_id})"
                )
                logger.info(
                    f"Test admin credentials: email={root_email}, "
                    f"password={root_password}"
                )
            except AdminUserCreationError as e:
                logger.error(f"Failed to bootstrap root admin: {e}")
            except Exception as e:
                logger.error(f"Unexpected error bootstrapping root admin: {e}")

    threading.Thread(target=run_startup_actions, daemon=True).start()

    try:
        start_server(config, handler, ready_event=ready_event)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        log_listener.stop()


def run():
    run_with_settings(settings)


if __name__ == "__main__":
    run()
