import enum
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Callable, Literal
from urllib.parse import parse_qs, urlparse

from freetser import (
    Request,
    Response,
    Storage,
    TcpServerConfig,
    setup_logging,
    start_server,
    start_storage_thread,
)
from freetser.server import StorageQueue
from tiauth_faroe.client import ActionErrorResult

from apiserver.actions import AdminUserCreationError, create_admin_user
from apiserver.data.admin import store_admin_credentials
from apiserver.data.client import AuthClient
from apiserver.data.newuser import (
    EmailExistsInNewUserTable,
    EmailExistsInUserTable,
    EmailNotFoundInNewUserTable,
    add_new_user,
    list_new_users,
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
    get_signup_token_by_email,
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
from apiserver.private import start_private_server
from apiserver.settings import Settings, load_settings_from_env, parse_args
from apiserver.tokens import TOKENS_TABLE, TokenWaiter

logger = logging.getLogger("apiserver.app")

# Cache session validations for 8 hours to reduce auth server load
SESSION_CACHE_EXPIRY_SECONDS = 8 * 60 * 60

# Session cookie names
#
# Primary session: The user's actual logged-in session. Used by default for
# session_info, get_session_token, and endpoints that need "who is the user".
#
# Secondary session: Authorization-only fallback for permission checks. Not the
# logged-in identity. Useful for testing: log in as a regular user (primary)
# while using an admin session (secondary) to authorize admin actions.
#
# Permission checks (check_access) try primary first, then secondary as fallback.
# session_info defaults to primary, but accepts ?secondary=true to check the
# secondary session (e.g., to verify it's still valid).
SESSION_COOKIE_PRIMARY = "session_token"
SESSION_COOKIE_SECONDARY = "session_token_secondary"


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


def make_clear_session_cookie_header(
    cookie_name: str = SESSION_COOKIE_PRIMARY,
) -> tuple[bytes, bytes]:
    """Create a Set-Cookie header that clears a session cookie."""
    cookie = SimpleCookie()
    cookie[cookie_name] = ""
    cookie[cookie_name]["httponly"] = True
    cookie[cookie_name]["samesite"] = "None"
    cookie[cookie_name]["secure"] = True
    cookie[cookie_name]["path"] = "/"
    cookie[cookie_name]["max-age"] = 0
    return (b"Set-Cookie", cookie[cookie_name].OutputString().encode("utf-8"))


@dataclass(frozen=True)
class ValidatedSession:
    """Session token validated successfully."""

    user_id: str
    created_at: int
    expires_at: int | None


@dataclass(frozen=True)
class InvalidSessionToken:
    """Session token was rejected by auth server."""

    pass


@dataclass(frozen=True)
class AccessGranted:
    """Access check passed."""

    user_id: str


@dataclass(frozen=True)
class AccessDenied:
    """Access check failed."""

    error: Literal["no_session", "invalid_session", "user_not_found", "missing"]
    message: str
    status_code: int


def check_session_for_access(
    session_token: str,
    required_permissions: frozenset[str],
    auth_client: AuthClient,
    store_queue: StorageQueue,
) -> AccessGranted | AccessDenied:
    """Check if a session token grants the required permissions."""
    validation = validate_session(auth_client, session_token, store_queue)
    if isinstance(validation, InvalidSessionToken):
        return AccessDenied("invalid_session", "Invalid session", 401)

    timestamp = int(time.time())

    def get_permissions(store: Storage) -> set[str] | None:
        user = get_user_info(store, timestamp, validation.user_id)
        return user.permissions if user else None

    permissions = store_queue.execute(get_permissions)

    if permissions is None:
        return AccessDenied("user_not_found", "User not found", 401)

    missing = required_permissions - permissions
    if missing:
        return AccessDenied(
            "missing",
            f"Missing permissions: {', '.join(sorted(missing))}",
            403,
        )

    return AccessGranted(user_id=validation.user_id)


def check_access(
    route: RouteData,
    headers: dict[str, str],
    auth_client: AuthClient,
    store_queue: StorageQueue,
) -> Response | None:
    """Check if the request has permission to access the route.

    Returns None if access is granted, or a Response with an error.
    """
    if route.entry.permission.mode == PermissionMode.DENY_ALL:
        raise ValueError(f"Route not configured: {route.method} {route.path}")

    if route.entry.permission.mode == PermissionMode.PUBLIC:
        return None

    required = route.entry.permission.permissions

    # Try primary session first, then secondary as fallback
    tokens = [
        ("primary", get_cookie_value(headers, SESSION_COOKIE_PRIMARY)),
        ("secondary", get_cookie_value(headers, SESSION_COOKIE_SECONDARY)),
    ]

    last_error: AccessDenied | None = None
    for name, token in tokens:
        if token is None:
            continue
        result = check_session_for_access(token, required, auth_client, store_queue)
        if isinstance(result, AccessGranted):
            logger.debug(f"Access granted ({name}): {route.method} {route.path}")
            return None
        last_error = result

    # No valid session
    if last_error is None:
        logger.warning(f"Access denied (no session): {route.method} {route.path}")
        return Response.text("Unauthorized: No session", status_code=401)

    logger.warning(f"Access denied ({last_error.error}): {route.method} {route.path}")
    return Response.text(last_error.message, status_code=last_error.status_code)


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
    req: Request,
    store_queue: StorageQueue | None,
    frontend_origin: str,
) -> Response:
    """
    This function dispatches a request to a specific handler, based on the route. It
    also handles things like CORS (browsers are careful when making requests that are
    not the same 'origin', so different domain)
    """
    if store_queue is None:
        logger.error("Storage not available")
        return Response.text("Storage not available", status_code=500)

    # Strip query string for route lookup (handlers can access full path via req.path)
    path = urlparse(req.path).path
    method = req.method

    # Parse headers once for reuse in handlers
    headers = parse_headers(req.headers)

    def h_request_registration():
        return request_registration(req, store_queue)

    def h_set_sess():
        return set_session(auth_client, req, headers, store_queue, frontend_origin)

    def h_clear_sess():
        return clear_session(req, headers, frontend_origin)

    def h_sess_info():
        return session_info(auth_client, req, headers, store_queue)

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

    def h_resend_signup_email():
        return resend_signup_email_handler(auth_client, req, store_queue)

    # This table maps each route to a specific handler (the RouteEntry)
    route_table = {
        # Dodeka-specific actions related to auth
        "/auth/request_registration": {
            "POST": RouteEntry(h_request_registration, PermissionConfig.public())
        },
        "/auth/registration_status": {
            "POST": RouteEntry(h_get_reg_status, PermissionConfig.public())
        },
        # We prefix the next with 'admin' to make it clear it's only accessible to
        # admins
        "/admin/accept_user/": {
            "POST": RouteEntry(h_accept_user, PermissionConfig.require("admin"))
        },
        "/admin/add_permission/": {
            "POST": RouteEntry(h_add_perm, PermissionConfig.require("admin"))
        },
        "/admin/remove_permission/": {
            "POST": RouteEntry(h_remove_perm, PermissionConfig.require("admin"))
        },
        "/admin/list_newusers/": {
            "GET": RouteEntry(h_list_newusers, PermissionConfig.require("admin"))
        },
        "/admin/resend_signup_email/": {
            "POST": RouteEntry(h_resend_signup_email, PermissionConfig.require("admin"))
        },
        "/auth/session_info/": {
            "GET": RouteEntry(
                h_sess_info, PermissionConfig.public(), requires_credentials=True
            )
        },
        # Since we have HttpOnly cookies, we need server functions to modify them
        "/cookies/session_token/": {
            "GET": RouteEntry(
                h_get_sess_token, PermissionConfig.public(), requires_credentials=True
            )
        },
        "/cookies/set_session/": {
            "POST": RouteEntry(
                h_set_sess, PermissionConfig.public(), requires_credentials=True
            )
        },
        "/cookies/clear_session/": {
            "POST": RouteEntry(
                h_clear_sess, PermissionConfig.public(), requires_credentials=True
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

    # Handle OPTIONS preflight for CORS (before auth - preflight has no cookies)
    if method == "OPTIONS":
        return handle_options_request(route, route_entry, frontend_origin)

    # Check access (permissions, etc.)
    if error := check_access(
        RouteData(entry=route_entry, method=method, path=path),
        headers,
        auth_client,
        store_queue,
    ):
        return error

    # Browsers generally only allow responses that have this set (CORS)
    allow_origin_header = (
        b"Access-Control-Allow-Origin",
        frontend_origin.encode("utf-8"),
    )

    response = route_entry.handler()
    # This one is basically always necessary for the browser to read it
    response.headers.append(allow_origin_header)
    # Add credentials header if this route requires it
    if route_entry.needs_credentials():
        response.headers.append((b"Access-Control-Allow-Credentials", b"true"))
    return response


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


def resend_signup_email_handler(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /admin/resend_signup_email/ - resends signup verification email."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        if not email:
            logger.warning("resend_signup_email: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"resend_signup_email: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Look up signup_token by email
    def get_token(store: Storage) -> str | None:
        return get_signup_token_by_email(store, email)

    signup_token = store_queue.execute(get_token)
    if signup_token is None:
        logger.warning(f"resend_signup_email: No signup token found for {email}")
        return Response.text(f"No signup token found for {email}", status_code=404)

    # Call Faroe to resend the email
    result = auth_client.send_signup_email_address_verification_code(signup_token)

    if isinstance(result, ActionErrorResult):
        logger.error(
            f"resend_signup_email: Failed for {email}: {result.error_code}"
        )
        return Response.json(
            {"error": "Failed to resend email", "error_code": result.error_code},
            status_code=400,
        )

    logger.info(f"resend_signup_email: Resent verification email to {email}")
    return Response.json({"success": True, "message": f"Email resent to {email}"})


def validate_session(
    auth_client: AuthClient,
    session_token: str,
    store_queue: StorageQueue,
) -> ValidatedSession | InvalidSessionToken:
    """Validate session token with auth server, using cache when possible."""
    timestamp = int(time.time())

    def check_cache(store: Storage) -> CachedSessionData | None:
        return get_cached_session(store, session_token, timestamp)

    cached = store_queue.execute(check_cache)

    if cached is not None:
        logger.debug(f"Session cache hit for user {cached.user_id}")
        return ValidatedSession(cached.user_id, cached.created_at, cached.expires_at)

    # Cache miss - validate with auth server
    logger.debug("Session cache miss, validating with auth server")
    result = auth_client.get_session(session_token)

    if isinstance(result, ActionErrorResult):
        if result.error_code != "invalid_session_token":
            logger.error(f"Auth server error: {result.error_code}")
            raise ValueError(f"Auth server error: {result.error_code}")
        logger.info("Invalid session token provided")
        return InvalidSessionToken()

    # Cache and return validated session
    session = result.session
    logger.debug(f"Session validated for user {session.user_id}, updating cache")

    def update_cache(store: Storage) -> None:
        update_session_cache(
            store, session_token, session.user_id,
            session.created_at, session.expires_at, timestamp
        )

    store_queue.execute(update_cache)
    return ValidatedSession(session.user_id, session.created_at, session.expires_at)


def set_session(
    auth_client: AuthClient,
    req: Request,
    headers: dict[str, str],
    store_queue: StorageQueue,
    frontend_origin: str,
) -> Response:
    """Handle /auth/set_session/ - validates and sets session cookie.

    Request body:
        session_token: The session token to set
        secondary: Optional boolean, if true sets the secondary session cookie
    """
    # Get Origin header
    # TODO: should we really perform this check or is it up to browser?
    origin = headers.get("origin")

    if origin != frontend_origin:
        logger.warning(f"set_session: Invalid origin {origin}")
        return Response.text("Invalid origin!", status_code=403)

    try:
        body_data = json.loads(req.body.decode("utf-8"))
        session_token = body_data.get("session_token")
        secondary = body_data.get("secondary", False)
        if not session_token:
            logger.warning("set_session: Missing session_token in request")
            return Response.text("Missing session_token", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"set_session: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Validate session with auth server (and cache it)
    result = validate_session(auth_client, session_token, store_queue)
    if isinstance(result, InvalidSessionToken):
        logger.info("set_session: Session validation failed")
        return Response.text("Invalid session_token", status_code=401)

    cookie_name = SESSION_COOKIE_SECONDARY if secondary else SESSION_COOKIE_PRIMARY
    logger.info(f"set_session: Setting {cookie_name} cookie for user {result.user_id}")

    max_session_age = 86400 * 365

    # Build Set-Cookie header using http.cookies
    cookie = SimpleCookie()
    cookie[cookie_name] = session_token
    cookie[cookie_name]["httponly"] = True
    cookie[cookie_name]["samesite"] = "None"
    cookie[cookie_name]["secure"] = True
    cookie[cookie_name]["path"] = "/"
    cookie[cookie_name]["max-age"] = max_session_age

    cookie_header = cookie[cookie_name].OutputString()

    return Response.empty(
        headers=[
            (b"Set-Cookie", cookie_header.encode("utf-8")),
        ],
    )


def clear_session(
    req: Request, headers: dict[str, str], frontend_origin: str
) -> Response:
    """Handle /auth/clear_session/ - clears session cookie.

    Request body (optional):
        secondary: Optional boolean, if true clears the secondary session cookie
    """
    # Get Origin header
    origin = headers.get("origin")

    if origin != frontend_origin:
        logger.warning(f"clear_session: Invalid origin {origin}")
        return Response.text("Invalid origin!", status_code=403)

    # Parse optional body for secondary flag
    secondary = False
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            secondary = body_data.get("secondary", False)
        except (json.JSONDecodeError, ValueError):
            pass  # Ignore invalid body, default to primary

    cookie_name = SESSION_COOKIE_SECONDARY if secondary else SESSION_COOKIE_PRIMARY
    logger.info(f"clear_session: Clearing {cookie_name} cookie")
    return Response.empty(headers=[make_clear_session_cookie_header(cookie_name)])


def session_info(
    auth_client: AuthClient,
    req: Request,
    headers: dict[str, str],
    store_queue: StorageQueue,
) -> Response:
    """Handle /auth/session_info/ - gets session information.

    Query params:
        secondary: If "true", check secondary session instead of primary.

    By default checks primary session (the logged-in user). Use secondary=true
    to check the authorization-only session.
    """
    # Parse query params to check for secondary flag
    secondary = False
    if "?" in req.path:
        query = parse_qs(urlparse(req.path).query)
        secondary = query.get("secondary", [""])[0].lower() == "true"

    cookie_name = SESSION_COOKIE_SECONDARY if secondary else SESSION_COOKIE_PRIMARY
    session_token = get_cookie_value(headers, cookie_name)

    if session_token is None:
        logger.debug(f"session_info: No {cookie_name} cookie found")
        return Response.json({"error": "no_session"})

    # Validate session with auth server (and cache it)
    result = validate_session(auth_client, session_token, store_queue)
    if isinstance(result, InvalidSessionToken):
        logger.info(f"session_info: {cookie_name} validation failed")
        return Response.json(
            {"error": "invalid_session"},
            status_code=401,
            headers=[make_clear_session_cookie_header(cookie_name)],
        )

    timestamp = int(time.time())

    # Get user info from database
    def get_session_data(store: Storage) -> SessionInfo | InvalidSession:
        user = get_user_info(store, timestamp, result.user_id)
        if user is None:
            return InvalidSession()
        return SessionInfo(
            user=user, created_at=result.created_at, expires_at=result.expires_at
        )

    session = store_queue.execute(get_session_data)

    if isinstance(session, InvalidSession):
        logger.warning(f"session_info: User {result.user_id} not found")
        return Response.json(
            {"error": "invalid_session"},
            status_code=401,
            headers=[make_clear_session_cookie_header(cookie_name)],
        )

    logger.debug(f"session_info: Returning info for user {result.user_id}")
    return Response.json(
        {
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


def bootstrap_admin(
    token_waiter: TokenWaiter,
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
        token_waiter,
        ["Root", "Admin"],
    )

    # Store credentials in database for retrieval via CLI
    def save_credentials(store: Storage) -> None:
        store_admin_credentials(store, root_email, root_password)

    store_queue.execute(save_credentials)

    logger.info(f"Root admin bootstrapped: {root_email} (user_id={user_id})")
    logger.info(f"Root admin credentials: email={root_email}, password={root_password}")
    return user_id, session_token


def get_session_token_handler(headers: dict[str, str]) -> Response:
    """Handle /cookies/session_token/ - returns session token from primary cookie."""
    session_token = get_cookie_value(headers, SESSION_COOKIE_PRIMARY)

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
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    # Also set handler levels (setup_logging may have set handlers with higher levels)
    for h in root_logger.handlers:
        h.setLevel(log_level)

    logger.info(
        f"Running with settings:\n\t- frontend_origin={settings.frontend_origin}"
        f"\n\t- debug_logs={settings.debug_logs}"
        f"\n\t- port={settings.port}"
        f"\n\t- private_port={settings.private_port}"
    )

    auth_client = AuthClient(settings.auth_server_url)

    db_tables = [
        "users",
        "users_by_email",
        "newusers",
        "registration_state",
        "metadata",
        "session_cache",
        TOKENS_TABLE,
    ]

    # Start storage thread
    store_queue = start_storage_thread(
        db_file=str(settings.db_file),
        db_tables=db_tables,
    )

    # Create token waiter for test notifications
    token_waiter = TokenWaiter(store_queue)

    # Helper to bootstrap admin (used on startup and reset)
    def do_bootstrap_admin() -> str:
        try:
            bootstrap_admin(token_waiter, auth_client, store_queue)
            return "Admin re-bootstrapped"
        except AdminUserCreationError as e:
            logger.error(f"Failed to bootstrap root admin: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error bootstrapping root admin: {e}")
            raise

    # Command handlers that need app.py dependencies (auth_client, token_waiter).
    # Other commands (prepare_user, get_admin_credentials) only need database
    # access and are handled directly in private.py.
    command_handlers = {
        "reset": do_bootstrap_admin,  # Called after tables are cleared
    }

    # Start private TCP server on 127.0.0.2 (Go and CLI connect to this)
    start_private_server(
        settings.private_port,
        store_queue,
        token_waiter,
        settings.frontend_origin,
        settings.smtp,
        command_handlers,
    )

    # freetser doesn't know about the client, so we create a handler that captures it
    frontend_origin = settings.frontend_origin

    def handler(req: Request, store_queue: StorageQueue | None) -> Response:
        return handler_with_client(auth_client, req, store_queue, frontend_origin)

    # Create ready event for server startup
    ready_event = threading.Event()

    # Run startup actions after server is ready
    def run_startup_actions():
        """Execute startup actions after server is ready."""
        ready_event.wait()
        logger.info("Server ready, running startup actions...")
        try:
            do_bootstrap_admin()
        except Exception:
            pass  # Already logged

    threading.Thread(target=run_startup_actions, daemon=True).start()

    # Create TCP server config
    config = TcpServerConfig(port=settings.port)

    try:
        start_server(config, handler, store_queue=store_queue, ready_event=ready_event)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        log_listener.stop()


def run():
    """Main entry point - parses args and runs with settings from env file."""
    args = parse_args()
    run_with_settings(load_settings_from_env(Path(args.env_file)))


def run_dev():
    """Run with .env.test settings."""
    run_with_settings(load_settings_from_env(Path(".env.test")))


def run_demo():
    """Run with .env.demo settings."""
    run_with_settings(load_settings_from_env(Path(".env.demo")))


def run_production():
    """Run with .env settings."""
    run_with_settings(load_settings_from_env(Path(".env")))


if __name__ == "__main__":
    run()
