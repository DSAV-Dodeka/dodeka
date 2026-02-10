import enum
import json
import logging
import logging.handlers
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
    Permissions,
    UserNotFoundError,
    add_permission,
    allowed_permission,
    get_all_permissions,
    read_permissions,
    remove_permission,
)
from apiserver.data.registration_state import (
    RegistrationStateNotFound,
    clear_notify_on_completion,
    create_registration_state,
    get_email_send_count_by_email,
    get_notify_on_completion,
    get_registration_state,
    get_registration_token_by_email,
    get_signup_token_by_email,
    mark_registration_state_accepted,
    update_registration_state_signup_token,
)
from apiserver.data.user import (
    CachedSessionData,
    InvalidSession,
    SessionInfo,
    get_cached_session,
    get_user_info,
    list_all_users,
    update_session_cache,
)
from apiserver.email import EmailData, sendemail
from apiserver.data import DB_TABLES
from apiserver.data.userdata import list_birthdays
from apiserver.private import (
    bootstrap_admin_on_startup,
    create_private_handler,
    do_accept_new_with_email,
    start_private_server,
)
from apiserver.settings import Settings, SmtpConfig, load_settings_from_env, parse_args
from apiserver.sync import (
    compute_groups,
    import_sync,
    list_system_users,
    parse_csv,
    remove_departed,
    serialize_groups,
    update_existing,
)
from apiserver.tokens import TokenWaiter, get_token

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


@dataclass
class InvalidHeaders:
    pass


@dataclass(frozen=True)
class CsrfRejected:
    """Cross-origin request rejected by CSRF protection."""

    reason: str


def check_csrf(
    method: str,
    headers: dict[str, str],
    trusted_origins: list[str],
) -> CsrfRejected | None:
    """Check cross-origin request forgery protection.

    Implements Filippo Valsorda's algorithm ("Protecting against CSRF in 2025"):
    1. Allow safe methods (GET, HEAD, OPTIONS).
    2. If Origin matches trusted origins allow-list, allow.
    3. If Sec-Fetch-Site is present: allow same-origin/none, reject otherwise.
    4. If neither Sec-Fetch-Site nor Origin are present, allow (not a browser).
    5. If Origin host:port matches Host header, allow; otherwise reject.

    Returns None if allowed, CsrfRejected if blocked.
    """
    # 1. Safe methods never change state
    if method in ("GET", "HEAD", "OPTIONS"):
        return None

    origin = headers.get("origin")
    sec_fetch_site = headers.get("sec-fetch-site")

    # 2. Origin in trusted allow-list (simple string equality)
    if origin is not None and origin in trusted_origins:
        return None

    # 3. Sec-Fetch-Site present — browser-enforced, cannot be spoofed by JS
    if sec_fetch_site is not None:
        if sec_fetch_site in ("same-origin", "none"):
            return None
        return CsrfRejected(f"sec-fetch-site={sec_fetch_site}")

    # Sec-Fetch-Site is absent from here on

    # 4. Neither header present — not a (post-2020) browser request
    if origin is None:
        return None

    # 5. Origin present but not in allow-list, no Sec-Fetch-Site
    # (old browser or HTTP origin) — fall back to host comparison
    host = headers.get("host")
    if host is not None:
        parsed = urlparse(origin)
        origin_host = parsed.hostname or ""
        origin_port = parsed.port
        origin_host_port = (
            f"{origin_host}:{origin_port}" if origin_port else origin_host
        )
        if origin_host_port == host:
            return None

    return CsrfRejected(f"origin={origin}, host={host}")


def parse_headers(
    req_headers: list[tuple[bytes, bytes]],
) -> dict[str, str] | InvalidHeaders:
    """Parse request headers into a dict. If header keys occur multiple times, we
    use only the last one. Returns InvalidHeaders if headers contain non-UTF-8 bytes."""
    headers: dict[str, str] = {}
    try:
        for header_name, header_value in req_headers:
            headers[header_name.lower().decode("utf-8")] = header_value.decode("utf-8")
    except ValueError:
        logger.debug("Received request with non-utf-8 headers.")
        return InvalidHeaders()
    return headers


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
    smtp_config: SmtpConfig | None = None,
    smtp_send: bool = False,
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
    if isinstance(headers, InvalidHeaders):
        return Response.text("Invalid headers", status_code=400)

    def h_request_registration():
        return request_registration(auth_client, req, store_queue)

    def h_set_sess():
        return set_session(
            auth_client,
            req,
            headers,
            store_queue,
            smtp_config,
            smtp_send,
            frontend_origin,
        )

    def h_clear_sess():
        return clear_session(req, headers)

    def h_sess_info():
        return session_info(auth_client, req, headers, store_queue)

    def h_add_perm():
        return add_user_permission(req, store_queue)

    def h_remove_perm():
        return remove_user_permission(req, store_queue)

    def h_list_newusers():
        return list_newusers_handler(store_queue)

    def h_accept_user():
        return accept_user_handler(
            req, store_queue, frontend_origin, smtp_config, smtp_send
        )

    def h_get_reg_status():
        return get_registration_status_handler(req, store_queue)

    def h_lookup_registration():
        return lookup_registration_handler(req, store_queue)

    def h_get_sess_token():
        return get_session_token_handler(headers)

    def h_resend_signup_email():
        return resend_signup_email_handler(auth_client, req, store_queue)

    def h_renew_signup():
        return renew_signup_handler(auth_client, req, store_queue)

    def h_list_users():
        return list_users_handler(store_queue)

    def h_available_permissions():
        return available_permissions_handler()

    def h_set_permissions():
        return set_permissions_handler(req, store_queue)

    # Sync route handlers
    def h_import_sync():
        return import_sync_handler(req, store_queue)

    def h_sync_status():
        return sync_status_handler(store_queue)

    def h_accept_new_sync():
        return accept_new_sync_handler(
            req, store_queue, frontend_origin, smtp_config, smtp_send
        )

    def h_remove_departed():
        return remove_departed_handler(req, store_queue)

    def h_update_existing():
        return update_existing_handler(req, store_queue)

    def h_list_system_users():
        return list_system_users_handler(store_queue)

    def h_birthdays():
        return birthdays_handler(store_queue)

    # This table maps each route to a specific handler (the RouteEntry)
    route_table = {
        # Dodeka-specific actions related to auth
        "/auth/request_registration": {
            "POST": RouteEntry(h_request_registration, PermissionConfig.public())
        },
        "/auth/registration_status": {
            "POST": RouteEntry(h_get_reg_status, PermissionConfig.public())
        },
        "/auth/lookup_registration": {
            "POST": RouteEntry(h_lookup_registration, PermissionConfig.public())
        },
        "/auth/renew_signup": {
            "POST": RouteEntry(h_renew_signup, PermissionConfig.public())
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
        "/admin/list_users/": {
            "GET": RouteEntry(h_list_users, PermissionConfig.require("admin"))
        },
        "/admin/available_permissions/": {
            "GET": RouteEntry(
                h_available_permissions, PermissionConfig.require("admin")
            )
        },
        "/admin/set_permissions/": {
            "POST": RouteEntry(h_set_permissions, PermissionConfig.require("admin"))
        },
        "/admin/list_newusers/": {
            "GET": RouteEntry(h_list_newusers, PermissionConfig.require("admin"))
        },
        "/admin/resend_signup_email/": {
            "POST": RouteEntry(h_resend_signup_email, PermissionConfig.require("admin"))
        },
        # Sync operations
        "/admin/import_sync/": {
            "POST": RouteEntry(h_import_sync, PermissionConfig.require("admin"))
        },
        "/admin/sync_status/": {
            "GET": RouteEntry(h_sync_status, PermissionConfig.require("admin"))
        },
        "/admin/accept_new_sync/": {
            "POST": RouteEntry(h_accept_new_sync, PermissionConfig.require("admin"))
        },
        "/admin/remove_departed/": {
            "POST": RouteEntry(h_remove_departed, PermissionConfig.require("admin"))
        },
        "/admin/update_existing/": {
            "POST": RouteEntry(h_update_existing, PermissionConfig.require("admin"))
        },
        "/admin/list_system_users/": {
            "GET": RouteEntry(h_list_system_users, PermissionConfig.require("admin"))
        },
        # Member routes
        "/members/birthdays/": {
            "GET": RouteEntry(h_birthdays, PermissionConfig.require("member"))
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

    def add_cors(response: Response, credentials: bool = False) -> Response:
        """Add CORS headers to any response."""
        response.headers.append(
            (
                b"Access-Control-Allow-Origin",
                frontend_origin.encode("utf-8"),
            )
        )
        if credentials:
            response.headers.append((b"Access-Control-Allow-Credentials", b"true"))
        return response

    route = route_table.get(path)
    if route is None:
        logger.info(f"Route not found: {method} {path}")
        return add_cors(Response.text(f"Not Found: {method} {path}", status_code=404))

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
        return add_cors(Response.text(f"Not Found: {method} {path}", status_code=404))

    credentials = route_entry.needs_credentials()

    # Handle OPTIONS preflight for CORS (before auth - preflight has no cookies)
    if method == "OPTIONS":
        return handle_options_request(route, route_entry, frontend_origin)

    # CSRF protection (Filippo Valsorda's algorithm)
    csrf = check_csrf(method, headers, [frontend_origin])
    if csrf is not None:
        logger.warning(f"CSRF rejected: {method} {path} ({csrf.reason})")
        return add_cors(Response.text("Cross-origin request blocked", status_code=403))

    # Check access (permissions, etc.)
    if error := check_access(
        RouteData(entry=route_entry, method=method, path=path),
        headers,
        auth_client,
        store_queue,
    ):
        return add_cors(error, credentials)

    # It's only here the actual handler is called
    response = route_entry.handler()
    return add_cors(response, credentials)


def request_registration(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """
    Creates a new user registration request and immediately initiates Faroe signup.
    Returns both registration_token and signup_token so the user can verify
    their email and set a password right away (before admin approval).
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

    registration_token = result

    # Immediately create Faroe signup (sends verification email)
    signup_result = auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        logger.error(
            f"request_registration: Faroe signup failed for {email}: "
            f"{signup_result.error_code}"
        )
        # Registration was created but signup failed - return registration_token
        # without signup_token so user can retry via renew_signup
        return Response.json(
            {
                "success": True,
                "message": (
                    f"Registration created but signup failed:"
                    f" {signup_result.error_code}"
                ),
                "registration_token": registration_token,
                "signup_token": None,
            }
        )

    signup_token = signup_result.signup_token

    # Store signup_token in registration_state (without changing accepted)
    # Registration state was just created above, so this should always succeed
    token_result = store_queue.execute(
        lambda store: update_registration_state_signup_token(store, email, signup_token)
    )
    if isinstance(token_result, RegistrationStateNotFound):
        logger.error(f"request_registration: Registration state missing for {email}")

    logger.info(
        f"request_registration: Registered {email} with token {registration_token}"
    )
    return Response.json(
        {
            "success": True,
            "message": f"Registration request submitted for {email}",
            "registration_token": registration_token,
            "signup_token": signup_token,
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
            "notify_on_completion": state.notify_on_completion,
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


def lookup_registration_handler(req: Request, store_queue: StorageQueue) -> Response:
    """
    Handle /auth/lookup_registration.

    Look up registration token by email and verification code.
    Used when users don't have the direct link but have received the email.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        code = body_data.get("code")
        if not email or not code:
            logger.warning("lookup_registration: Missing email or code")
            return Response.text("Missing email or code", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"lookup_registration: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    def lookup(store: Storage) -> dict:
        # First verify the code matches what we have stored
        stored = get_token(store, "signup_verification", email)
        if stored is None or stored.get("code") != code:
            return {"found": False}

        # Code matches, get the registration token
        reg_token = get_registration_token_by_email(store, email)
        if reg_token is None:
            return {"found": False}

        return {"found": True, "token": reg_token}

    result = store_queue.execute(lookup)
    logger.info(f"lookup_registration: email={email}, found={result['found']}")
    return Response.json(result)


def list_newusers_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_newusers/ - lists all pending user registrations."""

    def list_users(store: Storage) -> list:
        users = list_new_users(store)
        result = []
        for user in users:
            is_registered = store.get("users_by_email", user.email) is not None
            reg_token = get_registration_token_by_email(store, user.email)
            result.append(
                {
                    "email": user.email,
                    "firstname": user.firstname,
                    "lastname": user.lastname,
                    "accepted": user.accepted,
                    "email_send_count": get_email_send_count_by_email(
                        store, user.email
                    ),
                    "has_signup_token": get_signup_token_by_email(store, user.email)
                    is not None,
                    "is_registered": is_registered,
                    "registration_token": reg_token,
                }
            )
        return result

    result = store_queue.execute(list_users)
    logger.info(f"list_newusers: Returning {len(result)} users")
    return Response.json(result)


def accept_user_handler(
    req: Request,
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> Response:
    """Handle /admin/accept_user/ - accept a user and send notification email.

    If the user already completed signup (exists in users table), grants member
    permission and sends acceptance notification with homepage link.
    Otherwise marks accepted=True on the newuser entry and sends acceptance
    email with link to create their account.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        if not email:
            logger.warning("accept_user: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"accept_user: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    timestamp = int(time.time())

    def accept(store: Storage) -> dict:
        # Check if user already completed signup (exists in users table)
        user_result = store.get("users_by_email", email)
        if user_result is not None:
            # User already has an account — grant member + clean up newuser
            user_id = user_result[0].decode("utf-8")
            add_permission(store, timestamp, user_id, Permissions.MEMBER)
            store.delete("newusers", email)
            return {
                "success": True,
                "has_account": True,
                "message": f"Member permission granted to {email}",
            }

        # User hasn't completed signup yet — mark accepted in newusers and
        # registration_state. Set notify_on_completion so set_session sends
        # the deferred acceptance email after signup completes.
        flag_result = update_accepted_flag(store, email, True)
        if isinstance(flag_result, EmailNotFoundInNewUserTable):
            return {"error": f"Email {email} not found in newuser table"}

        reg_result = mark_registration_state_accepted(
            store, email, notify_on_completion=True
        )
        if isinstance(reg_result, RegistrationStateNotFound):
            return {"error": f"No registration state found for {email}"}

        reg_token = get_registration_token_by_email(store, email)

        # Get display name from newuser
        newuser_data = store.get("newusers", email)
        display_name = None
        if newuser_data is not None:
            data = json.loads(newuser_data[0].decode("utf-8"))
            display_name = data.get("firstname")

        return {
            "success": True,
            "has_account": False,
            "registration_token": reg_token,
            "display_name": display_name,
            "message": f"User {email} marked as accepted (pending signup completion)",
        }

    result = store_queue.execute(accept)
    if "error" in result:
        logger.warning(f"accept_user: {result['error']}")
        return Response.json(result, status_code=400)

    # Send acceptance email only if user already has an account.
    # If they haven't completed signup yet, the email is deferred to
    # set_session via the notify_on_completion flag (Scenario 1).
    if result.get("has_account"):
        try:
            link = frontend_origin
            email_data = EmailData(
                email_type="account_accepted_self",
                to_email=email,
                display_name=result.get("display_name"),
                link=link,
            )
            sendemail(smtp_config, email_data, smtp_send)
        except Exception as exc:
            logger.error(
                f"accept_user: Failed to send acceptance email to {email}: {exc}"
            )

    logger.info(f"accept_user: {result['message']}")
    return Response.json(result)


def resend_signup_email_handler(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /admin/resend_signup_email/ - (re)sends signup verification email.

    Faroe signups expire after ~20 minutes.  If the stored signup_token is
    stale or was never created (accept_new without signup), a new signup is
    created in Faroe and the token is updated in registration_state.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email = body_data.get("email")
        if not email:
            logger.warning("resend_signup_email: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"resend_signup_email: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Verify user has a registration state (was accepted through the newuser flow)
    def get_tokens(store: Storage) -> tuple[str | None, str | None]:
        return (
            get_signup_token_by_email(store, email),
            get_registration_token_by_email(store, email),
        )

    signup_token, registration_token = store_queue.execute(get_tokens)

    if registration_token is None:
        logger.warning(f"resend_signup_email: No registration found for {email}")
        return Response.json(
            {"error": f"No registration found for {email}"}, status_code=404
        )

    # Try resending with existing token (fast path when signup is still active)
    if signup_token is not None:
        result = auth_client.send_signup_email_address_verification_code(signup_token)
        if not isinstance(result, ActionErrorResult):
            logger.info(f"resend_signup_email: Resent verification email to {email}")
            return Response.json(
                {"success": True, "message": f"Email resent to {email}"}
            )
        logger.info(
            f"resend_signup_email: Token invalid ({result.error_code}), "
            f"creating new signup for {email}"
        )

    # Create new signup — Faroe sends the verification email automatically
    signup_result = auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        logger.error(
            f"resend_signup_email: Failed to create signup for "
            f"{email}: {signup_result.error_code}"
        )
        return Response.json(
            {
                "error": "Failed to initiate signup",
                "error_code": signup_result.error_code,
            },
            status_code=400,
        )

    # Store the new token so the next resend can try the fast path
    new_token = signup_result.signup_token
    token_result = store_queue.execute(
        lambda store: update_registration_state_signup_token(store, email, new_token)
    )
    if isinstance(token_result, RegistrationStateNotFound):
        logger.error(f"resend_signup_email: Registration state missing for {email}")

    logger.info(f"resend_signup_email: New signup created, email sent to {email}")
    return Response.json({"success": True, "message": f"Signup email sent to {email}"})


def renew_signup_handler(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /auth/renew_signup - renew an expired Faroe signup.

    Called by the frontend when email verification fails with invalid_signup_token.
    Takes the registration_token (from the signup URL) as authentication.
    Creates a new Faroe signup (which auto-sends a new verification email)
    and updates the stored signup_token.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        registration_token = body_data.get("registration_token")
        if not registration_token:
            return Response.text("Missing registration_token", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Look up registration state (uses registration_token as key)
    state = store_queue.execute(
        lambda store: get_registration_state(store, registration_token)
    )
    if state is None:
        return Response.json({"error": "Registration not found"}, status_code=404)

    email = state.email

    # Create new Faroe signup — sends verification email automatically
    signup_result = auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        logger.error(f"renew_signup: Failed for {email}: {signup_result.error_code}")
        return Response.json(
            {
                "error": "Failed to create signup",
                "error_code": signup_result.error_code,
            },
            status_code=400,
        )

    new_token = signup_result.signup_token
    token_result = store_queue.execute(
        lambda store: update_registration_state_signup_token(store, email, new_token)
    )
    if isinstance(token_result, RegistrationStateNotFound):
        logger.error(f"renew_signup: Registration state missing for {email}")

    logger.info(f"renew_signup: New signup created for {email}")
    return Response.json({"success": True, "signup_token": new_token, "email": email})


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
            store,
            session_token,
            session.user_id,
            session.created_at,
            session.expires_at,
            timestamp,
        )

    store_queue.execute(update_cache)
    return ValidatedSession(session.user_id, session.created_at, session.expires_at)


def set_session(
    auth_client: AuthClient,
    req: Request,
    headers: dict[str, str],
    store_queue: StorageQueue,
    smtp_config: SmtpConfig | None = None,
    smtp_send: bool = False,
    frontend_origin: str = "",
) -> Response:
    """Handle /auth/set_session/ - validates and sets session cookie.

    Also handles deferred acceptance emails (Scenario 1): if the user was
    accepted before completing signup, notify_on_completion is set in their
    registration state. On the first set_session after signup completes,
    this function detects the flag, sends the account_accepted_self email,
    and clears it.

    Request body:
        session_token: The session token to set
        secondary: Optional boolean, if true sets the secondary session cookie
    """
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

    # Check for deferred acceptance email (Scenario 1)
    def check_and_clear_notify(store: Storage) -> tuple[bool, str | None]:
        user_info = get_user_info(store, int(time.time()), result.user_id)
        if user_info is None:
            return False, None
        email = user_info.email
        if get_notify_on_completion(store, email):
            clear_notify_on_completion(store, email)
            return True, email
        return False, None

    should_notify, user_email = store_queue.execute(check_and_clear_notify)
    if should_notify and user_email:
        try:
            link = frontend_origin
            email_data = EmailData(
                email_type="account_accepted_self",
                to_email=user_email,
                link=link,
            )
            sendemail(smtp_config, email_data, smtp_send)
            logger.info(f"set_session: Sent deferred acceptance email to {user_email}")
        except Exception as exc:
            logger.error(
                f"set_session: Failed to send deferred email to {user_email}: {exc}"
            )

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


def clear_session(req: Request, headers: dict[str, str]) -> Response:
    """Handle /auth/clear_session/ - clears session cookie.

    Request body (optional):
        secondary: Optional boolean, if true clears the secondary session cookie
    """
    # Parse optional body for secondary flag
    secondary = False
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            secondary = body_data.get("secondary", False)
        except json.JSONDecodeError, ValueError:
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
    def get_session_data(
        store: Storage,
    ) -> tuple[SessionInfo, bool] | InvalidSession:
        user = get_user_info(store, timestamp, result.user_id)
        if user is None:
            return InvalidSession()
        pending = store.get("newusers", user.email) is not None
        return (
            SessionInfo(
                user=user,
                created_at=result.created_at,
                expires_at=result.expires_at,
            ),
            pending,
        )

    session_result = store_queue.execute(get_session_data)

    if isinstance(session_result, InvalidSession):
        logger.warning(f"session_info: User {result.user_id} not found")
        return Response.json(
            {"error": "invalid_session"},
            status_code=401,
            headers=[make_clear_session_cookie_header(cookie_name)],
        )

    session, pending_approval = session_result

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
            "pending_approval": pending_approval,
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


def list_users_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_users/ - lists all users with their permissions."""
    timestamp = int(time.time())

    def get_users(store: Storage) -> list[dict]:
        users = list_all_users(store, timestamp)
        return [
            {
                "user_id": u.user_id,
                "email": u.email,
                "firstname": u.firstname,
                "lastname": u.lastname,
                "permissions": sorted(u.permissions),
            }
            for u in users
        ]

    result = store_queue.execute(get_users)
    logger.info(f"list_users: Returning {len(result)} users")
    return Response.json(result)


def available_permissions_handler() -> Response:
    """Handle /admin/available_permissions/ - lists all valid permissions."""
    permissions = get_all_permissions()
    return Response.json({"permissions": permissions})


def set_permissions_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/set_permissions/ - declaratively set permissions for users.

    Request body (JSON):
        {
            "permissions": {
                "user_id_1": ["permission1", "permission2"],
                "user_id_2": ["permission3"],
                ...
            }
        }

    This will set each user's permissions to exactly the list provided,
    adding missing permissions and removing extra ones (except 'admin').
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        permissions_map = body_data.get("permissions")
        if not permissions_map or not isinstance(permissions_map, dict):
            logger.warning("set_permissions: Missing or invalid permissions map")
            return Response.text("Missing permissions map", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"set_permissions: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    # Validate all permissions first
    for user_id, perms in permissions_map.items():
        if not isinstance(perms, list):
            return Response.text(
                f"Permissions for {user_id} must be a list", status_code=400
            )
        for perm in perms:
            if not allowed_permission(perm):
                return Response.text(f"Invalid permission: {perm}", status_code=400)
            if perm == "admin":
                return Response.text(
                    "Cannot set admin permission via this endpoint", status_code=403
                )

    timestamp = int(time.time())
    results: dict[str, dict] = {}

    def apply_permissions(store: Storage) -> None:
        for user_id, target_perms in permissions_map.items():
            target_set = set(target_perms)

            # Get current permissions (excluding admin)
            current = read_permissions(store, timestamp, user_id)
            if isinstance(current, UserNotFoundError):
                results[user_id] = {"error": "user_not_found"}
                continue

            # Don't touch admin permission
            current_non_admin = current - {"admin"}
            target_non_admin = target_set - {"admin"}

            # Calculate changes
            to_add = target_non_admin - current_non_admin
            to_remove = current_non_admin - target_non_admin

            # Apply changes
            for perm in to_add:
                add_permission(store, timestamp, user_id, perm)
            for perm in to_remove:
                remove_permission(store, user_id, perm)

            results[user_id] = {
                "added": sorted(to_add),
                "removed": sorted(to_remove),
            }

    store_queue.execute(apply_permissions)
    logger.info(f"set_permissions: Updated {len(results)} users")
    return Response.json({"results": results})


def import_sync_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/import_sync/ - import CSV content into sync table."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        csv_content = body_data.get("csv_content")
        if not csv_content:
            return Response.text("Missing csv_content", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    entries = parse_csv(csv_content)
    count = store_queue.execute(lambda store: import_sync(store, entries))
    logger.info(f"import_sync: Imported {count} entries")
    return Response.json({"imported": count})


def sync_status_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/sync_status/ - compute and return sync groups."""
    result = store_queue.execute(lambda store: serialize_groups(compute_groups(store)))
    logger.info(
        f"sync_status: {len(result['to_accept'])} to_accept, "
        f"{len(result['pending_signup'])} pending_signup, "
        f"{len(result['existing'])} existing, "
        f"{len(result['departed'])} departed"
    )
    return Response.json(result)


def accept_new_sync_handler(
    req: Request,
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> Response:
    """Handle /admin/accept_new_sync/ - accept new users and send acceptance emails."""
    email = None
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            email = body_data.get("email")
        except json.JSONDecodeError, ValueError:
            pass
    result = do_accept_new_with_email(
        store_queue, frontend_origin, smtp_config, smtp_send, email
    )
    return Response.json(result)


def remove_departed_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/remove_departed/ - remove departed users."""
    email = None
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            email = body_data.get("email")
        except json.JSONDecodeError, ValueError:
            pass
    timestamp = int(time.time())
    result = store_queue.execute(lambda store: remove_departed(store, timestamp, email))
    logger.info(f"remove_departed: {result}")
    return Response.json(result)


def update_existing_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /admin/update_existing/ - update existing user data from sync."""
    email = None
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            email = body_data.get("email")
        except json.JSONDecodeError, ValueError:
            pass
    result = store_queue.execute(lambda store: update_existing(store, email))
    logger.info(f"update_existing: {result}")
    return Response.json(result)


def list_system_users_handler(store_queue: StorageQueue) -> Response:
    """Handle /admin/list_system_users/ - list system users."""
    users = store_queue.execute(list_system_users)
    return Response.json({"system_users": users})


def birthdays_handler(store_queue: StorageQueue) -> Response:
    """Handle /members/birthdays/ - list all member birthdays."""
    result = store_queue.execute(list_birthdays)
    logger.info(f"birthdays: Returning {len(result)} entries")
    return Response.json(result)


def get_session_token_handler(headers: dict[str, str]) -> Response:
    """Handle /cookies/session_token/ - returns session token from primary cookie."""
    session_token = get_cookie_value(headers, SESSION_COOKIE_PRIMARY)

    if session_token is None:
        logger.debug("get_session_token: No session cookie found")
        return Response.json({"error": "no_session"}, status_code=401)

    logger.debug("get_session_token: Returning session token")
    return Response.json({"session_token": session_token})


class PrefixFormatter(logging.Formatter):
    """Wraps an existing formatter, prepending a prefix to each line."""

    def __init__(self, prefix: str, base: logging.Formatter | None):
        super().__init__()
        self.prefix = prefix
        self.base = base

    def format(self, record: logging.LogRecord) -> str:
        msg = self.base.format(record) if self.base else super().format(record)
        return f"{self.prefix} {msg}"


def configure_logging(
    log_listener: logging.handlers.QueueListener,
    debug_logs: bool,
    log_prefix: str,
) -> None:
    """Configure log level and optional prefix on the listener's handlers."""
    log_level = logging.DEBUG if debug_logs else logging.INFO
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for h in root_logger.handlers:
        h.setLevel(log_level)

    # Set prefix on the QueueListener's console handler (not the QueueHandler).
    # Setting it on the QueueHandler would bake the prefix into the message
    # before the console handler adds [threadName], producing
    # "[Thread-1] [backend] msg" instead of the desired "[backend] [Thread-1] msg".
    if log_prefix:
        for h in log_listener.handlers:
            h.setFormatter(PrefixFormatter(log_prefix, h.formatter))


def run_with_settings(
    settings: Settings,
    *,
    log_prefix: str = "",
    ready_event: threading.Event | None = None,
):
    log_listener = setup_logging()
    log_listener.start()
    configure_logging(log_listener, settings.debug_logs, log_prefix)

    logger.info(
        f"Running with settings:\n\t- frontend_origin={settings.frontend_origin}"
        f"\n\t- debug_logs={settings.debug_logs}"
        f"\n\t- port={settings.port}"
        f"\n\t- private_port={settings.private_port}"
    )

    auth_client = AuthClient(settings.auth_server_url)

    store_queue = start_storage_thread(
        db_file=str(settings.db_file),
        db_tables=DB_TABLES,
    )

    token_waiter = TokenWaiter(store_queue)

    # Start private TCP server on 127.0.0.2 (Go and CLI connect to this)
    private_handler = create_private_handler(
        store_queue,
        token_waiter,
        settings.frontend_origin,
        settings.smtp,
        settings.smtp_send,
        auth_client,
    )
    start_private_server(settings.private_port, private_handler, store_queue)

    def handler(req: Request, store_queue: StorageQueue | None) -> Response:
        return handler_with_client(
            auth_client,
            req,
            store_queue,
            settings.frontend_origin,
            settings.smtp,
            settings.smtp_send,
        )

    if ready_event is None:
        ready_event = threading.Event()

    threading.Thread(
        target=bootstrap_admin_on_startup,
        args=(ready_event, token_waiter, settings.auth_server_url, store_queue),
        daemon=True,
    ).start()

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


def run_test():
    """Run only the Python backend with test environment settings."""
    run_with_settings(load_settings_from_env(Path("envs/test/.env")))


def run_demo():
    """Run with demo environment settings."""
    run_with_settings(load_settings_from_env(Path("envs/demo/.env")))


def run_production():
    """Run with production environment settings."""
    run_with_settings(load_settings_from_env(Path("envs/production/.env")))


if __name__ == "__main__":
    run()
