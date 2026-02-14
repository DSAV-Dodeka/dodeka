"""HTTP framework: CSRF, CORS, routing, session validation, permissions.

Provides the infrastructure that handlers in ``handlers/`` depend on.
Application-specific route tables and startup live in ``app.py``.
"""

import enum
import logging
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Callable, Literal
from urllib.parse import urlparse

from freetser import Response, Storage
from freetser.server import StorageQueue
from tiauth_faroe.client import ActionErrorResult

from apiserver.data.client import AuthClient
from apiserver.data.user import (
    CachedSessionData,
    get_cached_session,
    get_user_info,
    update_session_cache,
)

logger = logging.getLogger("apiserver.server")

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
