import json
from dataclasses import dataclass

from hfree import Storage

from apiserver.data.permissions import UserNotFoundError, read_permissions


@dataclass
class UserData:
    """Basic user data without permissions."""

    user_id: str
    email: str
    firstname: str
    lastname: str


@dataclass
class UserNotFound:
    user_id: str


def get_user(store: Storage, user_id: str) -> UserData | UserNotFound:
    """Get basic user information for a given user_id."""
    # Read user data from separate keys
    profile_result = store.get("users", f"{user_id}:profile")
    email_result = store.get("users", f"{user_id}:email")

    if profile_result is None or email_result is None:
        return UserNotFound(user_id=user_id)

    # Parse profile
    profile_bytes, _ = profile_result
    profile_data = json.loads(profile_bytes.decode("utf-8"))

    # Parse email
    email_bytes, _ = email_result
    email = email_bytes.decode("utf-8")

    return UserData(
        user_id=user_id,
        email=email,
        firstname=profile_data["firstname"],
        lastname=profile_data["lastname"],
    )


@dataclass
class UserInfo:
    """User information including permissions."""

    user_id: str
    email: str
    firstname: str
    lastname: str
    permissions: set[str]


def get_user_info(store: Storage, timestamp: int, user_id: str) -> UserInfo | None:
    """Get user information including permissions for a given user_id."""
    user = get_user(store, user_id)
    if isinstance(user, UserNotFound):
        return None

    # Get permissions (returns empty set if user has no permissions)
    permissions_result = read_permissions(store, timestamp, user_id)
    if isinstance(permissions_result, UserNotFoundError):
        permissions = set()
    else:
        permissions = permissions_result

    return UserInfo(
        user_id=user.user_id,
        email=user.email,
        firstname=user.firstname,
        lastname=user.lastname,
        permissions=permissions,
    )


@dataclass
class CachedSessionData:
    """Cached session information."""

    user_id: str
    created_at: int
    expires_at: int | None


def get_cached_session(
    store: Storage, session_token: str, timestamp: int
) -> CachedSessionData | None:
    """Get cached session data if it exists and is not expired."""
    result = store.get("session_cache", session_token, timestamp=timestamp)
    if result is None:
        return None

    cache_bytes, _ = result
    cache_json = json.loads(cache_bytes.decode("utf-8"))

    return CachedSessionData(
        user_id=cache_json["user_id"],
        created_at=cache_json["created_at"],
        expires_at=cache_json.get("expires_at"),
    )


SESSION_CACHE_EXPIRY = 2 * 60 * 60


def update_session_cache(
    store: Storage,
    session_token: str,
    user_id: str,
    created_at: int,
    expires_at: int | None,
    timestamp: int,
):
    """Update session cache with 2-hour expiration."""
    cache_expires_at = timestamp + SESSION_CACHE_EXPIRY

    cache_data = {
        "user_id": user_id,
        "created_at": created_at,
        "expires_at": expires_at,
    }
    cache_bytes = json.dumps(cache_data).encode("utf-8")

    result = store.get("session_cache", session_token)
    if result is None:
        store.add(
            "session_cache",
            session_token,
            cache_bytes,
            expires_at=cache_expires_at,
            timestamp=timestamp,
        )
    else:
        _, counter = result
        store.update(
            "session_cache",
            session_token,
            cache_bytes,
            counter,
            expires_at=cache_expires_at,
        )


@dataclass
class SessionInfo:
    """Session information including user data, creation and expiration times."""

    user: UserInfo
    created_at: int
    expires_at: int | None


class InvalidSession:
    pass
