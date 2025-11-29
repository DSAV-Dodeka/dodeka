import json
from dataclasses import dataclass

from hfree import Storage
from tiauth_faroe.client import ActionErrorResult

from apiserver.data.client import AuthClient
from apiserver.data.permissions import parse_permissions


@dataclass
class SessionUser:
    user_id: str
    email: str
    firstname: str
    lastname: str
    permissions: set[str]


def get_session_user(
    store: Storage, timestamp: int, user_id: str
) -> SessionUser | None:
    """Get member information for a given user_id."""
    # Read user data from separate keys
    profile_result = store.get("users", f"{user_id}:profile")
    email_result = store.get("users", f"{user_id}:email")
    permissions_result = store.get("users", f"{user_id}:permissions")

    if profile_result is None or email_result is None:
        return None

    # Parse profile
    profile_bytes, _ = profile_result
    profile_data = json.loads(profile_bytes.decode("utf-8"))
    firstname = profile_data["firstname"]
    lastname = profile_data["lastname"]

    # Parse email
    email_bytes, _ = email_result
    email = email_bytes.decode("utf-8")

    # Parse permissions
    if permissions_result:
        permissions_bytes, _ = permissions_result
    else:
        permissions_bytes = b""
    permissions_str = permissions_bytes.decode("utf-8")
    permissions = parse_permissions(timestamp, permissions_str)

    return SessionUser(
        user_id=user_id,
        email=email,
        firstname=firstname,
        lastname=lastname,
        permissions=set(permissions.keys()),
    )


@dataclass
class SessionInfo:
    user: SessionUser
    created_at: int
    expires_at: int | None


class InvalidSession:
    pass


def get_session(
    store: Storage, client: AuthClient, timestamp: int, session_token: str
) -> SessionInfo | InvalidSession:
    """Get session info and return non-expired permissions set."""
    session_result = client.get_session(session_token)

    if isinstance(session_result, ActionErrorResult):
        if session_result.error_code != "invalid_session_token":
            invocation_id = session_result.action_invocation_id
            error_code = session_result.error_code
            raise ValueError(
                f"Error getting session from auth server "
                f"(invocation {invocation_id}): {error_code}."
            )
        return InvalidSession()

    user_id = session_result.session.user_id
    user = get_session_user(store, timestamp, user_id)

    if user is None:
        return InvalidSession()

    return SessionInfo(
        user=user,
        created_at=session_result.session.created_at,
        expires_at=session_result.session.expires_at,
    )
