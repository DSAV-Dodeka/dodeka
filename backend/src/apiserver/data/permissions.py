from dataclasses import dataclass
from typing import final

from freetser import Storage


@final
@dataclass(frozen=True)
class Permissions:
    MEMBER = "member"
    ADMIN = "admin"


@dataclass
class UserNotFoundError:
    user_id: str


all_permissions = {Permissions.MEMBER, Permissions.ADMIN}


def allowed_permission(permission: str) -> bool:
    return permission in all_permissions


year_time = 86400 * 365


def read_permissions(
    store: Storage, timestamp: int, user_id: str
) -> set[str] | UserNotFoundError:
    if store.get("users", f"{user_id}:email") is None:
        return UserNotFoundError(user_id=user_id)

    permissions = set()
    for perm_name in all_permissions:
        result = store.get("users", f"{user_id}:perm:{perm_name}", timestamp=timestamp)
        if result is not None:
            permissions.add(perm_name)

    return permissions


def add_permission(
    store: Storage, timestamp: int, user_id: str, permission_name: str
) -> None | UserNotFoundError:
    if store.get("users", f"{user_id}:email") is None:
        return UserNotFoundError(user_id=user_id)

    assert allowed_permission(permission_name)

    expires_at = timestamp + year_time
    perm_key = f"{user_id}:perm:{permission_name}"

    result = store.get("users", perm_key)
    if result is None:
        store.add(
            "users",
            perm_key,
            b"",
            expires_at=expires_at,
            timestamp=timestamp,
        )
    else:
        _, counter = result
        store.update(
            "users",
            perm_key,
            b"",
            counter,
            expires_at=expires_at,
        )

    return None


def remove_permission(
    store: Storage, user_id: str, permission_name: str
) -> None | UserNotFoundError:
    """Remove a permission from a user."""
    if store.get("users", f"{user_id}:email") is None:
        return UserNotFoundError(user_id=user_id)

    assert allowed_permission(permission_name)

    perm_key = f"{user_id}:perm:{permission_name}"
    store.delete("users", perm_key)

    return None
