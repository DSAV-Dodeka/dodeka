from dataclasses import dataclass
from typing import final

from hfree import Storage


@final
@dataclass(frozen=True)
class Permissions:
    MEMBER = "member"
    ADMIN = "admin"


@dataclass
class UserNotFoundError:
    user_id: str


def allowed_permission(permission: str) -> bool:
    return permission in {Permissions.MEMBER, Permissions.ADMIN}


def parse_permissions(timestamp: int, permissions: str) -> dict[str, int]:
    perms_split = permissions.split(" ")
    perms_dict: dict[str, int] = {}
    for perm in perms_split:
        spl = perm.split(":")
        if len(spl) != 2:  # noqa: PLR2004
            continue
        perm_name = spl[0]
        try:
            perm_expiration = int(spl[1])
        except ValueError:
            continue

        if perm_expiration < timestamp:
            continue

        perms_dict[perm_name] = perm_expiration

    return perms_dict


def serialize_permissions(permissions: dict[str, int]) -> str:
    return " ".join(
        [f"{perm_item[0]}:{perm_item[1]}" for perm_item in permissions.items()]
    )


def read_permissions(
    store: Storage, timestamp: int, user_id: str
) -> dict[str, int] | UserNotFoundError:
    """Read permissions string for a given user_id."""
    result = store.get("users", f"{user_id}:permissions")
    if result is None:
        return UserNotFoundError(user_id=user_id)

    permissions_bytes, _ = result
    permissions_str = permissions_bytes.decode("utf-8")
    print(f"permissions={permissions_str}")

    return parse_permissions(timestamp, permissions_str)


year_time = 86400 * 365


def add_permission(
    store: Storage, now_timestamp: int, user_id: str, permission_name: str
) -> None | UserNotFoundError:
    """Add or update a permission for a user with the given timestamp."""
    # Get current permissions with counter
    result = store.get("users", f"{user_id}:permissions")
    if result is None:
        return UserNotFoundError(user_id=user_id)

    permissions_bytes, counter = result
    permissions_str = permissions_bytes.decode("utf-8")

    # Read current permissions
    current_perms = parse_permissions(now_timestamp, permissions_str)

    expires_timestamp = now_timestamp + year_time

    # Update or add the new permission
    new_perms_dict = current_perms | {permission_name: expires_timestamp}
    new_perms = serialize_permissions(new_perms_dict)

    # Update permissions key using hfree's native counter
    # assert_updated=True by default - will assert on concurrent modification
    store.update(
        "users",
        f"{user_id}:permissions",
        new_perms.encode("utf-8"),
        expires_at=0,
        counter=counter,
    )
    return None
