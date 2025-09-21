from dataclasses import dataclass
from typing import final
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from .model import UserTable
from .db import Db

@final
@dataclass(frozen=True)
class Permissions:
    MEMBER = "member"
    ADMIN = "admin"

def allowed_permission(permission: str) -> bool:
    return permission == Permissions.MEMBER or permission == Permissions.ADMIN

def parse_permissions(timestamp: int, permissions: str) -> dict[str, int]:
    perms_split = permissions.split(' ')
    perms_dict: dict[str, int] = {}
    for perm in perms_split:
        spl = perm.split(':')
        if len(spl) != 2:
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
    return " ".join([f"{perm_item[0]}:{perm_item[1]}" for perm_item in permissions.items()])


def read_permissions(db: Db, timestamp: int, user_id: str) -> dict[str, int]:
    """Read permissions string for a given user_id."""
    try:
        with db.engine.connect() as conn:
            stmt = text(f"""
                SELECT {UserTable.PERMISSIONS}
                FROM {UserTable.NAME}
                WHERE {UserTable.ID} = :user_id
            """)

            result = conn.execute(stmt, {"user_id": user_id})
            row = result.first()

            if row is None:
                raise ValueError("User not found")

            print(f"permissions={getattr(row, UserTable.PERMISSIONS)}")

            return parse_permissions(timestamp, getattr(row, UserTable.PERMISSIONS))

    except SQLAlchemyError:
        raise ValueError("Database error occurred")

year_time = 86400 * 365


def add_permission(db: Db, now_timestamp: int, user_id: str, permission_name: str)  -> None:
    """Add or update a permission for a user with the given timestamp."""
    with db.engine.begin() as conn:
        current_perms = read_permissions(db, now_timestamp, user_id)

        expires_timestamp = now_timestamp + year_time

        # Update or add the new permission
        new_perms_dict = current_perms | {permission_name: expires_timestamp}

        new_perms = serialize_permissions(new_perms_dict)

        update_stmt = text(f"""
            UPDATE {UserTable.NAME}
            SET {UserTable.PERMISSIONS} = :permissions
            WHERE {UserTable.ID} = :user_id
        """)

        result = conn.execute(update_stmt, {
            "permissions": new_perms,
            "user_id": user_id
        })

        if result.rowcount == 0:
            raise ValueError("User not found")
