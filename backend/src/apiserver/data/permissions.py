
from dataclasses import dataclass
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from tiauth_faroe.client import ActionErrorResult
from apiserver.data.client import AuthClient
from starlette.concurrency import run_in_threadpool
from .model import UserTable
from .db import Db


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

            return parse_permissions(timestamp, getattr(row, UserTable.PERMISSIONS))

    except SQLAlchemyError:
        raise ValueError("Database error occurred")


def add_permission(db: Db, timestamp: int, user_id: str, permission_name: str)  -> None:
    """Add or update a permission for a user with the given timestamp."""
    try:
        with db.engine.begin() as conn:
            current_perms = read_permissions(db, timestamp, user_id)

            # Update or add the new permission
            new_perms_dict = current_perms | {permission_name: timestamp}

            new_perms = serialize_permissions(new_perms_dict)

            # Update the database
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

    except SQLAlchemyError as e:
        raise ValueError(f"Database error occurred: {str(e)}")

@dataclass
class UserSession:
    user_id: str
    permissions: set[str]


# Async version for use in dependencies
async def get_session(db: Db, client: AuthClient, timestamp: int, session_token: str) -> UserSession:
    """Get session info and return non-expired permissions set."""
    session_result = await client.get_session(session_token)

    if isinstance(session_result, ActionErrorResult):
        raise ValueError(f"Session error: {session_result.error_code}")

    user_id = session_result.session.user_id
    permissions_dict = await run_in_threadpool(read_permissions, db, timestamp, user_id)

    return UserSession(user_id, set(permissions_dict.keys()))
