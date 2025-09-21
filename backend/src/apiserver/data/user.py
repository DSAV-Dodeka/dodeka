from pydantic import BaseModel
from sqlalchemy import text
from tiauth_faroe.client import ActionErrorResult
from apiserver.data.client import AuthClient
from starlette.concurrency import run_in_threadpool
from apiserver.data import Db
from apiserver.data.model import UserTable
from apiserver.data.permissions import parse_permissions

class SessionUser(BaseModel):
    user_id: str
    email: str
    firstname: str
    lastname: str
    permissions: set[str]


def get_session_user(db: Db, timestamp: int, user_id: str) -> SessionUser|None:
    """Get member information for a given user_id."""
    with db.engine.connect() as conn:
        stmt = text(f"""
            SELECT {UserTable.EMAIL}, {UserTable.FIRSTNAME}, {UserTable.LASTNAME}, {UserTable.PERMISSIONS}
            FROM {UserTable.NAME}
            WHERE {UserTable.ID} = :user_id
        """)

        result = conn.execute(stmt, {"user_id": user_id})
        row = result.first()

        if row is None:
            return None

        permissions_str = getattr(row, UserTable.PERMISSIONS)
        permissions = parse_permissions(timestamp, permissions_str)

        return SessionUser(
            user_id=user_id,
            email=getattr(row, UserTable.EMAIL),
            firstname=getattr(row, UserTable.FIRSTNAME),
            lastname=getattr(row, UserTable.LASTNAME),
            permissions=set(permissions.keys())
        )

class SessionInfo(BaseModel):
    user: SessionUser
    created_at: int
    expires_at: int | None

class InvalidSession:
    pass

# Async version for use in dependencies
async def get_session(db: Db, client: AuthClient, timestamp: int, session_token: str) -> SessionInfo | InvalidSession:
    """Get session info and return non-expired permissions set."""
    session_result = await client.get_session(session_token)

    if isinstance(session_result, ActionErrorResult):
        if session_result.error_code != 'invalid_session_token':
            raise ValueError(f"Error getting session from auth server (invocation {session_result.action_invocation_id}): {session_result.error_code}.")
        return InvalidSession()

    user_id = session_result.session.user_id
    user = await run_in_threadpool(get_session_user, db, timestamp, user_id)

    if user is None:
        return InvalidSession()

    return SessionInfo(
        user=user,
        created_at=session_result.session.created_at,
        expires_at=session_result.session.expires_at
    )
