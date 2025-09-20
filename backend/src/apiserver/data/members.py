from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from pydantic import BaseModel
from .model import UserTable
from .db import Db


class MemberData(BaseModel):
    user_id: str
    email: str
    firstname: str
    lastname: str


def get_member(db: Db, user_id: str) -> MemberData:
    """Get member information for a given user_id."""
    try:
        with db.engine.connect() as conn:
            stmt = text(f"""
                SELECT {UserTable.EMAIL}, {UserTable.FIRSTNAME}, {UserTable.LASTNAME}
                FROM {UserTable.NAME}
                WHERE {UserTable.ID} = :user_id
            """)

            result = conn.execute(stmt, {"user_id": user_id})
            row = result.first()

            if row is None:
                raise ValueError("User not found")

            return MemberData(
                user_id=user_id,
                email=getattr(row, UserTable.EMAIL),
                firstname=getattr(row, UserTable.FIRSTNAME),
                lastname=getattr(row, UserTable.LASTNAME)
            )

    except SQLAlchemyError:
        raise ValueError("Database error occurred")
