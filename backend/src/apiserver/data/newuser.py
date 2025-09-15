from dataclasses import dataclass
from typing import Union
import sqlalchemy as sqla
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from .model import UserTable, NewUserTable
from .db import Db


@dataclass
class NewUserError:
    error_code: str


@dataclass
class NewUser:
    email: str
    firstname: str
    lastname: str
    accepted: bool


NewUserResult = Union[NewUser, NewUserError, None]


def add_new_user(db: Db, email: str, firstname: str, lastname: str) -> NewUserResult:
    """
    Add a new user to the newuser table.
    Returns error if email already exists in either newuser or user table.
    """
    try:
        with db.engine.begin() as conn:
            # Check if email already exists in user table
            user_check_stmt = text(f"""
                SELECT COUNT(*) FROM {UserTable.NAME}
                WHERE {UserTable.EMAIL} = :email
            """)
            user_result = conn.execute(user_check_stmt, {"email": email})
            user_row = user_result.first()
            user_count = user_row[0] if user_row is not None else 0

            if user_count > 0:
                return NewUserError("email_already_exists")

            # Check if email already exists in newuser table
            newuser_check_stmt = text(f"""
                SELECT COUNT(*) FROM {NewUserTable.NAME}
                WHERE {NewUserTable.EMAIL} = :email
            """)
            newuser_result = conn.execute(newuser_check_stmt, {"email": email})
            newuser_row = newuser_result.first()
            newuser_count = newuser_row[0] if newuser_row is not None else 0

            if newuser_count > 0:
                return NewUserError("email_already_exists")

            # Insert new user into newuser table
            insert_stmt = text(f"""
                INSERT INTO {NewUserTable.NAME} (
                    {NewUserTable.EMAIL}, {NewUserTable.FIRSTNAME},
                    {NewUserTable.LASTNAME}, {NewUserTable.ACCEPTED}
                ) VALUES (
                    :email, :firstname, :lastname, :accepted
                )
            """)

            conn.execute(insert_stmt, {
                "email": email,
                "firstname": firstname,
                "lastname": lastname,
                "accepted": 0,  # Default to not accepted
            })

    except IntegrityError:
        # This shouldn't happen due to our checks, but handle it just in case
        return NewUserError("email_already_exists")
    except SQLAlchemyError:
        return NewUserError("unexpected_error")

    return NewUser(
        email=email,
        firstname=firstname,
        lastname=lastname,
        accepted=False,
    )


def update_accepted_flag(db: Db, email: str, accepted: bool) -> NewUserResult:
    """
    Update the accepted flag for a user in the newuser table.
    Returns error if user not found.
    """
    try:
        with db.engine.begin() as conn:
            update_stmt = text(f"""
                UPDATE {NewUserTable.NAME}
                SET {NewUserTable.ACCEPTED} = :accepted
                WHERE {NewUserTable.EMAIL} = :email
            """)

            result = conn.execute(update_stmt, {
                "email": email,
                "accepted": 1 if accepted else 0,
            })

            if result.rowcount == 0:
                return NewUserError("user_not_found")

            # Fetch the updated user to return
            select_stmt = text(f"""
                SELECT {NewUserTable.FIRSTNAME}, {NewUserTable.LASTNAME}, {NewUserTable.ACCEPTED}
                FROM {NewUserTable.NAME}
                WHERE {NewUserTable.EMAIL} = :email
            """)

            select_result = conn.execute(select_stmt, {"email": email})
            row = select_result.first()

            if row is None:
                return NewUserError("user_not_found")

            firstname = getattr(row, NewUserTable.FIRSTNAME)
            lastname = getattr(row, NewUserTable.LASTNAME)
            updated_accepted = bool(getattr(row, NewUserTable.ACCEPTED))

    except SQLAlchemyError:
        return NewUserError("unexpected_error")

    return NewUser(
        email=email,
        firstname=firstname,
        lastname=lastname,
        accepted=updated_accepted,
    )


def list_new_users(db: Db) -> Union[list[NewUser], NewUserError]:
    """
    List all new users.
    """
    try:
        with db.engine.connect() as conn:
            select_stmt = text(f"""
                SELECT {NewUserTable.EMAIL}, {NewUserTable.FIRSTNAME},
                       {NewUserTable.LASTNAME}, {NewUserTable.ACCEPTED}
                FROM {NewUserTable.NAME}
            """)
            result = conn.execute(select_stmt)

            rows = result.all()

    except SQLAlchemyError:
        return NewUserError("unexpected_error")

    users = []
    for row in rows:
        users.append(NewUser(
            email=getattr(row, NewUserTable.EMAIL),
            firstname=getattr(row, NewUserTable.FIRSTNAME),
            lastname=getattr(row, NewUserTable.LASTNAME),
            accepted=bool(getattr(row, NewUserTable.ACCEPTED)),
        ))

    return users


def clear_all_users(db: Db) -> NewUserResult:
    """
    Remove all rows from the user table.
    Returns None on success, error on failure.
    """
    try:
        with db.engine.begin() as conn:
            delete_stmt = text(f"""
                DELETE FROM {UserTable.NAME}
            """)
            conn.execute(delete_stmt)

    except SQLAlchemyError:
        return NewUserError("unexpected_error")

    return None


def clear_all_newusers(db: Db) -> NewUserResult:
    """
    Remove all rows from the newuser table.
    Returns None on success, error on failure.
    """
    try:
        with db.engine.begin() as conn:
            delete_stmt = text(f"""
                DELETE FROM {NewUserTable.NAME}
            """)
            conn.execute(delete_stmt)

    except SQLAlchemyError:
        return NewUserError("unexpected_error")

    return None
