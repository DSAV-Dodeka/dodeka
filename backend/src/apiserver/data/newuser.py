from dataclasses import dataclass
from typing import Union

from .db import Db
from .error import check_integrity_error
from .model import NewUserTable, UserTable


@dataclass
class NewUser:
    email: str
    firstname: str
    lastname: str
    accepted: bool


def add_new_user(db: Db, email: str, firstname: str, lastname: str):
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
                raise ValueError("User with e-mail already exists in user table.")

            # Insert new user into newuser table
            insert_stmt = text(f"""
                INSERT INTO {NewUserTable.NAME} (
                    {NewUserTable.EMAIL}, {NewUserTable.FIRSTNAME},
                    {NewUserTable.LASTNAME}, {NewUserTable.ACCEPTED}
                ) VALUES (
                    :email, :firstname, :lastname, :accepted
                )
            """)

            conn.execute(
                insert_stmt,
                {
                    "email": email,
                    "firstname": firstname,
                    "lastname": lastname,
                    "accepted": 0,  # Default to not accepted
                },
            )

    except IntegrityError as e:
        if check_integrity_error(e, "newuser.email", "unique"):
            raise ValueError("User with e-mail already exists in newuser table.")


def update_accepted_flag(db: Db, email: str, accepted: bool):
    """
    Update the accepted flag for a user in the newuser table.
    Returns error if user not found.
    """
    with db.engine.begin() as conn:
        update_stmt = text(f"""
            UPDATE {NewUserTable.NAME}
            SET {NewUserTable.ACCEPTED} = :accepted
            WHERE {NewUserTable.EMAIL} = :email
        """)

        result = conn.execute(
            update_stmt,
            {
                "email": email,
                "accepted": 1 if accepted else 0,
            },
        )

        if result.rowcount == 0:
            raise ValueError("User with e-mail does not exist.")


def list_new_users(db: Db) -> list[NewUser]:
    with db.engine.connect() as conn:
        select_stmt = text(f"""
            SELECT {NewUserTable.EMAIL}, {NewUserTable.FIRSTNAME},
                    {NewUserTable.LASTNAME}, {NewUserTable.ACCEPTED}
            FROM {NewUserTable.NAME}
        """)
        result = conn.execute(select_stmt)

        rows = result.all()

    users = []
    for row in rows:
        users.append(
            NewUser(
                email=getattr(row, NewUserTable.EMAIL),
                firstname=getattr(row, NewUserTable.FIRSTNAME),
                lastname=getattr(row, NewUserTable.LASTNAME),
                accepted=bool(getattr(row, NewUserTable.ACCEPTED)),
            )
        )

    return users


def clear_all_users(db: Db):
    with db.engine.begin() as conn:
        delete_stmt = text(f"""
            DELETE FROM {UserTable.NAME}
        """)
        conn.execute(delete_stmt)


def clear_all_newusers(db: Db):
    with db.engine.begin() as conn:
        delete_stmt = text(f"""
            DELETE FROM {NewUserTable.NAME}
        """)
        conn.execute(delete_stmt)


def prepare_user_store(db: Db, email: str, names: list[str]):
    # Validate names list length
    if len(names) > 2:
        raise ValueError("Only accepts two names.")
    elif len(names) == 2:
        firstname = names[0]
        lastname = names[1]
    elif len(names) == 1:
        firstname = names[0]
        lastname = ""
    else:
        # If no names provided, use email prefix as firstname
        email_prefix = email.split("@")[0]
        firstname = email_prefix
        lastname = ""

    try:
        with db.engine.begin() as conn:
            insert_stmt = text(f"""
                INSERT INTO {NewUserTable.NAME} (
                    {NewUserTable.EMAIL}, {NewUserTable.FIRSTNAME},
                    {NewUserTable.LASTNAME}, {NewUserTable.ACCEPTED}
                ) VALUES (
                    :email, :firstname, :lastname, :accepted
                )
            """)

            conn.execute(
                insert_stmt,
                {
                    "email": email,
                    "firstname": firstname,
                    "lastname": lastname,
                    "accepted": 1,  # Set to accepted
                },
            )

    except IntegrityError as e:
        if check_integrity_error(e, "newuser.email", "unique"):
            raise ValueError("User with e-mail already exists in newuser table.")
