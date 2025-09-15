import secrets
import sqlalchemy as sqla
import sqlite3
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from tiauth_faroe.user_server import (
    Effect,
    EffectResult,
    User,
    ActionError,
    CreateUserEffect,
    GetUserEffect,
    GetUserByEmailAddressEffect,
    UpdateUserEmailAddressEffect,
    UpdateUserPasswordHashEffect,
    IncrementUserSessionsCounterEffect,
    DeleteUserEffect,
    SyncServer,
)
from .model import UserTable, NewUserTable
from .db import Db

def create_user(db: Db, effect: CreateUserEffect) -> EffectResult:
    try:
        with db.engine.begin() as conn:
            # Query newuser table to get user information and check if accepted
            newuser_stmt = text(f"""
                SELECT {NewUserTable.FIRSTNAME}, {NewUserTable.LASTNAME}, {NewUserTable.ACCEPTED}
                FROM {NewUserTable.NAME}
                WHERE {NewUserTable.EMAIL} = :email_address
            """)
            newuser_result = conn.execute(newuser_stmt, {"email_address": effect.email_address})
            newuser_row = newuser_result.first()

            if newuser_row is None:
                # TODO figure out if this is good
                return ActionError("user_not_found")

            firstname = getattr(newuser_row, NewUserTable.FIRSTNAME)
            lastname = getattr(newuser_row, NewUserTable.LASTNAME)
            accepted = bool(getattr(newuser_row, NewUserTable.ACCEPTED))

            if not accepted:
                # TODO maybe standardize?
                return ActionError("user_not_accepted")

            name_id = f"{firstname.lower()}_{lastname.lower()}"

            # Look up the largest int_id currently in use
            max_id_stmt = text(f"""
                SELECT MAX({UserTable.INT_ID}) FROM {UserTable.NAME}
            """)
            max_id_result = conn.execute(max_id_stmt)
            max_id_row = max_id_result.first()
            if max_id_row is None or max_id_row[0] is None:
                max_int_id = 0
            else:
                max_int_id = max_id_row[0]

            # Ensure new int_id is higher than the previous one
            int_id = max_int_id + 1

            stmt = text(f"""
                INSERT INTO {UserTable.NAME} (
                    {UserTable.INT_ID}, {UserTable.NAME_ID}, {UserTable.EMAIL},
                    {UserTable.FIRSTNAME}, {UserTable.LASTNAME},
                    {UserTable.PASSWORD_HASH}, {UserTable.PASSWORD_HASH_ALGORITHM_ID},
                    {UserTable.PASSWORD_SALT}, {UserTable.DISABLED},
                    {UserTable.EMAIL_ADDRESS_COUNTER}, {UserTable.PASSWORD_HASH_COUNTER},
                    {UserTable.DISABLED_COUNTER}, {UserTable.SESSIONS_COUNTER}
                ) VALUES (
                    :int_id, :name_id, :email_address,
                    :firstname, :lastname,
                    :password_hash, :password_hash_algorithm_id, :password_salt,
                    :disabled, :email_address_counter, :password_hash_counter,
                    :disabled_counter, :sessions_counter
                )
            """)

            conn.execute(stmt, {
                "int_id": int_id,
                "name_id": name_id,
                "email_address": effect.email_address,
                "firstname": firstname,
                "lastname": lastname,
                "password_hash": effect.password_hash,
                "password_hash_algorithm_id": effect.password_hash_algorithm_id,
                "password_salt": effect.password_salt,
                "disabled": 0,
                "email_address_counter": 0,
                "password_hash_counter": 0,
                "disabled_counter": 0,
                "sessions_counter": 0,
            })

            # Remove the newuser row after successful user creation
            delete_newuser_stmt = text(f"""
                DELETE FROM {NewUserTable.NAME}
                WHERE {NewUserTable.EMAIL} = :email_address
            """)
            conn.execute(delete_newuser_stmt, {"email_address": effect.email_address})

    except IntegrityError as e:
        # Wish there was a better way to do this...
        orig = e.orig
        assert isinstance(orig, sqlite3.IntegrityError)
        assert isinstance(orig.args[0], str)
        if 'user.email' in orig.args[0] and 'unique' in orig.args[0].lower():
            return ActionError("email_address_already_used")
        else:
            return ActionError("unexpected_error")
    except SQLAlchemyError:
        return ActionError("unexpected_error")

    # Compute the final user_id
    user_id = f"{int_id}_{name_id}"

    return User(
        id=user_id,
        email_address=effect.email_address,
        password_hash=effect.password_hash,
        password_hash_algorithm_id=effect.password_hash_algorithm_id,
        password_salt=effect.password_salt,
        disabled=False,
        display_name=f"{firstname} {lastname}",
        email_address_counter=0,
        password_hash_counter=0,
        disabled_counter=0,
        sessions_counter=0,
    )


def get_user(db: Db, effect: GetUserEffect) -> EffectResult:
    try:
        with db.engine.connect() as conn:
            stmt = text(f"""
                SELECT {UserTable.EMAIL}, {UserTable.FIRSTNAME}, {UserTable.LASTNAME},
                       {UserTable.PASSWORD_HASH}, {UserTable.PASSWORD_HASH_ALGORITHM_ID},
                       {UserTable.PASSWORD_SALT}, {UserTable.DISABLED},
                       {UserTable.EMAIL_ADDRESS_COUNTER}, {UserTable.PASSWORD_HASH_COUNTER},
                       {UserTable.DISABLED_COUNTER}, {UserTable.SESSIONS_COUNTER}
                FROM {UserTable.NAME}
                WHERE {UserTable.ID} = :user_id
            """)

            result = conn.execute(stmt, {"user_id": effect.user_id})
            row = result.first()

    except SQLAlchemyError:
        return ActionError("unexpected_error")

    if row is None:
        return ActionError("user_not_found")

    firstname = getattr(row, UserTable.FIRSTNAME)
    lastname = getattr(row, UserTable.LASTNAME)

    return User(
        id=effect.user_id,
        email_address=getattr(row, UserTable.EMAIL),
        password_hash=getattr(row, UserTable.PASSWORD_HASH),
        password_hash_algorithm_id=getattr(row, UserTable.PASSWORD_HASH_ALGORITHM_ID),
        password_salt=getattr(row, UserTable.PASSWORD_SALT),
        disabled=bool(getattr(row, UserTable.DISABLED)),
        display_name=f"{firstname} {lastname}",
        email_address_counter=getattr(row, UserTable.EMAIL_ADDRESS_COUNTER),
        password_hash_counter=getattr(row, UserTable.PASSWORD_HASH_COUNTER),
        disabled_counter=getattr(row, UserTable.DISABLED_COUNTER),
        sessions_counter=getattr(row, UserTable.SESSIONS_COUNTER),
    )


def get_user_by_email_address(db: Db, effect: GetUserByEmailAddressEffect) -> EffectResult:
    try:
        with db.engine.connect() as conn:
            stmt = text(f"""
                SELECT {UserTable.ID}, {UserTable.FIRSTNAME}, {UserTable.LASTNAME},
                       {UserTable.PASSWORD_HASH}, {UserTable.PASSWORD_HASH_ALGORITHM_ID},
                       {UserTable.PASSWORD_SALT}, {UserTable.DISABLED},
                       {UserTable.EMAIL_ADDRESS_COUNTER}, {UserTable.PASSWORD_HASH_COUNTER},
                       {UserTable.DISABLED_COUNTER}, {UserTable.SESSIONS_COUNTER}
                FROM {UserTable.NAME}
                WHERE {UserTable.EMAIL} = :email_address
            """)

            result = conn.execute(stmt, {"email_address": effect.email_address})
            row = result.first()

    except SQLAlchemyError:
        return ActionError("unexpected_error")

    if row is None:
        return ActionError("user_not_found")

    firstname = getattr(row, UserTable.FIRSTNAME)
    lastname = getattr(row, UserTable.LASTNAME)

    return User(
        id=getattr(row, UserTable.ID),
        email_address=effect.email_address,
        password_hash=getattr(row, UserTable.PASSWORD_HASH),
        password_hash_algorithm_id=getattr(row, UserTable.PASSWORD_HASH_ALGORITHM_ID),
        password_salt=getattr(row, UserTable.PASSWORD_SALT),
        disabled=bool(getattr(row, UserTable.DISABLED)),
        display_name=f"{firstname} {lastname}",
        email_address_counter=getattr(row, UserTable.EMAIL_ADDRESS_COUNTER),
        password_hash_counter=getattr(row, UserTable.PASSWORD_HASH_COUNTER),
        disabled_counter=getattr(row, UserTable.DISABLED_COUNTER),
        sessions_counter=getattr(row, UserTable.SESSIONS_COUNTER),
    )


def update_user_email_address(db: Db, effect: UpdateUserEmailAddressEffect) -> EffectResult:
    try:
        with db.engine.begin() as conn:
            stmt = text(f"""
                UPDATE {UserTable.NAME}
                SET {UserTable.EMAIL} = :email_address,
                    {UserTable.EMAIL_ADDRESS_COUNTER} = {UserTable.EMAIL_ADDRESS_COUNTER} + 1
                WHERE {UserTable.ID} = :user_id
                  AND {UserTable.EMAIL_ADDRESS_COUNTER} = :user_email_address_counter
            """)

            result = conn.execute(stmt, {
                "email_address": effect.email_address,
                "user_id": effect.user_id,
                "user_email_address_counter": effect.user_email_address_counter,
            })

    except SQLAlchemyError:
        return ActionError("unexpected_error")

    if result.rowcount == 0:
        return ActionError("user_not_found")

    return None


def update_user_password_hash(db: Db, effect: UpdateUserPasswordHashEffect) -> EffectResult:
    try:
        with db.engine.begin() as conn:
            stmt = text(f"""
                UPDATE {UserTable.NAME}
                SET {UserTable.PASSWORD_HASH} = :password_hash,
                    {UserTable.PASSWORD_HASH_ALGORITHM_ID} = :password_hash_algorithm_id,
                    {UserTable.PASSWORD_SALT} = :password_salt,
                    {UserTable.PASSWORD_HASH_COUNTER} = {UserTable.PASSWORD_HASH_COUNTER} + 1
                WHERE {UserTable.ID} = :user_id
                  AND {UserTable.PASSWORD_HASH_COUNTER} = :user_password_hash_counter
            """)

            result = conn.execute(stmt, {
                "password_hash": effect.password_hash,
                "password_hash_algorithm_id": effect.password_hash_algorithm_id,
                "password_salt": effect.password_salt,
                "user_id": effect.user_id,
                "user_password_hash_counter": effect.user_password_hash_counter,
            })

    except SQLAlchemyError:
        return ActionError("unexpected_error")

    if result.rowcount == 0:
        return ActionError("user_not_found")

    return None


def increment_user_sessions_counter(db: Db, effect: IncrementUserSessionsCounterEffect) -> EffectResult:
    try:
        with db.engine.begin() as conn:
            stmt = text(f"""
                UPDATE {UserTable.NAME}
                SET {UserTable.SESSIONS_COUNTER} = {UserTable.SESSIONS_COUNTER} + 1
                WHERE {UserTable.ID} = :user_id
                  AND {UserTable.SESSIONS_COUNTER} = :user_sessions_counter
            """)

            result = conn.execute(stmt, {
                "user_id": effect.user_id,
                "user_sessions_counter": effect.user_sessions_counter,
            })

    except SQLAlchemyError:
        return ActionError("unexpected_error")

    if result.rowcount == 0:
        return ActionError("user_not_found")

    return None


def delete_user(db: Db, effect: DeleteUserEffect) -> EffectResult:
    try:
        with db.engine.begin() as conn:
            stmt = text(f"""
                DELETE FROM {UserTable.NAME}
                WHERE {UserTable.ID} = :user_id
            """)

            result = conn.execute(stmt, {"user_id": effect.user_id})

    except SQLAlchemyError:
        return ActionError("unexpected_error")

    if result.rowcount == 0:
        return ActionError("user_not_found")

    return None


class SqliteSyncServer(SyncServer):
    def __init__(self, db: Db):
        self.db = db

    def execute_effect(self, effect: Effect) -> EffectResult:
        print(f"effect:\n{effect}\n")
        if isinstance(effect, CreateUserEffect):
            return create_user(self.db, effect)
        elif isinstance(effect, GetUserEffect):
            return get_user(self.db, effect)
        elif isinstance(effect, GetUserByEmailAddressEffect):
            return get_user_by_email_address(self.db, effect)
        elif isinstance(effect, UpdateUserEmailAddressEffect):
            return update_user_email_address(self.db, effect)
        elif isinstance(effect, UpdateUserPasswordHashEffect):
            return update_user_password_hash(self.db, effect)
        elif isinstance(effect, IncrementUserSessionsCounterEffect):
            return increment_user_sessions_counter(self.db, effect)
        elif isinstance(effect, DeleteUserEffect):
            return delete_user(self.db, effect)
        else:
            raise ValueError(f"Unknown effect type: {type(effect)}")
