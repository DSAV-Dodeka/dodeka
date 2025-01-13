from datetime import date
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncConnection

from store.db import (
    lit_dict,
    retrieve_by_unique,
    insert_return_col,
    exists_by_unique,
    update_column_by_unique,
    delete_by_column,
    insert,
    select_some_where,
)
from schema.model import (
    USER_TABLE,
    USERDATA_TABLE,
    USER_ID,
    PASSWORD,
    USER_EMAIL,
    UD_ACTIVE,
)
from auth.data.relational.user import (
    UserOps as AuthUserOps,
    UserErrors,
)
from store.error import DataError, DbErrors, NoDataError, DbError
from apiserver.lib.model.entities import (
    User,
    SignedUp,
    UserID,
)
from apiserver.lib.utilities import gen_id_name
from apiserver.data.api.ud.userdata import new_userdata, insert_userdata

__all__ = [
    "UserOps",
    "insert_return_user_id",
    "insert_user",
    "new_user",
    "user_exists",
    "user_exists",
]


def parse_user(user_dict: Optional[dict[str, Any]]) -> User:
    if user_dict is None:
        raise NoDataError("User does not exist.", UserErrors.U_EMPTY)
    return User.model_validate(user_dict)


async def user_exists(conn: AsyncConnection, user_email: str) -> bool:
    return await exists_by_unique(conn, USER_TABLE, USER_EMAIL, user_email)


async def no_user_or_not_registered(conn: AsyncConnection, email: str) -> bool:
    """Returns True if a user does not exist or has not completed registration."""
    user_row = await retrieve_by_unique(conn, USER_TABLE, USER_EMAIL, email)

    if user_row is None:
        return True
    
    user = parse_user(user_row)

    return not user.password_file


async def get_user_by_email(conn: AsyncConnection, email: str) -> User | None:
    """Returns True if a user does not exist or has not completed registration."""
    user_row = await retrieve_by_unique(conn, USER_TABLE, USER_EMAIL, email)

    if user_row is None:
        return None
    
    user = parse_user(user_row)

    return user

async def get_user_by_id(conn: AsyncConnection, user_id: str) -> User | None:
    """Returns True if a user does not exist or has not completed registration."""
    user_row = await retrieve_by_unique(conn, USER_TABLE, USER_ID, user_id)

    if user_row is None:
        return None
    
    user = parse_user(user_row)

    return user


class UserOps(AuthUserOps):
    @classmethod
    async def get_user_by_id(cls, conn: AsyncConnection, user_id: str) -> User:
        user_row = await retrieve_by_unique(conn, USER_TABLE, USER_ID, user_id)
        return parse_user(user_row)

    @classmethod
    async def get_user_by_email(cls, conn: AsyncConnection, email: str) -> User:
        user_row = await retrieve_by_unique(conn, USER_TABLE, USER_EMAIL, email)
        return parse_user(user_row)

    @classmethod
    async def update_password_file(
        cls, conn: AsyncConnection, user_id: str, password_file: str
    ) -> int:
        return await update_column_by_unique(
            conn, USER_TABLE, PASSWORD, password_file, USER_ID, user_id
        )


async def insert_user(conn: AsyncConnection, user: User) -> None:
    user_row = lit_dict(user.model_dump(exclude={"user_id"}))
    try:
        await insert(conn, USER_TABLE, user_row)
    except DbError as e:
        raise DataError(f"{e.err_desc} from internal: {e.err_internal}", e.key)

EMAIL_EXISTS = "email_exists"

async def insert_return_user_id(conn: AsyncConnection, user: User) -> str:
    user_row = lit_dict(user.model_dump(exclude={"id", "user_id"}))
    try:
        user_id: str = await insert_return_col(conn, USER_TABLE, user_row, USER_ID)
    except DbError as e:
        if e.key == DbErrors.INTEGRITY:
            raise DataError(f"Integrity violation: {e.err_desc} from internal: {e.err_internal}.\nE-mail most likely already exists", EMAIL_EXISTS)

        raise DataError(f"{e.err_desc} from internal: {e.err_internal}", e.key)
    return user_id


async def new_user(
    conn: AsyncConnection,
    signed_up: SignedUp,
) -> str:
    id_name = gen_id_name(signed_up.firstname, signed_up.lastname)

    user = User(id_name=id_name, email=signed_up.email, password_file="", scope="")
    user_id = await insert_return_user_id(conn, user)
    # userdata = new_userdata(signed_up, user_id, register_id)

    # await insert_userdata(conn, userdata)

    return user_id


async def update_user_email(
    conn: AsyncConnection, user_id: str, new_email: str
) -> bool:
    try:
        count = await update_column_by_unique(
            conn, USER_TABLE, USER_EMAIL, new_email, USER_ID, user_id
        )
    except DbError as e:
        raise DataError(f"{e.err_desc} from internal: {e.err_internal}", e.key)
    return bool(count)


async def get_all_user_ids(conn: AsyncConnection) -> list[UserID]:
    all_user_ids = await select_some_where(
        conn, USERDATA_TABLE, {USER_ID}, UD_ACTIVE, True
    )
    # This is the fastest way to parse in pure Python, although converting to dict is only slightly faster
    return [UserID(user_id=u_id_r[USER_ID]) for u_id_r in all_user_ids]


async def delete_user(conn: AsyncConnection, user_id: str) -> None:
    row_count = await delete_by_column(conn, USER_TABLE, USER_ID, user_id)
    if row_count == 0:
        raise NoDataError("User does not exist.", "user_empty")
