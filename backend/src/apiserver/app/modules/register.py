from datetime import date
from apiserver import data
from apiserver.lib.model.entities import UserData
from apiserver.lib.utilities import gen_id_name
from loguru import logger

import opaquepy as opq
from pydantic import BaseModel

from apiserver.app.error import AppError, ErrorKeys
from apiserver.data import Source, ops
from apiserver.data.context import RegisterAppContext
from apiserver.data.context.register import (
    get_register_state,
)
from store.error import NoDataError


class RegisterRequest(BaseModel):
    email: str
    firstname: str
    lastname: str
    client_request: str


# async def check_register(
#     dsrc: Source, context: RegisterAppContext, register_start: RegisterRequest
# ):
#     """Ensures that email confirmation was sent and that it matches, so if succeeds we can confirm that register_start.email is correct."""
#     try:
#         stored_confirm = await data.trs.reg.get_email_confirmation(dsrc, register_start.email.lower())
#     except NoDataError as e:
#         logger.debug(e.message)
#         reason = "Email not currently being confirmed."
#         raise AppError(
#             err_type=ErrorKeys.REGISTER,
#             err_desc=reason,
#             debug_key="bad_registration_start",
#         )
    
#     if register_start.confirm_id != stored_confirm:
#         logger.debug("Confirm IDs do not match.")
#         reason = "Bad registration."
#         raise AppError(
#             err_type=ErrorKeys.REGISTER,
#             err_desc=reason,
#             debug_key="bad_registration_start",
#         )

    # ud, u = await get_registration(context, dsrc, register_start.register_id)

    # if ud.registered or len(u.password_file) > 0:
    #     logger.debug("Already registered.")
    #     reason = "Bad registration."
    #     raise AppError(
    #         err_type=ErrorKeys.REGISTER,
    #         err_desc=reason,
    #         debug_key="bad_registration_start",
    #     )

    # if u.email != register_start.email.lower():
    #     logger.debug("Registration start does not match e-mail")
    #     reason = "Bad registration."
    #     raise AppError(
    #         err_type=ErrorKeys.REGISTER,
    #         err_desc=reason,
    #         debug_key="bad_registration_start",
    #     )

    # return ud.user_id


class FinishRequest(BaseModel):
    auth_id: str
    firstname: str
    lastname: str
    client_request: str
    birthdate: date
    joined: date
    age_privacy: bool


async def finalize_save_register(
    dsrc: Source, context: RegisterAppContext, register_finish: FinishRequest
) -> None:
    saved_state = await get_register_state(context, dsrc, register_finish.auth_id)

    # Generate password file
    # Note that this is equal to the client request, it simply is a check for correct format
    try:
        password_file = opq.register_finish(register_finish.client_request)
    except ValueError as e:
        logger.debug(f"OPAQUE failure from client OPAQUE message: {e!s}")
        raise AppError(
            err_type=ErrorKeys.REGISTER,
            err_desc="Invalid OPAQUE registration.",
            debug_key="bad_opaque_registration",
        )

    user_id = saved_state.user_id

    async with data.get_conn(dsrc) as conn:
        user = await data.user.get_user_by_id(conn, user_id)

        # user needs to exist and password file should be empty
        if user is None or user.password_file:
            logger.debug(f"Bad user state during registration: user={user};")
            raise AppError(
                err_type=ErrorKeys.REGISTER,
                err_desc="Invalid user state before registration.",
                debug_key="bad_registration_bad_user_state",
            )
        
        id_name = gen_id_name(register_finish.firstname, register_finish.lastname)

        if id_name != user.id_name:
            logger.debug(f"id_name mismatch: id_name={user.id_name}; firstname={register_finish.firstname}; lastname={register_finish.lastname}")
            raise AppError(
                err_type=ErrorKeys.REGISTER,
                err_desc="Invalid user state before registration.",
                debug_key="bad_registration_bad_user_state",
            )
        
        userdata = UserData(
            user_id=saved_state.user_id,
            active=True,
            firstname=register_finish.firstname,
            lastname=register_finish.lastname,
            email=user.email,
            joined=register_finish.joined,
            birthdate=register_finish.birthdate,
            showage=register_finish.age_privacy
        )

        await ops.user.update_password_file(conn, user_id, password_file)
        await data.ud.upsert_userdata(conn, userdata)

    logger.debug(f"Registration finished for: {userdata}")
