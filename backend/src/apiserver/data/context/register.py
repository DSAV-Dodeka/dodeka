from loguru import logger
from apiserver import data
from apiserver.app.error import AppError, ErrorKeys
from apiserver.data import Source, ops
from apiserver.data.context import RegisterAppContext
from apiserver.lib.model.entities import UserData, User
from auth.core.model import SavedRegisterState
from auth.data.relational.user import UserErrors
from datacontext.context import ContextRegistry
from store.error import NoDataError

ctx_reg = ContextRegistry()


# @ctx_reg.register(RegisterAppContext)
# async def get_registration(dsrc: Source, register_id: str) -> tuple[UserData, User]:
#     try:
#         async with data.get_conn(dsrc) as conn:
#             ud = await data.ud.get_userdata_by_register_id(conn, register_id)

#             u = await ops.user.get_user_by_id(conn, ud.user_id)
#     except NoDataError as e:
#         if e.key == UserErrors.UD_EMPTY:
#             reason = "No registration by that register_id"
#             debug_key = "no_register_for_id"
#         else:
#             reason = "No registration for that user"
#             debug_key = "no_register_for_user"

#         raise AppError(
#             err_type=ErrorKeys.REGISTER,
#             err_desc=reason,
#             debug_key=debug_key,
#         )

#     return ud, u


@ctx_reg.register(RegisterAppContext)
async def get_register_state(dsrc: Source, auth_id: str) -> SavedRegisterState:
    try:
        saved_state = await data.trs.reg.get_register_state(dsrc, auth_id)
    except NoDataError as e:
        logger.debug(e.message)
        reason = "Registration not initialized or expired."
        raise AppError(
            err_type=ErrorKeys.REGISTER,
            err_desc=reason,
            debug_key="no_register_start",
        )

    return saved_state
