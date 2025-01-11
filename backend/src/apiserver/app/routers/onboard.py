import json
from apiserver.data import schema
from apiserver.data.api.user import EMAIL_EXISTS
from apiserver.data.source import Source
from apiserver.lib.utilities import gen_id_name
from loguru import logger
from datetime import date
from urllib.parse import urlencode

from anyio import sleep
from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

from apiserver import data
from apiserver.app.dependencies import AppContext, AuthContext, SourceDep
from apiserver.app.error import ErrorResponse, AppError
from apiserver.app.modules.register import (
    RegisterRequest,
    FinishRequest,
    finalize_save_register,
)
from apiserver.app.ops.mail import (
    send_signup_email,
    send_register_email,
    mail_from_config,
)
from apiserver.define import (
    DEFINE,
    email_expiration,
)
from apiserver.lib.model.entities import SignedUp, Signup
from auth.core.response import PasswordResponse
from auth.core.util import enc_b64url, random_time_hash_hex
from auth.modules.register import send_register_start
from store.db import lit_model
from store.error import DataError, NoDataError

router = APIRouter(prefix="/onboard", tags=["onboard"])
onboard_admin_router = APIRouter(prefix="/onboard", tags=["onboard"])


# class SignupRequest(BaseModel):
#     email: str


# @router.post("/email/start/")
# async def init_signup(
#     signup: SignupRequest, dsrc: SourceDep, background_tasks: BackgroundTasks
# ) -> None:
#     """Signup is initiated by leaving email. The link in the email then redirects to registration."""
    
#     email = signup.email.lower()

#     async with data.get_conn(dsrc) as conn:
#         do_send_email = data.user.no_user_or_not_registered(conn, email)

#     logger.debug(
#         f"{email} has not completed registration? {do_send_email}"
#     )

#     confirm_id = random_time_hash_hex()

#     await data.trs.reg.store_email_confirmation(
#         dsrc,
#         confirm_id,
#         email,
#         email_expiration,
#     )

#     registration_url = f"{DEFINE.credentials_url}register/{confirm_id}"

#     if do_send_email:
#         logger.opt(colors=True).debug(
#             f"Creating email with registration url <u><red>{registration_url}</red></u>"
#         )
#         send_signup_email(
#             background_tasks,
#             email,
#             mail_from_config(dsrc.config),
#             registration_url,
#         )
#     else:
#         # Prevent client enumeration
#         await sleep(0.00002)


# class EmailConfirm(BaseModel):
#     email: str
#     confirm_id: str


# @router.get("/email/check/")
# async def email_confirm(confirm_req: EmailConfirm, dsrc: SourceDep) -> None:
#     """Returns 200 if the given email and confirm id are the currently stored one and haven't expired."""
#     try:
#         stored_confirm = await data.trs.reg.get_email_confirmation(dsrc, confirm_req.confirm_id)
#     except NoDataError as e:
#         logger.debug(e.message)
#         reason = "Incorrect confirm ID or expired."
#         raise ErrorResponse(
#             400, err_type="invalid_signup", err_desc=reason, debug_key="bad_confirm_id"
#         )
    
#     if stored_confirm != confirm_req.confirm_id:
#         reason = "Incorrect confirm ID or expired."
#         raise ErrorResponse(
#             400, err_type="invalid_signup", err_desc=reason, debug_key="bad_confirm_id"
#         )
    
#     # TODO maybe also fail when user already exists 

#     logger.debug(f"Email {confirm_req.email} has been sent for confirm id {confirm_req.confirm_id}.")


@router.post("/register/", response_model=PasswordResponse)
async def start_register(
    register_start: RegisterRequest,
    dsrc: SourceDep,
    app_context: AppContext,
    auth_context: AuthContext,
) -> PasswordResponse:
    """First step of OPAQUE registration, requires username and client message generated in first client registration
    step."""

    id_name = gen_id_name(register_start.firstname, register_start.lastname)

    async with data.get_conn(dsrc) as conn:
        user = await data.user.get_user_by_email(conn, register_start.email)

        if user is None:
            signed_up = SignedUp(
                firstname=register_start.firstname,
                lastname=register_start.lastname,
                email=register_start.email
            )

            user_id = await data.user.new_user(
                conn,
                signed_up,
            )
        elif not user.password_file:
            if user.id_name != id_name:
                raise ErrorResponse(
                    400,
                    err_type="invalid_onboard",
                    err_desc="Request does not match user saved for email!",
                    debug_key="names_do_not_match_saved",
                )
            
            user_id = user.user_id
        else:
            logger.debug(f"Attempted register for email {register_start.email} that already exists with request {register_start}!")
            # user is already registered, fail, because Volta will allow client enumeration anyways
            raise ErrorResponse(
                    400,
                    err_type="invalid_onboard",
                    err_desc="Email not allowed!",
                    debug_key="invalid_email",
                )

    return await send_register_start(
        dsrc.store, auth_context.register_ctx, user_id, register_start.client_request
    )


@router.post("/finish/")
async def finish_register(
    register_finish: FinishRequest, dsrc: SourceDep, app_context: AppContext
) -> None:
    """At this point, we have info saved under 'userdata', 'users' and short-term storage as SavedRegisterState. All
    this data must match up for there to be a successful registration."""

    try:
        await finalize_save_register(dsrc, app_context.register_ctx, register_finish)
    except AppError as e:
        logger.debug(e.err_desc)
        raise ErrorResponse(
            400,
            err_type=e.err_type,
            err_desc=e.err_desc,
            debug_key=e.debug_key,
        )

# TODO fix this again
@onboard_admin_router.get("/get/", response_model=list[SignedUp])
async def get_signedup(dsrc: SourceDep) -> list[SignedUp]: # type: ignore
    # async with data.get_conn(dsrc) as conn:
    #     signed_up = await data.signedup.get_all_signedup(conn)
    # return signed_up
    pass


@router.get("/get/", response_model=list[SignedUp])
async def get_signedup_old(dsrc: SourceDep) -> list[SignedUp]:
    return await get_signedup(dsrc)


class SignupConfirm(BaseModel):
    email: str
    av40id: int
    joined: date


@onboard_admin_router.post("/confirm/")
async def confirm_join(
    dsrc: SourceDep,
    signup: SignupConfirm,
    background_tasks: BackgroundTasks,
) -> None:
    """Board confirms data from AV`40 signup through admin tool."""
    # signup_email = signup.email.lower()

    # try:
    #     async with data.get_conn(dsrc) as conn:
    #         signed_up = await data.signedup.get_signedup_by_email(conn, signup_email)
    # except DataError as e:
    #     if e.key == "signedup_empty":
    #         logger.debug(e.key)
    #         raise ErrorResponse(
    #             400,
    #             err_type="invalid_onboard",
    #             err_desc="No user under this e-mail in signup!",
    #             debug_key="no_user_signup",
    #         )
    #     else:
    #         logger.debug(e.message)
    #         raise e

    # # Success here means removing any existing records in signedup and also the KV relating to that email

    # register_id = random_time_hash_hex(short=True)
    # async with data.get_conn(dsrc) as conn:
    #     await data.user.new_user(
    #         conn,
    #         signed_up,
    #         register_id,
    #     )
    #     await data.signedup.confirm_signup(conn, signup_email)

    # logger.debug(
    #     f"Confirmed onboard for {signup_email} ="
    #     f" {signed_up.firstname} {signed_up.lastname}"
    # )
    # info = {
    #     "register_id": register_id,
    #     "firstname": signed_up.firstname,
    #     "lastname": signed_up.lastname,
    #     "email": signed_up.email,
    #     "phone": signed_up.phone,
    # }
    # info_str = enc_b64url(json.dumps(info).encode("utf-8"))
    # params = {"info": info_str}
    # registration_url = f"{DEFINE.credentials_url}register/?{urlencode(params)}"

    # logger.opt(colors=True).debug(
    #     f"Creating email with registration url <u><red>{registration_url}</red></u>"
    # )
    # send_register_email(
    #     background_tasks, signup_email, mail_from_config(dsrc.config), registration_url
    # )


@router.post("/confirm/")
async def confirm_join_old(
    dsrc: SourceDep,
    signup: SignupConfirm,
    background_tasks: BackgroundTasks,
) -> None:
    return await confirm_join(dsrc, signup, background_tasks)
