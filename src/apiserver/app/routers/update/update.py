import logging
from urllib.parse import urlencode

import opaquepy as opq
from fastapi import APIRouter, Request, BackgroundTasks
from pydantic import BaseModel

import auth.core.util
from apiserver import data
from apiserver.app.error import ErrorResponse
from apiserver.app.ops.mail import (
    send_change_email_email,
    send_reset_email,
    mail_from_config,
)
from apiserver.app.routers.helper import authentication
from apiserver.app.ops.header import Authorization
from apiserver.data import Source, ops
from apiserver.data.frame import Code
from auth.modules.update import change_password
from store.error import DataError, NoDataError
from apiserver.define import LOGGER_NAME, DEFINE
from apiserver.lib.model.entities import UpdateEmailState
from apiserver.app.routers.helper import require_user
from auth.modules.register import send_register_start

router = APIRouter()

logger = logging.getLogger(LOGGER_NAME)


class ChangePasswordRequest(BaseModel):
    email: str


@router.post("/update/password/reset/")
async def request_password_change(
    change_pass: ChangePasswordRequest,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Initiated from authpage. Sends out e-mail with reset link."""
    dsrc: Source = request.state.dsrc
    async with data.get_conn(dsrc) as conn:
        ud = await data.ud.get_userdata_by_email(conn, change_pass.email)
    logger.debug(f"Reset requested - is_registered={ud.registered}")
    flow_id = auth.core.util.random_time_hash_hex()
    params = {"reset_id": flow_id, "email": change_pass.email}
    reset_url = f"{DEFINE.credentials_url}reset/?{urlencode(params)}"

    await data.trs.store_string(dsrc, flow_id, change_pass.email, 1000)

    if ud.registered:
        send_reset_email(
            background_tasks,
            change_pass.email,
            mail_from_config(dsrc.config),
            reset_url,
        )


class UpdatePasswordRequest(BaseModel):
    email: str
    flow_id: str
    client_request: str


@router.post("/update/password/start/")
async def update_password_start(update_pass: UpdatePasswordRequest, request: Request):
    dsrc: Source = request.state.dsrc
    cd: Code = request.state.cd

    try:
        stored_email = await data.trs.pop_string(dsrc, update_pass.flow_id)
    except NoDataError as e:
        logger.debug(e.message)
        reason = "No reset has been requested for this user."
        raise ErrorResponse(
            400, err_type="invalid_reset", err_desc=reason, debug_key="no_user_reset"
        )

    if stored_email != update_pass.email:
        reason = "Emails do not match for this reset!"
        logger.debug(reason)
        raise ErrorResponse(
            400,
            err_type="invalid_reset",
            err_desc=reason,
            debug_key="reset_no_email_match",
        )

    async with data.get_conn(dsrc) as conn:
        u = await ops.user.get_user_by_email(conn, update_pass.email)

    return await send_register_start(
        dsrc.store, cd.context.register_ctx, u.user_id, update_pass.client_request
    )


class UpdatePasswordFinish(BaseModel):
    auth_id: str
    client_request: str


@router.post("/update/password/finish/")
async def update_password_finish(update_finish: UpdatePasswordFinish, request: Request):
    dsrc: Source = request.state.dsrc

    try:
        saved_state = await data.trs.reg.get_register_state(dsrc, update_finish.auth_id)
    except NoDataError as e:
        logger.debug(e.message)
        reason = "Reset not initialized or expired."
        raise ErrorResponse(
            400, err_type="invalid_reset", err_desc=reason, debug_key="no_reset_start"
        )

    password_file = opq.register_finish(update_finish.client_request)

    await change_password(
        dsrc.store, data.schema.OPS, password_file, saved_state.user_id
    )


class UpdateEmail(BaseModel):
    user_id: str
    new_email: str


@router.post("/update/email/send/")
async def update_email(
    new_email: UpdateEmail,
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: Authorization,
):
    dsrc: Source = request.state.dsrc
    user_id = new_email.user_id
    await require_user(authorization, dsrc, user_id)

    try:
        async with data.get_conn(dsrc) as conn:
            u = await ops.user.get_user_by_id(conn, user_id)
    except NoDataError:
        raise ErrorResponse(
            400, "bad_update", "User no longer exists.", "update_user_empty"
        )
    old_email = u.email

    flow_id = auth.core.util.random_time_hash_hex(user_id)
    params = {
        "flow_id": flow_id,
        "user": old_email,
        "redirect": "client:account/email/",
        "extra": new_email.new_email,
    }
    reset_url = f"{DEFINE.credentials_url}?{urlencode(params)}"

    state = UpdateEmailState(
        flow_id=flow_id,
        old_email=old_email,
        new_email=new_email.new_email,
        user_id=user_id,
    )

    await data.trs.reg.store_update_email(dsrc, user_id, state)

    send_change_email_email(
        background_tasks,
        new_email.new_email,
        mail_from_config(dsrc.config),
        reset_url,
        old_email,
    )


class UpdateEmailCheck(BaseModel):
    flow_id: str
    code: str


class ChangedEmailResponse(BaseModel):
    old_email: str
    new_email: str


@router.post("/update/email/check/")
async def update_email_check(update_check: UpdateEmailCheck, request: Request):
    dsrc: Source = request.state.dsrc

    flow_user = await authentication.check_password(dsrc, update_check.code)

    try:
        stored_email = await data.trs.reg.get_update_email(dsrc, flow_user.user_id)
    except NoDataError:
        reason = "Update request has expired, please try again!"
        logger.debug(reason + f" {flow_user.user_id}")
        raise ErrorResponse(
            status_code=400,
            err_type="bad_update",
            err_desc=reason,
            debug_key="update_flow_expired",
        )

    user_id = stored_email.user_id
    # The flow ID is the proof that the person who get the email is requesting the change
    # The code proves the person has the password, the flow ID proves the person has the old email
    if stored_email.flow_id != update_check.flow_id:
        reason = "Update check code and update flow ID do not match!"
        raise ErrorResponse(
            400,
            err_type="bad_update",
            err_desc=reason,
            debug_key="update_email_flow_not_equal",
        )

    async with data.get_conn(dsrc) as conn:
        u = await ops.user.get_user_by_id(conn, user_id)

        # If someone changed their email by now, we do not want it possible to happen again
        if stored_email.old_email != u.email:
            reason = "Old email and current email do not match!"
            raise ErrorResponse(
                400,
                err_type="bad_update",
                err_desc=reason,
                debug_key="update_email_email_not_equal",
            )

        # Refresh tokens are no longer valid
        await data.schema.OPS.refresh.delete_by_user_id(conn, flow_user.user_id)

        count_ud = await data.user.update_user_email(
            conn, user_id, stored_email.new_email
        )
        if count_ud != 1:
            raise DataError("Internal data error.", "user_data_error")

    return ChangedEmailResponse(
        old_email=stored_email.old_email, new_email=stored_email.new_email
    )


class DeleteAccount(BaseModel):
    user_id: str


class DeleteUrlResponse(BaseModel):
    delete_url: str


@router.post("/update/delete/url/")
async def delete_account(
    delete_acc: DeleteAccount,
    request: Request,
    authorization: Authorization,
):
    dsrc: Source = request.state.dsrc
    user_id = delete_acc.user_id
    await require_user(authorization, dsrc, user_id)

    try:
        async with data.get_conn(dsrc) as conn:
            ud = await ops.userdata.get_userdata_by_id(conn, user_id)
    except NoDataError:
        raise ErrorResponse(
            400, "bad_update", "User no longer exists.", "update_user_empty"
        )
    if not ud.registered:
        raise ErrorResponse(
            status_code=400,
            err_type="bad_delete",
            err_desc="User not registered",
            debug_key="delete_not_registered",
        )

    flow_id = auth.core.util.random_time_hash_hex(user_id)
    params = {
        "flow_id": flow_id,
        "user": ud.email,
        "redirect": "client:account/delete/",
    }
    delete_url = f"{DEFINE.credentials_url}?{urlencode(params)}"

    await data.trs.store_string(dsrc, flow_id, user_id, 1000)

    return DeleteUrlResponse(delete_url=delete_url)


class DeleteAccountCheck(BaseModel):
    flow_id: str
    code: str


@router.post("/update/delete/check/")
async def delete_account_check(delete_check: DeleteAccountCheck, request: Request):
    dsrc: Source = request.state.dsrc

    flow_user = await authentication.check_password(dsrc, delete_check.code)

    try:
        stored_user_id = await data.trs.pop_string(dsrc, delete_check.flow_id)
    except NoDataError:
        reason = "Delete request has expired, please try again!"
        logger.debug(reason + f" {flow_user.user_id}")
        raise ErrorResponse(status_code=400, err_type="bad_update", err_desc=reason)

    async with data.get_conn(dsrc) as conn:
        try:
            await data.user.delete_user(conn, stored_user_id)
            return DeleteAccount(user_id=stored_user_id)
        except NoDataError:
            reason = "User for delete request does not exist!"
            logger.debug(reason + f" {flow_user.user_id}")
            raise ErrorResponse(
                status_code=400,
                err_type="bad_update",
                err_desc="Delete request has expired, please try again!",
            )
