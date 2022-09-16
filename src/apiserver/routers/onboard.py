import time as tm

import logging
from urllib.parse import urlencode

from anyio import sleep
from fastapi import APIRouter, Security, status, BackgroundTasks, Request, Response

import opaquepy as opq

from apiserver.auth import authentication
from apiserver.define import ErrorResponse, LOGGER_NAME, signup_url, credentials_url
from apiserver.define.entities import SignedUp, UserData, User
from apiserver.define.request import SignupRequest, SignupConfirm, UserDataRegisterResponse, PasswordResponse, \
    RegisterRequest, FinishRequest, EmailConfirm
import apiserver.utilities as util
from apiserver.auth.header import auth_header
from apiserver.emailfn import send_email
import apiserver.data as data
from apiserver.data import DataError, Source, NoDataError
from apiserver.env import Config
from apiserver.routers.helper import require_admin

router = APIRouter()

logger = logging.getLogger(LOGGER_NAME)


def send_signup_email(background_tasks: BackgroundTasks, receiver: str, mail_pass: str, redirect_link: str,
                      signup_link: str):
    add_vars = {
        "redirect_link": redirect_link,
        "signup_link": signup_link
    }

    def send_lam():
        send_email("confirm.html.jinja2", receiver, mail_pass, "Please confirm your email", add_vars)

    background_tasks.add_task(send_lam)


def send_register_email(background_tasks: BackgroundTasks, receiver: str, mail_pass: str, register_link: str):
    add_vars = {
        "register_link": register_link
    }

    def send_lam():
        send_email("register.html.jinja2", receiver, mail_pass, "Welcome to D.S.A.V. Dodeka!", add_vars)

    background_tasks.add_task(send_lam)


@router.post("/onboard/signup/")
async def init_signup(signup: SignupRequest, request: Request, background_tasks: BackgroundTasks):
    """ Signup is initiated by leaving basic information. User is redirected to AV'40 page, where they will actually
    sign up. Board can see who has signed up this way. There might not be full correspondence between exact signup and
    what is provided to AV'40. So there is a manual check."""
    dsrc: Source = request.app.state.dsrc

    email_usph = util.usp_hex(signup.email)

    u_ex = await data.user.user_exists(dsrc, email_usph)
    su_ex = await data.signedup.signedup_exists(dsrc, signup.email)

    do_send_email = not u_ex and not su_ex

    confirm_id = util.random_time_hash_hex(email_usph)

    await data.kv.store_email_confirmation(dsrc, confirm_id, signup)
    config: Config = request.app.state.config

    params = {
        "confirm_id": confirm_id
    }
    confirmation_url = f"{credentials_url}email/?{urlencode(params)}"

    if do_send_email:
        send_signup_email(background_tasks, signup.email, config.MAIL_PASS, confirmation_url, signup_url)
    else:
        # Prevent client enumeration
        await sleep(0.00002)

    return None


@router.post("/onboard/email/")
async def email_confirm(confirm_req: EmailConfirm, request: Request):
    dsrc: Source = request.app.state.dsrc

    try:
        signup = await data.kv.get_email_confirmation(dsrc, confirm_req.confirm_id)
    except NoDataError as e:
        logger.debug(e.message)
        reason = "Incorrect confirm ID or expired."
        raise ErrorResponse(400, err_type="invalid_signup", err_desc=reason, debug_key="bad_confirm_id")

    signed_up = SignedUp(firstname=signup.firstname, lastname=signup.lastname, email=signup.email, phone=signup.phone)

    try:
        await data.signedup.insert_su_row(dsrc, signed_up.dict())
    except DataError as e:
        logger.debug(e.message)
        if e.key == "unique_violation":
            raise ErrorResponse(400, err_type="invalid_signup", err_desc="Email already exists!",
                                debug_key="user_exists")
        else:
            raise e

    return None


@router.post("/onboard/confirm/")
async def confirm_join(signup: SignupConfirm, request: Request, background_tasks: BackgroundTasks,
                       authorization: str = Security(auth_header)):
    """ Board confirms data from AV`40 signup through admin tool. """
    dsrc: Source = request.app.state.dsrc
    await require_admin(authorization, dsrc)

    dsrc: Source = request.app.state.dsrc

    try:
        signed_up = await data.signedup.get_signedup_by_email(dsrc, signup.email)
    except DataError as e:
        logger.debug(e.message)
        if e.key == "signedup_empty":
            raise ErrorResponse(400, err_type="invalid_onboard", err_desc="No user under this e-mail in signup!",
                                debug_key="no_user_signup")
        else:
            raise e

    # Success here means removing any existing records in signedup and also the KV relating to that email

    email_usph = util.usp_hex(signup.email)
    register_id = util.random_time_hash_hex(email_usph)
    await data.user.new_user(dsrc, signed_up, register_id, av40id=signup.av40id, joined=signup.joined)

    config: Config = request.app.state.config

    # params = {
    #     "register": ""
    # }
    # confirmation_url = f"{credentials_url}email/?{urlencode(params)}"
    #
    # send_register_email(background_tasks, signup.email, config.MAIL_PASS, confirmation_url, signup_url)

    return {
        "ok": register_id
    }


@router.get("/onboard/userdata/{register_id}")
async def register_id_userdata(register_id: str, request: Request):
    dsrc: Source = request.app.state.dsrc

    try:
        ud = await data.user.get_userdata_by_register_id(dsrc, register_id)
    except DataError as e:
        logger.debug(e)
        reason = "No registration for that register_id"
        raise ErrorResponse(400, err_type="invalid_register", err_desc=reason, debug_key="no_register_for_id")

    return UserDataRegisterResponse(email=ud.email, firstname=ud.firstname, lastname=ud.lastname, phone=ud.phone)


@router.post("/onboard/register/", response_model=PasswordResponse)
async def start_register(register_start: RegisterRequest, request: Request):
    """ First step of OPAQUE registration, requires username and client message generated in first client registration
    step."""
    dsrc: Source = request.app.state.dsrc
    email_usph = util.usp_hex(register_start.email)
    try:
        ud = await data.user.get_userdata_by_register_id(dsrc, register_start.register_id)
    except DataError as e:
        logger.debug(e)
        reason = "No registration for that register_id"
        raise ErrorResponse(400, err_type="invalid_register", err_desc=reason, debug_key="no_register_for_id")

    try:
        u = await data.user.get_user_by_id(dsrc, ud.id)
    except DataError as e:
        logger.debug(e)
        reason = "No registration for that user"
        raise ErrorResponse(400, err_type="invalid_register", err_desc=reason, debug_key="no_register_for_user")

    if ud.registered or len(u.password_file) > 0:
        logger.debug("Already registered.")
        reason = "Bad registration."
        raise ErrorResponse(400, err_type="invalid_register", err_desc=reason, debug_key="bad_registration_start")

    if u.usp_hex != email_usph:
        logger.debug("Registration start does not match e-mail")
        reason = "Bad registration."
        raise ErrorResponse(400, err_type="invalid_register", err_desc=reason, debug_key="bad_registration_start")

    # OPAQUE public key
    public_key = await data.key.get_opaque_public(dsrc)
    auth_id = util.random_time_hash_hex(email_usph)

    response, saved_state = authentication.opaque_register(register_start.client_request, public_key, email_usph, ud.id)

    await data.kv.store_auth_register_state(dsrc, auth_id, saved_state)

    return PasswordResponse(server_message=response, auth_id=auth_id)


@router.post("/onboard/finish/")
async def finish_register(register_finish: FinishRequest, request: Request):
    dsrc: Source = request.app.state.dsrc
    try:
        saved_state = await data.kv.get_register_state(dsrc, register_finish.auth_id)
    except NoDataError as e:
        logger.debug(e.message)
        reason = "Registration not initialized or expired"
        raise ErrorResponse(400, err_type="invalid_registration", err_desc=reason, debug_key="no_register_start")

    email_usph = util.usp_hex(register_finish.email)
    if saved_state.user_usph != email_usph:
        reason = "User does not match state!"
        logger.debug(reason)
        raise ErrorResponse(400, err_type="invalid_registration", err_desc=reason, debug_key="unequal_user")

    password_file = opq.register_finish(register_finish.client_request, saved_state.state)

    try:
        ud = await data.user.get_userdata_by_register_id(dsrc, register_finish.register_id)
    except DataError as e:
        logger.debug(e)
        reason = "No registration for that register_id"
        raise ErrorResponse(400, err_type="invalid_register", err_desc=reason, debug_key="no_register_for_id")

    if ud.registered:
        logger.debug("Already registered.")
        reason = "Bad registration."
        raise ErrorResponse(400, err_type="invalid_register", err_desc=reason, debug_key="bad_registration")

    ud_email_usph = util.usp_hex(ud.email)
    if ud_email_usph != email_usph:
        logger.debug("Registration does not match e-mail")
        reason = "Bad registration."
        raise ErrorResponse(400, err_type="invalid_register", err_desc=reason, debug_key="bad_registration")

    new_user = User(id=saved_state.id, usp_hex=email_usph, password_file=password_file).dict()

    try:
        await data.user.upsert_user_row(dsrc, new_user)
    except DataError as e:
        logger.debug(e.message)
        if e.key == "unique_violation":
            raise ErrorResponse(400, err_type="invalid_registration", err_desc="Username already exists!",
                                debug_key="user_exists")
        else:
            raise e

    new_userdata = UserData(id=ud.id, firstname=ud.firstname, lastname=ud.lastname, callname=register_finish.callname,
                            email=ud.email, phone=ud.phone, av40id=ud.av40id, joined=ud.joined,
                            eduinstitution=register_finish.eduinstitution, birthdate=register_finish.birthdate,
                            active=True, registered=True)

    await data.user.upsert_userdata(dsrc, new_userdata)

    # send welcome email

    return {
        "ok": "ok"
    }
