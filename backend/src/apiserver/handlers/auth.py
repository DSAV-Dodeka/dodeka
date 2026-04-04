"""Auth handlers for the public API.

Handles registration, signup, session management, and related flows.
"""

import json
import logging
import smtplib
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

from freetser import Request, Response, Storage
from freetser.server import StorageQueue
from tiauth_faroe.client import ActionErrorResult

from apiserver.data.client import AuthClient
from apiserver.data.registrations import (
    EmailExistsInUserTable,
    Registration,
    create_or_reuse_registration,
    delete_registration,
    get_registration,
    get_registration_by_token,
    normalize_email,
    upsert_registration,
)
from apiserver.data.user import InvalidSession, SessionInfo, get_user_info
from apiserver.email import EmailData, sendemail
from apiserver.server import (
    InvalidSessionToken,
    SESSION_COOKIE_PRIMARY,
    SESSION_COOKIE_SECONDARY,
    get_cookie_value,
    make_clear_session_cookie_header,
    validate_session,
)
from apiserver.settings import SmtpConfig
from apiserver.tooling.codes import peek_code

logger = logging.getLogger("apiserver.handlers.auth")


def request_registration(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Create or reuse a registration row and attempt Faroe signup.

    Returns registration_token (stable) and signup_token (ephemeral).
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email_raw = body_data.get("email")
        firstname = body_data.get("firstname", "")
        lastname = body_data.get("lastname", "")
        if not email_raw:
            logger.warning("request_registration: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"request_registration: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    email = normalize_email(email_raw)

    def register(store: Storage) -> Registration | EmailExistsInUserTable:
        if store.get("users_by_email", email) is not None:
            return EmailExistsInUserTable(email=email)
        return create_or_reuse_registration(store, email, firstname, lastname)

    result = store_queue.execute(register)
    if isinstance(result, EmailExistsInUserTable):
        logger.error(
            f"request_registration: Email {email} already exists in user table"
        )
        return Response.text(
            "User with e-mail already exists in user table", status_code=400
        )

    reg = result
    registration_token = reg.registration_token

    # Attempt Faroe signup (sends verification email)
    signup_result = auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        logger.error(
            f"request_registration: Faroe signup failed for {email}: "
            f"{signup_result.error_code}"
        )
        return Response.json(
            {
                "success": True,
                "message": (
                    f"Registration created but signup failed:"
                    f" {signup_result.error_code}"
                ),
                "registration_token": registration_token,
                "signup_token": None,
            }
        )

    signup_token = signup_result.signup_token

    # Store signup_token in registration
    def save_signup_token(store: Storage) -> None:
        r = get_registration(store, email)
        if r is not None:
            r.signup_token = signup_token
            upsert_registration(store, r)

    store_queue.execute(save_signup_token)

    logger.info(
        f"request_registration: Registered {email} with token {registration_token}"
    )
    return Response.json(
        {
            "success": True,
            "message": f"Registration request submitted for {email}",
            "registration_token": registration_token,
            "signup_token": signup_token,
        }
    )


def get_registration_status_handler(
    req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /auth/registration_status — resolve by registration_token."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        registration_token = body_data.get("registration_token")
        if not registration_token:
            logger.warning("get_registration_status: Missing registration_token")
            return Response.text("Missing registration_token", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"get_registration_status: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    def get_status(store: Storage) -> dict | None:
        reg = get_registration_by_token(store, registration_token)
        if reg is None:
            return None
        return {
            "email": reg.email,
            "accepted": reg.accepted,
            "account_created": reg.account_created,
            "signup_token": reg.signup_token,
            "notify_on_completion": reg.notify_on_completion,
        }

    result = store_queue.execute(get_status)
    if result is None:
        logger.info(f"get_registration_status: Token {registration_token} not found")
        return Response.text("Registration token not found", status_code=404)

    logger.info(
        f"get_registration_status: Found status for {result['email']}, "
        f"accepted={result['accepted']}"
    )
    return Response.json(result)


def lookup_registration_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /auth/lookup_registration — look up by email and verification code."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email_raw = body_data.get("email")
        code = body_data.get("code")
        if not email_raw or not code:
            logger.warning("lookup_registration: Missing email or code")
            return Response.text("Missing email or code", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"lookup_registration: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    email = normalize_email(email_raw)

    def lookup(store: Storage) -> dict:
        stored = peek_code(store, "signup_verification", email)
        if stored is None or stored.get("code") != code:
            return {"found": False}

        reg = get_registration(store, email)
        if reg is None:
            return {"found": False}

        return {"found": True, "token": reg.registration_token}

    result = store_queue.execute(lookup)
    logger.info(f"lookup_registration: email={email}, found={result['found']}")
    return Response.json(result)


def resend_signup_email_handler(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /admin/resend_signup_email/ — resend or create new signup."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        email_raw = body_data.get("email")
        if not email_raw:
            logger.warning("resend_signup_email: Missing email in request")
            return Response.text("Missing email", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"resend_signup_email: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    email = normalize_email(email_raw)

    reg = store_queue.execute(lambda store: get_registration(store, email))
    if reg is None:
        logger.warning(f"resend_signup_email: No registration found for {email}")
        return Response.json(
            {"error": f"No registration found for {email}"}, status_code=404
        )

    # Try resending with existing token (fast path when signup is still active)
    if reg.signup_token is not None:
        result = auth_client.send_signup_email_address_verification_code(
            reg.signup_token
        )
        if not isinstance(result, ActionErrorResult):
            logger.info(f"resend_signup_email: Resent verification email to {email}")
            return Response.json(
                {"success": True, "message": f"Email resent to {email}"}
            )
        logger.info(
            f"resend_signup_email: Token invalid ({result.error_code}), "
            f"creating new signup for {email}"
        )

    # Create new signup
    signup_result = auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        logger.error(
            f"resend_signup_email: Failed to create signup for "
            f"{email}: {signup_result.error_code}"
        )
        return Response.json(
            {
                "error": "Failed to initiate signup",
                "error_code": signup_result.error_code,
            },
            status_code=400,
        )

    new_token = signup_result.signup_token

    def save_token(store: Storage) -> None:
        r = get_registration(store, email)
        if r is not None:
            r.signup_token = new_token
            upsert_registration(store, r)

    store_queue.execute(save_token)

    logger.info(f"resend_signup_email: New signup created, email sent to {email}")
    return Response.json({"success": True, "message": f"Signup email sent to {email}"})


def renew_signup_handler(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /auth/renew_signup — create fresh Faroe signup by registration_token."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        registration_token = body_data.get("registration_token")
        if not registration_token:
            return Response.text("Missing registration_token", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    reg = store_queue.execute(
        lambda store: get_registration_by_token(store, registration_token)
    )
    if reg is None:
        return Response.json({"error": "Registration not found"}, status_code=404)

    email = reg.email

    signup_result = auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        logger.error(f"renew_signup: Failed for {email}: {signup_result.error_code}")
        return Response.json(
            {
                "error": "Failed to create signup",
                "error_code": signup_result.error_code,
            },
            status_code=400,
        )

    new_token = signup_result.signup_token

    def save_token(store: Storage) -> None:
        r = get_registration(store, email)
        if r is not None:
            r.signup_token = new_token
            upsert_registration(store, r)

    store_queue.execute(save_token)

    logger.info(f"renew_signup: New signup created for {email}")
    return Response.json({"success": True, "signup_token": new_token, "email": email})


def set_session(
    auth_client: AuthClient,
    req: Request,
    store_queue: StorageQueue,
    smtp_config: SmtpConfig | None = None,
    smtp_send: bool = False,
    frontend_origin: str = "",
) -> Response:
    """Handle /auth/set_session/ — validate and set session cookie.

    Also handles deferred acceptance emails: if notify_on_completion is set,
    sends account_accepted_self and deletes the registration row.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        session_token = body_data.get("session_token")
        secondary = body_data.get("secondary", False)
        if not session_token:
            logger.warning("set_session: Missing session_token in request")
            return Response.text("Missing session_token", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"set_session: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    result = validate_session(auth_client, session_token, store_queue)
    if isinstance(result, InvalidSessionToken):
        logger.info("set_session: Session validation failed")
        return Response.text("Invalid session_token", status_code=401)

    # Check for deferred acceptance email (don't delete yet — need retry on failure)
    def check_notify(store: Storage) -> tuple[bool, str | None]:
        user_info = get_user_info(store, int(time.time()), result.user_id)
        if user_info is None:
            return False, None
        email = user_info.email
        reg = get_registration(store, email)
        if reg is not None and reg.notify_on_completion:
            return True, email
        return False, None

    should_notify, user_email = store_queue.execute(check_notify)
    if should_notify and user_email:
        try:
            link = frontend_origin
            email_data = EmailData(
                email_type="account_accepted_self",
                to_email=user_email,
                link=link,
            )
            sendemail(smtp_config, email_data, smtp_send)
            logger.info(f"set_session: Sent deferred acceptance email to {user_email}")
            store_queue.execute(lambda store: delete_registration(store, user_email))
        except (smtplib.SMTPException, OSError) as exc:
            logger.error(
                f"set_session: Failed to send deferred email to {user_email}: {exc}"
            )

    cookie_name = SESSION_COOKIE_SECONDARY if secondary else SESSION_COOKIE_PRIMARY
    logger.info(f"set_session: Setting {cookie_name} cookie for user {result.user_id}")

    max_session_age = 86400 * 365

    cookie = SimpleCookie()
    cookie[cookie_name] = session_token
    cookie[cookie_name]["httponly"] = True
    cookie[cookie_name]["samesite"] = "None"
    cookie[cookie_name]["secure"] = True
    cookie[cookie_name]["path"] = "/"
    cookie[cookie_name]["max-age"] = max_session_age

    cookie_header = cookie[cookie_name].OutputString()

    return Response.empty(
        headers=[
            (b"Set-Cookie", cookie_header.encode("utf-8")),
        ],
    )


def clear_session(req: Request) -> Response:
    """Handle /auth/clear_session/ — clear session cookie."""
    secondary = False
    if req.body:
        try:
            body_data = json.loads(req.body.decode("utf-8"))
            secondary = body_data.get("secondary", False)
        except json.JSONDecodeError, ValueError:
            pass

    cookie_name = SESSION_COOKIE_SECONDARY if secondary else SESSION_COOKIE_PRIMARY
    logger.info(f"clear_session: Clearing {cookie_name} cookie")
    return Response.empty(headers=[make_clear_session_cookie_header(cookie_name)])


def session_info(
    auth_client: AuthClient,
    req: Request,
    headers: dict[str, str],
    store_queue: StorageQueue,
) -> Response:
    """Handle /auth/session_info/ — returns current user info and permissions.

    pending_approval is True when a registrations row exists with
    account_created=True and accepted=False.
    """
    secondary = False
    if "?" in req.path:
        query = parse_qs(urlparse(req.path).query)
        secondary = query.get("secondary", [""])[0].lower() == "true"

    cookie_name = SESSION_COOKIE_SECONDARY if secondary else SESSION_COOKIE_PRIMARY
    session_token = get_cookie_value(headers, cookie_name)

    if session_token is None:
        logger.debug(f"session_info: No {cookie_name} cookie found")
        return Response.json({"error": "no_session"})

    result = validate_session(auth_client, session_token, store_queue)
    if isinstance(result, InvalidSessionToken):
        logger.info(f"session_info: {cookie_name} validation failed")
        return Response.json(
            {"error": "invalid_session"},
            status_code=401,
            headers=[make_clear_session_cookie_header(cookie_name)],
        )

    timestamp = int(time.time())

    def get_session_data(
        store: Storage,
    ) -> tuple[SessionInfo, bool] | InvalidSession:
        user = get_user_info(store, timestamp, result.user_id)
        if user is None:
            return InvalidSession()
        reg = get_registration(store, user.email)
        pending = reg is not None and reg.account_created and not reg.accepted
        return (
            SessionInfo(
                user=user,
                created_at=result.created_at,
                expires_at=result.expires_at,
            ),
            pending,
        )

    session_result = store_queue.execute(get_session_data)

    if isinstance(session_result, InvalidSession):
        logger.warning(f"session_info: User {result.user_id} not found")
        return Response.json(
            {"error": "invalid_session"},
            status_code=401,
            headers=[make_clear_session_cookie_header(cookie_name)],
        )

    session, pending_approval = session_result

    logger.debug(f"session_info: Returning info for user {result.user_id}")
    return Response.json(
        {
            "user": {
                "user_id": session.user.user_id,
                "email": session.user.email,
                "firstname": session.user.firstname,
                "lastname": session.user.lastname,
                "permissions": list(session.user.permissions),
            },
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "pending_approval": pending_approval,
        }
    )


def get_session_token_handler(headers: dict[str, str]) -> Response:
    """Handle /cookies/session_token/ — returns session token from primary cookie."""
    session_token = get_cookie_value(headers, SESSION_COOKIE_PRIMARY)

    if session_token is None:
        logger.debug("get_session_token: No session cookie found")
        return Response.json({"error": "no_session"}, status_code=401)

    logger.debug("get_session_token: Returning session token")
    return Response.json({"session_token": session_token})
