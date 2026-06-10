"""Auth handlers for the public API.

- request_registration creates only a pending registration, does not start Faroe signup
- registration_status and renew_signup work by registration_id
- renew_signup requires accepted=True
- session_info does not return pending_approval
"""

import json
import logging
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
    get_registration,
    get_registration_by_email,
    normalize_email,
    upsert_registration,
)
from apiserver.data.user import InvalidSession, SessionInfo, get_user_info
from apiserver.server import (
    InvalidSessionToken,
    SESSION_COOKIE_PRIMARY,
    SESSION_COOKIE_SECONDARY,
    apply_session_cookie_security,
    get_cookie_value,
    make_clear_session_cookie_header,
    validate_session,
)
from apiserver.tooling.codes import peek_code

logger = logging.getLogger("apiserver.handlers.auth")


def request_registration(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Create or reuse a registration row. Does NOT start Faroe signup.

    Returns a generic success response without registration_id or signup_token.
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

    logger.info(f"request_registration: Registered {email}")
    return Response.json(
        {
            "success": True,
            "message": f"Registration request submitted for {email}",
        }
    )


def get_registration_status_handler(
    req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /auth/registration_status — resolve by registration_id."""
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        registration_id = body_data.get("registration_id")
        if not registration_id:
            logger.warning("get_registration_status: Missing registration_id")
            return Response.text("Missing registration_id", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"get_registration_status: Invalid request: {e}")
        return Response.text(f"Invalid request: {e}", status_code=400)

    def get_status(store: Storage) -> dict | None:
        reg = get_registration(store, registration_id)
        if reg is None:
            return None
        return {
            "exists": True,
            "email": reg.email,
            "accepted": reg.accepted,
            "signup_token": reg.signup_token,
        }

    result = store_queue.execute(get_status)
    if result is None:
        logger.info(f"get_registration_status: {registration_id} not found")
        return Response.text("Registration not found", status_code=404)

    logger.info(
        f"get_registration_status: Found status for {result['email']}, "
        f"accepted={result['accepted']}"
    )
    return Response.json(result)


def lookup_registration_handler(req: Request, store_queue: StorageQueue) -> Response:
    """Handle /auth/lookup_registration — look up by email and verification code.

    Returns the stable registration_id.
    """
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

        reg = get_registration_by_email(store, email)
        if reg is None:
            return {"found": False}

        return {"found": True, "registration_id": reg.registration_id}

    result = store_queue.execute(lookup)
    logger.info(f"lookup_registration: email={email}, found={result['found']}")
    return Response.json(result)


def renew_signup_handler(
    auth_client: AuthClient, req: Request, store_queue: StorageQueue
) -> Response:
    """Handle /auth/renew_signup — create fresh Faroe signup by registration_id.

    Requires accepted=True.
    """
    try:
        body_data = json.loads(req.body.decode("utf-8"))
        registration_id = body_data.get("registration_id")
        if not registration_id:
            return Response.text("Missing registration_id", status_code=400)
    except (json.JSONDecodeError, ValueError) as e:
        return Response.text(f"Invalid request: {e}", status_code=400)

    reg = store_queue.execute(lambda store: get_registration(store, registration_id))
    if reg is None:
        return Response.json({"error": "Registration not found"}, status_code=404)

    if not reg.accepted:
        return Response.json({"error": "Registration not accepted"}, status_code=400)

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
        r = get_registration(store, registration_id)
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
    smtp_config=None,
    smtp_send: bool = False,
    frontend_origin: str = "",
    environment: str = "production",
) -> Response:
    """Handle /auth/set_session/ — validate and set session cookie."""
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

    cookie_name = SESSION_COOKIE_SECONDARY if secondary else SESSION_COOKIE_PRIMARY
    logger.info(f"set_session: Setting {cookie_name} cookie for user {result.user_id}")

    max_session_age = 86400 * 365

    cookie = SimpleCookie()
    cookie[cookie_name] = session_token
    apply_session_cookie_security(cookie, cookie_name, environment)
    cookie[cookie_name]["max-age"] = max_session_age

    cookie_header = cookie[cookie_name].OutputString()

    return Response.empty(
        headers=[
            (b"Set-Cookie", cookie_header.encode("utf-8")),
        ],
    )


def clear_session(req: Request, environment: str = "production") -> Response:
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
    header = make_clear_session_cookie_header(cookie_name, environment)
    return Response.empty(headers=[header])


def session_info(
    auth_client: AuthClient,
    req: Request,
    headers: dict[str, str],
    store_queue: StorageQueue,
    environment: str = "production",
) -> Response:
    """Handle /auth/session_info/ — returns current user info and permissions.

    No pending_approval flag is returned.
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
            headers=[make_clear_session_cookie_header(cookie_name, environment)],
        )

    timestamp = int(time.time())

    def get_session_data(
        store: Storage,
    ) -> SessionInfo | InvalidSession:
        user = get_user_info(store, timestamp, result.user_id)
        if user is None:
            return InvalidSession()
        return SessionInfo(
            user=user,
            created_at=result.created_at,
            expires_at=result.expires_at,
        )

    session_result = store_queue.execute(get_session_data)

    if isinstance(session_result, InvalidSession):
        logger.warning(f"session_info: User {result.user_id} not found")
        return Response.json(
            {"error": "invalid_session"},
            status_code=401,
            headers=[make_clear_session_cookie_header(cookie_name, environment)],
        )

    session = session_result

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
