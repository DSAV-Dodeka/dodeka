from typing import Literal, Mapping, Any, Annotated
from fastapi import APIRouter, Request, Response, Header
from pydantic import BaseModel

from tiauth_faroe.user_server import handle_request_sync
from apiserver.settings import settings
from apiserver.app.dependencies import DbDep, JsonDep, SessionDep, TimeDep
from apiserver.data.user import InvalidSession, SessionInfo
from apiserver.data.auth import SqliteSyncServer
from apiserver.data.newuser import clear_all_users, clear_all_newusers, prepare_user_store

router = APIRouter(prefix='/auth', tags=["auth"])


class PrepareUserRequest(BaseModel):
    email: str
    names: list[str] = []

class JSONStrResponse(Response):
    """Useful if the JSON object is already seralized as a string."""
    media_type = "application/json"

    def __init__(
        self,
        serialized_body: str,
        status_code: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(serialized_body, status_code, headers, self.media_type)

    def render(self, content: Any) -> bytes:
        if not isinstance(content, str):
            raise Exception("Not initialized with serialized body!")
        return content.encode("utf-8")


@router.post("/invoke_user_action")
def invoke_action(request_json: JsonDep, db: DbDep) -> JSONStrResponse:
    server = SqliteSyncServer(db)
    result = handle_request_sync(request_json, server)

    if result.error is not None:
        print(result.error)

    print(result.response_json)

    return JSONStrResponse(result.response_json)


@router.post("/clear_tables")
def clear_tables(db: DbDep) -> None:
    """Clear both user and newuser tables for testing/setup purposes."""

    # TODO: figure out best way to define transactions here
    clear_all_users(db)
    clear_all_newusers(db)

    print(f"cleared!\n")

@router.post("/prepare_user")
def prepare_user(db: DbDep, prepare: PrepareUserRequest) -> None:
    """Prepare a user in the newuser store so they can be created via standard auth actions."""

    prepare_user_store(db, prepare.email, prepare.names)

    print(f"prepared {prepare.email}\n")

class SetSession(BaseModel):
    session_token: str

max_session_age = 86400 * 365

@router.post("/set_session/")
def set_session(origin: Annotated[str, Header()], set: SetSession, response: Response):
    if origin != settings.frontend_origin:
        raise ValueError("Invalid origin!")
    response.set_cookie("session_token", set.session_token, httponly=True, samesite='none', secure=True, path = "/", max_age=max_session_age)

    return None


class InvalidSessionResponse(BaseModel):
    error: Literal["invalid_session"] | Literal["no_session"]

@router.get("/session_info/")
def session_info(session: SessionDep) -> SessionInfo | InvalidSessionResponse:
    if session is None:
        return InvalidSessionResponse(error="no_session")
    if isinstance(session, InvalidSession):
        return InvalidSessionResponse(error="invalid_session")

    return session
