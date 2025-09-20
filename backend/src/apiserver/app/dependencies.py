
from datetime import datetime, timezone
from typing import Annotated, Any
from fastapi import Depends, Request, Cookie
from pydantic import BaseModel
from apiserver.data import Db
from apiserver.data.client import AuthClient

from apiserver.data.permissions import UserSession, get_session
# from apiserver.app.error import ErrorResponse
# from apiserver.app.ops.header import auth_header, verify_token_header
# from apiserver.data.context.app_context import Code, SourceContexts

# from apiserver.data.source import Source
# from apiserver.lib.model.entities import AccessToken
# from apiserver.lib.resource.error import ResourceError, resource_error_code

# Due to some internal stuff in FastAPI/Starlette, it's important to make all dependencies async. https://github.com/tiangolo/fastapi/discussions/5999


async def dep_db(request: Request) -> Db:
    db: Db = request.state.db
    return db

async def dep_auth_client(request: Request) -> AuthClient:
    client: AuthClient = request.state.auth_client
    return client

async def dep_json(request: Request) -> Any:
    return await request.json()

async def dep_time() -> int:
    return int(datetime.now(timezone.utc).timestamp())


DbDep = Annotated[Db, Depends(dep_db)]
JsonDep = Annotated[Any, Depends(dep_json)]
AuthClientDep = Annotated[AuthClient, Depends(dep_auth_client)]
TimeDep = Annotated[int, Depends(dep_time)]
# Authorization = Annotated[str, Depends(auth_header)]
#
#

async def dep_session(db: DbDep, auth_client: AuthClientDep, timestamp: TimeDep, session_token: Annotated[str, Cookie()]) -> UserSession:
    return await get_session(db, auth_client, timestamp, session_token)

SessionDep = Annotated[UserSession, Depends(dep_session)]


# AccessDep = Annotated[AccessToken, Depends(dep_header_token)]


# def verify_user(acc: AccessToken, user_id: str) -> bool:
#     """Verifies if the user in the access token corresponds to the provided user_id.

#     Args:
#         acc: AccessToken object.
#         user_id: user_id that will be compared against.

#     Returns:
#         True if user_id = acc.sub.

#     Raises:
#         ErrorResponse: If access token subject does not correspond to user_id.
#     """
#     if acc.sub != user_id:
#         reason = "Resource not available to this subject."
#         raise ErrorResponse(
#             403, err_type="wrong_subject", err_desc=reason, debug_key="bad_sub"
#         )

#     return True


# def has_scope(scopes: str, required: set[str]) -> bool:
#     scope_set = set(scopes.split())
#     return required.issubset(scope_set)


def require_admin():
    #     if not has_scope(acc.scope, {"admin"}):
    #         raise ErrorResponse(
    #             403,
    #             err_type="insufficient_scope",
    #             err_desc="Insufficient permissions to access this resource.",
    #             debug_key="low_perms",
    #         )

    #     return acc
    raise Exception("not implemented!")


class Member(BaseModel):
    user_id: str

async def require_member(session: SessionDep) -> Member:
    if "member" not in session.permissions:
        raise ValueError("Insufficient permissions!")

    return Member(user_id=session.user_id)




RequireMember = Annotated[Member, Depends(require_member)]
RequireAdmin = Annotated[None, Depends(require_admin)]
