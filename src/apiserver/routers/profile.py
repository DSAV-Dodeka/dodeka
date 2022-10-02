from fastapi import APIRouter, Security, Request

from apiserver.data import Source
from apiserver.auth.header import auth_header
from apiserver.routers.helper import handle_auth

router = APIRouter()


@router.get("/res/profile/")
async def get_profile(request: Request, authorization: str = Security(auth_header)):
    dsrc: Source = request.app.state.dsrc
    acc = await handle_auth(authorization, dsrc)

    return {"username": acc.sub, "scope": acc.scope}
