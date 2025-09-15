from typing import Mapping, Any
from fastapi import APIRouter, Request, Response

from tiauth_faroe.user_server import handle_request_sync
from apiserver.app.dependencies import DbDep, JsonDep
from apiserver.data.auth import SqliteSyncServer

router = APIRouter(prefix='/auth', tags=["auth"])


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
