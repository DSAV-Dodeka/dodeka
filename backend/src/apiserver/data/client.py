import httpx
from typing import override, cast
from tiauth_faroe.client import JSONValue, AsyncClient

class AuthClient(AsyncClient):
    pool: httpx.AsyncClient

    def __init__(self, auth_server_url: str):
        self.pool = httpx.AsyncClient(base_url=auth_server_url)


    @override
    async def send_action_invocation_request(self, body: JSONValue) -> JSONValue:
        response = await self.pool.post(
            "/",
            json=body
        )
        print(f"status={response.status_code};text=\n{response.text}")
        return cast(JSONValue, response.json())
