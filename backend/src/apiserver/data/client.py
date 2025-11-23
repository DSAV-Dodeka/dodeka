from typing import cast, override

import httpx
from tiauth_faroe.client import JSONValue, SyncClient


class AuthClient(SyncClient):
    pool: httpx.Client

    def __init__(self, auth_server_url: str):
        self.pool = httpx.Client(base_url=auth_server_url)

    @override
    def send_action_invocation_request(self, body: JSONValue) -> JSONValue:
        response = self.pool.post("/", json=body)
        print(f"status={response.status_code};text=\n{response.text}")
        return cast(JSONValue, response.json())
