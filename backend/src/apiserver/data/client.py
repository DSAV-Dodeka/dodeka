import logging
from typing import cast, override

import requests
from tiauth_faroe.client import JSONValue, SyncClient

logger = logging.getLogger("apiserver.client")


class AuthClient(SyncClient):
    session: requests.Session
    base_url: str

    def __init__(self, auth_server_url: str):
        self.session = requests.Session()
        self.base_url = auth_server_url

    @override
    def send_action_invocation_request(self, body: JSONValue) -> JSONValue:
        response = self.session.post(f"{self.base_url}/", json=body)
        logger.debug(f"status={response.status_code};text=\n{response.text}")
        return cast(JSONValue, response.json())
