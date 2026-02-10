import logging
from typing import cast, override

import requests
from requests.adapters import HTTPAdapter
from tiauth_faroe.client import JSONValue, SyncClient
from urllib3.util.retry import Retry

logger = logging.getLogger("apiserver.client")


class AuthClient(SyncClient):
    """Client for communicating with tiauth-faroe auth server.

    Args:
        auth_server_url: Base URL of the auth server.
        timeout: Request timeout in seconds (connect + read). None means no timeout.
        connect_retries: Number of retries on connection failure (e.g. server not
            started yet). Uses exponential backoff (0.5s base). 0 means no retries.
    """

    session: requests.Session
    base_url: str
    timeout: float | None

    def __init__(
        self,
        auth_server_url: str,
        *,
        timeout: float | None = None,
        connect_retries: int = 0,
    ):
        self.session = requests.Session()
        self.base_url = auth_server_url
        self.timeout = timeout

        if connect_retries > 0:
            retry = Retry(connect=connect_retries, backoff_factor=0.5)
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

    @override
    def send_action_invocation_request(self, body: JSONValue) -> JSONValue:
        response = self.session.post(
            f"{self.base_url}/", json=body, timeout=self.timeout
        )
        logger.debug(f"status={response.status_code};text=\n{response.text}")
        return cast(JSONValue, response.json())
