import json
import logging
import socket
import threading
from pathlib import Path
from typing import Any

import requests
from tiauth_faroe.client import ActionErrorResult

from apiserver.data.client import AuthClient

HTTP_OK = 200
logger = logging.getLogger("apiserver.actions")


class AdminUserCreationError(Exception):
    pass


class MessageReader:
    """Simple reader for messages stored in shared list with proper waiting."""

    def __init__(
        self,
        messages: list[dict[str, Any]],
        condition: threading.Condition,
    ):
        self.messages = messages
        self.condition = condition

    def find_and_pop(
        self,
        type: str,
        email: str,
    ) -> dict[str, Any]:
        """Find and remove first matching message, waiting if needed."""
        while True:
            for i, msg in enumerate(self.messages):
                if msg.get("type") != type:
                    continue
                if msg.get("email") != email:
                    continue
                return self.messages.pop(i)

            self.condition.wait()


def start_socket_reader(
    socket_path: str | Path,
    messages: list[dict[str, Any]],
    condition: threading.Condition,
) -> threading.Thread:
    """Start background thread that reads from Unix socket and stores messages."""
    running = threading.Event()
    running.set()

    def read_loop():
        path = Path(socket_path)
        if not path.exists():
            threading.Event().wait(1.0)
            raise ValueError(f"Unix socket path {path!s} does not exist.")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(str(path))

        buffer = b""
        while running.is_set():
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    try:
                        msg = json.loads(line.decode("utf-8"))
                        if isinstance(msg, dict):
                            with condition:
                                messages.append(msg)
                                condition.notify_all()
                            logger.debug(f"Unix socket message received: {msg}")
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        logger.warning(f"Invalid unix socket message: {e}")
            except socket.timeout:
                continue

        sock.close()

    thread = threading.Thread(target=read_loop, daemon=True)
    thread.start()
    return thread


class AppClient:
    """
    Client for interacting with the app's private routes and auth operations.
    Uses AuthClient directly for tiauth_faroe operations.
    """

    session: requests.Session
    app_base_url: str
    private_key: str
    auth_client: AuthClient

    def __init__(self, app_url: str, auth_server_url: str, private_key: str):
        self.session = requests.Session()
        self.app_base_url = app_url
        self.private_key = private_key
        self.auth_client = AuthClient(auth_server_url)

    def _private_headers(self) -> dict[str, str]:
        """Get headers with private route access key."""
        return {"x-private-route-access-key": self.private_key}

    def delete_user(self, email: str) -> requests.Response:
        """Delete user by email using private route."""
        url = f"{self.app_base_url}/private/delete_user/"
        response = self.session.post(
            url, json={"email": email}, headers=self._private_headers()
        )
        return response

    def add_admin_permission(self, user_id: str) -> requests.Response:
        """Add admin permission to user using private route."""
        url = f"{self.app_base_url}/private/add_admin_permission/"
        response = self.session.post(
            url, json={"user_id": user_id}, headers=self._private_headers()
        )
        return response

    def prepare_user(
        self, email: str, names: list[str] | None = None
    ) -> requests.Response:
        """Prepare user in newusers table with accepted=True."""
        url = f"{self.app_base_url}/private/prepare_user"
        response = self.session.post(
            url,
            json={"email": email, "names": names or []},
            headers=self._private_headers(),
        )
        return response


def create_admin_user(
    client: AppClient,
    email: str,
    password: str,
    message_reader: MessageReader,
    names: list[str] | None = None,
) -> tuple[str, str]:
    delete_resp = client.delete_user(email)
    if delete_resp.status_code != HTTP_OK:
        raise AdminUserCreationError(
            f"Failed to delete user: HTTP {delete_resp.status_code} - "
            f"{delete_resp.text}"
        )

    prepare_resp = client.prepare_user(email, names)
    if prepare_resp.status_code != HTTP_OK:
        raise AdminUserCreationError(
            f"Failed to prepare user: HTTP {prepare_resp.status_code} - "
            f"{prepare_resp.text}"
        )

    signup_result = client.auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        raise AdminUserCreationError(
            f"Failed to create signup: {signup_result.error_code}"
        )
    signup_token = signup_result.signup_token

    msg = message_reader.find_and_pop(type="signup_verification", email=email)
    if not msg.get("code"):
        raise AdminUserCreationError("Timeout waiting for email verification code")
    verification_code = msg["code"]

    # Verify email address
    verify_result = client.auth_client.verify_signup_email_address_verification_code(
        signup_token, verification_code
    )
    if isinstance(verify_result, ActionErrorResult):
        raise AdminUserCreationError(
            f"Failed to verify email: {verify_result.error_code}"
        )

    password_result = client.auth_client.set_signup_password(signup_token, password)
    if isinstance(password_result, ActionErrorResult):
        raise AdminUserCreationError(
            f"Failed to set password: {password_result.error_code}"
        )

    complete_result = client.auth_client.complete_signup(signup_token)
    if isinstance(complete_result, ActionErrorResult):
        raise AdminUserCreationError(
            f"Failed to complete signup: {complete_result.error_code}"
        )

    user_id = complete_result.session.user_id
    session_token = complete_result.session_token

    admin_resp = client.add_admin_permission(user_id)
    if admin_resp.status_code != HTTP_OK:
        raise AdminUserCreationError(
            f"Failed to add admin permission: HTTP {admin_resp.status_code} - "
            f"{admin_resp.text}"
        )

    return (user_id, session_token)
