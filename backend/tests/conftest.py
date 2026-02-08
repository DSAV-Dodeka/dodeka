"""Test fixtures for integration tests.

Starts the auth server (Go binary) and Python backend on free ports,
providing a command helper to send requests to the private server.
"""

import json
import socket
import subprocess
import threading
import time
from typing import Any

import pytest
import requests

from apiserver.app import run_with_settings
from apiserver.auth_binary import get_auth_binary_path
from apiserver.settings import PRIVATE_HOST, Settings


def freeport(host: str = "") -> int:
    """Find a free TCP port on the given host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def waitfor(url: str, timeout: float = 15) -> bool:
    """Poll an HTTP URL until it responds or timeout is reached."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            requests.get(url, timeout=1)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(0.2)
    return False


@pytest.fixture(scope="session")
def command(tmp_path_factory: pytest.TempPathFactory):
    """Start auth + backend servers and yield a command helper function.

    The helper sends commands to the backend's private server and returns
    the parsed JSON response (or raw text if not JSON).

    Skips all tests if the auth binary is not present.
    """
    auth_path = get_auth_binary_path()
    if not auth_path.exists():
        pytest.skip(f"Auth binary not found at {auth_path}")

    auth_port = freeport()
    backend_port = freeport()
    private_port = freeport(PRIVATE_HOST)

    tmppath = tmp_path_factory.mktemp("dodeka_test")

    # Write auth env file
    auth_env = tmppath / "auth.env"
    auth_env.write_text(
        f"FAROE_PORT={auth_port}\n"
        f"FAROE_USER_SERVER_PORT={private_port}\n"
        f"FAROE_DB_PATH={tmppath / 'auth_db.sqlite'}\n"
        f"FAROE_CORS_ALLOW_ORIGIN=http://localhost:3000\n"
    )

    # Start auth binary (suppress output to avoid pipe buffer blocking)
    auth_process = subprocess.Popen(
        [str(auth_path), "--env-file", str(auth_env)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(auth_path.parent),
    )

    try:
        # Wait for auth server to be ready
        assert waitfor(f"http://localhost:{auth_port}"), (
            f"Auth server failed to start on port {auth_port}"
        )

        # Create backend settings with free ports and temp database
        settings = Settings(
            db_file=tmppath / "backend_db.sqlite",
            environment="test",
            auth_server_url=f"http://localhost:{auth_port}",
            frontend_origin="http://localhost:3000",
            debug_logs=True,
            port=backend_port,
            private_port=private_port,
        )

        # Start backend in daemon thread (run_with_settings blocks)
        threading.Thread(
            target=run_with_settings,
            args=(settings,),
            daemon=True,
        ).start()

        # Wait for backend server to be ready
        assert waitfor(f"http://localhost:{backend_port}"), (
            f"Backend server failed to start on port {backend_port}"
        )

        # Build command helper
        command_url = f"http://{PRIVATE_HOST}:{private_port}/command"

        def send(name: str, **kwargs: Any) -> dict | str:
            payload = {"command": name, **kwargs}
            response = requests.post(command_url, json=payload, timeout=10)
            try:
                return json.loads(response.text)
            except json.JSONDecodeError:
                return response.text

        # Wait for admin bootstrap to complete
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            result = send("get_admin_credentials")
            if isinstance(result, dict) and "email" in result:
                break
            time.sleep(0.5)
        else:
            pytest.fail("Admin bootstrap did not complete within 20 seconds")

        yield send

    finally:
        auth_process.terminate()
        auth_process.wait(timeout=5)
