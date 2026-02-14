"""Test fixtures for integration tests.

Starts the auth server (Go binary) and Python backend on free ports,
providing a TestServers object with helper functions for sending commands,
making HTTP requests, and calling the Faroe auth API directly.

Each test module gets a clean database: a module-scoped autouse fixture
resets both the backend and auth server before the first test in each file.
"""

import json
import os
import socket
import subprocess
import threading
import time
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest
import requests

from apiserver.app import run_with_settings
from apiserver.data.client import AuthClient
from apiserver.settings import PRIVATE_HOST, Settings
from apiserver.tooling.auth_binary import get_auth_binary_path

# Set by the servers fixture, read by pytest_terminal_summary on failure.
log_files: dict[str, Path] = {}


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add --save-server-logs option, auto-enabled when CI env var is set."""
    parser.addoption(
        "--save-server-logs",
        action="store_true",
        default=bool(os.environ.get("CI")),
        help="Save auth server logs to file and print on failure (auto-enabled in CI)",
    )


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


@dataclass
class TestServers:
    """Running test servers with helper functions."""

    command: Callable[..., dict | str]
    backend_url: str
    auth_url: str
    auth_client: AuthClient
    auth_command_url: str

    def reset_all(self) -> None:
        """Reset both backend and auth server to a clean state.

        Clears all tables in both servers and re-bootstraps the admin user.
        """
        # Reset auth server first (clears Faroe's user/session database)
        requests.post(
            f"{self.auth_command_url}/command",
            json={"command": "reset"},
            timeout=10,
        )
        # Reset backend (clears all tables, re-bootstraps admin)
        self.command("reset")
        # Wait for admin bootstrap to complete after reset
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            result = self.command("get_admin_credentials")
            if isinstance(result, dict) and "email" in result:
                return
            time.sleep(0.5)
        raise TimeoutError("Admin bootstrap did not complete after reset")


@pytest.fixture(scope="session")
def servers(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> Generator[TestServers]:
    """Start auth + backend servers and yield a TestServers object.

    Provides command helper, backend URL, auth URL, and an AuthClient
    for direct Faroe API calls.

    Skips all tests if the auth binary is not present.
    """
    auth_path = get_auth_binary_path()
    if not auth_path.exists():
        pytest.skip(f"Auth binary not found at {auth_path}")

    auth_port = freeport()
    auth_command_port = freeport(PRIVATE_HOST)
    backend_port = freeport()
    private_port = freeport(PRIVATE_HOST)

    tmppath = tmp_path_factory.mktemp("dodeka_test")

    # Write auth env file — all ports must be dynamic to avoid collisions
    # with running dev servers or parallel test runs
    auth_env = tmppath / "auth.env"
    auth_env.write_text(
        f"FAROE_PORT={auth_port}\n"
        f"FAROE_COMMAND_PORT={auth_command_port}\n"
        f"FAROE_USER_SERVER_PORT={private_port}\n"
        f"FAROE_DB_PATH={tmppath / 'auth_db.sqlite'}\n"
        f"FAROE_CORS_ALLOW_ORIGIN=http://localhost:3000\n"
    )

    # In CI (or with --save-server-logs), capture server logs to files
    # for printing on failure. Locally, discard output.
    save_logs = request.config.getoption("--save-server-logs")
    if save_logs:
        auth_log_path = tmppath / "auth_server.log"
        log_files["auth"] = auth_log_path
        auth_log_handle = auth_log_path.open("w")
        auth_out = auth_log_handle
        backend_log_path = tmppath / "backend_server.log"
        log_files["backend"] = backend_log_path
    else:
        auth_log_handle = None
        auth_out = subprocess.DEVNULL
        backend_log_path = None

    auth_process = subprocess.Popen(
        [str(auth_path), "--env-file", str(auth_env)],
        stdout=auth_out,
        stderr=subprocess.STDOUT,
        cwd=str(auth_path.parent),
    )

    try:
        # Wait for auth server to be ready
        auth_url = f"http://localhost:{auth_port}"
        assert waitfor(auth_url), f"Auth server failed to start on port {auth_port}"

        # Create backend settings with free ports and temp database
        settings = Settings(
            db_file=tmppath / "backend_db.sqlite",
            environment="test",
            auth_server_url=auth_url,
            frontend_origin="http://localhost:3000",
            debug_logs=True,
            port=backend_port,
            private_port=private_port,
        )

        # Use ready_event for backend readiness instead of HTTP polling
        ready_event = threading.Event()

        # Start backend in daemon thread (run_with_settings blocks)
        threading.Thread(
            target=run_with_settings,
            args=(settings,),
            kwargs={"ready_event": ready_event, "log_file": backend_log_path},
            daemon=True,
        ).start()

        # Wait for backend server to be ready
        ready_event.wait(timeout=15)
        assert ready_event.is_set(), (
            f"Backend server failed to start on port {backend_port}"
        )

        # Build command helper
        command_url = f"http://{PRIVATE_HOST}:{private_port}/command"
        backend_url = f"http://localhost:{backend_port}"
        auth_command_url = f"http://{PRIVATE_HOST}:{auth_command_port}"

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

        auth_client = AuthClient(auth_url, timeout=10)

        yield TestServers(
            command=send,
            backend_url=backend_url,
            auth_url=auth_url,
            auth_client=auth_client,
            auth_command_url=auth_command_url,
        )

    finally:
        auth_process.terminate()
        auth_process.wait(timeout=5)
        if auth_log_handle is not None:
            auth_log_handle.close()


@pytest.fixture(autouse=True, scope="module")
def clean_state(servers: TestServers) -> None:
    """Reset both servers before each test module for isolation."""
    servers.reset_all()


@pytest.fixture(scope="session")
def command(servers: TestServers) -> Callable[..., dict | str]:
    """Backward-compatible fixture: send commands to the private server."""
    return servers.command


@pytest.fixture(scope="session")
def backend_url(servers: TestServers) -> str:
    """Public backend API URL."""
    return servers.backend_url


@pytest.fixture(scope="session")
def auth_client(servers: TestServers) -> AuthClient:
    """AuthClient for direct Faroe API calls."""
    return servers.auth_client


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter, exitstatus: int, config: pytest.Config
) -> None:
    """Print server logs when tests fail."""
    if exitstatus != 0:
        for name, path in log_files.items():
            if path.exists():
                terminalreporter.section(f"{name} server log")
                terminalreporter.write(path.read_text())
