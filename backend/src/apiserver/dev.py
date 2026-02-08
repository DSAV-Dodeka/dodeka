"""Dev mode orchestrator for ``uv run dev``.

Manages the Go auth server and Python backend as subprocesses.  Both
servers run as separate processes so that ``restart`` (triggered by
``uv run da restart``) reloads all code from disk.

Control is done via a tiny HTTP server on 127.0.0.1:12795 that accepts
restart/stop/status commands from the CLI.  Ctrl+C (SIGINT) in the
terminal also triggers a graceful shutdown.
"""

import signal
import subprocess
import sys
import threading
from typing import IO, Callable

from freetser import Request, Response, TcpServerConfig, start_server

from apiserver.auth_binary import ensure_auth_binary, get_auth_binary_path
from apiserver.settings import DEFAULT_DEV_CONTROL_PORT, PRIVATE_HOST


def pipe_with_prefix(
    pipe: IO[bytes], prefix: str, write_fn: Callable[[str], None]
) -> None:
    """Read lines from a byte pipe and forward them with a prefix."""
    for line in iter(pipe.readline, b""):
        write_fn(f"{prefix} {line.decode().rstrip()}")
    pipe.close()


class ManagedProcess:
    """Manages a subprocess lifecycle with piped output.

    stdout/stderr are captured and forwarded with a prefix via write_fn.
    """

    def __init__(
        self,
        args: list[str],
        *,
        cwd: str | None = None,
        prefix: str = "",
        write_fn: Callable[[str], None] | None = None,
    ) -> None:
        self.args = args
        self.cwd = cwd
        self.prefix = prefix
        self.write_fn = write_fn or (lambda text: print(text, flush=True))
        self.process: subprocess.Popen[bytes] | None = None
        self.lock = threading.Lock()

    def start(self) -> None:
        """Start the subprocess and output-forwarding threads."""
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                return

            # Isolate child from parent's console/session so Ctrl+C only
            # reaches the orchestrator, which then terminates children.
            if sys.platform == "win32":
                self.process = subprocess.Popen(
                    self.args,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=self.cwd,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                )
            else:
                self.process = subprocess.Popen(
                    self.args,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=self.cwd,
                    start_new_session=True,
                )

            threading.Thread(
                target=pipe_with_prefix,
                args=(self.process.stdout, self.prefix, self.write_fn),
                daemon=True,
            ).start()
            threading.Thread(
                target=pipe_with_prefix,
                args=(self.process.stderr, self.prefix, self.write_fn),
                daemon=True,
            ).start()

    def stop(self) -> None:
        """Terminate the subprocess and wait for it to exit."""
        with self.lock:
            if self.process is None:
                return
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None

    def restart(self) -> None:
        """Stop then start the process."""
        self.stop()
        self.start()


def create_control_handler(
    restart_event: threading.Event, shutdown_event: threading.Event
) -> Callable[[Request, object], Response]:
    """Create the handler for the dev control server."""

    def handler(req: Request, _: object) -> Response:
        if req.method == "POST" and req.path == "/restart":
            restart_event.set()
            return Response.text("Restart signal sent.")
        if req.method == "POST" and req.path == "/stop":
            shutdown_event.set()
            return Response.text("Stop signal sent.")
        if req.method == "GET" and req.path == "/status":
            return Response.text("running")
        return Response.text("Not Found", status_code=404)

    return handler


def run_dev() -> None:
    """Run auth server and backend together for local development.

    Both servers run as subprocesses so that restart reloads all code
    from disk.  Use ``uv run da restart`` from another terminal to
    trigger a restart.
    """
    ensure_auth_binary()

    auth_path = get_auth_binary_path()
    if not auth_path.exists():
        msg = (
            f"Auth binary not found at {auth_path}.\n"
            "Run 'uv run update-auth' to download it, or build"
            " it with 'CGO_ENABLED=1 go build -o auth .' in"
            " backend/auth/."
        )
        raise SystemExit(msg)

    shutdown_event = threading.Event()
    restart_event = threading.Event()

    def handle_shutdown(signum: int, frame: object) -> None:
        shutdown_event.set()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    def write_fn(text: str) -> None:
        print(text, flush=True)

    auth = ManagedProcess(
        [
            str(auth_path),
            "--env-file",
            "envs/test/.env",
        ],
        cwd=str(auth_path.parent),
        prefix="[auth]",
        write_fn=write_fn,
    )

    backend = ManagedProcess(
        ["uv", "run", "test"],
        prefix="[backend]",
        write_fn=write_fn,
    )

    # Start control server for CLI commands (restart/stop/status)
    control_config = TcpServerConfig(host=PRIVATE_HOST, port=DEFAULT_DEV_CONTROL_PORT)
    control_handler = create_control_handler(restart_event, shutdown_event)
    threading.Thread(
        target=start_server,
        args=(control_config, control_handler),
        daemon=True,
    ).start()

    auth.start()
    backend.start()

    print("Dev servers started. Use 'uv run da restart' from another terminal.")

    try:
        while not shutdown_event.is_set():
            restart_event.wait(timeout=1.0)
            if restart_event.is_set():
                restart_event.clear()
                print("Restarting...")
                backend.stop()
                auth.restart()
                backend.start()
                print("Restart complete.")
    finally:
        backend.stop()
        auth.stop()
