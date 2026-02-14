"""Confirmation code storage and waiting utilities.

During signup and password reset flows, the auth server sends confirmation
codes (e.g. email verification codes) to the Python backend via the /email
endpoint.  These are stored in the database so that automated processes
(admin bootstrap, CLI tooling) can retrieve them without a real email inbox.

CodeWaiter polls the database for a code to appear, which is useful for
the admin bootstrap flow and integration tests.
"""

import json
import threading
from typing import Any

from freetser import Storage
from freetser.server import StorageQueue

CODES_TABLE = "tokens"


def add_code(store: Storage, action: str, email: str, code: str) -> None:
    """Store a confirmation code in the database."""
    key = f"{action}:{email}"
    value = json.dumps({"action": action, "email": email, "code": code}).encode("utf-8")
    # Delete any existing code first, then add new one
    store.delete(CODES_TABLE, key)
    store.add(CODES_TABLE, key, value)


def get_code(store: Storage, action: str, email: str) -> dict[str, Any] | None:
    """Get and remove a confirmation code from the database."""
    key = f"{action}:{email}"
    result = store.get(CODES_TABLE, key)
    if result is None:
        return None
    value_bytes, _ = result
    store.delete(CODES_TABLE, key)
    return json.loads(value_bytes.decode("utf-8"))


class CodeWaiter:
    """Polls the database for a confirmation code to appear.

    Used by admin bootstrap and CLI tooling to synchronously wait for
    email verification codes that the auth server delivers via /email.
    """

    def __init__(self, store_queue: StorageQueue):
        self.store_queue = store_queue
        self.condition = threading.Condition()

    def notify(self) -> None:
        """Notify waiters that a new code may be available."""
        with self.condition:
            self.condition.notify_all()

    def wait_for_code(self, action: str, email: str, timeout: float = 30.0) -> str:
        """Wait for a confirmation code and return it."""
        with self.condition:
            while True:

                def check(store: Storage) -> dict[str, Any] | None:
                    return get_code(store, action, email)

                result = self.store_queue.execute(check)
                if result is not None:
                    return result["code"]

                if not self.condition.wait(timeout=1.0):
                    timeout -= 1.0
                    if timeout <= 0:
                        raise TimeoutError(
                            f"Timeout waiting for {action} code for {email}"
                        )
