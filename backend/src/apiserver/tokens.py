"""Token storage and waiting utilities.

Tokens are used for email verification codes during signup/password reset flows.
The TokenWaiter allows synchronous waiting for tokens to appear in the database,
which is useful for automated testing and admin user bootstrap.
"""

import json
import threading
from typing import Any

from freetser import Storage
from freetser.server import StorageQueue

# Token table name
TOKENS_TABLE = "tokens"


def add_token(store: Storage, action: str, email: str, code: str) -> None:
    """Store a token notification in the database."""
    key = f"{action}:{email}"
    value = json.dumps({"action": action, "email": email, "code": code}).encode("utf-8")
    # Delete any existing token first, then add new one
    store.delete(TOKENS_TABLE, key)
    store.add(TOKENS_TABLE, key, value)


def get_token(store: Storage, action: str, email: str) -> dict[str, Any] | None:
    """Get and remove a token from the database."""
    key = f"{action}:{email}"
    result = store.get(TOKENS_TABLE, key)
    if result is None:
        return None
    value_bytes, _ = result
    store.delete(TOKENS_TABLE, key)
    return json.loads(value_bytes.decode("utf-8"))


class TokenWaiter:
    """Waits for tokens to appear in the database."""

    def __init__(self, store_queue: StorageQueue):
        self.store_queue = store_queue
        self.condition = threading.Condition()

    def notify(self) -> None:
        """Notify waiters that a new token may be available."""
        with self.condition:
            self.condition.notify_all()

    def wait_for_token(self, action: str, email: str, timeout: float = 30.0) -> str:
        """Wait for a token and return the code."""
        with self.condition:
            while True:
                # Check database
                def check(store: Storage) -> dict[str, Any] | None:
                    return get_token(store, action, email)

                token = self.store_queue.execute(check)
                if token is not None:
                    return token["code"]

                # Wait for notification or timeout
                if not self.condition.wait(timeout=1.0):
                    timeout -= 1.0
                    if timeout <= 0:
                        raise TimeoutError(
                            f"Timeout waiting for {action} token for {email}"
                        )
