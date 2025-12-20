import json
from dataclasses import dataclass

from freetser import Storage


ADMIN_CREDENTIALS_KEY = "bootstrap_admin_credentials"


@dataclass
class AdminCredentials:
    """Bootstrap admin credentials."""

    email: str
    password: str


def store_admin_credentials(store: Storage, email: str, password: str) -> None:
    """Store bootstrap admin credentials in the database."""
    data = json.dumps({"email": email, "password": password}).encode("utf-8")

    # Delete existing and add new
    store.delete("metadata", ADMIN_CREDENTIALS_KEY)
    store.add("metadata", ADMIN_CREDENTIALS_KEY, data)


def get_admin_credentials(store: Storage) -> AdminCredentials | None:
    """Get bootstrap admin credentials from the database."""
    result = store.get("metadata", ADMIN_CREDENTIALS_KEY)
    if result is None:
        return None

    data_bytes, _ = result
    data = json.loads(data_bytes.decode("utf-8"))
    return AdminCredentials(email=data["email"], password=data["password"])
