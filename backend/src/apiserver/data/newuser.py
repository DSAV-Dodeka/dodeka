import json
from dataclasses import dataclass

from hfree import EntryAlreadyExists, Storage


@dataclass
class NewUser:
    email: str
    firstname: str
    lastname: str
    accepted: bool


def _serialize_newuser(
    email: str, firstname: str, lastname: str, accepted: bool
) -> bytes:
    """Serialize newuser data to bytes."""
    data = {
        "email": email,
        "firstname": firstname,
        "lastname": lastname,
        "accepted": accepted,
    }
    return json.dumps(data).encode("utf-8")


def _deserialize_newuser(data: bytes) -> dict:
    """Deserialize newuser data from bytes."""
    return json.loads(data.decode("utf-8"))


def add_new_user(store: Storage, email: str, firstname: str, lastname: str):
    """
    Add a new user to the newuser table.
    Returns error if email already exists in either newuser or user table.
    """
    # Check if email already exists in user table
    user_data = store.get("users", email)
    if user_data is not None:
        raise ValueError("User with e-mail already exists in user table.")

    # Add to newuser table
    try:
        data = _serialize_newuser(email, firstname, lastname, False)
        # expires_at = 0 means no expiration
        store.add("newusers", email, data, expires_at=0)
    except EntryAlreadyExists:
        raise ValueError("User with e-mail already exists in newuser table.")


def update_accepted_flag(store: Storage, email: str, accepted: bool):
    """
    Update the accepted flag for a user in the newuser table.
    Returns error if user not found.
    """
    result = store.get("newusers", email)
    if result is None:
        raise ValueError("User with e-mail does not exist.")

    data_bytes, counter = result
    user_data = _deserialize_newuser(data_bytes)

    # Update the accepted flag
    user_data["accepted"] = accepted
    updated_data = json.dumps(user_data).encode("utf-8")

    # assert_updated=True by default - will assert on concurrent modification
    store.update("newusers", email, updated_data, expires_at=0, counter=counter)


def list_new_users(store: Storage) -> list[NewUser]:
    """List all new users."""
    keys = store.list_keys("newusers")
    users = []

    for key in keys:
        result = store.get("newusers", key)
        if result is not None:
            data_bytes, _ = result
            user_data = _deserialize_newuser(data_bytes)
            users.append(
                NewUser(
                    email=user_data["email"],
                    firstname=user_data["firstname"],
                    lastname=user_data["lastname"],
                    accepted=user_data["accepted"],
                )
            )

    return users


def prepare_user_store(store: Storage, email: str, names: list[str]):
    """Prepare a user entry in the newuser table with accepted=True."""
    # Validate names list length
    if len(names) > 2:  # noqa: PLR2004
        raise ValueError("Only accepts two names.")
    elif len(names) == 2:  # noqa: PLR2004
        firstname = names[0]
        lastname = names[1]
    elif len(names) == 1:
        firstname = names[0]
        lastname = ""
    else:
        # If no names provided, use email prefix as firstname
        email_prefix = email.split("@")[0]
        firstname = email_prefix
        lastname = ""

    try:
        data = _serialize_newuser(email, firstname, lastname, True)
        store.add("newusers", email, data, expires_at=0)
    except EntryAlreadyExists:
        raise ValueError("User with e-mail already exists in newuser table.")
