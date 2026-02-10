import json
from dataclasses import dataclass

from freetser import EntryAlreadyExists, Storage


@dataclass
class NewUser:
    email: str
    firstname: str
    lastname: str
    accepted: bool


@dataclass
class EmailExistsInUserTable:
    email: str


@dataclass
class EmailExistsInNewUserTable:
    email: str


@dataclass
class EmailNotFoundInNewUserTable:
    email: str


@dataclass
class InvalidNamesCount:
    names_count: int


def serialize_newuser(
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


def deserialize_newuser(data: bytes) -> dict:
    """Deserialize newuser data from bytes."""
    return json.loads(data.decode("utf-8"))


def add_new_user(
    store: Storage, email: str, firstname: str, lastname: str
) -> None | EmailExistsInUserTable | EmailExistsInNewUserTable:
    """
    Add a new user to the newuser table.
    Returns error if email already exists in either newuser or user table.
    """
    # Check if email already exists in user table (users_by_email is the index)
    user_data = store.get("users_by_email", email)
    if user_data is not None:
        return EmailExistsInUserTable(email=email)

    # Add to newuser table
    try:
        data = serialize_newuser(email, firstname, lastname, False)
        # expires_at = 0 means no expiration
        store.add("newusers", email, data, expires_at=0)
    except EntryAlreadyExists:
        return EmailExistsInNewUserTable(email=email)

    return None


def update_accepted_flag(
    store: Storage, email: str, accepted: bool
) -> None | EmailNotFoundInNewUserTable:
    """
    Update the accepted flag for a user in the newuser table.
    Returns error if user not found.
    """
    result = store.get("newusers", email)
    if result is None:
        return EmailNotFoundInNewUserTable(email=email)

    data_bytes, counter = result
    user_data = deserialize_newuser(data_bytes)

    # Update the accepted flag
    user_data["accepted"] = accepted
    updated_data = json.dumps(user_data).encode("utf-8")

    # assert_updated=True by default - will assert on concurrent modification
    store.update("newusers", email, updated_data, counter, expires_at=0)
    return None


def list_new_users(store: Storage) -> list[NewUser]:
    """List all new users."""
    keys = store.list_keys("newusers")
    users = []

    for key in keys:
        result = store.get("newusers", key)
        if result is not None:
            data_bytes, _ = result
            user_data = deserialize_newuser(data_bytes)
            users.append(
                NewUser(
                    email=user_data["email"],
                    firstname=user_data["firstname"],
                    lastname=user_data["lastname"],
                    accepted=user_data["accepted"],
                )
            )

    return users


def delete_new_user(store: Storage, email: str) -> bool:
    """Delete a user from the newuser table. Returns True if deleted."""
    result = store.get("newusers", email)
    if result is None:
        return False
    store.delete("newusers", email)
    return True


MAX_NAMES = 2


def prepare_user_store(
    store: Storage, email: str, names: list[str]
) -> None | InvalidNamesCount | EmailExistsInNewUserTable:
    """Prepare a user entry in the newuser table with accepted=True."""
    # Validate names list length
    if len(names) > MAX_NAMES:
        return InvalidNamesCount(names_count=len(names))
    elif len(names) == MAX_NAMES:
        firstname = names[0]
        lastname = names[1]
    elif len(names) == 1:
        firstname = names[0]
        lastname = ""
    else:
        # If no names provided, use email prefix as firstname
        email_prefix = email.split("@", maxsplit=1)[0]
        firstname = email_prefix
        lastname = ""

    try:
        data = serialize_newuser(email, firstname, lastname, True)
        store.add("newusers", email, data, expires_at=0)
    except EntryAlreadyExists:
        return EmailExistsInNewUserTable(email=email)

    return None
