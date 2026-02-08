import json
import secrets
from dataclasses import dataclass

from freetser import Storage


@dataclass
class RegistrationState:
    registration_token: str
    email: str
    accepted: bool
    signup_token: str | None
    email_send_count: int = 0


@dataclass
class RegistrationStateNotFound:
    email: str


def serialize_registration_state(
    email: str,
    accepted: bool,
    signup_token: str | None,
    email_send_count: int = 0,
) -> bytes:
    """Serialize registration state data to bytes."""
    data = {
        "email": email,
        "accepted": accepted,
        "signup_token": signup_token,
        "email_send_count": email_send_count,
    }
    return json.dumps(data).encode("utf-8")


def deserialize_registration_state(data: bytes) -> dict:
    """Deserialize registration state data from bytes."""
    return json.loads(data.decode("utf-8"))


def generate_registration_token() -> str:
    """Generate a unique registration token."""
    return secrets.token_urlsafe(32)


def create_registration_state(store: Storage, email: str) -> str:
    """
    Create a registration state entry for a new user.
    Returns the registration token.
    """
    registration_token = generate_registration_token()

    # Create registration state entry
    data = serialize_registration_state(email, accepted=False, signup_token=None)
    # expires_at = 0 means no expiration
    store.add("registration_state", registration_token, data, expires_at=0)

    return registration_token


def get_registration_state(
    store: Storage, registration_token: str
) -> RegistrationState | None:
    """Get registration state by token."""
    result = store.get("registration_state", registration_token)
    if result is None:
        return None

    data_bytes, _ = result
    state_data = deserialize_registration_state(data_bytes)

    return RegistrationState(
        registration_token=registration_token,
        email=state_data["email"],
        accepted=state_data["accepted"],
        signup_token=state_data.get("signup_token"),
        email_send_count=state_data.get("email_send_count", 0),
    )


def mark_registration_state_accepted(
    store: Storage, email: str
) -> None | RegistrationStateNotFound:
    """Set registration state accepted=True without changing signup_token."""
    keys = store.list_keys("registration_state")

    for key in keys:
        result = store.get("registration_state", key)
        if result is not None:
            data_bytes, counter = result
            state_data = deserialize_registration_state(data_bytes)

            if state_data["email"] == email:
                state_data["accepted"] = True
                updated_data = json.dumps(state_data).encode("utf-8")

                store.update(
                    "registration_state",
                    key,
                    updated_data,
                    counter,
                    expires_at=0,
                )
                return None

    return RegistrationStateNotFound(email=email)


def update_registration_state_accepted(
    store: Storage, email: str, signup_token: str
) -> None | RegistrationStateNotFound:
    """
    Update registration state to accepted with signup token.
    Finds the registration state by email.
    """
    # Find registration token by email
    keys = store.list_keys("registration_state")

    for key in keys:
        result = store.get("registration_state", key)
        if result is not None:
            data_bytes, counter = result
            state_data = deserialize_registration_state(data_bytes)

            if state_data["email"] == email:
                # Update this entry
                state_data["accepted"] = True
                state_data["signup_token"] = signup_token
                updated_data = json.dumps(state_data).encode("utf-8")

                store.update(
                    "registration_state",
                    key,
                    updated_data,
                    counter,
                    expires_at=0,
                )
                return None

    return RegistrationStateNotFound(email=email)


def update_registration_state_signup_token(
    store: Storage, email: str, signup_token: str
) -> None | RegistrationStateNotFound:
    """
    Update registration state with signup_token WITHOUT changing accepted.
    Used when signup is created at registration time (accepted is still False).
    """
    keys = store.list_keys("registration_state")

    for key in keys:
        result = store.get("registration_state", key)
        if result is not None:
            data_bytes, counter = result
            state_data = deserialize_registration_state(data_bytes)

            if state_data["email"] == email:
                state_data["signup_token"] = signup_token
                updated_data = json.dumps(state_data).encode("utf-8")

                store.update(
                    "registration_state",
                    key,
                    updated_data,
                    counter,
                    expires_at=0,
                )
                return None

    return RegistrationStateNotFound(email=email)


def get_signup_token_by_email(store: Storage, email: str) -> str | None:
    """Get signup token by email from registration state."""
    keys = store.list_keys("registration_state")

    for key in keys:
        result = store.get("registration_state", key)
        if result is not None:
            data_bytes, _ = result
            state_data = deserialize_registration_state(data_bytes)

            if state_data["email"] == email:
                return state_data.get("signup_token")

    return None


def get_registration_token_by_email(store: Storage, email: str) -> str | None:
    """Get registration token by email from registration state.

    Unlike signup_token, registration_token exists from initial registration.
    """
    keys = store.list_keys("registration_state")

    for key in keys:
        result = store.get("registration_state", key)
        if result is not None:
            data_bytes, _ = result
            state_data = deserialize_registration_state(data_bytes)

            if state_data["email"] == email:
                return key  # The key IS the registration_token

    return None


def increment_email_send_count(store: Storage, email: str) -> int | None:
    """Increment email_send_count for the registration state matching email.

    Returns the new count, or None if not found.
    """
    for key in store.list_keys("registration_state"):
        result = store.get("registration_state", key)
        if result is not None:
            data_bytes, counter = result
            state_data = deserialize_registration_state(data_bytes)
            if state_data["email"] == email:
                new_count = state_data.get("email_send_count", 0) + 1
                state_data["email_send_count"] = new_count
                updated = json.dumps(state_data).encode("utf-8")
                store.update(
                    "registration_state",
                    key,
                    updated,
                    counter,
                    expires_at=0,
                )
                return new_count
    return None


def get_email_send_count_by_email(store: Storage, email: str) -> int:
    """Get email_send_count by email. Returns 0 if not found."""
    for key in store.list_keys("registration_state"):
        result = store.get("registration_state", key)
        if result is not None:
            data_bytes, _ = result
            state_data = deserialize_registration_state(data_bytes)
            if state_data["email"] == email:
                return state_data.get("email_send_count", 0)
    return 0
