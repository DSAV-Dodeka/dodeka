import json
import logging
from typing import override

from hfree import Storage
from tiauth_faroe.user_server import (
    ActionError,
    CreateUserEffect,
    DeleteUserEffect,
    Effect,
    EffectResult,
    GetUserByEmailAddressEffect,
    GetUserEffect,
    IncrementUserSessionsCounterEffect,
    SyncServer,
    UpdateUserEmailAddressEffect,
    UpdateUserPasswordHashEffect,
    User,
)

logger = logging.getLogger("apiserver.auth")


def create_user(store: Storage, effect: CreateUserEffect) -> EffectResult:
    email = effect.email_address

    user_id_result = store.get("users_by_email", email)
    if user_id_result is not None:
        logger.info(f"User with email {email} already exists")
        return ActionError("email_address_already_used")

    # We only allow users that have been accepted through the newusers flow
    newuser_result = store.get("newusers", email)
    if newuser_result is None:
        logger.info(f"Could not find user in newusers table with email={email}")
        return ActionError("user_not_found")

    newuser_bytes, _ = newuser_result
    newuser_data = json.loads(newuser_bytes.decode("utf-8"))

    firstname = newuser_data["firstname"]
    lastname = newuser_data["lastname"]
    accepted = newuser_data["accepted"]

    if not accepted:
        logger.info(f"User {firstname} {lastname} is not yet accepted")
        return ActionError("user_not_accepted")

    # We store a global counter that tracks the max user_id
    counter_result = store.get("metadata", "user_id_counter")
    if counter_result is None:
        store.add("metadata", "user_id_counter", b"0", expires_at=0)
        int_id = 0
        counter = 0
    else:
        counter_bytes, counter = counter_result
        int_id = int(counter_bytes.decode("utf-8"))

    # Increment counter for next user
    new_user_counter = str(int_id + 1).encode("utf-8")
    store.update(
        "metadata", "user_id_counter", new_user_counter, expires_at=0, counter=counter
    )

    # We construct a user_id from a unique integer and first name + last name
    name_id = f"{firstname.lower()}_{lastname.lower()}"
    user_id = f"{int_id}_{name_id}"

    # Construct the rest of the user data
    profile_data = {"firstname": firstname, "lastname": lastname}
    profile_bytes = json.dumps(profile_data).encode("utf-8")
    password_data = {
        "password_hash": effect.password_hash.hex(),
        "password_salt": effect.password_salt.hex(),
        "password_hash_algorithm_id": effect.password_hash_algorithm_id,
    }
    password_bytes = json.dumps(password_data).encode("utf-8")

    # Add all user keys
    store.add("users", f"{user_id}:profile", profile_bytes, expires_at=0)
    store.add("users", f"{user_id}:email", email.encode("utf-8"), expires_at=0)
    store.add("users", f"{user_id}:password", password_bytes, expires_at=0)
    store.add("users", f"{user_id}:disabled", b"0", expires_at=0)
    store.add("users", f"{user_id}:sessions_counter", b"0", expires_at=0)
    store.add("users", f"{user_id}:permissions", b"", expires_at=0)
    # This is used as an index to find a user_id by email
    store.add("users_by_email", email, user_id.encode("utf-8"), expires_at=0)

    # Remove newuser entry
    store.delete("newusers", email)

    logger.info(f"Created user {user_id} with email {email}")
    return User(
        id=user_id,
        email_address=email,
        password_hash=effect.password_hash,
        password_hash_algorithm_id=effect.password_hash_algorithm_id,
        password_salt=effect.password_salt,
        disabled=False,
        display_name=f"{firstname} {lastname}",
        email_address_counter=0,
        password_hash_counter=0,
        disabled_counter=0,
        sessions_counter=0,
    )


def get_user(store: Storage, effect: GetUserEffect) -> EffectResult:
    user_id = effect.user_id

    # Read all user data from separate keys
    profile_result = store.get("users", f"{user_id}:profile")
    email_result = store.get("users", f"{user_id}:email")
    password_result = store.get("users", f"{user_id}:password")
    disabled_result = store.get("users", f"{user_id}:disabled")
    sessions_result = store.get("users", f"{user_id}:sessions_counter")

    # Assert consistency: profile, email, and password must all exist together
    # or not at all
    all_none = (
        (profile_result is None) == (email_result is None) == (password_result is None)
    )
    assert all_none, (
        f"Inconsistent user data for {user_id}: "
        f"profile={profile_result is not None}, "
        f"email={email_result is not None}, "
        f"password={password_result is not None}"
    )

    # Check if user exists
    if profile_result is None:
        logger.info(f"User {user_id} not found")
        return ActionError("user_not_found")

    # At this point, due to the consistency assertion above,
    # email_result and password_result must also be not None
    assert email_result is not None
    assert password_result is not None

    # Now we parse and get all of the data
    profile_bytes, _ = profile_result
    profile_data = json.loads(profile_bytes.decode("utf-8"))
    firstname = profile_data["firstname"]
    lastname = profile_data["lastname"]
    email_bytes, email_counter = email_result
    email = email_bytes.decode("utf-8")
    password_bytes, password_counter = password_result
    password_data = json.loads(password_bytes.decode("utf-8"))
    password_hash = bytes.fromhex(password_data["password_hash"])
    password_salt = bytes.fromhex(password_data["password_salt"])
    password_hash_algorithm_id = password_data["password_hash_algorithm_id"]
    disabled_bytes, disabled_counter = disabled_result if disabled_result else (b"0", 0)
    disabled = int(disabled_bytes.decode("utf-8")) != 0
    _, sessions_counter = sessions_result if sessions_result else (b"0", 0)

    logger.info(f"Retrieved user {user_id}")
    return User(
        id=user_id,
        email_address=email,
        password_hash=password_hash,
        password_hash_algorithm_id=password_hash_algorithm_id,
        password_salt=password_salt,
        disabled=disabled,
        display_name=f"{firstname} {lastname}",
        email_address_counter=email_counter,
        password_hash_counter=password_counter,
        disabled_counter=disabled_counter,
        sessions_counter=sessions_counter,
    )


def get_user_by_email_address(
    store: Storage, effect: GetUserByEmailAddressEffect
) -> EffectResult:
    email_index_result = store.get("users_by_email", effect.email_address)
    if email_index_result is None:
        logger.info(f"User with email {effect.email_address} not found")
        return ActionError("user_not_found")

    user_id_bytes, _ = email_index_result
    user_id = user_id_bytes.decode("utf-8")

    logger.info(f"Found user_id {user_id} for email {effect.email_address}")
    return get_user(
        store,
        GetUserEffect(
            action_invocation_id=effect.action_invocation_id, user_id=user_id
        ),
    )


def update_user_email_address(
    store: Storage, effect: UpdateUserEmailAddressEffect
) -> EffectResult:
    """Update user email address. Runs atomically."""
    user_id = effect.user_id
    new_email = effect.email_address

    # Get current email
    old_email_result = store.get("users", f"{user_id}:email")
    if old_email_result is None:
        logger.info(f"User {user_id} not found for email update")
        return ActionError("user_not_found")

    old_email_bytes, _ = old_email_result
    old_email = old_email_bytes.decode("utf-8")

    # Check if already the same
    if old_email == new_email:
        logger.info(f"Email already set to {new_email} for user {user_id}")
        return None

    # Check if new email already in use
    new_email_check = store.get("users_by_email", new_email)
    if new_email_check is not None:
        logger.info(f"Email {new_email} already in use")
        return ActionError("email_address_already_used")

    # Update email (assert_updated=True by default - will assert on counter mismatch)
    new_email_bytes = new_email.encode("utf-8")
    store.update(
        "users",
        f"{user_id}:email",
        new_email_bytes,
        expires_at=0,
        counter=effect.user_email_address_counter,
    )

    # Update email index
    store.add("users_by_email", new_email, user_id.encode("utf-8"), expires_at=0)
    store.delete("users_by_email", old_email)

    logger.info(f"Updated email for user {user_id} from {old_email} to {new_email}")
    return None


def update_user_password_hash(
    store: Storage, effect: UpdateUserPasswordHashEffect
) -> EffectResult:
    """Update user password hash."""
    user_id = effect.user_id

    password_data = {
        "password_hash": effect.password_hash.hex(),
        "password_salt": effect.password_salt.hex(),
        "password_hash_algorithm_id": effect.password_hash_algorithm_id,
    }
    new_password_bytes = json.dumps(password_data).encode("utf-8")

    # Update password (assert_updated=True by default - will assert on counter mismatch)
    store.update(
        "users",
        f"{user_id}:password",
        new_password_bytes,
        expires_at=0,
        counter=effect.user_password_hash_counter,
    )

    logger.info(f"Updated password hash for user {user_id}")
    return None


def increment_user_sessions_counter(
    store: Storage, effect: IncrementUserSessionsCounterEffect
) -> EffectResult:
    """Increment user sessions counter."""
    user_id = effect.user_id

    # Get current sessions counter value
    sessions_result = store.get("users", f"{user_id}:sessions_counter")
    if sessions_result is None:
        logger.info(f"User {user_id} not found for sessions counter increment")
        return ActionError("user_not_found")

    sessions_bytes, _ = sessions_result
    current_count = int(sessions_bytes.decode("utf-8"))

    # Increment sessions counter (assert_updated=True by default)
    new_count_bytes = str(current_count + 1).encode("utf-8")
    store.update(
        "users",
        f"{user_id}:sessions_counter",
        new_count_bytes,
        expires_at=0,
        counter=effect.user_sessions_counter,
    )

    logger.info(
        f"Incremented sessions counter for user {user_id} to {current_count + 1}"
    )
    return None


def delete_user(store: Storage, effect: DeleteUserEffect) -> EffectResult:
    """Delete a user."""
    user_id = effect.user_id

    # Get email to delete from index
    email_result = store.get("users", f"{user_id}:email")
    if email_result is None:
        logger.info(f"User {user_id} not found for deletion")
        return ActionError("user_not_found")

    email_bytes, _ = email_result
    email = email_bytes.decode("utf-8")

    # Delete all user keys
    store.delete("users", f"{user_id}:profile")
    store.delete("users", f"{user_id}:password")
    store.delete("users", f"{user_id}:disabled")
    store.delete("users", f"{user_id}:sessions_counter")
    store.delete("users", f"{user_id}:permissions")
    store.delete("users_by_email", email)
    store.delete("users", f"{user_id}:email")

    logger.info(f"Deleted user {user_id} with email {email}")
    return None


class SqliteSyncServer(SyncServer):
    """Sync server that executes effects using hfree Storage."""

    store: Storage

    def __init__(self, store: Storage):
        self.store = store

    @override
    def execute_effect(self, effect: Effect) -> EffectResult:  # noqa: PLR0911
        """Execute an effect atomically."""
        logger.info(f"Executing effect: {type(effect).__name__}")

        if isinstance(effect, CreateUserEffect):
            return create_user(self.store, effect)
        elif isinstance(effect, GetUserEffect):
            return get_user(self.store, effect)
        elif isinstance(effect, GetUserByEmailAddressEffect):
            return get_user_by_email_address(self.store, effect)
        elif isinstance(effect, UpdateUserEmailAddressEffect):
            return update_user_email_address(self.store, effect)
        elif isinstance(effect, UpdateUserPasswordHashEffect):
            return update_user_password_hash(self.store, effect)
        elif isinstance(effect, IncrementUserSessionsCounterEffect):
            return increment_user_sessions_counter(self.store, effect)
        elif isinstance(effect, DeleteUserEffect):
            return delete_user(self.store, effect)
        else:
            raise ValueError(f"Unknown effect type: {type(effect)}")
