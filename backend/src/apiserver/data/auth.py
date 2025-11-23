import json
import logging
from collections.abc import Callable
from typing import override

from hfree import EntryAlreadyExists, StorageConnection
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

MAX_RETRIES = 10


def get_and_update_with_retry(
    conn: StorageConnection,
    namespace: str,
    key: str,
    update_fn: Callable[[bytes], bytes],
    expires_at: int = 0,
) -> bytes | None:
    """
    Get a value and update it atomically with retry logic.

    Args:
        conn: Storage connection
        namespace: Namespace to operate in
        key: Key to update
        update_fn: Function that takes current value (bytes) and returns new
            value (bytes)
        max_retries: Maximum retry attempts (default 10)
        expires_at: Expiration timestamp

    Returns:
        The current value (before update) if successful, None if failed
    """
    for attempt in range(MAX_RETRIES):
        result = conn.get(namespace, key)
        if result is None:
            logger.warning(f"Key {namespace}:{key} not found during get_and_update")
            return None

        current_bytes, counter = result
        new_bytes = update_fn(current_bytes)

        success = conn.update(
            namespace, key, new_bytes, expires_at=expires_at, counter=counter
        )
        if success:
            return current_bytes

        if attempt < MAX_RETRIES - 1:
            logger.debug(
                f"Update failed for {namespace}:{key}, retry {attempt + 1}/"
                f"{MAX_RETRIES}"
            )

    logger.error(f"Failed to update {namespace}:{key} after {MAX_RETRIES} attempts")
    return None


def add_or_continue(
    conn: StorageConnection, namespace: str, key: str, value: bytes, expires_at: int = 0
) -> bool:
    """
    Add a key-value pair or just do nothing if it already exists.
    """
    try:
        conn.add(namespace, key, value, expires_at=expires_at)
        return True
    except EntryAlreadyExists:
        return False


def create_user(conn: StorageConnection, effect: CreateUserEffect) -> EffectResult:
    # Query newuser table to get user information and check if accepted
    newuser_result = conn.get("newusers", effect.email_address)
    if newuser_result is None:
        # Check if user already exists in the email index
        user_id_result = conn.get("users_by_email", effect.email_address)
        if user_id_result is not None:
            logger.info(
                f"User with email={effect.email_address} already exists. "
                "Cannot create user."
            )
            return ActionError("email_address_already_used")

        logger.info(
            f"Could not find user in newusers table with email={effect.email_address}. "
            "Cannot create user."
        )
        return ActionError("user_not_found")

    newuser_bytes, _ = newuser_result
    newuser_data = json.loads(newuser_bytes.decode("utf-8"))

    firstname = newuser_data["firstname"]
    lastname = newuser_data["lastname"]
    accepted = newuser_data["accepted"]

    if not accepted:
        logger.info(
            f"User with name={firstname} {lastname} is not yet accepted. "
            "Cannot create user."
        )
        return ActionError("user_not_accepted")

    name_id = f"{firstname.lower()}_{lastname.lower()}"

    user_id_result = conn.get("users_by_email", effect.email_address)
    if user_id_result is None:
        # Get next int_id using hfree's native counter with retry logic
        counter_result = conn.get("users", "_id_counter")
        if counter_result is None:
            try:
                conn.add("users", "_id_counter", b"0", expires_at=0)
            except EntryAlreadyExists:
                logger.warning(
                    "Attempted to create user counter when it already exists. "
                    "Continuing."
                )

        # Atomically get current counter and increment it
        counter_bytes = get_and_update_with_retry(
            conn,
            "users",
            "_id_counter",
            lambda current: str(int(current.decode("utf-8")) + 1).encode("utf-8"),
        )
        if counter_bytes is None:
            logger.error("Failed to increment user ID counter after retries")
            return ActionError("unexpected_error")

        int_id = int(counter_bytes.decode("utf-8"))
        user_id = f"{int_id}_{name_id}"

        try:
            conn.add(
                "users_by_email",
                effect.email_address,
                user_id.encode("utf-8"),
                expires_at=0,
            )
        except EntryAlreadyExists:
            return ActionError("unexpected_error")
    else:
        user_id_bytes, _ = user_id_result
        user_id = user_id_bytes.decode("utf-8")

    password_hash_hex = effect.password_hash.hex()
    password_salt_hex = effect.password_salt.hex()

    profile_data = {"firstname": firstname, "lastname": lastname}
    profile_bytes = json.dumps(profile_data).encode("utf-8")

    password_data = {
        "password_hash": password_hash_hex,
        "password_salt": password_salt_hex,
        "password_hash_algorithm_id": effect.password_hash_algorithm_id,
    }
    password_bytes = json.dumps(password_data).encode("utf-8")

    # Add all user keys (or continue if they already exist)
    add_or_continue(conn, "users", f"{user_id}:profile", profile_bytes)
    email_bytes = effect.email_address.encode("utf-8")
    add_or_continue(conn, "users", f"{user_id}:email", email_bytes)
    add_or_continue(conn, "users", f"{user_id}:password", password_bytes)
    add_or_continue(conn, "users", f"{user_id}:disabled", b"0")
    add_or_continue(conn, "users", f"{user_id}:sessions_counter", b"0")
    add_or_continue(conn, "users", f"{user_id}:permissions", b"")

    # Remove the newuser entry after successful user creation
    conn.delete("newusers", effect.email_address)

    return User(
        id=user_id,
        email_address=effect.email_address,
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


def get_user(conn: StorageConnection, effect: GetUserEffect) -> EffectResult:
    user_id = effect.user_id

    # Read all user data from separate keys
    profile_result = conn.get("users", f"{user_id}:profile")
    email_result = conn.get("users", f"{user_id}:email")
    password_result = conn.get("users", f"{user_id}:password")
    disabled_result = conn.get("users", f"{user_id}:disabled")
    sessions_result = conn.get("users", f"{user_id}:sessions_counter")

    # Check if user exists
    if profile_result is None or email_result is None or password_result is None:
        return ActionError("user_not_found")

    # Parse profile
    profile_bytes, _ = profile_result
    profile_data = json.loads(profile_bytes.decode("utf-8"))
    firstname = profile_data["firstname"]
    lastname = profile_data["lastname"]

    # Parse email
    email_bytes, email_counter = email_result
    email = email_bytes.decode("utf-8")

    # Parse password data
    password_bytes, password_counter = password_result
    password_data = json.loads(password_bytes.decode("utf-8"))
    password_hash = bytes.fromhex(password_data["password_hash"])
    password_salt = bytes.fromhex(password_data["password_salt"])
    password_hash_algorithm_id = password_data["password_hash_algorithm_id"]

    # Parse disabled
    disabled_bytes, disabled_counter = disabled_result if disabled_result else (b"0", 0)
    disabled = int(disabled_bytes.decode("utf-8")) != 0

    # Parse sessions counter
    _, sessions_counter = sessions_result if sessions_result else (b"0", 0)

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
    conn: StorageConnection, effect: GetUserByEmailAddressEffect
) -> EffectResult:
    # Look up user_id from email index
    email_index_result = conn.get("users_by_email", effect.email_address)
    if email_index_result is None:
        return ActionError("user_not_found")

    user_id_bytes, _ = email_index_result
    user_id = user_id_bytes.decode("utf-8")

    # Use get_user to fetch the full user data
    return get_user(
        conn,
        GetUserEffect(
            action_invocation_id=effect.action_invocation_id, user_id=user_id
        ),
    )


def update_user_email_address(
    conn: StorageConnection, effect: UpdateUserEmailAddressEffect
) -> EffectResult:
    user_id = effect.user_id

    # Get current email to delete from index later
    email_result = conn.get("users", f"{user_id}:email")
    if email_result is None:
        return ActionError("user_not_found")

    old_email_bytes, _ = email_result
    old_email = old_email_bytes.decode("utf-8")

    # Update email index first (add new, remove old)
    try:
        conn.add(
            "users_by_email",
            effect.email_address,
            user_id.encode("utf-8"),
            expires_at=0,
        )
    except EntryAlreadyExists:
        return ActionError("email_address_already_used")

    # Update email key with counter check (no retry, single attempt)
    new_email_bytes = effect.email_address.encode("utf-8")
    success = conn.update(
        "users",
        f"{user_id}:email",
        new_email_bytes,
        expires_at=0,
        counter=effect.user_email_address_counter,
    )

    if not success:
        # Clean up new email index
        conn.delete("users_by_email", effect.email_address)
        logger.debug(f"Failed to update email for user {user_id} - counter mismatch")
        return ActionError("user_not_found")

    # Remove old email index
    conn.delete("users_by_email", old_email)

    return None


def update_user_password_hash(
    conn: StorageConnection, effect: UpdateUserPasswordHashEffect
) -> EffectResult:
    user_id = effect.user_id

    password_hash_hex = effect.password_hash.hex()
    password_salt_hex = effect.password_salt.hex()
    password_data = {
        "password_hash": password_hash_hex,
        "password_salt": password_salt_hex,
        "password_hash_algorithm_id": effect.password_hash_algorithm_id,
    }
    new_password_bytes = json.dumps(password_data).encode("utf-8")

    # Update password with counter check (no retry, single attempt)
    success = conn.update(
        "users",
        f"{user_id}:password",
        new_password_bytes,
        expires_at=0,
        counter=effect.user_password_hash_counter,
    )

    if not success:
        logger.debug(
            f"Failed to update password hash for user {user_id} - counter mismatch"
        )
        return ActionError("user_not_found")

    return None


def increment_user_sessions_counter(
    conn: StorageConnection, effect: IncrementUserSessionsCounterEffect
) -> EffectResult:
    user_id = effect.user_id

    # Get current sessions counter value
    sessions_result = conn.get("users", f"{user_id}:sessions_counter")
    if sessions_result is None:
        return ActionError("user_not_found")

    sessions_bytes, _ = sessions_result
    current_count = int(sessions_bytes.decode("utf-8"))

    # Increment sessions counter with counter check (no retry, single attempt)
    new_count_bytes = str(current_count + 1).encode("utf-8")
    success = conn.update(
        "users",
        f"{user_id}:sessions_counter",
        new_count_bytes,
        expires_at=0,
        counter=effect.user_sessions_counter,
    )

    if not success:
        logger.debug(
            f"Failed to increment sessions counter for user {user_id} - "
            "counter mismatch"
        )
        return ActionError("user_not_found")

    return None


def delete_user(conn: StorageConnection, effect: DeleteUserEffect) -> EffectResult:
    user_id = effect.user_id

    # Get email to delete from index
    email_result = conn.get("users", f"{user_id}:email")
    if email_result is None:
        return ActionError("user_not_found")

    email_bytes, _ = email_result
    email = email_bytes.decode("utf-8")

    # Delete all user keys
    conn.delete("users", f"{user_id}:profile")
    conn.delete("users", f"{user_id}:email")
    conn.delete("users", f"{user_id}:password")
    conn.delete("users", f"{user_id}:disabled")
    conn.delete("users", f"{user_id}:sessions_counter")
    conn.delete("users", f"{user_id}:permissions")

    # Delete email index
    conn.delete("users_by_email", email)

    return None


class SqliteSyncServer(SyncServer):
    conn: StorageConnection

    def __init__(self, conn: StorageConnection):
        self.conn = conn

    @override
    def execute_effect(self, effect: Effect) -> EffectResult:  # noqa: PLR0911
        print(f"effect:\n{effect}\n")
        if isinstance(effect, CreateUserEffect):
            return create_user(self.conn, effect)
        elif isinstance(effect, GetUserEffect):
            return get_user(self.conn, effect)
        elif isinstance(effect, GetUserByEmailAddressEffect):
            return get_user_by_email_address(self.conn, effect)
        elif isinstance(effect, UpdateUserEmailAddressEffect):
            return update_user_email_address(self.conn, effect)
        elif isinstance(effect, UpdateUserPasswordHashEffect):
            return update_user_password_hash(self.conn, effect)
        elif isinstance(effect, IncrementUserSessionsCounterEffect):
            return increment_user_sessions_counter(self.conn, effect)
        elif isinstance(effect, DeleteUserEffect):
            return delete_user(self.conn, effect)
        else:
            raise ValueError(f"Unknown effect type: {type(effect)}")
