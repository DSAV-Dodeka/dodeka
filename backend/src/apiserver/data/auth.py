"""
This file implements the Faroe user server interface, which means implementing the
SyncServer (since we use synchronous code) from the tiauth_faroe Python package.
Be careful modifying it!

What makes our approach different from the simplest possible implementation is the
newusers table, since we need to synchronize with Volta and ensure the user is really
a member. Creating a user then requires that a user actually exists in this table.
If the board has already accepted them (maybe because they were added to newusers
through sync and hence already accepted), we immediately add their member permissions.
"""

import json
import logging
import time
from typing import override

from freetser import Storage
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

from apiserver.data.permissions import Permissions, add_permission
from apiserver.data.registrations import (
    get_registration,
    normalize_email,
    upsert_registration,
    delete_registration,
)

logger = logging.getLogger("apiserver.auth")


def create_user(store: Storage, effect: CreateUserEffect) -> EffectResult:
    """Create a new user account from a completed Faroe signup.

    Requires a registrations[email] row with account_created=False.
    If accepted=True, grants member permission immediately.
    Sets account_created=True and clears signup_token.

    Registration row lifecycle after this function:
    - accepted=True, notify_on_completion=False: delete immediately
    - accepted=True, notify_on_completion=True: keep until set_session
    - accepted=False: keep for later admin approval
    """
    email = normalize_email(effect.email_address)

    user_id_result = store.get("users_by_email", email)
    if user_id_result is not None:
        logger.info(f"User with email {email} already exists")
        return ActionError("email_address_already_used")

    reg = get_registration(store, email)
    if reg is None:
        logger.info(f"No registration found for email={email}")
        return ActionError("user_not_found")
    if reg.account_created:
        logger.info(f"Account already created for email={email}")
        return ActionError("email_address_already_used")

    firstname = reg.firstname
    lastname = reg.lastname
    accepted = reg.accepted

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
    store.update("metadata", "user_id_counter", new_user_counter, counter, expires_at=0)

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
    store.add("users_by_email", email, user_id.encode("utf-8"), expires_at=0)

    # Update registration row
    reg.account_created = True
    reg.signup_token = None

    if accepted:
        timestamp = int(time.time())
        add_permission(store, timestamp, user_id, Permissions.MEMBER)
        if not reg.notify_on_completion:
            # Lifecycle complete — delete registration
            delete_registration(store, email)
        else:
            # Keep until set_session sends the deferred acceptance email
            upsert_registration(store, reg)
    else:
        # Keep registration for later admin approval
        upsert_registration(store, reg)
        logger.info(f"User {user_id} created but not yet accepted")

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
    email = normalize_email(effect.email_address)
    email_index_result = store.get("users_by_email", email)
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
    user_id = effect.user_id
    new_email = normalize_email(effect.email_address)

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

    # Use the non-throwing variant because a missing/stale record
    # maps to an action error.
    new_email_bytes = new_email.encode("utf-8")
    updated = store.try_update(
        "users",
        f"{user_id}:email",
        new_email_bytes,
        effect.user_email_address_counter,
        expires_at=0,
    )
    if not updated:
        return ActionError("user_not_found")

    # Update email index
    store.add("users_by_email", new_email, user_id.encode("utf-8"), expires_at=0)
    store.delete("users_by_email", old_email)

    logger.info(f"Updated email for user {user_id} from {old_email} to {new_email}")


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

    updated = store.try_update(
        "users",
        f"{user_id}:password",
        new_password_bytes,
        effect.user_password_hash_counter,
        expires_at=0,
    )

    if not updated:
        return ActionError("user_not_found")

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

    new_count_bytes = str(current_count + 1).encode("utf-8")
    updated = store.try_update(
        "users",
        f"{user_id}:sessions_counter",
        new_count_bytes,
        effect.user_sessions_counter,
        expires_at=0,
    )
    if not updated:
        logger.info(f"Stale sessions counter for user {user_id}")
        return ActionError("user_not_found")

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
    def execute_effect(self, effect: Effect) -> EffectResult:
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
            logger.error(f"Unknown effect type: {type(effect)}")
            return ActionError("unknown_effect_type")
