"""Faroe user server interface.

Implements the SyncServer from the tiauth_faroe Python package.
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
    delete_registration,
    get_registration_by_email,
    normalize_email,
)
from apiserver.data.userdata import populate_birthday_for_user, set_user_bondsnummer

logger = logging.getLogger("apiserver.auth")


def create_user(store: Storage, effect: CreateUserEffect) -> EffectResult:
    """Create a new user account from a completed Faroe signup.

    1. Normalize email
    2. Require registrations_by_email[email] -> registration_id
    3. Require registration with accepted=True
    4. Allocate user_id
    5. Create live user
    6. If registration has bondsnummer, set users_by_bondsnummer
    7. Grant member
    8. Delete registration row and indexes
    """
    email = normalize_email(effect.email_address)

    user_id_result = store.get("users_by_email", email)
    if user_id_result is not None:
        logger.info(f"User with email {email} already exists")
        return ActionError("email_address_already_used")

    reg = get_registration_by_email(store, email)
    if reg is None:
        logger.info(f"No registration found for email={email}")
        return ActionError("user_not_found")
    if not reg.accepted:
        logger.info(f"Registration not accepted for email={email}")
        return ActionError("user_not_found")

    firstname = reg.firstname
    lastname = reg.lastname
    bondsnummer = reg.bondsnummer

    # Allocate user_id from global counter
    counter_result = store.get("metadata", "user_id_counter")
    if counter_result is None:
        store.add("metadata", "user_id_counter", b"0", expires_at=0)
        int_id = 0
        counter = 0
    else:
        counter_bytes, counter = counter_result
        int_id = int(counter_bytes.decode("utf-8"))

    new_user_counter = str(int_id + 1).encode("utf-8")
    store.update("metadata", "user_id_counter", new_user_counter, counter, expires_at=0)

    name_id = f"{firstname.lower()}_{lastname.lower()}"
    user_id = f"{int_id}_{name_id}"

    # Construct user data
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

    # Link bondsnummer if registration had one
    if bondsnummer is not None:
        set_user_bondsnummer(store, bondsnummer, user_id)
        populate_birthday_for_user(store, user_id, bondsnummer)

    # Grant member immediately
    timestamp = int(time.time())
    add_permission(store, timestamp, user_id, Permissions.MEMBER)

    # Delete registration row and all its indexes
    delete_registration(store, reg.registration_id)

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

    profile_result = store.get("users", f"{user_id}:profile")
    email_result = store.get("users", f"{user_id}:email")
    password_result = store.get("users", f"{user_id}:password")
    disabled_result = store.get("users", f"{user_id}:disabled")
    sessions_result = store.get("users", f"{user_id}:sessions_counter")

    all_none = (
        (profile_result is None) == (email_result is None) == (password_result is None)
    )
    assert all_none, (
        f"Inconsistent user data for {user_id}: "
        f"profile={profile_result is not None}, "
        f"email={email_result is not None}, "
        f"password={password_result is not None}"
    )

    if profile_result is None:
        logger.info(f"User {user_id} not found")
        return ActionError("user_not_found")

    assert email_result is not None
    assert password_result is not None

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

    old_email_result = store.get("users", f"{user_id}:email")
    if old_email_result is None:
        logger.info(f"User {user_id} not found for email update")
        return ActionError("user_not_found")

    old_email_bytes, _ = old_email_result
    old_email = old_email_bytes.decode("utf-8")

    if old_email == new_email:
        logger.info(f"Email already set to {new_email} for user {user_id}")
        return None

    new_email_check = store.get("users_by_email", new_email)
    if new_email_check is not None:
        logger.info(f"Email {new_email} already in use")
        return ActionError("email_address_already_used")

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

    store.add("users_by_email", new_email, user_id.encode("utf-8"), expires_at=0)
    store.delete("users_by_email", old_email)

    logger.info(f"Updated email for user {user_id} from {old_email} to {new_email}")


def update_user_password_hash(
    store: Storage, effect: UpdateUserPasswordHashEffect
) -> EffectResult:
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
    user_id = effect.user_id

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
    user_id = effect.user_id

    email_result = store.get("users", f"{user_id}:email")
    if email_result is None:
        logger.info(f"User {user_id} not found for deletion")
        return ActionError("user_not_found")

    email_bytes, _ = email_result
    email = email_bytes.decode("utf-8")

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
    """Sync server that executes effects using freetser Storage."""

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
