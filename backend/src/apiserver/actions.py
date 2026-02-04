import logging
import time

from freetser import Storage
from freetser.server import StorageQueue
from tiauth_faroe.client import ActionErrorResult
from tiauth_faroe.user_server import handle_request_sync

from apiserver.data.auth import SqliteSyncServer
from apiserver.data.client import AuthClient
from apiserver.data.newuser import delete_new_user, prepare_user_store
from apiserver.data.permissions import add_permission
from apiserver.tokens import TokenWaiter

logger = logging.getLogger("apiserver.actions")


class AdminUserCreationError(Exception):
    pass


def create_admin_user(
    store_queue: StorageQueue,
    auth_client: AuthClient,
    email: str,
    password: str,
    token_waiter: TokenWaiter,
    names: list[str] | None = None,
) -> tuple[str, str]:
    """Create an admin user using direct DB calls."""

    # Delete existing user by email (cleanup from previous runs)
    def delete_user_by_email(store: Storage) -> str | None:
        # Clean up newusers table
        delete_new_user(store, email)

        # Look up user_id by email
        result = store.get("users_by_email", email)
        if result is None:
            return None
        user_id_bytes, _ = result
        return user_id_bytes.decode("utf-8")

    user_id = store_queue.execute(delete_user_by_email)

    # If user exists, delete via Faroe
    if user_id is not None:
        delete_request = {"action": "delete_user", "arguments": {"user_id": user_id}}

        def execute_delete(store: Storage) -> str | None:
            server = SqliteSyncServer(store)
            result = handle_request_sync(delete_request, server)
            if result.error is not None:
                logger.error(f"Failed to delete user: {result.error}")
                return result.error
            return None

        error = store_queue.execute(execute_delete)
        if error is not None:
            raise AdminUserCreationError(f"Failed to delete user: {error}")

    # Prepare user in newusers table with accepted=True
    def prepare(store: Storage) -> str | None:
        result = prepare_user_store(store, email, names or [])
        if result is not None:
            return str(result)
        return None

    prepare_error = store_queue.execute(prepare)
    if prepare_error is not None:
        raise AdminUserCreationError(f"Failed to prepare user: {prepare_error}")

    # Create signup via auth server
    signup_result = auth_client.create_signup(email)
    if isinstance(signup_result, ActionErrorResult):
        raise AdminUserCreationError(
            f"Failed to create signup: {signup_result.error_code}"
        )
    signup_token = signup_result.signup_token

    # Wait for verification code from Go (stored in tokens table)
    verification_code = token_waiter.wait_for_token("signup_verification", email)

    # Verify email address
    verify_result = auth_client.verify_signup_email_address_verification_code(
        signup_token, verification_code
    )
    if isinstance(verify_result, ActionErrorResult):
        raise AdminUserCreationError(
            f"Failed to verify email: {verify_result.error_code}"
        )

    # Set password
    password_result = auth_client.set_signup_password(signup_token, password)
    if isinstance(password_result, ActionErrorResult):
        raise AdminUserCreationError(
            f"Failed to set password: {password_result.error_code}"
        )

    # Complete signup
    complete_result = auth_client.complete_signup(signup_token)
    if isinstance(complete_result, ActionErrorResult):
        raise AdminUserCreationError(
            f"Failed to complete signup: {complete_result.error_code}"
        )

    new_user_id = complete_result.session.user_id
    session_token = complete_result.session_token

    # Add admin permission directly to DB
    timestamp = int(time.time())

    def add_admin_perm(store: Storage) -> str | None:
        result = add_permission(store, timestamp, new_user_id, "admin")
        if result is not None:
            return str(result)
        return None

    admin_error = store_queue.execute(add_admin_perm)
    if admin_error is not None:
        raise AdminUserCreationError(f"Failed to add admin permission: {admin_error}")

    return (new_user_id, session_token)
