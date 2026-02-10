"""Faroe API compatibility tests.

Mirrors the test patterns from tiauth-faroe/python/client/tests/test_integration.py,
adapted for our backend which requires users to exist in the newusers table before
signup can succeed.

Each test that calls create_signup first calls prepare_user to create the
newuser entry that our backend requires (the reference user-server in
tiauth-faroe accepts any email).

Tests cover the full Faroe API surface:
- Signup: create → verify email → set password → complete
- Signin: create → verify password → complete
- Session: get session from token
"""

import secrets
import time

import pytest
from tiauth_faroe.client import (
    ActionErrorResult,
    CompleteSigninActionSuccessResult,
    CompleteSignupActionSuccessResult,
    CreateSigninActionSuccessResult,
    CreateSignupActionSuccessResult,
    GetSessionActionSuccessResult,
)

TEST_PASSWORD = "Str0ng!Pass#2025"


def poll_for_token(command, action, email, timeout=10):
    """Poll the private server for a verification code."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = command("get_token", action=action, email=email)
        if isinstance(result, dict) and result.get("found"):
            return result["code"]
        time.sleep(0.05)
    raise TimeoutError(f"Token {action} for {email} not found within {timeout}s")


def complete_signup_flow(command, auth_client, email, password=TEST_PASSWORD):
    """Prepare user and run full Faroe signup flow.

    Returns CompleteSignupActionSuccessResult.
    """
    command("prepare_user", email=email, names=["Test", "User"])

    signup = auth_client.create_signup(email)
    assert isinstance(signup, CreateSignupActionSuccessResult)

    code = poll_for_token(command, "signup_verification", email)

    verify = auth_client.verify_signup_email_address_verification_code(
        signup.signup_token, code
    )
    assert verify.ok is True

    pwd = auth_client.set_signup_password(signup.signup_token, password)
    assert pwd.ok is True

    result = auth_client.complete_signup(signup.signup_token)
    assert isinstance(result, CompleteSignupActionSuccessResult)
    return result


@pytest.fixture
def unique_email():
    """Generate a unique email for each test to avoid conflicts."""
    suffix = secrets.token_hex(8)
    return f"faroe_{suffix}@example.com"


class TestSignupFlow:
    """Faroe signup API compatibility — mirrors tiauth-faroe/python/client/tests."""

    def test_create_signup(self, command, auth_client, unique_email):
        """prepare_user → create_signup succeeds."""
        command("prepare_user", email=unique_email, names=["Test", "User"])

        result = auth_client.create_signup(unique_email)

        assert isinstance(result, CreateSignupActionSuccessResult)
        assert result.ok is True
        assert result.signup.email_address == unique_email
        assert result.signup.email_address_verified is False
        assert result.signup.password_set is False
        assert result.signup_token is not None

    def test_create_signup_duplicate_email(self, command, auth_client, unique_email):
        """Second signup with same email fails with email_address_already_used."""
        # First: complete full signup
        complete_signup_flow(command, auth_client, unique_email)

        # Second attempt should fail — user already exists in users table
        result = auth_client.create_signup(unique_email)

        assert isinstance(result, ActionErrorResult)
        assert result.ok is False
        assert result.error_code == "email_address_already_used"

    def test_complete_signup_full_flow(self, command, auth_client, unique_email):
        """Full: prepare_user → create → verify → password → complete."""
        command("prepare_user", email=unique_email, names=["Full", "Flow"])

        signup = auth_client.create_signup(unique_email)
        assert isinstance(signup, CreateSignupActionSuccessResult)
        signup_token = signup.signup_token

        # Send verification code (Faroe auto-sends on create, but we can resend)
        send_result = auth_client.send_signup_email_address_verification_code(
            signup_token
        )
        assert send_result.ok is True

        code = poll_for_token(command, "signup_verification", unique_email)
        assert code is not None

        verify = auth_client.verify_signup_email_address_verification_code(
            signup_token, code
        )
        assert verify.ok is True

        pwd = auth_client.set_signup_password(signup_token, TEST_PASSWORD)
        assert pwd.ok is True

        result = auth_client.complete_signup(signup_token)
        assert isinstance(result, CompleteSignupActionSuccessResult)
        assert result.ok is True
        assert result.session_token is not None

    def test_complete_signup_without_verification(
        self, command, auth_client, unique_email
    ):
        """Completing without email verification fails."""
        command("prepare_user", email=unique_email, names=["No", "Verify"])

        signup = auth_client.create_signup(unique_email)
        assert isinstance(signup, CreateSignupActionSuccessResult)

        # Set password but skip email verification
        auth_client.set_signup_password(signup.signup_token, TEST_PASSWORD)

        # Complete should fail — email not verified
        result = auth_client.complete_signup(signup.signup_token)
        assert isinstance(result, ActionErrorResult)
        assert result.ok is False


class TestSigninFlow:
    """Faroe signin API after signup."""

    def test_signin_full_flow(self, command, auth_client, unique_email):
        """Signin with correct password after signup."""
        complete_signup_flow(command, auth_client, unique_email)

        signin = auth_client.create_signin(unique_email)
        assert isinstance(signin, CreateSigninActionSuccessResult)
        assert signin.ok is True

        verify = auth_client.verify_signin_user_password(
            signin.signin_token, TEST_PASSWORD
        )
        assert verify.ok is True

        result = auth_client.complete_signin(signin.signin_token)
        assert isinstance(result, CompleteSigninActionSuccessResult)
        assert result.ok is True
        assert result.session_token is not None

    def test_signin_wrong_password(self, command, auth_client, unique_email):
        """Signin with wrong password fails."""
        complete_signup_flow(command, auth_client, unique_email)

        signin = auth_client.create_signin(unique_email)
        assert isinstance(signin, CreateSigninActionSuccessResult)

        result = auth_client.verify_signin_user_password(
            signin.signin_token, "WrongPassword456!"
        )
        assert isinstance(result, ActionErrorResult)
        assert result.ok is False

    def test_signin_nonexistent_user(self, auth_client):
        """Signin with non-existent email returns user_not_found."""
        result = auth_client.create_signin("nonexistent_faroe@example.com")

        assert isinstance(result, ActionErrorResult)
        assert result.ok is False
        assert result.error_code == "user_not_found"


class TestSessionFlow:
    """Faroe session API."""

    def test_get_session_valid(self, command, auth_client, unique_email):
        """Get session after signup returns valid session."""
        signup_result = complete_signup_flow(command, auth_client, unique_email)

        result = auth_client.get_session(signup_result.session_token)

        assert isinstance(result, GetSessionActionSuccessResult)
        assert result.ok is True
        assert result.session.user_id is not None

    def test_get_session_invalid_token(self, auth_client):
        """Invalid session token returns error."""
        result = auth_client.get_session("invalid_session_token_12345")

        assert isinstance(result, ActionErrorResult)
        assert result.ok is False
        assert result.error_code == "invalid_session_token"
