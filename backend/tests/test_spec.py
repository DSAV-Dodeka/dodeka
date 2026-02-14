"""Tests for spec.md behavioral requirements.

Changes tested:
  1. Email type sync_please_register exists
  2. compute_groups returns to_accept/pending_signup groups
  3. to_accept group includes self-registered users
  4. accept_new handles scenario 3 (self-reg with account in sync)
  5. remove_departed fully deletes accounts
  6. No disabled field in session_info
  7. Scenario 1: accept_user defers email, set_session sends it
"""

import csv
import io
import time

import requests
from tiauth_faroe.client import (
    ActionErrorResult,
    CompleteSignupActionSuccessResult,
    CreateSignupActionSuccessResult,
)

TEST_PASSWORD = "Str0ng_T3st_P@ss!2024"


def poll_for_token(command, action, email, timeout=10):
    """Poll the private server for a verification code."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = command("get_token", action=action, email=email)
        if isinstance(result, dict) and result.get("found"):
            return result["code"]
        time.sleep(0.05)
    raise TimeoutError(f"Token {action} for {email} not found within {timeout}s")


def complete_signup_flow(command, auth_client, signup_token, email):
    """Run verify -> set_password -> complete_signup. Returns result."""
    code = poll_for_token(command, "signup_verification", email)
    verify = auth_client.verify_signup_email_address_verification_code(
        signup_token, code
    )
    assert verify.ok is True
    pwd = auth_client.set_signup_password(signup_token, TEST_PASSWORD)
    assert pwd.ok is True
    result = auth_client.complete_signup(signup_token)
    assert isinstance(result, CompleteSignupActionSuccessResult)
    return result


AU_COLUMNS = [
    "Verenigingscode",
    "Regio",
    "Naam vereniging",
    "Clubnummer",
    "Bondsnummer",
    "Club lidmaatschap type",
    "Club lidmaatschap startdatum",
    "Club lidmaatschap einddatum",
    "Club lidmaatschap opzegdatum",
    "Club lidmaatschap opzegreden",
    "Bond lidmaatschapstype",
    "Bond lidmaatschap startdatum",
    "Bond lidmaatschap einddatum",
    "Bond lidmaatschap opzegdatum",
    "Bond opzegreden",
    "Voornaam",
    "Tussenvoegsel",
    "Achternaam",
    "Initialen",
    "Geslacht",
    "Geboortedatum",
    "Nationaliteit",
    "Straat",
    "Huisnummer",
    "Huisnummer toevoeging",
    "Postcode",
    "Stad",
    "Landcode",
    "Mobiel",
    "Telefoon",
    "Email",
    "Naam ouder 1",
    "Email ouder 1",
    "Telefoon ouder 1",
    "Naam ouder 2",
    "Email ouder 2",
    "Telefoon ouder 2",
    "Incasso",
    "Naam bankrekening",
    "IBAN",
    "BIC",
    "Mandaat ID",
    "Mandaat datum",
    "Contributie termijn",
    "VOG",
    "_Geef je toestemming om foto's van jou op onze social media te plaatsen?",
    "_Ben je student?",
]


def make_au_csv(members):
    """Create CSV content in Atletiekunie export format."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=AU_COLUMNS, restval="")
    writer.writeheader()
    for member in members:
        writer.writerow(member)
    return buf.getvalue()


# -- 1. Email type -----------------------------------------------------------


def test_email_type_sync_please_register(command):
    """sync_please_register must exist in EMAIL_CONFIG.

    Spec: Email notifications > Email types > Backend-initiated
    """
    from apiserver.email import EMAIL_CONFIG  # noqa: PLC0415

    assert "sync_please_register" in EMAIL_CONFIG, (
        "Email type 'sync_please_register' should exist in EMAIL_CONFIG"
    )


# -- 2-3. compute_groups: to_accept and pending_signup -------------------------


def test_compute_groups_to_accept_truly_new(command):
    """Truly new members (not in newusers, not in users_by_email) should
    appear in the to_accept group.

    Spec: Sync lifecycle > Compute groups > to_accept
    """
    email = "spec_newmember@example.com"
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7001",
                "Voornaam": "Truly",
                "Achternaam": "New",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    groups = command("compute_groups")

    assert "to_accept" in groups, "compute_groups should return 'to_accept' group"
    to_accept_emails = [u["email"] for u in groups["to_accept"]]
    assert email in to_accept_emails


def test_compute_groups_to_accept_includes_selfreg_no_account(command, backend_url):
    """Self-registered users (no account, accepted=False) in sync CSV should
    appear in the to_accept group.

    Spec: Sync lifecycle > Compute groups > to_accept definition
    """
    email = "spec_selfreg_sync@example.com"

    # Step 1: Self-register (creates newusers with accepted=False)
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Self", "lastname": "RegSync"},
        timeout=10,
    )
    assert resp.status_code == 200

    # Step 2: Same email appears in sync CSV
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7002",
                "Voornaam": "Self",
                "Achternaam": "RegSync",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    groups = command("compute_groups")

    assert "to_accept" in groups, "compute_groups should return 'to_accept' group"
    to_accept_emails = [
        u["email"] if isinstance(u, dict) else u for u in groups["to_accept"]
    ]
    assert email in to_accept_emails, (
        f"Self-registered user {email} should be in to_accept, not pending"
    )


def test_compute_groups_to_accept_includes_selfreg_with_account(
    command, backend_url, auth_client
):
    """Self-registered users WITH an account (accepted=False, in newusers)
    appearing in sync CSV should be in the to_accept group.

    Spec: Sync lifecycle > Compute groups > to_accept definition
    """
    email = "spec_selfreg_acct_sync@example.com"

    # Step 1: Self-register and complete signup (accepted=False)
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Self", "lastname": "AcctSync"},
        timeout=10,
    )
    assert resp.status_code == 200
    signup_token = resp.json()["signup_token"]
    complete_signup_flow(command, auth_client, signup_token, email)

    # Step 2: Same email appears in sync CSV
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7003",
                "Voornaam": "Self",
                "Achternaam": "AcctSync",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    groups = command("compute_groups")

    assert "to_accept" in groups, "compute_groups should return 'to_accept' group"
    to_accept_emails = [
        u["email"] if isinstance(u, dict) else u for u in groups["to_accept"]
    ]
    assert email in to_accept_emails, (
        f"Self-registered user with account {email} should be in to_accept "
        "(has newusers entry with accepted=False)"
    )


def test_compute_groups_pending_signup(command):
    """Users who have been accepted but haven't completed signup should be
    in the pending_signup group.

    Spec: Sync lifecycle > Compute groups > pending_signup
    """
    email = "spec_pendingsignup@example.com"
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7004",
                "Voornaam": "Pending",
                "Achternaam": "Signup",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    command("accept_new", email=email)

    groups = command("compute_groups")
    assert "pending_signup" in groups, (
        "compute_groups should return 'pending_signup' group"
    )
    assert email in groups["pending_signup"]


# -- 4. accept_new handles scenario 3 -----------------------------------------


def test_accept_new_scenario3_selfreg_with_account(command, backend_url, auth_client):
    """Scenario 3: accept_new should grant member permission to a
    self-registered user who already has an account.

    Spec: Registration scenarios > Scenario 3
    """
    email = "spec_scenario3@example.com"

    # Step 1: Self-register and complete signup (accepted=False, no member)
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Scenario", "lastname": "Three"},
        timeout=10,
    )
    assert resp.status_code == 200
    signup_token = resp.json()["signup_token"]
    complete_signup_flow(command, auth_client, signup_token, email)

    # Step 2: Same email appears in sync CSV
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7010",
                "Voornaam": "Scenario",
                "Achternaam": "Three",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)

    # Step 3: Accept all -- should process this user (not skip them)
    result = command("accept_new")
    assert result["added"] >= 1, (
        "accept_new should process self-registered user with account"
    )

    # Step 4: User should now have member permission
    signin = auth_client.create_signin(email)
    assert not isinstance(signin, ActionErrorResult)
    verify = auth_client.verify_signin_user_password(signin.signin_token, TEST_PASSWORD)
    assert verify.ok is True
    result = auth_client.complete_signin(signin.signin_token)
    assert not isinstance(result, ActionErrorResult)


# -- 5. remove_departed fully deletes accounts --------------------------------


def test_remove_departed_full_deletion(command, auth_client):
    """remove_departed should fully delete the user account.

    Spec: Sync lifecycle > Remove departed
    """
    email = "spec_departed@example.com"

    # Step 1: Create a user via sync flow
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7020",
                "Voornaam": "Will",
                "Achternaam": "Depart",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    command("accept_new", email=email)

    # Complete signup
    signup_result = auth_client.create_signup(email)
    assert isinstance(signup_result, CreateSignupActionSuccessResult)
    complete_signup_flow(command, auth_client, signup_result.signup_token, email)

    # Update existing to grant member permission
    command("update_existing")

    # Step 2: Import empty CSV (member departed)
    command("import_sync", csv_content=make_au_csv([]))
    groups = command("compute_groups")
    assert email in groups["departed"]

    # Step 3: Remove departed
    command("remove_departed", email=email)

    # Step 4: User should be completely gone -- not just disabled.
    # They should appear as new in a future sync, not existing.
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7020",
                "Voornaam": "Will",
                "Achternaam": "Depart",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    groups = command("compute_groups")

    # With full deletion, user should be in to_accept, NOT existing
    existing_emails = {e["sync"]["email"] for e in groups.get("existing", [])}
    assert email not in existing_emails, (
        f"Departed user {email} should not be in 'existing' after full deletion"
    )


# -- 6. No disabled field -----------------------------------------------------


def test_session_info_no_disabled_field(command, backend_url, auth_client):
    """session_info should not return a 'disabled' field.

    Spec: Login and sessions > Session info
    """
    email = "spec_nodisabled@example.com"

    # Create user via prepare_user + signup
    command("prepare_user", email=email, names=["No", "Disabled"])
    signup_result = auth_client.create_signup(email)
    assert isinstance(signup_result, CreateSignupActionSuccessResult)
    result = complete_signup_flow(
        command, auth_client, signup_result.signup_token, email
    )

    # Set session and check session_info
    resp = requests.post(
        f"{backend_url}/cookies/set_session/",
        json={"session_token": result.session_token},
        timeout=10,
    )
    assert resp.status_code == 200

    # Get session info using the cookie
    resp = requests.get(
        f"{backend_url}/auth/session_info/",
        cookies=resp.cookies,
        timeout=10,
    )
    assert resp.status_code == 200
    info = resp.json()

    assert "disabled" not in info.get("user", {}), (
        "session_info user object should not contain 'disabled' field"
    )


# -- 7. Scenario 1: Deferred accepted email via set_session --------------------


def test_scenario1_accept_user_defers_email(command, backend_url):
    """When admin accepts a user who hasn't completed signup, the
    account_accepted_self email should NOT be sent immediately.
    Instead, notify_on_completion is set in registration_state.

    Spec: Registration scenarios > Scenario 1
    """
    email = "spec_scenario1@example.com"

    # Step 1: Self-register (accepted=False)
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Scenario", "lastname": "One"},
        timeout=10,
    )
    assert resp.status_code == 200
    registration_token = resp.json()["registration_token"]

    # Step 2: Admin accepts before signup completes
    accept_result = command("accept_user", email=email)
    assert accept_result["success"] is True
    assert accept_result["has_account"] is False

    # Step 3: Check registration_state has notify_on_completion=True
    resp = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert resp.status_code == 200
    status = resp.json()
    assert status.get("notify_on_completion") is True, (
        "registration_state should have notify_on_completion=True after "
        "accept_user when user has no account"
    )


def test_scenario1_set_session_sends_deferred_email(command, backend_url, auth_client):
    """After signup completes for a pre-accepted user, set_session should
    send the account_accepted_self email and registration_state should be
    deleted.

    Spec: Login and sessions > Deferred accepted email in set_session
    """
    email = "spec_scenario1_deferred@example.com"

    # Step 1: Self-register
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Deferred", "lastname": "Email"},
        timeout=10,
    )
    assert resp.status_code == 200
    reg_data = resp.json()
    signup_token = reg_data["signup_token"]
    registration_token = reg_data["registration_token"]

    # Step 2: Admin accepts before signup
    command("accept_user", email=email)

    # Step 3: Complete signup
    result = complete_signup_flow(command, auth_client, signup_token, email)

    # Step 4: Call set_session -- this should trigger the deferred email
    resp = requests.post(
        f"{backend_url}/cookies/set_session/",
        json={"session_token": result.session_token},
        timeout=10,
    )
    assert resp.status_code == 200

    # Step 5: Registration state should be deleted (create_user cleans it up)
    resp = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert resp.status_code == 404, (
        "registration_state should be deleted after account creation"
    )
