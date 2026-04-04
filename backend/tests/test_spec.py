"""Executable spec targets for spec-new.md.

These tests describe the intended public behavior of the new registration
model based on the canonical `registrations` table.
"""

import csv
import io
import smtplib
import time

import requests
from tiauth_faroe.client import (
    ActionErrorResult,
    CompleteSignupActionSuccessResult,
)

import apiserver.handlers.auth as auth_handlers

TEST_PASSWORD = "Str0ng_T3st_P@ss!2024"
BOARD_EMAIL = "bestuur@dsavdodeka.nl"
ADMIN_COOKIE_HEADERS_BY_CREDS = {}

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


def get_session_info(backend_url, session_token):
    """Get session info using a direct Cookie header."""
    resp = requests.get(
        f"{backend_url}/auth/session_info/",
        headers={"Cookie": f"session_token={session_token}"},
        timeout=10,
    )
    assert resp.status_code == 200
    return resp.json()


def get_admin_cookie_headers(command, auth_client):
    """Sign in as the bootstrapped admin and return Cookie headers."""
    creds = command("get_admin_credentials")
    assert isinstance(creds, dict)
    email = creds["email"]
    password = creds["password"]
    cache_key = (email, password)
    cached = ADMIN_COOKIE_HEADERS_BY_CREDS.get(cache_key)
    if cached is not None:
        return cached

    deadline = time.monotonic() + 10

    while True:
        signin = auth_client.create_signin(email)
        if isinstance(signin, ActionErrorResult):
            if signin.error_code == "rate_limited" and time.monotonic() < deadline:
                time.sleep(0.5)
                continue
            assert not isinstance(signin, ActionErrorResult)

        verify = auth_client.verify_signin_user_password(signin.signin_token, password)
        if isinstance(verify, ActionErrorResult):
            if verify.error_code == "rate_limited" and time.monotonic() < deadline:
                time.sleep(0.5)
                continue
            assert verify.ok is True

        complete = auth_client.complete_signin(signin.signin_token)
        assert not isinstance(complete, ActionErrorResult)
        headers = {"Cookie": f"session_token={complete.session_token}"}
        ADMIN_COOKIE_HEADERS_BY_CREDS[cache_key] = headers
        return headers


def extract_cookie_value(headers, name):
    """Extract one cookie value from a simple Cookie header dict."""
    cookie_header = headers["Cookie"]
    for part in cookie_header.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    raise AssertionError(f"Cookie {name} not found in {cookie_header!r}")


def create_prepared_user(command, auth_client, backend_url, email, firstname, lastname):
    """Create a regular user account through prepare_user + Faroe signup."""
    prepared = command("prepare_user", email=email, names=[firstname, lastname])
    assert isinstance(prepared, str)

    signup = auth_client.create_signup(email)
    assert not isinstance(signup, ActionErrorResult)
    complete = complete_signup_flow(command, auth_client, signup.signup_token, email)
    info = get_session_info(backend_url, complete.session_token)
    return complete.session_token, info["user"]["user_id"]


def test_request_registration_reuses_existing_registration_token(backend_url):
    """Repeated registration requests for the same pending email reuse one row."""
    email = "  Spec.New.Mixed@Example.com "

    first = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Spec", "lastname": "One"},
        timeout=10,
    )
    assert first.status_code == 200
    first_data = first.json()
    first_token = first_data["registration_token"]

    second = requests.post(
        f"{backend_url}/auth/request_registration",
        json={
            "email": "spec.new.mixed@example.com",
            "firstname": "Spec",
            "lastname": "One",
        },
        timeout=10,
    )
    assert second.status_code == 200
    second_data = second.json()
    assert second_data["registration_token"] == first_token

    status = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": first_token},
        timeout=10,
    )
    assert status.status_code == 200
    status_data = status.json()
    assert status_data["email"] == "spec.new.mixed@example.com"
    assert status_data["accepted"] is False
    assert status_data["account_created"] is False


def test_request_registration_rejects_existing_user(command, auth_client, backend_url):
    """request_registration rejects emails that already belong to a user."""
    email = "spec-new-existing-user@example.com"
    create_prepared_user(command, auth_client, backend_url, email, "Exists", "Already")

    duplicate = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": "  SPEC-NEW-EXISTING-USER@example.com ", "firstname": "Dup"},
        timeout=10,
    )
    assert duplicate.status_code == 400
    assert "already exists" in duplicate.text


def test_accept_user_keeps_registration_until_first_session(
    command, backend_url, auth_client
):
    """Scenario 1 keeps the registration row until deferred email delivery."""
    email = "spec-new-scenario1@example.com"

    register = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Scenario", "lastname": "One"},
        timeout=10,
    )
    assert register.status_code == 200
    register_data = register.json()
    registration_token = register_data["registration_token"]
    signup_token = register_data["signup_token"]

    accept_result = command("accept_user", email=email)
    assert accept_result["success"] is True
    assert accept_result["has_account"] is False

    complete = complete_signup_flow(command, auth_client, signup_token, email)

    status_before_session = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert status_before_session.status_code == 200
    status_data = status_before_session.json()
    assert status_data["accepted"] is True
    assert status_data["account_created"] is True
    assert status_data["notify_on_completion"] is True

    set_session = requests.post(
        f"{backend_url}/cookies/set_session/",
        json={"session_token": complete.session_token},
        timeout=10,
    )
    assert set_session.status_code == 200

    status_after_session = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert status_after_session.status_code == 404


def test_accept_new_normalizes_email_and_upgrades_existing_registration(
    command, backend_url
):
    """Sync acceptance upgrades the existing normalized registration row in place."""
    original_email = "Spec.New.Sync@Example.com"

    register = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": original_email, "firstname": "Spec", "lastname": "Sync"},
        timeout=10,
    )
    assert register.status_code == 200
    registration_token = register.json()["registration_token"]

    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "8601",
                "Voornaam": "Spec",
                "Achternaam": "Sync",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": "spec.new.sync@example.com",
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    command("accept_new", email="spec.new.sync@example.com")

    status = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert status.status_code == 200
    status_data = status.json()
    assert status_data["email"] == "spec.new.sync@example.com"
    assert status_data["accepted"] is True
    assert status_data["account_created"] is False


def test_bondsnummer_email_change_migrates_pending_registration(command, backend_url):
    """Pending registration email changes migrate one canonical row."""
    old_email = "spec-new-pending-a@example.com"
    new_email = "spec-new-pending-b@example.com"
    bondsnummer = "8602"

    register = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": old_email, "firstname": "Pending", "lastname": "Move"},
        timeout=10,
    )
    assert register.status_code == 200
    registration_token = register.json()["registration_token"]

    initial_csv = make_au_csv(
        [
            {
                "Bondsnummer": bondsnummer,
                "Voornaam": "Pending",
                "Achternaam": "Move",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": old_email,
            }
        ]
    )
    command("import_sync", csv_content=initial_csv)
    command("accept_new", email=old_email)

    changed_csv = make_au_csv(
        [
            {
                "Bondsnummer": bondsnummer,
                "Voornaam": "Pending",
                "Achternaam": "Move",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": new_email,
            }
        ]
    )
    command("import_sync", csv_content=changed_csv)
    groups = command("compute_groups")

    to_accept_emails = {entry["email"] for entry in groups["to_accept"]}
    assert new_email not in to_accept_emails
    assert old_email not in groups["departed"]
    assert any(
        change["old_email"] == old_email
        and change["new_email"] == new_email
        and change["bondsnummer"] == int(bondsnummer)
        for change in groups["email_changes"]
    )

    update_result = command("update_existing")
    assert update_result["email_changes_applied"] >= 1

    status = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert status.status_code == 200
    status_data = status.json()
    assert status_data["email"] == new_email
    assert status_data["accepted"] is True
    assert status_data["account_created"] is False

    restarted = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": new_email, "firstname": "Pending", "lastname": "Move"},
        timeout=10,
    )
    assert restarted.status_code == 200
    assert restarted.json()["registration_token"] == registration_token


def test_lookup_registration_finds_token_by_email_and_code(command, backend_url):
    """lookup_registration resolves the stable token by normalized email + code."""
    email = "Lookup.Mixed@Example.com"

    register = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Lookup", "lastname": "User"},
        timeout=10,
    )
    assert register.status_code == 200
    registration_token = register.json()["registration_token"]

    code_result = command(
        "get_token",
        action="signup_verification",
        email="lookup.mixed@example.com",
        consume=False,
    )
    assert code_result["found"] is True
    code = code_result["code"]

    found = requests.post(
        f"{backend_url}/auth/lookup_registration",
        json={"email": "  lookup.mixed@example.com ", "code": code},
        timeout=10,
    )
    assert found.status_code == 200
    assert found.json() == {"found": True, "token": registration_token}

    not_found = requests.post(
        f"{backend_url}/auth/lookup_registration",
        json={"email": "lookup.mixed@example.com", "code": "000000"},
        timeout=10,
    )
    assert not_found.status_code == 200
    assert not_found.json() == {"found": False}


def test_session_info_pending_approval_uses_registration_state(
    command, backend_url, auth_client
):
    """session_info derives pending_approval from registrations, not disabled."""
    email = "spec-new-pending-approval@example.com"

    register = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Pending", "lastname": "Approval"},
        timeout=10,
    )
    assert register.status_code == 200
    signup_token = register.json()["signup_token"]

    complete = complete_signup_flow(command, auth_client, signup_token, email)
    info = get_session_info(backend_url, complete.session_token)

    assert info["pending_approval"] is True
    assert "member" not in info["user"]["permissions"]
    assert "disabled" not in info["user"]


def test_admin_list_newusers_and_resend_signup_email_for_accepted_registration(
    command, backend_url, auth_client
):
    """Admin endpoints expose and recover accepted registrations without accounts."""
    email = "spec-new-admin-sync@example.com"

    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "8603",
                "Voornaam": "Admin",
                "Achternaam": "Sync",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    command("accept_new", email=email)

    admin_headers = get_admin_cookie_headers(command, auth_client)

    listed = requests.get(
        f"{backend_url}/admin/list_newusers/",
        headers=admin_headers,
        timeout=10,
    )
    assert listed.status_code == 200
    rows = listed.json()
    row = next(r for r in rows if r["email"] == email)
    assert row["accepted"] is True
    assert row["account_created"] is False
    assert row["has_signup_token"] is False
    assert row["registration_token"]

    resend = requests.post(
        f"{backend_url}/admin/resend_signup_email/",
        json={"email": email},
        headers=admin_headers,
        timeout=10,
    )
    assert resend.status_code == 200
    assert resend.json()["success"] is True

    status = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": row["registration_token"]},
        timeout=10,
    )
    assert status.status_code == 200
    status_data = status.json()
    assert status_data["email"] == email
    assert status_data["accepted"] is True
    assert status_data["account_created"] is False
    assert status_data["signup_token"] is not None

    token_result = command("get_token", action="signup_verification", email=email)
    assert token_result["found"] is True
    assert token_result["code"]


def test_accept_new_sync_tracks_email_send_count(command, backend_url, auth_client):
    """Public sync acceptance increments email_send_count across invite steps."""
    command("reset")
    email = "spec-new-email-count@example.com"

    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "8606",
                "Voornaam": "Email",
                "Achternaam": "Count",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    admin_headers = get_admin_cookie_headers(command, auth_client)

    accepted = requests.post(
        f"{backend_url}/admin/accept_new_sync/",
        json={"email": email},
        headers=admin_headers,
        timeout=10,
    )
    assert accepted.status_code == 200
    accepted_data = accepted.json()
    assert accepted_data["added"] == 1
    assert accepted_data["emails_sent"] == 1
    assert accepted_data["emails_failed"] == 0

    listed = requests.get(
        f"{backend_url}/admin/list_newusers/",
        headers=admin_headers,
        timeout=10,
    )
    assert listed.status_code == 200
    row = next(r for r in listed.json() if r["email"] == email)
    assert row["email_send_count"] == 1
    assert row["has_signup_token"] is False

    resend = requests.post(
        f"{backend_url}/admin/resend_signup_email/",
        json={"email": email},
        headers=admin_headers,
        timeout=10,
    )
    assert resend.status_code == 200

    listed = requests.get(
        f"{backend_url}/admin/list_newusers/",
        headers=admin_headers,
        timeout=10,
    )
    row = next(r for r in listed.json() if r["email"] == email)
    assert row["email_send_count"] == 2
    assert row["has_signup_token"] is True


def test_accept_new_sync_normalizes_single_email_request(
    command, backend_url, auth_client
):
    """Single-email sync acceptance should honor normalized email identity."""
    command("reset")
    email = "spec-new-admin-case@example.com"

    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "8607",
                "Voornaam": "Admin",
                "Achternaam": "Case",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    admin_headers = get_admin_cookie_headers(command, auth_client)

    accepted = requests.post(
        f"{backend_url}/admin/accept_new_sync/",
        json={"email": "  SPEC-NEW-ADMIN-CASE@EXAMPLE.COM "},
        headers=admin_headers,
        timeout=10,
    )
    assert accepted.status_code == 200
    accepted_data = accepted.json()
    assert accepted_data["added"] == 1
    assert accepted_data["emails_sent"] == 1
    assert accepted_data["emails_failed"] == 0

    listed = requests.get(
        f"{backend_url}/admin/list_newusers/",
        headers=admin_headers,
        timeout=10,
    )
    assert listed.status_code == 200
    row = next(r for r in listed.json() if r["email"] == email)
    assert row["accepted"] is True
    assert row["email_send_count"] == 1


def test_permission_management_endpoints(command, backend_url, auth_client):
    """Admin permission endpoints manage non-admin permissions declaratively."""
    _, user_id = create_prepared_user(
        command,
        auth_client,
        backend_url,
        "spec-new-permissions@example.com",
        "Perm",
        "Target",
    )
    admin_headers = get_admin_cookie_headers(command, auth_client)

    available = requests.get(
        f"{backend_url}/admin/available_permissions/",
        headers=admin_headers,
        timeout=10,
    )
    assert available.status_code == 200
    permissions = set(available.json()["permissions"])
    assert {"member", "admin", "comcom", "batcie"} <= permissions

    add = requests.post(
        f"{backend_url}/admin/add_permission/",
        json={"user_id": user_id, "permission": "comcom"},
        headers=admin_headers,
        timeout=10,
    )
    assert add.status_code == 200

    users = requests.get(
        f"{backend_url}/admin/list_users/",
        headers=admin_headers,
        timeout=10,
    )
    assert users.status_code == 200
    user_row = next(row for row in users.json() if row["user_id"] == user_id)
    assert "comcom" in user_row["permissions"]

    remove = requests.post(
        f"{backend_url}/admin/remove_permission/",
        json={"user_id": user_id, "permission": "comcom"},
        headers=admin_headers,
        timeout=10,
    )
    assert remove.status_code == 200

    users = requests.get(
        f"{backend_url}/admin/list_users/",
        headers=admin_headers,
        timeout=10,
    )
    user_row = next(row for row in users.json() if row["user_id"] == user_id)
    assert "comcom" not in user_row["permissions"]

    declarative = requests.post(
        f"{backend_url}/admin/set_permissions/",
        json={"permissions": {user_id: ["member", "bestuur", "batcie"]}},
        headers=admin_headers,
        timeout=10,
    )
    assert declarative.status_code == 200
    results = declarative.json()["results"][user_id]
    assert "bestuur" in results["added"]
    assert "batcie" in results["added"]

    users = requests.get(
        f"{backend_url}/admin/list_users/",
        headers=admin_headers,
        timeout=10,
    )
    user_row = next(row for row in users.json() if row["user_id"] == user_id)
    assert {"member", "bestuur", "batcie"} <= set(user_row["permissions"])
    assert "comcom" not in user_row["permissions"]

    forbidden = requests.post(
        f"{backend_url}/admin/add_permission/",
        json={"user_id": user_id, "permission": "admin"},
        headers=admin_headers,
        timeout=10,
    )
    assert forbidden.status_code == 403


def test_set_permissions_preserves_admin_permission(command, backend_url, auth_client):
    """Declarative permission updates never remove an existing admin permission."""
    email = "spec-new-admin-preserved@example.com"
    _, user_id = create_prepared_user(
        command,
        auth_client,
        backend_url,
        email,
        "Admin",
        "Preserved",
    )
    grant = command("grant_admin", email=email)
    assert grant["success"] is True

    admin_headers = get_admin_cookie_headers(command, auth_client)
    update = requests.post(
        f"{backend_url}/admin/set_permissions/",
        json={"permissions": {user_id: ["member", "batcie"]}},
        headers=admin_headers,
        timeout=10,
    )
    assert update.status_code == 200

    users = requests.get(
        f"{backend_url}/admin/list_users/",
        headers=admin_headers,
        timeout=10,
    )
    assert users.status_code == 200
    row = next(r for r in users.json() if r["user_id"] == user_id)
    assert {"admin", "member", "batcie"} <= set(row["permissions"])


def test_secondary_session_info_and_admin_fallback(command, backend_url, auth_client):
    """Secondary cookies can authorize admin routes without replacing identity."""
    email = "spec-new-secondary@example.com"
    primary_session, user_id = create_prepared_user(
        command,
        auth_client,
        backend_url,
        email,
        "Primary",
        "User",
    )

    admin_headers = get_admin_cookie_headers(command, auth_client)
    admin_email = command("get_admin_credentials")["email"]
    secondary_session = extract_cookie_value(admin_headers, "session_token")

    regular_only_headers = {"Cookie": f"session_token={primary_session}"}
    both_headers = {
        "Cookie": (
            f"session_token={primary_session}; "
            f"session_token_secondary={secondary_session}"
        )
    }

    denied = requests.get(
        f"{backend_url}/admin/list_users/",
        headers=regular_only_headers,
        timeout=10,
    )
    assert denied.status_code == 403

    allowed = requests.get(
        f"{backend_url}/admin/list_users/",
        headers=both_headers,
        timeout=10,
    )
    assert allowed.status_code == 200
    assert any(row["user_id"] == user_id for row in allowed.json())

    primary_info = requests.get(
        f"{backend_url}/auth/session_info/",
        headers=both_headers,
        timeout=10,
    )
    assert primary_info.status_code == 200
    assert primary_info.json()["user"]["email"] == email

    secondary_info = requests.get(
        f"{backend_url}/auth/session_info/?secondary=true",
        headers=both_headers,
        timeout=10,
    )
    assert secondary_info.status_code == 200
    assert secondary_info.json()["user"]["email"] == admin_email


def test_board_account_setup_and_renewal(command, backend_url, auth_client):
    """Board setup creates a system registration and board_renew issues reset."""
    command("reset")
    setup = command("board_setup")
    assert setup["success"] is True
    assert setup["email"] == BOARD_EMAIL

    admin_headers = get_admin_cookie_headers(command, auth_client)

    system_users = requests.get(
        f"{backend_url}/admin/list_system_users/",
        headers=admin_headers,
        timeout=10,
    )
    assert system_users.status_code == 200
    assert BOARD_EMAIL in system_users.json()["system_users"]
    assert "root_admin@localhost" in system_users.json()["system_users"]

    listed = requests.get(
        f"{backend_url}/admin/list_newusers/",
        headers=admin_headers,
        timeout=10,
    )
    assert listed.status_code == 200
    row = next(r for r in listed.json() if r["email"] == BOARD_EMAIL)
    assert row["accepted"] is True
    assert row["account_created"] is False
    assert row["has_signup_token"] is True

    status = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": row["registration_token"]},
        timeout=10,
    )
    assert status.status_code == 200
    signup_token = status.json()["signup_token"]
    assert signup_token is not None

    complete = complete_signup_flow(command, auth_client, signup_token, BOARD_EMAIL)
    assert complete.session_token is not None

    grant = command("grant_admin", email=BOARD_EMAIL)
    assert grant["success"] is True

    renew = command("board_renew")
    assert renew["success"] is True
    assert renew["email"] == BOARD_EMAIL

    reset_token = command(
        "get_token",
        action="password_reset",
        email=BOARD_EMAIL,
        consume=False,
    )
    assert reset_token["found"] is True


def test_remove_departed_invalidates_faroe_session(command, auth_client):
    """Departed-user cleanup invalidates existing session tokens."""
    email = "spec-new-remove-session@example.com"

    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "8604",
                "Voornaam": "Session",
                "Achternaam": "Gone",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    command("accept_new", email=email)

    signup = auth_client.create_signup(email)
    assert not isinstance(signup, ActionErrorResult)
    complete = complete_signup_flow(command, auth_client, signup.signup_token, email)

    command("import_sync", csv_content=make_au_csv([]))
    command("remove_departed", email=email)

    session = auth_client.get_session(complete.session_token)
    assert isinstance(session, ActionErrorResult)
    assert session.error_code == "invalid_session_token"


def test_signin_normalizes_email_case(command, auth_client, backend_url):
    """Signin should work with the normalized email, regardless of caller casing."""
    email = "spec-new-signin-case@example.com"
    create_prepared_user(command, auth_client, backend_url, email, "Signin", "Case")

    signin = auth_client.create_signin("SPEC-NEW-SIGNIN-CASE@EXAMPLE.COM")
    assert not isinstance(signin, ActionErrorResult)

    verify = auth_client.verify_signin_user_password(signin.signin_token, TEST_PASSWORD)
    assert verify.ok is True

    complete = auth_client.complete_signin(signin.signin_token)
    assert not isinstance(complete, ActionErrorResult)


def test_update_existing_normalizes_single_email_request(
    command, backend_url, auth_client
):
    """Single-email sync update should use normalized email identity."""
    command("reset")
    email = "spec-new-update-case@example.com"
    create_prepared_user(command, auth_client, backend_url, email, "Update", "Case")

    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "8608",
                "Voornaam": "Update",
                "Achternaam": "Case",
                "Geslacht": "V",
                "Geboortedatum": "02/02/2001",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    birthdays_before = command("list_birthdays")
    assert "Update" not in {entry["voornaam"] for entry in birthdays_before}

    admin_headers = get_admin_cookie_headers(command, auth_client)
    updated = requests.post(
        f"{backend_url}/admin/update_existing/",
        json={"email": " SPEC-NEW-UPDATE-CASE@EXAMPLE.COM "},
        headers=admin_headers,
        timeout=10,
    )
    assert updated.status_code == 200
    assert updated.json() == {"updated": 1}

    birthdays_after = command("list_birthdays")
    by_name = {entry["voornaam"]: entry for entry in birthdays_after}
    assert by_name["Update"]["achternaam"] == "Case"


def test_set_session_keeps_registration_when_deferred_email_send_fails(
    command, backend_url, auth_client, monkeypatch
):
    """Deferred acceptance state should survive email-send failure for retry."""
    email = "spec-new-deferred-failure@example.com"

    register = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Deferred", "lastname": "Retry"},
        timeout=10,
    )
    assert register.status_code == 200
    registration_token = register.json()["registration_token"]
    signup_token = register.json()["signup_token"]

    accept = command("accept_user", email=email)
    assert accept["success"] is True
    assert accept["has_account"] is False

    complete = complete_signup_flow(command, auth_client, signup_token, email)

    def fail_sendemail(*args, **kwargs):
        raise smtplib.SMTPException("synthetic send failure")

    monkeypatch.setattr(auth_handlers, "sendemail", fail_sendemail)

    set_session = requests.post(
        f"{backend_url}/cookies/set_session/",
        json={"session_token": complete.session_token},
        timeout=10,
    )
    assert set_session.status_code == 200

    status = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert status.status_code == 200
    status_data = status.json()
    assert status_data["accepted"] is True
    assert status_data["account_created"] is True
    assert status_data["notify_on_completion"] is True


def test_pending_registration_email_change_collision_keeps_one_canonical_row(
    command, backend_url, auth_client
):
    """Email migration should resolve conflicting pending registrations cleanly."""
    old_email = "spec-new-collision-a@example.com"
    new_email = "spec-new-collision-b@example.com"
    bondsnummer = "8605"

    old_reg = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": old_email, "firstname": "Collision", "lastname": "Old"},
        timeout=10,
    )
    assert old_reg.status_code == 200
    old_token = old_reg.json()["registration_token"]

    new_reg = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": new_email, "firstname": "Collision", "lastname": "New"},
        timeout=10,
    )
    assert new_reg.status_code == 200
    new_token = new_reg.json()["registration_token"]

    initial_csv = make_au_csv(
        [
            {
                "Bondsnummer": bondsnummer,
                "Voornaam": "Collision",
                "Achternaam": "Old",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": old_email,
            }
        ]
    )
    command("import_sync", csv_content=initial_csv)
    command("accept_new", email=old_email)

    changed_csv = make_au_csv(
        [
            {
                "Bondsnummer": bondsnummer,
                "Voornaam": "Collision",
                "Achternaam": "New",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": new_email,
            }
        ]
    )
    command("import_sync", csv_content=changed_csv)
    update_result = command("update_existing")
    assert isinstance(update_result, dict)

    admin_headers = get_admin_cookie_headers(command, auth_client)
    listed = requests.get(
        f"{backend_url}/admin/list_newusers/",
        headers=admin_headers,
        timeout=10,
    )
    assert listed.status_code == 200
    rows = listed.json()
    assert not any(row["email"] == old_email for row in rows)
    assert sum(1 for row in rows if row["email"] == new_email) == 1

    status_old = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": old_token},
        timeout=10,
    )
    status_new = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": new_token},
        timeout=10,
    )
    live = [status for status in (status_old, status_new) if status.status_code == 200]
    assert len(live) == 1
