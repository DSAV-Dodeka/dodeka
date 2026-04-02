"""Executable spec targets for spec-new.md.

These tests describe the intended public behavior of the new registration
model. They are marked xfail until the runtime implementation is updated to
match `docs/spec-new.md`.
"""

import csv
import io
import time

import pytest
import requests
from tiauth_faroe.client import CompleteSignupActionSuccessResult

pytestmark = pytest.mark.xfail(
    reason="Pending implementation of docs/spec-new.md.",
    strict=False,
)

TEST_PASSWORD = "Str0ng_T3st_P@ss!2024"

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
        json={"email": "spec.new.mixed@example.com", "firstname": "Spec", "lastname": "One"},
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


def test_bondsnummer_email_change_migrates_pending_registration(
    command, backend_url
):
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
