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


def get_session_info(backend_url, session_token):
    """Get session info by passing the session token directly as a Cookie header.

    The requests library filters out Secure cookies over HTTP connections,
    so we cannot rely on resp.cookies from set_session (which sets Secure=True).
    Constructing the Cookie header manually bypasses the CookieJar policy.
    """
    resp = requests.get(
        f"{backend_url}/auth/session_info/",
        headers={"Cookie": f"session_token={session_token}"},
        timeout=10,
    )
    assert resp.status_code == 200
    info = resp.json()
    assert "user" in info, f"session_info should return user data, got: {info}"
    return info


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

    info = get_session_info(backend_url, result.session_token)

    assert "disabled" not in info["user"], (
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


# -- Scenario 2: accept_new upgrades self-registered newusers entry -----------


def test_scenario2_accept_new_upgrades_selfreg(command, backend_url, auth_client):
    """accept_new should upgrade an existing newusers entry to accepted=True
    when a self-registered user (no account yet) appears in the sync CSV.
    After signup completes, the user should have member permission.

    Spec: Registration scenarios > Scenario 2
    """
    email = "spec_scenario2_accept@example.com"

    # Step 1: Self-register (creates newusers with accepted=False)
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Scenario", "lastname": "Two"},
        timeout=10,
    )
    assert resp.status_code == 200
    signup_token = resp.json()["signup_token"]

    # Step 2: Same email appears in sync CSV
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7100",
                "Voornaam": "Scenario",
                "Achternaam": "Two",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)

    # Step 3: Accept -- should upgrade existing newusers entry
    result = command("accept_new", email=email)
    assert result["added"] >= 1

    # Step 4: Complete signup -- since accepted=True now, create_user
    # should grant member permission
    complete = complete_signup_flow(command, auth_client, signup_token, email)

    # Step 5: Verify member permission was granted
    info = get_session_info(backend_url, complete.session_token)
    assert "member" in info["user"]["permissions"], (
        "User should have member permission after signup with accepted=True"
    )


# -- update_existing ----------------------------------------------------------


def test_update_existing_syncs_data(command, backend_url, auth_client):
    """update_existing should copy sync data to userdata, update the user
    profile (names), renew member permission, and populate the birthday table.

    Spec: Sync lifecycle > Update existing
    """
    email = "spec_update_existing@example.com"

    # Step 1: Create user via sync flow
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7101",
                "Voornaam": "Original",
                "Achternaam": "Name",
                "Geslacht": "V",
                "Geboortedatum": "15/03/1995",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    command("accept_new", email=email)

    signup_result = auth_client.create_signup(email)
    assert isinstance(signup_result, CreateSignupActionSuccessResult)
    complete = complete_signup_flow(
        command, auth_client, signup_result.signup_token, email
    )

    # Step 2: Import CSV with updated name and run update_existing
    csv_updated = make_au_csv(
        [
            {
                "Bondsnummer": "7101",
                "Voornaam": "Updated",
                "Tussenvoegsel": "van",
                "Achternaam": "Name",
                "Geslacht": "V",
                "Geboortedatum": "15/03/1995",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_updated)
    result = command("update_existing")
    assert result["updated"] >= 1

    # Step 3: Verify profile was updated via session_info
    info = get_session_info(backend_url, complete.session_token)
    assert info["user"]["firstname"] == "Updated"
    assert info["user"]["lastname"] == "van Name"

    # Step 4: Verify member permission is still active
    assert "member" in info["user"]["permissions"]

    # Step 5: Verify birthday was populated
    # list_birthdays returns entries keyed by email but the email is the
    # storage key, not part of the value. Check by matching the name/dob.
    birthdays = command("list_birthdays")
    found = any(
        b["voornaam"] == "Updated" and b["geboortedatum"] == "15/03/1995"
        for b in birthdays
    )
    assert found, "Birthday entry should be populated by update_existing"


# -- Bondsnummer matching / email changes --------------------------------------


def test_bondsnummer_email_change(command, backend_url, auth_client):
    """When a bondsnummer maps to a different email in a new CSV import,
    compute_groups should report it in email_changes and update_existing
    should migrate all references.

    Spec: Bondsnummer matching
    """
    old_email = "spec_bns_old@example.com"
    new_email = "spec_bns_new@example.com"
    bondsnummer = "7110"

    # Step 1: Create user via sync flow with old_email
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": bondsnummer,
                "Voornaam": "Bns",
                "Achternaam": "User",
                "Geslacht": "V",
                "Geboortedatum": "01/06/1990",
                "Email": old_email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    command("accept_new", email=old_email)

    signup_result = auth_client.create_signup(old_email)
    assert isinstance(signup_result, CreateSignupActionSuccessResult)
    complete_signup_flow(command, auth_client, signup_result.signup_token, old_email)

    # Run update_existing to populate bondsnummer index
    command("update_existing")

    # Step 2: Import CSV with same bondsnummer but different email
    csv_changed = make_au_csv(
        [
            {
                "Bondsnummer": bondsnummer,
                "Voornaam": "Bns",
                "Achternaam": "User",
                "Geslacht": "V",
                "Geboortedatum": "01/06/1990",
                "Email": new_email,
            }
        ]
    )
    command("import_sync", csv_content=csv_changed)

    # Step 3: compute_groups should detect email change
    groups = command("compute_groups")
    change_entries = groups.get("email_changes", [])
    found = any(
        ec["old_email"] == old_email
        and ec["new_email"] == new_email
        and ec["bondsnummer"] == int(bondsnummer)
        for ec in change_entries
    )
    assert found, (
        f"email_changes should contain {old_email} -> {new_email} "
        f"for bondsnummer {bondsnummer}"
    )

    # old_email should NOT appear as departed (being email-changed, not leaving)
    assert old_email not in groups.get("departed", [])

    # Step 4: update_existing should apply the email change
    result = command("update_existing")
    assert result.get("email_changes_applied", 0) >= 1

    # Step 5: User should be able to sign in with new_email
    signin = auth_client.create_signin(new_email)
    assert not isinstance(signin, ActionErrorResult), (
        f"Sign in with new email {new_email} should succeed after email change"
    )


# -- pending_approval in session_info ------------------------------------------


def test_session_info_pending_approval(command, backend_url, auth_client):
    """session_info should return pending_approval=True for a self-registered
    user who completed signup but has not been accepted by an admin.

    Spec: Login and sessions > Session info
    """
    email = "spec_pending_approval@example.com"

    # Step 1: Self-register (creates newusers with accepted=False)
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Pending", "lastname": "Approval"},
        timeout=10,
    )
    assert resp.status_code == 200
    signup_token = resp.json()["signup_token"]

    # Step 2: Complete signup (accepted=False, so newusers entry is kept)
    complete = complete_signup_flow(command, auth_client, signup_token, email)

    # Step 3: Check session_info
    info = get_session_info(backend_url, complete.session_token)

    assert info["pending_approval"] is True, (
        "session_info should show pending_approval=True for unaccepted user"
    )
    assert "member" not in info["user"]["permissions"], (
        "Unaccepted user should not have member permission"
    )


# -- Cancelled members (opzegdatum) -------------------------------------------


def test_cancelled_member_treated_as_departed(command, auth_client):
    """Members with a past cancellation date (opzegdatum) should be treated
    as departed even if present in the sync CSV.

    Spec: Sync lifecycle > Compute groups (cancelled members)
    """
    email = "spec_cancelled@example.com"

    # Step 1: Create user via sync flow (no cancellation)
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7120",
                "Voornaam": "Will",
                "Achternaam": "Cancel",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    command("accept_new", email=email)

    signup_result = auth_client.create_signup(email)
    assert isinstance(signup_result, CreateSignupActionSuccessResult)
    complete_signup_flow(command, auth_client, signup_result.signup_token, email)

    # Grant member permission via update_existing
    command("update_existing")

    # Step 2: Import CSV with same member but past cancellation date
    csv_cancelled = make_au_csv(
        [
            {
                "Bondsnummer": "7120",
                "Voornaam": "Will",
                "Achternaam": "Cancel",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
                "Club lidmaatschap opzegdatum": "01/01/2020",
            }
        ]
    )
    command("import_sync", csv_content=csv_cancelled)

    # Step 3: compute_groups should show them as departed
    groups = command("compute_groups")
    assert email in groups["departed"], (
        "Member with past opzegdatum should appear in departed"
    )


# -- Departed members returning ------------------------------------------------


def test_departed_member_returns_as_to_accept(command, auth_client):
    """A departed member returning in a future sync CSV should appear in
    to_accept, indistinguishable from a first-time user.

    Spec: Registration scenarios > Departed members returning
    """
    email = "spec_departed_return@example.com"

    # Step 1: Create user via sync flow
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "7130",
                "Voornaam": "Departed",
                "Achternaam": "Returner",
                "Geslacht": "V",
                "Geboortedatum": "01/01/2000",
                "Email": email,
            }
        ]
    )
    command("import_sync", csv_content=csv_content)
    command("accept_new", email=email)

    signup_result = auth_client.create_signup(email)
    assert isinstance(signup_result, CreateSignupActionSuccessResult)
    complete_signup_flow(command, auth_client, signup_result.signup_token, email)
    command("update_existing")

    # Step 2: Member departs (empty CSV)
    command("import_sync", csv_content=make_au_csv([]))
    groups = command("compute_groups")
    assert email in groups["departed"]
    command("remove_departed", email=email)

    # Step 3: Member returns in a new CSV
    command("import_sync", csv_content=csv_content)
    groups = command("compute_groups")

    # Should be in to_accept (treated as first-time user)
    to_accept_emails = [u["email"] for u in groups.get("to_accept", [])]
    assert email in to_accept_emails, (
        f"Departed member {email} returning in sync should be in to_accept"
    )

    # Should NOT be in existing
    existing_emails = {e["sync"]["email"] for e in groups.get("existing", [])}
    assert email not in existing_emails
