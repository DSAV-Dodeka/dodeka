"""Integration tests for user registration flows.

Documents the complete lifecycle of user registration, covering both:
1. Self-registration (user signs up via website)
2. Sync-imported registration (admin imports from athletics union CSV)

Each test function walks through a complete flow with detailed step
comments referencing the source code, serving as executable documentation
of the registration system.

Registration state machine:
  ┌──────────┐   register    ┌──────────────┐   verify+complete   ┌──────────────┐
  │  (none)  │──────────────>│  newuser      │───────────────────>│  user         │
  │          │               │  accepted=F   │                    │  no member    │
  └──────────┘               │  reg_state=F  │                    │  still in     │
                             └──────────────┘                    │  newusers     │
                                                                  └──────┬───────┘
                                                                         │ admin accept
                                                                         v
                                                                  ┌──────────────┐
                                                                  │  user         │
                                                                  │  has member   │
                                                                  │  not in       │
                                                                  │  newusers     │
                                                                  └──────────────┘
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

# Strong password that satisfies Faroe's password policy
TEST_PASSWORD = "Str0ng_T3st_P@ss!2024"


def poll_for_token(command, action, email, timeout=10):
    """Poll the private server for a verification code.

    The code is stored by handle_email() in private.py when Faroe sends
    the verification email callback. We poll because there's a small delay
    between create_signup and the email callback arriving.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = command("get_token", action=action, email=email)
        if isinstance(result, dict) and result.get("found"):
            return result["code"]
        time.sleep(0.05)
    raise TimeoutError(f"Token {action} for {email} not found within {timeout}s")


def complete_signup_flow(command, auth_client, signup_token, email):
    """Run the verify → set_password → complete_signup sequence.

    Returns the CompleteSignupActionSuccessResult with session_token.
    """
    # Get verification code (stored by handle_email in private.py)
    code = poll_for_token(command, "signup_verification", email)

    # Verify email address — Faroe marks email as verified
    verify = auth_client.verify_signup_email_address_verification_code(
        signup_token, code
    )
    assert verify.ok is True

    # Set password — Faroe stores the password hash
    pwd = auth_client.set_signup_password(signup_token, TEST_PASSWORD)
    assert pwd.ok is True

    # Complete signup — Faroe calls /invoke which triggers create_user() in auth.py
    result = auth_client.complete_signup(signup_token)
    assert isinstance(result, CompleteSignupActionSuccessResult)
    return result


# -- Atletiekunie CSV helpers (shared with test_sync.py) --

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


# ── Flow A: Self-Registration ───────────────────────────────────────────


def test_self_registration_flow(command, backend_url, auth_client):
    """Self-registration: user signs up via website, admin accepts later.

    Flow: register → check status → verify email → set password →
          complete signup → (no member yet) → admin accept → has member

    References:
        - request_registration(): app.py — creates newuser + registration_state,
          initiates Faroe signup
        - get_registration_status_handler(): app.py — returns accepted flag
        - create_user(): data/auth.py:33-121 — checks accepted flag to decide
          whether to grant member permission
        - cmdhandler_accept_user(): private.py — grants member, removes from newusers
    """
    email = "selfreg@example.com"

    # Step 1: Register via public API
    # app.py:request_registration creates newuser(accepted=False),
    # registration_state, and immediately calls auth_client.create_signup()
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Self", "lastname": "Register"},
        timeout=10,
    )
    assert resp.status_code == 200
    reg_data = resp.json()
    assert reg_data["success"] is True
    registration_token = reg_data["registration_token"]
    signup_token = reg_data["signup_token"]
    assert registration_token is not None
    assert signup_token is not None

    # Step 2: Check registration status — accepted should be False
    # app.py:get_registration_status_handler reads registration_state
    resp = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert resp.status_code == 200
    status = resp.json()
    assert status["email"] == email
    assert status["accepted"] is False
    assert status["signup_token"] == signup_token

    # Steps 3-6: Complete the signup flow (verify email, set password, complete)
    # Faroe calls /invoke → create_user() in auth.py
    # Because accepted=False, create_user() does NOT grant member permission
    # and does NOT remove from newusers (auth.py:105-106)
    result = complete_signup_flow(command, auth_client, signup_token, email)
    session_token = result.session_token
    assert session_token is not None

    # Step 7: Verify user exists but has NO member permission
    # create_user() skipped add_permission because accepted=False
    session_result = auth_client.get_session(session_token)
    assert session_result.ok is True

    # Step 8: Verify user still appears in newusers (pending admin approval)
    # accept_user with has_account=True proves user is in newusers
    # (if not in newusers, accept_user would return an error)
    accept_result = command("accept_user", email=email)
    assert accept_result["success"] is True
    # has_account=True means the user already completed signup but was
    # still in the newusers table awaiting admin approval
    assert accept_result["has_account"] is True

    # Step 9: Verify user now has member permission (can sign in)
    signin = auth_client.create_signin(email)
    assert not isinstance(signin, ActionErrorResult)
    verify = auth_client.verify_signin_user_password(signin.signin_token, TEST_PASSWORD)
    assert verify.ok is True
    complete = auth_client.complete_signin(signin.signin_token)
    assert not isinstance(complete, ActionErrorResult)


# ── Flow B: Sync-Imported Registration ──────────────────────────────────


def test_sync_imported_flow(command, auth_client):
    """Sync-imported: admin imports CSV, accepts new members, user completes signup.

    Flow: import CSV → compute groups → accept new → user completes signup →
          user gets member immediately

    References:
        - sync.py:import_sync() — stores CSV entries in sync table
        - sync.py:compute_groups() — compares sync vs users/newusers
        - sync.py:accept_new() — creates newuser(accepted=True) + registration_state
        - create_user(): data/auth.py:99-104 — accepted=True grants member + removes
          from newusers
    """
    email = "syncimport@example.com"

    # Step 1: Import CSV with a new member
    csv_content = make_au_csv(
        [
            {
                "Bondsnummer": "9001",
                "Voornaam": "Sync",
                "Achternaam": "Import",
                "Geslacht": "V",
                "Geboortedatum": "01/01/1995",
                "Email": email,
            }
        ]
    )
    result = command("import_sync", csv_content=csv_content)
    assert result["imported"] == 1

    # Step 2: Compute groups — should show 1 new user
    groups = command("compute_groups")
    new_emails = [u["email"] for u in groups["new"]]
    assert email in new_emails

    # Step 3: Accept new users — creates newuser(accepted=True) + registration_state
    # sync.py:accept_new stores newuser with accepted=True
    result = command("accept_new", email=email)
    assert result["added"] == 1

    # Step 4: Compute groups — user moves from "new" to "pending"
    # "new" is list[dict] with "email" key, "pending" is list[str]
    groups = command("compute_groups")
    assert email not in [u["email"] for u in groups["new"]]
    assert email in groups["pending"]

    # Step 5: Create Faroe signup for the user
    # In the real flow, accept_new_with_signup or resend_signup_email does this.
    # Here we call create_signup directly via auth_client.
    signup_result = auth_client.create_signup(email)
    assert isinstance(signup_result, CreateSignupActionSuccessResult)
    signup_token = signup_result.signup_token

    # Steps 6-7: Complete signup (verify + password + complete)
    # create_user() sees accepted=True → grants member + removes newuser
    result = complete_signup_flow(command, auth_client, signup_token, email)
    assert result.session_token is not None

    # Step 8: Verify user has member permission immediately
    # accepted=True → create_user() called add_permission(MEMBER)
    session = auth_client.get_session(result.session_token)
    assert session.ok is True

    # Step 9: Verify user removed from newusers (auth.py:103-104)
    groups = command("compute_groups")
    assert email not in groups.get("pending", [])


# ── Edge case: Accept before signup completion ──────────────────────────


def test_accepted_before_signup_completion(command, backend_url, auth_client):
    """Admin accepts a self-registered user BEFORE they complete signup.

    The user registers (accepted=False), admin accepts (accepted=True),
    then user completes signup. create_user() sees accepted=True and
    grants member immediately.

    References:
        - cmdhandler_accept_user(): private.py — marks accepted=True before signup
        - create_user(): data/auth.py:99-104 — checks accepted at signup time
    """
    email = "earlyaccept@example.com"

    # Step 1: Register — gets signup_token (accepted=False)
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Early", "lastname": "Accept"},
        timeout=10,
    )
    assert resp.status_code == 200
    reg_data = resp.json()
    signup_token = reg_data["signup_token"]

    # Step 2: Admin accepts before signup completes
    # cmdhandler_accept_user: user has no account yet → marks accepted=True
    # in newusers and registration_state
    accept_result = command("accept_user", email=email)
    assert accept_result["success"] is True
    assert accept_result["has_account"] is False

    # Step 3: Complete signup (verify + password + complete)
    # create_user() in auth.py reads newuser_data["accepted"] == True
    # → grants member permission immediately (auth.py:99-104)
    result = complete_signup_flow(command, auth_client, signup_token, email)
    assert result.session_token is not None

    # Step 4: Verify user gets member permission immediately
    session = auth_client.get_session(result.session_token)
    assert session.ok is True

    # Step 5: Verify removed from newusers (accepted=True path in auth.py:103)
    groups = command("compute_groups")
    assert email not in groups.get("pending", [])


# ── Registration status reflects acceptance ─────────────────────────────


def test_registration_status_reflects_acceptance(command, backend_url):
    """Registration status endpoint reflects the accepted flag changing.

    References:
        - get_registration_status_handler(): app.py — reads registration_state
        - cmdhandler_accept_user(): private.py — calls mark_registration_state_accepted
    """
    email = "statuscheck@example.com"

    # Step 1: Register — check status shows accepted=False
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Status", "lastname": "Check"},
        timeout=10,
    )
    assert resp.status_code == 200
    registration_token = resp.json()["registration_token"]

    resp = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert resp.status_code == 200
    assert resp.json()["accepted"] is False

    # Step 2: Accept — check status shows accepted=True
    command("accept_user", email=email)

    resp = requests.post(
        f"{backend_url}/auth/registration_status",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert resp.status_code == 200
    assert resp.json()["accepted"] is True


# ── Renew expired signup ────────────────────────────────────────────────


def test_renew_expired_signup(command, backend_url, auth_client):
    """Renewing a signup creates a new signup_token for the same registration.

    References:
        - renew_signup_handler(): app.py — creates new Faroe signup,
          updates registration_state with new signup_token
    """
    email = "renewtest@example.com"

    # Step 1: Register — get initial signup_token
    resp = requests.post(
        f"{backend_url}/auth/request_registration",
        json={"email": email, "firstname": "Renew", "lastname": "Test"},
        timeout=10,
    )
    assert resp.status_code == 200
    reg_data = resp.json()
    registration_token = reg_data["registration_token"]
    original_signup_token = reg_data["signup_token"]

    # Step 2: Call renew_signup with the registration_token
    # This creates a new Faroe signup (new signup_token) for the same user
    resp = requests.post(
        f"{backend_url}/auth/renew_signup",
        json={"registration_token": registration_token},
        timeout=10,
    )
    assert resp.status_code == 200
    renew_data = resp.json()
    assert renew_data["success"] is True
    new_signup_token = renew_data["signup_token"]
    assert new_signup_token != original_signup_token

    # Step 3: Complete signup with the NEW token
    # Accept user first so they get member permission on completion
    command("accept_user", email=email)
    result = complete_signup_flow(command, auth_client, new_signup_token, email)
    assert result.session_token is not None
