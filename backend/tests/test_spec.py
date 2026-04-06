"""Future-facing contract tests for the final backend specification.

These tests intentionally target the final `registration_id` / `user_id` /
`bondsnummer` model described in `backend/docs/spec.md`, not the currently
implemented email-keyed lifecycle.

They are marked xfail until the backend migration is implemented.
"""

import csv
import io
import time
from typing import Any

import pytest
import requests
from tiauth_faroe.client import (
    ActionErrorResult,
    CompleteSignupActionSuccessResult,
)

pytestmark = pytest.mark.xfail(
    reason="Final registration/sync spec is documented ahead of implementation",
    strict=False,
)

TEST_PASSWORD = "Str0ng_T3st_P@ss!2024"
ADMIN_COOKIE_HEADERS_BY_CREDS: dict[tuple[str, str], dict[str, str]] = {}

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


def make_au_csv(members: list[dict[str, str]]) -> str:
    """Create CSV content in Atletiekunie export format."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=AU_COLUMNS, restval="")
    writer.writeheader()
    for member in members:
        writer.writerow(member)
    return buf.getvalue()


def poll_for_token(command, action: str, email: str, timeout: float = 10) -> str:
    """Poll the private token mirror used by the integration tests."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = command("get_token", action=action, email=email)
        if isinstance(result, dict) and result.get("found"):
            return result["code"]
        time.sleep(0.05)
    raise TimeoutError(f"Token {action} for {email} not found within {timeout}s")


def get_admin_cookie_headers(command, auth_client) -> dict[str, str]:
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


def post_json(
    backend_url: str,
    path: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> requests.Response:
    """POST JSON to the backend."""
    return requests.post(
        f"{backend_url}{path}",
        json=payload,
        headers=headers,
        timeout=10,
    )


def get_json(
    backend_url: str,
    path: str,
    headers: dict[str, str] | None = None,
) -> requests.Response:
    """GET JSON from the backend."""
    return requests.get(
        f"{backend_url}{path}",
        headers=headers,
        timeout=10,
    )


def list_registrations(
    backend_url: str, admin_headers: dict[str, str]
) -> list[dict[str, Any]]:
    """Return the final registration admin read model list."""
    response = get_json(backend_url, "/admin/list_registrations/", admin_headers)
    assert response.status_code == 200
    return response.json()


def list_users(backend_url: str, admin_headers: dict[str, str]) -> list[dict[str, Any]]:
    """Return the admin user list."""
    response = get_json(backend_url, "/admin/list_users/", admin_headers)
    assert response.status_code == 200
    return response.json()


def get_sync_status(
    backend_url: str, admin_headers: dict[str, str]
) -> dict[str, Any]:
    """Return the final sync preview."""
    response = get_json(backend_url, "/admin/sync_status/", admin_headers)
    assert response.status_code == 200
    return response.json()


def import_sync_csv(
    backend_url: str,
    admin_headers: dict[str, str],
    csv_content: str,
) -> requests.Response:
    """Import one pending Volta snapshot."""
    return post_json(
        backend_url,
        "/admin/import_sync/",
        {"csv_content": csv_content},
        admin_headers,
    )


def get_registration_by_email(
    backend_url: str,
    admin_headers: dict[str, str],
    email: str,
) -> dict[str, Any]:
    """Find one pending registration by normalized email."""
    rows = list_registrations(backend_url, admin_headers)
    return next(row for row in rows if row["email"] == email)


def get_user_by_email(
    backend_url: str,
    admin_headers: dict[str, str],
    email: str,
) -> dict[str, Any]:
    """Find one live user by normalized email."""
    rows = list_users(backend_url, admin_headers)
    return next(row for row in rows if row["email"] == email)


def accept_registration(
    backend_url: str,
    admin_headers: dict[str, str],
    registration_id: str,
) -> requests.Response:
    """Accept one pending registration."""
    return post_json(
        backend_url,
        "/admin/accept_registration/",
        {"registration_id": registration_id},
        admin_headers,
    )


def renew_signup(backend_url: str, registration_id: str) -> requests.Response:
    """Renew signup for one accepted registration."""
    return post_json(
        backend_url,
        "/auth/renew_signup",
        {"registration_id": registration_id},
    )


def complete_signup_from_registration(
    command,
    auth_client,
    backend_url: str,
    admin_headers: dict[str, str],
    email: str,
) -> tuple[str, str]:
    """Create a live user through the final accepted-registration flow."""
    registration = get_registration_by_email(backend_url, admin_headers, email)
    registration_id = registration["registration_id"]

    accepted = accept_registration(backend_url, admin_headers, registration_id)
    assert accepted.status_code == 200

    renewed = renew_signup(backend_url, registration_id)
    assert renewed.status_code == 200
    signup_token = renewed.json()["signup_token"]

    code = poll_for_token(command, "signup_verification", email)
    verify = auth_client.verify_signup_email_address_verification_code(
        signup_token, code
    )
    assert verify.ok is True

    pwd = auth_client.set_signup_password(signup_token, TEST_PASSWORD)
    assert pwd.ok is True

    complete = auth_client.complete_signup(signup_token)
    assert isinstance(complete, CompleteSignupActionSuccessResult)
    return registration_id, complete.session_token


def test_request_registration_creates_only_pending_registration(
    command, backend_url, auth_client
) -> None:
    """Self-registration creates pending state but does not start Faroe signup."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    response = post_json(
        backend_url,
        "/auth/request_registration",
        {
            "email": "  Final.Pending@Example.com ",
            "firstname": "Final",
            "lastname": "Pending",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data.get("success") is True
    assert "registration_id" not in data
    assert "registration_token" not in data
    assert "signup_token" not in data

    row = get_registration_by_email(
        backend_url, admin_headers, "final.pending@example.com"
    )
    assert row["accepted"] is False
    assert row["signup_active"] is False
    assert row["bondsnummer"] is None


def test_accepted_registration_starts_signup_only_through_renew(
    command, backend_url, auth_client
) -> None:
    """Accepted registrations only enter Faroe signup through renew_signup."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    post_json(
        backend_url,
        "/auth/request_registration",
        {"email": "renew.me@example.com", "firstname": "Renew", "lastname": "Me"},
    )
    row = get_registration_by_email(backend_url, admin_headers, "renew.me@example.com")
    registration_id = row["registration_id"]

    before_accept = renew_signup(backend_url, registration_id)
    assert before_accept.status_code >= 400

    first_accept = accept_registration(backend_url, admin_headers, registration_id)
    second_accept = accept_registration(backend_url, admin_headers, registration_id)
    assert first_accept.status_code == 200
    assert second_accept.status_code == 200

    status = post_json(
        backend_url,
        "/auth/registration_status",
        {"registration_id": registration_id},
    )
    assert status.status_code == 200
    assert status.json()["accepted"] is True
    assert status.json()["signup_token"] is None

    renewed = renew_signup(backend_url, registration_id)
    assert renewed.status_code == 200
    signup_token = renewed.json()["signup_token"]
    assert signup_token

    status = post_json(
        backend_url,
        "/auth/registration_status",
        {"registration_id": registration_id},
    )
    assert status.status_code == 200
    assert status.json()["signup_token"] == signup_token


def test_lookup_registration_uses_current_email_and_code(
    command, backend_url, auth_client
) -> None:
    """lookup_registration resolves the stable registration_id from current email."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    post_json(
        backend_url,
        "/auth/request_registration",
        {"email": "lookup.final@example.com", "firstname": "Look", "lastname": "Up"},
    )
    row = get_registration_by_email(
        backend_url, admin_headers, "lookup.final@example.com"
    )
    registration_id = row["registration_id"]

    accepted = accept_registration(backend_url, admin_headers, registration_id)
    assert accepted.status_code == 200

    renewed = renew_signup(backend_url, registration_id)
    assert renewed.status_code == 200

    code = poll_for_token(command, "signup_verification", "lookup.final@example.com")
    found = post_json(
        backend_url,
        "/auth/lookup_registration",
        {"email": "  Lookup.Final@example.com ", "code": code},
    )
    assert found.status_code == 200
    assert found.json() == {"found": True, "registration_id": registration_id}


def test_sync_status_returns_final_top_level_groups(
    command, backend_url, auth_client
) -> None:
    """Sync preview exposes final review/apply groups, not the legacy ones."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9101",
                    "Voornaam": "Sync",
                    "Achternaam": "Preview",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "sync.preview@example.com",
                }
            ]
        ),
    )
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    assert set(status) == {
        "review_required",
        "linked_registrations",
        "existing",
        "departed",
    }


def test_sync_review_candidates_use_final_pool_and_reason_order(
    command, backend_url, auth_client
) -> None:
    """Unresolved rows return ordered candidates from the unlinked pool only."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    post_json(
        backend_url,
        "/auth/request_registration",
        {
            "email": "candidate.exact@example.com",
            "firstname": "Casey",
            "lastname": "Matcher",
        },
    )
    registration = get_registration_by_email(
        backend_url, admin_headers, "candidate.exact@example.com"
    )

    linked = post_json(
        backend_url,
        "/auth/request_registration",
        {
            "email": "already.linked@example.com",
            "firstname": "Casey",
            "lastname": "Matcher",
        },
    )
    assert linked.status_code == 200
    linked_registration = get_registration_by_email(
        backend_url, admin_headers, "already.linked@example.com"
    )
    linked_result = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {
            "kind": "registration",
            "subject_id": linked_registration["registration_id"],
            "bondsnummer": 9991,
        },
        admin_headers,
    )
    assert linked_result.status_code == 200

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9102",
                    "Voornaam": "Casey",
                    "Achternaam": "Matcher",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "candidate.exact@example.com",
                }
            ]
        ),
    )
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    assert len(status["review_required"]) == 1
    item = status["review_required"][0]
    assert item["bondsnummer"] == 9102

    candidates = item["candidates"]
    assert 1 <= len(candidates) <= 5
    assert candidates[0]["subject_id"] == registration["registration_id"]
    assert candidates[0]["reasons"][0] == "email_exact"
    assert set(candidates[0]["reasons"]) <= {
        "email_exact",
        "name_exact",
        "name_partial",
    }
    assert all(
        candidate["subject_id"] != linked_registration["registration_id"]
        for candidate in candidates
    )


def test_resolve_sync_match_links_registration_and_removes_review_item(
    command, backend_url, auth_client
) -> None:
    """Resolving a registration match creates the canonical bondsnummer link."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    post_json(
        backend_url,
        "/auth/request_registration",
        {"email": "resolve.me@example.com", "firstname": "Resolve", "lastname": "Me"},
    )
    registration = get_registration_by_email(
        backend_url, admin_headers, "resolve.me@example.com"
    )

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9103",
                    "Voornaam": "Resolve",
                    "Achternaam": "Me",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "volta.resolve@example.com",
                }
            ]
        ),
    )
    assert imported.status_code == 200

    before = get_sync_status(backend_url, admin_headers)
    assert any(item["bondsnummer"] == 9103 for item in before["review_required"])

    resolved = post_json(
        backend_url,
        "/admin/resolve_sync_match/",
        {
            "bondsnummer": 9103,
            "kind": "registration",
            "subject_id": registration["registration_id"],
        },
        admin_headers,
    )
    assert resolved.status_code == 200

    after = get_sync_status(backend_url, admin_headers)
    assert not any(item["bondsnummer"] == 9103 for item in after["review_required"])

    linked = next(
        row for row in after["linked_registrations"] if row["bondsnummer"] == 9103
    )
    assert linked["registration"]["registration_id"] == registration["registration_id"]
    assert linked["registration"]["accepted"] is True


def test_update_existing_rewrites_linked_pending_registration_email(
    command, backend_url, auth_client
) -> None:
    """Linked pending registrations follow the current Volta email."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    post_json(
        backend_url,
        "/auth/request_registration",
        {
            "email": "pending.old@example.com",
            "firstname": "Pending",
            "lastname": "User",
        },
    )
    registration = get_registration_by_email(
        backend_url, admin_headers, "pending.old@example.com"
    )

    import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9104",
                    "Voornaam": "Pending",
                    "Achternaam": "User",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "pending.old@example.com",
                }
            ]
        ),
    )
    post_json(
        backend_url,
        "/admin/resolve_sync_match/",
        {
            "bondsnummer": 9104,
            "kind": "registration",
            "subject_id": registration["registration_id"],
        },
        admin_headers,
    )

    import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9104",
                    "Voornaam": "Pending",
                    "Achternaam": "User",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "pending.new@example.com",
                }
            ]
        ),
    )

    status = get_sync_status(backend_url, admin_headers)
    linked = next(
        row for row in status["linked_registrations"] if row["bondsnummer"] == 9104
    )
    assert linked["email_will_change"] is True

    updated = post_json(backend_url, "/admin/update_existing/", {}, admin_headers)
    assert updated.status_code == 200

    moved = get_registration_by_email(
        backend_url,
        admin_headers,
        "pending.new@example.com",
    )
    assert moved["registration_id"] == registration["registration_id"]
    assert moved["signup_active"] is False


def test_linked_live_user_keeps_account_email_when_volta_email_changes(
    command, backend_url, auth_client
) -> None:
    """Sync never rewrites the verified account email of a linked live user."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    _, session_token = complete_signup_from_registration(
        command,
        auth_client,
        backend_url,
        admin_headers,
        "live.account@example.com",
    )
    assert session_token

    user = get_user_by_email(backend_url, admin_headers, "live.account@example.com")
    linked = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {"kind": "user", "subject_id": user["user_id"], "bondsnummer": 9105},
        admin_headers,
    )
    assert linked.status_code == 200

    import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9105",
                    "Voornaam": "Live",
                    "Achternaam": "Account",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "volta.changed@example.com",
                }
            ]
        ),
    )

    updated = post_json(backend_url, "/admin/update_existing/", {}, admin_headers)
    assert updated.status_code == 200

    still_live = get_user_by_email(
        backend_url, admin_headers, "live.account@example.com"
    )
    assert still_live["user_id"] == user["user_id"]


def test_remove_departed_only_removes_linked_live_users(
    command, backend_url, auth_client
) -> None:
    """Only linked live users are eligible for automatic departed handling."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    complete_signup_from_registration(
        command,
        auth_client,
        backend_url,
        admin_headers,
        "linked.departed@example.com",
    )
    linked_user = get_user_by_email(
        backend_url, admin_headers, "linked.departed@example.com"
    )
    post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {"kind": "user", "subject_id": linked_user["user_id"], "bondsnummer": 9106},
        admin_headers,
    )

    complete_signup_from_registration(
        command,
        auth_client,
        backend_url,
        admin_headers,
        "unlinked.stays@example.com",
    )

    import_sync_csv(backend_url, admin_headers, make_au_csv([]))
    removed = post_json(backend_url, "/admin/remove_departed/", {}, admin_headers)
    assert removed.status_code == 200

    users = list_users(backend_url, admin_headers)
    emails = {user["email"] for user in users}
    assert "linked.departed@example.com" not in emails
    assert "unlinked.stays@example.com" in emails


def test_import_sync_rejects_duplicate_bondsnummer_and_duplicate_email(
    command, backend_url, auth_client
) -> None:
    """Import validation rejects duplicate bondsnummers and duplicate emails."""
    command("reset")
    admin_headers = get_admin_cookie_headers(command, auth_client)

    duplicate_bondsnummer = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9107",
                    "Voornaam": "Dup",
                    "Achternaam": "Bond",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "dup.bond.a@example.com",
                },
                {
                    "Bondsnummer": "9107",
                    "Voornaam": "Dup",
                    "Achternaam": "Bond",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "dup.bond.b@example.com",
                },
            ]
        ),
    )
    assert duplicate_bondsnummer.status_code == 400

    duplicate_email = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9108",
                    "Voornaam": "Dup",
                    "Achternaam": "Mail",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "dup.mail@example.com",
                },
                {
                    "Bondsnummer": "9109",
                    "Voornaam": "Dup",
                    "Achternaam": "Mail",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": " DUP.MAIL@example.com ",
                },
            ]
        ),
    )
    assert duplicate_email.status_code == 400
