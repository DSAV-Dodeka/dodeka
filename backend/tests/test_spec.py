"""Contract tests for the backend specification.

These tests target the `registration_id` / `user_id` /
`bondsnummer` model described in `backend/docs/spec.md`.
"""

import csv
import io
import time
from typing import Any

import requests
from tiauth_faroe.client import (
    ActionErrorResult,
    CompleteSignupActionSuccessResult,
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


def poll_for_token(
    command, action: str, email: str, timeout: float = 10, consume: bool = True
) -> str:
    """Poll the private token mirror used by the integration tests."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = command("get_token", action=action, email=email, consume=consume)
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
    """Return the registration admin read model list."""
    response = get_json(backend_url, "/admin/list_registrations/", admin_headers)
    assert response.status_code == 200
    return response.json()


def list_users(backend_url: str, admin_headers: dict[str, str]) -> list[dict[str, Any]]:
    """Return the admin user list."""
    response = get_json(backend_url, "/admin/list_users/", admin_headers)
    assert response.status_code == 200
    return response.json()


def get_sync_status(backend_url: str, admin_headers: dict[str, str]) -> dict[str, Any]:
    """Return the sync preview."""
    response = get_json(backend_url, "/admin/sync_status/", admin_headers)
    assert response.status_code == 200
    return response.json()


def import_sync_csv(
    backend_url: str,
    admin_headers: dict[str, str],
    csv_content: str,
    sync_state_counter: int | None = None,
) -> requests.Response:
    """Import one pending Volta snapshot."""
    payload: dict[str, Any] = {"csv_content": csv_content}
    if sync_state_counter is not None:
        payload["sync_state_counter"] = sync_state_counter
    return post_json(
        backend_url,
        "/admin/import_sync/",
        payload,
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


def resend_registration_invite(
    backend_url: str,
    admin_headers: dict[str, str],
    registration_id: str,
) -> requests.Response:
    """Request a manual registration invite resend."""
    return post_json(
        backend_url,
        "/admin/resend_registration_invite/",
        {"registration_id": registration_id},
        admin_headers,
    )


def resolve_sync_match(
    backend_url: str,
    admin_headers: dict[str, str],
    bondsnummer: int,
    kind: str,
    subject_id: str | None,
    sync_state_counter: int | None = None,
) -> requests.Response:
    """Submit one explicit sync-review decision."""
    payload: dict[str, Any] = {
        "bondsnummer": bondsnummer,
        "kind": kind,
        "subject_id": subject_id,
    }
    if sync_state_counter is not None:
        payload["sync_state_counter"] = sync_state_counter
    return post_json(
        backend_url,
        "/admin/resolve_sync_match/",
        payload,
        admin_headers,
    )


def complete_sync(
    backend_url: str,
    admin_headers: dict[str, str],
    sync_state_counter: int,
) -> requests.Response:
    """Apply the pending sync session."""
    return post_json(
        backend_url,
        "/admin/complete_sync/",
        {"sync_state_counter": sync_state_counter},
        admin_headers,
    )


def list_birthdays(command) -> list[dict[str, Any]]:
    """Return the derived birthdays read model."""
    result = command("list_birthdays")
    assert isinstance(result, list)
    return result


def list_outbox_rows(
    command,
    *,
    kind: str | None = None,
    subject_kind: str | None = None,
    subject_id: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """Return internal outbox rows for test assertions."""
    result = command(
        "list_outbox",
        kind=kind,
        subject_kind=subject_kind,
        subject_id=subject_id,
        status=status,
    )
    assert isinstance(result, list)
    return result


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
    """Create a live user through the accepted-registration flow."""
    # Request registration
    post_json(
        backend_url,
        "/auth/request_registration",
        {
            "email": email,
            "firstname": email.split("@", maxsplit=1)[0],
            "lastname": "Testuser",
        },
    )

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
    servers, command, backend_url, auth_client
) -> None:
    """Self-registration creates pending state but does not start Faroe signup."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
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
    servers, command, backend_url, auth_client
) -> None:
    """Accepted registrations only enter Faroe signup through renew_signup."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    post_json(
        backend_url,
        "/auth/request_registration",
        {"email": "renew.me@example.com", "firstname": "Renew", "lastname": "Me"},
    )
    row = get_registration_by_email(backend_url, admin_headers, "renew.me@example.com")
    registration_id = row["registration_id"]

    before_accept = renew_signup(backend_url, registration_id)
    assert before_accept.status_code == 400

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


def test_accept_registration_sends_only_one_invite_when_repeated(
    servers, command, backend_url, auth_client
) -> None:
    """Repeated accept_registration calls do not create a second durable invite."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    email = "accept.once@example.com"

    post_json(
        backend_url,
        "/auth/request_registration",
        {"email": email, "firstname": "Accept", "lastname": "Once"},
    )
    row = get_registration_by_email(backend_url, admin_headers, email)
    registration_id = row["registration_id"]

    first_accept = accept_registration(backend_url, admin_headers, registration_id)
    assert first_accept.status_code == 200
    first_rows = list_outbox_rows(
        command,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id=registration_id,
    )
    assert len(first_rows) == 1
    assert first_rows[0]["payload"]["email"] == email

    second_accept = accept_registration(backend_url, admin_headers, registration_id)
    assert second_accept.status_code == 200
    rows = list_outbox_rows(
        command,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id=registration_id,
    )
    assert len(rows) == 1
    assert rows[0]["payload"]["email"] == email


def test_resend_registration_invite_is_manual_admin_retry_path(
    servers, command, backend_url, auth_client
) -> None:
    """Admins can request a fresh invite without relying on the durable outbox."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    email = "resend.invite@example.com"

    post_json(
        backend_url,
        "/auth/request_registration",
        {"email": email, "firstname": "Resend", "lastname": "Invite"},
    )
    row = get_registration_by_email(backend_url, admin_headers, email)
    registration_id = row["registration_id"]

    accepted = accept_registration(backend_url, admin_headers, registration_id)
    assert accepted.status_code == 200
    before_rows = list_outbox_rows(
        command,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id=registration_id,
    )
    assert len(before_rows) == 1
    before_registration = get_registration_by_email(backend_url, admin_headers, email)

    resent = resend_registration_invite(backend_url, admin_headers, registration_id)
    assert resent.status_code == 200
    after_registration = get_registration_by_email(backend_url, admin_headers, email)
    rows = list_outbox_rows(
        command,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id=registration_id,
    )
    assert len(rows) == 1
    assert after_registration == before_registration


def test_lookup_registration_uses_current_email_and_code(
    servers, command, backend_url, auth_client
) -> None:
    """lookup_registration resolves the stable registration_id from current email."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
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

    code = poll_for_token(
        command, "signup_verification", "lookup.final@example.com", consume=False
    )
    found = post_json(
        backend_url,
        "/auth/lookup_registration",
        {"email": "  Lookup.Final@example.com ", "code": code},
    )
    assert found.status_code == 200
    assert found.json() == {"found": True, "registration_id": registration_id}


def test_sync_status_returns_complete_sync_preview_groups(
    servers, command, backend_url, auth_client
) -> None:
    """Sync preview exposes the pending complete_sync groups from the spec."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
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
        "sync_in_progress",
        "sync_state_counter",
        "can_complete",
        "review_required",
        "registrations_created",
        "registrations_accepted",
        "pending_registrations_updated",
        "live_users_enriched",
        "departed_users",
        "volta_data_changes",
    }
    assert status["sync_in_progress"] is True
    assert status["can_complete"] is False


def test_import_sync_requires_counter_to_overwrite_pending_session(
    servers, command, backend_url, auth_client
) -> None:
    """Overwriting a pending sync import requires the current sync_state_counter."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    first_import = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9111",
                    "Voornaam": "First",
                    "Achternaam": "Snapshot",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "first.snapshot@example.com",
                }
            ]
        ),
    )
    assert first_import.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    overwrite_without_counter = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9112",
                    "Voornaam": "Second",
                    "Achternaam": "Snapshot",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "second.snapshot@example.com",
                }
            ]
        ),
    )
    assert overwrite_without_counter.status_code == 400

    overwrite_with_counter = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9112",
                    "Voornaam": "Second",
                    "Achternaam": "Snapshot",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "second.snapshot@example.com",
                }
            ]
        ),
        status["sync_state_counter"],
    )
    assert overwrite_with_counter.status_code == 200

    replaced = get_sync_status(backend_url, admin_headers)
    assert any(item["bondsnummer"] == 9112 for item in replaced["review_required"])
    assert not any(item["bondsnummer"] == 9111 for item in replaced["review_required"])


def test_sync_review_candidates_use_unlinked_pool_and_reason_order(
    servers, command, backend_url, auth_client
) -> None:
    """Unresolved rows return ordered candidates from the unlinked pool only."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
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


def test_resolve_sync_match_rejects_stale_sync_state_counter(
    servers, command, backend_url, auth_client
) -> None:
    """Each sync decision must use the current sync_state_counter."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    post_json(
        backend_url,
        "/auth/request_registration",
        {
            "email": "stale.counter@example.com",
            "firstname": "Stale",
            "lastname": "Counter",
        },
    )
    registration = get_registration_by_email(
        backend_url, admin_headers, "stale.counter@example.com"
    )

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9113",
                    "Voornaam": "Stale",
                    "Achternaam": "Counter",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "stale.counter@example.com",
                },
                {
                    "Bondsnummer": "9114",
                    "Voornaam": "Needs",
                    "Achternaam": "Decision",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "needs.decision@example.com",
                },
            ]
        ),
    )
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    counter = status["sync_state_counter"]

    first = resolve_sync_match(
        backend_url,
        admin_headers,
        9113,
        "registration",
        registration["registration_id"],
        counter,
    )
    assert first.status_code == 200

    stale = resolve_sync_match(
        backend_url,
        admin_headers,
        9114,
        "none",
        None,
        counter,
    )
    assert stale.status_code == 400

    updated = get_sync_status(backend_url, admin_headers)
    assert not any(item["bondsnummer"] == 9113 for item in updated["review_required"])
    assert any(item["bondsnummer"] == 9114 for item in updated["review_required"])


def test_resolve_sync_match_only_records_pending_registration_decision_until_complete_sync(  # noqa: E501
    servers, command, backend_url, auth_client
) -> None:
    """Resolving a registration match records the decision but does not apply it yet."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
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
    assert before["can_complete"] is False

    resolved = resolve_sync_match(
        backend_url,
        admin_headers,
        9103,
        "registration",
        registration["registration_id"],
        before["sync_state_counter"],
    )
    assert resolved.status_code == 200

    after = get_sync_status(backend_url, admin_headers)
    assert not any(item["bondsnummer"] == 9103 for item in after["review_required"])
    accepted = next(
        row for row in after["registrations_accepted"] if row["bondsnummer"] == 9103
    )
    assert (
        accepted["registration"]["registration_id"] == registration["registration_id"]
    )
    assert accepted["registration"]["accepted"] is False
    assert after["can_complete"] is True

    row = get_registration_by_email(
        backend_url, admin_headers, "resolve.me@example.com"
    )
    assert row["accepted"] is False
    assert row["bondsnummer"] is None
    renewed = renew_signup(backend_url, registration["registration_id"])
    assert renewed.status_code == 400


def test_complete_sync_applies_recorded_registration_match_and_queues_invite(
    servers, command, backend_url, auth_client
) -> None:
    """complete_sync applies a recorded registration match and creates one invite row."""  # noqa: E501
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    email = "resolve.same@example.com"

    post_json(
        backend_url,
        "/auth/request_registration",
        {"email": email, "firstname": "Resolve", "lastname": "Same"},
    )
    registration = get_registration_by_email(backend_url, admin_headers, email)

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "91032",
                    "Voornaam": "Resolve",
                    "Achternaam": "Same",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": email,
                }
            ]
        ),
    )
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    resolved = resolve_sync_match(
        backend_url,
        admin_headers,
        91032,
        "registration",
        registration["registration_id"],
        status["sync_state_counter"],
    )
    assert resolved.status_code == 200

    before_complete = get_registration_by_email(backend_url, admin_headers, email)
    assert before_complete["accepted"] is False
    assert before_complete["bondsnummer"] is None

    status = get_sync_status(backend_url, admin_headers)
    completed = complete_sync(backend_url, admin_headers, status["sync_state_counter"])
    assert completed.status_code == 200
    rows = list_outbox_rows(
        command,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id=registration["registration_id"],
    )
    assert len(rows) == 1
    assert rows[0]["payload"]["email"] == email

    row = get_registration_by_email(backend_url, admin_headers, email)
    assert row["accepted"] is True
    assert row["bondsnummer"] == 91032
    renewed = renew_signup(backend_url, row["registration_id"])
    assert renewed.status_code == 200
    code = poll_for_token(command, "signup_verification", email)
    assert code


def test_complete_sync_registration_match_with_email_change_still_accepts(
    servers, command, backend_url, auth_client
) -> None:
    """A matched registration should still be accepted when sync rewrites its email."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    original_email = "fenna.vanhoorn@example1.com"
    volta_email = "fenna.vanhoorn@example.com"

    post_json(
        backend_url,
        "/auth/request_registration",
        {
            "email": original_email,
            "firstname": "Fenna",
            "lastname": "van Hoorn",
        },
    )
    registration = get_registration_by_email(
        backend_url, admin_headers, original_email
    )

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "91033",
                    "Voornaam": "Fenna",
                    "Tussenvoegsel": "van",
                    "Achternaam": "Hoorn",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": volta_email,
                }
            ]
        ),
    )
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    resolved = resolve_sync_match(
        backend_url,
        admin_headers,
        91033,
        "registration",
        registration["registration_id"],
        status["sync_state_counter"],
    )
    assert resolved.status_code == 200

    preview = get_sync_status(backend_url, admin_headers)
    accepted = next(
        row for row in preview["registrations_accepted"] if row["bondsnummer"] == 91033
    )
    assert (
        accepted["registration"]["registration_id"]
        == registration["registration_id"]
    )
    assert accepted["registration"]["accepted"] is False
    assert accepted["email_will_change"] is True

    completed = complete_sync(
        backend_url, admin_headers, preview["sync_state_counter"]
    )
    assert completed.status_code == 200

    row = get_registration_by_email(backend_url, admin_headers, volta_email)
    assert row["registration_id"] == registration["registration_id"]
    assert row["accepted"] is True
    assert row["bondsnummer"] == 91033
    assert row["signup_active"] is False

    rows = list_outbox_rows(
        command,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id=registration["registration_id"],
    )
    assert len(rows) == 1
    assert rows[0]["payload"]["email"] == volta_email

    renewed = renew_signup(backend_url, row["registration_id"])
    assert renewed.status_code == 200
    code = poll_for_token(command, "signup_verification", volta_email)
    assert code


def test_complete_sync_partial_name_registration_match_still_accepts(
    servers, command, backend_url, auth_client
) -> None:
    """A partial-name registration match should still be accepted on complete_sync."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    original_email = "fenna.hoorn@example1.com"
    volta_email = "fenna.hoorn@example.com"

    post_json(
        backend_url,
        "/auth/request_registration",
        {
            "email": original_email,
            "firstname": "Fenna",
            "lastname": "Hoorn",
        },
    )
    registration = get_registration_by_email(
        backend_url, admin_headers, original_email
    )

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "91034",
                    "Voornaam": "Fenneke",
                    "Achternaam": "Hoorn",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": volta_email,
                }
            ]
        ),
    )
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    review_item = next(
        item for item in status["review_required"] if item["bondsnummer"] == 91034
    )
    candidate = next(
        row
        for row in review_item["candidates"]
        if row["subject_id"] == registration["registration_id"]
    )
    assert candidate["reasons"] == ["name_partial"]

    resolved = resolve_sync_match(
        backend_url,
        admin_headers,
        91034,
        "registration",
        registration["registration_id"],
        status["sync_state_counter"],
    )
    assert resolved.status_code == 200

    preview = get_sync_status(backend_url, admin_headers)
    accepted = next(
        row for row in preview["registrations_accepted"] if row["bondsnummer"] == 91034
    )
    assert (
        accepted["registration"]["registration_id"]
        == registration["registration_id"]
    )
    assert accepted["email_will_change"] is True

    completed = complete_sync(
        backend_url, admin_headers, preview["sync_state_counter"]
    )
    assert completed.status_code == 200

    row = get_registration_by_email(backend_url, admin_headers, volta_email)
    assert row["registration_id"] == registration["registration_id"]
    assert row["accepted"] is True
    assert row["bondsnummer"] == 91034

    renewed = renew_signup(backend_url, row["registration_id"])
    assert renewed.status_code == 200
    code = poll_for_token(command, "signup_verification", volta_email)
    assert code


def test_complete_sync_creates_registration_for_recorded_no_match_and_invite(
    servers, command, backend_url, auth_client
) -> None:
    """A no-match decision becomes one accepted registration with one invite row."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    email = "resolve.none@example.com"

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "91031",
                    "Voornaam": "Resolve",
                    "Achternaam": "None",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": email,
                }
            ]
        ),
    )
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    resolved = resolve_sync_match(
        backend_url,
        admin_headers,
        91031,
        "none",
        None,
        status["sync_state_counter"],
    )
    assert resolved.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    created = next(
        row for row in status["registrations_created"] if row["bondsnummer"] == 91031
    )
    assert created["email"] == email
    assert not any(item["bondsnummer"] == 91031 for item in status["review_required"])
    assert all(
        row["email"] != email for row in list_registrations(backend_url, admin_headers)
    )

    completed = complete_sync(backend_url, admin_headers, status["sync_state_counter"])
    assert completed.status_code == 200
    row = get_registration_by_email(backend_url, admin_headers, email)
    rows = list_outbox_rows(
        command,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id=row["registration_id"],
    )
    assert len(rows) == 1
    assert rows[0]["payload"]["email"] == email
    assert row["accepted"] is True
    assert row["bondsnummer"] == 91031
    renewed = renew_signup(backend_url, row["registration_id"])
    assert renewed.status_code == 200
    code = poll_for_token(command, "signup_verification", email)
    assert code


def test_complete_sync_rewrites_linked_pending_registration_email_and_queues_invite(
    servers, command, backend_url, auth_client
) -> None:
    """complete_sync rewrites linked pending registrations to the Volta email."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
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

    linked = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {
            "kind": "registration",
            "subject_id": registration["registration_id"],
            "bondsnummer": 9104,
        },
        admin_headers,
    )
    assert linked.status_code == 200

    imported = import_sync_csv(
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
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    pending = next(
        row
        for row in status["pending_registrations_updated"]
        if row["bondsnummer"] == 9104
    )
    assert pending["registration"]["registration_id"] == registration["registration_id"]
    assert pending["email_will_change"] is True

    completed = complete_sync(backend_url, admin_headers, status["sync_state_counter"])
    assert completed.status_code == 200
    rows = list_outbox_rows(
        command,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id=registration["registration_id"],
    )
    assert len(rows) == 1
    assert rows[0]["payload"]["email"] == "pending.new@example.com"

    moved = get_registration_by_email(
        backend_url,
        admin_headers,
        "pending.new@example.com",
    )
    assert moved["registration_id"] == registration["registration_id"]
    assert moved["signup_active"] is False
    renewed = renew_signup(backend_url, moved["registration_id"])
    assert renewed.status_code == 200
    code = poll_for_token(command, "signup_verification", "pending.new@example.com")
    assert code


def test_complete_sync_keeps_linked_live_user_account_email_when_volta_email_changes(
    servers, command, backend_url, auth_client
) -> None:
    """complete_sync never rewrites the verified account email of a linked live user."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
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

    status = get_sync_status(backend_url, admin_headers)
    completed = complete_sync(backend_url, admin_headers, status["sync_state_counter"])
    assert completed.status_code == 200

    still_live = get_user_by_email(
        backend_url, admin_headers, "live.account@example.com"
    )
    assert still_live["user_id"] == user["user_id"]


def test_link_bondsnummer_rejects_subject_already_linked_to_different_bondsnummer(
    servers, command, backend_url, auth_client
) -> None:
    """A subject cannot be relinked to a second different bondsnummer."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    post_json(
        backend_url,
        "/auth/request_registration",
        {"email": "reg.relink@example.com", "firstname": "Reg", "lastname": "Relink"},
    )
    registration = get_registration_by_email(
        backend_url, admin_headers, "reg.relink@example.com"
    )

    first_reg_link = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {
            "kind": "registration",
            "subject_id": registration["registration_id"],
            "bondsnummer": 91061,
        },
        admin_headers,
    )
    assert first_reg_link.status_code == 200

    second_reg_link = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {
            "kind": "registration",
            "subject_id": registration["registration_id"],
            "bondsnummer": 91062,
        },
        admin_headers,
    )
    assert second_reg_link.status_code == 400

    complete_signup_from_registration(
        command,
        auth_client,
        backend_url,
        admin_headers,
        "user.relink@example.com",
    )
    user = get_user_by_email(backend_url, admin_headers, "user.relink@example.com")

    first_user_link = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {"kind": "user", "subject_id": user["user_id"], "bondsnummer": 91063},
        admin_headers,
    )
    assert first_user_link.status_code == 200

    second_user_link = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {"kind": "user", "subject_id": user["user_id"], "bondsnummer": 91064},
        admin_headers,
    )
    assert second_user_link.status_code == 400


def test_resolve_sync_match_rejects_user_already_linked_to_different_bondsnummer(
    servers, command, backend_url, auth_client
) -> None:
    """resolve_sync_match rejects a live user already linked elsewhere."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    complete_signup_from_registration(
        command,
        auth_client,
        backend_url,
        admin_headers,
        "resolve.user@example.com",
    )
    user = get_user_by_email(backend_url, admin_headers, "resolve.user@example.com")

    linked = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {"kind": "user", "subject_id": user["user_id"], "bondsnummer": 91065},
        admin_headers,
    )
    assert linked.status_code == 200

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "91066",
                    "Voornaam": "Resolve",
                    "Achternaam": "User",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "resolve.user.volta@example.com",
                }
            ]
        ),
    )
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    assert any(item["bondsnummer"] == 91066 for item in status["review_required"])

    resolved = resolve_sync_match(
        backend_url,
        admin_headers,
        91066,
        "user",
        user["user_id"],
        status["sync_state_counter"],
    )
    assert resolved.status_code == 400


def test_birthdays_projection_is_rebuilt_during_complete_sync(
    servers, command, backend_url, auth_client
) -> None:
    """Birthdays are rebuilt from applied Volta data during complete_sync."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    complete_signup_from_registration(
        command,
        auth_client,
        backend_url,
        admin_headers,
        "birthday.user@example.com",
    )
    user = get_user_by_email(backend_url, admin_headers, "birthday.user@example.com")

    linked = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {"kind": "user", "subject_id": user["user_id"], "bondsnummer": 91067},
        admin_headers,
    )
    assert linked.status_code == 200

    import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "91067",
                    "Voornaam": "Birthday",
                    "Tussenvoegsel": "van",
                    "Achternaam": "User",
                    "Geslacht": "V",
                    "Geboortedatum": "02/03/2000",
                    "Email": "birthday.user@example.com",
                },
                {
                    "Bondsnummer": "91068",
                    "Voornaam": "Unlinked",
                    "Achternaam": "Person",
                    "Geslacht": "V",
                    "Geboortedatum": "04/05/2001",
                    "Email": "unlinked.person@example.com",
                },
            ]
        ),
    )

    # Resolve unlinked row before completing
    status = get_sync_status(backend_url, admin_headers)
    resolved = resolve_sync_match(
        backend_url,
        admin_headers,
        91068,
        "none",
        None,
        status["sync_state_counter"],
    )
    assert resolved.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    completed = complete_sync(backend_url, admin_headers, status["sync_state_counter"])
    assert completed.status_code == 200

    birthdays = list_birthdays(command)
    rows = [row for row in birthdays if row["user_id"] == user["user_id"]]
    assert len(rows) == 1
    assert rows[0]["geboortedatum"] == "02/03/2000"
    assert rows[0]["voornaam"] == "Birthday"
    assert rows[0]["tussenvoegsel"] == "van"
    assert rows[0]["achternaam"] == "User"

    import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "91067",
                    "Voornaam": "Birthday",
                    "Tussenvoegsel": "",
                    "Achternaam": "Updated",
                    "Geslacht": "V",
                    "Geboortedatum": "06/07/2000",
                    "Email": "birthday.user@example.com",
                }
            ]
        ),
    )

    status = get_sync_status(backend_url, admin_headers)
    completed_again = complete_sync(
        backend_url, admin_headers, status["sync_state_counter"]
    )
    assert completed_again.status_code == 200

    birthdays = list_birthdays(command)
    rows = [row for row in birthdays if row["user_id"] == user["user_id"]]
    assert len(rows) == 1
    assert rows[0]["geboortedatum"] == "06/07/2000"
    assert rows[0]["tussenvoegsel"] == ""
    assert rows[0]["achternaam"] == "Updated"


def test_signup_from_already_linked_registration_populates_birthdays_from_applied_volta_data(  # noqa: E501
    servers, command, backend_url, auth_client
) -> None:
    """Signup after an applied linked registration should populate birthdays."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    post_json(
        backend_url,
        "/auth/request_registration",
        {
            "email": "birthday.pending@example.com",
            "firstname": "Birthday",
            "lastname": "Pending",
        },
    )
    registration = get_registration_by_email(
        backend_url, admin_headers, "birthday.pending@example.com"
    )
    linked = post_json(
        backend_url,
        "/admin/link_bondsnummer/",
        {
            "kind": "registration",
            "subject_id": registration["registration_id"],
            "bondsnummer": 91069,
        },
        admin_headers,
    )
    assert linked.status_code == 200

    imported = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "91069",
                    "Voornaam": "Birthday",
                    "Achternaam": "Pending",
                    "Geslacht": "V",
                    "Geboortedatum": "08/09/2000",
                    "Email": "birthday.pending@example.com",
                }
            ]
        ),
    )
    assert imported.status_code == 200

    status = get_sync_status(backend_url, admin_headers)
    completed = complete_sync(backend_url, admin_headers, status["sync_state_counter"])
    assert completed.status_code == 200

    renewed = renew_signup(backend_url, registration["registration_id"])
    assert renewed.status_code == 200
    signup_token = renewed.json()["signup_token"]
    code = poll_for_token(
        command, "signup_verification", "birthday.pending@example.com"
    )
    verify = auth_client.verify_signup_email_address_verification_code(
        signup_token, code
    )
    assert verify.ok is True
    pwd = auth_client.set_signup_password(signup_token, TEST_PASSWORD)
    assert pwd.ok is True
    complete = auth_client.complete_signup(signup_token)
    assert isinstance(complete, CompleteSignupActionSuccessResult)

    user = get_user_by_email(backend_url, admin_headers, "birthday.pending@example.com")
    birthdays = list_birthdays(command)
    rows = [row for row in birthdays if row["user_id"] == user["user_id"]]
    assert len(rows) == 1
    assert rows[0]["geboortedatum"] == "08/09/2000"


def test_complete_sync_removes_only_linked_live_users_departed_from_snapshot(
    servers, command, backend_url, auth_client
) -> None:
    """complete_sync removes departed linked live users but leaves unlinked users."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
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
    status = get_sync_status(backend_url, admin_headers)
    completed = complete_sync(backend_url, admin_headers, status["sync_state_counter"])
    assert completed.status_code == 200

    users = list_users(backend_url, admin_headers)
    emails = {user["email"] for user in users}
    assert "linked.departed@example.com" not in emails
    assert "unlinked.stays@example.com" in emails


def test_import_sync_rejects_duplicate_bondsnummer_and_duplicate_email(
    servers, command, backend_url, auth_client
) -> None:
    """Import validation rejects duplicate bondsnummers and duplicate emails."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
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


def test_import_sync_rejects_blank_email_and_malformed_bondsnummer(
    servers, command, backend_url, auth_client
) -> None:
    """Import validation rejects blank emails and malformed bondsnummers."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    servers.reset_all()
    admin_headers = get_admin_cookie_headers(command, auth_client)

    blank_email = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "9110",
                    "Voornaam": "Blank",
                    "Achternaam": "Email",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "   ",
                }
            ]
        ),
    )
    assert blank_email.status_code == 400

    malformed_bondsnummer = import_sync_csv(
        backend_url,
        admin_headers,
        make_au_csv(
            [
                {
                    "Bondsnummer": "not-a-number",
                    "Voornaam": "Bad",
                    "Achternaam": "Bondsnummer",
                    "Geslacht": "V",
                    "Geboortedatum": "01/01/2000",
                    "Email": "bad.bondsnummer@example.com",
                }
            ]
        ),
    )
    assert malformed_bondsnummer.status_code == 400
