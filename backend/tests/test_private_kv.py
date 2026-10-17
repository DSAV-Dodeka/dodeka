"""Regression test: saving an existing private key must replace it."""

from test_spec import (
    ADMIN_COOKIE_HEADERS_BY_CREDS,
    get_admin_cookie_headers,
    post_json,
)


def test_admin_can_save_an_existing_private_key_again(
    command, backend_url, auth_client
) -> None:
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    admin = get_admin_cookie_headers(command, auth_client)

    first = post_json(
        backend_url,
        "/admin/private_kv/set/",
        {"key": "hordes_join", "value": {"Koers": "a"}, "role": "member"},
        admin,
    )
    assert first.status_code == 200, first.text

    # Used to fail with a 500 (EntryAlreadyExists from store.add)
    second = post_json(
        backend_url,
        "/admin/private_kv/set/",
        {"key": "hordes_join", "value": {"Koers": "b"}},
        admin,
    )
    assert second.status_code == 200, second.text
    assert second.json()["required_role"] == "member"

    read = post_json(backend_url, "/members/private/", {"key": "hordes_join"}, admin)
    assert read.json() == {"value": {"Koers": "b"}}
