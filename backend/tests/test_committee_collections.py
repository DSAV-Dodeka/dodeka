"""Integration tests for committee collections, using the fotoboek ("fotos").

FOCUS members (and admins) edit cards one at a time; every member reads them.
Admins configure nothing: granting the focus tag is enough.
"""

from dataclasses import dataclass

import pytest
from test_spec import (
    ADMIN_COOKIE_HEADERS_BY_CREDS,
    complete_signup_from_registration,
    get_admin_cookie_headers,
    get_user_by_email,
    post_json,
)

from apiserver.data.features.fotos import validate_foto_card


@dataclass
class Members:
    admin: dict[str, str]
    focus: dict[str, str]
    plain: dict[str, str]


@pytest.fixture(scope="module")
def members(command, backend_url, auth_client) -> Members:
    """Admin headers plus one member with ``focus`` and one without."""
    ADMIN_COOKIE_HEADERS_BY_CREDS.clear()
    admin = get_admin_cookie_headers(command, auth_client)

    _, focus_token = complete_signup_from_registration(
        command, auth_client, backend_url, admin, "focus.lid@example.com"
    )
    _, plain_token = complete_signup_from_registration(
        command, auth_client, backend_url, admin, "gewoon.lid@example.com"
    )
    focus_user = get_user_by_email(backend_url, admin, "focus.lid@example.com")
    added = post_json(
        backend_url,
        "/admin/add_permission/",
        {"user_id": focus_user["user_id"], "permission": "focus"},
        admin,
    )
    assert added.status_code == 200

    return Members(
        admin=admin,
        focus={"Cookie": f"session_token={focus_token}"},
        plain={"Cookie": f"session_token={plain_token}"},
    )


def card(**overrides) -> dict:
    base = {
        "name": "NSK Baan",
        "date": "2026-06-14",
        "type": "Wedstrijd",
        "links": [{"label": "dump", "url": "https://example.com/dump"}],
    }
    return {**base, **overrides}


def list_fotos(backend_url: str, headers: dict[str, str]):
    return post_json(
        backend_url, "/members/collections/list/", {"collection": "fotos"}, headers
    )


def save_foto(backend_url: str, headers: dict[str, str], item: dict):
    return post_json(
        backend_url,
        "/members/collections/save/",
        {"collection": "fotos", "item": item},
        headers,
    )


def delete_foto(backend_url: str, headers: dict[str, str], item_id: str):
    return post_json(
        backend_url,
        "/members/collections/delete/",
        {"collection": "fotos", "id": item_id},
        headers,
    )


def test_validate_foto_card() -> None:
    assert validate_foto_card(card()) == []
    assert validate_foto_card(card(image="data:image/jpeg;base64,AAAA")) == []
    assert validate_foto_card(card(seizoen="25/26")) == []

    assert validate_foto_card(card(name=" "))
    assert validate_foto_card(card(date="14-06-2026"))
    assert validate_foto_card(card(type="Feest"))
    assert validate_foto_card(card(seizoen="2025"))
    assert validate_foto_card(card(image="javascript:alert(1)"))
    assert validate_foto_card(card(links=[{"label": "x", "url": "ftp://x"}]))
    assert validate_foto_card(card(extra="field"))


def test_focus_member_manages_cards_one_at_a_time(backend_url, members) -> None:
    assert list_fotos(backend_url, members.plain).json() == {"items": []}

    # Create two cards: one with a client id, one with a server-generated id
    first = save_foto(backend_url, members.focus, card(id="nsk-baan"))
    assert first.status_code == 200, first.text
    assert first.json()["item"]["id"] == "nsk-baan"
    second = save_foto(backend_url, members.focus, card(name="Borrel", type="Overig"))
    assert second.status_code == 200, second.text
    second_id = second.json()["item"]["id"]

    created_at = first.json()["item"]["created_at"]
    assert isinstance(created_at, int)

    # Editing one card leaves the other untouched; created_at is kept and a
    # client-sent created_at is ignored
    edited = save_foto(
        backend_url, members.focus, card(id="nsk-baan", name="NSK", created_at=1)
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["item"]["created_at"] == created_at
    items = {i["id"]: i for i in list_fotos(backend_url, members.plain).json()["items"]}
    assert items["nsk-baan"]["name"] == "NSK"
    assert items[second_id]["name"] == "Borrel"

    # Deleting one card leaves the other
    assert delete_foto(backend_url, members.focus, second_id).status_code == 200
    items = list_fotos(backend_url, members.plain).json()["items"]
    assert [i["id"] for i in items] == ["nsk-baan"]
    assert delete_foto(backend_url, members.focus, second_id).status_code == 404


def test_admin_can_edit_without_focus_tag(backend_url, members) -> None:
    saved = save_foto(backend_url, members.admin, card(id="admin-card"))
    assert saved.status_code == 200, saved.text
    assert delete_foto(backend_url, members.admin, "admin-card").status_code == 200


def test_only_focus_or_admin_may_write(backend_url, members) -> None:
    assert save_foto(backend_url, members.plain, card()).status_code == 403
    assert save_foto(backend_url, {}, card()).status_code == 403
    assert delete_foto(backend_url, members.plain, "nsk-baan").status_code == 403
    # Not logged in: can't read either
    assert list_fotos(backend_url, {}).status_code == 403


def test_focus_tag_unlocks_nothing_outside_its_collection(backend_url, members) -> None:
    """A committee tag only writes its own collection, nothing else."""
    attempts = [
        ("/admin/private_kv/set/", {"key": "hordes_join", "value": {}}),
        ("/admin/add_permission/", {"user_id": "x", "permission": "focus"}),
        ("/admin/delete_user/", {"user_id": "x"}),
    ]
    for path, payload in attempts:
        response = post_json(backend_url, path, payload, members.focus)
        assert response.status_code in (401, 403), (path, response.status_code)


def test_invalid_requests_are_rejected(backend_url, members) -> None:
    assert save_foto(backend_url, members.focus, card(date="nope")).status_code == 400
    assert save_foto(backend_url, members.focus, card(id="bad id!")).status_code == 400
    too_big = card(image="data:image/jpeg;base64," + "A" * 1_100_000)
    assert save_foto(backend_url, members.focus, too_big).status_code == 413

    unknown = post_json(
        backend_url,
        "/members/collections/list/",
        {"collection": "nope"},
        members.focus,
    )
    assert unknown.status_code == 404
