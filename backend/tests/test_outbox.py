"""Unit tests for the durable outbox state machine.

These tests open a freetser Storage directly against a temp path. They do
not start the backend, do not touch SMTP, and do not monkeypatch anything.
A "process restart" is simulated by closing the Storage and reopening it.
"""

import time
from pathlib import Path

import pytest
from freetser import Storage

from apiserver.data.outbox import (
    OUTBOX_TABLE,
    RETRY_DELAYS,
    RETRY_WINDOW,
    OutboxRow,
    create_outbox_row,
    deserialize_outbox,
    get_outbox_row,
    list_pending_outbox,
    mark_attempt_failed,
    mark_attempt_succeeded,
    serialize_outbox,
)


# Override the module-scope autouse fixture from conftest.py so this file
# does not spin up the backend + auth server.
@pytest.fixture(autouse=True, scope="module")
def clean_state() -> None:
    return None


@pytest.fixture
def store(tmp_path: Path):
    db = tmp_path / "outbox.sqlite"
    s = Storage(str(db), tables=[OUTBOX_TABLE])
    yield s
    s.close()


def reopen(store: Storage, tmp_path: Path) -> Storage:
    """Close and reopen the Storage at the same path — simulates a restart."""
    store.close()
    return Storage(str(tmp_path / "outbox.sqlite"), tables=[OUTBOX_TABLE])


def make_payload(email: str = "x@example.com") -> dict:
    return {
        "registration_id": "reg-1",
        "email": email,
        "display_name": "X",
    }


def test_create_persists_and_roundtrips(store: Storage) -> None:
    row = create_outbox_row(
        store,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id="reg-1",
        payload=make_payload(),
    )
    fetched = get_outbox_row(store, row.outbox_id)
    assert fetched is not None
    assert fetched.status == "pending"
    assert fetched.attempt_count == 0
    assert fetched.next_attempt_at == fetched.created_at
    assert fetched.payload == make_payload()


def test_pending_listed_only_when_due(store: Storage) -> None:
    row = create_outbox_row(
        store, "send_registration_invite", "registration", "reg-1", make_payload()
    )
    now = row.created_at
    assert [r.outbox_id for r in list_pending_outbox(store, now)] == [row.outbox_id]
    # Not due yet
    assert list_pending_outbox(store, now - 1) == []


def test_successful_delivery_deletes_row(store: Storage) -> None:
    row = create_outbox_row(
        store, "send_registration_invite", "registration", "reg-1", make_payload()
    )
    mark_attempt_succeeded(store, row)
    # Row is gone — no unbounded growth from succeeded deliveries.
    assert get_outbox_row(store, row.outbox_id) is None
    assert list_pending_outbox(store, int(time.time()) + 1) == []


def test_failure_schedules_retry_and_keeps_row(store: Storage) -> None:
    row = create_outbox_row(
        store, "send_registration_invite", "registration", "reg-1", make_payload()
    )
    before_count = row.attempt_count
    abandoned = mark_attempt_failed(store, row, "smtp down")
    assert abandoned is False

    fetched = get_outbox_row(store, row.outbox_id)
    assert fetched is not None
    assert fetched.status == "pending"
    assert fetched.attempt_count == before_count + 1
    assert fetched.last_error == "smtp down"
    # First failure → next attempt ~RETRY_DELAYS[1] from now.
    now = int(time.time())
    assert (
        now + RETRY_DELAYS[1] - 2
        <= fetched.next_attempt_at
        <= now + RETRY_DELAYS[1] + 2
    )


def test_window_exhaustion_deletes_row(store: Storage, tmp_path: Path) -> None:
    """An old pending row that fails again is deleted, not stranded."""
    # Forge an old row by writing it directly with a created_at past the window.
    now = int(time.time())
    old = OutboxRow(
        outbox_id="forged-old",
        kind="send_registration_invite",
        status="pending",
        subject_kind="registration",
        subject_id="reg-1",
        payload=make_payload(),
        created_at=now - RETRY_WINDOW - 600,
        last_attempt_at=None,
        next_attempt_at=now - 60,
        attempt_count=0,
        last_error=None,
    )
    store.add(OUTBOX_TABLE, old.outbox_id, serialize_outbox(old), expires_at=0)

    abandoned = mark_attempt_failed(store, old, "smtp still down")
    assert abandoned is True
    assert get_outbox_row(store, old.outbox_id) is None
    # And nothing left for the dispatcher to pick up.
    assert list_pending_outbox(store, int(time.time())) == []


def test_old_pending_row_still_dispatched_not_silently_stranded(
    store: Storage,
) -> None:
    """A pending row older than the retry window must still be listed so the
    dispatcher can attempt-and-delete it (instead of leaving it stuck)."""
    now = int(time.time())
    old = OutboxRow(
        outbox_id="forged-stale",
        kind="send_registration_invite",
        status="pending",
        subject_kind="registration",
        subject_id="reg-1",
        payload=make_payload(),
        created_at=now - RETRY_WINDOW - 3600,
        last_attempt_at=None,
        next_attempt_at=now - 1,
        attempt_count=0,
        last_error=None,
    )
    store.add(OUTBOX_TABLE, old.outbox_id, serialize_outbox(old), expires_at=0)
    listed = list_pending_outbox(store, now)
    assert [r.outbox_id for r in listed] == ["forged-stale"]


def test_pending_survives_simulated_restart(store: Storage, tmp_path: Path) -> None:
    """Closing and reopening Storage at the same path preserves pending rows
    — this is what happens across a backend process restart."""
    row = create_outbox_row(
        store, "send_registration_invite", "registration", "reg-1", make_payload()
    )
    outbox_id = row.outbox_id

    reopened = reopen(store, tmp_path)
    try:
        fetched = get_outbox_row(reopened, outbox_id)
        assert fetched is not None
        assert fetched.status == "pending"
        # Dispatcher on boot would see it.
        listed = list_pending_outbox(reopened, fetched.next_attempt_at)
        assert [r.outbox_id for r in listed] == [outbox_id]
    finally:
        reopened.close()


def test_serialization_roundtrip_preserves_all_fields(store: Storage) -> None:
    row = create_outbox_row(
        store, "send_registration_invite", "registration", "reg-1", make_payload()
    )
    raw = store.get(OUTBOX_TABLE, row.outbox_id)
    assert raw is not None
    revived = deserialize_outbox(raw[0])
    assert revived == row
