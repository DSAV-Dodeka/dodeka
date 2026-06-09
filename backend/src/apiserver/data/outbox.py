"""Durable outbox for backend side effects.

Outbox rows are created atomically with canonical state mutations inside
one freetser storage callback. Delivery happens after commit with
at-least-once semantics.

Retry schedule (after each failed attempt):
  attempt 1: immediately (next_attempt_at = created_at)
  attempt 2: 1 minute later
  attempt 3: 5 minutes later
  attempt 4: 30 minutes later
  attempt 5+: every 2 hours
  past 72 hours from created_at: row is deleted and the action is logged
  loudly as lost. Sized so a Friday-afternoon SMTP outage plus a Monday-
  morning restart still falls inside the retry window.
"""

import json
import secrets
import time
from dataclasses import dataclass

from freetser import Storage

OUTBOX_TABLE = "outbox"

# Retry delays in seconds after each failed attempt
RETRY_DELAYS = [60, 300, 1800]
RETRY_DEFAULT = 7200
RETRY_WINDOW = 72 * 3600


def generate_outbox_id() -> str:
    return secrets.token_urlsafe(16)


@dataclass
class OutboxRow:
    outbox_id: str
    kind: str
    status: str
    subject_kind: str
    subject_id: str
    payload: dict
    created_at: int
    last_attempt_at: int | None
    next_attempt_at: int
    attempt_count: int
    last_error: str | None


def serialize_outbox(row: OutboxRow) -> bytes:
    return json.dumps(
        {
            "outbox_id": row.outbox_id,
            "kind": row.kind,
            "status": row.status,
            "subject_kind": row.subject_kind,
            "subject_id": row.subject_id,
            "payload": row.payload,
            "created_at": row.created_at,
            "last_attempt_at": row.last_attempt_at,
            "next_attempt_at": row.next_attempt_at,
            "attempt_count": row.attempt_count,
            "last_error": row.last_error,
        }
    ).encode("utf-8")


def deserialize_outbox(data: bytes) -> OutboxRow:
    d = json.loads(data.decode("utf-8"))
    return OutboxRow(
        outbox_id=d["outbox_id"],
        kind=d["kind"],
        status=d["status"],
        subject_kind=d["subject_kind"],
        subject_id=d["subject_id"],
        payload=d.get("payload", {}),
        created_at=d["created_at"],
        last_attempt_at=d.get("last_attempt_at"),
        next_attempt_at=d["next_attempt_at"],
        attempt_count=d["attempt_count"],
        last_error=d.get("last_error"),
    )


def create_outbox_row(
    store: Storage,
    kind: str,
    subject_kind: str,
    subject_id: str,
    payload: dict,
    now: int | None = None,
) -> OutboxRow:
    """Create a new pending outbox row."""
    if now is None:
        now = int(time.time())
    row = OutboxRow(
        outbox_id=generate_outbox_id(),
        kind=kind,
        status="pending",
        subject_kind=subject_kind,
        subject_id=subject_id,
        payload=payload,
        created_at=now,
        last_attempt_at=None,
        next_attempt_at=now,
        attempt_count=0,
        last_error=None,
    )
    store.add(OUTBOX_TABLE, row.outbox_id, serialize_outbox(row), expires_at=0)
    return row


def get_outbox_row(store: Storage, outbox_id: str) -> OutboxRow | None:
    result = store.get(OUTBOX_TABLE, outbox_id)
    if result is None:
        return None
    return deserialize_outbox(result[0])


def save_outbox_row(store: Storage, row: OutboxRow) -> None:
    store.overwrite(OUTBOX_TABLE, row.outbox_id, serialize_outbox(row), expires_at=0)


def compute_next_attempt(attempt_count: int) -> int:
    """Compute next_attempt_at after a failure."""
    if attempt_count < len(RETRY_DELAYS):
        delay = RETRY_DELAYS[attempt_count]
    else:
        delay = RETRY_DEFAULT
    return int(time.time()) + delay


def mark_attempt_failed(store: Storage, row: OutboxRow, error: str) -> bool:
    """Record a failed delivery attempt.

    Returns True if the row was abandoned (deleted) because the retry window
    is exhausted; the caller is expected to log the lost action loudly.
    """
    now = int(time.time())
    row.last_attempt_at = now
    row.attempt_count += 1
    row.last_error = error

    next_at = compute_next_attempt(row.attempt_count)
    if next_at >= row.created_at + RETRY_WINDOW:
        store.delete(OUTBOX_TABLE, row.outbox_id)
        return True

    row.next_attempt_at = next_at
    save_outbox_row(store, row)
    return False


def mark_attempt_succeeded(store: Storage, row: OutboxRow) -> None:
    """Delete the row: the side effect was delivered, nothing more to do."""
    store.delete(OUTBOX_TABLE, row.outbox_id)


def list_pending_outbox(store: Storage, now: int) -> list[OutboxRow]:
    """List outbox rows eligible for automatic dispatch.

    Rows older than the retry window are still returned: the next attempt
    will fail-and-delete in mark_attempt_failed, which is where the loud
    log happens. We never silently strand a pending row.
    """
    rows = []
    for key in store.list_keys(OUTBOX_TABLE):
        result = store.get(OUTBOX_TABLE, key)
        if result is None:
            continue
        row = deserialize_outbox(result[0])
        if row.status == "pending" and row.next_attempt_at <= now:
            rows.append(row)
    return rows
