"""Outbox dispatcher and registration invite sending.

The outbox dispatcher runs automatically on startup and periodically.
It processes durable outbox rows for send_registration_invite.
"""

import logging
import smtplib
import threading
import time

from freetser.server import StorageQueue

from apiserver.data.outbox import (
    get_outbox_row,
    list_pending_outbox,
    mark_attempt_failed,
    mark_attempt_succeeded,
)
from apiserver.email import EmailData, sendemail
from apiserver.settings import SmtpConfig

logger = logging.getLogger("apiserver.handlers.acceptance")


def send_registration_invite(
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    registration_id: str,
    email: str,
    display_name: str,
) -> bool:
    """Send a registration invite email directly (not outbox-backed)."""
    try:
        link = f"{frontend_origin}/account/signup?registration_id={registration_id}"
        data = EmailData(
            email_type="sync_please_register",
            to_email=email,
            display_name=display_name,
            link=link,
        )
        sendemail(smtp_config, data, smtp_send)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        logger.error(f"Failed to send invite to {email}: {exc}")
        return False


def attempt_outbox_row(
    store_queue: StorageQueue,
    outbox_id: str,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> None:
    """Attempt delivery for one outbox row."""
    row = store_queue.execute(lambda store: get_outbox_row(store, outbox_id))
    if row is None:
        return

    if row.kind != "send_registration_invite":
        logger.warning(f"Unknown outbox kind: {row.kind}")
        return

    payload = row.payload
    reg_id = payload.get("registration_id", "")
    email = payload.get("email", "")
    display_name = payload.get("display_name", "")

    success = send_registration_invite(
        frontend_origin=frontend_origin,
        smtp_config=smtp_config,
        smtp_send=smtp_send,
        registration_id=reg_id,
        email=email,
        display_name=display_name,
    )

    if success:
        store_queue.execute(lambda store: mark_attempt_succeeded(store, row))
        return

    abandoned = store_queue.execute(
        lambda store: mark_attempt_failed(store, row, "send failed")
    )
    if abandoned:
        logger.error(
            "OUTBOX ABANDONED: action lost after %s attempts over %ss. "
            "outbox_id=%s kind=%s subject=%s/%s payload=%s",
            row.attempt_count + 1,
            int(time.time()) - row.created_at,
            row.outbox_id,
            row.kind,
            row.subject_kind,
            row.subject_id,
            row.payload,
        )


def dispatch_pending_outbox(
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
) -> int:
    """Process all pending outbox rows eligible for dispatch."""
    now = int(time.time())
    rows = store_queue.execute(lambda store: list_pending_outbox(store, now))
    for row in rows:
        attempt_outbox_row(
            store_queue,
            row.outbox_id,
            frontend_origin,
            smtp_config,
            smtp_send,
        )
    return len(rows)


def start_outbox_dispatcher(
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    ready_event: threading.Event | None = None,
) -> None:
    """Start the automatic outbox dispatcher thread."""

    def run() -> None:
        if ready_event is not None:
            ready_event.wait()
        # Initial dispatch on startup
        try:
            dispatch_pending_outbox(
                store_queue, frontend_origin, smtp_config, smtp_send
            )
        except Exception as exc:
            logger.error(f"Outbox startup dispatch failed: {exc}")

        while True:
            time.sleep(60)
            try:
                dispatch_pending_outbox(
                    store_queue, frontend_origin, smtp_config, smtp_send
                )
            except Exception as exc:
                logger.error(f"Outbox dispatch failed: {exc}")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
