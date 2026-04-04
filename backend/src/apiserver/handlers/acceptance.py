"""Shared acceptance logic used by both admin handlers and command handlers.

This module owns the accept-new-with-email flow that sends notification
emails after accepting users through sync. It depends on core data modules
and sync, but NOT on tooling or handlers.
"""

import logging
import smtplib
from dataclasses import dataclass

from freetser import Storage
from freetser.server import StorageQueue

from apiserver.data.registrations import (
    get_registration,
    list_registrations,
    upsert_registration,
)
from apiserver.email import EmailData, sendemail
from apiserver.settings import SmtpConfig
from apiserver.sync import accept_new

logger = logging.getLogger("apiserver.handlers.acceptance")


@dataclass
class AcceptNewResult:
    added: int
    skipped: int
    emails_sent: int
    emails_failed: int


@dataclass
class SignupTarget:
    email: str
    display_name: str
    registration_token: str | None


@dataclass
class AcceptedTarget:
    email: str
    display_name: str


def do_accept_new_with_email(
    store_queue: StorageQueue,
    frontend_origin: str,
    smtp_config: SmtpConfig | None,
    smtp_send: bool,
    email: str | None = None,
) -> AcceptNewResult:
    """Accept new users and send notification emails.

    Sends sync_please_register to users who still need to create an account,
    and account_accepted_self to users who already have one.
    """

    def accept_and_prepare(
        store: Storage,
    ) -> tuple[
        dict[str, int],
        list[SignupTarget],
        list[AcceptedTarget],
    ]:
        registered = set(store.list_keys("users_by_email"))

        # Snapshot registrations with accounts that are pending approval
        # (accept_new will delete these registrations, so capture now)
        pending_with_account: dict[str, str] = {}
        for reg in list_registrations(store):
            if not reg.accepted and reg.account_created and reg.email in registered:
                pending_with_account[reg.email] = reg.firstname

        result = accept_new(store, email)

        # Find accepted users without accounts who need signup emails
        signup_targets: list[SignupTarget] = []
        for reg in list_registrations(store):
            if not reg.accepted or reg.email in registered:
                continue
            if reg.account_created:
                continue
            signup_targets.append(
                SignupTarget(reg.email, reg.firstname, reg.registration_token)
            )

        # Users who already had an account and were just accepted
        accepted_targets: list[AcceptedTarget] = []
        for acc_email, firstname in pending_with_account.items():
            # If registration was deleted by accept_new, it means
            # the user was accepted with an existing account
            if get_registration(store, acc_email) is None:
                accepted_targets.append(AcceptedTarget(acc_email, firstname))

        # Filter to requested email in single-email mode
        if email is not None:
            signup_targets = [t for t in signup_targets if t.email == email]
            accepted_targets = [t for t in accepted_targets if t.email == email]

        return result, signup_targets, accepted_targets

    accept_result, signup_targets, accepted_targets = store_queue.execute(
        accept_and_prepare
    )

    emails_sent = 0
    emails_failed = 0

    for target in signup_targets:
        try:
            link = f"{frontend_origin}/account/signup?token={target.registration_token}"
            data = EmailData(
                email_type="sync_please_register",
                to_email=target.email,
                display_name=target.display_name,
                link=link,
            )
            sendemail(smtp_config, data, smtp_send)

            # Increment email_send_count
            def inc_count(store: Storage, e: str = target.email) -> None:
                reg = get_registration(store, e)
                if reg is not None:
                    reg.email_send_count += 1
                    upsert_registration(store, reg)

            store_queue.execute(inc_count)
            emails_sent += 1
        except (smtplib.SMTPException, OSError) as exc:
            logger.error(
                f"accept_new_with_email: Failed to send to {target.email}: {exc}"
            )
            emails_failed += 1

    for target in accepted_targets:
        try:
            data = EmailData(
                email_type="account_accepted_self",
                to_email=target.email,
                display_name=target.display_name,
                link=frontend_origin,
            )
            sendemail(smtp_config, data, smtp_send)
            emails_sent += 1
        except (smtplib.SMTPException, OSError) as exc:
            logger.error(
                f"accept_new_with_email: Failed to send to {target.email}: {exc}"
            )
            emails_failed += 1

    result = AcceptNewResult(
        added=accept_result["added"],
        skipped=accept_result["skipped"],
        emails_sent=emails_sent,
        emails_failed=emails_failed,
    )
    logger.info(f"accept_new_with_email: {result}")
    return result
