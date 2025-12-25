"""Email sending module with SMTP support.

Sends emails via SMTP with STARTTLS. Creates a new connection per request
(simple, no keep-alive complexity). Supports multipart text/html emails.
"""

import logging
import smtplib
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate
from typing import Literal

from apiserver.settings import SmtpConfig

logger = logging.getLogger("apiserver.email")

# Email types that carry verification tokens (stored for testing/automation)
TOKEN_EMAIL_TYPES = frozenset(
    ["signup_verification", "email_update_verification", "password_reset"]
)

EmailType = Literal[
    "signup_verification",
    "email_update_verification",
    "password_reset",
    "signin_notification",
    "password_updated",
    "email_updated",
]

# Email templates with subject, text, and HTML versions
# Uses simple {variable} placeholders for formatting
TEMPLATES: dict[EmailType, dict[str, str]] = {
    "signup_verification": {
        "subject": "Signup verification code",
        "text": "Your email address verification code is {code}.",
        "html": """
<p>Your email address verification code is <strong>{code}</strong>.</p>
""",
    },
    "email_update_verification": {
        "subject": "Email update verification code",
        "text": """{greeting}

You have made a request to update your email. Your verification code is {code}.
""",
        "html": """
<p>{greeting}</p>
<p>You have made a request to update your email.</p>
<p>Your verification code is <strong>{code}</strong>.</p>
""",
    },
    "password_reset": {
        "subject": "Password reset temporary password",
        "text": """{greeting}

Your password reset temporary password is {code}.
""",
        "html": """
<p>{greeting}</p>
<p>Your password reset temporary password is <strong>{code}</strong>.</p>
""",
    },
    "signin_notification": {
        "subject": "Sign-in detected",
        "text": """{greeting}

We detected a sign-in to your account at {timestamp} (UTC).
""",
        "html": """
<p>{greeting}</p>
<p>We detected a sign-in to your account at <strong>{timestamp}</strong> (UTC).</p>
""",
    },
    "password_updated": {
        "subject": "Password updated",
        "text": """{greeting}

Your account password was updated at {timestamp} (UTC).
""",
        "html": """
<p>{greeting}</p>
<p>Your account password was updated at <strong>{timestamp}</strong> (UTC).</p>
""",
    },
    "email_updated": {
        "subject": "Email updated",
        "text": """{greeting}

Your account email address was updated to {new_email} at {timestamp} (UTC).
""",
        "html": """
<p>{greeting}</p>
<p>Your account email was updated to <strong>{new_email}</strong> at {timestamp}.</p>
""",
    },
}


def formatgreeting(display_name: str | None) -> str:
    """Format a greeting line based on display name."""
    if display_name:
        return f"Dear {display_name},"
    return "Hello,"


def sendmail(
    config: SmtpConfig,
    to_email: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> None:
    """Send a multipart email via SMTP with STARTTLS.

    Creates a new connection per call (simple, no keep-alive).
    Raises exception on failure.
    """
    # Create multipart message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["From"] = formataddr((config.sender_name, config.sender_email))
    msg["To"] = to_email

    # Attach text and HTML parts
    msg.attach(MIMEText(text_body.strip(), "plain", "utf-8"))
    msg.attach(MIMEText(html_body.strip(), "html", "utf-8"))

    # Connect and send
    logger.debug(f"Connecting to SMTP server {config.host}:{config.port}")
    with smtplib.SMTP(config.host, config.port) as server:
        server.starttls()
        if config.username and config.password:
            server.login(config.username, config.password)
        server.sendmail(config.sender_email, [to_email], msg.as_string())

    logger.info(f"Email sent to {to_email}: {subject}")


@dataclass
class EmailData:
    """Data for sending an email."""

    email_type: EmailType
    to_email: str
    display_name: str | None = None
    code: str | None = None  # Verification code or temporary password
    timestamp: str | None = None  # For notification emails
    new_email: str | None = None  # For email_updated notifications


def sendemail(config: SmtpConfig, data: EmailData) -> None:
    """Send an email using the specified template type."""
    template = TEMPLATES[data.email_type]

    # Build template context
    context = {
        "greeting": formatgreeting(data.display_name),
        "code": data.code or "",
        "timestamp": data.timestamp or "",
        "new_email": data.new_email or "",
    }

    # Render template
    subject = template["subject"]
    text_body = template["text"].format(**context)
    html_body = template["html"].format(**context)

    sendmail(config, data.to_email, subject, text_body, html_body)
