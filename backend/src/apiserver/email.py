"""Email sending module with SMTP support.

Sends emails via SMTP with STARTTLS. Creates a new connection per request
(simple, no keep-alive complexity). Supports multipart text/html emails.

Templates are loaded from the templates/ directory.
When SMTP sending is disabled, emails are saved to the emails/ folder.
"""

import logging
import smtplib
from dataclasses import dataclass
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate
from html import escape
from pathlib import Path
from typing import Literal

from apiserver.resources import res_path
from apiserver.settings import SmtpConfig

# Directory for saved emails (when SMTP sending is disabled)
EMAILS_DIR: Path = res_path.parent.parent.parent / "emails"

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
    "account_accepted",
]

# Email subjects, titles and preheaders for each type
# Format: (subject, title, preheader)
EMAIL_CONFIG: dict[EmailType, tuple[str, str, str]] = {
    "signup_verification": (
        "Activeer je Dodeka account",
        "Account activeren",
        "Klik op de link om je account te activeren",
    ),
    "email_update_verification": (
        "Bevestig je nieuwe e-mailadres",
        "E-mailadres wijzigen",
        "Voer de code in om je nieuwe e-mailadres te bevestigen",
    ),
    "password_reset": (
        "Wachtwoord resetten",
        "Wachtwoord reset",
        "Je tijdelijke wachtwoord staat in deze e-mail",
    ),
    "signin_notification": (
        "Nieuwe aanmelding gedetecteerd",
        "Aanmelding",
        "Er is ingelogd op je account",
    ),
    "password_updated": (
        "Je wachtwoord is gewijzigd",
        "Wachtwoord gewijzigd",
        "Je accountwachtwoord is gewijzigd",
    ),
    "email_updated": (
        "Je e-mailadres is gewijzigd",
        "E-mailadres gewijzigd",
        "Je account e-mailadres is gewijzigd",
    ),
    "account_accepted": (
        "Je bent goedgekeurd bij Dodeka",
        "Lidmaatschap goedgekeurd",
        "Je aanmelding bij D.S.A.V. Dodeka is goedgekeurd",
    ),
}

# Templates directory (in resources folder)
TEMPLATES_DIR: Path = res_path / "templates"


@dataclass
class EmailTemplate:
    """Loaded email template with subject, title, preheader, text and HTML content."""

    subject: str
    title: str
    preheader: str
    text: str
    html: str


def load_template(email_type: EmailType) -> EmailTemplate:
    """Load an email template from the templates directory."""
    subject, title, preheader = EMAIL_CONFIG[email_type]

    # Load text template
    text_path = TEMPLATES_DIR / f"{email_type}.txt"
    with open(text_path) as f:
        text = f.read()

    # Load HTML content template
    html_path = TEMPLATES_DIR / f"{email_type}.html"
    with open(html_path) as f:
        html_content = f.read()

    return EmailTemplate(
        subject=subject,
        title=title,
        preheader=preheader,
        text=text,
        html=html_content,
    )


def load_base_template() -> str:
    """Load the base HTML template."""
    base_path = TEMPLATES_DIR / "base.html"
    with open(base_path) as f:
        return f.read()


@dataclass
class TemplateCache:
    """Cache for loaded email templates."""

    templates: dict[EmailType, EmailTemplate]
    base: str
    initialized: bool = False

    def init(self) -> None:
        """Initialize template cache."""
        if self.initialized:
            return

        self.base = load_base_template()

        email_types: list[EmailType] = [
            "signup_verification",
            "email_update_verification",
            "password_reset",
            "signin_notification",
            "password_updated",
            "email_updated",
            "account_accepted",
        ]
        for email_type in email_types:
            self.templates[email_type] = load_template(email_type)

        self.initialized = True
        logger.info(f"Loaded {len(self.templates)} email templates")


# Template cache instance
cache = TemplateCache(templates={}, base="")


def formatgreeting(display_name: str | None) -> str:
    """Format a greeting line based on display name."""
    if display_name:
        return f"Hallo {display_name},"
    return "Hallo,"


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
class RenderedEmail:
    """Rendered email ready for sending or saving."""

    email_type: str
    to_email: str
    subject: str
    text_body: str
    html_body: str
    link: str | None = None
    code: str | None = None


def save_email_to_file(email: RenderedEmail) -> Path:
    """Save email to files instead of sending.

    Creates both .txt and .html files in the emails/ directory.
    Returns the path to the directory containing the saved files.
    """
    EMAILS_DIR.mkdir(exist_ok=True)

    # Create filename with timestamp and details
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    # Sanitize email for filename (replace @ and . with _)
    safe_email = email.to_email.replace("@", "_at_").replace(".", "_")
    base_name = f"{timestamp}_{email.email_type}_{safe_email}"

    # Save text version
    text_path = EMAILS_DIR / f"{base_name}.txt"
    text_content = f"To: {email.to_email}\nSubject: {email.subject}\n"
    if email.code:
        text_content += f"Code: {email.code}\n"
    if email.link:
        text_content += f"Link: {email.link}\n"
    text_content += f"\n{'-' * 40}\n\n{email.text_body}"
    text_path.write_text(text_content, encoding="utf-8")

    # Save HTML version
    html_path = EMAILS_DIR / f"{base_name}.html"
    html_path.write_text(email.html_body, encoding="utf-8")

    logger.info(f"Email saved to {EMAILS_DIR}/{base_name}.{{txt,html}}")
    if email.link:
        logger.info(f"Signup link: {email.link}")
    if email.code:
        logger.info(f"Verification code: {email.code}")

    return EMAILS_DIR


@dataclass
class EmailData:
    """Data for sending an email."""

    email_type: EmailType
    to_email: str
    display_name: str | None = None
    code: str | None = None  # Verification code or temporary password
    timestamp: str | None = None  # For notification emails
    new_email: str | None = None  # For email_updated notifications
    link: str | None = None  # Signup or action link


def sendemail(
    config: SmtpConfig | None, data: EmailData, smtp_send: bool = False
) -> None:
    """Send an email using the specified template type.

    If smtp_send is True and config is provided, sends via SMTP.
    Otherwise, saves the email to the emails/ directory.
    """
    # Initialize templates on first use
    cache.init()

    template = cache.templates[data.email_type]

    # Build context for plain text (no escaping needed)
    text_context = {
        "greeting": formatgreeting(data.display_name),
        "code": data.code or "",
        "timestamp": data.timestamp or "",
        "new_email": data.new_email or "",
        "link": data.link or "",
    }

    # Build context for HTML (escape user-provided values)
    escaped_name = escape(data.display_name) if data.display_name else None
    html_context = {
        "subject": template.subject,
        "title": template.title,
        "preheader": template.preheader,
        "greeting": formatgreeting(escaped_name),
        "code": data.code or "",  # System-generated, safe
        "timestamp": data.timestamp or "",  # System-generated, safe
        "new_email": escape(data.new_email) if data.new_email else "",
        "link": data.link or "",  # System-generated URL, safe
    }

    # Render text template
    text_body = template.text.format(**text_context)

    # Render HTML content, then wrap in base template
    html_content = template.html.format(**html_context)
    html_context["content"] = html_content
    html_body = cache.base.format(**html_context)

    if smtp_send and config is not None:
        sendmail(config, data.to_email, template.subject, text_body, html_body)
    else:
        rendered = RenderedEmail(
            email_type=data.email_type,
            to_email=data.to_email,
            subject=template.subject,
            text_body=text_body,
            html_body=html_body,
            link=data.link,
            code=data.code,
        )
        save_email_to_file(rendered)
