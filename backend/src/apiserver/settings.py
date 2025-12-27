import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

# Private server address - uses 127.0.0.2 for isolation from main loopback
PRIVATE_HOST = "127.0.0.2"

__all__ = ["PRIVATE_HOST", "Settings", "SmtpConfig", "load_settings_from_env"]


@dataclass
class SmtpConfig:
    """SMTP configuration for sending emails."""

    host: str
    port: int
    sender_email: str
    sender_name: str = ""
    username: str | None = None
    password: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Settings:
    """Application settings loaded from environment file."""

    db_file: Path = Path("./db.sqlite")
    environment: Literal["test", "demo", "production"] = "production"
    auth_server_url: str = "http://localhost:3777"
    frontend_origin: str = "https://dsavdodeka.nl"
    debug_logs: bool = False
    # Port for main HTTP server (public API)
    port: int = 8000
    # Port for private server (Go-Python communication). Binds to PRIVATE_HOST.
    private_port: int = 8079
    # SMTP configuration for sending emails (None = config not provided)
    smtp: SmtpConfig | None = None
    # Whether to actually send emails via SMTP (False = save to files instead)
    smtp_send: bool = False


def load_env_file(env_file: Path) -> dict[str, str]:
    """Load environment variables from a file into a dict."""
    env: dict[str, str] = {}

    if not env_file.exists():
        return env

    with open(env_file) as f:
        for raw_line in f:
            line = raw_line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Split on first = sign
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            # Remove quotes if present
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]

            env[key] = value

    return env


def get_env(env_map: dict[str, str], key: str, default: str = "") -> str:
    """Get a value from the env map or OS environment."""
    value = env_map.get(key)
    if value:
        return value
    return os.environ.get(key, default)


def get_env_bool(env_map: dict[str, str], key: str, default: bool = False) -> bool:
    """Get a boolean value from the env map or OS environment."""
    value = get_env(env_map, key, "")
    if not value:
        return default
    return value.lower() in ("true", "1", "yes")


def get_env_int(env_map: dict[str, str], key: str, default: int) -> int:
    """Get an integer value from the env map or OS environment."""
    value = get_env(env_map, key, "")
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def load_settings_from_env(env_file: Path) -> Settings:
    """Load settings from an environment file."""
    env_map = load_env_file(env_file)

    config: dict[str, Any] = {}

    # Database file
    db_file = get_env(env_map, "BACKEND_DB_FILE", "")
    if db_file:
        config["db_file"] = Path(db_file)

    # Environment
    environment = get_env(env_map, "BACKEND_ENVIRONMENT", "")
    if environment in ("test", "demo", "production"):
        config["environment"] = environment

    # Auth server URL
    auth_server_url = get_env(env_map, "BACKEND_AUTH_SERVER_URL", "")
    if auth_server_url:
        config["auth_server_url"] = auth_server_url

    # Frontend origin
    frontend_origin = get_env(env_map, "BACKEND_FRONTEND_ORIGIN", "")
    if frontend_origin:
        config["frontend_origin"] = frontend_origin

    # Debug logs
    if get_env(env_map, "BACKEND_DEBUG_LOGS", ""):
        config["debug_logs"] = get_env_bool(env_map, "BACKEND_DEBUG_LOGS", False)

    # Port
    port = get_env(env_map, "BACKEND_PORT", "")
    if port:
        config["port"] = get_env_int(env_map, "BACKEND_PORT", 8000)

    # Private port
    private_port = get_env(env_map, "BACKEND_PRIVATE_PORT", "")
    if private_port:
        config["private_port"] = get_env_int(env_map, "BACKEND_PRIVATE_PORT", 8079)

    # SMTP configuration
    smtp_host = get_env(env_map, "BACKEND_SMTP_HOST", "")
    smtp_port = get_env(env_map, "BACKEND_SMTP_PORT", "")
    smtp_sender_email = get_env(env_map, "BACKEND_SMTP_SENDER_EMAIL", "")
    if smtp_host and smtp_port and smtp_sender_email:
        try:
            smtp_username = get_env(env_map, "BACKEND_SMTP_USERNAME", "") or None
            smtp_password = get_env(env_map, "BACKEND_SMTP_PASSWORD", "") or None
            config["smtp"] = SmtpConfig(
                host=smtp_host,
                port=int(smtp_port),
                sender_email=smtp_sender_email,
                sender_name=get_env(env_map, "BACKEND_SMTP_SENDER_NAME", ""),
                username=smtp_username,
                password=smtp_password,
            )
        except ValueError:
            pass

    # SMTP send toggle (requires smtp config to be set)
    if get_env(env_map, "BACKEND_SMTP_SEND", ""):
        config["smtp_send"] = get_env_bool(env_map, "BACKEND_SMTP_SEND", False)

    return Settings(**config)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="backend",
        description="D.S.A.V. Dodeka backend server",
    )
    parser.add_argument(
        "--env-file",
        type=str,
        default=".env",
        help="Path to environment file (default: .env)",
    )
    return parser.parse_args()


# Default private port for CLI
DEFAULT_PRIVATE_PORT = 8079
