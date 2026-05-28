"""Shared command definitions for the backend private server.

This module provides:
- HTTP client functions for talking to the private server
- An argparse parser factory for the CLI
- Command execution functions (one per command) that print output directly
"""

import argparse
import json
from pathlib import Path
from typing import Any

import requests

from apiserver.settings import (
    PRIVATE_HOST,
    load_settings_from_env,
)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

PRIVATE_PORT_CONFIG: dict[str, int | None] = {"port": None}


def get_backend_dir() -> Path:
    """Get the backend project directory from this source file."""
    return Path(__file__).resolve().parents[3]


def get_env_file(env: str) -> Path:
    """Resolve the environment file for a named backend environment."""
    cwd_path = Path.cwd() / "envs" / env / ".env"
    if cwd_path.exists():
        return cwd_path

    return get_backend_dir() / "envs" / env / ".env"


def configure_private_port(env: str | None, env_file: Path | None) -> None:
    """Configure the private server port from an environment file."""
    resolved_env_file = (
        env_file if env_file is not None else get_env_file(env or "test")
    )
    if not resolved_env_file.exists():
        raise FileNotFoundError(f"Environment file not found: {resolved_env_file}")

    settings = load_settings_from_env(resolved_env_file)
    PRIVATE_PORT_CONFIG["port"] = settings.private_port


def get_private_url(port: int | None = None) -> str:
    """Get the base URL for the private server."""
    selected_port = PRIVATE_PORT_CONFIG["port"] if port is None else port
    if selected_port is None:
        raise RuntimeError("Private server port has not been configured")
    return f"http://{PRIVATE_HOST}:{selected_port}"


def send_command(command: str, **kwargs: Any) -> str:
    """Send a command to the running server via HTTP."""
    url = f"{get_private_url()}/command"
    payload = {"command": command, **kwargs}

    try:
        response = requests.post(url, json=payload, timeout=30)
        return response.text
    except requests.exceptions.ConnectionError:
        return f"Error: Could not connect to {url}. Is the server running?"


def send_command_json(command: str, **kwargs: Any) -> dict | None:
    """Send a command and parse JSON response."""
    timeout = kwargs.pop("timeout", 30)
    url = f"{get_private_url()}/command"
    payload = {"command": command, **kwargs}

    try:
        response = requests.post(url, json=payload, timeout=timeout)
        return json.loads(response.text)
    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to {url}. Is the server running?")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid response: {response.text}")
        return None


# ---------------------------------------------------------------------------
# Command execution functions
# ---------------------------------------------------------------------------


def cmd_reset(args: argparse.Namespace) -> None:
    """Clear all tables and re-bootstrap admin."""
    result = send_command("reset")
    print(result)


def cmd_prepare_user(args: argparse.Namespace) -> None:
    """Prepare a user with an accepted registration."""
    names = []
    if args.firstname:
        names.append(args.firstname)
    if args.lastname:
        names.append(args.lastname)

    result = send_command("prepare_user", email=args.email, names=names)
    print(result)


def cmd_get_admin_credentials(args: argparse.Namespace) -> None:
    """Get the bootstrap admin credentials."""
    result = send_command("get_admin_credentials")
    print(result)


def cmd_get_token(args: argparse.Namespace) -> None:
    """Get an email verification token."""
    result = send_command("get_token", action=args.action, email=args.email)
    print(result)


def cmd_import_sync(args: argparse.Namespace) -> None:
    """Read CSV file and send to server for import into sync table."""
    with open(args.csv_path) as f:
        csv_content = f.read()
    result = send_command("import_sync", csv_content=csv_content)
    print(result)


def cmd_sync_status(args: argparse.Namespace) -> None:
    """Compute and display sync status."""
    data = send_command_json("compute_groups")
    if data is None:
        return

    review = data.get("review_required", [])
    linked_regs = data.get("linked_registrations", [])
    existing = data.get("existing", [])
    departed = data.get("departed", [])

    print("=== Sync Status ===")
    print(f"\nReview Required ({len(review)} rows):")
    for item in review:
        bn = item["bondsnummer"]
        volta = item.get("incoming_volta_data", {})
        email = volta.get("email", "?")
        candidates = item.get("candidates", [])
        print(f"  BN={bn} email={email} ({len(candidates)} candidates)")

    print(f"\nLinked Registrations ({len(linked_regs)} rows):")
    for item in linked_regs:
        reg = item.get("registration", {})
        print(
            f"  BN={item['bondsnummer']} email={reg.get('email', '?')}"
            f" email_will_change={item.get('email_will_change', False)}"
        )

    print(f"\nExisting ({len(existing)} users):")
    for item in existing:
        user = item.get("user", {})
        diffs = item.get("field_diffs", [])
        print(
            f"  BN={item['bondsnummer']} email={user.get('email', '?')}"
            f" ({len(diffs)} diffs)"
        )

    print(f"\nDeparted ({len(departed)} users):")
    for item in departed:
        print(f"  {item.get('email', '?')} (BN={item.get('bondsnummer')})")


def cmd_remove_departed(args: argparse.Namespace) -> None:
    """Remove departed linked live users."""
    result = send_command_json("remove_departed")
    if result:
        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Removed {result.get('removed', 0)} user(s)")


def cmd_update_existing(args: argparse.Namespace) -> None:
    """Update existing from imported Volta data."""
    result = send_command_json("update_existing")
    if result:
        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(
                f"Registrations updated: {result.get('registrations_updated', 0)}, "
                f"Users refreshed: {result.get('users_refreshed', 0)}"
            )


def cmd_board_setup(args: argparse.Namespace) -> None:
    """One-time setup for the Bestuur (board) account."""
    result = send_command_json("board_setup")
    if result:
        if result.get("success"):
            print(f"Board account created: {result.get('email')}")
            print(result.get("message", ""))
        elif "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(result)


def cmd_board_renew(args: argparse.Namespace) -> None:
    """Yearly renewal: reset board password and renew admin permission."""
    result = send_command_json("board_renew")
    if result:
        if result.get("success"):
            print(result.get("message", "Board renewed."))
        elif "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(result)


def cmd_grant_admin(args: argparse.Namespace) -> None:
    """Grant admin permission and mark as system user."""
    result = send_command_json("grant_admin", email=args.email)
    if result:
        if result.get("success"):
            print(f"Admin granted to {args.email} (user_id={result.get('user_id')})")
        elif "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(result)


def cmd_create_accounts(args: argparse.Namespace) -> None:
    """Complete signup for all accepted registrations."""
    result = send_command_json("create_accounts", password=args.password, timeout=120)
    if result:
        print(f"Created: {result.get('created', 0)}, Failed: {result.get('failed', 0)}")
        if result.get("message"):
            print(result["message"])
        for failure in result.get("failures", []):
            print(f"  {failure['email']}: {failure['error']}")


# ---------------------------------------------------------------------------
# Parser factory
# ---------------------------------------------------------------------------


def create_backend_parser() -> argparse.ArgumentParser:
    """Create the argument parser for backend commands."""
    parser = argparse.ArgumentParser(
        prog="backend",
        description="Backend management commands",
    )
    env_group = parser.add_mutually_exclusive_group()
    env_group.add_argument(
        "--env",
        choices=("test", "demo", "production"),
        help="Load private server port from envs/<env>/.env",
    )
    env_group.add_argument(
        "--env-file",
        type=Path,
        help="Load private server port from a specific backend .env file",
    )
    parser.set_defaults(env="test")
    subparsers = parser.add_subparsers(dest="command", required=True)

    reset_parser = subparsers.add_parser(
        "reset", help="Clear all tables and re-bootstrap admin"
    )
    reset_parser.set_defaults(func=cmd_reset)

    prepare_parser = subparsers.add_parser(
        "prepare-user",
        help="Prepare a user with an accepted registration",
    )
    prepare_parser.add_argument("email", help="Email address of the user")
    prepare_parser.add_argument("--firstname", "-f", help="First name of the user")
    prepare_parser.add_argument("--lastname", "-l", help="Last name of the user")
    prepare_parser.set_defaults(func=cmd_prepare_user)

    admin_creds_parser = subparsers.add_parser(
        "get-admin-credentials", help="Get the bootstrap admin credentials"
    )
    admin_creds_parser.set_defaults(func=cmd_get_admin_credentials)

    token_parser = subparsers.add_parser(
        "get-token", help="Get an email verification token"
    )
    token_parser.add_argument("action", help="Token action (e.g., signup, reset)")
    token_parser.add_argument("email", help="Email address")
    token_parser.set_defaults(func=cmd_get_token)

    sync_parser = subparsers.add_parser(
        "import-sync", help="Parse CSV export and import into sync table"
    )
    sync_parser.add_argument("csv_path", help="Path to the CSV export file")
    sync_parser.set_defaults(func=cmd_import_sync)

    status_parser = subparsers.add_parser("sync-status", help="Show sync status")
    status_parser.set_defaults(func=cmd_sync_status)

    remove_parser = subparsers.add_parser(
        "remove-departed",
        help="Remove departed linked live users",
    )
    remove_parser.set_defaults(func=cmd_remove_departed)

    update_parser = subparsers.add_parser(
        "update-existing",
        help="Update existing from imported Volta data",
    )
    update_parser.set_defaults(func=cmd_update_existing)

    board_setup_parser = subparsers.add_parser(
        "board-setup",
        help="One-time setup for the Bestuur (board) account",
    )
    board_setup_parser.set_defaults(func=cmd_board_setup)

    board_renew_parser = subparsers.add_parser(
        "board-renew",
        help="Yearly: reset board password and renew admin permission",
    )
    board_renew_parser.set_defaults(func=cmd_board_renew)

    grant_admin_parser = subparsers.add_parser(
        "grant-admin",
        help="Grant admin permission and mark as system user",
    )
    grant_admin_parser.add_argument("email", help="Email address of the user")
    grant_admin_parser.set_defaults(func=cmd_grant_admin)

    create_accs_parser = subparsers.add_parser(
        "create-accounts",
        help="Complete signup for all accepted registrations (testing)",
    )
    create_accs_parser.add_argument(
        "password", help="Password to set for all new accounts"
    )
    create_accs_parser.set_defaults(func=cmd_create_accounts)

    return parser
