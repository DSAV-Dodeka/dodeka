"""Shared command definitions for the backend private server.

This module provides:
- HTTP client functions for talking to the private server
- An argparse parser factory for the CLI
- Command execution functions (one per command) that print output directly

Commands:
- reset: clear all tables and re-bootstrap admin
- prepare-user: create user ready for tiauth-faroe signup flow (testing)
- get-admin-credentials: return bootstrapped admin email/password
- get-token: retrieve email verification code (for test automation)
- import-sync: parse CSV export and import into sync table
- sync-status: compute and display sync groups (departed/new/existing)
- remove-departed: revoke member permission for departed users
- accept-new: add new users as board-accepted and initiate signup
- board-setup: one-time setup for the Bestuur (board) account
- board-renew: yearly renewal (password reset + admin permission)
- grant-admin: grant admin permission to a user
- update-existing: update userdata from sync for existing users
- create-accounts: complete signup for all accepted newusers (testing)
"""

import argparse
import json
from typing import Any

import requests

from apiserver.settings import DEFAULT_PRIVATE_PORT, PRIVATE_HOST


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


def get_private_url(port: int = DEFAULT_PRIVATE_PORT) -> str:
    """Get the base URL for the private server."""
    return f"http://{PRIVATE_HOST}:{port}"


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
    """Prepare a user in the newusers table with accepted=True."""
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
    """Compute and display sync groups."""
    data = send_command_json("compute_groups")
    if data is None:
        return

    departed = data.get("departed", [])
    new = data.get("new", [])
    pending = data.get("pending", [])
    existing = data.get("existing", [])

    print("=== Sync Status ===")
    print(f"\nDeparted ({len(departed)} users - in system but not in import):")
    for email in departed:
        print(f"  {email}")

    print(f"\nNew ({len(new)} users - in import but not in system):")
    for entry in new:
        name = entry.get("voornaam", "")
        if entry.get("tussenvoegsel"):
            name += f" {entry['tussenvoegsel']}"
        name += f" {entry.get('achternaam', '')}"
        print(f"  {entry['email']} ({name.strip()})")

    print(f"\nPending ({len(pending)} users - accepted, awaiting signup):")
    for email in pending:
        print(f"  {email}")

    print(f"\nExisting ({len(existing)} users - in both):")
    for pair in existing:
        sync = pair["sync"]
        current = pair.get("current")
        status = "has data" if current else "no data yet"
        print(f"  {sync['email']} ({status})")


def cmd_remove_departed(args: argparse.Namespace) -> None:
    """Revoke member permission for departed users."""
    kwargs: dict[str, str] = {}
    if args.email:
        kwargs["email"] = args.email
    result = send_command_json("remove_departed", **kwargs)
    if result:
        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Removed member permission for {result.get('removed', 0)} user(s)")


def cmd_accept_new(args: argparse.Namespace) -> None:
    """Accept new users and initiate Faroe signup (email suppressed)."""
    kwargs: dict[str, str] = {}
    if args.email:
        kwargs["email"] = args.email
    result = send_command_json("accept_new_with_signup", **kwargs)
    if result:
        print(f"Added: {result.get('added', 0)}, Skipped: {result.get('skipped', 0)}")
        initiated = result.get("signup_initiated", 0)
        failed = result.get("signup_failed", 0)
        if initiated or failed:
            print(f"Signups: {initiated} initiated, {failed} failed")
        if result.get("failed_emails"):
            for email in result["failed_emails"]:
                print(f"  Failed: {email}")


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
    """Complete signup for all accepted newusers."""
    result = send_command_json("create_accounts", password=args.password, timeout=120)
    if result:
        print(f"Created: {result.get('created', 0)}, Failed: {result.get('failed', 0)}")
        if result.get("message"):
            print(result["message"])
        for failure in result.get("failures", []):
            print(f"  {failure['email']}: {failure['error']}")


def cmd_update_existing(args: argparse.Namespace) -> None:
    """Update userdata from sync for existing users."""
    kwargs: dict[str, str] = {}
    if args.email:
        kwargs["email"] = args.email
    result = send_command_json("update_existing", **kwargs)
    if result:
        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Updated {result.get('updated', 0)} user(s)")


# ---------------------------------------------------------------------------
# Parser factory
# ---------------------------------------------------------------------------


def create_backend_parser() -> argparse.ArgumentParser:
    """Create the argument parser for backend commands."""
    parser = argparse.ArgumentParser(
        prog="backend",
        description="Backend management commands",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # reset
    reset_parser = subparsers.add_parser(
        "reset", help="Clear all tables and re-bootstrap admin"
    )
    reset_parser.set_defaults(func=cmd_reset)

    # prepare-user
    prepare_parser = subparsers.add_parser(
        "prepare-user",
        help="Prepare a user in the newusers table with accepted=True",
    )
    prepare_parser.add_argument("email", help="Email address of the user")
    prepare_parser.add_argument("--firstname", "-f", help="First name of the user")
    prepare_parser.add_argument("--lastname", "-l", help="Last name of the user")
    prepare_parser.set_defaults(func=cmd_prepare_user)

    # get-admin-credentials
    admin_creds_parser = subparsers.add_parser(
        "get-admin-credentials", help="Get the bootstrap admin credentials"
    )
    admin_creds_parser.set_defaults(func=cmd_get_admin_credentials)

    # get-token
    token_parser = subparsers.add_parser(
        "get-token", help="Get an email verification token"
    )
    token_parser.add_argument("action", help="Token action (e.g., signup, reset)")
    token_parser.add_argument("email", help="Email address")
    token_parser.set_defaults(func=cmd_get_token)

    # import-sync
    sync_parser = subparsers.add_parser(
        "import-sync", help="Parse CSV export and import into sync table"
    )
    sync_parser.add_argument("csv_path", help="Path to the CSV export file")
    sync_parser.set_defaults(func=cmd_import_sync)

    # sync-status
    status_parser = subparsers.add_parser(
        "sync-status", help="Show sync groups (departed/new/existing)"
    )
    status_parser.set_defaults(func=cmd_sync_status)

    # remove-departed
    remove_parser = subparsers.add_parser(
        "remove-departed",
        help="Revoke member permission for departed users",
    )
    remove_parser.add_argument(
        "--email", help="Remove single user (omit for all departed)"
    )
    remove_parser.set_defaults(func=cmd_remove_departed)

    # accept-new
    accept_parser = subparsers.add_parser(
        "accept-new",
        help="Accept new users and initiate signup (email suppressed)",
    )
    accept_parser.add_argument("--email", help="Accept single user (omit for all new)")
    accept_parser.set_defaults(func=cmd_accept_new)

    # board-setup
    board_setup_parser = subparsers.add_parser(
        "board-setup",
        help="One-time setup for the Bestuur (board) account",
    )
    board_setup_parser.set_defaults(func=cmd_board_setup)

    # board-renew
    board_renew_parser = subparsers.add_parser(
        "board-renew",
        help="Yearly: reset board password and renew admin permission",
    )
    board_renew_parser.set_defaults(func=cmd_board_renew)

    # grant-admin
    grant_admin_parser = subparsers.add_parser(
        "grant-admin",
        help="Grant admin permission and mark as system user",
    )
    grant_admin_parser.add_argument("email", help="Email address of the user")
    grant_admin_parser.set_defaults(func=cmd_grant_admin)

    # create-accounts
    create_accs_parser = subparsers.add_parser(
        "create-accounts",
        help="Complete signup for all accepted newusers (testing)",
    )
    create_accs_parser.add_argument(
        "password", help="Password to set for all new accounts"
    )
    create_accs_parser.set_defaults(func=cmd_create_accounts)

    # update-existing
    update_parser = subparsers.add_parser(
        "update-existing",
        help="Update userdata from sync for existing users",
    )
    update_parser.add_argument(
        "--email", help="Update single user (omit for all existing)"
    )
    update_parser.set_defaults(func=cmd_update_existing)

    return parser
